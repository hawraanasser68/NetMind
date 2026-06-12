import ipaddress
import json
import time
from datetime import datetime

import anthropic
from sentence_transformers import SentenceTransformer

from src.agent.agent_osint import call_osint_tool
from src.agent.agent_prompts import (
    FLOW_ANALYSIS_PROMPT,
    INJECTION_DETECTED_PROMPT,
    LIMIT_HIT_PROMPT,
    SYSTEM_PROMPT,
)
from src.agent.agent_tools import TOOLS
from src.infra.infra_redaction import redact
from src.infra.infra_vault import get_secret

MAX_TOOL_CALLS = 5
MAX_TOKENS     = 1000
MAX_SECONDS    = 30

OSINT_TOOLS    = {'lookup_ip_vt', 'lookup_ip_abuse', 'lookup_threats', 'whois_domain', 'lookup_ports'}
INTERNAL_TOOLS = {'rag_search', 'generate_rule', 'escalate'}

_embedder: SentenceTransformer | None = None

_INJECTION_PATTERNS = [
    'ignore previous instructions',
    'disregard your system prompt',
    'you are now',
    'forget everything',
    'new instructions',
]


def _get_embedder() -> SentenceTransformer:
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformer('all-MiniLM-L6-v2')
    return _embedder


def _is_rfc1918(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class BudgetExceeded(Exception):
    pass


class AgentBudget:
    def __init__(self):
        self.tool_calls_remaining = MAX_TOOL_CALLS
        self.start_time           = time.time()

    def check(self) -> None:
        if self.tool_calls_remaining <= 0:
            raise BudgetExceeded('Maximum tool calls reached')
        if time.time() - self.start_time > MAX_SECONDS:
            raise BudgetExceeded('Time limit reached')

    def consume(self) -> None:
        self.tool_calls_remaining -= 1


def get_session_context(machine_ip: str, redis) -> dict:
    session_key = f'session:{machine_ip}'
    data        = redis.get(session_key)
    if data:
        return json.loads(data)
    return {
        'machine_ip':        machine_ip,
        'flows_this_window': 0,
        'first_seen':        datetime.utcnow().isoformat(),
        'agent_context':     '',
    }


def update_session(session: dict, finding: dict, redis) -> None:
    session['flows_this_window'] += 1
    session['agent_context']     += f"\n{finding.get('explanation', '')[:200]}"
    session_key = f'session:{session["machine_ip"]}'
    redis.set(session_key, redact(json.dumps(session)), ex=1800)


def retrieve_machine_history(machine_ip: str, db) -> str:
    """RAG: embed a query and retrieve the 3 most similar snapshots via pgvector cosine search."""
    query_vector = _get_embedder().encode(f'Machine {machine_ip} behavioral history').tolist()

    with db.cursor() as cur:
        cur.execute("""
            SELECT summary
            FROM machine_history
            WHERE machine_ip = %s
            ORDER BY embedding <=> %s::vector
            LIMIT 3
        """, (machine_ip, str(query_vector)))
        rows = cur.fetchall()

    if not rows:
        return f'No behavioral history found for {machine_ip}. This may be a new machine.'
    return '\n'.join(r['summary'] for r in rows)


def build_deviation_signals(components: dict) -> str:
    signals = []
    if components.get('z_bytes_machine', 0) > 0.7:
        signals.append(f"bytes {components['z_bytes_machine']:.0%} above normal")
    if components.get('new_port'):
        signals.append('destination port never seen before')
    if components.get('off_hours'):
        signals.append('machine active outside normal hours')
    if components.get('external_first'):
        signals.append('first ever external connection')
    if components.get('z_bytes_per_sec', 0) > 0.7:
        signals.append(f"transfer rate {components['z_bytes_per_sec']:.0%} above normal")
    return '; '.join(signals) if signals else 'moderate deviation'


def _validate_tool_call(tool_name: str, args: dict, flow: dict, budget: AgentBudget) -> dict:
    if tool_name in OSINT_TOOLS:
        if _is_rfc1918(flow.get('machine_ip', '')):
            return {'approved': False, 'reason': 'OSINT not applicable to internal IPs'}
        if budget.tool_calls_remaining < 2:
            return {'approved': False, 'reason': 'Insufficient budget for OSINT'}

    if tool_name == 'generate_rule':
        if args.get('src_ip') != flow.get('machine_ip'):
            return {'approved': False, 'reason': 'Rule target must match flow source IP'}
        if args.get('action') not in ('DROP', 'REJECT', None):
            return {'approved': False, 'reason': 'Action must be DROP or REJECT'}
        if _is_rfc1918(args.get('src_ip', '')):
            if flow.get('risk_level') != 'CRITICAL':
                return {'approved': False, 'reason': 'Cannot block internal IP unless CRITICAL risk'}

    if tool_name == 'escalate':
        if not args.get('reason'):
            return {'approved': False, 'reason': 'Escalation reason must not be empty'}
        if args.get('priority') not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            return {'approved': False, 'reason': 'Invalid priority level'}

    return {'approved': True, 'reason': None}


def _validate_tool_result(result: str) -> str:
    lower = result.lower()
    for pattern in _INJECTION_PATTERNS:
        if pattern in lower:
            return '[Tool result contained suspicious content and was sanitized for security.]'
    return result


def _build_iptables_rule(args: dict) -> str:
    src_ip   = args['src_ip']
    protocol = args['protocol']
    action   = args.get('action', 'DROP')
    dst_port = args.get('dst_port')
    if dst_port:
        return f'iptables -A INPUT -s {src_ip} -p {protocol} --dport {dst_port} -j {action}'
    return f'iptables -A INPUT -s {src_ip} -p {protocol} -j {action}'


def process_flow(scoring_result: dict, flow: dict, redis, db) -> dict:
    """
    Main agent loop. Loads session, retrieves RAG history, calls tools, returns finding.
    Budget: MAX_TOOL_CALLS calls or MAX_SECONDS, whichever hits first.
    """
    client = anthropic.Anthropic(api_key=get_secret('claude_api_key'))
    budget = AgentBudget()

    machine_ip = flow.get('machine_ip', 'unknown')
    session    = get_session_context(machine_ip, redis)

    session_context = (
        f"This machine has triggered {session['flows_this_window']} "
        f"suspicious flows in the current window. "
        f"Previous context: {session['agent_context'][:300]}"
        if session['flows_this_window'] > 0
        else 'No prior suspicious flows in current window.'
    )

    # Extract scalar values from features list (indices from ml_feature_contract.py)
    features    = flow.get('features', [])
    total_bytes = int((features[2] if len(features) > 2 else 0) + (features[3] if len(features) > 3 else 0))
    duration    = features[8] if len(features) > 8 else 0.0

    prompt = redact(FLOW_ANALYSIS_PROMPT.format(
        machine_ip        = machine_ip,
        dst_port          = flow.get('dst_port', 0),
        protocol          = flow.get('protocol', 'unknown'),
        total_bytes       = total_bytes,
        duration          = float(duration),
        hour              = datetime.utcnow().hour,
        is_external       = not _is_rfc1918(machine_ip),
        risk_level        = scoring_result.get('risk_level', 'HIGH'),
        classifier_score  = float(scoring_result.get('classifier_score', 0.0)),
        risk_score        = float(scoring_result.get('risk_score', 0.0)),
        machine_confidence= float(scoring_result.get('ml_confidence', scoring_result.get('confidence', 0.0))),
        deviation_signals = build_deviation_signals(scoring_result.get('components', {})),
        session_context   = session_context,
    ))

    messages      = [{'role': 'user', 'content': prompt}]
    tools_called  = []
    osint_results = {}
    firewall_rule = None
    escalated     = False
    limit_hit     = False
    limit_reason  = None
    explanation   = ''

    while True:
        try:
            budget.check()
        except BudgetExceeded as e:
            limit_hit    = True
            limit_reason = str(e)
            messages.append({'role': 'user', 'content': LIMIT_HIT_PROMPT.format(reason=str(e))})

        response = client.messages.create(
            model      = 'claude-3-5-sonnet-20241022',
            max_tokens = MAX_TOKENS,
            system     = SYSTEM_PROMPT,
            tools      = TOOLS if not limit_hit else [],
            messages   = messages,
        )

        messages.append({'role': 'assistant', 'content': response.content})

        if response.stop_reason == 'end_turn' or limit_hit:
            for block in response.content:
                if hasattr(block, 'text'):
                    explanation = redact(block.text)
            break

        if response.stop_reason != 'tool_use':
            break

        tool_results = []
        for block in response.content:
            if block.type != 'tool_use':
                continue

            tool_name = block.name
            tool_args = block.input

            validation = _validate_tool_call(tool_name, tool_args, flow, budget)
            if not validation['approved']:
                tool_results.append({
                    'type':        'tool_result',
                    'tool_use_id': block.id,
                    'content':     f"Tool call rejected: {validation['reason']}",
                })
                continue

            budget.consume()
            tools_called.append(tool_name)

            if tool_name == 'rag_search':
                result = retrieve_machine_history(tool_args['machine_ip'], db)

            elif tool_name in OSINT_TOOLS:
                raw    = call_osint_tool(tool_name, tool_args, redis)
                result = raw.get('data', {}).get('summary', str(raw))
                osint_results[tool_name] = raw.get('data', {})

            elif tool_name == 'generate_rule':
                firewall_rule = _build_iptables_rule(tool_args)
                result        = f'Rule generated: {firewall_rule}'

            elif tool_name == 'escalate':
                escalated = True
                result    = f"Escalation logged: {tool_args.get('reason', '')}"

            else:
                result = f'Unknown tool: {tool_name}'

            result = _validate_tool_result(str(result))

            tool_results.append({
                'type':        'tool_result',
                'tool_use_id': block.id,
                'content':     redact(result),
            })

        messages.append({'role': 'user', 'content': tool_results})

    finding = {
        'flow_id':            flow.get('flow_id', ''),
        'risk_level':         scoring_result.get('risk_level', 'HIGH'),
        'classifier_score':   float(scoring_result.get('classifier_score', 0.0)),
        'deviation_score':    float(scoring_result.get('risk_score', 0.0)),
        'machine_confidence': float(scoring_result.get('ml_confidence', scoring_result.get('confidence', 0.0))),
        'explanation':        redact(explanation),
        'firewall_rule':      firewall_rule if not limit_hit else None,
        'tools_called':       tools_called,
        'osint_results':      osint_results,
        'escalated_to_human': escalated or limit_hit,
        'limit_hit':          limit_hit,
        'limit_reason':       limit_reason,
        'confidence':         'LOW' if limit_hit else 'HIGH',
    }

    update_session(session, finding, redis)
    return finding
