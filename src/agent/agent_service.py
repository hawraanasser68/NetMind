import ipaddress
import json
import time
from datetime import datetime, timezone

from typing import TYPE_CHECKING

import requests
import structlog

if TYPE_CHECKING:
    from fastembed import TextEmbedding

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
from src.llm.llm_client import (
    AnthropicLLM, GroqLLM, GeminiLLM,
    get_anthropic_llm, get_groq_llm, get_gemini_llm,
    is_credits_error, is_groq_rate_limit,
)

logger = structlog.get_logger(__name__)

_GUARDRAILS_URL     = 'http://guardrails:8004/guardrails'
_GUARDRAILS_TIMEOUT = 5  # seconds — fail open if sidecar is unavailable

MAX_TOOL_CALLS = 5
MAX_TOKENS     = 1500
MAX_SECONDS    = 90

OSINT_TOOLS    = {'lookup_ip_vt', 'lookup_ip_abuse', 'lookup_threats', 'whois_domain', 'lookup_ports'}
INTERNAL_TOOLS = {'rag_search', 'generate_rule', 'escalate'}

_embedder: "TextEmbedding | None" = None


def _get_embedder() -> "TextEmbedding":
    global _embedder
    if _embedder is None:
        from fastembed import TextEmbedding
        _embedder = TextEmbedding('sentence-transformers/all-MiniLM-L6-v2')
    return _embedder


def _guardrails_headers() -> dict:
    return {'Authorization': f'Bearer {get_secret("service_token")}'}


def _guardrails_post(endpoint: str, payload: dict) -> dict:
    """
    POST to the guardrails sidecar. Fails open on any network/timeout error —
    a guardrails outage must not stop the investigation.
    """
    try:
        resp = requests.post(
            f'{_GUARDRAILS_URL}/{endpoint}',
            json=payload,
            headers=_guardrails_headers(),
            timeout=_GUARDRAILS_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning('Guardrails sidecar unreachable — failing open', endpoint=endpoint, error=str(e))
        return {'approved': True, 'sanitized_result': payload.get('tool_result', ''), 'was_modified': False}


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
        'first_seen':        datetime.now(timezone.utc).isoformat(),
        'agent_context':     '',
    }


def update_session(session: dict, finding: dict, redis) -> None:
    session['flows_this_window'] += 1
    session['agent_context']     += f"\n{finding.get('explanation', '')[:200]}"
    session_key = f'session:{session["machine_ip"]}'
    redis.set(session_key, redact(json.dumps(session)), ex=1800)


def retrieve_machine_history(machine_ip: str, db) -> str:
    """RAG: embed a query and retrieve the 3 most similar snapshots via pgvector cosine search."""
    query_vector = list(_get_embedder().embed([f'Machine {machine_ip} behavioral history']))[0].tolist()

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
    llm    = get_anthropic_llm()
    budget = AgentBudget()

    machine_ip  = flow.get('machine_ip', 'unknown')
    trace_steps = []

    # Synthetic classify step — scoring already ran in the classifier worker
    trace_steps.append({
        'step_type':        'classify',
        'tool_name':        None,
        'tool_args':        None,
        'result_summary':   (
            f"Score {scoring_result.get('classifier_score', 0):.3f} · "
            f"Risk {scoring_result.get('risk_level', '?')} · "
            f"Deviation {scoring_result.get('risk_score', 0):.3f}"
        ),
        'duration_ms':      None,
        'guardrail_status': None,
        'metadata':         {k: v for k, v in scoring_result.items() if not isinstance(v, (list, dict))},
    })

    # Point 1 — check all flow field values for injection before agent sees them
    _t = time.time()
    input_check = _guardrails_post('check_input', {
        'flow_id':     flow.get('flow_id', ''),
        'flow_fields': {k: v for k, v in flow.items() if k != 'features'},
    })
    trace_steps.append({
        'step_type':        'input_check',
        'tool_name':        None,
        'tool_args':        None,
        'result_summary':   input_check.get('reason') or ('Approved' if input_check.get('approved', True) else 'Rejected'),
        'duration_ms':      int((time.time() - _t) * 1000),
        'guardrail_status': 'approved' if input_check.get('approved', True) else 'rejected',
        'metadata':         {},
    })

    if not input_check.get('approved', True):
        logger.warning('Guardrails rejected flow input', reason=input_check.get('reason'), machine_ip=machine_ip)
        return {
            'flow_id':            flow.get('flow_id', ''),
            'risk_level':         scoring_result.get('risk_level', 'HIGH'),
            'classifier_score':   float(scoring_result.get('classifier_score', 0.0)),
            'deviation_score':    float(scoring_result.get('risk_score', 0.0)),
            'machine_confidence': float(scoring_result.get('ml_confidence', 0.0)),
            'explanation':        f"Flow flagged by input guardrail: {input_check.get('reason')}",
            'firewall_rule':      None,
            'tools_called':       [],
            'osint_results':      {},
            'escalated_to_human': True,
            'limit_hit':          False,
            'limit_reason':       None,
            'confidence':         'LOW',
            'trace_steps':        trace_steps,
        }

    session = get_session_context(machine_ip, redis)

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
        hour              = datetime.now(timezone.utc).hour,
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

        try:
            response = llm.chat(
                system     = SYSTEM_PROMPT,
                messages   = messages,
                tools      = TOOLS if not limit_hit else [],
                max_tokens = MAX_TOKENS,
            )
        except Exception as exc:
            no_assistant_yet = not any(m.get('role') == 'assistant' for m in messages)
            if is_credits_error(exc) and no_assistant_yet:
                logger.warning('Anthropic credits exhausted — switching to Groq fallback',
                               flow_id=flow.get('flow_id'))
                llm = get_groq_llm()
                try:
                    response = llm.chat(
                        system     = SYSTEM_PROMPT,
                        messages   = messages,
                        tools      = TOOLS if not limit_hit else [],
                        max_tokens = MAX_TOKENS,
                    )
                except Exception as groq_exc:
                    if is_groq_rate_limit(groq_exc):
                        logger.warning('Groq rate limit hit — switching to Gemini fallback',
                                       flow_id=flow.get('flow_id'))
                        llm      = get_gemini_llm()
                        response = llm.chat(
                            system     = SYSTEM_PROMPT,
                            messages   = messages,
                            tools      = TOOLS if not limit_hit else [],
                            max_tokens = MAX_TOKENS,
                        )
                    else:
                        raise
            else:
                raise

        llm.append_assistant(messages, response)

        if response.stop_reason == 'end_turn' or limit_hit:
            explanation = redact(response.text)
            break

        if response.stop_reason != 'tool_use':
            break

        tool_results = []
        injection_detected = False
        for tc in response.tool_calls:
            tool_name = tc.name
            tool_args = tc.args

            # Point 2 — validate tool call via guardrails sidecar
            tool_check = _guardrails_post('check_tool_call', {
                'flow_id':   flow.get('flow_id', ''),
                'tool_name': tool_name,
                'tool_args': tool_args,
                'flow':      flow,
            })
            if not tool_check.get('approved', True):
                trace_steps.append({
                    'step_type':        'tool_call',
                    'tool_name':        tool_name,
                    'tool_args':        {k: redact(str(v)) for k, v in tool_args.items()},
                    'result_summary':   f"Blocked by guardrail: {tool_check.get('reason', '')}",
                    'duration_ms':      0,
                    'guardrail_status': 'rejected',
                    'metadata':         {},
                })
                tool_results.append({
                    'tool_call_id': tc.id,
                    'content':      f"Tool call rejected: {tool_check.get('reason')}",
                })
                continue

            budget.consume()
            tools_called.append(tool_name)
            _tool_t = time.time()

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

            _tool_dur = int((time.time() - _tool_t) * 1000)

            # Point 3 — sanitize tool result via guardrails sidecar
            result_check = _guardrails_post('check_tool_result', {
                'flow_id':     flow.get('flow_id', ''),
                'tool_name':   tool_name,
                'tool_result': str(result),
            })
            result = result_check.get('sanitized_result', str(result))
            if result_check.get('was_modified'):
                injection_detected = True

            trace_steps.append({
                'step_type':        'tool_call',
                'tool_name':        tool_name,
                'tool_args':        {k: redact(str(v)) for k, v in tool_args.items()},
                'result_summary':   redact(str(result))[:500],
                'duration_ms':      _tool_dur,
                'guardrail_status': 'modified' if result_check.get('was_modified') else 'approved',
                'metadata':         {},
            })

            tool_results.append({
                'tool_call_id': tc.id,
                'content':      redact(result),
            })

        llm.append_tool_results(messages, tool_results)
        if injection_detected:
            messages.append({'role': 'user', 'content': INJECTION_DETECTED_PROMPT})

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

    # Point 4 — validate finding consistency before writing to security_alerts
    _t = time.time()
    finding_check = _guardrails_post('check_finding', {
        'flow_id':          finding['flow_id'],
        'risk_level':       finding['risk_level'],
        'classifier_score': finding['classifier_score'],
        'explanation':      finding['explanation'],
        'firewall_rule':    finding['firewall_rule'],
        'limit_hit':        finding['limit_hit'],
    })
    trace_steps.append({
        'step_type':        'finding_check',
        'tool_name':        None,
        'tool_args':        None,
        'result_summary':   finding_check.get('reason') or ('Approved' if finding_check.get('approved', True) else 'Modified'),
        'duration_ms':      int((time.time() - _t) * 1000),
        'guardrail_status': 'approved' if finding_check.get('approved', True) else 'modified',
        'metadata':         {},
    })
    if not finding_check.get('approved', True):
        logger.warning('Guardrails rejected finding', reason=finding_check.get('reason'), flow_id=finding['flow_id'])
        finding['firewall_rule']      = None
        finding['escalated_to_human'] = True
        finding['explanation']        = (
            f"{finding['explanation']} "
            f"[Finding modified by guardrail: {finding_check.get('reason')}]"
        )

    finding['trace_steps'] = trace_steps
    update_session(session, finding, redis)
    return finding
