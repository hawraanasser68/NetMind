import ipaddress
import re

from src.guardrails.guardrails_schemas import (
    FindingCheckRequest,
    FindingCheckResponse,
    InputCheckRequest,
    InputCheckResponse,
    ToolCallCheckRequest,
    ToolCallCheckResponse,
    ToolResultCheckRequest,
    ToolResultCheckResponse,
)

INJECTION_PATTERNS = [
    r'ignore previous instructions',
    r'disregard your system prompt',
    r'you are now',
    r'forget everything',
    r'new instructions',
    r'system\s*:',
    r'assistant\s*:',
]

CODE_PATTERNS = [
    r'<script>',
    r'eval\s*\(',
    r'exec\s*\(',
    r'drop\s+table',
    r'select\s+\*',
    r'iptables',
]

MAX_FIELD_LENGTH = 500

_OSINT_TOOLS = {
    'lookup_ip_vt', 'lookup_ip_abuse', 'lookup_threats',
    'whois_domain', 'lookup_ports',
}

_BENIGN_PHRASES = [
    'no action needed', 'benign', 'safe traffic', 'normal behavior',
]


def check_input(request: InputCheckRequest) -> InputCheckResponse:
    """Point 1 — scan all flow field values before the agent sees them."""
    for field_name, field_value in request.flow_fields.items():
        value_str = str(field_value)

        if len(value_str) > MAX_FIELD_LENGTH:
            return InputCheckResponse(
                approved  = False,
                reason    = f"Field '{field_name}' exceeds maximum length ({MAX_FIELD_LENGTH} chars).",
                rail_type = 'oversized_field',
            )

        lower = value_str.lower()

        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, lower, re.IGNORECASE):
                return InputCheckResponse(
                    approved  = False,
                    reason    = f"Potential prompt injection detected in field '{field_name}'.",
                    rail_type = 'prompt_injection',
                )

        for pattern in CODE_PATTERNS:
            if re.search(pattern, lower, re.IGNORECASE):
                return InputCheckResponse(
                    approved  = False,
                    reason    = f"Suspicious code pattern detected in field '{field_name}'.",
                    rail_type = 'code_injection',
                )

    return InputCheckResponse(approved=True, reason=None, rail_type=None)


def check_tool_call(request: ToolCallCheckRequest) -> ToolCallCheckResponse:
    """Point 2 — validate a tool call before it executes."""
    tool = request.tool_name
    args = request.tool_args
    flow = request.flow

    if tool in _OSINT_TOOLS:
        target_ip = args.get('ip_address', '')
        if target_ip and _is_rfc1918(target_ip):
            return ToolCallCheckResponse(
                approved = False,
                reason   = 'OSINT tools cannot be called on internal IP addresses.',
            )

    if tool == 'generate_rule':
        src_ip = args.get('src_ip', '')
        action = args.get('action', '')
        port   = args.get('dst_port')

        # Our flow uses machine_ip as the source IP field
        if src_ip != flow.get('machine_ip', flow.get('src_ip', '')):
            return ToolCallCheckResponse(
                approved = False,
                reason   = "Firewall rule target must match the flow's source IP.",
            )

        if action not in ('DROP', 'REJECT'):
            return ToolCallCheckResponse(
                approved = False,
                reason   = 'Firewall rule action must be DROP or REJECT.',
            )

        if port is not None and (not isinstance(port, int) or not 1 <= port <= 65535):
            return ToolCallCheckResponse(
                approved = False,
                reason   = 'Firewall rule port must be an integer between 1 and 65535.',
            )

    if tool == 'escalate':
        if not args.get('reason', '').strip():
            return ToolCallCheckResponse(
                approved = False,
                reason   = 'Escalation must include a non-empty reason.',
            )
        if args.get('priority') not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            return ToolCallCheckResponse(
                approved = False,
                reason   = 'Escalation priority must be LOW, MEDIUM, HIGH, or CRITICAL.',
            )

    return ToolCallCheckResponse(approved=True, reason=None)


def check_tool_result(request: ToolResultCheckRequest) -> ToolResultCheckResponse:
    """Point 3 — sanitize a tool result before the agent reads it."""
    result       = request.tool_result
    was_modified = False

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, result, re.IGNORECASE):
            result       = '[Tool result contained suspicious content and was sanitized.]'
            was_modified = True
            break

    return ToolResultCheckResponse(sanitized_result=result, was_modified=was_modified)


def check_finding(request: FindingCheckRequest) -> FindingCheckResponse:
    """Point 4 — validate finding consistency before it is written to security_alerts."""
    risk        = request.risk_level
    explanation = request.explanation.lower()
    has_rule    = bool(request.firewall_rule)

    if risk in ('CRITICAL', 'HIGH'):
        if any(phrase in explanation for phrase in _BENIGN_PHRASES):
            return FindingCheckResponse(
                approved = False,
                reason   = 'A HIGH/CRITICAL risk flow cannot conclude as benign.',
            )

    if risk == 'BENIGN' and has_rule:
        return FindingCheckResponse(
            approved = False,
            reason   = 'A BENIGN flow cannot have a firewall rule.',
        )

    if request.limit_hit and has_rule:
        return FindingCheckResponse(
            approved = False,
            reason   = 'Cannot generate a firewall rule when investigation was incomplete.',
        )

    return FindingCheckResponse(approved=True, reason=None)


def _is_rfc1918(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
