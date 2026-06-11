class SOCError(Exception):
    """
    Base error class.
    user_message:     shown to user (plain English, no technical details)
    technical_detail: logged only (never shown to user)
    """
    def __init__(self, user_message: str, technical_detail: str = ''):
        self.user_message     = user_message
        self.technical_detail = technical_detail
        super().__init__(technical_detail or user_message)


# ── Infrastructure ─────────────────────────────────────────────────────────
class VaultUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = 'The system configuration service is unreachable. '
                               'The application cannot start safely.',
            technical_detail = 'Vault returned connection refused',
        )

class DatabaseUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = 'The database is temporarily unavailable. '
                               'Your request will be retried automatically.',
            technical_detail = 'PostgreSQL connection refused',
        )

class RedisUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = 'The cache service is temporarily unavailable. '
                               'Performance may be degraded.',
            technical_detail = 'Redis connection refused',
        )


# ── Classifier ─────────────────────────────────────────────────────────────
class ClassifierUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = 'The threat classifier is temporarily unavailable. '
                               'Flows are being queued and will be processed shortly.',
            technical_detail = 'Classifier service returned non-200 response',
        )

class ModelSHA256Mismatch(SOCError):
    def __init__(self, expected: str, actual: str):
        super().__init__(
            user_message     = 'The classifier model failed its integrity check. '
                               'The service cannot start safely.',
            technical_detail = f'SHA-256 mismatch. Expected: {expected}. Got: {actual}.',
        )

class InvalidFeatureCount(SOCError):
    def __init__(self, expected: int, got: int):
        super().__init__(
            user_message     = 'A flow could not be scored due to a data format issue. '
                               'The flow has been logged for review.',
            technical_detail = f'Expected {expected} features, got {got}',
        )


# ── Agent ──────────────────────────────────────────────────────────────────
class AgentUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = 'The analysis agent is temporarily unavailable. '
                               'This flow has been queued for retry.',
            technical_detail = 'Claude API connection failed',
        )

class InvestigationIncomplete(SOCError):
    def __init__(self, reason: str):
        super().__init__(
            user_message     = 'The investigation could not be completed. '
                               'This flow has been escalated to a human analyst.',
            technical_detail = f'Agent limit hit: {reason}',
        )

class InjectionDetected(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = 'This flow contains content that cannot be safely analyzed. '
                               'It has been flagged for human review.',
            technical_detail = 'Input rail triggered — injection pattern detected',
        )


# ── OSINT ──────────────────────────────────────────────────────────────────
class OSINTUnavailable(SOCError):
    def __init__(self, tool_name: str):
        super().__init__(
            user_message     = f'External threat intelligence ({tool_name}) is currently unavailable. '
                               f'The analysis will proceed with available signals only.',
            technical_detail = f'{tool_name} API returned non-200 response',
        )


# ── Guardrails ─────────────────────────────────────────────────────────────
class GuardrailsUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = 'The security guardrails service is unavailable. '
                               'Processing has been paused for safety.',
            technical_detail = 'NeMo guardrails sidecar connection refused',
        )

class ToolCallRejected(SOCError):
    def __init__(self, tool_name: str, reason: str):
        super().__init__(
            user_message     = 'A security check prevented an action from being taken. '
                               'This flow has been escalated for review.',
            technical_detail = f"Tool '{tool_name}' rejected by output rail: {reason}",
        )

class FindingInconsistent(SOCError):
    def __init__(self, reason: str):
        super().__init__(
            user_message     = 'The analysis produced an inconsistent result and has been '
                               'flagged for human review.',
            technical_detail = f'Consistency check failed: {reason}',
        )
