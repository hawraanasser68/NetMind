import re

# Patterns applied in order — most specific first to avoid partial matches
REDACTION_PATTERNS = [
    # API keys (sk- prefix, 32+ chars) — catches Claude, OpenAI keys
    (re.compile(r'sk-[a-zA-Z0-9]{32,}'), '[REDACTED]'),

    # JWT / Bearer tokens
    (re.compile(r'Bearer\s+[a-zA-Z0-9._\-]{20,}'), 'Bearer [REDACTED]'),

    # Passwords in key=value format
    (re.compile(r'password\s*=\s*\S+', re.IGNORECASE), 'password=[REDACTED]'),

    # Credit card numbers (groups of 4 digits separated by space or dash)
    (re.compile(r'\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b'), '[REDACTED]'),

    # Email addresses
    (re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'), '[REDACTED]'),

    # Generic 32+ hex strings (SHA-256 hashes, API keys without prefix)
    # Must come last — broad pattern that would match too aggressively if first
    (re.compile(r'\b[a-f0-9]{32,}\b'), '[REDACTED]'),
]


def redact(text: str) -> str:
    """
    Apply all redaction patterns to a string.
    Returns the original value unchanged if it is not a non-empty string.
    """
    if not text or not isinstance(text, str):
        return text

    for pattern, replacement in REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)

    return text


def redact_dict(d: dict) -> dict:
    """Recursively redact all string values in a dict."""
    result = {}
    for key, value in d.items():
        if isinstance(value, str):
            result[key] = redact(value)
        elif isinstance(value, dict):
            result[key] = redact_dict(value)
        elif isinstance(value, list):
            result[key] = [redact(v) if isinstance(v, str) else v for v in value]
        else:
            result[key] = value
    return result
