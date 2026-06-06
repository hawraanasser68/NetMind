# SPEC_INFRA.md
# Shared Infrastructure Specification
# All decisions final. Implement exactly as specified.

---

## Overview

The infra module is shared by all other modules. It provides database connections, Redis client, Vault secret loading, redaction, and error classes. Every module imports from here. Nothing in infra imports from other modules.

---

## File Structure

```
src/infra/
  infra_db.py        ← PostgreSQL connection and session
  infra_redis.py     ← Redis client (see SPEC_REDIS.md)
  infra_vault.py     ← Vault secret loading
  infra_redaction.py ← redact() function
  infra_errors.py    ← SOCError hierarchy
```

---

## infra_vault.py

```python
# src/infra/infra_vault.py

import os
import hvac
import logging

logger = logging.getLogger(__name__)

_vault_client = None
_secrets_cache = {}

def _get_vault_client() -> hvac.Client:
    global _vault_client
    if _vault_client is None:
        vault_addr  = os.environ.get('VAULT_ADDR', 'http://vault:8200')
        vault_token = os.environ.get('VAULT_TOKEN')

        if not vault_token:
            raise RuntimeError(
                "VAULT_TOKEN environment variable is not set. "
                "The application cannot start safely without secret management."
            )

        _vault_client = hvac.Client(url=vault_addr, token=vault_token)

        if not _vault_client.is_authenticated():
            raise RuntimeError(
                "Cannot connect to Vault. "
                "The application cannot start safely. "
                "Check that Vault is running and the token is valid."
            )

        logger.info(f"Connected to Vault at {vault_addr}")

    return _vault_client

def get_secret(secret_name: str) -> str:
    """
    Load secret from Vault.
    Cached in memory after first load.
    Raises RuntimeError if Vault is unreachable.
    """
    if secret_name in _secrets_cache:
        return _secrets_cache[secret_name]

    client = _get_vault_client()

    try:
        response = client.secrets.kv.v2.read_secret_version(
            path  = f'soc-agent/{secret_name}',
            mount_point = 'secret',
        )
        value = response['data']['data']['value']
        _secrets_cache[secret_name] = value
        return value
    except Exception as e:
        raise RuntimeError(
            f"Failed to load secret '{secret_name}' from Vault. "
            f"The application cannot start safely."
        ) from e

def load_secrets():
    """
    Pre-load all secrets at startup.
    Called once from each service's startup event.
    App refuses to start if any secret is missing.
    """
    required_secrets = [
        'claude_api_key',
        'virustotal_api_key',
        'abuseipdb_api_key',
        'alienvault_api_key',
        'greynoise_api_key',
        'shodan_api_key',
        'db_password',
        'redis_password',
        'service_token',
    ]

    for secret in required_secrets:
        try:
            get_secret(secret)
            logger.info(f"Secret loaded: {secret}")
        except RuntimeError as e:
            raise RuntimeError(
                f"Missing required secret: {secret}. "
                f"The service cannot start."
            ) from e

    logger.info("All secrets loaded successfully.")
```

---

## infra_db.py

```python
# src/infra/infra_db.py

import psycopg2
import psycopg2.extras
import os
import logging
from src.infra.infra_vault import get_secret

logger = logging.getLogger(__name__)

_connection = None

def get_db_connection():
    global _connection
    if _connection is None or _connection.closed:
        _connection = psycopg2.connect(
            host     = os.environ.get('DB_HOST', 'postgres'),
            port     = int(os.environ.get('DB_PORT', 5432)),
            dbname   = os.environ.get('DB_NAME', 'socdb'),
            user     = os.environ.get('DB_USER', 'postgres'),
            password = get_secret('db_password'),
            cursor_factory = psycopg2.extras.RealDictCursor,
        )
        logger.info("Database connection established.")
    return _connection

def get_db_session():
    """Returns a database connection. Reconnects if closed."""
    return get_db_connection()
```

---

## infra_redaction.py

```python
# src/infra/infra_redaction.py

import re

# Patterns to redact (order matters — most specific first)
REDACTION_PATTERNS = [
    # API keys (sk- prefix, 32+ chars)
    (re.compile(r'sk-[a-zA-Z0-9]{32,}'), '[REDACTED]'),

    # JWT tokens
    (re.compile(r'Bearer\s+[a-zA-Z0-9._\-]{20,}'), 'Bearer [REDACTED]'),

    # Passwords in key=value format
    (re.compile(r'password\s*=\s*\S+', re.IGNORECASE), 'password=[REDACTED]'),

    # Credit card numbers
    (re.compile(r'\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b'), '[REDACTED]'),

    # Email addresses
    (re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'), '[REDACTED]'),

    # Generic API key patterns (32+ hex chars)
    (re.compile(r'\b[a-f0-9]{32,}\b'), '[REDACTED]'),
]

def redact(text: str) -> str:
    """
    Apply all redaction patterns to text.
    Called at 6 points:
      1. Before agent prompt is built
      2. Before agent response stored in PostgreSQL
      3. Before dashboard displays finding
      4. Before Redis session written
      5. Before pgvector summary written
      6. Before every structlog line written (via processor)
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
```

---

## infra_errors.py

```python
# src/infra/infra_errors.py

class SOCError(Exception):
    """
    Base error class.
    user_message:     shown to user (plain English, no technical details)
    technical_detail: logged only (never shown to user)
    """
    def __init__(self, user_message: str, technical_detail: str = ""):
        self.user_message     = user_message
        self.technical_detail = technical_detail
        super().__init__(technical_detail or user_message)

# ── Infrastructure errors ──────────────────────────────────────────────────
class VaultUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = "The system configuration service is unreachable. "
                               "The application cannot start safely.",
            technical_detail = "Vault returned connection refused"
        )

class DatabaseUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = "The database is temporarily unavailable. "
                               "Your request will be retried automatically.",
            technical_detail = "PostgreSQL connection refused"
        )

class RedisUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = "The cache service is temporarily unavailable. "
                               "Performance may be degraded.",
            technical_detail = "Redis connection refused"
        )

# ── Classifier errors ──────────────────────────────────────────────────────
class ClassifierUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = "The threat classifier is temporarily unavailable. "
                               "Flows are being queued and will be processed shortly.",
            technical_detail = "Classifier service returned non-200 response"
        )

class ModelSHA256Mismatch(SOCError):
    def __init__(self, expected: str, actual: str):
        super().__init__(
            user_message     = "The classifier model failed its integrity check. "
                               "The service cannot start safely.",
            technical_detail = f"SHA-256 mismatch. Expected: {expected}. Got: {actual}."
        )

class InvalidFeatureCount(SOCError):
    def __init__(self, expected: int, got: int):
        super().__init__(
            user_message     = "A flow could not be scored due to a data format issue. "
                               "The flow has been logged for review.",
            technical_detail = f"Expected {expected} features, got {got}"
        )

# ── Agent errors ───────────────────────────────────────────────────────────
class AgentUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = "The analysis agent is temporarily unavailable. "
                               "This flow has been queued for retry.",
            technical_detail = "Claude API connection failed"
        )

class InvestigationIncomplete(SOCError):
    def __init__(self, reason: str):
        super().__init__(
            user_message     = "The investigation could not be completed. "
                               "This flow has been escalated to a human analyst.",
            technical_detail = f"Agent limit hit: {reason}"
        )

class InjectionDetected(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = "This flow contains content that cannot be safely analyzed. "
                               "It has been flagged for human review.",
            technical_detail = "Input rail triggered — injection pattern detected"
        )

# ── OSINT errors ───────────────────────────────────────────────────────────
class OSINTUnavailable(SOCError):
    def __init__(self, tool_name: str):
        super().__init__(
            user_message     = f"External threat intelligence ({tool_name}) is currently unavailable. "
                               f"The analysis will proceed with available signals only.",
            technical_detail = f"{tool_name} API returned non-200 response"
        )

# ── Guardrails errors ──────────────────────────────────────────────────────
class GuardrailsUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message     = "The security guardrails service is unavailable. "
                               "Processing has been paused for safety.",
            technical_detail = "NeMo guardrails sidecar connection refused"
        )

class ToolCallRejected(SOCError):
    def __init__(self, tool_name: str, reason: str):
        super().__init__(
            user_message     = f"A security check prevented an action from being taken. "
                               f"This flow has been escalated for review.",
            technical_detail = f"Tool '{tool_name}' rejected by output rail: {reason}"
        )

class FindingInconsistent(SOCError):
    def __init__(self, reason: str):
        super().__init__(
            user_message     = "The analysis produced an inconsistent result and has been "
                               "flagged for human review.",
            technical_detail = f"Consistency check failed: {reason}"
        )
```

---

## FastAPI Exception Handler

Add to every service's main.py:

```python
# In every ml_main.py, agent_main.py, etc.

from fastapi import Request
from fastapi.responses import JSONResponse
from src.infra.infra_errors import SOCError
import structlog

log = structlog.get_logger()

@app.exception_handler(SOCError)
async def soc_error_handler(request: Request, exc: SOCError):
    # Log technical detail
    log.error(
        "soc_error",
        user_message     = exc.user_message,
        technical_detail = exc.technical_detail,
        path             = str(request.url),
    )
    # Return plain English to user
    return JSONResponse(
        status_code = 400,
        content     = {
            "error":   exc.user_message,
            "request_id": request.headers.get("x-request-id", "unknown"),
        }
    )

@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    log.error("unexpected_error", error=str(exc), path=str(request.url))
    return JSONResponse(
        status_code = 500,
        content     = {
            "error": "An unexpected error occurred. Our team has been notified.",
            "request_id": request.headers.get("x-request-id", "unknown"),
        }
    )
```

---

## Structlog Configuration (Logging with Redaction)

```python
# Add to every service's main.py before anything else

import structlog
from src.infra.infra_redaction import redact

def redaction_processor(logger, method, event_dict):
    """Structlog processor — redact all string values before logging."""
    for key, value in event_dict.items():
        if isinstance(value, str):
            event_dict[key] = redact(value)
    return event_dict

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        redaction_processor,                   # redact before any output
        structlog.processors.JSONRenderer(),   # structured JSON output
    ],
    wrapper_class    = structlog.make_filtering_bound_logger(20),  # INFO level
    context_class    = dict,
    logger_factory   = structlog.PrintLoggerFactory(),
)
```

---

## Docker Compose — Vault Service

```yaml
vault:
  image: hashicorp/vault:latest
  environment:
    VAULT_DEV_ROOT_TOKEN_ID:   ${VAULT_TOKEN}
    VAULT_DEV_LISTEN_ADDRESS:  0.0.0.0:8200
  ports:
    - "8200:8200"
  cap_add:
    - IPC_LOCK

# vault_init container runs once to seed secrets
vault-init:
  image: hashicorp/vault:latest
  depends_on:
    - vault
  environment:
    VAULT_ADDR:  http://vault:8200
    VAULT_TOKEN: ${VAULT_TOKEN}
  command: |
    sh -c "
      sleep 5
      vault kv put secret/soc-agent/claude_api_key value=${CLAUDE_API_KEY}
      vault kv put secret/soc-agent/virustotal_api_key value=${VIRUSTOTAL_API_KEY}
      vault kv put secret/soc-agent/abuseipdb_api_key value=${ABUSEIPDB_API_KEY}
      vault kv put secret/soc-agent/alienvault_api_key value=${ALIENVAULT_API_KEY}
      vault kv put secret/soc-agent/greynoise_api_key value=${GREYNOISE_API_KEY}
      vault kv put secret/soc-agent/shodan_api_key value=${SHODAN_API_KEY}
      vault kv put secret/soc-agent/db_password value=${DB_PASSWORD}
      vault kv put secret/soc-agent/redis_password value=${REDIS_PASSWORD}
      vault kv put secret/soc-agent/service_token value=${SERVICE_TOKEN}
      echo 'Vault secrets initialized.'
    "
```

---

## .env.example

```bash
# .env.example
# Copy to .env and fill in values
# NEVER commit .env to git

# Vault
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=your-vault-root-token

# Secrets (loaded into Vault by vault-init container)
CLAUDE_API_KEY=sk-ant-...
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
ALIENVAULT_API_KEY=...
GREYNOISE_API_KEY=...
SHODAN_API_KEY=...

# Database
DB_PASSWORD=your-db-password

# Redis
REDIS_PASSWORD=your-redis-password

# Service token (for service-to-service auth)
SERVICE_TOKEN=your-service-token

# PostgreSQL root (for migrate container only)
POSTGRES_PASSWORD=your-postgres-password
```
