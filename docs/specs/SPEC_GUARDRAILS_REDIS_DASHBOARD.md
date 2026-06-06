# SPEC_GUARDRAILS.md
# Guardrails Sidecar Specification
# All decisions final. Implement exactly as specified.

---

## Overview

NeMo Guardrails runs as a separate sidecar service. The agent calls it at four interception points. It authenticates via service token from Vault.

---

## File Structure

```
src/guardrails/
  guardrails_main.py         ← FastAPI entry point
  guardrails_router.py       ← all routes
  guardrails_schemas.py      ← Pydantic models
  guardrails_dependencies.py ← FastAPI dependencies
  guardrails_service.py      ← rail logic
```

---

## Four Interception Points

```
Point 1: POST /guardrails/check_input
  Called before agent sees flow data
  Scans all flow field values for injection

Point 2: POST /guardrails/check_tool_call
  Called before each tool call executes
  Validates tool name, arguments, constraints

Point 3: POST /guardrails/check_tool_result
  Called after each tool result returns
  Sanitizes injection patterns in results

Point 4: POST /guardrails/check_finding
  Called before final finding is written
  Validates consistency of risk vs conclusion
```

---

## guardrails_schemas.py

```python
# src/guardrails/guardrails_schemas.py

from pydantic import BaseModel
from typing import Optional, Dict, Any

class InputCheckRequest(BaseModel):
    flow_id:     str
    flow_fields: Dict[str, Any]

class InputCheckResponse(BaseModel):
    approved:    bool
    reason:      Optional[str]
    rail_type:   Optional[str]

class ToolCallCheckRequest(BaseModel):
    flow_id:   str
    tool_name: str
    tool_args: Dict[str, Any]
    flow:      Dict[str, Any]   # original flow for validation

class ToolCallCheckResponse(BaseModel):
    approved:  bool
    reason:    Optional[str]

class ToolResultCheckRequest(BaseModel):
    flow_id:     str
    tool_name:   str
    tool_result: str

class ToolResultCheckResponse(BaseModel):
    sanitized_result: str
    was_modified:     bool

class FindingCheckRequest(BaseModel):
    flow_id:        str
    risk_level:     str
    classifier_score: float
    explanation:    str
    firewall_rule:  Optional[str]
    limit_hit:      bool

class FindingCheckResponse(BaseModel):
    approved:  bool
    reason:    Optional[str]
```

---

## guardrails_service.py

```python
# src/guardrails/guardrails_service.py

import re
import ipaddress
from src.guardrails.guardrails_schemas import (
    InputCheckRequest, InputCheckResponse,
    ToolCallCheckRequest, ToolCallCheckResponse,
    ToolResultCheckRequest, ToolResultCheckResponse,
    FindingCheckRequest, FindingCheckResponse,
)

# Input rail patterns
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

def check_input(request: InputCheckRequest) -> InputCheckResponse:
    """Point 1 — scan flow fields before agent sees them."""

    for field_name, field_value in request.flow_fields.items():
        value_str = str(field_value).lower()

        # Check field length
        if len(str(field_value)) > MAX_FIELD_LENGTH:
            return InputCheckResponse(
                approved  = False,
                reason    = f"Field '{field_name}' exceeds maximum length ({MAX_FIELD_LENGTH} chars).",
                rail_type = 'oversized_field'
            )

        # Check injection patterns
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, value_str, re.IGNORECASE):
                return InputCheckResponse(
                    approved  = False,
                    reason    = f"Potential prompt injection detected in field '{field_name}'.",
                    rail_type = 'prompt_injection'
                )

        # Check code patterns
        for pattern in CODE_PATTERNS:
            if re.search(pattern, value_str, re.IGNORECASE):
                return InputCheckResponse(
                    approved  = False,
                    reason    = f"Suspicious code pattern detected in field '{field_name}'.",
                    rail_type = 'code_injection'
                )

    return InputCheckResponse(approved=True, reason=None, rail_type=None)

def check_tool_call(request: ToolCallCheckRequest) -> ToolCallCheckResponse:
    """Point 2 — validate tool call before execution."""

    tool = request.tool_name
    args = request.tool_args
    flow = request.flow

    # OSINT tools — must target external IP
    osint_tools = {'lookup_ip_vt', 'lookup_ip_abuse', 'lookup_threats',
                   'check_scanner', 'whois_domain', 'lookup_ports'}

    if tool in osint_tools:
        target_ip = args.get('ip_address', '')
        if target_ip and _is_rfc1918(target_ip):
            return ToolCallCheckResponse(
                approved = False,
                reason   = "OSINT tools cannot be called on internal IP addresses."
            )

    # generate_rule validation
    if tool == 'generate_rule':
        src_ip = args.get('src_ip', '')
        action = args.get('action', '')
        port   = args.get('dst_port')

        if src_ip != flow.get('src_ip', ''):
            return ToolCallCheckResponse(
                approved = False,
                reason   = "Firewall rule target must match the flow's source IP."
            )

        if action not in ('DROP', 'REJECT'):
            return ToolCallCheckResponse(
                approved = False,
                reason   = "Firewall rule action must be DROP or REJECT."
            )

        if port and (not isinstance(port, int) or not 1 <= port <= 65535):
            return ToolCallCheckResponse(
                approved = False,
                reason   = "Firewall rule port must be an integer between 1 and 65535."
            )

    # escalate validation
    if tool == 'escalate':
        if not args.get('reason', '').strip():
            return ToolCallCheckResponse(
                approved = False,
                reason   = "Escalation must include a non-empty reason."
            )
        if args.get('priority') not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            return ToolCallCheckResponse(
                approved = False,
                reason   = "Escalation priority must be LOW, MEDIUM, HIGH, or CRITICAL."
            )

    return ToolCallCheckResponse(approved=True, reason=None)

def check_tool_result(request: ToolResultCheckRequest) -> ToolResultCheckResponse:
    """Point 3 — sanitize tool results before agent reads them."""

    result      = request.tool_result
    was_modified = False

    result_lower = result.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, result_lower, re.IGNORECASE):
            result       = "[Tool result contained suspicious content and was sanitized.]"
            was_modified = True
            break

    return ToolResultCheckResponse(
        sanitized_result = result,
        was_modified     = was_modified
    )

def check_finding(request: FindingCheckRequest) -> FindingCheckResponse:
    """Point 4 — validate finding consistency before writing."""

    risk          = request.risk_level
    score         = request.classifier_score
    explanation   = request.explanation.lower()
    has_rule      = bool(request.firewall_rule)
    limit_hit     = request.limit_hit

    # CRITICAL/HIGH must not conclude benign
    if risk in ('CRITICAL', 'HIGH'):
        benign_phrases = ['no action needed', 'benign', 'safe traffic', 'normal behavior']
        if any(phrase in explanation for phrase in benign_phrases):
            return FindingCheckResponse(
                approved = False,
                reason   = "A HIGH/CRITICAL risk flow cannot conclude as benign."
            )

    # BENIGN must not recommend blocking
    if risk == 'BENIGN' and has_rule:
        return FindingCheckResponse(
            approved = False,
            reason   = "A BENIGN flow cannot have a firewall rule."
        )

    # limit_hit must not have a rule
    if limit_hit and has_rule:
        return FindingCheckResponse(
            approved = False,
            reason   = "Cannot generate a firewall rule when investigation was incomplete."
        )

    return FindingCheckResponse(approved=True, reason=None)

def _is_rfc1918(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
```

---

## guardrails_router.py

```python
# src/guardrails/guardrails_router.py

from fastapi import APIRouter, Header, HTTPException
from src.guardrails.guardrails_schemas import (
    InputCheckRequest, InputCheckResponse,
    ToolCallCheckRequest, ToolCallCheckResponse,
    ToolResultCheckRequest, ToolResultCheckResponse,
    FindingCheckRequest, FindingCheckResponse,
)
from src.guardrails.guardrails_service import (
    check_input, check_tool_call, check_tool_result, check_finding
)
from src.infra.infra_vault import get_secret

router = APIRouter(prefix="/guardrails", tags=["guardrails"])

def verify_service_token(authorization: str = Header(...)):
    """Authenticate service-to-service calls via token from Vault."""
    expected = f"Bearer {get_secret('service_token')}"
    if authorization != expected:
        raise HTTPException(status_code=403, detail="Invalid service token.")

@router.post("/check_input", response_model=InputCheckResponse)
def api_check_input(request: InputCheckRequest,
                    _=verify_service_token) -> InputCheckResponse:
    return check_input(request)

@router.post("/check_tool_call", response_model=ToolCallCheckResponse)
def api_check_tool_call(request: ToolCallCheckRequest,
                        _=verify_service_token) -> ToolCallCheckResponse:
    return check_tool_call(request)

@router.post("/check_tool_result", response_model=ToolResultCheckResponse)
def api_check_tool_result(request: ToolResultCheckRequest,
                          _=verify_service_token) -> ToolResultCheckResponse:
    return check_tool_result(request)

@router.post("/check_finding", response_model=FindingCheckResponse)
def api_check_finding(request: FindingCheckRequest,
                      _=verify_service_token) -> FindingCheckResponse:
    return check_finding(request)

@router.get("/health")
def health():
    return {"status": "ok", "service": "guardrails"}
```

---
---
---

# SPEC_REDIS.md
# Redis Infrastructure Specification
# All decisions final. Implement exactly as specified.

---

## File Structure

```
src/infra/
  infra_redis.py    ← Redis client + connection
```

---

## infra_redis.py

```python
# src/infra/infra_redis.py

import redis
import json
from src.infra.infra_vault import get_secret

_redis_client = None

def get_redis_client() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis(
            host     = 'redis',
            port     = 6379,
            password = get_secret('redis_password'),
            decode_responses = True,
        )
    return _redis_client
```

---

## Docker Compose — Redis Service

```yaml
redis:
  image: redis:7
  command: >
    redis-server
    --requirepass ${REDIS_PASSWORD}
    --appendonly yes
    --appendfsync everysec
    --save 60 1000
    --save 300 100
    --save 900 1
  ports:
    - "6379:6379"
  volumes:
    - redis_data:/data
  healthcheck:
    test: ["CMD", "redis-cli", "ping"]
    interval: 10s
    timeout: 5s
    retries: 5
```

---

## Key Schema (All Redis Keys)

```
profile:{ip}              → machine profile (TTL 3600s)
buffer:{ip}               → new machine buffer flows 1-9 (TTL 3600s, resets)
session:{ip}              → incident session context (TTL 1800s, resets)
reqtype:{protocol}:{port} → request type profile cache (TTL 3600s)
osint:{target}:{tool}     → OSINT API result cache (TTL varies per tool)

Streams:
  network-flows            → all flows (MAXLEN 100,000)
  high-risk-flows          → escalated flows (MAXLEN 10,000)
```

---
---
---

# SPEC_DASHBOARD.md
# Streamlit Dashboard Specification
# All decisions final. Implement exactly as specified.

---

## File Structure

```
src/dashboard/
  dashboard_main.py        ← Streamlit entry point
  dashboard_components.py  ← reusable UI components
```

---

## dashboard_main.py

```python
# src/dashboard/dashboard_main.py

import streamlit as st
import pandas as pd
import time
import json
from src.infra.infra_db import get_db_session

st.set_page_config(
    page_title = "SOC Agent Dashboard",
    page_icon  = "🛡️",
    layout     = "wide",
    initial_sidebar_state = "expanded"
)

REFRESH_INTERVAL = 5  # seconds

RISK_COLORS = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MEDIUM':   '🟡',
    'LOW':      '🔵',
    'BENIGN':   '🟢',
}

def load_recent_alerts(db, limit=50) -> pd.DataFrame:
    rows = db.execute("""
        SELECT
            sa.alert_id,
            sa.flow_id,
            sa.risk_level,
            sa.classifier_score,
            sa.deviation_score,
            sa.machine_confidence,
            sa.explanation,
            sa.firewall_rule,
            sa.tools_called,
            sa.osint_results,
            sa.limit_hit,
            sa.escalated_to_human,
            sa.created_at,
            nf.src_ip,
            nf.dst_ip,
            nf.dst_port,
            nf.protocol,
            nf.totlen_fwd_pkts + nf.totlen_bwd_pkts AS total_bytes
        FROM security_alerts sa
        LEFT JOIN network_flows nf ON sa.flow_id = nf.flow_id
        ORDER BY sa.created_at DESC
        LIMIT %s
    """, (limit,)).fetchall()
    return pd.DataFrame(rows) if rows else pd.DataFrame()

def load_stats(db) -> dict:
    row = db.execute("""
        SELECT
            COUNT(*) AS total_alerts,
            SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN risk_level = 'HIGH'     THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN risk_level = 'MEDIUM'   THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN escalated_to_human THEN 1 ELSE 0 END) AS escalated,
            SUM(CASE WHEN limit_hit THEN 1 ELSE 0 END) AS limit_hit_count
        FROM security_alerts
        WHERE created_at > NOW() - INTERVAL '1 hour'
    """).fetchone()
    return dict(row) if row else {}

def load_flow_stats(db) -> dict:
    row = db.execute("""
        SELECT COUNT(*) AS total_flows
        FROM network_flows
        WHERE created_at > NOW() - INTERVAL '1 hour'
    """).fetchone()
    return dict(row) if row else {}

def render_stats_panel(stats: dict, flow_stats: dict):
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Flows (1hr)",   flow_stats.get('total_flows', 0))
    col2.metric("Alerts (1hr)",  stats.get('total_alerts', 0))
    col3.metric("🔴 Critical",   stats.get('critical', 0))
    col4.metric("🟠 High",       stats.get('high', 0))
    col5.metric("👤 Escalated",  stats.get('escalated', 0))

def render_alert_row(alert: dict):
    risk     = alert.get('risk_level', 'UNKNOWN')
    icon     = RISK_COLORS.get(risk, '⚪')
    src_ip   = alert.get('src_ip', 'unknown')
    dst_ip   = alert.get('dst_ip', 'unknown')
    dst_port = alert.get('dst_port', 0)
    bytes_   = alert.get('total_bytes', 0)

    with st.expander(
        f"{icon} [{risk}]  {src_ip} → {dst_ip}:{dst_port}  "
        f"({bytes_:,} bytes)  —  {alert.get('created_at', '')}"
    ):
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Scores**")
            st.write(f"Classifier:  {alert.get('classifier_score', 0):.1%}")
            st.write(f"Deviation:   {alert.get('deviation_score', 0):.1%}")
            st.write(f"Confidence:  {alert.get('machine_confidence', 0):.1%}")

            st.markdown("**Tools Called**")
            tools = alert.get('tools_called', [])
            st.write(", ".join(tools) if tools else "none")

            if alert.get('limit_hit'):
                st.warning("⚠️ Investigation was incomplete — budget limit reached.")
            if alert.get('escalated_to_human'):
                st.info("👤 Escalated to human analyst for review.")

        with col2:
            st.markdown("**Finding**")
            st.write(alert.get('explanation', 'No explanation available.'))

            rule = alert.get('firewall_rule')
            if rule:
                st.markdown("**Recommended Firewall Rule**")
                st.code(rule, language='bash')

            osint = alert.get('osint_results', {})
            if osint:
                st.markdown("**OSINT Results**")
                if isinstance(osint, str):
                    try:
                        osint = json.loads(osint)
                    except:
                        osint = {}
                for tool_name, result in osint.items():
                    if isinstance(result, dict) and 'summary' in result:
                        st.write(f"• {result['summary']}")

def main():
    st.title("🛡️ Network Traffic Analysis SOC Agent")

    db = get_db_session()

    # Auto-refresh
    placeholder = st.empty()
    with placeholder.container():

        # Stats
        stats      = load_stats(db)
        flow_stats = load_flow_stats(db)
        render_stats_panel(stats, flow_stats)

        st.divider()

        # Alerts feed
        st.subheader("Live Security Alerts")
        alerts_df = load_recent_alerts(db)

        if alerts_df.empty:
            st.info("No alerts yet. Waiting for flows...")
        else:
            for _, alert in alerts_df.iterrows():
                render_alert_row(alert.to_dict())

    time.sleep(REFRESH_INTERVAL)
    st.rerun()

if __name__ == "__main__":
    main()
```

---

## Docker Compose — Dashboard Service

```yaml
dashboard:
  build: .
  command: streamlit run src/dashboard/dashboard_main.py --server.port 8501
  ports:
    - "8501:8501"
  depends_on:
    - postgres
    - redis
  environment:
    VAULT_ADDR:  ${VAULT_ADDR}
    VAULT_TOKEN: ${VAULT_TOKEN}
```
