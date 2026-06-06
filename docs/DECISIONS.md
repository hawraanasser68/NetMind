# DECISIONS.md
# Network Traffic Analysis SOC Agent
# Complete Decision Register — All decisions final before implementation

---

## Decision 1 — Feature Contract

**Choice**: 33 features from CICIDS2018 / CICFlowMeter intersection

**Features**:
```
Volume:       Tot Fwd Pkts, Tot Bwd Pkts, TotLen Fwd Pkts, TotLen Bwd Pkts
Rate:         Flow Byts/s, Flow Pkts/s, Fwd Pkts/s, Bwd Pkts/s
Timing:       Flow Duration, Flow IAT Mean, Flow IAT Std,
              Fwd IAT Mean, Fwd IAT Std, Bwd IAT Mean, Bwd IAT Std
Active/Idle:  Active Mean, Active Std, Idle Mean, Idle Std
TCP Flags:    SYN Flag Cnt, FIN Flag Cnt, RST Flag Cnt,
              PSH Flag Cnt, ACK Flag Cnt, URG Flag Cnt
Packet size:  Pkt Len Mean, Pkt Len Std, Down/Up Ratio
Derived:      byte_ratio, proto_tcp, proto_udp, proto_icmp, is_privileged_port
```

**Cleaning rules**:
- Drop rows where Flow Duration < 0
- Replace inf with 0 in rate columns
- Fill remaining nulls with 0

**Payload entropy**: not a classifier feature. Computed at runtime by CICFlowMeter. Used by behavioral baseline as a deviation signal. Stored in behavioral profile table.

**Rationale**: Features selected from intersection of CICIDS2018 columns and CICFlowMeter runtime output. Ensures zero training-serving skew.

---

## Decision 2 — Label Schema and Train/Test Split

**Label mapping**:
```
Benign (0):      Benign
Suspicious (1):  Infilteration
Attack (2):      FTP-BruteForce, SSH-Bruteforce, BruteForce-Web,
                 BruteForce-XSS, SQL-Injection, DoS-Slowloris,
                 DoS-Slowhttptest, DoS-Hulk, DoS-GoldenEye,
                 DDoS-HOIC, DDoS-LOIC-UDP, DDoS-LOIC-HTTP,
                 Bot, Heartbleed
```

**Train/test split**:
```
Train: Feb 14, 15, 16, 22, 23
Test:  Feb 28 + Mar 01 (strictly more recent, never seen during training)
```

**Cross-validation**: TimeSeriesSplit — validation window always moves forward in time. Never validate on data older than training data.

**Rationale**: Infiltration mapped to Suspicious because it is designed to look normal — the classifier should be uncertain about it. That uncertainty triggers the behavioral baseline. Temporal split reflects real-world validation conditions.

---

## Decision 3 — Behavioral Profile Schema

**Table: machine_profiles**
```
PRIMARY KEY:    machine_ip (TEXT)
TIMESTAMPS:     first_seen, last_seen, updated_at
COUNTER:        observation_count
WELFORD SETS:   bytes (bytes_mean, bytes_std, bytes_m2)
                pkts (pkts_mean, pkts_std, pkts_m2)
                duration (duration_mean, duration_std, duration_m2)
                entropy (entropy_mean, entropy_std, entropy_m2) ← runtime only
ARRAYS:         typical_dst_ports (INTEGER[], cap 100)
                typical_protocols (INTEGER[])
                typical_dst_ips (TEXT[], cap 100)
                active_hours (INTEGER[], fixed length 24)
COUNTERS:       external_conn_count, internal_conn_count
                smb_conn_count, dns_conn_count
                http_conn_count, https_conn_count, rdp_conn_count
CONFIDENCE:     confidence (FLOAT, 0.0 to 1.0)
```

**Table: request_type_profiles**
```
PRIMARY KEY:    (protocol INTEGER, dst_port INTEGER) composite
COUNTER:        observation_count
WELFORD SETS:   bytes, pkts, duration, entropy,
                byte_ratio, bytes_per_sec
TIMESTAMP:      updated_at
```

**Bootstrap**: request_type_profiles populated from CICIDS2018 benign flows (all days). machine_profiles start empty, build from live traffic only.

**Confidence**: confidence = min(observation_count / 100, 1.0)

**Rationale**: Welford stored as three separate columns (mean, std, m2) not tuples. Each column is independently queryable and updatable. Arrays capped to prevent unbounded growth.

---

## Decision 4 — Deviation Score Formula

**Classifier score**:
```python
proba = classifier.predict_proba([features])[0]
classifier_score = proba[1] + proba[2]   # suspicious + attack probability
```

**Effective deviation**:
```python
effective_deviation = deviation_score × machine_confidence
machine_confidence  = min(observation_count / 100, 1.0)
```

**Routing logic (Option B — Threshold Gate)**:
```python
if classifier_score >= 0.8:                                  → CRITICAL
if classifier_score >= 0.5 and effective_deviation >= 0.7:   → HIGH
if classifier_score >= 0.5 or  effective_deviation >= 0.8:   → MEDIUM
if effective_deviation >= 0.6 and machine_confidence < 0.3:  → LOW
else:                                                         → BENIGN
```

**Escalation policy**:
```
CRITICAL → agent immediately
HIGH     → agent immediately
MEDIUM   → agent if budget allows, else log + flag
LOW      → log only, update profiles
BENIGN   → log only, update profiles
```

**Thresholds**: stored in config/deviation_weights.yaml. Not hardcoded.

**Agent context** (sent on escalation):
```
classifier_score, benign_probability, suspicious_probability,
attack_probability, deviation_score, machine_confidence,
effective_deviation, risk_level
```

**Rationale**: Option B chosen over weighted average because every escalation has an explicit, auditable reason. Confidence modifier prevents false positives on new machines.

---

## Decision 5 — Deviation Score Computation

**Z-score normalization**:
```python
normalized_z = 1 - exp(-abs(Z) / 3)
# Maps any Z to 0-1. Z=3 → 0.63. Z=10 → 0.96. Z=82 → 1.00
```

**Safe Z-score** (handles std=0):
```python
def safe_z(observed, mean, std):
    if std == 0:
        return 0.0 if observed == mean else 3.0
    return (observed - mean) / std
```

**Feature weights** (stored in config/deviation_weights.yaml):
```yaml
z_bytes_machine:       0.25
z_bytes_per_sec:       0.20
z_bytes_request_type:  0.15
z_byte_ratio:          0.10
z_pkts_machine:        0.05
z_duration_machine:    0.05
new_port:              0.08
off_hours:             0.07
external_first:        0.03
new_protocol:          0.02
```

**Two-component formula**:
```python
deviation_score = (0.6 × effective_machine) + (0.4 × effective_req_type)
```

**Binary checks**:
```
new_port:       1 if dst_port not in typical_dst_ports else 0
new_protocol:   1 if protocol not in typical_protocols else 0
new_dst_ip:     1 if dst_ip not in typical_dst_ips else 0
off_hours:      1 if active_hours[current_hour] == 0 else 0
external_first: 1 if is_external AND external_conn_count == 0 else 0
```

**Return value**: return both deviation_score AND components dict so agent knows which signals were elevated.

**Rationale**: Bytes and rate weighted highest because data exfiltration always shows as volume anomalies. Weighted average chosen over max because it balances all signals rather than letting one dominate.

---

## Decision 6 — Profile Update Strategy

**Algorithm**: Welford's online algorithm
```python
def welford_update(count, mean, M2, new_value):
    count  += 1
    delta   = new_value - mean
    mean   += delta / count
    delta2  = new_value - mean
    M2     += delta * delta2
    std     = sqrt(M2 / count) if count > 1 else 0.0
    return count, mean, M2, std
```

**What gets updated**: all flows update profiles regardless of risk level (BENIGN included).

**Write strategy**:
```
Redis cache:   updated on every flow (always current)
PostgreSQL:    written every 10 flows (durable persistence)
```

**Consumer**: profiler consumer group (independent of classifier).

**Crash recovery**: Redis Stream holds unacknowledged messages. Welford is safe to replay — replaying a flow slightly adjusts statistics but does not corrupt them.

**Correction**: classifier does NOT read machine profile. Deviation scorer reads machine profile from Redis cache.

**Rationale**: O(1) update regardless of history size. Redis as live cache eliminates database bottleneck at high flow rates.

---

## Decision 7 — Cold Start Handling

**Two-component deviation for new machines**:
```python
deviation_score = (machine_component × confidence)
                + (population_component × 0.4)
```

**Unknown port/protocol** (no machine profile AND no population profile):
- Always escalate to human
- No firewall rule generated without evidence
- After human review, population profile builds naturally

**Profile creation timing** (Option B):
```
Flows 1-9:  held in Redis buffer only
            Welford runs in memory
            No PostgreSQL row yet
            Scored using population profile only

Flow 10:    PostgreSQL row created with count=10
            More stable starting point than count=1
```

**Buffer TTL**: resets on every new flow added. Machine that sends one flow per 20 minutes still reaches count=10 eventually.

**Rationale**: Population profile (bootstrapped from CICIDS2018) provides meaningful floor of detection even for brand new machines. 10-flow buffer prevents poisoned profiles from single unusual first flows.

---

## Decision 8 — Agent Loop Bounds

**Budget**:
```yaml
max_tool_calls:   5
max_tokens:       1000
max_seconds:      30
max_concurrent:   3
```

**When limit is hit**:
```
No firewall rule generated
Flow escalated to human always
Finding logged with limit_hit=True
Confidence set to LOW
Explanation states which limit was hit
```

**Overflow**: more than 3 concurrent high-risk flows wait in high-risk-flows Redis Stream. Not dropped, just queued.

**Rationale**: Prevents cost attacks via hostile flows designed to keep agent looping. Cap is both a cost control and a security control.

---

## Decision 9 — OSINT Call Policy

**Tool list**:
```
rag_search          always first, machine behavioral history
lookup_ip_vt        VirusTotal — primary IP check (90+ vendors)
lookup_ip_abuse     AbuseIPDB — secondary, community reports
lookup_threats      AlienVault OTX — campaign intelligence
check_scanner       GreyNoise — scanner vs targeted
whois_domain        WHOIS — domain age and registration
lookup_ports        Shodan — open services on IP
generate_rule       produces firewall rule
escalate            flags for human review
```

**Four conditions** (all must be true):
```
1. dst_ip is external (not RFC1918)
2. risk_level is HIGH or CRITICAL
3. IP not in Redis OSINT cache for this tool
4. tool_calls_remaining >= 2
```

**Calling order**:
```
rag_search (always, no conditions)
→ VirusTotal (primary IP check)
→ AbuseIPDB (if VT flags > 3 vendors)
→ GreyNoise (if intent still unclear)
→ AlienVault OTX (if campaign context needed)
→ WHOIS (if domain available + budget allows)
→ Shodan (last resort, most rate limited)
→ generate_rule OR escalate (always last)
```

**Cache TTL per tool**:
```
VirusTotal:    3600s
AbuseIPDB:     3600s
GreyNoise:     1800s
AlienVault:    7200s
WHOIS:         86400s
Shodan:        3600s
```

**Rationale**: VirusTotal added as primary because it aggregates 90+ vendors in one call — more comprehensive than AbuseIPDB alone. Free tiers sufficient for demo.

---

## Decision 10 — Redis TTL Values

```
Profile cache:        3600s (1 hour)
                      active invalidation by profiler on every update
                      TTL is safety net only

Session memory:       1800s (30 minutes)
                      resets on every new suspicious flow from same machine

New machine buffer:   3600s (1 hour)
                      TTL resets on every new flow added
                      if 10 flows reached → create PostgreSQL row → delete buffer
                      if TTL expires before 10 flows → buffer deleted,
                      machine restarts from count=0 on next appearance
```

**Rationale**: Session TTL of 30 minutes covers most active attack sequences. Profile cache TTL is a safety net — primary invalidation is active (profiler updates Redis on every flow).

---

## Decision 11 — pgvector Snapshot Frequency

**Frequency**: every 100 flows per machine (triggered by observation_count % 100 == 0)

**Process**:
```
1. Generate plain text summary from profile stats
2. Embed via sentence-transformers all-MiniLM-L6-v2
3. INSERT into machine_history (pgvector table)
4. DELETE oldest rows beyond latest 10
```

**Retention**: latest 10 summaries per machine. Bounded storage, never grows indefinitely.

**Rationale**: 100 flows gives enough statistical change to justify a new snapshot. Keeping 10 gives the agent ~1000 flows of narrative history per machine.

---

## Decision 12 — Embedding Model

```
Model:      sentence-transformers all-MiniLM-L6-v2
Dimensions: 384
Cost:       free, runs locally
Hosting:    inside profiler container, no external API call
Mode:       synchronous
```

**Production path**: upgrade to OpenAI text-embedding-3-small (1,536 dimensions).

**Rationale**: Free, local, no API dependency, sufficient quality for short machine behavioral summaries.

---

## Decision 13 — Guardrails Rails

**Input rails** (block before agent sees flow):
```
Prompt injection patterns:
  "ignore previous instructions", "disregard your system prompt",
  "you are now", "forget everything", "new instructions",
  "system:", "assistant:"

Oversized fields:  any text field > 500 characters

Script/code patterns:
  <script>, eval(), exec(), DROP TABLE, SELECT *, iptables
```

**Output rails** (validate before each tool call):
```
generate_rule:
  target IP must match flow dst_ip
  action must be DROP or REJECT only
  target must be external IP
  rule must match iptables syntax exactly

escalate:
  reason must be non-empty
  priority must be LOW/MEDIUM/HIGH/CRITICAL

OSINT tools:
  target must be external IP
  must not be loopback or broadcast
```

**Consistency check** (before final finding written):
```
CRITICAL/HIGH risk → cannot conclude benign
BENIGN risk        → cannot recommend block
ATTACK label       → must recommend action
limit_hit=True     → no firewall rule generated
```

**On trigger**:
```
Input rail:   flow rejected, logged as injection_attempt,
              escalated to human, original flow preserved in audit log
Output rail:  tool call blocked, agent notified with reason,
              repeated violations → escalate to human
```

**Rationale**: Output rails fire before tool execution, not just before final response. A rule that executes before the guardrail runs causes real damage.

---

## Decision 14 — Demo PCAP Selection

```
Source:  CICIDS2018 held-out test set (never seen during training)
Files:   Feb 28 + Mar 01
Sample:  1,000 rows from Feb 28 (botnet, DDoS, port scan, benign)
         1,000 rows from Mar 01 (infiltration, benign)
Total:   2,000 flows
```

**Rationale**: Feb 28 shows classifier catching clear attacks. Mar 01 shows behavioral baseline catching infiltration the classifier alone would miss.

---

## Decision 15 — Firewall Rule Format

**Format**: iptables

```
With port:    iptables -A INPUT -s {src_ip} -p {protocol} --dport {dst_port} -j {action}
Without port: iptables -A INPUT -s {src_ip} -p {protocol} -j {action}
```

**Valid actions**: DROP, REJECT (default: DROP)

**Validation**: target IP must match flow dst_ip, protocol must be tcp/udp/icmp, port must be 1-65535, action must be DROP or REJECT.

**Production note**: iptables rules not persistent across reboots. Production would use iptables-save or integrate with firewalld/nftables.

---

## Decision 16 — Alert Display Format

**Format**: Streamlit dashboard

**Components**:
```
Live alerts feed:    auto-refresh every 5 seconds
                     color coded by risk level
                     CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue

Per alert panel:     flow info, scores, OSINT results,
                     agent finding, firewall rule, actions taken

Profile panel:       machine behavioral history,
                     typical ports, active hours chart,
                     observation count, confidence

Stats panel:         total flows, total alerts,
                     alerts by risk level, % escalated
```

**Data source**: reads from PostgreSQL security_alerts table. No direct Redis access.

---

## Decision 17 — Logging Format

**Format**: structured JSON via structlog

**Every log line includes**: timestamp, level, component, flow_id, trace_id

**Redaction patterns**:
```
API keys:        sk-[a-zA-Z0-9]{32,}
Passwords:       password=\S+
JWT tokens:      Bearer [a-zA-Z0-9._-]+
Credit cards:    \d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}
Email addresses: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
Replace with:    [REDACTED]
```

**Redaction applied at 6 points**:
```
1. Before agent prompt is built
2. Before agent response stored in PostgreSQL
3. Before dashboard displays finding
4. Before Redis session written
5. Before pgvector summary written
6. Before every structlog line written (automatic via processor)
```

**Implementation**: single redact(text) function in src/infra/infra_redaction.py. Used by every component. Never duplicated.

---

## Decision 18 — Redis Streams Consumer Topology

**Consumer groups**:
```
group: classifiers
  Reads flow → computes 33 features → scores with classifier
  → computes deviation score (reads machine profile from Redis)
  → routing decision → pushes HIGH/CRITICAL to high-risk-flows stream
  → ACKs message

group: profilers
  Reads flow → Welford update in Redis cache
  → every 10 flows writes to PostgreSQL
  → every 100 flows generates pgvector snapshot
  → ACKs message

group: loggers
  Reads flow → writes raw flow to PostgreSQL network_flows table
  → ACKs message
```

**Agent queue**: separate Redis Stream (high-risk-flows). Classifier pushes here. Agent worker consumes from here. Keeps agent decoupled from classifier.

**Crash recovery**: consumers check pending (unacknowledged) messages before reading new ones on restart.

**Duplicate protection**: logger uses INSERT ... ON CONFLICT DO NOTHING.

---

## Decision 19 — Session Scope

**Default (implemented)**: per source IP
```
key: session:{src_ip}
All suspicious flows from same machine share one session
```

**Enhancement (documented, not implemented)**: per incident cluster
```
key: session:{src_ip}:{incident_id}
Flows clustered by timing + destination + pattern similarity
Requires clustering logic before Redis lookup
```

---

## Decision 20 — Guardrail Interception Points

**Four points**:
```
Point 1 — BEFORE AGENT SEES FLOW (input rail)
  Scans all flow field values
  Blocks injection patterns, oversized fields, script/code patterns

Point 2 — BEFORE EACH TOOL CALL (output rail)
  Validates tool name, arguments, target IP, action type, syntax

Point 3 — AFTER EACH TOOL RESULT (input rail)
  Scans all text returned by OSINT tools
  Sanitizes injection patterns in results
  Agent warned if result was sanitized

Point 4 — BEFORE FINAL FINDING WRITTEN (consistency check)
  Validates risk level vs conclusion coherence
  Validates rule presence vs evidence sufficiency
```

**Implementation**: NeMo Guardrails as separate sidecar service. Agent calls sidecar via HTTP at each point. Sidecar authenticates via service token from Vault. Every interception logged with flow_id and trace_id.

---

## Additional Decisions (From Gap Analysis)

**Gap 2 — Service Authentication**: Option A — shared service token from Vault. Each service gets token at startup. Passes in Authorization header on every inter-service call. mTLS documented as production enhancement.

**Gap 3 — Docker Compose Services**:
```
postgres, redis, classifier, profiler, agent,
logger, guardrails, dashboard, vault, migrate
```
migrate runs alembic upgrade head then exits before other services start.

**Gap 4 — Migration Strategy**: Alembic migrations in migrations/versions/. migrate container applies all migrations on startup. Seed script runs after migrations if request_type_profiles table is empty (idempotent).

**Gap 5 — Error Handling**: SOCError base class with user_message and technical_detail. User sees plain English only. Technical details go to structlog only. Dashboard shows clean banners.

**Gap 6 — Feature Contract File**: src/ml/ml_feature_contract.py is single source of truth for feature names, order, count, and label mapping. Imported by both training and production code. Never duplicated.

**Gap 7 — Weights Config**: config/deviation_weights.yaml contains all thresholds and weights. Never hardcoded in application code.

**Gap 8 — Architecture**: modular monolith. One repository. Shared src/ with unique file names across entire codebase (prefix every file with module name). Separate thin containers per service.

**Database Access**: least-privilege PostgreSQL users per component. No RLS — single organization, no tenant isolation needed. Vault manages all credentials.

**Redis Persistence**: RDB + AOF (both enabled). appendfsync everysec. Maximum data loss on crash: 1 second. Volume mounted to host disk.

**MLflow**: skipped for demo. Training metrics logged to metrics.json. SHA-256 validated via model_card.json. MLflow and drift detection documented as production enhancements.

**File naming**: every file prefixed with its module name. All file names unique across entire codebase.
