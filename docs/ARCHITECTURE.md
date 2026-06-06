# ARCHITECTURE.md
# Network Traffic Analysis SOC Agent
# System Architecture Document

---

## System Overview

A production-grade network traffic analysis agent that detects threats by combining ML classification with behavioral baselining, enriched by live OSINT intelligence and reasoned about by a bounded LLM agent.

The system answers two questions simultaneously on every flow:
1. **What is this flow?** (ML classifier — trained on CICIDS2018)
2. **Is this normal for this machine?** (behavioral baseline — learned from live traffic)

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  DATA INGESTION                                             │
│  PCAP / CICIDS2018 CSV → data_ingest.py → Redis Stream     │
│  (network-flows)                                            │
└───────────────────────────┬─────────────────────────────────┘
                            │ (3 consumer groups, parallel)
            ┌───────────────┼───────────────┐
            ↓               ↓               ↓
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │  CLASSIFIERS  │ │   PROFILERS   │ │    LOGGERS    │
    │               │ │               │ │               │
    │ Extract 33    │ │ Welford       │ │ Write flow    │
    │ features      │ │ updates to    │ │ to PostgreSQL │
    │               │ │ Redis cache   │ │ network_flows │
    │ Score with    │ │               │ │ table         │
    │ ML classifier │ │ Every 10 →    │ │               │
    │               │ │ write to PG   │ │               │
    │ Compute       │ │               │ │               │
    │ deviation     │ │ Every 100 →   │ │               │
    │ score         │ │ pgvector      │ │               │
    │               │ │ snapshot      │ │               │
    │ Route flow    │ │               │ │               │
    └───────┬───────┘ └───────────────┘ └───────────────┘
            │ HIGH/CRITICAL only
            ↓
    ┌───────────────────────────────────────────────────────┐
    │  HIGH-RISK-FLOWS STREAM                               │
    │  (separate Redis Stream, max 10,000 messages)         │
    └───────────────────────────┬───────────────────────────┘
                                │
                                ↓
    ┌───────────────────────────────────────────────────────┐
    │  LLM AGENT (max 3 concurrent)                         │
    │                                                       │
    │  1. Load Redis session context                        │
    │  2. RAG: retrieve machine history from pgvector       │
    │  3. Call tools (max 5, max 30s, max 1000 tokens):     │
    │     rag_search → lookup_ip_vt → lookup_ip_abuse →     │
    │     check_scanner → lookup_threats → whois_domain →   │
    │     lookup_ports → generate_rule / escalate           │
    │                                                       │
    │  Guardrails sidecar intercepts at 4 points:           │
    │    - Before agent sees flow                           │
    │    - Before each tool call                            │
    │    - After each tool result                           │
    │    - Before final finding is written                  │
    └───────────────────────────┬───────────────────────────┘
                                │
                                ↓
    ┌───────────────────────────────────────────────────────┐
    │  STORAGE                                              │
    │                                                       │
    │  PostgreSQL:                                          │
    │    network_flows         (all flows)                  │
    │    machine_profiles      (Welford statistics)         │
    │    request_type_profiles (population statistics)      │
    │    machine_history       (pgvector narrative history) │
    │    security_alerts       (agent findings)             │
    │                                                       │
    │  Redis:                                               │
    │    profile:{ip}          (machine profile cache)      │
    │    session:{ip}          (incident context)           │
    │    buffer:{ip}           (new machine flows 1-9)      │
    │    osint:{target}:{tool} (OSINT result cache)         │
    │    Streams: network-flows, high-risk-flows            │
    └───────────────────────────────────────────────────────┘
                                │
                                ↓
    ┌───────────────────────────────────────────────────────┐
    │  STREAMLIT DASHBOARD                                  │
    │  Reads from PostgreSQL security_alerts                │
    │  Auto-refreshes every 5 seconds                       │
    │  Shows: alerts, scores, OSINT results, rules          │
    └───────────────────────────────────────────────────────┘
```

---

## Service Map

| Service | Port | Purpose |
|---------|------|---------|
| postgres | 5432 | Main database |
| redis | 6379 | Cache + streams + sessions |
| vault | 8200 | Secret management |
| classifier | 8001 | ML model HTTP API |
| guardrails | 8002 | NeMo sidecar HTTP API |
| agent | 8003 | LLM agent HTTP API |
| dashboard | 8501 | Streamlit UI |
| migrate | — | Alembic migrations (exits) |
| vault-init | — | Seeds Vault secrets (exits) |

---

## Data Flow Summary

```
1. Flow arrives (CSV or PCAP)
2. Normalized and published to network-flows stream
3. Three consumer groups process in parallel:
   a. classifiers: score + route
   b. profilers: update behavioral profiles
   c. loggers: persist to PostgreSQL
4. HIGH/CRITICAL flows pushed to high-risk-flows stream
5. Agent worker consumes from high-risk-flows:
   a. Load Redis session context
   b. RAG search in pgvector
   c. Call OSINT tools (conditions apply)
   d. Guardrails validate at each step
   e. Generate finding + firewall rule
   f. Store in PostgreSQL security_alerts
6. Streamlit dashboard reads alerts and displays in real time
```

---

## Security Architecture

```
Secret management:    HashiCorp Vault (every credential)
Service auth:         Shared service token from Vault (Bearer header)
Injection protection: NeMo Guardrails sidecar (4 interception points)
PII redaction:        infra_redaction.py (6 application points)
DB isolation:         Least-privilege users per component
Redis persistence:    RDB + AOF (max 1s data loss on crash)
Model integrity:      SHA-256 in model_card.json, validated on startup
```

---

## Module Dependencies

```
infra (no dependencies)
  ↑ imported by all modules

ml        → infra
profiles  → infra
scoring   → infra, profiles
agent     → infra, profiles, scoring
guardrails→ infra
data      → infra, ml, profiles, scoring, agent
dashboard → infra
```

---

## Production Path (Future Enhancements)

```
Current:
  Single machine deployment
  Redis Streams for message queue
  sentence-transformers for embeddings (local, free)
  ~1,000 flows/sec throughput

Production enhancements:
  Replace Redis Streams with Kafka (multi-machine, higher throughput)
  Upgrade to OpenAI text-embedding-3-small (better quality)
  Add MLflow for experiment tracking and drift detection
  Add mTLS for service-to-service authentication
  Add per-incident session scope (vs per-IP)
  Add online model retraining pipeline
  Add horizontal scaling (Kubernetes)
  Add threat intelligence feed integration
```

---
---