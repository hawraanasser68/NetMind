# NetMind — AI-Powered SOC Agent

NetMind is a real-time network threat detection system that listens to live network traffic, scores every flow using a trained ML classifier, and automatically investigates high-risk events using an AI agent backed by external threat intelligence tools. Results are surfaced to a security analyst dashboard with a human review queue for cases that require manual decision-making.

---

## What It Does

1. **Ingests** raw network flow data (CICIDS2018 CSV or live capture)
2. **Classifies** every flow with a LightGBM model (33 features, 3-class: benign / suspicious / attack)
3. **Scores** risk using ML confidence + deviation from the machine's behavioral baseline
4. **Investigates** high-risk flows autonomously — queries VirusTotal, AbuseIPDB, AlienVault OTX, WHOIS, Shodan, and the machine's own history via RAG
5. **Generates** firewall rules or escalates to a human analyst when evidence is inconclusive
6. **Displays** everything on a live Streamlit dashboard that refreshes every 10 seconds

---

## Architecture

```
Network Traffic
      │
      ▼
  [Ingest] ──► Redis Stream: network-flows
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
      [Logger]  [Profiler] [Classifier Worker]
      (raw DB)  (baselines)      │
                            high-risk-flows
                                 │
                         [Agent Worker × 3]
                          Input Guard → LLM Loop → Finding Guard
                                 │
                           PostgreSQL
                                 │
                          [Dashboard :8501]
```

Full detailed flow diagram: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

## Risk Levels

| Level | Condition | Agent investigates? |
|---|---|---|
| **CRITICAL** | risk_score ≥ 0.80 | Yes |
| **HIGH** | risk_score ≥ 0.50 · or new machine (< 10 flows) | Yes |
| **MEDIUM** | deviation above low threshold | No — monitor only |
| **LOW** | all normal | No |

`risk_score = 0.6 × classifier_score + 0.4 × deviation_score`

---

## Guardrails

The AI agent is wrapped by four guardrails:

| # | Stage | What it checks |
|---|---|---|
| **G1 Input** | Before LLM sees data | Prompt injection in flow fields, oversized inputs |
| **G2 Tool Call** | Before each tool executes | Invalid targets (e.g. OSINT on internal IP), malformed args |
| **G3 Result** | After each tool returns | Injection patterns in external API responses |
| **G4 Finding** | Before writing to DB | Finding contradicts evidence (benign phrases + block rule, limit hit + rule) |

---

## Stack

| Layer | Technology |
|---|---|
| ML Classifier | LightGBM · scikit-learn |
| AI Agent | Anthropic Claude Sonnet 4.6 (fallback: Groq llama-3.3-70b) |
| Streaming | Redis Streams |
| Database | PostgreSQL 16 + pgvector |
| Secrets | HashiCorp Vault |
| Dashboard | Streamlit |
| Threat Intel | VirusTotal · AbuseIPDB · AlienVault OTX · Shodan · WHOIS |
| Container | Docker Compose |

---

## Quick Start

**Prerequisites:** Docker Desktop, a `.env` file with API keys (see below)

```bash
# Clone
git clone https://github.com/hawraanasser68/NetMind
cd NetMind

# Start all services
docker compose up -d

# Open dashboard
open http://localhost:8501
```

### Run a pipeline test (ingest sample CSV rows)

```bash
docker compose run --rm classifier-worker \
  python -m src.data.data_ingest \
  /path/to/CICIDS2018.csv --rows 500
```

---

## Environment Variables

Create a `.env` file in the project root:

```env
# PostgreSQL
POSTGRES_PASSWORD=...
DASHBOARD_DB_PASSWORD=...

# Redis
REDIS_PASSWORD=...

# Vault
VAULT_TOKEN=...

# API keys (stored in Vault at runtime)
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
SHODAN_API_KEY=...
ANTHROPIC_API_KEY=...
GROQ_API_KEY=...
```

---

## Services

| Service | Port | Description |
|---|---|---|
| `dashboard` | 8501 | Streamlit analyst dashboard |
| `classifier` | 8001 | LightGBM inference API |
| `guardrails` | 8004 | Guardrail screening API |
| `agent` | 8003 | Agent HTTP API |
| `agent-worker` × 3 | — | Inline agent consumers |
| `logger` | — | Raw flow writer |
| `profiler` | — | Machine behavioral profiler |
| `classifier-worker` | — | Flow scoring + routing |
| `postgres` | 5432 | Primary database |
| `redis` | 6379 | Stream broker + profile cache |
| `vault` | 8200 | Secrets management |

---

## Project Structure

```
src/
  agent/        # AI agent: tool loop, session context, investigation logic
  data/         # Ingest, workers (logger, classifier, profiler, agent)
  dashboard/    # Streamlit UI
  guardrails/   # Four-layer guardrail service
  infra/        # DB, Redis, Vault, logging
  llm/          # LLM client (Anthropic + Groq fallback)
  ml/           # LightGBM classifier service
  profiles/     # Machine behavioral profiles + RAG snapshots
  scoring/      # Risk scoring and level assignment

migrations/     # Alembic DB schema migrations
models/         # Trained classifier (soc_classifier.pkl)
config/         # Deviation weights
tests/          # Unit + integration tests
docs/           # Architecture diagram, decision log
```

---

## Dataset

Trained on [CICIDS2018](https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv) — 1.5M+ labeled network flows covering benign traffic, DoS, DDoS, brute-force, infiltration, and botnet attacks.
