# SPEC_DATABASE.md
# Database Schema Specification
# All decisions final. Implement exactly as specified.

---

## Overview

Single PostgreSQL 16 instance with pgvector extension.
Two logical databases on same instance:
- socdb — application data
- mlflowdb — MLflow experiment tracking (MLflow manages its own schema)

---

## PostgreSQL Users (Least Privilege)

```sql
-- Create least-privilege users per component
CREATE USER classifier_user  WITH PASSWORD '${VAULT:classifier_db_password}';
CREATE USER profiler_user    WITH PASSWORD '${VAULT:profiler_db_password}';
CREATE USER logger_user      WITH PASSWORD '${VAULT:logger_db_password}';
CREATE USER agent_user       WITH PASSWORD '${VAULT:agent_db_password}';
CREATE USER dashboard_user   WITH PASSWORD '${VAULT:dashboard_db_password}';
CREATE USER migrate_user     WITH PASSWORD '${VAULT:migrate_db_password}';

-- Permissions per component
GRANT SELECT ON machine_profiles TO classifier_user;
GRANT SELECT ON request_type_profiles TO classifier_user;

GRANT SELECT, INSERT, UPDATE ON machine_profiles TO profiler_user;
GRANT SELECT, INSERT, UPDATE ON request_type_profiles TO profiler_user;
GRANT INSERT ON machine_history TO profiler_user;

GRANT INSERT ON network_flows TO logger_user;

GRANT SELECT ON machine_history TO agent_user;
GRANT INSERT ON security_alerts TO agent_user;
GRANT SELECT ON machine_profiles TO agent_user;

GRANT SELECT ON security_alerts TO dashboard_user;
GRANT SELECT ON network_flows TO dashboard_user;
GRANT SELECT ON machine_profiles TO dashboard_user;

GRANT ALL ON ALL TABLES IN SCHEMA public TO migrate_user;
```

---

## Extensions

```sql
CREATE EXTENSION IF NOT EXISTS vector;   -- pgvector
CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- for text search if needed
```

---

## Tables

### network_flows

```sql
CREATE TABLE network_flows (
    flow_id               VARCHAR(50)  PRIMARY KEY,
    timestamp             TIMESTAMP    NOT NULL,
    src_ip                INET         NOT NULL,
    dst_ip                INET         NOT NULL,
    src_port              INTEGER,
    dst_port              INTEGER,
    protocol              INTEGER,

    -- Volume
    tot_fwd_pkts          INTEGER,
    tot_bwd_pkts          INTEGER,
    totlen_fwd_pkts       BIGINT,
    totlen_bwd_pkts       BIGINT,

    -- Rate
    flow_byts_s           FLOAT,
    flow_pkts_s           FLOAT,
    fwd_pkts_s            FLOAT,
    bwd_pkts_s            FLOAT,

    -- Timing
    flow_duration         FLOAT,
    flow_iat_mean         FLOAT,
    flow_iat_std          FLOAT,
    fwd_iat_mean          FLOAT,
    fwd_iat_std           FLOAT,
    bwd_iat_mean          FLOAT,
    bwd_iat_std           FLOAT,

    -- Active/Idle
    active_mean           FLOAT,
    active_std            FLOAT,
    idle_mean             FLOAT,
    idle_std              FLOAT,

    -- TCP Flags
    syn_flag_cnt          INTEGER,
    fin_flag_cnt          INTEGER,
    rst_flag_cnt          INTEGER,
    psh_flag_cnt          INTEGER,
    ack_flag_cnt          INTEGER,
    urg_flag_cnt          INTEGER,

    -- Packet size
    pkt_len_mean          FLOAT,
    pkt_len_std           FLOAT,
    down_up_ratio         FLOAT,

    -- Derived
    byte_ratio            FLOAT,
    proto_tcp             INTEGER,
    proto_udp             INTEGER,
    proto_icmp            INTEGER,
    is_privileged_port    INTEGER,

    -- Scores (set after scoring)
    classifier_score      FLOAT,
    deviation_score       FLOAT,
    effective_deviation   FLOAT,
    risk_level            VARCHAR(20),

    created_at            TIMESTAMP    DEFAULT NOW()
);

CREATE INDEX idx_flows_timestamp ON network_flows(timestamp);
CREATE INDEX idx_flows_src_ip    ON network_flows(src_ip);
CREATE INDEX idx_flows_dst_ip    ON network_flows(dst_ip);
CREATE INDEX idx_flows_risk      ON network_flows(risk_level);
```

---

### machine_profiles

```sql
CREATE TABLE machine_profiles (
    machine_ip              TEXT         PRIMARY KEY,

    -- Timestamps
    first_seen              TIMESTAMP,
    last_seen               TIMESTAMP,
    updated_at              TIMESTAMP,

    -- Counter
    observation_count       INTEGER      DEFAULT 0,

    -- Welford: bytes
    bytes_mean              FLOAT        DEFAULT 0.0,
    bytes_std               FLOAT        DEFAULT 0.0,
    bytes_m2                FLOAT        DEFAULT 0.0,

    -- Welford: packets
    pkts_mean               FLOAT        DEFAULT 0.0,
    pkts_std                FLOAT        DEFAULT 0.0,
    pkts_m2                 FLOAT        DEFAULT 0.0,

    -- Welford: duration
    duration_mean           FLOAT        DEFAULT 0.0,
    duration_std            FLOAT        DEFAULT 0.0,
    duration_m2             FLOAT        DEFAULT 0.0,

    -- Welford: entropy (runtime only, not from CICIDS2018)
    entropy_mean            FLOAT        DEFAULT 0.0,
    entropy_std             FLOAT        DEFAULT 0.0,
    entropy_m2              FLOAT        DEFAULT 0.0,

    -- Arrays
    typical_dst_ports       INTEGER[]    DEFAULT '{}',
    typical_protocols       INTEGER[]    DEFAULT '{}',
    typical_dst_ips         TEXT[]       DEFAULT '{}',
    active_hours            INTEGER[]    DEFAULT '{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}',

    -- Connection counters
    external_conn_count     INTEGER      DEFAULT 0,
    internal_conn_count     INTEGER      DEFAULT 0,
    smb_conn_count          INTEGER      DEFAULT 0,
    dns_conn_count          INTEGER      DEFAULT 0,
    http_conn_count         INTEGER      DEFAULT 0,
    https_conn_count        INTEGER      DEFAULT 0,
    rdp_conn_count          INTEGER      DEFAULT 0,

    -- Confidence
    confidence              FLOAT        DEFAULT 0.0
);

CREATE INDEX idx_profiles_confidence ON machine_profiles(confidence);
CREATE INDEX idx_profiles_updated    ON machine_profiles(updated_at);
```

---

### request_type_profiles

```sql
CREATE TABLE request_type_profiles (
    protocol                INTEGER      NOT NULL,
    dst_port                INTEGER      NOT NULL,
    PRIMARY KEY (protocol, dst_port),

    observation_count       INTEGER      DEFAULT 0,

    -- Welford: bytes
    bytes_mean              FLOAT        DEFAULT 0.0,
    bytes_std               FLOAT        DEFAULT 0.0,
    bytes_m2                FLOAT        DEFAULT 0.0,

    -- Welford: packets
    pkts_mean               FLOAT        DEFAULT 0.0,
    pkts_std                FLOAT        DEFAULT 0.0,
    pkts_m2                 FLOAT        DEFAULT 0.0,

    -- Welford: duration
    duration_mean           FLOAT        DEFAULT 0.0,
    duration_std            FLOAT        DEFAULT 0.0,
    duration_m2             FLOAT        DEFAULT 0.0,

    -- Welford: entropy
    entropy_mean            FLOAT        DEFAULT 0.0,
    entropy_std             FLOAT        DEFAULT 0.0,
    entropy_m2              FLOAT        DEFAULT 0.0,

    -- Welford: byte ratio
    byte_ratio_mean         FLOAT        DEFAULT 0.0,
    byte_ratio_std          FLOAT        DEFAULT 0.0,
    byte_ratio_m2           FLOAT        DEFAULT 0.0,

    -- Welford: bytes per second
    bytes_per_sec_mean      FLOAT        DEFAULT 0.0,
    bytes_per_sec_std       FLOAT        DEFAULT 0.0,
    bytes_per_sec_m2        FLOAT        DEFAULT 0.0,

    updated_at              TIMESTAMP    DEFAULT NOW()
);
```

---

### machine_history (pgvector)

```sql
CREATE TABLE machine_history (
    id                      SERIAL       PRIMARY KEY,
    machine_ip              TEXT         NOT NULL,
    summary_text            TEXT         NOT NULL,
    embedding               VECTOR(384), -- sentence-transformers all-MiniLM-L6-v2
    created_at              TIMESTAMP    DEFAULT NOW()
);

CREATE INDEX idx_history_machine_ip ON machine_history(machine_ip);
CREATE INDEX idx_history_created    ON machine_history(created_at);
CREATE INDEX idx_history_embedding  ON machine_history
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
```

---

### security_alerts

```sql
CREATE TABLE security_alerts (
    alert_id                SERIAL       PRIMARY KEY,
    flow_id                 VARCHAR(50)  REFERENCES network_flows(flow_id),

    -- Risk assessment
    risk_level              VARCHAR(20)  NOT NULL,
    classifier_score        FLOAT,
    deviation_score         FLOAT,
    effective_deviation     FLOAT,
    machine_confidence      FLOAT,

    -- Agent output
    explanation             TEXT,
    firewall_rule           TEXT,
    tools_called            TEXT[],
    osint_results           JSONB,
    limit_hit               BOOLEAN      DEFAULT FALSE,

    -- Status
    escalated_to_human      BOOLEAN      DEFAULT FALSE,
    human_reviewed          BOOLEAN      DEFAULT FALSE,
    false_positive          BOOLEAN,

    created_at              TIMESTAMP    DEFAULT NOW()
);

CREATE INDEX idx_alerts_risk_level  ON security_alerts(risk_level);
CREATE INDEX idx_alerts_created     ON security_alerts(created_at);
CREATE INDEX idx_alerts_escalated   ON security_alerts(escalated_to_human);
CREATE INDEX idx_alerts_flow_id     ON security_alerts(flow_id);
```

---

## Migrations Order

```
001_create_extensions.py           -- vector, pg_trgm
002_create_users.py                -- least-privilege users
003_create_network_flows.py        -- network_flows table
004_create_machine_profiles.py     -- machine_profiles table
005_create_request_type_profiles.py-- request_type_profiles table
006_create_machine_history.py      -- machine_history pgvector table
007_create_security_alerts.py      -- security_alerts table
008_seed_request_type_profiles.py  -- bootstrap from CICIDS2018 benign flows
                                   -- only runs if table is empty (idempotent)
```

---

## Seed Script (Migration 008)

The seed script reads CICIDS2018 benign flows and computes population statistics per (protocol, dst_port) combination using Welford's algorithm. It only runs if the table is empty.

```python
def seed_request_type_profiles(csv_paths: list, db_session):
    # Check if already seeded
    count = db_session.execute(
        "SELECT COUNT(*) FROM request_type_profiles"
    ).scalar()
    if count > 0:
        print("request_type_profiles already seeded. Skipping.")
        return

    # Load benign flows only from all days
    dfs = []
    for path in csv_paths:
        df = pd.read_csv(path, low_memory=False)
        df = df[df['Label'] == 'Benign']
        dfs.append(df)

    benign = pd.concat(dfs)

    # Compute Welford statistics per (protocol, dst_port)
    groups = benign.groupby(['Protocol', 'Dst Port'])
    for (protocol, dst_port), group in groups:
        # Run Welford on each metric
        # Insert into request_type_profiles
        ...

    print(f"Seeded {len(groups)} request type profiles.")
```

---

## Docker Compose Database Service

```yaml
postgres:
  image: postgres:16
  environment:
    POSTGRES_DB:       socdb
    POSTGRES_USER:     postgres
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
  ports:
    - "5432:5432"
  volumes:
    - postgres_data:/var/lib/postgresql/data
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U postgres"]
    interval: 10s
    timeout: 5s
    retries: 5

migrate:
  build:
    context: .
    dockerfile: Dockerfile.migrate
  environment:
    DATABASE_URL: postgresql://migrate_user:${MIGRATE_PASSWORD}@postgres/socdb
  depends_on:
    postgres:
      condition: service_healthy
  command: alembic upgrade head
  # exits after running — does not stay alive
```

---

## Error Handling

All database errors use plain English user messages:

```python
class DatabaseUnavailable(SOCError):
    def __init__(self):
        super().__init__(
            user_message="The database is temporarily unavailable. "
                         "Your request will be retried automatically.",
            technical_detail="PostgreSQL connection refused"
        )

class RecordNotFound(SOCError):
    def __init__(self, entity: str):
        super().__init__(
            user_message=f"The requested {entity} could not be found.",
            technical_detail=f"{entity} not found in database"
        )
```
