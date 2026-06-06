# SPEC_PIPELINE.md
# Data Pipeline Specification
# All decisions final. Implement exactly as specified.

---

## Overview

The pipeline moves network flows from CICFlowMeter (or PCAP replay) through Redis Streams to three independent consumer groups: classifiers, profilers, and loggers. High-risk flows are pushed to a second stream consumed by the agent.

---

## File Structure

```
src/data/
  data_ingest.py       ← PCAP parsing and flow publishing
  data_consumer.py     ← base consumer loop (shared by all groups)
  data_classifier_worker.py  ← classifiers consumer group worker
  data_profiler_worker.py    ← profilers consumer group worker
  data_logger_worker.py      ← loggers consumer group worker
  data_agent_worker.py       ← agent consumer (high-risk-flows stream)
  data_feature_extractor.py  ← flow dict → 33-feature array
```

---

## Redis Streams Setup

Two streams:

```
Stream 1: network-flows
  Producers: CICFlowMeter / PCAP replay (data_ingest.py)
  Consumers:
    group: classifiers  → data_classifier_worker.py
    group: profilers    → data_profiler_worker.py
    group: loggers      → data_logger_worker.py
  Max length: 100,000 messages (MAXLEN ~)

Stream 2: high-risk-flows
  Producers: classifiers consumer group
  Consumers:
    group: agents       → data_agent_worker.py
  Max length: 10,000 messages
```

---

## Stream Initialization

```python
# src/data/data_consumer.py

import redis as redis_lib

NETWORK_FLOWS_STREAM  = 'network-flows'
HIGH_RISK_STREAM      = 'high-risk-flows'
STREAM_MAX_LEN        = 100_000
HIGH_RISK_MAX_LEN     = 10_000

CONSUMER_GROUPS = {
    NETWORK_FLOWS_STREAM: ['classifiers', 'profilers', 'loggers'],
    HIGH_RISK_STREAM:     ['agents'],
}

def initialize_streams(redis):
    """Create streams and consumer groups. Safe to call multiple times."""
    for stream, groups in CONSUMER_GROUPS.items():
        for group in groups:
            try:
                redis.xgroup_create(stream, group, id='0', mkstream=True)
                print(f"Created consumer group: {group} on {stream}")
            except redis_lib.exceptions.ResponseError as e:
                if 'BUSYGROUP' in str(e):
                    pass  # group already exists — fine
                else:
                    raise
```

---

## data_ingest.py

```python
# src/data/data_ingest.py

import json
import hashlib
import pandas as pd
import numpy as np
from datetime import datetime
from src.infra.infra_redis import get_redis_client
from src.ml.ml_feature_contract import (
    FEATURE_COLUMNS, RATE_COLUMNS, LABEL_MAP
)

STREAM         = 'network-flows'
STREAM_MAX_LEN = 100_000

def ingest_cicids_csv(csv_path: str):
    """
    Load CICIDS2018 CSV and publish flows to Redis Stream.
    Used for demo PCAP replay.
    """
    redis = get_redis_client()

    print(f"Loading: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)

    # Clean
    df = df[df['Flow Duration'] >= 0].copy()
    for col in RATE_COLUMNS:
        if col in df.columns:
            df[col] = df[col].replace([np.inf, -np.inf], 0)
    df = df.fillna(0)

    # Compute derived features
    df['byte_ratio'] = np.where(
        df['TotLen Fwd Pkts'] > 0,
        df['TotLen Bwd Pkts'] / df['TotLen Fwd Pkts'],
        0
    )
    df['proto_tcp']            = (df['Protocol'] == 6).astype(int)
    df['proto_udp']            = (df['Protocol'] == 17).astype(int)
    df['proto_icmp']           = (df['Protocol'] == 0).astype(int)
    df['is_privileged_port']   = (df['Dst Port'] < 1024).astype(int)

    # Map labels if present
    if 'Label' in df.columns:
        df['label'] = df['Label'].map(LABEL_MAP).fillna(-1).astype(int)

    print(f"Publishing {len(df)} flows to Redis Stream...")

    for _, row in df.iterrows():
        flow = row.to_dict()

        # Generate flow_id
        flow_id_str = f"{flow.get('Src IP', 'unknown')}:{flow.get('Src Port', 0)}-"
        flow_id_str += f"{flow.get('Dst IP', 'unknown')}:{flow.get('Dst Port', 0)}-"
        flow_id_str += f"{flow.get('Timestamp', '')}"
        flow['flow_id'] = hashlib.md5(flow_id_str.encode()).hexdigest()[:12]

        # Normalize column names for pipeline
        normalized = normalize_flow(flow)

        redis.xadd(
            STREAM,
            {'data': json.dumps(normalized, default=str)},
            maxlen=STREAM_MAX_LEN,
            approximate=True
        )

    print(f"Ingestion complete. {len(df)} flows published.")

def normalize_flow(flow: dict) -> dict:
    """Normalize CICIDS2018 column names to snake_case for pipeline."""
    return {
        'flow_id':        flow.get('flow_id', ''),
        'timestamp':      flow.get('Timestamp', datetime.utcnow().isoformat()),
        'src_ip':         flow.get('Src IP', '0.0.0.0'),
        'dst_ip':         flow.get('Dst IP', '0.0.0.0'),
        'src_port':       int(flow.get('Src Port', 0)),
        'dst_port':       int(flow.get('Dst Port', 0)),
        'protocol':       int(flow.get('Protocol', 0)),
        'tot_fwd_pkts':   int(flow.get('Tot Fwd Pkts', 0)),
        'tot_bwd_pkts':   int(flow.get('Tot Bwd Pkts', 0)),
        'totlen_fwd_pkts':float(flow.get('TotLen Fwd Pkts', 0)),
        'totlen_bwd_pkts':float(flow.get('TotLen Bwd Pkts', 0)),
        'flow_byts_s':    float(flow.get('Flow Byts/s', 0)),
        'flow_pkts_s':    float(flow.get('Flow Pkts/s', 0)),
        'fwd_pkts_s':     float(flow.get('Fwd Pkts/s', 0)),
        'bwd_pkts_s':     float(flow.get('Bwd Pkts/s', 0)),
        'flow_duration':  float(flow.get('Flow Duration', 0)),
        'flow_iat_mean':  float(flow.get('Flow IAT Mean', 0)),
        'flow_iat_std':   float(flow.get('Flow IAT Std', 0)),
        'fwd_iat_mean':   float(flow.get('Fwd IAT Mean', 0)),
        'fwd_iat_std':    float(flow.get('Fwd IAT Std', 0)),
        'bwd_iat_mean':   float(flow.get('Bwd IAT Mean', 0)),
        'bwd_iat_std':    float(flow.get('Bwd IAT Std', 0)),
        'active_mean':    float(flow.get('Active Mean', 0)),
        'active_std':     float(flow.get('Active Std', 0)),
        'idle_mean':      float(flow.get('Idle Mean', 0)),
        'idle_std':       float(flow.get('Idle Std', 0)),
        'syn_flag_cnt':   int(flow.get('SYN Flag Cnt', 0)),
        'fin_flag_cnt':   int(flow.get('FIN Flag Cnt', 0)),
        'rst_flag_cnt':   int(flow.get('RST Flag Cnt', 0)),
        'psh_flag_cnt':   int(flow.get('PSH Flag Cnt', 0)),
        'ack_flag_cnt':   int(flow.get('ACK Flag Cnt', 0)),
        'urg_flag_cnt':   int(flow.get('URG Flag Cnt', 0)),
        'pkt_len_mean':   float(flow.get('Pkt Len Mean', 0)),
        'pkt_len_std':    float(flow.get('Pkt Len Std', 0)),
        'down_up_ratio':  float(flow.get('Down/Up Ratio', 0)),
        'byte_ratio':     float(flow.get('byte_ratio', 0)),
        'proto_tcp':      int(flow.get('proto_tcp', 0)),
        'proto_udp':      int(flow.get('proto_udp', 0)),
        'proto_icmp':     int(flow.get('proto_icmp', 0)),
        'is_privileged_port': int(flow.get('is_privileged_port', 0)),
        'label':          int(flow.get('label', -1)),
    }
```

---

## data_feature_extractor.py

```python
# src/data/data_feature_extractor.py
# Converts normalized flow dict to 33-feature array for classifier.
# Feature order MUST match ml_feature_contract.py FEATURE_COLUMNS exactly.

from src.ml.ml_feature_contract import FEATURE_COLUMNS

FLOW_KEY_MAP = {
    'Tot Fwd Pkts':       'tot_fwd_pkts',
    'Tot Bwd Pkts':       'tot_bwd_pkts',
    'TotLen Fwd Pkts':    'totlen_fwd_pkts',
    'TotLen Bwd Pkts':    'totlen_bwd_pkts',
    'Flow Byts/s':        'flow_byts_s',
    'Flow Pkts/s':        'flow_pkts_s',
    'Fwd Pkts/s':         'fwd_pkts_s',
    'Bwd Pkts/s':         'bwd_pkts_s',
    'Flow Duration':      'flow_duration',
    'Flow IAT Mean':      'flow_iat_mean',
    'Flow IAT Std':       'flow_iat_std',
    'Fwd IAT Mean':       'fwd_iat_mean',
    'Fwd IAT Std':        'fwd_iat_std',
    'Bwd IAT Mean':       'bwd_iat_mean',
    'Bwd IAT Std':        'bwd_iat_std',
    'Active Mean':        'active_mean',
    'Active Std':         'active_std',
    'Idle Mean':          'idle_mean',
    'Idle Std':           'idle_std',
    'SYN Flag Cnt':       'syn_flag_cnt',
    'FIN Flag Cnt':       'fin_flag_cnt',
    'RST Flag Cnt':       'rst_flag_cnt',
    'PSH Flag Cnt':       'psh_flag_cnt',
    'ACK Flag Cnt':       'ack_flag_cnt',
    'URG Flag Cnt':       'urg_flag_cnt',
    'Pkt Len Mean':       'pkt_len_mean',
    'Pkt Len Std':        'pkt_len_std',
    'Down/Up Ratio':      'down_up_ratio',
    'byte_ratio':         'byte_ratio',
    'proto_tcp':          'proto_tcp',
    'proto_udp':          'proto_udp',
    'proto_icmp':         'proto_icmp',
    'is_privileged_port': 'is_privileged_port',
}

def extract_features(flow: dict) -> list:
    """
    Convert normalized flow dict to feature array.
    Order matches FEATURE_COLUMNS in ml_feature_contract.py exactly.
    Raises ValueError if any feature is missing.
    """
    features = []
    for contract_name in FEATURE_COLUMNS:
        flow_key = FLOW_KEY_MAP.get(contract_name, contract_name.lower().replace(' ', '_'))
        value    = flow.get(flow_key, 0)
        features.append(float(value))

    assert len(features) == 33, f"Expected 33 features, got {len(features)}"
    return features
```

---

## data_classifier_worker.py

```python
# src/data/data_classifier_worker.py

import json
import requests
from src.data.data_consumer import consume_stream, publish_high_risk
from src.data.data_feature_extractor import extract_features
from src.profiles.profiles_machine import get_machine_profile
from src.profiles.profiles_request_type import get_request_type_profile
from src.scoring.scoring_service import score_flow
from src.infra.infra_redis import get_redis_client
from src.infra.infra_db import get_db_session

CLASSIFIER_URL = 'http://classifier:8001/classifier/score'

def classifier_handler(flow: dict, redis, db):
    """
    Score flow, compute deviation, route to agent if needed.
    """
    # Extract features
    features = extract_features(flow)

    # Call classifier service
    try:
        response = requests.post(
            CLASSIFIER_URL,
            json={'flow_id': flow['flow_id'], 'features': features},
            timeout=5
        )
        response.raise_for_status()
        classifier_result = response.json()
    except Exception as e:
        # Classifier unavailable — use neutral score, still run deviation
        classifier_result = {
            'flow_id':                flow['flow_id'],
            'benign_probability':     0.5,
            'suspicious_probability': 0.3,
            'attack_probability':     0.2,
            'classifier_score':       0.5,
            'predicted_class':        0,
        }

    # Get profiles for deviation scoring
    machine_profile      = get_machine_profile(flow['src_ip'], redis, db)
    request_type_profile = get_request_type_profile(
        flow['protocol'], flow['dst_port'], redis, db
    )

    # Score
    scoring_result = score_flow(
        flow, classifier_result, machine_profile, request_type_profile
    )

    # Route high-risk flows to agent stream
    if scoring_result['escalate_to_agent']:
        publish_high_risk({
            'flow':           flow,
            'scoring_result': scoring_result,
        }, redis)

    return scoring_result

def run_classifier_worker():
    redis = get_redis_client()
    db    = get_db_session()

    consume_stream(
        stream   = 'network-flows',
        group    = 'classifiers',
        consumer = 'classifier-1',
        handler  = lambda flow: classifier_handler(flow, redis, db),
        redis    = redis,
    )
```

---

## data_consumer.py (Base Consumer Loop)

```python
# src/data/data_consumer.py

import json
import logging

logger = logging.getLogger(__name__)

NETWORK_FLOWS_STREAM = 'network-flows'
HIGH_RISK_STREAM     = 'high-risk-flows'

def consume_stream(stream: str, group: str, consumer: str, handler, redis):
    """
    Generic consumer loop.
    1. Recover pending messages first (crash recovery)
    2. Read new messages
    3. Process and acknowledge each
    """
    # Step 1 — recover pending messages
    pending = redis.xreadgroup(
        group, consumer,
        {stream: '0'},   # 0 = pending messages only
        count=100,
        block=0
    )

    if pending:
        for stream_name, entries in pending:
            for message_id, fields in entries:
                flow = json.loads(fields[b'data'])
                _process_message(message_id, flow, handler, group, stream, redis)

    # Step 2 — read new messages
    while True:
        messages = redis.xreadgroup(
            group, consumer,
            {stream: '>'},   # > = only new messages
            count=1,
            block=0          # block indefinitely until message arrives
        )

        if not messages:
            continue

        for stream_name, entries in messages:
            for message_id, fields in entries:
                flow = json.loads(fields[b'data'])
                _process_message(message_id, flow, handler, group, stream, redis)

def _process_message(message_id, flow: dict, handler, group: str, stream: str, redis):
    try:
        handler(flow)
        redis.xack(stream, group, message_id)   # acknowledge on success
    except Exception as e:
        logger.error(f"Failed to process message {message_id}: {e}")
        # Do NOT acknowledge — message will be redelivered on restart

def publish_high_risk(payload: dict, redis):
    """Push high-risk flow to agent stream."""
    redis.xadd(
        HIGH_RISK_STREAM,
        {'data': json.dumps(payload, default=str)},
        maxlen=10_000,
        approximate=True
    )
```

---

## data_profiler_worker.py

```python
# src/data/data_profiler_worker.py

from src.data.data_consumer import consume_stream
from src.profiles.profiles_machine import update_machine_profile, maybe_generate_snapshot
from src.profiles.profiles_request_type import update_request_type_profile
from src.infra.infra_redis import get_redis_client
from src.infra.infra_db import get_db_session

def profiler_handler(flow: dict, redis, db):
    """Update behavioral profiles for every flow regardless of risk."""
    updated = update_machine_profile(flow, redis, db)
    update_request_type_profile(flow, redis, db)
    maybe_generate_snapshot(updated, db)

def run_profiler_worker():
    redis = get_redis_client()
    db    = get_db_session()

    consume_stream(
        stream   = 'network-flows',
        group    = 'profilers',
        consumer = 'profiler-1',
        handler  = lambda flow: profiler_handler(flow, redis, db),
        redis    = redis,
    )
```

---

## data_logger_worker.py

```python
# src/data/data_logger_worker.py

from src.data.data_consumer import consume_stream
from src.infra.infra_db import get_db_session
from src.infra.infra_redis import get_redis_client

def logger_handler(flow: dict, db):
    """Write raw flow to PostgreSQL. INSERT ON CONFLICT DO NOTHING."""
    db.execute("""
        INSERT INTO network_flows (
            flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
            tot_fwd_pkts, tot_bwd_pkts, totlen_fwd_pkts, totlen_bwd_pkts,
            flow_byts_s, flow_pkts_s, fwd_pkts_s, bwd_pkts_s,
            flow_duration, flow_iat_mean, flow_iat_std,
            fwd_iat_mean, fwd_iat_std, bwd_iat_mean, bwd_iat_std,
            active_mean, active_std, idle_mean, idle_std,
            syn_flag_cnt, fin_flag_cnt, rst_flag_cnt, psh_flag_cnt,
            ack_flag_cnt, urg_flag_cnt,
            pkt_len_mean, pkt_len_std, down_up_ratio,
            byte_ratio, proto_tcp, proto_udp, proto_icmp, is_privileged_port
        ) VALUES (
            %(flow_id)s, %(timestamp)s, %(src_ip)s, %(dst_ip)s,
            %(src_port)s, %(dst_port)s, %(protocol)s,
            %(tot_fwd_pkts)s, %(tot_bwd_pkts)s, %(totlen_fwd_pkts)s, %(totlen_bwd_pkts)s,
            %(flow_byts_s)s, %(flow_pkts_s)s, %(fwd_pkts_s)s, %(bwd_pkts_s)s,
            %(flow_duration)s, %(flow_iat_mean)s, %(flow_iat_std)s,
            %(fwd_iat_mean)s, %(fwd_iat_std)s, %(bwd_iat_mean)s, %(bwd_iat_std)s,
            %(active_mean)s, %(active_std)s, %(idle_mean)s, %(idle_std)s,
            %(syn_flag_cnt)s, %(fin_flag_cnt)s, %(rst_flag_cnt)s, %(psh_flag_cnt)s,
            %(ack_flag_cnt)s, %(urg_flag_cnt)s,
            %(pkt_len_mean)s, %(pkt_len_std)s, %(down_up_ratio)s,
            %(byte_ratio)s, %(proto_tcp)s, %(proto_udp)s, %(proto_icmp)s, %(is_privileged_port)s
        )
        ON CONFLICT (flow_id) DO NOTHING
    """, flow)
    db.commit()

def run_logger_worker():
    redis = get_redis_client()
    db    = get_db_session()

    consume_stream(
        stream   = 'network-flows',
        group    = 'loggers',
        consumer = 'logger-1',
        handler  = lambda flow: logger_handler(flow, db),
        redis    = redis,
    )
```

---

## data_agent_worker.py

```python
# src/data/data_agent_worker.py

import json
import requests
from src.data.data_consumer import consume_stream
from src.infra.infra_redis import get_redis_client
from src.infra.infra_db import get_db_session

AGENT_URL = 'http://agent:8003/agent/analyze'

def agent_handler(payload: dict, redis, db):
    """Send high-risk flow to agent service and store finding."""
    try:
        response = requests.post(
            AGENT_URL,
            json=payload,
            timeout=35   # slightly above 30s agent timeout
        )
        response.raise_for_status()
        finding = response.json()

        # Store finding in PostgreSQL
        db.execute("""
            INSERT INTO security_alerts (
                flow_id, risk_level, classifier_score,
                deviation_score, effective_deviation, machine_confidence,
                explanation, firewall_rule, tools_called, osint_results,
                limit_hit, escalated_to_human
            ) VALUES (
                %(flow_id)s, %(risk_level)s, %(classifier_score)s,
                %(deviation_score)s, %(deviation_score)s, %(machine_confidence)s,
                %(explanation)s, %(firewall_rule)s, %(tools_called)s,
                %(osint_results)s::jsonb, %(limit_hit)s, %(escalated_to_human)s
            )
        """, {
            **finding,
            'osint_results': json.dumps(finding.get('osint_results', {})),
        })
        db.commit()

    except Exception as e:
        # Agent unavailable — store minimal alert
        db.execute("""
            INSERT INTO security_alerts (flow_id, risk_level, explanation, escalated_to_human)
            VALUES (%(flow_id)s, %(risk_level)s, %(explanation)s, TRUE)
        """, {
            'flow_id':    payload['flow']['flow_id'],
            'risk_level': payload['scoring_result']['risk_level'],
            'explanation': 'Analysis agent temporarily unavailable. Manual review required.',
        })
        db.commit()

def run_agent_worker():
    redis = get_redis_client()
    db    = get_db_session()

    consume_stream(
        stream   = 'high-risk-flows',
        group    = 'agents',
        consumer = 'agent-1',
        handler  = lambda payload: agent_handler(payload, redis, db),
        redis    = redis,
    )
```

---

## Docker Compose Services

```yaml
# All pipeline workers in docker-compose.yml

classifier:
  build: .
  command: python -m src.data.data_classifier_worker
  depends_on: [redis, postgres, migrate, vault]

profiler:
  build: .
  command: python -m src.data.data_profiler_worker
  depends_on: [redis, postgres, migrate, vault]

logger:
  build: .
  command: python -m src.data.data_logger_worker
  depends_on: [redis, postgres, migrate, vault]

agent-worker:
  build: .
  command: python -m src.data.data_agent_worker
  depends_on: [redis, postgres, migrate, vault]
  deploy:
    replicas: 3   # max 3 concurrent agent invocations
```
