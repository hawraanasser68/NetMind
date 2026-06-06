# SPEC_RISK_SCORER.md
# Risk Scorer Specification
# All decisions final. Implement exactly as specified.

---

## Overview

The risk scorer combines the classifier score with the behavioral deviation score to produce a single risk level. It runs inside the classifier consumer group, immediately after the classifier scores a flow.

---

## File Structure

```
src/scoring/
  scoring_main.py         ← FastAPI entry point (if exposed as service)
  scoring_schemas.py      ← all Pydantic models
  scoring_dependencies.py ← FastAPI dependencies
  scoring_service.py      ← routing logic
  scoring_deviation.py    ← deviation score computation
```

---

## Config File

All thresholds and weights stored in config/deviation_weights.yaml.
Never hardcoded in application code.

```yaml
# config/deviation_weights.yaml

# Deviation formula weights
machine_component_weight:    0.60
population_component_weight: 0.40

# Feature weights (must sum to 1.0)
feature_weights:
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

# Routing thresholds
routing_thresholds:
  critical:              0.80
  high_classifier:       0.50
  high_deviation:        0.70
  medium_deviation:      0.80
  low_deviation:         0.60
  low_confidence_max:    0.30
```

---

## scoring_deviation.py

```python
# src/scoring/scoring_deviation.py

import math
import yaml
from typing import Tuple
from datetime import datetime

def load_weights() -> dict:
    with open('config/deviation_weights.yaml') as f:
        return yaml.safe_load(f)

def normalize_z(z: float) -> float:
    """Map Z-score to 0-1. Z=3 → 0.63. Z=10 → 0.96."""
    return 1 - math.exp(-abs(z) / 3)

def safe_z(observed: float, mean: float, std: float) -> float:
    """Z-score with std=0 handling."""
    if std == 0:
        return 0.0 if observed == mean else 3.0
    return (observed - mean) / std

def compute_deviation_score(
    flow: dict,
    machine_profile: dict,
    request_type_profile: dict,
) -> Tuple[float, dict]:
    """
    Compute deviation score.
    Returns: (deviation_score, components_dict)
    components_dict shows which signals were elevated — fed to agent.
    """
    weights = load_weights()
    fw      = weights['feature_weights']
    mw      = weights['machine_component_weight']
    pw      = weights['population_component_weight']

    total_bytes   = flow.get('totlen_fwd_pkts', 0) + flow.get('totlen_bwd_pkts', 0)
    total_pkts    = flow.get('tot_fwd_pkts', 0) + flow.get('tot_bwd_pkts', 0)
    duration      = flow.get('flow_duration', 0)
    bytes_per_sec = flow.get('flow_byts_s', 0)
    fwd_bytes     = flow.get('totlen_fwd_pkts', 0)
    bwd_bytes     = flow.get('totlen_bwd_pkts', 0)
    byte_ratio    = bwd_bytes / fwd_bytes if fwd_bytes > 0 else 0
    dst_port      = flow.get('dst_port', 0)
    protocol      = flow.get('protocol', 0)
    dst_ip        = flow.get('dst_ip', '')
    hour          = datetime.utcnow().hour

    # ── Machine component Z-scores ─────────────────────────────────────
    z_bytes_machine = normalize_z(safe_z(
        total_bytes,
        machine_profile.get('bytes_mean', 0),
        machine_profile.get('bytes_std', 0)
    ))

    z_pkts_machine = normalize_z(safe_z(
        total_pkts,
        machine_profile.get('pkts_mean', 0),
        machine_profile.get('pkts_std', 0)
    ))

    z_duration_machine = normalize_z(safe_z(
        duration,
        machine_profile.get('duration_mean', 0),
        machine_profile.get('duration_std', 0)
    ))

    # ── Population component Z-scores ──────────────────────────────────
    if request_type_profile:
        z_bytes_request_type = normalize_z(safe_z(
            total_bytes,
            request_type_profile.get('bytes_mean', 0),
            request_type_profile.get('bytes_std', 0)
        ))

        z_bytes_per_sec = normalize_z(safe_z(
            bytes_per_sec,
            request_type_profile.get('bytes_per_sec_mean', 0),
            request_type_profile.get('bytes_per_sec_std', 0)
        ))

        z_byte_ratio = normalize_z(safe_z(
            byte_ratio,
            request_type_profile.get('byte_ratio_mean', 0),
            request_type_profile.get('byte_ratio_std', 0)
        ))
    else:
        # Unknown protocol/port — maximum population deviation
        z_bytes_request_type = 1.0
        z_bytes_per_sec      = 1.0
        z_byte_ratio         = 1.0

    # ── Binary checks ──────────────────────────────────────────────────
    typical_ports     = machine_profile.get('typical_dst_ports', [])
    typical_protocols = machine_profile.get('typical_protocols', [])
    typical_dst_ips   = machine_profile.get('typical_dst_ips', [])
    active_hours      = machine_profile.get('active_hours', [0] * 24)
    external_count    = machine_profile.get('external_conn_count', 0)

    from src.profiles.profiles_machine import is_rfc1918
    is_external = not is_rfc1918(dst_ip)

    new_port      = 0 if dst_port in typical_ports     else 1
    new_protocol  = 0 if protocol  in typical_protocols else 1
    off_hours     = 1 if active_hours[hour] == 0        else 0
    external_first = 1 if (is_external and external_count == 0) else 0

    # ── Machine component (weighted average) ───────────────────────────
    machine_component = (
        z_bytes_machine    * fw['z_bytes_machine']    +
        z_pkts_machine     * fw['z_pkts_machine']     +
        z_duration_machine * fw['z_duration_machine'] +
        new_port           * fw['new_port']           +
        off_hours          * fw['off_hours']          +
        external_first     * fw['external_first']     +
        new_protocol       * fw['new_protocol']
    )

    # ── Population component (weighted average) ────────────────────────
    population_component = (
        z_bytes_request_type * fw['z_bytes_request_type'] +
        z_bytes_per_sec      * fw['z_bytes_per_sec']      +
        z_byte_ratio         * fw['z_byte_ratio']
    )

    # ── Apply confidence modifier ──────────────────────────────────────
    confidence        = machine_profile.get('confidence', 0.0)
    effective_machine = machine_component * confidence

    # ── Combined score ─────────────────────────────────────────────────
    deviation_score = (effective_machine * mw) + (population_component * pw)

    # ── Components dict (fed to agent for explanation) ─────────────────
    components = {
        'z_bytes_machine':       round(z_bytes_machine, 4),
        'z_pkts_machine':        round(z_pkts_machine, 4),
        'z_duration_machine':    round(z_duration_machine, 4),
        'z_bytes_request_type':  round(z_bytes_request_type, 4),
        'z_bytes_per_sec':       round(z_bytes_per_sec, 4),
        'z_byte_ratio':          round(z_byte_ratio, 4),
        'new_port':              new_port,
        'new_protocol':          new_protocol,
        'off_hours':             off_hours,
        'external_first':        external_first,
        'machine_confidence':    round(confidence, 4),
        'machine_component':     round(machine_component, 4),
        'population_component':  round(population_component, 4),
        'effective_machine':     round(effective_machine, 4),
        'deviation_score':       round(deviation_score, 4),
        'unknown_protocol_port': request_type_profile is None,
    }

    return round(deviation_score, 4), components
```

---

## scoring_service.py

```python
# src/scoring/scoring_service.py

import yaml
from src.scoring.scoring_deviation import compute_deviation_score

def load_thresholds() -> dict:
    with open('config/deviation_weights.yaml') as f:
        return yaml.safe_load(f)['routing_thresholds']

def compute_risk_level(
    classifier_score: float,
    deviation_score: float,
    machine_confidence: float,
) -> str:
    """
    Apply threshold gate to determine risk level.
    All thresholds from config file.
    """
    t = load_thresholds()

    effective_deviation = deviation_score * machine_confidence

    if classifier_score >= t['critical']:
        return 'CRITICAL'

    if classifier_score >= t['high_classifier'] and effective_deviation >= t['high_deviation']:
        return 'HIGH'

    if classifier_score >= t['high_classifier'] or effective_deviation >= t['medium_deviation']:
        return 'MEDIUM'

    if effective_deviation >= t['low_deviation'] and machine_confidence < t['low_confidence_max']:
        return 'LOW'

    return 'BENIGN'

def should_escalate_to_agent(risk_level: str) -> bool:
    return risk_level in ('CRITICAL', 'HIGH')

def score_flow(
    flow: dict,
    classifier_result: dict,
    machine_profile: dict,
    request_type_profile: dict,
) -> dict:
    """
    Full scoring pipeline.
    Returns complete scoring result dict.
    """
    # Unknown protocol/port — always escalate to human
    if request_type_profile is None and machine_profile.get('observation_count', 0) == 0:
        return {
            'flow_id':              flow['flow_id'],
            'classifier_score':     classifier_result['classifier_score'],
            'deviation_score':      1.0,
            'effective_deviation':  1.0,
            'machine_confidence':   0.0,
            'risk_level':           'HIGH',
            'escalate_to_agent':    False,
            'escalate_to_human':    True,
            'reason':               'unknown_protocol_port',
            'components':           {},
        }

    deviation_score, components = compute_deviation_score(
        flow, machine_profile, request_type_profile
    )

    machine_confidence  = machine_profile.get('confidence', 0.0)
    effective_deviation = deviation_score * machine_confidence
    risk_level          = compute_risk_level(
        classifier_result['classifier_score'],
        deviation_score,
        machine_confidence
    )

    return {
        'flow_id':                flow['flow_id'],
        'classifier_score':       classifier_result['classifier_score'],
        'benign_probability':     classifier_result['benign_probability'],
        'suspicious_probability': classifier_result['suspicious_probability'],
        'attack_probability':     classifier_result['attack_probability'],
        'deviation_score':        deviation_score,
        'effective_deviation':    effective_deviation,
        'machine_confidence':     machine_confidence,
        'risk_level':             risk_level,
        'escalate_to_agent':      should_escalate_to_agent(risk_level),
        'escalate_to_human':      False,
        'reason':                 'scored',
        'components':             components,
    }
```

---

## scoring_schemas.py

```python
# src/scoring/scoring_schemas.py

from pydantic import BaseModel
from typing import Optional, Dict

class ScoringResult(BaseModel):
    flow_id:                  str
    classifier_score:         float
    benign_probability:       float
    suspicious_probability:   float
    attack_probability:       float
    deviation_score:          float
    effective_deviation:      float
    machine_confidence:       float
    risk_level:               str
    escalate_to_agent:        bool
    escalate_to_human:        bool
    reason:                   str
    components:               Dict[str, float]
```
