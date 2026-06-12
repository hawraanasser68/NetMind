import math
import yaml
from datetime import datetime
from pathlib import Path
from functools import lru_cache

_WEIGHTS_PATH = Path('config/deviation_weights.yaml')

# Feature names that belong to the machine component vs population component
_MACHINE_FEATURES = {
    'z_bytes_machine', 'z_bytes_per_sec', 'z_byte_ratio',
    'z_pkts_machine', 'z_duration_machine',
    'new_port', 'off_hours', 'external_first', 'new_protocol',
}
_POPULATION_FEATURES = {'z_bytes_request_type'}


@lru_cache(maxsize=1)
def load_weights() -> dict:
    """Read deviation_weights.yaml once and cache it for the process lifetime."""
    with open(_WEIGHTS_PATH) as f:
        return yaml.safe_load(f)


def safe_z(value: float, mean: float, m2: float, n: int) -> float:
    """
    Compute a z-score from Welford running state.
    Returns 0.0 when the profile has too few observations to be reliable.
    """
    if n < 2:
        return 0.0
    variance = m2 / n
    std = math.sqrt(variance)
    if std < 1e-9:
        return 0.0
    return (value - mean) / std


def normalize_z(z: float) -> float:
    """
    Map |z| → [0, 1].  A z-score of ±3 or beyond maps to 1.0 (maximum deviation).
    """
    return min(abs(z) / 3.0, 1.0)


def _is_off_hours(captured_at: str) -> float:
    """1.0 if the flow occurred outside 08:00–18:00 local time, else 0.0."""
    try:
        hour = datetime.fromisoformat(captured_at).hour
        return 0.0 if 8 <= hour < 18 else 1.0
    except Exception:
        return 0.0


def compute_deviation_score(
    flow: dict,
    machine_profile: dict | None,
    request_type_profile: dict | None,
) -> tuple[float, dict, float]:
    """
    Compute the behavioural deviation score for one flow.

    Returns:
        deviation_score  – float in [0, 1]
        components       – dict of individual feature values (for debugging)
        confidence       – float in [0, 1], based on machine profile maturity
    """
    weights    = load_weights()
    fw         = weights['feature_weights']
    mc_weight  = weights['machine_component_weight']    # 0.60
    pop_weight = weights['population_component_weight'] # 0.40

    mp  = machine_profile        or {}
    rtp = request_type_profile   or {}

    flow_count  = int(mp.get('flow_count', 0))
    confidence  = min(flow_count / 100.0, 1.0)

    features = flow.get('features', [])
    # Feature indices in FEATURE_COLUMNS order (see ml_feature_contract.py)
    # 0:tot_fwd_pkts 1:tot_bwd_pkts 2:totlen_fwd_pkts 3:totlen_bwd_pkts
    # 4:flow_byts_per_s  8:flow_duration  28:byte_ratio
    fwd_bytes    = features[2] if len(features) > 2 else 0.0
    bwd_bytes    = features[3] if len(features) > 3 else 0.0
    total_bytes  = fwd_bytes + bwd_bytes
    byts_per_s   = features[4] if len(features) > 4 else 0.0
    duration     = features[8] if len(features) > 8 else 0.0
    tot_pkts     = (features[0] + features[1]) if len(features) > 1 else 0.0
    byte_ratio   = features[28] if len(features) > 28 else 0.5

    components = {}

    # ── Machine-component features ────────────────────────────────────────────
    components['z_bytes_machine'] = normalize_z(safe_z(
        total_bytes, mp.get('bytes_mean', 0), mp.get('bytes_m2', 0), flow_count,
    ))
    components['z_bytes_per_sec'] = normalize_z(safe_z(
        byts_per_s, mp.get('bytes_per_sec_mean', 0), mp.get('bytes_per_sec_m2', 0), flow_count,
    ))
    components['z_byte_ratio'] = normalize_z(safe_z(
        byte_ratio, mp.get('byte_ratio_mean', 0), mp.get('byte_ratio_m2', 0), flow_count,
    ))
    components['z_pkts_machine'] = normalize_z(safe_z(
        tot_pkts, mp.get('pkts_mean', 0), mp.get('pkts_m2', 0), flow_count,
    ))
    components['z_duration_machine'] = normalize_z(safe_z(
        duration, mp.get('duration_mean', 0), mp.get('duration_m2', 0), flow_count,
    ))

    dst_port = int(flow.get('dst_port', 0))
    protocol = int(flow.get('protocol', 0))
    known_ports     = mp.get('known_ports', [])
    known_protocols = mp.get('known_protocols', [])

    components['new_port']      = 0.0 if dst_port in known_ports     else 1.0
    components['new_protocol']  = 0.0 if protocol  in known_protocols else 1.0
    components['off_hours']     = _is_off_hours(flow.get('captured_at', ''))
    components['external_first'] = 1.0 if flow_count == 0 else 0.0

    # ── Population-component feature ──────────────────────────────────────────
    rtp_count = int(rtp.get('flow_count', 0))
    components['z_bytes_request_type'] = normalize_z(safe_z(
        total_bytes, rtp.get('bytes_mean', 0), rtp.get('bytes_m2', 0), rtp_count,
    ))

    # ── Weighted combination ──────────────────────────────────────────────────
    machine_weights_total = sum(fw[k] for k in _MACHINE_FEATURES if k in fw)
    pop_weights_total     = sum(fw[k] for k in _POPULATION_FEATURES if k in fw)

    machine_score = 0.0
    if machine_weights_total > 0:
        for feat in _MACHINE_FEATURES:
            if feat in fw:
                machine_score += (fw[feat] / machine_weights_total) * components.get(feat, 0.0)

    pop_score = 0.0
    if pop_weights_total > 0:
        for feat in _POPULATION_FEATURES:
            if feat in fw:
                pop_score += (fw[feat] / pop_weights_total) * components.get(feat, 0.0)

    deviation_score = mc_weight * machine_score + pop_weight * pop_score

    return deviation_score, components, confidence
