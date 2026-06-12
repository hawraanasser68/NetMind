import math
from src.ml.ml_feature_contract import FEATURE_COLUMNS, N_FEATURES

# First 28 features map directly to CICIDS2018 CSV column names.
# Last 5 are derived at extraction time (byte_ratio, proto_*, is_privileged_port).
_DIRECT_COLUMNS = FEATURE_COLUMNS[:28]


def _safe_float(value) -> float:
    """Convert to float, treating None / NaN / Inf as 0.0."""
    try:
        v = float(value)
        if math.isnan(v) or math.isinf(v):
            return 0.0
        return v
    except (TypeError, ValueError):
        return 0.0


def extract_features(flow: dict) -> list[float]:
    """
    Map a flow dict (keyed by CICIDS2018 column names) to a 33-element feature list
    in FEATURE_COLUMNS order.

    Expects keys to be stripped of whitespace (data_ingest normalises them).
    """
    features = []

    # Direct features — read straight from the flow dict
    for col in _DIRECT_COLUMNS:
        features.append(_safe_float(flow.get(col, 0)))

    # Derived features
    fwd_bytes   = _safe_float(flow.get('TotLen Fwd Pkts', 0))
    bwd_bytes   = _safe_float(flow.get('TotLen Bwd Pkts', 0))
    total_bytes = fwd_bytes + bwd_bytes

    protocol = int(_safe_float(flow.get('Protocol', 0)))
    dst_port = int(_safe_float(flow.get('Dst Port', 0)))

    features.append(fwd_bytes / total_bytes if total_bytes > 0 else 0.5)  # byte_ratio
    features.append(1.0 if protocol == 6  else 0.0)                       # proto_tcp
    features.append(1.0 if protocol == 17 else 0.0)                       # proto_udp
    features.append(1.0 if protocol == 1  else 0.0)                       # proto_icmp
    features.append(1.0 if 0 < dst_port < 1024 else 0.0)                  # is_privileged_port

    assert len(features) == N_FEATURES, (
        f'Feature extraction produced {len(features)} features, expected {N_FEATURES}'
    )

    return features
