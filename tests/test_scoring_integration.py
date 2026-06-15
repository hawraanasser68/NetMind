"""Integration tests for score_flow() — classifier + deviation → routing decision."""
import pytest

from src.scoring.scoring_service import score_flow, should_escalate_to_agent

_FLOW = {
    'machine_ip': '10.0.0.5',
    'dst_port':   443,
    'protocol':   6,
    'features':   [0.0] * 33,
}

_HIGH_CLF = {'classifier_score': 0.85, 'label': 2, 'confidence': 0.9}
_LOW_CLF  = {'classifier_score': 0.10, 'label': 0, 'confidence': 0.9}
_MID_CLF  = {'classifier_score': 0.55, 'label': 1, 'confidence': 0.7}


def _profile(flow_count=50, protocols=None):
    """Mature profile with zero means — all z-scores will be 0, deviation=0."""
    return {
        'machine_ip':          '10.0.0.5',
        'flow_count':          flow_count,
        'bytes_mean':          0.0, 'bytes_m2':          0.0,
        'bytes_per_sec_mean':  0.0, 'bytes_per_sec_m2':  0.0,
        'byte_ratio_mean':     0.0, 'byte_ratio_m2':     0.0,
        'pkts_mean':           0.0, 'pkts_m2':           0.0,
        'duration_mean':       0.0, 'duration_m2':       0.0,
        'known_ports':         [80, 443, 22],
        'known_protocols':     protocols if protocols is not None else [6, 17],
    }


# ── New machine (flow_count < 10) always escalates regardless of score ─────────

def test_new_machine_always_escalates():
    result = score_flow(_FLOW, _LOW_CLF, _profile(flow_count=5), None)
    assert result.risk_level == 'HIGH'
    assert result.escalate_to_agent is True


def test_new_machine_no_profiles_escalates():
    """No profiles at all means flow_count=0 → new machine."""
    result = score_flow(_FLOW, _LOW_CLF, None, None)
    assert result.risk_level == 'HIGH'
    assert result.escalate_to_agent is True


# ── Unknown protocol always escalates ──────────────────────────────────────────

def test_unknown_protocol_escalates():
    flow = {**_FLOW, 'protocol': 99}  # 99 not in [6, 17]
    result = score_flow(flow, _LOW_CLF, _profile(), None)
    assert result.risk_level == 'HIGH'
    assert result.escalate_to_agent is True


def test_known_protocol_does_not_force_escalation():
    flow = {**_FLOW, 'protocol': 6}   # 6 in [6, 17]
    result = score_flow(flow, _LOW_CLF, _profile(), None)
    assert result.escalate_to_agent is False


# ── Risk level routing ─────────────────────────────────────────────────────────

def test_high_classifier_score_escalates():
    # risk_score = 0.6 * 0.85 = 0.51 >= high_classifier threshold (0.50)
    result = score_flow(_FLOW, _HIGH_CLF, _profile(), None)
    assert result.risk_level in ('CRITICAL', 'HIGH')
    assert result.escalate_to_agent is True


def test_low_classifier_score_does_not_escalate():
    # risk_score = 0.6 * 0.10 = 0.06 → LOW
    result = score_flow(_FLOW, _LOW_CLF, _profile(), None)
    assert result.risk_level in ('LOW', 'MEDIUM')
    assert result.escalate_to_agent is False


def test_risk_score_is_bounded():
    result = score_flow(_FLOW, _MID_CLF, _profile(), None)
    assert 0.0 <= result.risk_score <= 1.0


def test_confidence_grows_with_profile_maturity():
    young  = score_flow(_FLOW, _MID_CLF, _profile(flow_count=10), None)
    mature = score_flow(_FLOW, _MID_CLF, _profile(flow_count=100), None)
    assert mature.confidence > young.confidence


def test_confidence_capped_at_one():
    result = score_flow(_FLOW, _MID_CLF, _profile(flow_count=500), None)
    assert result.confidence <= 1.0


# ── should_escalate_to_agent mirrors escalate_to_agent field ──────────────────

def test_should_escalate_matches_result_field():
    for clf in (_HIGH_CLF, _LOW_CLF):
        result = score_flow(_FLOW, clf, _profile(), None)
        assert should_escalate_to_agent(result) == result.escalate_to_agent
