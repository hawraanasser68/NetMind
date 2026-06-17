"""Tests for worker routing logic: message splitting and classify-and-route decisions."""
import pytest
from unittest.mock import patch, MagicMock

from src.data.data_agent_worker import _split_message, _SCORING_KEYS
from src.data.data_classifier_worker import _simple_risk


_FLOW = {
    'machine_ip': '1.2.3.4',
    'flow_id':    'abc-123',
    'dst_port':   443,
    'protocol':   6,
    'features':   [0.0] * 33,
}


# ── _split_message ─────────────────────────────────────────────────────────────

def test_split_puts_scoring_keys_in_scoring_dict():
    raw = {**_FLOW, 'ml_label': 2, 'ml_confidence': 0.9,
           'classifier_score': 0.85, 'risk_score': 0.72, 'risk_level': 'HIGH'}
    flow, scoring = _split_message(raw)
    assert set(scoring.keys()) == _SCORING_KEYS
    assert scoring['risk_level'] == 'HIGH'
    assert scoring['classifier_score'] == 0.85


def test_split_keeps_flow_fields_in_flow_dict():
    raw = {**_FLOW, 'ml_label': 2, 'classifier_score': 0.85, 'risk_level': 'HIGH'}
    flow, scoring = _split_message(raw)
    assert 'machine_ip' in flow
    assert 'features' in flow
    assert 'classifier_score' not in flow
    assert 'machine_ip' not in scoring


def test_split_scoring_fields_none_when_absent():
    flow, scoring = _split_message(_FLOW)
    assert all(v is None for v in scoring.values())
    assert flow == _FLOW


def test_split_no_overlap_between_dicts():
    raw = {**_FLOW, 'ml_label': 2, 'classifier_score': 0.85, 'risk_level': 'HIGH'}
    flow, scoring = _split_message(raw)
    assert not set(flow.keys()) & set(scoring.keys()) - {k for k, v in scoring.items() if v is None}


# ── _simple_risk thresholds ────────────────────────────────────────────────────

def test_simple_risk_critical():
    level, escalate = _simple_risk(0.85)
    assert level == 'CRITICAL' and escalate is True


def test_simple_risk_high():
    level, escalate = _simple_risk(0.65)
    assert level == 'HIGH' and escalate is True


def test_simple_risk_medium():
    level, escalate = _simple_risk(0.40)
    assert level == 'MEDIUM' and escalate is False


def test_simple_risk_low():
    level, escalate = _simple_risk(0.10)
    assert level == 'LOW' and escalate is False


def test_simple_risk_boundary_high():
    level, escalate = _simple_risk(0.50)
    assert level == 'HIGH' and escalate is True


def test_simple_risk_boundary_medium():
    level, escalate = _simple_risk(0.30)
    assert level == 'MEDIUM' and escalate is False


# ── classify_and_route integration ────────────────────────────────────────────

def test_high_risk_flow_published_to_stream():
    high_result = {
        'label': 2, 'confidence': 0.95,
        'classifier_score': 0.90,
        'probabilities': {'benign': 0.05, 'suspicious': 0.05, 'attack': 0.90},
    }
    with patch('src.data.data_classifier_worker._call_classifier', return_value=high_result), \
         patch('src.data.data_classifier_worker.get_machine_profile', return_value=None), \
         patch('src.data.data_classifier_worker.get_request_type_profile', return_value=None), \
         patch('src.data.data_classifier_worker.publish_high_risk') as mock_pub:
        from src.data.data_classifier_worker import classify_and_route
        classify_and_route(_FLOW)
        mock_pub.assert_called_once()


def test_any_flow_escalates_without_profile():
    """classify_and_route always passes machine_profile=None (profiler is a separate worker).
    No profile → flow_count=0 → is_new_machine=True → always escalates regardless of score."""
    low_result = {
        'label': 0, 'confidence': 0.95,
        'classifier_score': 0.05,
        'probabilities': {'benign': 0.95, 'suspicious': 0.03, 'attack': 0.02},
    }
    with patch('src.data.data_classifier_worker._call_classifier', return_value=low_result), \
         patch('src.data.data_classifier_worker.get_machine_profile', return_value=None), \
         patch('src.data.data_classifier_worker.get_request_type_profile', return_value=None), \
         patch('src.data.data_classifier_worker.publish_high_risk') as mock_pub:
        from src.data.data_classifier_worker import classify_and_route
        classify_and_route(_FLOW)
        mock_pub.assert_called_once()


def test_published_message_includes_scoring_fields():
    high_result = {
        'label': 2, 'confidence': 0.9,
        'classifier_score': 0.85,
        'probabilities': {'benign': 0.05, 'suspicious': 0.05, 'attack': 0.90},
    }
    with patch('src.data.data_classifier_worker._call_classifier', return_value=high_result), \
         patch('src.data.data_classifier_worker.get_machine_profile', return_value=None), \
         patch('src.data.data_classifier_worker.get_request_type_profile', return_value=None), \
         patch('src.data.data_classifier_worker.publish_high_risk') as mock_pub:
        from src.data.data_classifier_worker import classify_and_route
        classify_and_route(_FLOW)
        published = mock_pub.call_args[0][0]
        assert 'risk_level' in published
        assert 'classifier_score' in published
        assert 'machine_ip' in published
