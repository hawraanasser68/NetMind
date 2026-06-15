"""Unit tests for scoring pure functions (T067): normalize_z, safe_z, compute_risk_level."""
import pytest

from src.scoring.scoring_deviation import normalize_z, safe_z
from src.scoring.scoring_service import compute_risk_level

# Thresholds from config/deviation_weights.yaml (copied here so tests are self-documenting)
# critical: 0.80 | high_classifier: 0.50 | high_deviation: 0.70
# low_deviation: 0.60 | low_confidence_max: 0.30


# ── normalize_z ────────────────────────────────────────────────────────────────

def test_normalize_z_zero():
    assert normalize_z(0.0) == pytest.approx(0.0)


def test_normalize_z_three_is_maximum():
    assert normalize_z(3.0) == pytest.approx(1.0)
    assert normalize_z(-3.0) == pytest.approx(1.0)


def test_normalize_z_beyond_three_clamped():
    assert normalize_z(10.0) == pytest.approx(1.0)


def test_normalize_z_half():
    assert normalize_z(1.5) == pytest.approx(0.5)


def test_normalize_z_symmetric():
    assert normalize_z(2.0) == pytest.approx(normalize_z(-2.0))


# ── safe_z ─────────────────────────────────────────────────────────────────────

def test_safe_z_returns_zero_for_n_less_than_2():
    assert safe_z(100.0, 50.0, 100.0, 1) == 0.0
    assert safe_z(100.0, 50.0, 100.0, 0) == 0.0


def test_safe_z_returns_zero_when_std_negligible():
    # m2=0 → variance=0 → std≈0
    assert safe_z(7.0, 7.0, 0.0, 10) == 0.0


def test_safe_z_positive_for_above_mean():
    # Two observations [10, 20]: mean=15, m2=50, std=sqrt(25)=5
    z = safe_z(25.0, 15.0, 50.0, 2)
    assert z == pytest.approx((25.0 - 15.0) / 5.0)
    assert z > 0


def test_safe_z_negative_for_below_mean():
    z = safe_z(5.0, 15.0, 50.0, 2)
    assert z < 0


# ── compute_risk_level ─────────────────────────────────────────────────────────

def test_risk_level_new_machine_always_high():
    level, escalate = compute_risk_level(
        risk_score=0.1, deviation_score=0.1, confidence=0.9, is_new_machine=True,
    )
    assert level == 'HIGH'
    assert escalate is True


def test_risk_level_unknown_protocol_always_high():
    level, escalate = compute_risk_level(
        risk_score=0.1, deviation_score=0.1, confidence=0.9, is_unknown_protocol=True,
    )
    assert level == 'HIGH'
    assert escalate is True


def test_risk_level_low_confidence_capped_at_medium():
    # confidence=0.1 < low_confidence_max=0.30
    level, escalate = compute_risk_level(
        risk_score=0.9, deviation_score=0.9, confidence=0.1,
    )
    assert level == 'MEDIUM'
    assert escalate is False


def test_risk_level_critical_threshold():
    # risk_score=0.85 >= critical=0.80
    level, escalate = compute_risk_level(
        risk_score=0.85, deviation_score=0.1, confidence=0.9,
    )
    assert level == 'CRITICAL'
    assert escalate is True


def test_risk_level_high_via_classifier_score():
    # risk_score=0.55 >= high_classifier=0.50 but < 0.80
    level, escalate = compute_risk_level(
        risk_score=0.55, deviation_score=0.1, confidence=0.9,
    )
    assert level == 'HIGH'
    assert escalate is True


def test_risk_level_high_via_deviation_score():
    # deviation_score=0.75 >= high_deviation=0.70, risk_score low
    level, escalate = compute_risk_level(
        risk_score=0.1, deviation_score=0.75, confidence=0.9,
    )
    assert level == 'HIGH'
    assert escalate is True


def test_risk_level_medium_via_deviation():
    # deviation_score=0.65, >= low_deviation=0.60 but < high_deviation=0.70
    level, escalate = compute_risk_level(
        risk_score=0.1, deviation_score=0.65, confidence=0.9,
    )
    assert level == 'MEDIUM'
    assert escalate is False


def test_risk_level_low():
    level, escalate = compute_risk_level(
        risk_score=0.1, deviation_score=0.1, confidence=0.9,
    )
    assert level == 'LOW'
    assert escalate is False
