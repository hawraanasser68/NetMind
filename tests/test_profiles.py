"""Unit tests for Welford online algorithm and z-score helpers (T069)."""
import math

import pytest

from src.profiles.profiles_service import normalize_z, safe_z_score, welford_update


# ── welford_update ─────────────────────────────────────────────────────────────

def test_welford_first_observation():
    mean, m2, n = welford_update(0.0, 0.0, 0, 10.0)
    assert n == 1
    assert mean == pytest.approx(10.0)
    assert m2 == pytest.approx(0.0)


def test_welford_two_observations():
    mean, m2, n = welford_update(0.0, 0.0, 0, 10.0)
    mean, m2, n = welford_update(mean, m2, n, 20.0)
    assert n == 2
    assert mean == pytest.approx(15.0)
    # Population variance = 25; Welford M2 stores sum of squared deviations = n * variance = 50
    assert m2 == pytest.approx(50.0)


def test_welford_converges_to_known_mean():
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    mean, m2, n = 0.0, 0.0, 0
    for v in values:
        mean, m2, n = welford_update(mean, m2, n, v)
    assert mean == pytest.approx(3.0)
    assert n == 5


def test_welford_variance_correct():
    # All same value → variance = 0
    mean, m2, n = 0.0, 0.0, 0
    for _ in range(5):
        mean, m2, n = welford_update(mean, m2, n, 7.0)
    assert m2 == pytest.approx(0.0)


# ── safe_z_score ───────────────────────────────────────────────────────────────

def test_safe_z_score_returns_zero_for_n_less_than_2():
    assert safe_z_score(100.0, 50.0, 100.0, 1) == 0.0
    assert safe_z_score(100.0, 50.0, 100.0, 0) == 0.0


def test_safe_z_score_returns_zero_when_std_negligible():
    # All same values → m2=0 → std≈0
    assert safe_z_score(7.0, 7.0, 0.0, 5) == 0.0


def test_safe_z_score_correct_value():
    # Two observations [10, 20]: mean=15, m2=50, n=2, std=sqrt(50/2)=5
    mean, m2, n = 0.0, 0.0, 0
    mean, m2, n = welford_update(mean, m2, n, 10.0)
    mean, m2, n = welford_update(mean, m2, n, 20.0)
    z = safe_z_score(25.0, mean, m2, n)
    assert z == pytest.approx((25.0 - 15.0) / 5.0)


def test_safe_z_score_negative_for_below_mean():
    mean, m2, n = 0.0, 0.0, 0
    mean, m2, n = welford_update(mean, m2, n, 10.0)
    mean, m2, n = welford_update(mean, m2, n, 20.0)
    z = safe_z_score(5.0, mean, m2, n)
    assert z < 0


# ── normalize_z ────────────────────────────────────────────────────────────────

def test_normalize_z_zero():
    assert normalize_z(0.0) == pytest.approx(0.0)


def test_normalize_z_three_maps_to_one():
    assert normalize_z(3.0) == pytest.approx(1.0)
    assert normalize_z(-3.0) == pytest.approx(1.0)


def test_normalize_z_clamped_at_one():
    assert normalize_z(6.0) == pytest.approx(1.0)
    assert normalize_z(-6.0) == pytest.approx(1.0)


def test_normalize_z_midpoint():
    assert normalize_z(1.5) == pytest.approx(0.5)


def test_normalize_z_symmetric():
    assert normalize_z(2.0) == pytest.approx(normalize_z(-2.0))
