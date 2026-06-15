"""HTTP integration tests for the classifier FastAPI service."""
import pytest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.ml.ml_feature_contract import N_FEATURES


@pytest.fixture(scope='module')
def client():
    """Start the classifier app with load_secrets patched out (model files are real)."""
    with patch('src.ml.ml_main.load_secrets'):
        from src.ml.ml_main import app
        with TestClient(app) as c:
            yield c


# ── Health ─────────────────────────────────────────────────────────────────────

def test_health_returns_ok(client):
    resp = client.get('/classifier/health')
    assert resp.status_code == 200
    body = resp.json()
    assert body['status'] == 'ok'
    assert body['n_features'] == N_FEATURES
    assert 'model_type' in body


# ── Score endpoint ─────────────────────────────────────────────────────────────

def test_score_valid_features_returns_200(client):
    resp = client.post('/classifier/score', json={'features': [0.0] * N_FEATURES})
    assert resp.status_code == 200


def test_score_response_shape(client):
    resp = client.post('/classifier/score', json={'features': [0.0] * N_FEATURES})
    body = resp.json()
    assert body['label'] in (0, 1, 2)
    assert 0.0 <= body['confidence'] <= 1.0
    assert 0.0 <= body['classifier_score'] <= 1.0
    assert set(body['probabilities'].keys()) == {'benign', 'suspicious', 'attack'}


def test_score_probabilities_sum_to_one(client):
    resp = client.post('/classifier/score', json={'features': [0.0] * N_FEATURES})
    probs = resp.json()['probabilities']
    assert abs(sum(probs.values()) - 1.0) < 1e-5


def test_score_wrong_feature_count_returns_422(client):
    resp = client.post('/classifier/score', json={'features': [0.0] * 10})
    assert resp.status_code == 422


def test_score_too_many_features_returns_422(client):
    resp = client.post('/classifier/score', json={'features': [0.0] * (N_FEATURES + 1)})
    assert resp.status_code == 422


def test_score_echoes_flow_id(client):
    resp = client.post('/classifier/score',
        json={'features': [0.0] * N_FEATURES, 'flow_id': 'test-abc'})
    assert resp.json().get('flow_id') == 'test-abc'


def test_score_empty_body_returns_422(client):
    resp = client.post('/classifier/score', json={})
    assert resp.status_code == 422
