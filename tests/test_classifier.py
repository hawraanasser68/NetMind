import pytest
import numpy as np
import yaml
from pathlib import Path
from sklearn.metrics import f1_score

THRESHOLDS_PATH = Path('eval_thresholds.yaml')
MODELS_DIR      = Path('models/')


def load_thresholds() -> dict:
    if not THRESHOLDS_PATH.exists():
        pytest.skip('eval_thresholds.yaml not found — keep off public repos, add locally')
    with open(THRESHOLDS_PATH) as f:
        return yaml.safe_load(f)['classifier']


@pytest.fixture(scope='module')
def server():
    from src.ml.ml_model_server import ModelServer
    s = ModelServer()
    s.load()
    return s


@pytest.fixture(scope='module')
def golden_set():
    path = MODELS_DIR / 'test_set.npz'
    if not path.exists():
        pytest.skip('test_set.npz not found — re-run the save cell in the training notebook')
    data = np.load(path)
    return data['X'], data['y']


def test_feature_contract_integrity():
    from src.ml.ml_feature_contract import FEATURE_COLUMNS, N_FEATURES
    assert len(FEATURE_COLUMNS) == N_FEATURES == 33


def test_model_sha256_valid(server):
    # load() already validates SHA-256 and raises ModelSHA256Mismatch on failure.
    assert server.pipeline is not None


def test_predict_returns_valid_shape(server):
    from src.ml.ml_feature_contract import N_FEATURES
    result = server.predict([0.0] * N_FEATURES)

    assert set(result.keys()) == {'label', 'confidence', 'probabilities', 'classifier_score'}
    assert result['label'] in {0, 1, 2}
    assert 0.0 <= result['confidence'] <= 1.0
    assert 0.0 <= result['classifier_score'] <= 1.0

    probs = result['probabilities']
    assert set(probs.keys()) == {'benign', 'suspicious', 'attack'}
    assert abs(sum(probs.values()) - 1.0) < 1e-6


def test_classifier_scores_meet_thresholds(server, golden_set):
    """CI gate: fails if any F1 threshold from eval_thresholds.yaml is breached."""
    thresholds = load_thresholds()
    X_test, y_test = golden_set

    preds  = server.pipeline.predict(X_test)
    scores = f1_score(y_test, preds, average=None, labels=[0, 1, 2], zero_division=0)
    macro  = float(f1_score(y_test, preds, average='macro', zero_division=0))

    assert macro     >= thresholds['macro_f1'],      f'macro_f1 {macro:.4f} < {thresholds["macro_f1"]}'
    assert scores[0] >= thresholds['benign_f1'],     f'benign_f1 {scores[0]:.4f} < {thresholds["benign_f1"]}'
    assert scores[1] >= thresholds['suspicious_f1'], f'suspicious_f1 {scores[1]:.4f} < {thresholds["suspicious_f1"]}'
    assert scores[2] >= thresholds['attack_f1'],     f'attack_f1 {scores[2]:.4f} < {thresholds["attack_f1"]}'
