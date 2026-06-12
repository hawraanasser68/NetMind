import hashlib
import json
import joblib
import numpy as np
import structlog
from pathlib import Path

from src.infra.infra_errors import ModelSHA256Mismatch
from src.ml.ml_feature_contract import N_FEATURES, CLASS_NAMES

logger     = structlog.get_logger(__name__)
MODELS_DIR = Path('models/')


class ModelServer:
    def __init__(self):
        self.pipeline   = None
        self.model_card = None

    def load(self) -> None:
        """
        Load the LightGBM pipeline and validate its SHA-256 against model_card.json.
        Raises ModelSHA256Mismatch if the file has been tampered with.
        Raises RuntimeError if required files are missing.
        """
        card_path = MODELS_DIR / 'model_card.json'
        if not card_path.exists():
            raise RuntimeError(
                'model_card.json not found. '
                'Run notebooks/train_classifier.ipynb before starting the service.'
            )
        with open(card_path) as f:
            self.model_card = json.load(f)

        model_path = MODELS_DIR / 'soc_classifier.pkl'
        if not model_path.exists():
            raise RuntimeError(
                'soc_classifier.pkl not found. '
                'Run notebooks/train_classifier.ipynb before starting the service.'
            )

        with open(model_path, 'rb') as f:
            actual_sha256 = hashlib.sha256(f.read()).hexdigest()

        expected_sha256 = self.model_card.get('sha256', '')
        if actual_sha256 != expected_sha256:
            raise ModelSHA256Mismatch(
                f'SHA-256 mismatch — model may have been tampered with. '
                f'Expected {expected_sha256[:16]}..., got {actual_sha256[:16]}...'
            )

        self.pipeline = joblib.load(model_path)
        logger.info(
            'Model loaded',
            model_type=self.model_card.get('model_type'),
            sha256_prefix=actual_sha256[:16],
            n_features=N_FEATURES,
        )

    def predict(self, features: list[float]) -> dict:
        """
        Score a single flow. features must be exactly N_FEATURES values
        in FEATURE_COLUMNS order.

        Returns a dict matching ScoreResponse fields.
        """
        if self.pipeline is None:
            raise RuntimeError('Model not loaded. Call load() first.')

        proba           = self.pipeline.predict_proba([features])[0]
        predicted_class = int(np.argmax(proba))

        return {
            'label':      predicted_class,
            'confidence': float(proba[predicted_class]),
            'probabilities': {
                CLASS_NAMES[0]: float(proba[0]),   # benign
                CLASS_NAMES[1]: float(proba[1]),   # suspicious
                CLASS_NAMES[2]: float(proba[2]),   # attack
            },
            'classifier_score': float(proba[1] + proba[2]),
        }


model_server = ModelServer()
