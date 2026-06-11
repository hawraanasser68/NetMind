import joblib
import json
import hashlib
import numpy as np
from pathlib import Path

MODELS_DIR = Path('models/')


class ModelServer:
    def __init__(self):
        self.pipeline   = None
        self.model_card = None

    def load(self):
        """Load Pipeline artifact and validate SHA-256. Raises RuntimeError on any failure."""
        card_path = MODELS_DIR / 'model_card.json'
        if not card_path.exists():
            raise RuntimeError(
                'Model card not found. '
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

        expected_sha256 = self.model_card['sha256']
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                f'Model SHA-256 mismatch. '
                f'Expected: {expected_sha256}. '
                f'Got: {actual_sha256}. '
                f'Refusing to start — model may have been tampered with.'
            )

        self.pipeline = joblib.load(model_path)

        print(f"Model loaded: {self.model_card['model_type']}")
        print(f"SHA-256 validated: {actual_sha256[:16]}...")

    def predict(self, features: list) -> dict:
        """Score a single flow. features must be in FEATURE_COLUMNS order (33 values)."""
        if self.pipeline is None:
            raise RuntimeError('Model not loaded. Call load() first.')

        proba = self.pipeline.predict_proba([features])[0]

        return {
            'benign_probability':     float(proba[0]),
            'suspicious_probability': float(proba[1]),
            'attack_probability':     float(proba[2]),
            'classifier_score':       float(proba[1] + proba[2]),
            'predicted_class':        int(np.argmax(proba)),
        }


model_server = ModelServer()
