# SPEC_CLASSIFIER.md
# ML Classifier Specification
# All decisions final. Implement exactly as specified.

---

## Overview

Three models trained offline in a Jupyter notebook (notebooks/train_classifier.ipynb).
One model selected and deployed in a lean model server (src/ml/).
Model server exposes HTTP API consumed by the scoring pipeline.

---

## File Structure

```
src/ml/
  ml_main.py            ← FastAPI app entry point
  ml_router.py          ← all routes
  ml_schemas.py         ← all Pydantic models
  ml_dependencies.py    ← FastAPI dependencies
  ml_service.py         ← scoring business logic
  ml_feature_contract.py← single source of truth for features
  ml_model_server.py    ← model loading and validation

notebooks/
  train_classifier.ipynb← offline training (never shipped)

models/
  model_card.json       ← SHA-256, metrics, metadata
  soc_classifier.pkl    ← deployed model (sklearn joblib)
  scaler.pkl            ← fitted StandardScaler
```

---

## ml_feature_contract.py

This file is the single source of truth. Imported by training code and production code. Never duplicated.

```python
# src/ml/ml_feature_contract.py

FEATURE_COLUMNS = [
    # Volume
    'Tot Fwd Pkts',
    'Tot Bwd Pkts',
    'TotLen Fwd Pkts',
    'TotLen Bwd Pkts',
    # Rate
    'Flow Byts/s',
    'Flow Pkts/s',
    'Fwd Pkts/s',
    'Bwd Pkts/s',
    # Timing
    'Flow Duration',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    # Active/Idle
    'Active Mean',
    'Active Std',
    'Idle Mean',
    'Idle Std',
    # TCP Flags
    'SYN Flag Cnt',
    'FIN Flag Cnt',
    'RST Flag Cnt',
    'PSH Flag Cnt',
    'ACK Flag Cnt',
    'URG Flag Cnt',
    # Packet size
    'Pkt Len Mean',
    'Pkt Len Std',
    'Down/Up Ratio',
    # Derived (computed before feeding to model)
    'byte_ratio',
    'proto_tcp',
    'proto_udp',
    'proto_icmp',
    'is_privileged_port',
]

TARGET_COLUMN = 'label'
N_FEATURES    = 33
N_CLASSES     = 3

LABEL_MAP = {
    'Benign':                   0,
    'Infilteration':            1,   # suspicious — only source is 02-28 and 03-01
    # Brute force (spec names + actual dataset names)
    'FTP-BruteForce':           2,
    'SSH-Bruteforce':           2,
    'Brute Force -Web':         2,
    'BruteForce-Web':           2,
    'Brute Force -XSS':         2,
    'BruteForce-XSS':           2,
    # Injection
    'SQL Injection':            2,
    'SQL-Injection':            2,
    # DoS
    'DoS attacks-GoldenEye':    2,
    'DoS-GoldenEye':            2,
    'DoS attacks-SlowHTTPTest': 2,
    'DoS-Slowhttptest':         2,
    'DoS attacks-Hulk':         2,
    'DoS-Hulk':                 2,
    'DoS attacks-Slowloris':    2,
    'DoS-Slowloris':            2,
    # DDoS
    'DDoS attacks-LOIC-HTTP':   2,
    'DDoS-LOIC-HTTP':           2,
    'DDOS attack-LOIC-UDP':     2,
    'DDoS-LOIC-UDP':            2,
    'DDOS attack-HOIC':         2,
    'DDoS-HOIC':                2,
    # Other
    'Bot':                      2,
    'Heartbleed':               2,
}

CLASS_NAMES = {0: 'benign', 1: 'suspicious', 2: 'attack'}

CLEANING_RULES = {
    'drop_negative_duration': True,     # drop rows where Flow Duration < 0
    'replace_inf_with_zero':  True,     # in rate columns
    'fill_nulls_with_zero':   True,
}

RATE_COLUMNS = ['Flow Byts/s', 'Flow Pkts/s', 'Fwd Pkts/s', 'Bwd Pkts/s']
```

---

## Training Notebook (Offline Only — Never Shipped)

### Data Loading and Cleaning

```python
import pandas as pd
import numpy as np
from src.ml.ml_feature_contract import (
    FEATURE_COLUMNS, TARGET_COLUMN, LABEL_MAP,
    CLEANING_RULES, RATE_COLUMNS
)

# All 10 files loaded together.
# Infilteration (suspicious) only exists in 02-28 and 03-01 — a file-level
# temporal split would put it entirely in training with 0 suspicious in test.
# Stratified split is used instead (see Decision 2).
ALL_FILES = [
    'data/02-14-2018.csv',   # FTP-BruteForce
    'data/02-15-2018.csv',   # DoS-GoldenEye
    'data/02-16-2018.csv',   # DoS-SlowHTTPTest
    'data/02-20-2018.csv',   # DDoS-LOIC-HTTP
    'data/02-21-2018.csv',   # DDoS-LOIC-UDP, DDoS-HOIC
    'data/02-22-2018.csv',   # Brute Force, SQL Injection
    'data/02-23-2018.csv',   # Brute Force, SQL Injection
    'data/02-28-2018.csv',   # Infilteration (suspicious)
    'data/03-01-2018.csv',   # Infilteration (suspicious)
    'data/03-02-2018.csv',   # Bot
]

def load_and_clean(file_paths: list, max_rows_per_file: int = 150_000) -> pd.DataFrame:
    ESTIMATED_FILE_SIZE = 1_048_576
    dfs = []
    for path in file_paths:
        step   = max(1, ESTIMATED_FILE_SIZE // max_rows_per_file)
        skipfn = lambda i, s=step: i > 0 and i % s != 0
        df = pd.read_csv(path, skiprows=skipfn, low_memory=False)

        # Coerce all columns except Label to numeric.
        # Some files have a repeated header row mid-file that corrupts dtype inference.
        for col in df.columns:
            if col != 'Label':
                df[col] = pd.to_numeric(df[col], errors='coerce')

        df = df[df['Flow Duration'] >= 0]

        for col in RATE_COLUMNS:
            if col in df.columns:
                df[col] = df[col].replace([np.inf, -np.inf], 0)

        df = df.fillna(0)
        dfs.append(df)

    return pd.concat(dfs, ignore_index=True)

def compute_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    df['byte_ratio'] = np.where(
        df['TotLen Fwd Pkts'] > 0,
        df['TotLen Bwd Pkts'] / df['TotLen Fwd Pkts'],
        0
    )
    df['proto_tcp']  = (df['Protocol'] == 6).astype(int)
    df['proto_udp']  = (df['Protocol'] == 17).astype(int)
    df['proto_icmp'] = (df['Protocol'] == 0).astype(int)
    df['is_privileged_port'] = (df['Dst Port'] < 1024).astype(int)
    return df

def map_labels(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df['label'] = df['Label'].map(LABEL_MAP)
    df = df[df['label'].notna()]
    return df

# Load, engineer, map
combined_df = load_and_clean(ALL_FILES)
combined_df = compute_derived_features(combined_df)
combined_df = map_labels(combined_df)

# Balance classes: take all suspicious rows (rarest), sample equal amounts
# of benign and attack so the model gets equal signal for all three classes.
n_suspicious = int((combined_df['label'] == 1).sum())
balanced_df  = pd.concat([
    combined_df[combined_df['label'] == cid].sample(n=n_suspicious, random_state=42)
    for cid in [0, 1, 2]
], ignore_index=True)

# Stratified 80/20 split — guarantees all 3 classes in both train and test.
from sklearn.model_selection import train_test_split
X = balanced_df[FEATURE_COLUMNS]
y = balanced_df[TARGET_COLUMN]
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

print(f"Train: {len(X_train)} rows")
print(f"Test:  {len(X_test)} rows")
print(f"Label distribution (train): {y_train.value_counts().to_dict()}")
```

---

### Scaling

```python
from sklearn.preprocessing import StandardScaler
import joblib

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

# Save scaler immediately
joblib.dump(scaler, 'models/scaler.pkl')
```

---

### Model 1 — Random Forest (Classical ML)

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import TimeSeriesSplit, cross_val_score
from sklearn.metrics import f1_score, classification_report, roc_auc_score
import time

print("Training Random Forest...")
start = time.time()

rf = RandomForestClassifier(
    n_estimators=500,
    max_depth=20,
    max_features='sqrt',
    n_jobs=-1,
    random_state=42
)

# TimeSeriesSplit cross-validation
tscv = TimeSeriesSplit(n_splits=5)
cv_scores = cross_val_score(rf, X_train_scaled, y_train, cv=tscv, scoring='f1_macro')
print(f"RF CV F1 (macro): {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

rf.fit(X_train_scaled, y_train)
train_duration = time.time() - start

# Evaluate on test set
rf_preds = rf.predict(X_test_scaled)
rf_proba = rf.predict_proba(X_test_scaled)

rf_metrics = {
    'model':           'RandomForest',
    'macro_f1':        f1_score(y_test, rf_preds, average='macro'),
    'benign_f1':       f1_score(y_test, rf_preds, average=None)[0],
    'suspicious_f1':   f1_score(y_test, rf_preds, average=None)[1],
    'attack_f1':       f1_score(y_test, rf_preds, average=None)[2],
    'cv_mean':         cv_scores.mean(),
    'cv_std':          cv_scores.std(),
    'train_duration_s': train_duration,
}
print(classification_report(y_test, rf_preds, target_names=['benign','suspicious','attack']))
```

---

### Model 2 — Gradient Boosting (DL alternative for this scope)

```python
from sklearn.ensemble import GradientBoostingClassifier

print("Training Gradient Boosting...")
start = time.time()

gb = GradientBoostingClassifier(
    n_estimators=300,
    learning_rate=0.1,
    max_depth=5,
    subsample=0.8,
    random_state=42
)

cv_scores_gb = cross_val_score(gb, X_train_scaled, y_train, cv=tscv, scoring='f1_macro')
print(f"GB CV F1 (macro): {cv_scores_gb.mean():.4f} (+/- {cv_scores_gb.std():.4f})")

gb.fit(X_train_scaled, y_train)
train_duration_gb = time.time() - start

gb_preds = gb.predict(X_test_scaled)
gb_metrics = {
    'model':           'GradientBoosting',
    'macro_f1':        f1_score(y_test, gb_preds, average='macro'),
    'benign_f1':       f1_score(y_test, gb_preds, average=None)[0],
    'suspicious_f1':   f1_score(y_test, gb_preds, average=None)[1],
    'attack_f1':       f1_score(y_test, gb_preds, average=None)[2],
    'cv_mean':         cv_scores_gb.mean(),
    'cv_std':          cv_scores_gb.std(),
    'train_duration_s': train_duration_gb,
}
print(classification_report(y_test, gb_preds, target_names=['benign','suspicious','attack']))
```

---

### Model 3 — LLM Zero-Shot Baseline

```python
import anthropic
import json

client = anthropic.Anthropic()

def llm_classify(flow_row: dict) -> int:
    prompt = f"""
    Classify this network flow as benign (0), suspicious (1), or attack (2).
    Return only the integer.

    Flow features:
    {json.dumps(flow_row, indent=2)}
    """

    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=10,
        messages=[{"role": "user", "content": prompt}]
    )

    try:
        return int(response.content[0].text.strip())
    except:
        return 0  # default to benign on parse error

# Run on sample of test set (cost control — 100 samples)
sample_indices = np.random.choice(len(X_test), 100, replace=False)
X_test_sample  = X_test.iloc[sample_indices]
y_test_sample  = y_test.iloc[sample_indices]

llm_preds = []
for _, row in X_test_sample.iterrows():
    pred = llm_classify(row.to_dict())
    llm_preds.append(pred)

llm_metrics = {
    'model':         'LLM_ZeroShot',
    'macro_f1':      f1_score(y_test_sample, llm_preds, average='macro'),
    'sample_size':   100,
    'note':          'sampled due to API cost'
}
```

---

### Model Comparison and Selection

```python
import json
import hashlib

# Print comparison table
print("\n=== MODEL COMPARISON ===")
print(f"{'Model':<25} {'Macro F1':<12} {'Benign F1':<12} {'Susp F1':<12} {'Attack F1':<12} {'Train Time'}")
print("-" * 85)
for m in [rf_metrics, gb_metrics, llm_metrics]:
    print(f"{m['model']:<25} {m['macro_f1']:<12.4f} "
          f"{m.get('benign_f1', 'N/A'):<12} "
          f"{m.get('suspicious_f1', 'N/A'):<12} "
          f"{m.get('attack_f1', 'N/A'):<12} "
          f"{m.get('train_duration_s', 'N/A')}")

# Select winner — decision documented in DECISIONS.md
# Default: Random Forest unless Gradient Boosting beats it by > 0.03 macro_f1
if gb_metrics['macro_f1'] - rf_metrics['macro_f1'] > 0.03:
    winning_model = gb
    winning_name  = 'GradientBoosting'
    winning_metrics = gb_metrics
else:
    winning_model = rf
    winning_name  = 'RandomForest'
    winning_metrics = rf_metrics

print(f"\nSelected: {winning_name}")

# Save winning model
joblib.dump(winning_model, 'models/soc_classifier.pkl')

# Compute SHA-256
with open('models/soc_classifier.pkl', 'rb') as f:
    sha256 = hashlib.sha256(f.read()).hexdigest()

# Save model card
model_card = {
    'model_name':      'soc-classifier',
    'model_type':      winning_name,
    'sha256':          sha256,
    'n_features':      N_FEATURES,
    'n_classes':       N_CLASSES,
    'feature_columns': FEATURE_COLUMNS,
    'label_map':       LABEL_MAP,
    'train_files':     TRAIN_FILES,
    'test_files':      TEST_FILES,
    'metrics':         winning_metrics,
    'all_models':      [rf_metrics, gb_metrics, llm_metrics],
    'trained_at':      pd.Timestamp.now().isoformat(),
}

with open('models/model_card.json', 'w') as f:
    json.dump(model_card, f, indent=2)

print(f"SHA-256: {sha256}")
print("Model card saved to models/model_card.json")
print("Training complete.")
```

---

## Model Server (Production)

### ml_model_server.py

```python
# src/ml/ml_model_server.py

import joblib
import json
import hashlib
import numpy as np
from pathlib import Path

MODELS_DIR = Path('models/')

class ModelServer:
    def __init__(self):
        self.classifier = None
        self.scaler     = None
        self.model_card = None

    def load(self):
        """Load models and validate SHA-256. Raises on mismatch."""

        # Load model card
        card_path = MODELS_DIR / 'model_card.json'
        if not card_path.exists():
            raise RuntimeError(
                "Model card not found. "
                "Run training notebook before starting the service."
            )

        with open(card_path) as f:
            self.model_card = json.load(f)

        # Load model
        model_path = MODELS_DIR / 'soc_classifier.pkl'
        if not model_path.exists():
            raise RuntimeError(
                "Classifier model not found. "
                "Run training notebook before starting the service."
            )

        # Validate SHA-256
        with open(model_path, 'rb') as f:
            actual_sha256 = hashlib.sha256(f.read()).hexdigest()

        expected_sha256 = self.model_card['sha256']
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                f"Model SHA-256 mismatch. "
                f"Expected: {expected_sha256}. "
                f"Got: {actual_sha256}. "
                f"Refusing to start — model weights may have been tampered with."
            )

        self.classifier = joblib.load(model_path)
        self.scaler     = joblib.load(MODELS_DIR / 'scaler.pkl')

        print(f"Model loaded: {self.model_card['model_type']}")
        print(f"SHA-256 validated: {actual_sha256[:16]}...")

    def predict(self, features: list) -> dict:
        """Score a single flow. Returns probabilities and classifier_score."""

        scaled = self.scaler.transform([features])
        proba  = self.classifier.predict_proba(scaled)[0]

        return {
            'benign_probability':     float(proba[0]),
            'suspicious_probability': float(proba[1]),
            'attack_probability':     float(proba[2]),
            'classifier_score':       float(proba[1] + proba[2]),
            'predicted_class':        int(np.argmax(proba)),
        }

model_server = ModelServer()
```

---

### ml_schemas.py

```python
# src/ml/ml_schemas.py

from pydantic import BaseModel
from typing import List

class ScoreRequest(BaseModel):
    flow_id:   str
    features:  List[float]  # exactly 33 values in feature contract order

class ScoreResponse(BaseModel):
    flow_id:                  str
    benign_probability:       float
    suspicious_probability:   float
    attack_probability:       float
    classifier_score:         float   # proba[1] + proba[2]
    predicted_class:          int     # 0=benign, 1=suspicious, 2=attack

class HealthResponse(BaseModel):
    status:      str
    model_type:  str
    sha256:      str
    n_features:  int
```

---

### ml_router.py

```python
# src/ml/ml_router.py

from fastapi import APIRouter
from src.ml.ml_schemas import ScoreRequest, ScoreResponse, HealthResponse
from src.ml.ml_model_server import model_server
from src.ml.ml_feature_contract import N_FEATURES

router = APIRouter(prefix="/classifier", tags=["classifier"])

@router.post("/score", response_model=ScoreResponse)
def score_flow(request: ScoreRequest) -> ScoreResponse:
    if len(request.features) != N_FEATURES:
        raise ValueError(
            f"Expected {N_FEATURES} features, got {len(request.features)}. "
            f"Check feature contract."
        )
    result = model_server.predict(request.features)
    return ScoreResponse(flow_id=request.flow_id, **result)

@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status     = "ok",
        model_type = model_server.model_card['model_type'],
        sha256     = model_server.model_card['sha256'][:16] + "...",
        n_features = N_FEATURES,
    )
```

---

### ml_main.py

```python
# src/ml/ml_main.py

from fastapi import FastAPI
from src.ml.ml_router import router
from src.ml.ml_model_server import model_server
from src.infra.infra_vault import load_secrets

app = FastAPI(title="SOC Classifier Service")
app.include_router(router)

@app.on_event("startup")
def startup():
    load_secrets()       # load from Vault
    model_server.load()  # load model + validate SHA-256
                         # raises RuntimeError if validation fails
                         # service will not start
```

---

## CI Gate — Classifier Eval

```python
# tests/test_classifier.py

import pytest
import numpy as np
from sklearn.metrics import f1_score
import yaml

def load_thresholds():
    with open('eval_thresholds.yaml') as f:
        return yaml.safe_load(f)

def test_classifier_macro_f1():
    thresholds = load_thresholds()
    # Load test set
    # Score with model server
    # Assert macro_f1 >= thresholds['classifier']['macro_f1']
    pass

def test_classifier_per_class_f1():
    thresholds = load_thresholds()
    # Assert per-class F1 >= respective thresholds
    pass

def test_feature_contract_integrity():
    """Feature contract has exactly 33 features."""
    from src.ml.ml_feature_contract import FEATURE_COLUMNS, N_FEATURES
    assert len(FEATURE_COLUMNS) == N_FEATURES == 33

def test_model_sha256_valid():
    """Model server loads without raising."""
    from src.ml.ml_model_server import ModelServer
    server = ModelServer()
    server.load()  # raises if SHA-256 mismatch
```

---

## Docker Compose — Classifier Service

```yaml
classifier:
  build:
    context: .
    dockerfile: Dockerfile.classifier
  ports:
    - "8001:8001"
  volumes:
    - ./models:/app/models:ro   # read-only — never modified at runtime
  environment:
    VAULT_ADDR:       ${VAULT_ADDR}
    VAULT_TOKEN:      ${VAULT_TOKEN}
  depends_on:
    - vault
    - migrate
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:8001/classifier/health"]
    interval: 30s
    timeout: 10s
    retries: 3
```

---

## Error Handling

```python
from src.infra.infra_errors import SOCError

class ModelNotLoaded(SOCError):
    def __init__(self):
        super().__init__(
            user_message="The threat classifier is not ready yet. "
                         "Please try again in a moment.",
            technical_detail="Model server not initialized"
        )

class InvalidFeatureCount(SOCError):
    def __init__(self, expected: int, got: int):
        super().__init__(
            user_message="A flow could not be scored due to a data format issue. "
                         "The flow has been logged for review.",
            technical_detail=f"Expected {expected} features, got {got}"
        )
```
