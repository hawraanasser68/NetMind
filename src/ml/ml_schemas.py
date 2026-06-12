from typing import Optional
from pydantic import BaseModel


class ScoreRequest(BaseModel):
    features: list[float]           # exactly 33 values in FEATURE_COLUMNS order
    flow_id:  Optional[str] = None  # optional — used for tracing, not required for scoring


class ScoreResponse(BaseModel):
    flow_id:          Optional[str] = None
    label:            int    # 0=benign  1=suspicious  2=attack
    confidence:       float  # probability of the predicted class
    probabilities:    dict   # {'benign': float, 'suspicious': float, 'attack': float}
    classifier_score: float  # probabilities[suspicious] + probabilities[attack]


class HealthResponse(BaseModel):
    status:     str
    model_type: str
    sha256:     str   # first 16 chars + '...' (safe to expose)
    n_features: int
