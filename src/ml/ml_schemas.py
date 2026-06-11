from pydantic import BaseModel
from typing import List


class ScoreRequest(BaseModel):
    flow_id:  str
    features: List[float]  # exactly 33 values in FEATURE_COLUMNS order


class ScoreResponse(BaseModel):
    flow_id:                  str
    benign_probability:       float
    suspicious_probability:   float
    attack_probability:       float
    classifier_score:         float   # proba[suspicious] + proba[attack]
    predicted_class:          int     # 0=benign, 1=suspicious, 2=attack


class HealthResponse(BaseModel):
    status:      str
    model_type:  str
    sha256:      str
    n_features:  int
