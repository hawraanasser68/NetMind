from fastapi import APIRouter, HTTPException

from src.infra.infra_errors import InvalidFeatureCount
from src.ml.ml_feature_contract import N_FEATURES
from src.ml.ml_model_server import model_server
from src.ml.ml_schemas import HealthResponse, ScoreRequest, ScoreResponse

router = APIRouter(prefix='/classifier', tags=['classifier'])


@router.post('/score', response_model=ScoreResponse)
def score(request: ScoreRequest) -> ScoreResponse:
    if len(request.features) != N_FEATURES:
        raise InvalidFeatureCount(
            f'Expected {N_FEATURES} features, got {len(request.features)}.'
        )
    result = model_server.predict(request.features)
    return ScoreResponse(flow_id=request.flow_id, **result)


@router.get('/health', response_model=HealthResponse)
def health() -> HealthResponse:
    if model_server.pipeline is None:
        raise HTTPException(status_code=503, detail='Model not loaded.')
    return HealthResponse(
        status     = 'ok',
        model_type = model_server.model_card['model_type'],
        sha256     = model_server.model_card['sha256'][:16] + '...',
        n_features = N_FEATURES,
    )
