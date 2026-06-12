from fastapi import APIRouter, Depends

from src.agent.agent_dependencies import get_db, get_redis
from src.agent.agent_schemas import AgentRequest, AgentResponse
from src.agent.agent_service import process_flow

router = APIRouter(prefix='/agent', tags=['agent'])


@router.post('/analyze', response_model=AgentResponse)
async def analyze_flow(
    request: AgentRequest,
    db    = Depends(get_db),
    redis = Depends(get_redis),
) -> AgentResponse:
    finding = process_flow(request.scoring_result, request.flow, redis, db)
    return AgentResponse(**finding)


@router.get('/health')
def health() -> dict:
    return {'status': 'ok', 'service': 'agent'}
