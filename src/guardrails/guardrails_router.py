from fastapi import APIRouter, Depends, Header, HTTPException

from src.guardrails.guardrails_schemas import (
    FindingCheckRequest,
    FindingCheckResponse,
    InputCheckRequest,
    InputCheckResponse,
    ToolCallCheckRequest,
    ToolCallCheckResponse,
    ToolResultCheckRequest,
    ToolResultCheckResponse,
)
from src.guardrails.guardrails_service import (
    check_finding,
    check_input,
    check_tool_call,
    check_tool_result,
)
from src.infra.infra_vault import get_secret

router = APIRouter(prefix='/guardrails', tags=['guardrails'])


def verify_service_token(authorization: str = Header(...)) -> None:
    """Reject any caller that doesn't present the correct Bearer token from Vault."""
    if authorization != f'Bearer {get_secret("service_token")}':
        raise HTTPException(status_code=403, detail='Invalid service token.')


@router.post('/check_input', response_model=InputCheckResponse)
def api_check_input(
    request: InputCheckRequest,
    _: None = Depends(verify_service_token),
) -> InputCheckResponse:
    return check_input(request)


@router.post('/check_tool_call', response_model=ToolCallCheckResponse)
def api_check_tool_call(
    request: ToolCallCheckRequest,
    _: None = Depends(verify_service_token),
) -> ToolCallCheckResponse:
    return check_tool_call(request)


@router.post('/check_tool_result', response_model=ToolResultCheckResponse)
def api_check_tool_result(
    request: ToolResultCheckRequest,
    _: None = Depends(verify_service_token),
) -> ToolResultCheckResponse:
    return check_tool_result(request)


@router.post('/check_finding', response_model=FindingCheckResponse)
def api_check_finding(
    request: FindingCheckRequest,
    _: None = Depends(verify_service_token),
) -> FindingCheckResponse:
    return check_finding(request)


@router.get('/health')
def health() -> dict:
    return {'status': 'ok', 'service': 'guardrails'}
