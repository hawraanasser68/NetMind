from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.agent.agent_router import router
from src.infra.infra_errors import SOCError
from src.infra.infra_logging import configure_logging
from src.infra.infra_vault import load_secrets

configure_logging()
logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_secrets()
    yield


app = FastAPI(title='SOC Agent — Agent Service', lifespan=lifespan)
app.include_router(router)


@app.exception_handler(SOCError)
async def soc_error_handler(request: Request, exc: SOCError) -> JSONResponse:
    logger.error('SOC error', detail=exc.technical_detail)
    return JSONResponse(status_code=500, content={'detail': exc.user_message})


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception('Unhandled error')
    return JSONResponse(status_code=500, content={'detail': 'Internal server error'})
