from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.infra.infra_errors import SOCError, InvalidFeatureCount
from src.infra.infra_logging import configure_logging
from src.infra.infra_vault import load_secrets
from src.ml.ml_model_server import model_server
from src.ml.ml_router import router

configure_logging()
logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_secrets()
    model_server.load()
    logger.info('Classifier service ready')
    yield
    logger.info('Classifier service shutting down')


app = FastAPI(title='SOC Classifier Service', version='1.0.0', lifespan=lifespan)
app.include_router(router)


@app.exception_handler(InvalidFeatureCount)
async def invalid_feature_count_handler(request: Request, exc: InvalidFeatureCount):
    return JSONResponse(status_code=422, content={'detail': str(exc)})


@app.exception_handler(SOCError)
async def soc_error_handler(request: Request, exc: SOCError):
    logger.error('SOCError in classifier service', error=str(exc))
    return JSONResponse(status_code=500, content={'detail': str(exc)})


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    logger.error('Unhandled exception in classifier service', error=str(exc))
    return JSONResponse(status_code=500, content={'detail': 'Internal server error'})
