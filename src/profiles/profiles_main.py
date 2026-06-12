from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.infra.infra_logging import configure_logging
from src.infra.infra_vault import load_secrets
from src.profiles.profiles_router import router

configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_secrets()
    yield


app = FastAPI(title='SOC Agent — Profiles Service', lifespan=lifespan)
app.include_router(router)
