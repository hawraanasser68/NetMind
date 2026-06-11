from contextlib import asynccontextmanager
from fastapi import FastAPI
from src.ml.ml_router import router
from src.ml.ml_model_server import model_server


@asynccontextmanager
async def lifespan(app: FastAPI):
    model_server.load()
    yield


app = FastAPI(title='SOC Classifier Service', lifespan=lifespan)
app.include_router(router)
