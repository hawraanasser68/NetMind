from src.infra.infra_db import get_db_session
from src.infra.infra_redis import get_redis_client


def get_db():
    return get_db_session()


def get_redis():
    return get_redis_client()
