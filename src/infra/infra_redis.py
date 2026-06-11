import redis
from src.infra.infra_vault import get_secret

_redis_client = None


def get_redis_client() -> redis.Redis:
    """
    Returns a singleton Redis client.
    Creates the connection on first call, reuses it on every subsequent call.
    """
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis(
            host             = 'redis',
            port             = 6379,
            password         = get_secret('redis_password'),
            decode_responses = True,
        )
    return _redis_client
