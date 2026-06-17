import json
import structlog

from src.infra.infra_db import get_db_session
from src.infra.infra_redis import get_redis_client
from src.profiles.profiles_service import welford_update

logger = structlog.get_logger(__name__)

PROFILE_CACHE_TTL = 3600   # Redis TTL in seconds

_CACHE_KEY_PREFIX   = 'reqtype:'
_POPULATION_SENTINEL = '0.0.0.0'

_PORT_TO_REQUEST_TYPE = {
    80:  'HTTP',
    443: 'HTTPS',
    53:  'DNS',
    22:  'SSH',
    21:  'FTP',
    25:  'SMTP',
}


def _request_type_for_port(dst_port: int) -> str:
    return _PORT_TO_REQUEST_TYPE.get(dst_port, 'UNKNOWN')


def _cache_key(machine_ip: str, request_type: str) -> str:
    return f'{_CACHE_KEY_PREFIX}{machine_ip}:{request_type}'


def _empty_request_type_profile(machine_ip: str, request_type: str) -> dict:
    return {
        'machine_ip':   machine_ip,
        'request_type': request_type,
        'flow_count':   0,
        'first_seen':   None,
        'last_seen':    None,
        'bytes_mean':   0.0,
        'bytes_m2':     0.0,
    }


def _get_or_load_profile(machine_ip: str, request_type: str) -> dict:
    """
    Cache-aside: Redis (hot, TTL 3600s) → PostgreSQL → population sentinel → empty.
    Shared across all worker replicas via Redis.
    """
    redis  = get_redis_client()
    cached = redis.get(_cache_key(machine_ip, request_type))
    if cached:
        return json.loads(cached)

    conn = get_db_session()
    with conn.cursor() as cur:
        cur.execute(
            'SELECT * FROM request_type_profiles WHERE machine_ip = %s AND request_type = %s',
            (machine_ip, request_type),
        )
        row = cur.fetchone()

    if row:
        profile = dict(row)
    else:
        # Seed from population baseline so the first flow has a meaningful reference
        with conn.cursor() as cur:
            cur.execute(
                'SELECT * FROM request_type_profiles WHERE machine_ip = %s AND request_type = %s',
                (_POPULATION_SENTINEL, request_type),
            )
            seed = cur.fetchone()

        profile = (
            {
                'machine_ip':   machine_ip,
                'request_type': request_type,
                'flow_count':   int(seed['flow_count']),
                'first_seen':   None,
                'last_seen':    None,
                'bytes_mean':   float(seed['bytes_mean']),
                'bytes_m2':     float(seed['bytes_m2']),
            }
            if seed
            else _empty_request_type_profile(machine_ip, request_type)
        )

    _write_redis(profile)
    return profile


def _write_redis(profile: dict) -> None:
    """Write profile to Redis. Called on every flow — keeps all replicas in sync."""
    get_redis_client().set(
        _cache_key(profile['machine_ip'], profile['request_type']),
        json.dumps(profile, default=str),
        ex=PROFILE_CACHE_TTL,
    )


def _upsert_db(profile: dict) -> None:
    """Persist profile to PostgreSQL. Called every 10 flows."""
    conn = get_db_session()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO request_type_profiles
                (machine_ip, request_type, flow_count, first_seen, last_seen,
                 bytes_mean, bytes_m2)
            VALUES
                (%(machine_ip)s, %(request_type)s, %(flow_count)s, %(first_seen)s,
                 %(last_seen)s, %(bytes_mean)s, %(bytes_m2)s)
            ON CONFLICT (machine_ip, request_type) DO UPDATE SET
                flow_count = EXCLUDED.flow_count,
                last_seen  = EXCLUDED.last_seen,
                bytes_mean = EXCLUDED.bytes_mean,
                bytes_m2   = EXCLUDED.bytes_m2
        """, profile)
    conn.commit()


def get_request_type_profile(machine_ip: str, dst_port: int) -> dict:
    """Read-only profile fetch for the classifier worker. Never writes."""
    return _get_or_load_profile(machine_ip, _request_type_for_port(dst_port))


def update_request_type_profile(flow: dict) -> dict:
    """
    Update the per-(machine, request_type) profile for one flow.
    Redis updated on every flow; PostgreSQL every 10 flows.
    Returns the updated profile (used by the deviation formula).
    """
    machine_ip   = flow['machine_ip']
    dst_port     = int(flow.get('dst_port', 0))
    request_type = _request_type_for_port(dst_port)
    captured_at  = flow.get('captured_at')

    features    = flow.get('features', [])
    fwd_bytes   = features[2] if len(features) > 2 else 0.0
    bwd_bytes   = features[3] if len(features) > 3 else 0.0
    total_bytes = fwd_bytes + bwd_bytes

    profile = _get_or_load_profile(machine_ip, request_type)

    profile['bytes_mean'], profile['bytes_m2'], n = welford_update(
        profile['bytes_mean'], profile['bytes_m2'], profile['flow_count'], total_bytes,
    )
    profile['flow_count'] = n

    if profile['first_seen'] is None:
        profile['first_seen'] = captured_at
    profile['last_seen'] = captured_at

    _write_redis(profile)

    if n % 10 == 0:
        _upsert_db(profile)

    return profile
