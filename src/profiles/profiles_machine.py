import ipaddress
import structlog
from sentence_transformers import SentenceTransformer

from src.infra.infra_db import get_db_session
from src.profiles.profiles_service import welford_update

logger = structlog.get_logger(__name__)

# New machines are buffered in memory until they reach GRADUATION_THRESHOLD flows.
# Below this count, the deviation formula treats them as new-machine HIGH risk.
GRADUATION_THRESHOLD = 10
SNAPSHOT_INTERVAL    = 100   # generate a pgvector embedding every N flows
SNAPSHOT_KEEP        = 10    # retain only the latest N snapshots per machine

_profile_cache: dict[str, dict] = {}   # machine_ip → profile dict
_new_machine_buffer: dict[str, list] = {}  # machine_ip → list of flows (pre-graduation)

_embedder: SentenceTransformer | None = None


def _get_embedder() -> SentenceTransformer:
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformer('all-MiniLM-L6-v2')
    return _embedder


def _is_rfc1918(ip: str) -> bool:
    """Return True if the IP is a private (RFC 1918) address."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _empty_profile(machine_ip: str) -> dict:
    return {
        'machine_ip':         machine_ip,
        'flow_count':         0,
        'first_seen':         None,
        'last_seen':          None,
        'bytes_mean':         0.0, 'bytes_m2':         0.0,
        'bytes_per_sec_mean': 0.0, 'bytes_per_sec_m2': 0.0,
        'byte_ratio_mean':    0.0, 'byte_ratio_m2':    0.0,
        'pkts_mean':          0.0, 'pkts_m2':          0.0,
        'duration_mean':      0.0, 'duration_m2':      0.0,
        'known_ports':        [],
        'known_protocols':    [],
    }


def _get_or_load_profile(machine_ip: str) -> dict:
    """Cache-aside: return from memory, or load from DB, or return empty."""
    if machine_ip in _profile_cache:
        return _profile_cache[machine_ip]

    conn = get_db_session()
    with conn.cursor() as cur:
        cur.execute(
            'SELECT * FROM machine_profiles WHERE machine_ip = %s',
            (machine_ip,),
        )
        row = cur.fetchone()

    if row:
        profile = dict(row)
        profile['known_ports']     = list(profile.get('known_ports') or [])
        profile['known_protocols'] = list(profile.get('known_protocols') or [])
    else:
        profile = _empty_profile(machine_ip)

    _profile_cache[machine_ip] = profile
    return profile


def _upsert_profile(profile: dict) -> None:
    """Write the in-memory profile to PostgreSQL (INSERT or UPDATE)."""
    conn = get_db_session()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO machine_profiles (
                machine_ip, flow_count, first_seen, last_seen,
                bytes_mean, bytes_m2, bytes_per_sec_mean, bytes_per_sec_m2,
                byte_ratio_mean, byte_ratio_m2, pkts_mean, pkts_m2,
                duration_mean, duration_m2, known_ports, known_protocols
            ) VALUES (
                %(machine_ip)s, %(flow_count)s, %(first_seen)s, %(last_seen)s,
                %(bytes_mean)s, %(bytes_m2)s, %(bytes_per_sec_mean)s, %(bytes_per_sec_m2)s,
                %(byte_ratio_mean)s, %(byte_ratio_m2)s, %(pkts_mean)s, %(pkts_m2)s,
                %(duration_mean)s, %(duration_m2)s, %(known_ports)s, %(known_protocols)s
            )
            ON CONFLICT (machine_ip) DO UPDATE SET
                flow_count         = EXCLUDED.flow_count,
                last_seen          = EXCLUDED.last_seen,
                bytes_mean         = EXCLUDED.bytes_mean,
                bytes_m2           = EXCLUDED.bytes_m2,
                bytes_per_sec_mean = EXCLUDED.bytes_per_sec_mean,
                bytes_per_sec_m2   = EXCLUDED.bytes_per_sec_m2,
                byte_ratio_mean    = EXCLUDED.byte_ratio_mean,
                byte_ratio_m2      = EXCLUDED.byte_ratio_m2,
                pkts_mean          = EXCLUDED.pkts_mean,
                pkts_m2            = EXCLUDED.pkts_m2,
                duration_mean      = EXCLUDED.duration_mean,
                duration_m2        = EXCLUDED.duration_m2,
                known_ports        = EXCLUDED.known_ports,
                known_protocols    = EXCLUDED.known_protocols
        """, profile)
    conn.commit()


def maybe_generate_snapshot(machine_ip: str, profile: dict) -> None:
    """
    Every SNAPSHOT_INTERVAL flows, embed a summary of the machine profile and
    insert it into machine_history for RAG retrieval by the agent.
    Keeps only the latest SNAPSHOT_KEEP entries per machine.
    """
    if profile['flow_count'] % SNAPSHOT_INTERVAL != 0:
        return

    summary = (
        f"Machine {machine_ip}: {profile['flow_count']} flows observed. "
        f"Avg bytes/flow={profile['bytes_mean']:.0f}, "
        f"avg bytes/s={profile['bytes_per_sec_mean']:.0f}, "
        f"avg duration={profile['duration_mean']:.0f}ms, "
        f"known ports={len(profile['known_ports'])}, "
        f"known protocols={profile['known_protocols']}."
    )

    embedding = _get_embedder().encode(summary).tolist()

    conn = get_db_session()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO machine_history (machine_ip, summary, embedding)
            VALUES (%s, %s, %s::vector)
        """, (machine_ip, summary, str(embedding)))

        # Prune old snapshots — keep only the latest SNAPSHOT_KEEP rows
        cur.execute("""
            DELETE FROM machine_history
            WHERE machine_ip = %s
              AND id NOT IN (
                  SELECT id FROM machine_history
                  WHERE machine_ip = %s
                  ORDER BY investigated_at DESC
                  LIMIT %s
              )
        """, (machine_ip, machine_ip, SNAPSHOT_KEEP))

    conn.commit()
    logger.info('Machine history snapshot saved', machine_ip=machine_ip, flows=profile['flow_count'])


def update_machine_profile(flow: dict) -> dict:
    """
    Update the machine profile for one flow. Returns the current profile.

    New machines are buffered until GRADUATION_THRESHOLD flows — they are
    treated as high-risk by the scorer until graduation.
    """
    machine_ip = flow['machine_ip']
    features   = flow.get('features', [])

    fwd_bytes  = features[2] if len(features) > 2 else 0.0
    bwd_bytes  = features[3] if len(features) > 3 else 0.0
    total_bytes = fwd_bytes + bwd_bytes
    byts_per_s  = features[4] if len(features) > 4 else 0.0
    tot_pkts    = (features[0] + features[1]) if len(features) > 1 else 0.0
    duration    = features[8] if len(features) > 8 else 0.0
    byte_ratio  = features[28] if len(features) > 28 else 0.5
    dst_port    = int(flow.get('dst_port', 0))
    protocol    = int(flow.get('protocol', 0))
    captured_at = flow.get('captured_at')

    profile = _get_or_load_profile(machine_ip)

    # Buffer pre-graduation flows without touching the DB
    if profile['flow_count'] < GRADUATION_THRESHOLD:
        buf = _new_machine_buffer.setdefault(machine_ip, [])
        buf.append(flow)

        if len(buf) >= GRADUATION_THRESHOLD:
            # Graduate: replay all buffered flows into the profile at once
            for buffered_flow in buf:
                _apply_flow_to_profile(profile, buffered_flow)
            del _new_machine_buffer[machine_ip]
            _upsert_profile(profile)
            logger.info('Machine graduated from buffer', machine_ip=machine_ip)
        return profile

    # Normal update path (post-graduation)
    _apply_flow_to_profile(profile, flow)

    if profile['flow_count'] % 10 == 0:
        _upsert_profile(profile)

    maybe_generate_snapshot(machine_ip, profile)

    return profile


def _apply_flow_to_profile(profile: dict, flow: dict) -> None:
    """Mutate profile in-place with one flow's data."""
    features    = flow.get('features', [])
    fwd_bytes   = features[2] if len(features) > 2 else 0.0
    bwd_bytes   = features[3] if len(features) > 3 else 0.0
    total_bytes = fwd_bytes + bwd_bytes
    byts_per_s  = features[4] if len(features) > 4 else 0.0
    tot_pkts    = (features[0] + features[1]) if len(features) > 1 else 0.0
    duration    = features[8] if len(features) > 8 else 0.0
    byte_ratio  = features[28] if len(features) > 28 else 0.5
    dst_port    = int(flow.get('dst_port', 0))
    protocol    = int(flow.get('protocol', 0))
    captured_at = flow.get('captured_at')

    n = profile['flow_count']

    profile['bytes_mean'],         profile['bytes_m2'],         n = welford_update(
        profile['bytes_mean'], profile['bytes_m2'], n, total_bytes)
    profile['bytes_per_sec_mean'], profile['bytes_per_sec_m2'], _ = welford_update(
        profile['bytes_per_sec_mean'], profile['bytes_per_sec_m2'], n, byts_per_s)
    profile['byte_ratio_mean'],    profile['byte_ratio_m2'],    _ = welford_update(
        profile['byte_ratio_mean'], profile['byte_ratio_m2'], n, byte_ratio)
    profile['pkts_mean'],          profile['pkts_m2'],          _ = welford_update(
        profile['pkts_mean'], profile['pkts_m2'], n, tot_pkts)
    profile['duration_mean'],      profile['duration_m2'],      _ = welford_update(
        profile['duration_mean'], profile['duration_m2'], n, duration)

    profile['flow_count'] = n

    if dst_port and dst_port not in profile['known_ports']:
        profile['known_ports'].append(dst_port)
    if protocol and protocol not in profile['known_protocols']:
        profile['known_protocols'].append(protocol)

    if profile['first_seen'] is None:
        profile['first_seen'] = captured_at
    profile['last_seen'] = captured_at
