# SPEC_BEHAVIORAL_PROFILES.md
# Behavioral Profiles Specification
# All decisions final. Implement exactly as specified.

---

## Overview

The behavioral profiling system maintains two PostgreSQL tables updated by the profiler consumer group. It answers the question: is this flow normal for this machine and this request type?

---

## File Structure

```
src/profiles/
  profiles_main.py           ← FastAPI entry point
  profiles_router.py         ← all routes
  profiles_schemas.py        ← all Pydantic models
  profiles_dependencies.py   ← FastAPI dependencies
  profiles_service.py        ← business logic
  profiles_machine.py        ← machine profile operations
  profiles_request_type.py   ← request type profile operations
```

---

## Welford's Online Algorithm

Single implementation. Used everywhere. Never duplicated.

```python
# src/profiles/profiles_service.py

import math

def welford_update(count: int, mean: float, M2: float, new_value: float):
    """
    Update running mean and std deviation without storing history.
    Returns: (new_count, new_mean, new_M2, new_std)
    """
    count  += 1
    delta   = new_value - mean
    mean   += delta / count
    delta2  = new_value - mean
    M2     += delta * delta2
    std     = math.sqrt(M2 / count) if count > 1 else 0.0
    return count, mean, M2, std

def safe_z_score(observed: float, mean: float, std: float) -> float:
    """Z-score with std=0 handling."""
    if std == 0:
        return 0.0 if observed == mean else 3.0
    return (observed - mean) / std

def normalize_z(z: float) -> float:
    """Map Z-score to 0-1 range. Z=3 → 0.63. Z=10 → 0.96."""
    return 1 - math.exp(-abs(z) / 3)
```

---

## profiles_machine.py

```python
# src/profiles/profiles_machine.py

import json
from datetime import datetime
from typing import Optional
import numpy as np
from src.profiles.profiles_service import welford_update
from src.infra.infra_db import get_db_session
from src.infra.infra_redis import get_redis_client

PROFILE_CACHE_TTL  = 3600   # 1 hour (safety net — active invalidation is primary)
BUFFER_TTL         = 3600   # 1 hour (resets on every new flow)
BUFFER_THRESHOLD   = 10     # flows before creating PostgreSQL row
PORT_CAP           = 100    # max entries in typical_dst_ports
IP_CAP             = 100    # max entries in typical_dst_ips
CONFIDENCE_TARGET  = 100    # observations to reach confidence=1.0

def is_rfc1918(ip: str) -> bool:
    """Returns True if IP is private (internal)."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False  # malformed → treat as external

def get_machine_profile(machine_ip: str, redis, db) -> dict:
    """
    Cache-aside pattern:
      1. Try Redis cache
      2. On miss: load from PostgreSQL
      3. On miss: return empty profile
    """
    cache_key = f'profile:{machine_ip}'
    cached = redis.get(cache_key)

    if cached:
        return json.loads(cached)

    # Redis miss → load from PostgreSQL
    row = db.execute(
        "SELECT * FROM machine_profiles WHERE machine_ip = %s",
        (machine_ip,)
    ).fetchone()

    if row:
        profile = dict(row)
        redis.set(cache_key, json.dumps(profile, default=str), ex=PROFILE_CACHE_TTL)
        return profile

    # New machine → return empty profile
    return _empty_profile(machine_ip)

def _empty_profile(machine_ip: str) -> dict:
    return {
        'machine_ip':           machine_ip,
        'observation_count':    0,
        'confidence':           0.0,
        'bytes_mean':           0.0, 'bytes_std': 0.0, 'bytes_m2': 0.0,
        'pkts_mean':            0.0, 'pkts_std':  0.0, 'pkts_m2':  0.0,
        'duration_mean':        0.0, 'duration_std': 0.0, 'duration_m2': 0.0,
        'entropy_mean':         0.0, 'entropy_std':  0.0, 'entropy_m2':  0.0,
        'typical_dst_ports':    [],
        'typical_protocols':    [],
        'typical_dst_ips':      [],
        'active_hours':         [0] * 24,
        'external_conn_count':  0,
        'internal_conn_count':  0,
        'smb_conn_count':       0,
        'dns_conn_count':       0,
        'http_conn_count':      0,
        'https_conn_count':     0,
        'rdp_conn_count':       0,
        'first_seen':           None,
        'last_seen':            None,
    }

def update_machine_profile(flow: dict, redis, db) -> dict:
    """
    Update machine profile with new flow.
    Writes to Redis on every flow.
    Writes to PostgreSQL every 10 flows.
    """
    machine_ip = flow['src_ip']
    profile    = get_machine_profile(machine_ip, redis, db)

    # Handle new machine buffer (flows 1-9)
    if profile['observation_count'] < BUFFER_THRESHOLD:
        return _update_buffer(flow, profile, redis, db)

    # Established profile — update normally
    profile = _apply_welford_updates(flow, profile)
    profile = _apply_array_updates(flow, profile)
    profile = _apply_counter_updates(flow, profile)
    profile['confidence']  = min(profile['observation_count'] / CONFIDENCE_TARGET, 1.0)
    profile['last_seen']   = datetime.utcnow().isoformat()

    # Always write to Redis cache
    cache_key = f'profile:{machine_ip}'
    redis.set(cache_key, json.dumps(profile, default=str), ex=PROFILE_CACHE_TTL)

    # Write to PostgreSQL every 10 flows
    if profile['observation_count'] % 10 == 0:
        _write_to_postgres(profile, db)

    return profile

def _update_buffer(flow: dict, profile: dict, redis, db) -> dict:
    """Handle flows 1-9 before PostgreSQL row exists."""
    buffer_key = f'buffer:{flow["src_ip"]}'

    # Load existing buffer or start fresh
    buffer_data = redis.get(buffer_key)
    if buffer_data:
        buffer = json.loads(buffer_data)
    else:
        buffer = _empty_profile(flow['src_ip'])
        buffer['first_seen'] = datetime.utcnow().isoformat()

    # Apply Welford update to buffer
    buffer = _apply_welford_updates(flow, buffer)
    buffer = _apply_array_updates(flow, buffer)
    buffer = _apply_counter_updates(flow, buffer)

    if buffer['observation_count'] >= BUFFER_THRESHOLD:
        # Graduated — write to PostgreSQL and delete buffer
        buffer['confidence'] = min(buffer['observation_count'] / CONFIDENCE_TARGET, 1.0)
        _write_to_postgres(buffer, db)
        redis.delete(buffer_key)

        # Also write to Redis profile cache
        cache_key = f'profile:{flow["src_ip"]}'
        redis.set(cache_key, json.dumps(buffer, default=str), ex=PROFILE_CACHE_TTL)
    else:
        # Still buffering — update buffer with TTL reset
        redis.set(buffer_key, json.dumps(buffer, default=str), ex=BUFFER_TTL)

    return buffer

def _apply_welford_updates(flow: dict, profile: dict) -> dict:
    """Apply Welford updates to all tracked continuous features."""
    total_bytes = flow.get('totlen_fwd_pkts', 0) + flow.get('totlen_bwd_pkts', 0)
    total_pkts  = flow.get('tot_fwd_pkts', 0) + flow.get('tot_bwd_pkts', 0)
    duration    = flow.get('flow_duration', 0)
    entropy     = flow.get('payload_entropy')  # may be None if not computed

    n, m, m2, s = welford_update(
        profile['observation_count'], profile['bytes_mean'],
        profile['bytes_m2'], total_bytes
    )
    profile.update({'observation_count': n, 'bytes_mean': m, 'bytes_m2': m2, 'bytes_std': s})

    _, m, m2, s = welford_update(n, profile['pkts_mean'], profile['pkts_m2'], total_pkts)
    profile.update({'pkts_mean': m, 'pkts_m2': m2, 'pkts_std': s})

    _, m, m2, s = welford_update(n, profile['duration_mean'], profile['duration_m2'], duration)
    profile.update({'duration_mean': m, 'duration_m2': m2, 'duration_std': s})

    if entropy is not None:
        _, m, m2, s = welford_update(n, profile['entropy_mean'], profile['entropy_m2'], entropy)
        profile.update({'entropy_mean': m, 'entropy_m2': m2, 'entropy_std': s})

    return profile

def _apply_array_updates(flow: dict, profile: dict) -> dict:
    """Update array fields (ports, protocols, IPs, active hours)."""
    dst_port = flow.get('dst_port')
    protocol = flow.get('protocol')
    dst_ip   = flow.get('dst_ip')
    hour     = datetime.utcnow().hour

    if dst_port and dst_port not in profile['typical_dst_ports']:
        if len(profile['typical_dst_ports']) < PORT_CAP:
            profile['typical_dst_ports'].append(dst_port)

    if protocol and protocol not in profile['typical_protocols']:
        profile['typical_protocols'].append(protocol)

    if dst_ip and dst_ip not in profile['typical_dst_ips']:
        if len(profile['typical_dst_ips']) < IP_CAP:
            profile['typical_dst_ips'].append(dst_ip)

    profile['active_hours'][hour] += 1

    return profile

def _apply_counter_updates(flow: dict, profile: dict) -> dict:
    """Update connection counters."""
    dst_ip   = flow.get('dst_ip', '')
    dst_port = flow.get('dst_port', 0)

    if is_rfc1918(dst_ip):
        profile['internal_conn_count'] += 1
    else:
        profile['external_conn_count'] += 1

    if dst_port == 445:  profile['smb_conn_count']   += 1
    if dst_port == 53:   profile['dns_conn_count']   += 1
    if dst_port in (80, 8080): profile['http_conn_count']  += 1
    if dst_port == 443:  profile['https_conn_count'] += 1
    if dst_port == 3389: profile['rdp_conn_count']   += 1

    return profile

def _write_to_postgres(profile: dict, db):
    """Upsert profile to PostgreSQL."""
    db.execute("""
        INSERT INTO machine_profiles (
            machine_ip, observation_count, confidence,
            bytes_mean, bytes_std, bytes_m2,
            pkts_mean, pkts_std, pkts_m2,
            duration_mean, duration_std, duration_m2,
            entropy_mean, entropy_std, entropy_m2,
            typical_dst_ports, typical_protocols, typical_dst_ips,
            active_hours,
            external_conn_count, internal_conn_count,
            smb_conn_count, dns_conn_count, http_conn_count,
            https_conn_count, rdp_conn_count,
            first_seen, last_seen, updated_at
        ) VALUES (
            %(machine_ip)s, %(observation_count)s, %(confidence)s,
            %(bytes_mean)s, %(bytes_std)s, %(bytes_m2)s,
            %(pkts_mean)s, %(pkts_std)s, %(pkts_m2)s,
            %(duration_mean)s, %(duration_std)s, %(duration_m2)s,
            %(entropy_mean)s, %(entropy_std)s, %(entropy_m2)s,
            %(typical_dst_ports)s, %(typical_protocols)s, %(typical_dst_ips)s,
            %(active_hours)s,
            %(external_conn_count)s, %(internal_conn_count)s,
            %(smb_conn_count)s, %(dns_conn_count)s, %(http_conn_count)s,
            %(https_conn_count)s, %(rdp_conn_count)s,
            %(first_seen)s, %(last_seen)s, NOW()
        )
        ON CONFLICT (machine_ip) DO UPDATE SET
            observation_count = EXCLUDED.observation_count,
            confidence        = EXCLUDED.confidence,
            bytes_mean        = EXCLUDED.bytes_mean,
            bytes_std         = EXCLUDED.bytes_std,
            bytes_m2          = EXCLUDED.bytes_m2,
            pkts_mean         = EXCLUDED.pkts_mean,
            pkts_std          = EXCLUDED.pkts_std,
            pkts_m2           = EXCLUDED.pkts_m2,
            duration_mean     = EXCLUDED.duration_mean,
            duration_std      = EXCLUDED.duration_std,
            duration_m2       = EXCLUDED.duration_m2,
            entropy_mean      = EXCLUDED.entropy_mean,
            entropy_std       = EXCLUDED.entropy_std,
            entropy_m2        = EXCLUDED.entropy_m2,
            typical_dst_ports = EXCLUDED.typical_dst_ports,
            typical_protocols = EXCLUDED.typical_protocols,
            typical_dst_ips   = EXCLUDED.typical_dst_ips,
            active_hours      = EXCLUDED.active_hours,
            external_conn_count = EXCLUDED.external_conn_count,
            internal_conn_count = EXCLUDED.internal_conn_count,
            smb_conn_count    = EXCLUDED.smb_conn_count,
            dns_conn_count    = EXCLUDED.dns_conn_count,
            http_conn_count   = EXCLUDED.http_conn_count,
            https_conn_count  = EXCLUDED.https_conn_count,
            rdp_conn_count    = EXCLUDED.rdp_conn_count,
            last_seen         = EXCLUDED.last_seen,
            updated_at        = NOW()
    """, profile)
    db.commit()
```

---

## profiles_request_type.py

```python
# src/profiles/profiles_request_type.py

import json
from src.profiles.profiles_service import welford_update
from src.infra.infra_redis import get_redis_client

REQUEST_TYPE_CACHE_TTL = 3600

def get_request_type_profile(protocol: int, dst_port: int, redis, db) -> dict:
    """Cache-aside pattern for request type profiles."""
    cache_key = f'reqtype:{protocol}:{dst_port}'
    cached = redis.get(cache_key)

    if cached:
        return json.loads(cached)

    row = db.execute(
        "SELECT * FROM request_type_profiles WHERE protocol = %s AND dst_port = %s",
        (protocol, dst_port)
    ).fetchone()

    if row:
        profile = dict(row)
        redis.set(cache_key, json.dumps(profile, default=str), ex=REQUEST_TYPE_CACHE_TTL)
        return profile

    # Unknown protocol/port — return None (triggers unknown handling)
    return None

def update_request_type_profile(flow: dict, redis, db):
    """Update request type profile with new flow."""
    protocol = flow.get('protocol')
    dst_port = flow.get('dst_port')

    if protocol is None or dst_port is None:
        return

    profile = get_request_type_profile(protocol, dst_port, redis, db)

    if profile is None:
        # First time seeing this protocol/port — create entry
        profile = _empty_request_type_profile(protocol, dst_port)

    total_bytes    = flow.get('totlen_fwd_pkts', 0) + flow.get('totlen_bwd_pkts', 0)
    total_pkts     = flow.get('tot_fwd_pkts', 0) + flow.get('tot_bwd_pkts', 0)
    duration       = flow.get('flow_duration', 0)
    fwd_bytes      = flow.get('totlen_fwd_pkts', 0)
    bwd_bytes      = flow.get('totlen_bwd_pkts', 0)
    byte_ratio     = bwd_bytes / fwd_bytes if fwd_bytes > 0 else 0
    bytes_per_sec  = flow.get('flow_byts_s', 0)
    entropy        = flow.get('payload_entropy')

    n = profile['observation_count']

    n, m, m2, s = welford_update(n, profile['bytes_mean'], profile['bytes_m2'], total_bytes)
    profile.update({'observation_count': n, 'bytes_mean': m, 'bytes_m2': m2, 'bytes_std': s})

    _, m, m2, s = welford_update(n, profile['pkts_mean'], profile['pkts_m2'], total_pkts)
    profile.update({'pkts_mean': m, 'pkts_m2': m2, 'pkts_std': s})

    _, m, m2, s = welford_update(n, profile['duration_mean'], profile['duration_m2'], duration)
    profile.update({'duration_mean': m, 'duration_m2': m2, 'duration_std': s})

    _, m, m2, s = welford_update(n, profile['byte_ratio_mean'], profile['byte_ratio_m2'], byte_ratio)
    profile.update({'byte_ratio_mean': m, 'byte_ratio_m2': m2, 'byte_ratio_std': s})

    _, m, m2, s = welford_update(n, profile['bytes_per_sec_mean'], profile['bytes_per_sec_m2'], bytes_per_sec)
    profile.update({'bytes_per_sec_mean': m, 'bytes_per_sec_m2': m2, 'bytes_per_sec_std': s})

    if entropy is not None:
        _, m, m2, s = welford_update(n, profile['entropy_mean'], profile['entropy_m2'], entropy)
        profile.update({'entropy_mean': m, 'entropy_m2': m2, 'entropy_std': s})

    # Update Redis cache
    cache_key = f'reqtype:{protocol}:{dst_port}'
    redis.set(cache_key, json.dumps(profile, default=str), ex=REQUEST_TYPE_CACHE_TTL)

    # Write to PostgreSQL every 10 flows
    if profile['observation_count'] % 10 == 0:
        _upsert_request_type_profile(profile, db)

def _empty_request_type_profile(protocol: int, dst_port: int) -> dict:
    return {
        'protocol': protocol, 'dst_port': dst_port,
        'observation_count':    0,
        'bytes_mean':           0.0, 'bytes_std': 0.0, 'bytes_m2': 0.0,
        'pkts_mean':            0.0, 'pkts_std':  0.0, 'pkts_m2':  0.0,
        'duration_mean':        0.0, 'duration_std': 0.0, 'duration_m2': 0.0,
        'entropy_mean':         0.0, 'entropy_std':  0.0, 'entropy_m2':  0.0,
        'byte_ratio_mean':      0.0, 'byte_ratio_std': 0.0, 'byte_ratio_m2': 0.0,
        'bytes_per_sec_mean':   0.0, 'bytes_per_sec_std': 0.0, 'bytes_per_sec_m2': 0.0,
    }

def _upsert_request_type_profile(profile: dict, db):
    db.execute("""
        INSERT INTO request_type_profiles (
            protocol, dst_port, observation_count,
            bytes_mean, bytes_std, bytes_m2,
            pkts_mean, pkts_std, pkts_m2,
            duration_mean, duration_std, duration_m2,
            entropy_mean, entropy_std, entropy_m2,
            byte_ratio_mean, byte_ratio_std, byte_ratio_m2,
            bytes_per_sec_mean, bytes_per_sec_std, bytes_per_sec_m2,
            updated_at
        ) VALUES (
            %(protocol)s, %(dst_port)s, %(observation_count)s,
            %(bytes_mean)s, %(bytes_std)s, %(bytes_m2)s,
            %(pkts_mean)s, %(pkts_std)s, %(pkts_m2)s,
            %(duration_mean)s, %(duration_std)s, %(duration_m2)s,
            %(entropy_mean)s, %(entropy_std)s, %(entropy_m2)s,
            %(byte_ratio_mean)s, %(byte_ratio_std)s, %(byte_ratio_m2)s,
            %(bytes_per_sec_mean)s, %(bytes_per_sec_std)s, %(bytes_per_sec_m2)s,
            NOW()
        )
        ON CONFLICT (protocol, dst_port) DO UPDATE SET
            observation_count   = EXCLUDED.observation_count,
            bytes_mean          = EXCLUDED.bytes_mean,
            bytes_std           = EXCLUDED.bytes_std,
            bytes_m2            = EXCLUDED.bytes_m2,
            byte_ratio_mean     = EXCLUDED.byte_ratio_mean,
            byte_ratio_std      = EXCLUDED.byte_ratio_std,
            byte_ratio_m2       = EXCLUDED.byte_ratio_m2,
            bytes_per_sec_mean  = EXCLUDED.bytes_per_sec_mean,
            bytes_per_sec_std   = EXCLUDED.bytes_per_sec_std,
            bytes_per_sec_m2    = EXCLUDED.bytes_per_sec_m2,
            updated_at          = NOW()
    """, profile)
    db.commit()
```

---

## pgvector Snapshot (every 100 flows)

```python
# In profiles_machine.py — called from update_machine_profile

from sentence_transformers import SentenceTransformer

_embedding_model = SentenceTransformer('all-MiniLM-L6-v2')

def maybe_generate_snapshot(profile: dict, db):
    """Generate pgvector snapshot every 100 flows."""
    if profile['observation_count'] % 100 != 0:
        return

    # Generate narrative summary
    active = [i for i, v in enumerate(profile['active_hours']) if v > 0]
    active_str = f"{min(active)}:00-{max(active)+1}:00" if active else "unknown"

    summary = (
        f"Machine {profile['machine_ip']}: "
        f"active hours {active_str}, "
        f"typical ports {profile['typical_dst_ports'][:10]}, "
        f"avg bytes/flow {profile['bytes_mean']:.0f} "
        f"(std {profile['bytes_std']:.0f}), "
        f"external connections {profile['external_conn_count']}, "
        f"SMB connections {profile['smb_conn_count']}, "
        f"observation count {profile['observation_count']}, "
        f"confidence {profile['confidence']:.2f}."
    )

    # Embed
    vector = _embedding_model.encode(summary).tolist()

    # Insert into machine_history
    db.execute("""
        INSERT INTO machine_history (machine_ip, summary_text, embedding)
        VALUES (%s, %s, %s)
    """, (profile['machine_ip'], summary, vector))

    # Keep only latest 10 per machine
    db.execute("""
        DELETE FROM machine_history
        WHERE machine_ip = %s
        AND id NOT IN (
            SELECT id FROM machine_history
            WHERE machine_ip = %s
            ORDER BY created_at DESC
            LIMIT 10
        )
    """, (profile['machine_ip'], profile['machine_ip']))

    db.commit()
```
