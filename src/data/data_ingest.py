import hashlib
import random
import sys
import pandas as pd
import structlog
from datetime import datetime, timezone

from src.ml.ml_feature_contract import LABEL_MAP, CLEANING_RULES
from src.data.data_feature_extractor import extract_features
from src.data.data_consumer import initialize_streams, publish_flow

logger = structlog.get_logger(__name__)


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names — CICIDS2018 has inconsistent spacing."""
    df.columns = [c.strip() for c in df.columns]
    return df


_MAX_DURATION_SECONDS = 7 * 24 * 3600   # 7 days — any longer is a sensor/CSV artifact


def _drop_artifacts(df: pd.DataFrame) -> pd.DataFrame:
    """Remove structurally impossible rows that cannot represent real network traffic.

    Two patterns identified in CICIDS2018 Kaggle exports:
      1. Duration > 7 days — physically impossible for a single flow record.
      2. Protocol=0 AND Dst Port=0 AND total bytes=0 — zero-payload raw-IP
         placeholder rows (often cause the agent to escalate pointlessly).
    """
    before = len(df)
    mask   = pd.Series(True, index=df.index)

    dur_col = next((c for c in df.columns if 'duration' in c.lower()), None)
    if dur_col:
        mask &= df[dur_col] <= _MAX_DURATION_SECONDS

    proto_col = next((c for c in df.columns if c.lower() == 'protocol'), None)
    port_col  = next((c for c in df.columns if 'dst port' in c.lower() or c.lower() == 'destination port'), None)
    fwd_col   = next((c for c in df.columns if 'tot fwd pkts' in c.lower() or 'total fwd packets' in c.lower()), None)
    bwd_col   = next((c for c in df.columns if 'tot bwd pkts' in c.lower() or 'total backward packets' in c.lower()), None)

    if proto_col and port_col and fwd_col and bwd_col:
        zero_payload = (
            (df[proto_col].fillna(0).astype(float) == 0) &
            (df[port_col].fillna(0).astype(float)  == 0) &
            (df[fwd_col].fillna(0).astype(float)   == 0) &
            (df[bwd_col].fillna(0).astype(float)   == 0)
        )
        mask &= ~zero_payload

    df      = df[mask].copy()
    dropped = before - len(df)
    if dropped:
        logger.info('Dropped artifact rows', count=dropped, reasons='impossible_duration_or_zero_payload')
    return df


def _clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Apply cleaning rules from ml_feature_contract.CLEANING_RULES."""
    if CLEANING_RULES['drop_negative_duration'] and 'Flow Duration' in df.columns:
        before = len(df)
        df = df[df['Flow Duration'] >= 0].copy()
        dropped = before - len(df)
        if dropped:
            logger.info('Dropped negative-duration rows', count=dropped)

    if CLEANING_RULES['replace_inf_with_zero']:
        df = df.replace([float('inf'), float('-inf')], 0)

    if CLEANING_RULES['fill_nulls_with_zero']:
        df = df.fillna(0)

    return df


def _make_flow_id(machine_ip: str, captured_at: str, tot_fwd_pkts: float) -> str:
    """MD5 of key fields — used for ON CONFLICT DO NOTHING deduplication in the DB."""
    raw = f'{machine_ip}|{captured_at}|{tot_fwd_pkts}'
    return hashlib.md5(raw.encode()).hexdigest()


def _map_label(raw_label) -> int:
    """Map CICIDS2018 label string to 0/1/2. Returns -1 if missing or unknown."""
    if pd.isna(raw_label):
        return -1
    return LABEL_MAP.get(str(raw_label).strip(), -1)


def _parse_timestamp(raw) -> str:
    """Parse a CICIDS2018 timestamp to ISO-8601 string."""
    try:
        return pd.to_datetime(raw).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def normalize_flow(row: dict) -> dict:
    """
    Build the Redis message envelope from a cleaned CSV row.

    Envelope shape:
      flow_id, machine_ip, captured_at, label, dst_port, protocol, features (33 floats)
    """
    # CICIDS2018 from this Kaggle source strips IPs; generate realistic synthetic ones.
    # Benign traffic → internal RFC1918 subnets; attack traffic → routable external IPs.
    raw_ip = str(row.get('Src IP') or row.get('Source IP') or '').strip()
    if not raw_ip or raw_ip == '0.0.0.0':
        label_str = str(row.get('Label') or row.get('label') or '').strip().lower()
        if 'benign' in label_str:
            # Small pool (150 IPs) so each machine accumulates enough flows to
            # exceed the 10-flow graduation threshold with a 50k-row ingest.
            machine_ip = f'192.168.{random.randint(1,3)}.{random.randint(1,50)}'
        else:
            machine_ip = f'{random.choice([45,52,80,104,138,185])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}'
    else:
        machine_ip = raw_ip
    # Use ingestion time so dashboard 24h windows work correctly
    captured_at = datetime.now(timezone.utc).isoformat()

    features = extract_features(row)
    flow_id  = _make_flow_id(machine_ip, captured_at, features[0])

    dst_port = int(float(row.get('Dst Port') or row.get('Destination Port') or 0))
    protocol = int(float(row.get('Protocol') or 0))

    return {
        'flow_id':     flow_id,
        'machine_ip':  machine_ip,
        'captured_at': captured_at,
        'label':       _map_label(row.get('Label') or row.get('label')),
        'dst_port':    dst_port,
        'protocol':    protocol,
        'features':    features,
    }


def ingest_cicids_csv(csv_path: str, batch_size: int = 500, max_rows: int | None = None) -> int:
    """
    Read a CICIDS2018 CSV, clean it, and publish each row to the network-flows stream.
    Returns the number of flows successfully published.
    """
    logger.info('Starting CICIDS2018 ingest', path=csv_path, max_rows=max_rows)

    df = pd.read_csv(csv_path, low_memory=False, nrows=max_rows)
    df = _normalize_columns(df)
    df = _clean_dataframe(df)
    df = _drop_artifacts(df)

    published = 0
    errors    = 0

    for i, (_, row) in enumerate(df.iterrows()):
        try:
            flow = normalize_flow(row.to_dict())
            publish_flow(flow)
            published += 1
        except Exception as e:
            errors += 1
            logger.warning('Failed to ingest row', row_index=i, error=str(e))

        if published > 0 and published % batch_size == 0:
            logger.info('Ingest progress', published=published, errors=errors)

    logger.info('Ingest complete', published=published, errors=errors)
    return published


if __name__ == '__main__':
    import argparse
    from src.infra.infra_vault import load_secrets
    from src.infra.infra_logging import configure_logging

    configure_logging()
    load_secrets()
    initialize_streams()

    parser = argparse.ArgumentParser()
    parser.add_argument('csv_path')
    parser.add_argument('--rows', '--limit', dest='rows', type=int, default=None)
    args = parser.parse_args()
    ingest_cicids_csv(args.csv_path, max_rows=args.rows)
