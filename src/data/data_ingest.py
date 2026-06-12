import hashlib
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
    # CICIDS2018 uses 'Src IP' in most versions; fall back for variations
    machine_ip  = str(row.get('Src IP') or row.get('Source IP') or '0.0.0.0').strip()
    captured_at = _parse_timestamp(row.get('Timestamp') or row.get('timestamp') or '')

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


def ingest_cicids_csv(csv_path: str, batch_size: int = 500) -> int:
    """
    Read a CICIDS2018 CSV, clean it, and publish each row to the network-flows stream.
    Returns the number of flows successfully published.
    """
    logger.info('Starting CICIDS2018 ingest', path=csv_path)

    df = pd.read_csv(csv_path, low_memory=False)
    df = _normalize_columns(df)
    df = _clean_dataframe(df)

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
    from src.infra.infra_vault import load_secrets
    from src.infra.infra_logging import configure_logging

    configure_logging()
    load_secrets()
    initialize_streams()

    path = sys.argv[1] if len(sys.argv) > 1 else 'data/cicids2018.csv'
    ingest_cicids_csv(path)
