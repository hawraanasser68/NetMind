import json
import time
import structlog

from src.infra.infra_db import get_db_session
from src.infra.infra_logging import configure_logging
from src.infra.infra_vault import load_secrets
from src.data.data_consumer import (
    STREAM_NETWORK_FLOWS,
    ack_message,
    consume_stream,
    initialize_streams,
)
from src.ml.ml_feature_contract import FEATURE_COLUMNS

logger = structlog.get_logger(__name__)

# Snake_case DB column names in the same order as FEATURE_COLUMNS
_DB_FEATURE_COLS = [
    'tot_fwd_pkts',    'tot_bwd_pkts',    'totlen_fwd_pkts',  'totlen_bwd_pkts',
    'flow_byts_per_s', 'flow_pkts_per_s', 'fwd_pkts_per_s',   'bwd_pkts_per_s',
    'flow_duration',   'flow_iat_mean',   'flow_iat_std',
    'fwd_iat_mean',    'fwd_iat_std',     'bwd_iat_mean',      'bwd_iat_std',
    'active_mean',     'active_std',      'idle_mean',         'idle_std',
    'syn_flag_cnt',    'fin_flag_cnt',    'rst_flag_cnt',      'psh_flag_cnt',
    'ack_flag_cnt',    'urg_flag_cnt',
    'pkt_len_mean',    'pkt_len_std',     'down_up_ratio',
    'byte_ratio',      'proto_tcp',       'proto_udp',         'proto_icmp',
    'is_privileged_port',
]

assert len(_DB_FEATURE_COLS) == len(FEATURE_COLUMNS), (
    f'DB column mapping is out of sync with FEATURE_COLUMNS '
    f'({len(_DB_FEATURE_COLS)} vs {len(FEATURE_COLUMNS)})'
)

_FEATURE_COLS_SQL  = ', '.join(_DB_FEATURE_COLS)
_FEATURE_PLACEHOLDERS = ', '.join(['%s'] * len(_DB_FEATURE_COLS))

_INSERT_SQL = f"""
    INSERT INTO network_flows (
        flow_id, machine_ip, captured_at, label, confidence,
        {_FEATURE_COLS_SQL}
    )
    VALUES (
        %s, %s, %s, %s, %s,
        {_FEATURE_PLACEHOLDERS}
    )
    ON CONFLICT (flow_id) DO NOTHING
"""


def logger_handler(flow: dict) -> None:
    """
    INSERT one flow into network_flows.
    ON CONFLICT (flow_id) DO NOTHING makes replays safe — if the same flow
    arrives twice during stream recovery, the second insert is silently dropped.
    """
    label      = flow['label']
    # Ground-truth label from CICIDS2018 CSV → confidence = 1.0 (certain).
    # Unlabeled production flows (label == -1) get confidence = 0.0 until the
    # classifier worker scores them.
    confidence = 1.0 if label >= 0 else 0.0
    stored_label = max(label, 0)  # store 0 for unlabeled (-1) rows

    conn = get_db_session()
    with conn.cursor() as cur:
        cur.execute(_INSERT_SQL, [
            flow['flow_id'],
            flow['machine_ip'],
            flow['captured_at'],
            stored_label,
            confidence,
            *flow['features'],
        ])
    conn.commit()


def run_logger_worker(consumer_name: str = 'logger-1') -> None:
    """Consume from network-flows (logger-group) and persist each flow to PostgreSQL."""
    logger.info('Logger worker starting', consumer=consumer_name)

    while True:
        try:
            messages = consume_stream(
                stream=STREAM_NETWORK_FLOWS,
                group='logger-group',
                consumer=consumer_name,
            )

            for msg_id, msg_data in messages:
                try:
                    flow = json.loads(msg_data['data'])
                    logger_handler(flow)
                    ack_message(STREAM_NETWORK_FLOWS, 'logger-group', msg_id)
                    logger.info(
                        'Flow persisted',
                        flow_id=flow.get('flow_id'),
                        machine_ip=flow.get('machine_ip'),
                    )
                except Exception as e:
                    logger.error('Failed to persist flow', msg_id=msg_id, error=str(e))
                    # Do not ack — message stays pending and will be retried on next cycle

        except Exception as e:
            logger.error('Logger worker loop error', error=str(e))
            time.sleep(5)


if __name__ == '__main__':
    configure_logging()
    load_secrets()
    initialize_streams()
    run_logger_worker()
