import json
import time
import structlog

from src.data.data_consumer import (
    STREAM_NETWORK_FLOWS,
    consume_stream,
    ack_message,
)
from src.profiles.profiles_machine import update_machine_profile, maybe_generate_snapshot
from src.profiles.profiles_request_type import update_request_type_profile
from src.infra.infra_logging import configure_logging

logger = structlog.get_logger(__name__)

_GROUP    = 'profilers'
_CONSUMER = 'profiler-1'


def profiler_handler(flow: dict) -> None:
    """Update behavioral profiles for every flow regardless of risk level."""
    updated_machine = update_machine_profile(flow)
    update_request_type_profile(flow)
    maybe_generate_snapshot(flow['machine_ip'], updated_machine)


def run_profiler_worker(consumer_name: str = _CONSUMER) -> None:
    """Consume from network-flows (profilers group) and update behavioral profiles."""
    configure_logging()
    logger.info('Profiler worker started', consumer=consumer_name)

    while True:
        try:
            messages = consume_stream(
                stream=STREAM_NETWORK_FLOWS,
                group=_GROUP,
                consumer=consumer_name,
            )

            for msg_id, msg_data in messages:
                raw = msg_data.get(b'data') or msg_data.get('data', '{}')
                if isinstance(raw, bytes):
                    raw = raw.decode()
                flow = json.loads(raw)
                try:
                    profiler_handler(flow)
                    ack_message(STREAM_NETWORK_FLOWS, _GROUP, msg_id)
                except Exception:
                    logger.exception('Profile update failed — leaving unacked for retry', msg_id=msg_id)

        except Exception:
            logger.exception('Profiler worker outer loop error')
            time.sleep(2)


if __name__ == '__main__':
    run_profiler_worker()
