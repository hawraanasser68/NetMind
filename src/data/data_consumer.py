import json
import structlog
from src.infra.infra_redis import get_redis_client

logger = structlog.get_logger(__name__)

STREAM_NETWORK_FLOWS  = 'network-flows'
STREAM_HIGH_RISK      = 'high-risk-flows'

MAXLEN_NETWORK_FLOWS  = 100_000
MAXLEN_HIGH_RISK      = 10_000

_GROUPS = {
    STREAM_NETWORK_FLOWS: ['logger-group', 'classifier-group', 'profilers'],
    STREAM_HIGH_RISK:     ['agent-group'],
}


def initialize_streams() -> None:
    """Create streams and consumer groups if they do not already exist."""
    redis = get_redis_client()
    for stream, groups in _GROUPS.items():
        for group in groups:
            try:
                redis.xgroup_create(stream, group, id='$', mkstream=True)
                logger.info('Consumer group created', stream=stream, group=group)
            except Exception as e:
                if 'BUSYGROUP' in str(e):
                    pass  # already exists — normal on every restart after the first
                else:
                    raise


def consume_stream(
    stream: str,
    group: str,
    consumer: str,
    count: int = 10,
    block_ms: int = 2000,
) -> list[tuple[str, dict]]:
    """
    Read messages from a Redis stream using a consumer group.

    Pending-then-new pattern:
    1. Drain any unacknowledged messages left over from a previous crash (id='0').
    2. Block for new, undelivered messages (id='>').
    """
    redis = get_redis_client()

    # Step 1: recover any pending (unacknowledged) messages from a crash
    pending = redis.xreadgroup(
        groupname=group,
        consumername=consumer,
        streams={stream: '0'},
        count=count,
    )
    if pending:
        _, messages = pending[0]
        if messages:
            return [(msg_id, msg_data) for msg_id, msg_data in messages]

    # Step 2: block for new messages
    new = redis.xreadgroup(
        groupname=group,
        consumername=consumer,
        streams={stream: '>'},
        count=count,
        block=block_ms,
    )
    if not new:
        return []

    _, messages = new[0]
    return [(msg_id, msg_data) for msg_id, msg_data in messages]


def ack_message(stream: str, group: str, message_id: str) -> None:
    """Acknowledge a message after successful processing."""
    get_redis_client().xack(stream, group, message_id)


def publish_flow(flow_data: dict) -> None:
    """Publish a raw flow to the network-flows stream (called by the ingest worker)."""
    get_redis_client().xadd(
        STREAM_NETWORK_FLOWS,
        {'data': json.dumps(flow_data)},
        maxlen=MAXLEN_NETWORK_FLOWS,
        approximate=True,
    )


def publish_high_risk(flow_data: dict) -> None:
    """Publish a scored high-risk flow to the high-risk-flows stream (called by classifier worker)."""
    get_redis_client().xadd(
        STREAM_HIGH_RISK,
        {'data': json.dumps(flow_data)},
        maxlen=MAXLEN_HIGH_RISK,
        approximate=True,
    )
