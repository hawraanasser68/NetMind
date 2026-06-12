import json

import requests
import structlog

from src.data.data_consumer import (
    STREAM_HIGH_RISK,
    ack_message,
    consume_stream,
)
from src.infra.infra_db import get_db_session
from src.infra.infra_logging import configure_logging
from src.infra.infra_vault import load_secrets

logger = structlog.get_logger(__name__)

_AGENT_URL     = 'http://agent:8003/agent/analyze'
_AGENT_TIMEOUT = 35   # seconds — agent has a 30s internal budget + buffer
_GROUP         = 'agent-group'
_CONSUMER      = 'agent-1'

# Fields that belong to the scoring layer (published by classifier worker)
_SCORING_KEYS = {'ml_label', 'ml_confidence', 'classifier_score', 'risk_score', 'risk_level'}


def _split_message(raw: dict) -> tuple[dict, dict]:
    """
    The classifier worker combines flow fields and scoring fields into one message.
    Split them back out for the agent service's AgentRequest schema.
    """
    scoring_result = {k: raw.get(k) for k in _SCORING_KEYS}
    flow = {k: v for k, v in raw.items() if k not in _SCORING_KEYS}
    return flow, scoring_result


def _insert_alert(flow: dict, finding: dict, db) -> None:
    """Write the agent's finding to security_alerts."""
    machine_ip         = flow.get('machine_ip', '0.0.0.0')
    risk_level         = finding.get('risk_level', 'HIGH')
    explanation        = finding.get('explanation', '')
    recommended_action = (
        f"firewall_rule: {finding['firewall_rule']}"
        if finding.get('firewall_rule')
        else 'Monitor and escalate if behaviour continues.'
    )

    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO security_alerts
                (machine_ip, risk_level, summary, recommended_action, iocs, osint_results)
            VALUES
                (%s, %s, %s, %s, %s::jsonb, %s::jsonb)
        """, (
            machine_ip,
            risk_level,
            explanation,
            recommended_action,
            json.dumps([machine_ip]),                          # iocs: at minimum the source IP
            json.dumps(finding.get('osint_results', {})),
        ))
    db.commit()


def agent_handler(raw: dict) -> None:
    """
    POST flow to the agent service, then persist the finding to security_alerts.
    Falls back to a minimal alert if the agent call fails.
    """
    db         = get_db_session()
    flow, scoring = _split_message(raw)
    machine_ip = flow.get('machine_ip', 'unknown')

    try:
        resp = requests.post(
            _AGENT_URL,
            json={'flow': flow, 'scoring_result': scoring},
            timeout=_AGENT_TIMEOUT,
        )
        resp.raise_for_status()
        finding = resp.json()
    except Exception as e:
        logger.warning(
            'Agent call failed — writing minimal alert',
            machine_ip=machine_ip,
            error=str(e),
        )
        finding = {
            'risk_level':         scoring.get('risk_level', 'HIGH'),
            'explanation':        f'Agent unavailable. Flow flagged for manual review. Error: {e}',
            'firewall_rule':      None,
            'osint_results':      {},
            'escalated_to_human': True,
        }

    try:
        _insert_alert(flow, finding, db)
    except Exception:
        logger.exception('Failed to insert security alert', machine_ip=machine_ip)


def run_agent_worker(consumer_name: str = _CONSUMER) -> None:
    """Consume from high-risk-flows (agent-group) and trigger agent investigation."""
    configure_logging()
    load_secrets()
    logger.info('Agent worker started', consumer=consumer_name)

    while True:
        try:
            messages = consume_stream(
                stream=STREAM_HIGH_RISK,
                group=_GROUP,
                consumer=consumer_name,
            )

            for msg_id, msg_data in messages:
                raw = msg_data.get(b'data') or msg_data.get('data', '{}')
                if isinstance(raw, bytes):
                    raw = raw.decode()
                flow_msg = json.loads(raw)
                try:
                    agent_handler(flow_msg)
                    ack_message(STREAM_HIGH_RISK, _GROUP, msg_id)
                except Exception:
                    logger.exception('Agent handler failed — leaving unacked', msg_id=msg_id)

        except Exception:
            logger.exception('Agent worker outer loop error')


if __name__ == '__main__':
    run_agent_worker()
