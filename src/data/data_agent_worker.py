import json
import os

import structlog

from src.agent.agent_service import process_flow
from src.data.data_consumer import (
    STREAM_HIGH_RISK,
    ack_message,
    consume_stream,
)
from src.infra.infra_db import get_db_session
from src.infra.infra_logging import configure_logging
from src.infra.infra_redis import get_redis_client
from src.infra.infra_vault import load_secrets

logger = structlog.get_logger(__name__)

_GROUP    = 'agent-group'
_CONSUMER = os.environ.get('HOSTNAME', 'agent-1')

_SCORING_KEYS = {'ml_label', 'ml_confidence', 'classifier_score', 'risk_score', 'risk_level'}


def _split_message(raw: dict) -> tuple[dict, dict]:
    scoring_result = {k: raw.get(k) for k in _SCORING_KEYS}
    flow = {k: v for k, v in raw.items() if k not in _SCORING_KEYS}
    return flow, scoring_result


def _insert_alert(flow: dict, finding: dict, db) -> str:
    """Write the agent's finding to security_alerts. Returns the new alert UUID."""
    machine_ip    = flow.get('machine_ip', '0.0.0.0')
    firewall_rule = finding.get('firewall_rule')
    recommended_action = (
        f"Apply firewall rule: {firewall_rule}"
        if firewall_rule
        else 'Monitor and escalate if behaviour continues.'
    )

    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO security_alerts (
                machine_ip, flow_id, risk_level,
                summary, recommended_action, iocs, osint_results,
                classifier_score, deviation_score, machine_confidence,
                tools_called, firewall_rule, limit_hit, escalated_to_human
            ) VALUES (
                %s, %s, %s,
                %s, %s, %s::jsonb, %s::jsonb,
                %s, %s, %s,
                %s::jsonb, %s, %s, %s
            )
            RETURNING id
        """, (
            machine_ip,
            flow.get('flow_id'),
            finding.get('risk_level', 'HIGH'),
            finding.get('explanation', ''),
            recommended_action,
            json.dumps([machine_ip]),
            json.dumps(finding.get('osint_results', {})),
            finding.get('classifier_score'),
            finding.get('deviation_score'),
            finding.get('machine_confidence'),
            json.dumps(finding.get('tools_called', [])),
            firewall_rule,
            bool(finding.get('limit_hit', False)),
            bool(finding.get('escalated_to_human', False)),
        ))
        alert_id = str(cur.fetchone()['id'])
    db.commit()
    return alert_id


def _insert_trace_steps(alert_id: str, flow_id: str | None, steps: list[dict], db) -> None:
    """Write per-step agent trace to flow_traces."""
    if not steps:
        return
    with db.cursor() as cur:
        for order, step in enumerate(steps):
            cur.execute("""
                INSERT INTO flow_traces (
                    alert_id, flow_id, step_order, step_type,
                    tool_name, tool_args, result_summary,
                    duration_ms, guardrail_status, metadata
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s::jsonb, %s,
                    %s, %s, %s::jsonb
                )
            """, (
                alert_id,
                flow_id,
                order,
                step.get('step_type'),
                step.get('tool_name'),
                json.dumps(step.get('tool_args') or {}),
                step.get('result_summary'),
                step.get('duration_ms'),
                step.get('guardrail_status'),
                json.dumps(step.get('metadata') or {}),
            ))
    db.commit()


def agent_handler(raw: dict) -> None:
    """Call process_flow directly (no HTTP hop) then persist finding and trace."""
    db         = get_db_session()
    redis      = get_redis_client()
    flow, scoring = _split_message(raw)
    machine_ip = flow.get('machine_ip', 'unknown')

    try:
        finding = process_flow(scoring, flow, redis, db)
        logger.info('Agent investigation complete', machine_ip=machine_ip, risk=finding.get('risk_level'))
    except Exception as e:
        logger.warning(
            'process_flow failed — writing minimal alert',
            machine_ip=machine_ip,
            error=str(e),
        )
        finding = {
            'risk_level':         scoring.get('risk_level', 'HIGH'),
            'explanation':        f'Agent error. Flow flagged for manual review. Error: {e}',
            'firewall_rule':      None,
            'osint_results':      {},
            'tools_called':       [],
            'escalated_to_human': True,
            'limit_hit':          False,
            'trace_steps':        [],
        }

    try:
        alert_id = _insert_alert(flow, finding, db)
        _insert_trace_steps(
            alert_id,
            flow.get('flow_id'),
            finding.get('trace_steps', []),
            db,
        )
    except Exception:
        logger.exception('Failed to insert security alert', machine_ip=machine_ip)


def run_agent_worker(consumer_name: str = _CONSUMER) -> None:
    """Consume from high-risk-flows (agent-group) and run agent investigation inline."""
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
