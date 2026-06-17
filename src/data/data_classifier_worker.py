import json
import time
import requests
import structlog

from src.infra.infra_logging import configure_logging
from src.infra.infra_vault import load_secrets
from src.profiles.profiles_machine import get_machine_profile
from src.profiles.profiles_request_type import get_request_type_profile
from src.data.data_consumer import (
    STREAM_NETWORK_FLOWS,
    ack_message,
    consume_stream,
    initialize_streams,
    publish_high_risk,
)

logger = structlog.get_logger(__name__)

_CLASSIFIER_URL     = 'http://classifier:8001/classifier/score'
_CLASSIFIER_TIMEOUT = 5   # seconds — fail fast; don't stall the pipeline

# Neutral fallback values used when the classifier service is unavailable.
# Label=suspicious, low confidence → most flows won't escalate, keeping the
# agent queue clear until the classifier recovers.
_NEUTRAL = {
    'label':            1,
    'confidence':       0.33,
    'classifier_score': 0.33,
    'probabilities':    {'benign': 0.34, 'suspicious': 0.33, 'attack': 0.33},
}


def _call_classifier(features: list[float]) -> dict:
    """POST features to the classifier service; return neutral result on any failure."""
    try:
        resp = requests.post(
            _CLASSIFIER_URL,
            json={'features': features},
            timeout=_CLASSIFIER_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning('Classifier unavailable, using neutral fallback', error=str(e))
        return _NEUTRAL


def _simple_risk(classifier_score: float) -> tuple[str, bool]:
    """
    Threshold routing used before score_flow() (Phase 5) is available.
    Returns (risk_level, should_escalate).
    """
    if classifier_score >= 0.80:
        return 'CRITICAL', True
    if classifier_score >= 0.50:
        return 'HIGH', True
    if classifier_score >= 0.30:
        return 'MEDIUM', False
    return 'LOW', False


def classify_and_route(flow: dict) -> None:
    """
    Score one flow and publish to high-risk-flows if it warrants agent investigation.

    Integrates score_flow() from Phase 5 when available; falls back to simple
    thresholds until then so Phase 3 is independently runnable.
    """
    result           = _call_classifier(flow['features'])
    classifier_score = result.get('classifier_score', _NEUTRAL['classifier_score'])

    machine_ip          = flow.get('machine_ip', '')
    machine_profile     = get_machine_profile(machine_ip)
    request_type_profile = get_request_type_profile(machine_ip, int(flow.get('dst_port', 0)))

    try:
        from src.scoring.scoring_service import score_flow, should_escalate_to_agent
        scoring = score_flow(
            flow=flow,
            classifier_result=result,
            machine_profile=machine_profile,
            request_type_profile=request_type_profile,
        )
        risk_level = scoring.risk_level
        risk_score = scoring.risk_score
        escalate   = should_escalate_to_agent(scoring)
    except ImportError:
        risk_level, escalate = _simple_risk(classifier_score)
        risk_score = classifier_score

    if escalate:
        publish_high_risk({
            **flow,
            'ml_label':         result.get('label'),
            'ml_confidence':    result.get('confidence'),
            'classifier_score': classifier_score,
            'risk_score':       risk_score,
            'risk_level':       risk_level,
        })
        logger.info(
            'Flow escalated',
            flow_id=flow.get('flow_id'),
            machine_ip=flow.get('machine_ip'),
            risk_level=risk_level,
            classifier_score=round(classifier_score, 3),
        )
    else:
        logger.info(
            'Flow scored, not escalated',
            flow_id=flow.get('flow_id'),
            risk_level=risk_level,
        )


def run_classifier_worker(consumer_name: str = 'classifier-1') -> None:
    """Consume from network-flows (classifier-group), score, and route high-risk flows."""
    logger.info('Classifier worker starting', consumer=consumer_name)

    while True:
        try:
            messages = consume_stream(
                stream=STREAM_NETWORK_FLOWS,
                group='classifier-group',
                consumer=consumer_name,
            )

            for msg_id, msg_data in messages:
                try:
                    flow = json.loads(msg_data['data'])
                    classify_and_route(flow)
                    ack_message(STREAM_NETWORK_FLOWS, 'classifier-group', msg_id)
                except Exception as e:
                    logger.error('Failed to classify flow', msg_id=msg_id, error=str(e))
                    # Do not ack — stays pending, retried on next cycle

        except Exception as e:
            logger.error('Classifier worker loop error', error=str(e))
            time.sleep(5)


if __name__ == '__main__':
    configure_logging()
    load_secrets()
    initialize_streams()
    run_classifier_worker()
