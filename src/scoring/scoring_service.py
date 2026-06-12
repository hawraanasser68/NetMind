from functools import lru_cache
import yaml
from pathlib import Path

from src.scoring.scoring_deviation import compute_deviation_score, load_weights
from src.scoring.scoring_schemas import ScoringResult

_THRESHOLDS_PATH = Path('config/deviation_weights.yaml')


@lru_cache(maxsize=1)
def load_thresholds() -> dict:
    with open(_THRESHOLDS_PATH) as f:
        return yaml.safe_load(f)['routing_thresholds']


def compute_risk_level(
    risk_score: float,
    deviation_score: float,
    confidence: float,
    is_new_machine: bool = False,
    is_unknown_protocol: bool = False,
) -> tuple[str, bool]:
    """
    Map scores → (risk_level, escalate_to_agent).

    Special cases (from spec):
      - New machine (< 10 flows) or unknown protocol → at least HIGH + escalate
      - Low confidence (< low_confidence_max) → cap at MEDIUM
    """
    t = load_thresholds()

    # Special cases — always escalate regardless of score
    if is_new_machine or is_unknown_protocol:
        return 'HIGH', True

    # Cap risk level when we don't have enough history to trust the score
    if confidence < t['low_confidence_max']:
        return 'MEDIUM', False

    if risk_score >= t['critical']:
        return 'CRITICAL', True

    if risk_score >= t['high_classifier'] or deviation_score >= t['high_deviation']:
        return 'HIGH', True

    if deviation_score >= t['low_deviation']:
        return 'MEDIUM', False

    return 'LOW', False


def should_escalate_to_agent(result: ScoringResult) -> bool:
    return result.escalate_to_agent


def score_flow(
    flow: dict,
    classifier_result: dict,
    machine_profile: dict | None,
    request_type_profile: dict | None,
) -> ScoringResult:
    """
    Combine classifier output + behavioural deviation into a single ScoringResult.

    Called by the classifier worker after getting ML scores.
    machine_profile and request_type_profile may be None (Phase 6 not yet built)
    — deviation falls back to zero in that case, routing is classifier-only.
    """
    classifier_score = float(classifier_result.get('classifier_score', 0.0))
    confidence       = 0.0
    deviation_score  = 0.0
    components       = {}

    mp  = machine_profile
    rtp = request_type_profile

    if mp is not None:
        deviation_score, components, confidence = compute_deviation_score(
            flow, mp, rtp,
        )

    # Combined risk: classifier dominates (60%), deviation modifies (40%)
    risk_score = 0.6 * classifier_score + 0.4 * deviation_score

    flow_count           = int((mp or {}).get('flow_count', 0))
    known_protocols      = (mp or {}).get('known_protocols', [])
    protocol             = int(flow.get('protocol', 0))
    is_new_machine       = flow_count < 10
    is_unknown_protocol  = bool(known_protocols) and protocol not in known_protocols

    risk_level, escalate = compute_risk_level(
        risk_score, deviation_score, confidence,
        is_new_machine, is_unknown_protocol,
    )

    return ScoringResult(
        risk_score        = round(risk_score, 4),
        risk_level        = risk_level,
        confidence        = round(confidence, 4),
        escalate_to_agent = escalate,
        components        = components,
    )
