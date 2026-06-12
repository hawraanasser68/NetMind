from dataclasses import dataclass, field


@dataclass
class ScoringResult:
    risk_score:        float   # 0.0 – 1.0 combined classifier + deviation score
    risk_level:        str     # CRITICAL / HIGH / MEDIUM / LOW
    confidence:        float   # machine profile maturity — min(flow_count/100, 1.0)
    escalate_to_agent: bool
    components:        dict = field(default_factory=dict)  # z-score breakdown for debugging
