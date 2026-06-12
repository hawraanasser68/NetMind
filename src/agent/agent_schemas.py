from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class AgentRequest(BaseModel):
    flow:           Dict[str, Any]
    scoring_result: Dict[str, Any]


class AgentResponse(BaseModel):
    flow_id:             str
    risk_level:          str
    classifier_score:    float
    deviation_score:     float
    machine_confidence:  float
    explanation:         str
    firewall_rule:       Optional[str]
    tools_called:        List[str]
    osint_results:       Dict[str, Any]
    escalated_to_human:  bool
    limit_hit:           bool
    limit_reason:        Optional[str]
    confidence:          str
