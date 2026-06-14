from typing import Any, Dict, Optional

from pydantic import BaseModel


class InputCheckRequest(BaseModel):
    flow_id:     str
    flow_fields: Dict[str, Any]


class InputCheckResponse(BaseModel):
    approved:  bool
    reason:    Optional[str]
    rail_type: Optional[str]


class ToolCallCheckRequest(BaseModel):
    flow_id:   str
    tool_name: str
    tool_args: Dict[str, Any]
    flow:      Dict[str, Any]


class ToolCallCheckResponse(BaseModel):
    approved: bool
    reason:   Optional[str]


class ToolResultCheckRequest(BaseModel):
    flow_id:     str
    tool_name:   str
    tool_result: str


class ToolResultCheckResponse(BaseModel):
    sanitized_result: str
    was_modified:     bool


class FindingCheckRequest(BaseModel):
    flow_id:          str
    risk_level:       str
    classifier_score: float
    explanation:      str
    firewall_rule:    Optional[str]
    limit_hit:        bool


class FindingCheckResponse(BaseModel):
    approved: bool
    reason:   Optional[str]
