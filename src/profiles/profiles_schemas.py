from typing import Optional
from pydantic import BaseModel


class MachineProfileResponse(BaseModel):
    machine_ip:          str
    flow_count:          int
    first_seen:          Optional[str]
    last_seen:           Optional[str]
    bytes_mean:          float
    bytes_per_sec_mean:  float
    byte_ratio_mean:     float
    pkts_mean:           float
    duration_mean:       float
    known_ports:         list[int]
    known_protocols:     list[int]
    is_new:              bool   # True when flow_count < 10 (graduation threshold)


class RequestTypeProfileResponse(BaseModel):
    machine_ip:   str
    request_type: str
    flow_count:   int
    bytes_mean:   float


class HealthResponse(BaseModel):
    status: str
