from fastapi import APIRouter, HTTPException

from src.profiles.profiles_machine import (
    GRADUATION_THRESHOLD,
    _get_or_load_profile,
)
from src.profiles.profiles_request_type import _get_or_load_profile as _get_rt_profile
from src.profiles.profiles_schemas import (
    HealthResponse,
    MachineProfileResponse,
    RequestTypeProfileResponse,
)

router = APIRouter(prefix='/profiles')


@router.get('/health', response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status='ok')


@router.get('/machine/{machine_ip}', response_model=MachineProfileResponse)
def get_machine_profile(machine_ip: str) -> MachineProfileResponse:
    profile = _get_or_load_profile(machine_ip)
    return MachineProfileResponse(
        machine_ip         = profile['machine_ip'],
        flow_count         = profile['flow_count'],
        first_seen         = str(profile['first_seen']) if profile['first_seen'] else None,
        last_seen          = str(profile['last_seen'])  if profile['last_seen']  else None,
        bytes_mean         = profile['bytes_mean'],
        bytes_per_sec_mean = profile['bytes_per_sec_mean'],
        byte_ratio_mean    = profile['byte_ratio_mean'],
        pkts_mean          = profile['pkts_mean'],
        duration_mean      = profile['duration_mean'],
        known_ports        = profile['known_ports'],
        known_protocols    = profile['known_protocols'],
        is_new             = profile['flow_count'] < GRADUATION_THRESHOLD,
    )


@router.get('/machine/{machine_ip}/request-type/{request_type}', response_model=RequestTypeProfileResponse)
def get_request_type_profile(machine_ip: str, request_type: str) -> RequestTypeProfileResponse:
    profile = _get_rt_profile(machine_ip, request_type.upper())
    return RequestTypeProfileResponse(
        machine_ip   = profile['machine_ip'],
        request_type = profile['request_type'],
        flow_count   = profile['flow_count'],
        bytes_mean   = profile['bytes_mean'],
    )
