"""Liveness endpoint."""

from fastapi import APIRouter

from app.schemas import HealthResponse
from app.services.splunk import splunk_enabled

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/health/siem")
def health_siem() -> dict[str, object]:
    """Report whether Splunk HEC forwarding is configured."""
    return {
        "status": "ok",
        "splunk_hec_configured": splunk_enabled(),
    }

