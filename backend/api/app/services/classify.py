"""Turn RASP monitoring events into threat alerts when risk signals appear."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from app.schemas import RaspEvent

_HIGH_EVENT_TYPES = {
    "DEBUGGER_ATTACHMENT",
    "ROOT_ENVIRONMENT",
    "APPLICATION_INTEGRITY_CHECK",
}

_MEDIUM_EVENT_TYPES = {
    "EMULATOR_ENVIRONMENT_DETECTION",
    "EXTERNAL_INPUT",
}


@dataclass(frozen=True)
class ThreatMatch:
    severity: str
    title: str
    reason: str


def _data_str(data: dict[str, Any], key: str) -> Optional[str]:
    value = data.get(key)
    if value is None:
        return None
    return str(value).upper()


def classify_rasp_event(event: RaspEvent) -> Optional[ThreatMatch]:
    """Return a ThreatMatch when the event carries a positive risk signal."""
    data = event.data or {}
    detection = _data_str(data, "detection_result")
    validation = _data_str(data, "validation_result")
    verification = _data_str(data, "verification_result")
    debugger_state = _data_str(data, "debugger_state")
    login_result = _data_str(data, "login_result")
    connection_result = _data_str(data, "connection_result")

    if detection == "DETECTED":
        severity = "critical" if event.event_type in _HIGH_EVENT_TYPES else "high"
        return ThreatMatch(
            severity=severity,
            title=f"RASP threat: {event.event_type}",
            reason=f"detection_result=DETECTED ({event.event_id})",
        )

    if verification == "FAILED":
        return ThreatMatch(
            severity="critical",
            title=f"Integrity failure: {event.event_type}",
            reason=f"verification_result=FAILED ({event.event_id})",
        )

    if validation == "SUSPICIOUS":
        return ThreatMatch(
            severity="medium",
            title=f"Suspicious input: {event.event_type}",
            reason=f"validation_result=SUSPICIOUS ({event.event_id})",
        )

    if event.event_type == "DEBUGGER_ATTACHMENT" and debugger_state == "ATTACHED":
        return ThreatMatch(
            severity="critical",
            title="Debugger attached",
            reason="debugger_state=ATTACHED",
        )

    if login_result in {"FAILED", "FAILURE", "DENIED", "INVALID"}:
        return ThreatMatch(
            severity="medium",
            title="Failed login attempt",
            reason=f"login_result={login_result} ({event.event_id})",
        )

    if connection_result and connection_result.startswith("HTTP_5"):
        return ThreatMatch(
            severity="medium",
            title=f"Banking API server error: {data.get('url_path', '?')}",
            reason=f"connection_result={connection_result} ({event.event_id})",
        )

    if connection_result and connection_result.startswith("HTTP_4"):
        return ThreatMatch(
            severity="low",
            title=f"Banking API client error: {data.get('url_path', '?')}",
            reason=f"connection_result={connection_result} ({event.event_id})",
        )

    if event.event_type in _HIGH_EVENT_TYPES and detection in {"DETECTED", "TRUE", "YES"}:
        return ThreatMatch(
            severity="high",
            title=f"RASP threat: {event.event_type}",
            reason=f"high-risk event type with positive signal ({event.event_id})",
        )

    if event.event_type in _MEDIUM_EVENT_TYPES and detection == "DETECTED":
        return ThreatMatch(
            severity="medium",
            title=f"RASP threat: {event.event_type}",
            reason=f"medium-risk event type detected ({event.event_id})",
        )

    return None
