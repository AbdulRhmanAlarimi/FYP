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

_FAILED_LOGIN_RESULTS = {
    "FAILED",
    "FAILURE",
    "DENIED",
    "INVALID",
    "WRONG",
    "WRONG_PASSWORD",
    "WRONG PASSWORD",
    "USER DOES NOT EXIST",
    "FAIL",
}


@dataclass(frozen=True)
class ThreatMatch:
    severity: str
    title: str
    reason: str
    source: str = "RULE"  # RULE = classify rules; ML = on-device Markov


def _data_str(data: dict[str, Any], key: str) -> Optional[str]:
    value = data.get(key)
    if value is None:
        return None
    return str(value).upper()


def classify_rasp_event(event: RaspEvent) -> Optional[ThreatMatch]:
    """Return a ThreatMatch when the event carries a positive risk signal."""
    data = event.data or {}

    # On-device MarkovDetector posts this once per unusual session.
    if event.event_id == "ME-ML" or event.event_type == "ML_ANOMALY":
        score = data.get("ml_score", "?")
        threshold = data.get("threshold", "?")
        step = data.get("trigger_step", "?")
        return ThreatMatch(
            severity="high",
            title="ML anomaly: unusual session",
            reason=f"Markov score {score} > threshold {threshold} at step {step}",
            source="ML",
        )

    detection = _data_str(data, "detection_result")
    validation = _data_str(data, "validation_result")
    verification = _data_str(data, "verification_result")
    debugger_state = _data_str(data, "debugger_state")
    login_result = _data_str(data, "login_result")
    connection_result = _data_str(data, "connection_result")
    url_path = str(data.get("url_path") or "").lower()
    component = (event.component or "").lower()

    # --- Failed login (RULE): check early so it always becomes a clear alert ---
    if login_result in _FAILED_LOGIN_RESULTS:
        return ThreatMatch(
            severity="low",
            title="Failed login attempt",
            reason=f"login_result={login_result} ({event.event_id})",
            source="RULE",
        )

    # WrongLogin screen opened after a bad password (DoLogin navigates here).
    if event.event_id == "ME-09" and "wronglogin" in component:
        return ThreatMatch(
            severity="low",
            title="Failed login attempt",
            reason=f"WrongLogin screen opened ({event.event_id})",
            source="RULE",
        )

    # /login HTTP client errors (if the server ever returns 4xx).
    if (
        event.event_id == "ME-10"
        and connection_result
        and connection_result.startswith("HTTP_4")
        and "/login" in url_path
    ):
        return ThreatMatch(
            severity="low",
            title="Failed login attempt",
            reason=f"connection_result={connection_result} on {url_path} ({event.event_id})",
            source="RULE",
        )

    if detection == "DETECTED":
        severity = "critical" if event.event_type in _HIGH_EVENT_TYPES else "high"
        return ThreatMatch(
            severity=severity,
            title=f"RASP threat: {event.event_type}",
            reason=f"detection_result=DETECTED ({event.event_id})",
            source="RULE",
        )

    if verification == "FAILED":
        return ThreatMatch(
            severity="critical",
            title=f"Integrity failure: {event.event_type}",
            reason=f"verification_result=FAILED ({event.event_id})",
            source="RULE",
        )

    if validation == "SUSPICIOUS":
        return ThreatMatch(
            severity="medium",
            title=f"Suspicious input: {event.event_type}",
            reason=f"validation_result=SUSPICIOUS ({event.event_id})",
            source="RULE",
        )

    if event.event_type == "DEBUGGER_ATTACHMENT" and debugger_state == "ATTACHED":
        return ThreatMatch(
            severity="critical",
            title="Debugger attached",
            reason="debugger_state=ATTACHED",
            source="RULE",
        )

    if connection_result and connection_result.startswith("HTTP_5"):
        return ThreatMatch(
            severity="medium",
            title=f"Banking API server error: {data.get('url_path', '?')}",
            reason=f"connection_result={connection_result} ({event.event_id})",
            source="RULE",
        )

    if connection_result and connection_result.startswith("HTTP_4"):
        return ThreatMatch(
            severity="low",
            title=f"Banking API client error: {data.get('url_path', '?')}",
            reason=f"connection_result={connection_result} ({event.event_id})",
            source="RULE",
        )

    if event.event_type in _HIGH_EVENT_TYPES and detection in {"DETECTED", "TRUE", "YES"}:
        return ThreatMatch(
            severity="high",
            title=f"RASP threat: {event.event_type}",
            reason=f"high-risk event type with positive signal ({event.event_id})",
            source="RULE",
        )

    if event.event_type in _MEDIUM_EVENT_TYPES and detection == "DETECTED":
        return ThreatMatch(
            severity="medium",
            title=f"RASP threat: {event.event_type}",
            reason=f"medium-risk event type detected ({event.event_id})",
            source="RULE",
        )

    return None
