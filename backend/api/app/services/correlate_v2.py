"""Stateful v2 correlation rules (async/background) for RASP alerts.

Edit thresholds in V2_THRESHOLDS below if tuning is needed.
All v2 alerts are emitted with source="RULE" and *_v2 event types so they are
easy to distinguish in Grafana from v1 stateless alerts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Alert, Event

# ---------------------------------------------------------------------------
# V2_THRESHOLDS: edit these values to tune sensitivity without changing logic.
# ---------------------------------------------------------------------------
V2_THRESHOLDS = {
    # Brute-force login (failed logins in window, same launch_id)
    "bruteforce_window_min": 5,
    "bruteforce_medium": 5,          # >=5 fails -> medium
    "bruteforce_high": 10,           # >=10 fails -> high
    "bruteforce_compromise_min_fails": 3,  # success after >=3 fails -> high
    # ATO / transaction chains
    "ato_chain_window_min": 10,      # password/profile change -> beneficiary/transfer
    "tx_burst_window_sec": 60,
    "tx_burst_count": 3,             # >=3 transfers/payments in window
    "beneficiary_burst_window_min": 10,
    "beneficiary_burst_count": 3,    # >=3 beneficiary adds in window
    # Runtime compromise correlation
    "runtime_window_min": 5,         # >=2 distinct runtime signals in window
    # API recon / errors
    "recon_window_sec": 60,
    "recon_count": 20,               # >=20 sensitive reads in window
    "error4_window_min": 5,
    "error4_count": 10,              # >=10 4xx in window
    "error5_window_min": 5,
    "error5_count": 5,               # >=5 5xx in window
    # Dedup/cooldown per (launch_id, dedupe_key)
    "dedupe_window_min": 10,
}

_FAILED_LOGIN_RESULTS = {
    "FAILED", "FAILURE", "DENIED", "INVALID", "WRONG",
    "WRONG_PASSWORD", "WRONG PASSWORD", "USER DOES NOT EXIST", "FAIL",
}
_SUCCESS_LOGIN_RESULTS = {"SUCCESS", "SUCCESSFUL", "OK", "AUTHENTICATED", "LOGGED_IN"}
_SENSITIVE_WRITE_PATHS_CRITICAL = {"/dotransfer", "/changepassword"}
_SENSITIVE_WRITE_PATHS_HIGH = {"/addbeneficiary", "/updateprofile", "/paybill", "/deposit"}
_SENSITIVE_READ_PATHS = {"/getaccountdetails", "/gettransactions", "/getbeneficiaries", "/getmyaccounts"}
_TRANSFER_PATHS = {"/dotransfer", "/paybill"}
_RUNTIME_EVENT_IDS = {"ME-11", "ME-13", "ME-14", "ME-15"}
_PASSWORD_CHANGE_PATHS = {"/changepassword"}
_PROFILE_CHANGE_PATHS = {"/updateprofile"}
_BENEFICIARY_PATHS = {"/addbeneficiary"}


@dataclass(frozen=True)
class V2ThreatMatch:
    severity: str
    title: str
    reason: str
    alert_event_type: str
    alert_event_id: str
    dedupe_key: str
    source: str = "RULE"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _to_aware(dt: Optional[datetime]) -> datetime:
    if dt is None:
        return _now_utc()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _data_str(data: dict[str, Any], key: str) -> Optional[str]:
    value = (data or {}).get(key)
    if value is None:
        return None
    return str(value).upper()


def _path(data: dict[str, Any]) -> str:
    return str((data or {}).get("url_path") or "").lower()


def _is_failed_login(event: Event) -> bool:
    data = event.data or {}
    login_result = _data_str(data, "login_result")
    conn = _data_str(data, "connection_result")
    if login_result in _FAILED_LOGIN_RESULTS:
        return True
    if event.event_id == "ME-09" and "wronglogin" in (event.component or "").lower():
        return True
    if event.event_id == "ME-10" and conn and conn.startswith("HTTP_4") and "/login" in _path(data):
        return True
    return False


def _is_success_login(event: Event) -> bool:
    data = event.data or {}
    login_result = _data_str(data, "login_result")
    if login_result in _SUCCESS_LOGIN_RESULTS:
        return True
    # Common positive server response for login endpoint
    conn = _data_str(data, "connection_result")
    if event.event_id == "ME-10" and conn == "HTTP_200" and _path(data).rstrip("/") == "/login":
        return True
    return False


def _runtime_signal_kind(event: Event) -> Optional[str]:
    if event.event_id not in _RUNTIME_EVENT_IDS:
        return None
    data = event.data or {}
    detection = _data_str(data, "detection_result")
    verification = _data_str(data, "verification_result")
    debugger_state = _data_str(data, "debugger_state")
    if event.event_id == "ME-11" and (debugger_state == "ATTACHED" or detection == "DETECTED"):
        return "ME-11"
    if event.event_id == "ME-13" and verification == "FAILED":
        return "ME-13"
    if event.event_id in {"ME-14", "ME-15"} and detection in {"DETECTED", "TRUE", "YES"}:
        return event.event_id
    # Generic positive detection on runtime event types
    if detection in {"DETECTED", "TRUE", "YES"}:
        return event.event_id
    return None


def _launch_events_since(db: Session, launch_id: str, since: datetime) -> list[Event]:
    if not launch_id:
        return []
    stmt = (
        select(Event)
        .where(Event.launch_id == launch_id, Event.received_at >= since)
        .order_by(Event.received_at.asc(), Event.id.asc())
    )
    return list(db.scalars(stmt).all())


def _recent_alert_exists_v2(db: Session, launch_id: str, dedupe_key: str, since: datetime) -> bool:
    if not launch_id:
        return False
    # Join via event to scope dedupe to same launch/session window.
    stmt = (
        select(func.count())
        .select_from(Alert)
        .join(Event, Alert.event_pk == Event.id)
        .where(
            Event.launch_id == launch_id,
            Alert.created_at >= since,
            Alert.title == dedupe_key,  # title used as stable dedupe label key carrier
        )
    )
    # We store dedupe via reason marker; safer to check by reason prefix token.
    # Fallback: query by reason containing dedupe key marker.
    stmt2 = (
        select(func.count())
        .select_from(Alert)
        .join(Event, Alert.event_pk == Event.id)
        .where(
            Event.launch_id == launch_id,
            Alert.created_at >= since,
            Alert.reason.like(f"%[dedupe:{dedupe_key}]%"),
        )
    )
    return (db.scalar(stmt2) or 0) > 0


def _with_dedupe(reason: str, dedupe_key: str) -> str:
    return f"{reason} [dedupe:{dedupe_key}]"


def _matches_sqli_xss_path(payload: str) -> Optional[str]:
    s = payload.lower()
    if any(tok in s for tok in ["' or ", "\" or ", " or 1=1", "union select", "--", "/*", "*/", "drop table", "xp_"]):
        return "SQLi"
    if any(tok in s for tok in ["<script", "javascript:", "onerror=", "onload=", "<img", "alert("]):
        return "XSS"
    if any(tok in s for tok in ["../", "..\\", "/etc/passwd", "file://"]):
        return "PathTraversal"
    return None


def classify_event_v2(db: Session, event: Event) -> list[V2ThreatMatch]:
    """Return v2 correlated ThreatMatches for the given stored event."""
    matches: list[V2ThreatMatch] = []
    data = event.data or {}
    launch_id = event.launch_id or ""
    now = _to_aware(event.received_at)
    T = V2_THRESHOLDS

    # --- Deep link correlation (ME-12) ---
    if event.event_id == "ME-12" or event.event_type == "DEEP_LINK_INVOCATION":
        uri = str(data.get("data_uri") or data.get("uri") or "")
        sev = "medium"
        reason = f"ME-12 deep link received uri={uri or 'n/a'}"
        # elevate if sensitive target hinted
        if any(k in uri.lower() for k in ["transfer", "beneficiary", "password", "changepassword", "dotransfer"]):
            sev = "high"
            reason = f"ME-12 deep link targets sensitive flow uri={uri}"
        # correlate with runtime threats in same launch
        if launch_id:
            since = now - timedelta(minutes=T["runtime_window_min"])
            evs = _launch_events_since(db, launch_id, since)
            if any(_runtime_signal_kind(e) for e in evs):
                sev = "critical"
                reason = f"ME-12 deep link in compromised runtime uri={uri or 'n/a'}"
        matches.append(V2ThreatMatch(
            severity=sev,
            title="Deep link invocation_v2",
            reason=reason,
            alert_event_type="DEEP_LINK_INVOCATION_v2",
            alert_event_id=event.event_id,
            dedupe_key=f"deeplink:{event.event_id}:{sev}",
        ))

    # --- Malicious input correlated pattern ---
    if event.event_type == "EXTERNAL_INPUT" and _data_str(data, "validation_result") == "SUSPICIOUS":
        blob = " ".join(str(v) for v in data.values())
        pat = _matches_sqli_xss_path(blob)
        if pat:
            matches.append(V2ThreatMatch(
                severity="high",
                title="Malicious input pattern detected_v2",
                reason=f"validation_result=SUSPICIOUS, pattern={pat} ({event.event_id})",
                alert_event_type="EXTERNAL_INPUT_v2",
                alert_event_id=event.event_id,
                dedupe_key=f"malinput:{pat}",
            ))

    # --- Stateful rules scoped to launch/session ---
    if launch_id:
        # Brute-force window
        bf_since = now - timedelta(minutes=T["bruteforce_window_min"])
        recent = _launch_events_since(db, launch_id, bf_since)
        fails = [e for e in recent if _is_failed_login(e)]
        fail_count = len(fails)

        if _is_failed_login(event):
            if fail_count >= T["bruteforce_high"]:
                matches.append(V2ThreatMatch(
                    severity="high",
                    title="Brute-force login detected_v2",
                    reason=f"{fail_count} failed logins in {T['bruteforce_window_min']}m (launch_id={launch_id})",
                    alert_event_type="BRUTE_FORCE_LOGIN_v2",
                    alert_event_id=event.event_id,
                    dedupe_key="bruteforce:high",
                ))
            elif fail_count >= T["bruteforce_medium"]:
                matches.append(V2ThreatMatch(
                    severity="medium",
                    title="Brute-force login suspected_v2",
                    reason=f"{fail_count} failed logins in {T['bruteforce_window_min']}m (launch_id={launch_id})",
                    alert_event_type="BRUTE_FORCE_LOGIN_v2",
                    alert_event_id=event.event_id,
                    dedupe_key="bruteforce:medium",
                ))

        if _is_success_login(event) and fail_count >= T["bruteforce_compromise_min_fails"]:
            matches.append(V2ThreatMatch(
                severity="high",
                title="Possible credential compromise_v2",
                reason=f"login success after {fail_count} failures in {T['bruteforce_window_min']}m (launch_id={launch_id})",
                alert_event_type="CREDENTIAL_COMPROMISE_v2",
                alert_event_id=event.event_id,
                dedupe_key="compromise:after-fails",
            ))

        # Unauthenticated sensitive actions (no prior success in this launch)
        if event.event_id == "ME-10":
            p = _path(data)
            # consider whole launch for auth state, not just window
            launch_all = _launch_events_since(db, launch_id, now - timedelta(hours=12))
            authed = any(_is_success_login(e) for e in launch_all)
            if not authed:
                if p in _SENSITIVE_WRITE_PATHS_CRITICAL:
                    matches.append(V2ThreatMatch(
                        severity="critical",
                        title="Unauthenticated sensitive action_v2",
                        reason=f"POST {p} without authenticated session (launch_id={launch_id})",
                        alert_event_type="UNAUTHENTICATED_ACCESS_v2",
                        alert_event_id=event.event_id,
                        dedupe_key=f"unauth:critical:{p}",
                    ))
                elif p in _SENSITIVE_WRITE_PATHS_HIGH:
                    matches.append(V2ThreatMatch(
                        severity="high",
                        title="Unauthenticated sensitive action_v2",
                        reason=f"POST {p} without authenticated session (launch_id={launch_id})",
                        alert_event_type="UNAUTHENTICATED_ACCESS_v2",
                        alert_event_id=event.event_id,
                        dedupe_key=f"unauth:high:{p}",
                    ))
                elif p in _SENSITIVE_READ_PATHS:
                    matches.append(V2ThreatMatch(
                        severity="medium",
                        title="Unauthenticated access attempt_v2",
                        reason=f"access to {p} without authenticated session (launch_id={launch_id})",
                        alert_event_type="UNAUTHENTICATED_ACCESS_v2",
                        alert_event_id=event.event_id,
                        dedupe_key=f"unauth:read:{p}",
                    ))

        # ATO chains / bursts
        if event.event_id == "ME-10":
            p = _path(data)
            chain_since = now - timedelta(minutes=T["ato_chain_window_min"])
            chain_events = _launch_events_since(db, launch_id, chain_since)
            had_pw_change = any(_path(e.data or {}) in _PASSWORD_CHANGE_PATHS for e in chain_events if e.event_id == "ME-10")
            had_profile_change = any(_path(e.data or {}) in _PROFILE_CHANGE_PATHS for e in chain_events if e.event_id == "ME-10")
            if p in _TRANSFER_PATHS.union(_BENEFICIARY_PATHS) and (had_pw_change or had_profile_change):
                matches.append(V2ThreatMatch(
                    severity="critical",
                    title="Possible account takeover chain_v2",
                    reason=f"password/profile change followed by {p} within {T['ato_chain_window_min']}m (launch_id={launch_id})",
                    alert_event_type="ATO_CHAIN_v2",
                    alert_event_id=event.event_id,
                    dedupe_key="ato:chain",
                ))

            # transaction/payment burst
            burst_since = now - timedelta(seconds=T["tx_burst_window_sec"])
            burst_events = _launch_events_since(db, launch_id, burst_since)
            tx_count = sum(1 for e in burst_events if e.event_id == "ME-10" and _path(e.data or {}) in _TRANSFER_PATHS)
            if p in _TRANSFER_PATHS and tx_count >= T["tx_burst_count"]:
                matches.append(V2ThreatMatch(
                    severity="high",
                    title="Transaction burst detected_v2",
                    reason=f"{tx_count} transfer/payment calls in {T['tx_burst_window_sec']}s (launch_id={launch_id})",
                    alert_event_type="TRANSACTION_BURST_v2",
                    alert_event_id=event.event_id,
                    dedupe_key="burst:tx",
                ))

            ben_since = now - timedelta(minutes=T["beneficiary_burst_window_min"])
            ben_events = _launch_events_since(db, launch_id, ben_since)
            ben_count = sum(1 for e in ben_events if e.event_id == "ME-10" and _path(e.data or {}) in _BENEFICIARY_PATHS)
            if p in _BENEFICIARY_PATHS and ben_count >= T["beneficiary_burst_count"]:
                matches.append(V2ThreatMatch(
                    severity="high",
                    title="Beneficiary modification burst_v2",
                    reason=f"{ben_count} /addbeneficiary calls in {T['beneficiary_burst_window_min']}m (launch_id={launch_id})",
                    alert_event_type="BENEFICIARY_BURST_v2",
                    alert_event_id=event.event_id,
                    dedupe_key="burst:beneficiary",
                ))

        # Runtime compromise correlation
        kind = _runtime_signal_kind(event)
        if kind:
            rt_since = now - timedelta(minutes=T["runtime_window_min"])
            rt_events = _launch_events_since(db, launch_id, rt_since)
            kinds = sorted({k for e in rt_events for k in [_runtime_signal_kind(e)] if k})
            if len(kinds) >= 2:
                matches.append(V2ThreatMatch(
                    severity="critical",
                    title="Multiple runtime compromise signals_v2",
                    reason=f"{' + '.join(kinds)} detected in same session (launch_id={launch_id})",
                    alert_event_type="RUNTIME_COMPROMISE_v2",
                    alert_event_id=event.event_id,
                    dedupe_key="runtime:multiple",
                ))
            # runtime + login success or sensitive action
            has_auth = any(_is_success_login(e) for e in rt_events)
            has_sensitive = any(e.event_id == "ME-10" and _path(e.data or {}) in (_SENSITIVE_WRITE_PATHS_CRITICAL | _SENSITIVE_WRITE_PATHS_HIGH) for e in rt_events)
            if has_auth or has_sensitive:
                what = "login/sensitive activity" if (has_auth and has_sensitive) else ("login success" if has_auth else "sensitive action")
                matches.append(V2ThreatMatch(
                    severity="critical",
                    title="Compromised runtime with sensitive activity_v2",
                    reason=f"{kind} detected with {what} in same session (launch_id={launch_id})",
                    alert_event_type="RUNTIME_COMPROMISE_v2",
                    alert_event_id=event.event_id,
                    dedupe_key="runtime:sensitive",
                ))

        # API recon / errors (ME-10)
        if event.event_id == "ME-10":
            p = _path(data)
            conn = _data_str(data, "connection_result") or ""
            # recon: sensitive reads burst
            recon_since = now - timedelta(seconds=T["recon_window_sec"])
            recon_events = _launch_events_since(db, launch_id, recon_since)
            read_count = sum(1 for e in recon_events if e.event_id == "ME-10" and _path(e.data or {}) in _SENSITIVE_READ_PATHS)
            if p in _SENSITIVE_READ_PATHS and read_count >= T["recon_count"]:
                matches.append(V2ThreatMatch(
                    severity="medium",
                    title="API enumeration suspected_v2",
                    reason=f"{read_count} sensitive-read requests in {T['recon_window_sec']}s (launch_id={launch_id})",
                    alert_event_type="API_RECON_v2",
                    alert_event_id=event.event_id,
                    dedupe_key="recon:reads",
                ))
            # repeated 4xx on protected endpoints
            if conn.startswith("HTTP_4"):
                e4_since = now - timedelta(minutes=T["error4_window_min"])
                e4_events = _launch_events_since(db, launch_id, e4_since)
                e4_count = sum(1 for e in e4_events if e.event_id == "ME-10" and (_data_str(e.data or {}, "connection_result") or "").startswith("HTTP_4"))
                if e4_count >= T["error4_count"]:
                    sev = "high" if (p in _SENSITIVE_WRITE_PATHS_CRITICAL.union(_SENSITIVE_WRITE_PATHS_HIGH) or "/login" in p) else "medium"
                    matches.append(V2ThreatMatch(
                        severity=sev,
                        title="Repeated unauthorized requests_v2",
                        reason=f"{e4_count} HTTP_4xx in {T['error4_window_min']}m (launch_id={launch_id})",
                        alert_event_type="API_ERROR_v2",
                        alert_event_id=event.event_id,
                        dedupe_key="errors:4xx",
                    ))
            # repeated 5xx on same endpoint
            if conn.startswith("HTTP_5"):
                e5_since = now - timedelta(minutes=T["error5_window_min"])
                e5_events = _launch_events_since(db, launch_id, e5_since)
                e5_count = sum(1 for e in e5_events if e.event_id == "ME-10" and (_data_str(e.data or {}, "connection_result") or "").startswith("HTTP_5") and _path(e.data or {}) == p)
                if e5_count >= T["error5_count"]:
                    matches.append(V2ThreatMatch(
                        severity="high",
                        title="Repeated server errors_v2",
                        reason=f"{e5_count} {conn} on {p} in {T['error5_window_min']}m (launch_id={launch_id})",
                        alert_event_type="API_ERROR_v2",
                        alert_event_id=event.event_id,
                        dedupe_key=f"errors:5xx:{p}",
                    ))

    return matches


def persist_v2_alerts_for_event(db: Session, event: Event, commit: bool = True) -> int:
    """Run v2 correlation for a stored event and persist deduped alerts. Returns count created."""
    db.flush()
    matches = classify_event_v2(db, event)
    if not matches:
        return 0
    created = 0
    dedupe_since = _to_aware(event.received_at) - timedelta(minutes=V2_THRESHOLDS["dedupe_window_min"])
    for m in matches:
        if _recent_alert_exists_v2(db, event.launch_id or "", m.dedupe_key, dedupe_since):
            continue
        db.add(Alert(
            event_pk=event.id,
            severity=m.severity,
            title=m.title,
            reason=_with_dedupe(m.reason, m.dedupe_key),
            event_type=m.alert_event_type,
            event_id=m.alert_event_id or event.event_id,
            source=m.source,
            created_at=_to_aware(event.received_at),
        ))
        created += 1
    if created:
        if commit:
            db.commit()
        else:
            db.flush()
    return created


def correlate_event_v2_background(event_pk: int) -> None:
    """Background task entrypoint: open own DB session and correlate v2 rules."""
    db = SessionLocal()
    try:
        event = db.get(Event, event_pk)
        if event is None:
            return
        persist_v2_alerts_for_event(db, event)
    except Exception:
        db.rollback()
    finally:
        db.close()
