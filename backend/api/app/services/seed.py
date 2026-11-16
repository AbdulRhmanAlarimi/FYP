"""Demo RASP events so Grafana panels are never empty before the emulator runs."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Alert, Event
from app.schemas import RaspEvent
from app.services.classify import classify_rasp_event

logger = logging.getLogger(__name__)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _build_demo_events(now: datetime) -> list[RaspEvent]:
    """Spread sample traffic across the last ~4 hours for Grafana charts."""
    launch_a = str(uuid4())
    launch_b = str(uuid4())
    launch_c = str(uuid4())

    # (minutes_ago, event_id, event_type, component, data, seq, launch_id)
    samples: list[tuple[int, str, str, str, dict[str, Any], int, str]] = [
        # Launch A — morning session
        (230, "ME-15", "EMULATOR_ENVIRONMENT_DETECTION", "Rasp",
         {"emulator_indicator_type": "FINGERPRINT,HARDWARE", "detection_result": "DETECTED"}, 1, launch_a),
        (228, "ME-14", "ROOT_ENVIRONMENT", "Rasp",
         {"detection_result": "NOT_DETECTED"}, 2, launch_a),
        (226, "ME-13", "APPLICATION_INTEGRITY_CHECK", "RaspApp",
         {"verification_result": "PASSED"}, 3, launch_a),
        (220, "ME-09", "ANDROID_COMPONENT_INVOCATION", "LoginActivity",
         {"auth_state": "ANONYMOUS"}, 4, launch_a),
        (215, "ME-06", "EXTERNAL_INPUT", "DoLogin",
         {"input_source": "UI", "login_result": "FAILED", "validation_result": "PASSED"}, 5, launch_a),
        (214, "ME-10", "NETWORK_CONNECTION", "DoLogin",
         {"url_path": "/login", "http_method": "POST", "connection_result": "HTTP_401", "destination_port": "8888"}, 6, launch_a),
        (200, "ME-06", "EXTERNAL_INPUT", "DoLogin",
         {"input_source": "UI", "login_result": "SUCCESS", "validation_result": "PASSED"}, 7, launch_a),
        (199, "ME-10", "NETWORK_CONNECTION", "DoLogin",
         {"url_path": "/login", "http_method": "POST", "connection_result": "HTTP_200", "destination_port": "8888"}, 8, launch_a),
        (190, "ME-09", "ANDROID_COMPONENT_INVOCATION", "PostLogin",
         {"auth_state": "AUTHENTICATED"}, 9, launch_a),
        (180, "ME-09", "ANDROID_COMPONENT_INVOCATION", "DoTransfer",
         {"auth_state": "AUTHENTICATED"}, 10, launch_a),
        (178, "ME-10", "NETWORK_CONNECTION", "DoTransfer",
         {"url_path": "/getaccounts", "http_method": "POST", "connection_result": "HTTP_200", "destination_port": "8888"}, 11, launch_a),
        (175, "ME-10", "NETWORK_CONNECTION", "DoTransfer",
         {"url_path": "/dotransfer", "http_method": "POST", "connection_result": "HTTP_200", "destination_port": "8888"}, 12, launch_a),
        (160, "ME-09", "ANDROID_COMPONENT_INVOCATION", "BillPaymentActivity",
         {"auth_state": "AUTHENTICATED"}, 13, launch_a),
        (158, "ME-10", "NETWORK_CONNECTION", "BillPaymentActivity",
         {"url_path": "/paybill", "http_method": "POST", "connection_result": "HTTP_200", "destination_port": "8888"}, 14, launch_a),
        (150, "ME-09", "ANDROID_COMPONENT_INVOCATION", "ViewStatement",
         {"auth_state": "AUTHENTICATED"}, 15, launch_a),
        (148, "ME-08", "WEBVIEW_ACTIVITY", "ViewStatement",
         {"url": "file:///sdcard/statement.html", "javascript_enabled": True}, 16, launch_a),
        (140, "ME-05", "APPLICATION_LOG_EVENT", "DoLogin",
         {"log_level": "SENSITIVE", "message": "username logged"}, 17, launch_a),
        # Launch B — attack-ish session
        (120, "ME-15", "EMULATOR_ENVIRONMENT_DETECTION", "Rasp",
         {"detection_result": "DETECTED"}, 1, launch_b),
        (118, "ME-13", "APPLICATION_INTEGRITY_CHECK", "RaspApp",
         {"verification_result": "FAILED"}, 2, launch_b),
        (115, "ME-09", "ANDROID_COMPONENT_INVOCATION", "LoginActivity",
         {"auth_state": "ANONYMOUS"}, 3, launch_b),
        (110, "ME-06", "EXTERNAL_INPUT", "DoLogin",
         {"login_result": "FAILED", "validation_result": "SUSPICIOUS"}, 4, launch_b),
        (109, "ME-10", "NETWORK_CONNECTION", "DoLogin",
         {"url_path": "/login", "http_method": "POST", "connection_result": "HTTP_500", "destination_port": "8888"}, 5, launch_b),
        (100, "ME-11", "DEBUGGER_ATTACHMENT", "Rasp",
         {"debugger_state": "ATTACHED", "detection_result": "DETECTED"}, 6, launch_b),
        (95, "ME-14", "ROOT_ENVIRONMENT", "Rasp",
         {"detection_result": "DETECTED"}, 7, launch_b),
        (90, "ME-12", "DEEP_LINK_INVOCATION", "RaspApp",
         {"action": "ACTION_VIEW", "data_uri": "insecurebank://transfer"}, 8, launch_b),
        (85, "ME-06", "EXTERNAL_INPUT", "DoLogin",
         {"login_result": "FAILED", "validation_result": "PASSED"}, 9, launch_b),
        (84, "ME-10", "NETWORK_CONNECTION", "DoLogin",
         {"url_path": "/login", "http_method": "POST", "connection_result": "HTTP_401", "destination_port": "8888"}, 10, launch_b),
        # Launch C — recent benign banking
        (60, "ME-15", "EMULATOR_ENVIRONMENT_DETECTION", "Rasp",
         {"detection_result": "DETECTED"}, 1, launch_c),
        (58, "ME-13", "APPLICATION_INTEGRITY_CHECK", "RaspApp",
         {"verification_result": "PASSED"}, 2, launch_c),
        (55, "ME-09", "ANDROID_COMPONENT_INVOCATION", "LoginActivity",
         {"auth_state": "ANONYMOUS"}, 3, launch_c),
        (50, "ME-06", "EXTERNAL_INPUT", "DoLogin",
         {"login_result": "SUCCESS", "validation_result": "PASSED"}, 4, launch_c),
        (49, "ME-10", "NETWORK_CONNECTION", "DoLogin",
         {"url_path": "/login", "http_method": "POST", "connection_result": "HTTP_200", "destination_port": "8888"}, 5, launch_c),
        (45, "ME-09", "ANDROID_COMPONENT_INVOCATION", "PostLogin",
         {"auth_state": "AUTHENTICATED"}, 6, launch_c),
        (40, "ME-09", "ANDROID_COMPONENT_INVOCATION", "DepositActivity",
         {"auth_state": "AUTHENTICATED"}, 7, launch_c),
        (38, "ME-10", "NETWORK_CONNECTION", "DepositActivity",
         {"url_path": "/deposit", "http_method": "POST", "connection_result": "HTTP_200", "destination_port": "8888"}, 8, launch_c),
        (35, "ME-09", "ANDROID_COMPONENT_INVOCATION", "AccountDetailsActivity",
         {"auth_state": "AUTHENTICATED"}, 9, launch_c),
        (33, "ME-10", "NETWORK_CONNECTION", "AccountDetailsActivity",
         {"url_path": "/getaccountdetails", "http_method": "POST", "connection_result": "HTTP_200", "destination_port": "8888"}, 10, launch_c),
        (30, "ME-09", "ANDROID_COMPONENT_INVOCATION", "BeneficiaryActivity",
         {"auth_state": "AUTHENTICATED"}, 11, launch_c),
        (28, "ME-10", "NETWORK_CONNECTION", "BeneficiaryActivity",
         {"url_path": "/addbeneficiary", "http_method": "POST", "connection_result": "HTTP_200", "destination_port": "8888"}, 12, launch_c),
        (25, "ME-09", "ANDROID_COMPONENT_INVOCATION", "TransactionHistoryActivity",
         {"auth_state": "AUTHENTICATED"}, 13, launch_c),
        (23, "ME-10", "NETWORK_CONNECTION", "TransactionHistoryActivity",
         {"url_path": "/gettransactions", "http_method": "POST", "connection_result": "HTTP_200", "destination_port": "8888"}, 14, launch_c),
        (20, "ME-09", "ANDROID_COMPONENT_INVOCATION", "ChangePassword",
         {"auth_state": "AUTHENTICATED"}, 15, launch_c),
        (18, "ME-10", "NETWORK_CONNECTION", "ChangePassword",
         {"url_path": "/changepassword", "http_method": "POST", "connection_result": "HTTP_200", "destination_port": "8888"}, 16, launch_c),
        (15, "ME-04", "CLIPBOARD_ACCESS", "RaspApp",
         {"operation": "GET", "content_type": "text"}, 17, launch_c),
        (10, "ME-01", "SHARED_PREFERENCES_ACCESS", "DoLogin",
         {"pref_name": "mySharedPreferences", "operation": "WRITE"}, 18, launch_c),
        (5, "ME-10", "NETWORK_CONNECTION", "DoTransfer",
         {"url_path": "/dotransfer", "http_method": "POST", "connection_result": "HTTP_200", "destination_port": "8888"}, 19, launch_c),
        (2, "ME-09", "ANDROID_COMPONENT_INVOCATION", "PostLogin",
         {"auth_state": "AUTHENTICATED"}, 20, launch_c),
    ]

    events: list[RaspEvent] = []
    for minutes_ago, event_id, event_type, component, data, seq, launch_id in samples:
        ts = now - timedelta(minutes=minutes_ago)
        events.append(
            RaspEvent(
                event_id=event_id,
                event_type=event_type,
                timestamp=_iso(ts),
                component=component,
                data=data,
                seq=seq,
                launch_id=launch_id,
            )
        )
    return events


def seed_demo_data(db: Session, *, force: bool = False) -> dict[str, int]:
    existing = db.scalar(select(func.count()).select_from(Event)) or 0
    if existing > 0 and not force:
        return {"events_created": 0, "alerts_created": 0, "skipped": int(existing)}

    if force:
        db.execute(delete(Alert))
        db.execute(delete(Event))
        db.commit()

    now = datetime.now(timezone.utc)
    created_events = 0
    created_alerts = 0

    for payload in _build_demo_events(now):
        received_at = datetime.fromisoformat(payload.timestamp.replace("Z", "+00:00"))
        row = Event(
            event_id=payload.event_id,
            event_type=payload.event_type,
            timestamp=payload.timestamp,
            component=payload.component,
            data=payload.data or {},
            seq=payload.seq,
            launch_id=payload.launch_id or "",
            received_at=received_at,
        )
        db.add(row)
        db.flush()
        created_events += 1

        match = classify_rasp_event(payload)
        if match is not None:
            db.add(
                Alert(
                    event_pk=row.id,
                    severity=match.severity,
                    title=match.title,
                    reason=match.reason,
                    event_type=payload.event_type,
                    event_id=payload.event_id,
                    source="RASP",
                    created_at=received_at,
                )
            )
            created_alerts += 1

    db.commit()
    return {
        "events_created": created_events,
        "alerts_created": created_alerts,
        "skipped": 0,
    }


def ensure_sample_data() -> dict[str, int]:
    """Load demo rows when the database has no events (safe for API startup)."""
    db = SessionLocal()
    try:
        result = seed_demo_data(db, force=False)
        if result["events_created"]:
            logger.info(
                "Seeded sample data: %s events, %s alerts",
                result["events_created"],
                result["alerts_created"],
            )
        else:
            logger.info("Sample data already present (%s events); skip seed", result["skipped"])
        return result
    finally:
        db.close()
