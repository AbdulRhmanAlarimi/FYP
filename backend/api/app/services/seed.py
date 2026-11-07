"""Demo RASP events so Grafana panels are never empty before the emulator runs."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models import Alert, Event
from app.schemas import RaspEvent
from app.services.classify import classify_rasp_event


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _build_demo_events(now: datetime) -> list[RaspEvent]:
    launch_a = str(uuid4())
    launch_b = str(uuid4())
    samples: list[tuple[timedelta, str, str, str, dict[str, Any], int, str]] = [
        (
            timedelta(minutes=55),
            "ME-15",
            "EMULATOR_ENVIRONMENT_DETECTION",
            "Rasp",
            {
                "emulator_indicator_type": "FINGERPRINT,HARDWARE",
                "detection_result": "DETECTED",
            },
            1,
            launch_a,
        ),
        (
            timedelta(minutes=54),
            "ME-14",
            "ROOT_ENVIRONMENT",
            "Rasp",
            {"detection_result": "NOT_DETECTED"},
            2,
            launch_a,
        ),
        (
            timedelta(minutes=53),
            "ME-13",
            "APPLICATION_INTEGRITY_CHECK",
            "RaspApp",
            {"verification_result": "PASSED"},
            3,
            launch_a,
        ),
        (
            timedelta(minutes=50),
            "ME-09",
            "ANDROID_COMPONENT_INVOCATION",
            "LoginActivity",
            {"auth_state": "ANONYMOUS"},
            4,
            launch_a,
        ),
        (
            timedelta(minutes=48),
            "ME-06",
            "EXTERNAL_INPUT",
            "DoLogin",
            {
                "input_source": "UI",
                "login_result": "FAILED",
                "validation_result": "PASSED",
            },
            5,
            launch_a,
        ),
        (
            timedelta(minutes=47),
            "ME-10",
            "NETWORK_CONNECTION",
            "DoLogin",
            {
                "url_path": "/login",
                "http_method": "POST",
                "connection_result": "HTTP_401",
                "destination_port": "8888",
            },
            6,
            launch_a,
        ),
        (
            timedelta(minutes=40),
            "ME-06",
            "EXTERNAL_INPUT",
            "DoLogin",
            {
                "input_source": "UI",
                "login_result": "SUCCESS",
                "validation_result": "PASSED",
            },
            7,
            launch_a,
        ),
        (
            timedelta(minutes=39),
            "ME-10",
            "NETWORK_CONNECTION",
            "DoLogin",
            {
                "url_path": "/login",
                "http_method": "POST",
                "connection_result": "HTTP_200",
                "destination_port": "8888",
            },
            8,
            launch_a,
        ),
        (
            timedelta(minutes=35),
            "ME-09",
            "ANDROID_COMPONENT_INVOCATION",
            "PostLogin",
            {"auth_state": "AUTHENTICATED"},
            9,
            launch_a,
        ),
        (
            timedelta(minutes=30),
            "ME-09",
            "ANDROID_COMPONENT_INVOCATION",
            "DoTransfer",
            {"auth_state": "AUTHENTICATED"},
            10,
            launch_a,
        ),
        (
            timedelta(minutes=28),
            "ME-10",
            "NETWORK_CONNECTION",
            "DoTransfer",
            {
                "url_path": "/dotransfer",
                "http_method": "POST",
                "connection_result": "HTTP_200",
                "destination_port": "8888",
            },
            11,
            launch_a,
        ),
        (
            timedelta(minutes=25),
            "ME-10",
            "NETWORK_CONNECTION",
            "BillPaymentActivity",
            {
                "url_path": "/paybill",
                "http_method": "POST",
                "connection_result": "HTTP_200",
                "destination_port": "8888",
            },
            12,
            launch_a,
        ),
        (
            timedelta(minutes=20),
            "ME-11",
            "DEBUGGER_ATTACHMENT",
            "Rasp",
            {"debugger_state": "ATTACHED", "detection_result": "DETECTED"},
            13,
            launch_a,
        ),
        (
            timedelta(minutes=15),
            "ME-09",
            "ANDROID_COMPONENT_INVOCATION",
            "ViewStatement",
            {"auth_state": "AUTHENTICATED"},
            14,
            launch_a,
        ),
        (
            timedelta(minutes=12),
            "ME-08",
            "WEBVIEW_ACTIVITY",
            "ViewStatement",
            {"url": "file:///sdcard/statement.html", "javascript_enabled": True},
            15,
            launch_a,
        ),
        (
            timedelta(minutes=10),
            "ME-15",
            "EMULATOR_ENVIRONMENT_DETECTION",
            "Rasp",
            {"detection_result": "DETECTED"},
            1,
            launch_b,
        ),
        (
            timedelta(minutes=9),
            "ME-13",
            "APPLICATION_INTEGRITY_CHECK",
            "RaspApp",
            {"verification_result": "FAILED"},
            2,
            launch_b,
        ),
        (
            timedelta(minutes=8),
            "ME-09",
            "ANDROID_COMPONENT_INVOCATION",
            "LoginActivity",
            {"auth_state": "ANONYMOUS"},
            3,
            launch_b,
        ),
        (
            timedelta(minutes=6),
            "ME-06",
            "EXTERNAL_INPUT",
            "DoLogin",
            {"login_result": "FAILED", "validation_result": "SUSPICIOUS"},
            4,
            launch_b,
        ),
        (
            timedelta(minutes=5),
            "ME-10",
            "NETWORK_CONNECTION",
            "DoLogin",
            {
                "url_path": "/login",
                "http_method": "POST",
                "connection_result": "HTTP_500",
                "destination_port": "8888",
            },
            5,
            launch_b,
        ),
        (
            timedelta(minutes=3),
            "ME-10",
            "NETWORK_CONNECTION",
            "DepositActivity",
            {
                "url_path": "/deposit",
                "http_method": "POST",
                "connection_result": "HTTP_200",
                "destination_port": "8888",
            },
            6,
            launch_b,
        ),
        (
            timedelta(minutes=2),
            "ME-09",
            "ANDROID_COMPONENT_INVOCATION",
            "AccountDetailsActivity",
            {"auth_state": "AUTHENTICATED"},
            7,
            launch_b,
        ),
        (
            timedelta(minutes=1),
            "ME-14",
            "ROOT_ENVIRONMENT",
            "Rasp",
            {"detection_result": "DETECTED"},
            8,
            launch_b,
        ),
    ]

    events: list[RaspEvent] = []
    for offset, event_id, event_type, component, data, seq, launch_id in samples:
        events.append(
            RaspEvent(
                event_id=event_id,
                event_type=event_type,
                timestamp=_iso(now - offset),
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
        return {"events_created": 0, "alerts_created": 0, "skipped": existing}

    if force:
        db.execute(delete(Alert))
        db.execute(delete(Event))
        db.commit()

    now = datetime.now(timezone.utc)
    created_events = 0
    created_alerts = 0

    for payload in _build_demo_events(now):
        row = Event(
            event_id=payload.event_id,
            event_type=payload.event_type,
            timestamp=payload.timestamp,
            component=payload.component,
            data=payload.data or {},
            seq=payload.seq,
            launch_id=payload.launch_id or "",
            received_at=datetime.fromisoformat(payload.timestamp.replace("Z", "+00:00")),
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
                    created_at=row.received_at,
                )
            )
            created_alerts += 1

    db.commit()
    return {
        "events_created": created_events,
        "alerts_created": created_alerts,
        "skipped": 0,
    }
