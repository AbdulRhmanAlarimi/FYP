"""Insert demo alerts so the SIEM charts have something to show."""

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models import Alert, Event


def _utc_days_ago(days: int, hour: int = 12) -> datetime:
    base = datetime.now(timezone.utc) - timedelta(days=days)
    return base.replace(hour=hour, minute=15, second=0, microsecond=0)


SEED_ALERTS: list[dict[str, Any]] = [
    {
        "source": "rasp",
        "severity": "critical",
        "title": "Debugger attached",
        "event_id": "ME-11",
        "event_type": "DEBUGGER_ATTACHMENT",
        "component": "Rasp",
        "days_ago": 0,
        "status": "open",
        "reason": "detection_result=DETECTED (demo)",
    },
    {
        "source": "rasp",
        "severity": "critical",
        "title": "Integrity failure: APPLICATION_INTEGRITY_CHECK",
        "event_id": "ME-13",
        "event_type": "APPLICATION_INTEGRITY_CHECK",
        "component": "RaspApp",
        "days_ago": 1,
        "status": "open",
        "reason": "verification_result=FAILED (demo)",
    },
    {
        "source": "rasp",
        "severity": "high",
        "title": "RASP threat: ROOT_ENVIRONMENT",
        "event_id": "ME-14",
        "event_type": "ROOT_ENVIRONMENT",
        "component": "Rasp",
        "days_ago": 1,
        "status": "open",
        "reason": "detection_result=DETECTED (demo)",
    },
    {
        "source": "rasp",
        "severity": "medium",
        "title": "Suspicious input: EXTERNAL_INPUT",
        "event_id": "ME-06",
        "event_type": "EXTERNAL_INPUT",
        "component": "DoLogin",
        "days_ago": 2,
        "status": "acked",
        "reason": "validation_result=SUSPICIOUS (demo)",
    },
    {
        "source": "rasp",
        "severity": "medium",
        "title": "RASP threat: EMULATOR_ENVIRONMENT_DETECTION",
        "event_id": "ME-15",
        "event_type": "EMULATOR_ENVIRONMENT_DETECTION",
        "component": "Rasp",
        "days_ago": 3,
        "status": "open",
        "reason": "detection_result=DETECTED (demo)",
    },
    {
        "source": "rasp",
        "severity": "high",
        "title": "RASP threat: DEBUGGER_ATTACHMENT",
        "event_id": "ME-11",
        "event_type": "DEBUGGER_ATTACHMENT",
        "component": "Rasp",
        "days_ago": 4,
        "status": "acked",
        "reason": "detection_result=DETECTED (demo)",
    },
    {
        "source": "ml",
        "severity": "high",
        "title": "Anomalous transfer pattern",
        "event_id": None,
        "event_type": "ML_BEHAVIOR",
        "component": "future-ml",
        "days_ago": 0,
        "status": "open",
        "reason": "score above threshold (demo)",
        "payload": {"score": 0.93},
    },
    {
        "source": "ml",
        "severity": "medium",
        "title": "Unusual login velocity",
        "event_id": None,
        "event_type": "ML_BEHAVIOR",
        "component": "future-ml",
        "days_ago": 2,
        "status": "open",
        "reason": "burst of login attempts (demo)",
        "payload": {"score": 0.77},
    },
    {
        "source": "ml",
        "severity": "low",
        "title": "Mild session anomaly",
        "event_id": None,
        "event_type": "ML_SESSION",
        "component": "future-ml",
        "days_ago": 5,
        "status": "acked",
        "reason": "low-confidence anomaly (demo)",
        "payload": {"score": 0.55},
    },
    {
        "source": "rasp",
        "severity": "critical",
        "title": "RASP threat: ROOT_ENVIRONMENT",
        "event_id": "ME-14",
        "event_type": "ROOT_ENVIRONMENT",
        "component": "Rasp",
        "days_ago": 6,
        "status": "acked",
        "reason": "detection_result=DETECTED (demo)",
    },
    {
        "source": "rasp",
        "severity": "high",
        "title": "RASP threat: DEBUGGER_ATTACHMENT",
        "event_id": "ME-11",
        "event_type": "DEBUGGER_ATTACHMENT",
        "component": "Rasp",
        "days_ago": 7,
        "status": "open",
        "reason": "detection_result=DETECTED (demo)",
    },
    {
        "source": "rasp",
        "severity": "medium",
        "title": "Suspicious input: EXTERNAL_INPUT",
        "event_id": "ME-06",
        "event_type": "EXTERNAL_INPUT",
        "component": "DoLogin",
        "days_ago": 8,
        "status": "open",
        "reason": "validation_result=SUSPICIOUS (demo)",
    },
]


def seed_demo_alerts(db: Session, *, force: bool = False) -> dict[str, int]:
    existing = int(db.scalar(select(func.count()).select_from(Alert)) or 0)
    if existing > 0 and not force:
        return {"created": 0, "skipped": existing, "forced": 0}

    if force and existing > 0:
        db.execute(delete(Alert))
        db.execute(delete(Event))
        db.commit()

    created = 0
    for item in SEED_ALERTS:
        created_at = _utc_days_ago(int(item["days_ago"]))
        ts = created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        payload = item.get("payload") or {
            "event_id": item["event_id"],
            "event_type": item["event_type"],
            "timestamp": ts,
            "component": item["component"],
            "data": {"demo": True},
        }
        alert = Alert(
            source=item["source"],
            severity=item["severity"],
            title=item["title"],
            event_id=item["event_id"],
            event_type=item["event_type"],
            component=item["component"],
            timestamp=ts,
            payload=payload,
            status=item["status"],
            reason=item["reason"],
            created_at=created_at,
        )
        db.add(alert)
        created += 1

    db.commit()
    return {"created": created, "skipped": 0, "forced": int(force)}
