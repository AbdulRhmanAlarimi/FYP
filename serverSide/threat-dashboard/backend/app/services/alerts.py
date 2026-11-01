from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Alert
from app.schemas import (
    AlertCreate,
    AlertStats,
    NamedCount,
    RaspEvent,
    TimelinePoint,
)
from app.services.classify import ThreatMatch, classify_rasp_event


def create_alert_from_rasp(
    db: Session,
    event: RaspEvent,
    match: ThreatMatch,
) -> Alert:
    alert = Alert(
        source="rasp",
        severity=match.severity,
        title=match.title,
        event_id=event.event_id,
        event_type=event.event_type,
        component=event.component,
        timestamp=event.timestamp,
        payload={
            "event_id": event.event_id,
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "component": event.component,
            "data": event.data,
        },
        status="open",
        reason=match.reason,
    )
    db.add(alert)
    return alert


def maybe_create_rasp_alert(db: Session, event: RaspEvent) -> Optional[Alert]:
    match = classify_rasp_event(event)
    if match is None:
        return None
    return create_alert_from_rasp(db, event, match)


def create_ml_alert(db: Session, body: AlertCreate) -> Alert:
    alert = Alert(
        source="ml",
        severity=body.severity,
        title=body.title,
        event_id=body.event_id,
        event_type=body.event_type,
        component=body.component,
        timestamp=body.timestamp,
        payload=body.payload,
        status="open",
        reason=body.reason or "ML model flagged this activity",
    )
    db.add(alert)
    return alert


def list_alerts(
    db: Session,
    *,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Alert], int]:
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)

    filters = []
    if source:
        filters.append(Alert.source == source)
    if severity:
        filters.append(Alert.severity == severity)
    if status:
        filters.append(Alert.status == status)

    count_stmt = select(func.count()).select_from(Alert)
    list_stmt = select(Alert).order_by(Alert.id.desc()).limit(limit).offset(offset)

    if filters:
        count_stmt = count_stmt.where(*filters)
        list_stmt = list_stmt.where(*filters)

    total = int(db.scalar(count_stmt) or 0)
    items = list(db.scalars(list_stmt).all())
    return items, total


def get_alert(db: Session, alert_id: int) -> Optional[Alert]:
    return db.get(Alert, alert_id)


def update_alert_status(db: Session, alert: Alert, status: str) -> Alert:
    alert.status = status
    db.add(alert)
    return alert


def _count_by(db: Session, column) -> list[NamedCount]:
    rows = db.execute(
        select(column, func.count())
        .where(column.is_not(None))
        .group_by(column)
        .order_by(func.count().desc())
    ).all()
    return [NamedCount(name=str(name), count=int(count)) for name, count in rows if name]


def get_alert_stats(db: Session, *, days: int = 14) -> AlertStats:
    days = min(max(days, 1), 90)
    total = int(db.scalar(select(func.count()).select_from(Alert)) or 0)
    open_count = int(
        db.scalar(select(func.count()).select_from(Alert).where(Alert.status == "open")) or 0
    )
    acked_count = int(
        db.scalar(select(func.count()).select_from(Alert).where(Alert.status == "acked")) or 0
    )
    critical_open = int(
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.status == "open", Alert.severity == "critical")
        )
        or 0
    )

    top_event_types = _count_by(db, Alert.event_type)[:8]

    since = datetime.now(timezone.utc) - timedelta(days=days - 1)
    # SQLite-friendly day buckets from created_at
    day_expr = func.strftime("%Y-%m-%d", Alert.created_at)
    timeline_rows = db.execute(
        select(day_expr, func.count())
        .where(Alert.created_at >= since)
        .group_by(day_expr)
        .order_by(day_expr.asc())
    ).all()
    counts = {str(day): int(count) for day, count in timeline_rows if day}

    timeline: list[TimelinePoint] = []
    for offset in range(days):
        day = (since + timedelta(days=offset)).date().isoformat()
        timeline.append(TimelinePoint(date=day, count=counts.get(day, 0)))

    return AlertStats(
        total=total,
        open=open_count,
        acked=acked_count,
        critical_open=critical_open,
        by_severity=_count_by(db, Alert.severity),
        by_source=_count_by(db, Alert.source),
        by_status=_count_by(db, Alert.status),
        top_event_types=top_event_types,
        timeline=timeline,
    )
