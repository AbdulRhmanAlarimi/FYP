"""Android-compatible RASP webhook endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Alert, Event
from app.schemas import RaspEvent
from app.services.classify import classify_rasp_event

router = APIRouter(tags=["events"])


@router.post("/events")
def receive_event(payload: RaspEvent, db: Session = Depends(get_db)) -> dict[str, str]:
    """Persist a RASP event and create an alert when a risk signal is present."""
    row = Event(
        event_id=payload.event_id,
        event_type=payload.event_type,
        timestamp=payload.timestamp,
        component=payload.component,
        data=payload.data or {},
        seq=payload.seq,
        launch_id=payload.launch_id or "",
    )
    db.add(row)
    db.flush()

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
            )
        )

    db.commit()
    return {"action": "allow"}



@router.get("/events")
def list_events(
    db: Session = Depends(get_db),
    limit: int = Query(default=5000, ge=1, le=10000),
) -> list[dict]:
    """Return newest events first (ML collector compatible)."""
    stmt = select(Event).order_by(Event.id.desc()).limit(limit)
    rows = db.scalars(stmt).all()
    return [
        {
            "event_id": row.event_id,
            "event_type": row.event_type,
            "timestamp": row.timestamp,
            "component": row.component,
            "data": row.data,
            "seq": row.seq,
            "launch_id": row.launch_id,
        }
        for row in rows
    ]
