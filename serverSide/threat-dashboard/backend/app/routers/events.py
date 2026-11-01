from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Event
from app.schemas import EventActionResponse, EventOut, RaspEvent

router = APIRouter(tags=["events"])


@router.post("/events", response_model=EventActionResponse)
def receive_event(event: RaspEvent, db: Session = Depends(get_db)):
    row = Event(
        event_id=event.event_id,
        event_type=event.event_type,
        timestamp=event.timestamp,
        component=event.component,
        data=event.data,
    )
    db.add(row)
    db.commit()
    return EventActionResponse()


@router.get("/events", response_model=list[EventOut])
def list_events(limit: int = 100, offset: int = 0, db: Session = Depends(get_db)):
    limit = min(max(limit, 1), 500)
    offset = max(offset, 0)
    stmt = (
        select(Event)
        .order_by(Event.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(db.scalars(stmt).all())
