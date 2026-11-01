from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.schemas import (
    AlertCreate,
    AlertListResponse,
    AlertOut,
    AlertStatusUpdate,
)
from app.services import alerts as alerts_service

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts", response_model=AlertListResponse)
def list_alerts(
    source: Optional[Literal["rasp", "ml"]] = Query(default=None),
    severity: Optional[Literal["low", "medium", "high", "critical"]] = Query(default=None),
    status: Optional[Literal["open", "acked"]] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    items, total = alerts_service.list_alerts(
        db,
        source=source,
        severity=severity,
        status=status,
        limit=limit,
        offset=offset,
    )
    return AlertListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = alerts_service.get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/alerts", response_model=AlertOut, status_code=201)
def create_ml_alert(body: AlertCreate, db: Session = Depends(get_db)):
    """Ingest path for future ML threats — does not modify the ML/ tree."""
    alert = alerts_service.create_ml_alert(db, body)
    db.commit()
    db.refresh(alert)
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
def update_alert_status(
    alert_id: int,
    body: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    alert = alerts_service.get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alerts_service.update_alert_status(db, alert, body.status)
    db.commit()
    db.refresh(alert)
    return alert
