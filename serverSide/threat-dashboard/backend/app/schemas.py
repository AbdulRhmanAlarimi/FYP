from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class RaspEvent(BaseModel):
    event_id: str
    event_type: str
    timestamp: str
    component: str
    data: dict[str, Any] = Field(default_factory=dict)


class EventActionResponse(BaseModel):
    action: Literal["allow"] = "allow"


class EventOut(BaseModel):
    id: int
    event_id: str
    event_type: str
    timestamp: str
    component: str
    data: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertCreate(BaseModel):
    """Ingest path for future ML alerts (does not touch the ML/ folder)."""

    title: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    event_id: Optional[str] = None
    event_type: Optional[str] = None
    component: Optional[str] = None
    timestamp: Optional[str] = None
    payload: dict[str, Any] = Field(default_factory=dict)
    reason: Optional[str] = None


class AlertOut(BaseModel):
    id: int
    source: str
    severity: str
    title: str
    event_id: Optional[str]
    event_type: Optional[str]
    component: Optional[str]
    timestamp: Optional[str]
    payload: dict[str, Any]
    status: str
    reason: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertStatusUpdate(BaseModel):
    status: Literal["open", "acked"]


class AlertListResponse(BaseModel):
    items: list[AlertOut]
    total: int
    limit: int
    offset: int
