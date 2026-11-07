"""Pydantic schemas matching the Android RASP webhook envelope."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RaspEvent(BaseModel):
    event_id: str
    event_type: str
    timestamp: str
    component: str
    data: dict[str, Any] = Field(default_factory=dict)
    seq: int = 0
    launch_id: str = ""


class HealthResponse(BaseModel):
    status: str
