"""Demo data endpoint for empty Grafana panels."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.seed import seed_demo_data

router = APIRouter(prefix="/api", tags=["seed"])


@router.post("/seed")
def seed(
    force: bool = Query(
        default=False,
        description="Wipe existing events/alerts and reload demo data",
    ),
    db: Session = Depends(get_db),
) -> dict[str, int]:
    return seed_demo_data(db, force=force)
