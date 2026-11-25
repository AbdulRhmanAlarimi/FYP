"""FastAPI entrypoint for the RASP webhook API."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import init_db
from app.routers import events, health, integrity, seed
from app.services.seed import ensure_sample_data

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    try:
        ensure_sample_data()
    except Exception:
        # Keep /health up even if demo seed fails (schema drift, HEC, etc.).
        logger.exception("Sample data seed failed during startup")
    yield



app = FastAPI(
    title="RASP Grafana Backend",
    description="Receives Android RASP webhook events and persists them for Grafana.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(health.router)
app.include_router(events.router)
app.include_router(seed.router)
app.include_router(integrity.router)

