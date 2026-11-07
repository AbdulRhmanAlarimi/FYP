"""FastAPI entrypoint for the RASP webhook API."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import init_db
from app.routers import events, health, seed


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
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

