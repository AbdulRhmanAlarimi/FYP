"""Database engine and session helpers."""

from __future__ import annotations

import logging
import os
from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://rasp:rasp@localhost:5432/rasp",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _drop_alerts_event_pk_unique() -> None:
    """v2 allows multiple alerts per event; older DBs still have UNIQUE(event_pk).

    create_all() does not drop constraints, so seed/correlate crashes until this runs.
    """
    if engine.dialect.name != "postgresql":
        return
    with engine.begin() as conn:
        constraints = conn.execute(
            text(
                """
                SELECT c.conname
                FROM pg_constraint c
                JOIN pg_class t ON c.conrelid = t.oid
                WHERE t.relname = 'alerts'
                  AND c.contype = 'u'
                  AND pg_get_constraintdef(c.oid) ILIKE '%event_pk%'
                """
            )
        ).fetchall()
        for (name,) in constraints:
            logger.info("Dropping obsolete unique constraint alerts.%s", name)
            conn.execute(text(f'ALTER TABLE alerts DROP CONSTRAINT IF EXISTS "{name}"'))

        indexes = conn.execute(
            text(
                """
                SELECT indexname
                FROM pg_indexes
                WHERE tablename = 'alerts'
                  AND indexdef ILIKE '%UNIQUE%'
                  AND indexdef ILIKE '%event_pk%'
                """
            )
        ).fetchall()
        for (name,) in indexes:
            logger.info("Dropping obsolete unique index %s", name)
            conn.execute(text(f'DROP INDEX IF EXISTS "{name}"'))


def init_db() -> None:
    from app import models  # noqa: F401 — register models

    Base.metadata.create_all(bind=engine)
    try:
        _drop_alerts_event_pk_unique()
    except Exception:
        logger.exception("Failed to migrate alerts.event_pk unique constraint")
