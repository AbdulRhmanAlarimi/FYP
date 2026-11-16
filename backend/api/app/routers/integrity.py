"""Official APK integrity baseline for on-device AS09 checks."""

from __future__ import annotations

import os
import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import IntegrityBaseline
from app.schemas import TrustedHashResponse, TrustedHashUpdate

router = APIRouter(prefix="/api/integrity", tags=["integrity"])

_SHA256_HEX = re.compile(r"^[0-9a-fA-F]{64}$")
_BASELINE_ID = 1


def _get_or_create(db: Session) -> IntegrityBaseline:
    row = db.get(IntegrityBaseline, _BASELINE_ID)
    if row is not None:
        return row
    env_hash = (os.getenv("TRUSTED_APK_SHA256") or "").strip().lower()
    row = IntegrityBaseline(id=_BASELINE_ID, trusted_apk_sha256=env_hash)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.get("/trusted-hash", response_model=TrustedHashResponse)
def get_trusted_hash(db: Session = Depends(get_db)) -> TrustedHashResponse:
    """Phone AS09 fetches the official APK SHA-256 from here (not embedded in the APK)."""
    row = _get_or_create(db)
    return TrustedHashResponse(sha256=row.trusted_apk_sha256 or "")


@router.put("/trusted-hash", response_model=TrustedHashResponse)
def put_trusted_hash(
    payload: TrustedHashUpdate,
    db: Session = Depends(get_db),
) -> TrustedHashResponse:
    """Set/replace the official APK hash after building a release APK."""
    value = payload.sha256.strip().lower()
    if not _SHA256_HEX.match(value):
        raise HTTPException(status_code=400, detail="sha256 must be 64 hex characters")
    row = _get_or_create(db)
    row.trusted_apk_sha256 = value
    db.commit()
    db.refresh(row)
    return TrustedHashResponse(sha256=row.trusted_apk_sha256)
