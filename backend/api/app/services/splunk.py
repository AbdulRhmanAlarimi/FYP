"""Optional forward of RASP events to Splunk HTTP Event Collector (HEC)."""

from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.error
import urllib.request
from typing import Any, Optional

from app.schemas import RaspEvent

logger = logging.getLogger(__name__)


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def splunk_enabled() -> bool:
    return bool(os.getenv("SPLUNK_HEC_URL", "").strip() and os.getenv("SPLUNK_HEC_TOKEN", "").strip())


def _hec_endpoint() -> str:
    base = os.getenv("SPLUNK_HEC_URL", "").rstrip("/")
    if base.endswith("/services/collector") or base.endswith("/services/collector/event"):
        return base
    return f"{base}/services/collector/event"


def build_hec_payload(
    event: RaspEvent,
    *,
    alert: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "timestamp": event.timestamp,
        "component": event.component,
        "data": event.data or {},
        "seq": event.seq,
        "launch_id": event.launch_id,
    }
    if alert:
        body["alert"] = alert

    return {
        "sourcetype": os.getenv("SPLUNK_HEC_SOURCETYPE", "rasp:json"),
        "source": os.getenv("SPLUNK_HEC_SOURCE", "rasp_webhook"),
        "index": os.getenv("SPLUNK_HEC_INDEX", "rasp"),
        "event": body,
    }


def send_to_splunk(
    event: RaspEvent,
    *,
    alert: Optional[dict[str, Any]] = None,
) -> bool:
    """POST one event to Splunk HEC. Failures are logged and do not raise."""
    if not splunk_enabled():
        return False

    token = os.getenv("SPLUNK_HEC_TOKEN", "").strip()
    url = _hec_endpoint()
    payload = build_hec_payload(event, alert=alert)
    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        },
    )

    context: Optional[ssl.SSLContext] = None
    if url.startswith("https://") and not _truthy(os.getenv("SPLUNK_HEC_VERIFY_SSL", "false")):
        context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(request, timeout=5, context=context) as response:
            ok = 200 <= getattr(response, "status", 200) < 300
            if not ok:
                logger.warning("Splunk HEC returned status %s", getattr(response, "status", "?"))
            return ok
    except urllib.error.URLError as exc:
        logger.warning("Splunk HEC unreachable: %s", exc)
        return False
    except Exception as exc:  # noqa: BLE001 — never break the Android webhook path
        logger.warning("Splunk HEC send failed: %s", exc)
        return False
