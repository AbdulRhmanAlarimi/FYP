from fastapi import APIRouter

router = APIRouter(tags=["events"])


@router.get("/events")
def list_events_placeholder():
    """Placeholder until persistence is wired."""
    return []


@router.post("/events")
def receive_event_placeholder(payload: dict):
    """Placeholder — Android POSTs here; persistence comes next."""
    return {"action": "allow", "received": payload.get("event_type")}
