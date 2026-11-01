from fastapi import APIRouter

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts")
def list_alerts_placeholder():
    """Placeholder until alerts API is implemented."""
    return {"items": [], "total": 0}
