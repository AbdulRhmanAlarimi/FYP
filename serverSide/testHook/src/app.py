from typing import Any
from fastapi import FastAPI
from pydantic import BaseModel

class RaspEvent(BaseModel):
    event_id: str
    event_type: str
    timestamp: str
    component: str
    data: dict[str, Any]

app = FastAPI()
events = []

@app.post("/events")
def receive(event: RaspEvent):
    print("Got event:", event.event_type, event.data)
    events.append(event)
    return {"action": "allow"}

@app.get("/events")
def show_events():
    return events