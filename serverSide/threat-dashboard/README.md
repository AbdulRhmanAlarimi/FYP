# Threat Alert Dashboard

FastAPI backend + React/MUI frontend for RASP (and future ML) threat alerts.

The Android emulator already posts RASP events to `http://10.0.2.2:8000/events`. Run **this** backend on port `8000` instead of `serverSide/testHook` so events are persisted and classified.

## Layout

```text
threat-dashboard/
  backend/     FastAPI + SQLite (alerts.db)
  frontend/    Vite + React + TypeScript + MUI
```

## Local run (no Docker)

### 1. Backend

```powershell
cd serverSide/threat-dashboard/backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

- OpenAPI docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/health

Use `0.0.0.0` so the Android emulator can reach the host via `10.0.2.2`.

### 2. Frontend

```powershell
cd serverSide/threat-dashboard/frontend
npm install
npm run dev
```

Dashboard: http://127.0.0.1:5173

Vite proxies `/api` (and related paths) to the backend on `:8000`.

### 3. Emulator

1. Start the backend on `:8000`.
2. Launch the InsecureBankv2 app in the emulator.
3. Trigger RASP signals (debugger attach, root/emulator detection, suspicious login input, etc.).
4. Open the dashboard — RASP threats show with source `RASP`.

Benign monitoring events are still stored under `GET /events`, but only risk signals become alerts.

### ML alerts (later)

Do not change the `ML/` folder for this feature. When a model exists, post alerts to:

`POST /api/alerts`

Example:

```json
{
  "title": "Anomalous transfer pattern",
  "severity": "high",
  "event_type": "ML_BEHAVIOR",
  "reason": "score above threshold",
  "payload": { "score": 0.91 }
}
```

## API summary

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/events` | Android RASP webhook (returns `{"action":"allow"}`) |
| GET | `/events` | Raw stored events |
| GET | `/api/alerts` | List threats (`source`, `severity`, `status` filters) |
| POST | `/api/alerts` | Ingest ML (or manual) alert |
| GET | `/api/alerts/{id}` | Alert detail |
| PATCH | `/api/alerts/{id}` | Acknowledge (`{"status":"acked"}`) |

## Theme

The UI follows the OS preference (`prefers-color-scheme`) for light/dark mode via MUI.
