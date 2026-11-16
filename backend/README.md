# RASP Grafana Backend

FastAPI webhook + Postgres + Grafana SIEM for InsecureBankv2 RASP events (ME-01..ME-15).

All code for this feature lives in this folder. It does **not** change the Android app, ML collector, or `serverSide/testHook`.

## Quick start

```bash
cd backend
./start.sh
```

Requirements: Docker with Compose.

| Service | URL |
|---------|-----|
| API docs | http://127.0.0.1:8000/docs |
| Health | http://127.0.0.1:8000/health |
| Grafana | http://127.0.0.1:3000 (`admin` / `admin`) |

`start.sh` builds containers, waits for health, and force-loads sample RASP events/alerts so Grafana charts are never empty.

The API also auto-seeds on startup whenever the `events` table is empty.


## Android emulator

The app already posts to `http://10.0.2.2:8000/events`. Run **this** stack on host port `8000` (instead of `serverSide/testHook`) so events persist and appear in Grafana.

Response contract is unchanged: `{"action": "allow"}`.

ML collector can still `GET http://127.0.0.1:8000/events`.

## API

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/events` | Ingest RASP webhook; classify risk into `alerts` |
| `GET` | `/events` | List recent events (newest first) |
| `GET` | `/health` | Liveness |
| `POST` | `/api/seed` | Load demo events (`?force=true` to wipe and reload) |
| `GET` | `/api/integrity/trusted-hash` | Official APK SHA-256 for on-device AS09 |
| `PUT` | `/api/integrity/trusted-hash` | Set official APK SHA-256 (`{"sha256":"<64 hex>"}`) |

### AS09 trusted APK hash

The official APK hash must **not** be embedded in the APK (that would change the hash).
Store it in Postgres via the API after you build:

```bash
# after assembling the APK
sha256sum Android-InsecureBankv2-master/InsecureBankv2/app/build/outputs/apk/debug/app-debug.apk

curl -X PUT http://127.0.0.1:8000/api/integrity/trusted-hash \
  -H 'Content-Type: application/json' \
  -d '{"sha256":"<paste 64-char hex here>"}'
```

On launch, `AS09IntegrityRule` fetches that baseline and compares it to the installed APK.
Mismatch → ME-13 with `verification_result=FAILED` and a RULE alert in Grafana.

## Grafana dashboard

Provisioned dashboard **RASP SIEM Overview** (folder `RASP`) includes:

- KPI stats: event count, critical alerts, failed logins, env detections, HTTP errors, launches
- Time series: event rate by type, env threats, alerts by severity
- Donut: alert severity mix
- Bars: top banking API paths (ME-10), hottest screens (ME-09)
- Table: latest alerts (secondary detail)

Anonymous Viewer access is enabled for local demos.

## Layout

```text
backend/
  start.sh
  docker-compose.yml
  PLAN.md
  api/                 FastAPI + SQLAlchemy
  grafana/             provisioning + dashboard JSON
```

## Stop

```bash
cd backend
docker compose down
```

Add `-v` to also wipe Postgres/Grafana volumes.
