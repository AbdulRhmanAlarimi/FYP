# RASP SIEM Backend

FastAPI webhook + Postgres for InsecureBankv2 RASP events (ME-01..ME-15), with optional **Grafana** and/or **Splunk** frontends.

All code for this feature lives in this folder. It does **not** change the Android app, ML collector, or `serverSide/testHook`.

## Quick start

```bash
cd backend
./start.sh
```

You will be asked which SIEM to run:

| Choice | What starts |
|--------|-------------|
| `grafana` | API + Postgres + Grafana |
| `splunk` | API + Postgres + Splunk |
| `both` | API + Postgres + Grafana + Splunk |

Non-interactive:

```bash
./start.sh grafana
./start.sh splunk
./start.sh both
```

Requirements: Docker with Compose.

| Service | URL | Creds |
|---------|-----|-------|
| API docs | http://127.0.0.1:8000/docs | — |
| Health | http://127.0.0.1:8000/health | — |
| SIEM config | http://127.0.0.1:8000/health/siem | — |
| Grafana | http://127.0.0.1:3000 | `admin` / `admin` |
| Splunk Web | http://127.0.0.1:8001 | `admin` / `Chang3d!Rasp` |
| Splunk HEC | https://127.0.0.1:8088 | token below |

`start.sh` builds containers, waits for health, and force-loads sample RASP events/alerts so dashboards are never empty.

The API also auto-seeds on startup whenever the `events` table is empty.

## Android emulator

The app already posts to `http://10.0.2.2:8000/events`. Run **this** stack on host port `8000` (instead of `serverSide/testHook`) so events persist and appear in Grafana and/or Splunk.

Response contract is unchanged: `{"action": "allow"}`.

ML collector can still `GET http://127.0.0.1:8000/events`.

## API

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/events` | Ingest RASP webhook; classify risk into `alerts`; forward to Splunk HEC when enabled |
| `GET` | `/events` | List recent events (newest first) |
| `GET` | `/health` | Liveness |
| `GET` | `/health/siem` | Whether Splunk HEC forwarding is configured |
| `POST` | `/api/seed` | Load demo events (`?force=true` to wipe and reload) |

## Grafana dashboard

Provisioned dashboard **RASP SIEM Overview** (folder `RASP`) includes:

- KPI stats: event count, critical alerts, failed logins, env detections, HTTP errors, launches
- Time series: event rate by type, env threats, alerts by severity
- Donut: alert severity mix
- Bars: top banking API paths (ME-10), hottest screens (ME-09)
- Table: latest alerts (secondary detail)

Anonymous Viewer access is enabled for local demos.

## Splunk

When you start with `splunk` or `both`, the API forwards each live webhook event to Splunk **HEC**.

| Setting | Value |
|---------|-------|
| Web UI | http://127.0.0.1:8001 |
| Username | `admin` |
| Password | `Chang3d!Rasp` |
| HEC token | `11111111-1111-1111-1111-111111111111` |
| Index | `rasp` |
| Sourcetype | `rasp:json` |

Example search in Splunk:

```text
index=rasp sourcetype=rasp:json
| stats count by event_type
```

Threats that were classified also include an `alert` object (severity, title, reason).

First Splunk boot can take several minutes while it accepts the license and starts HEC.

## Layout

```text
backend/
  start.sh              # choose grafana | splunk | both
  docker-compose.yml    # profiles: grafana, splunk
  PLAN.md
  api/                  # FastAPI + SQLAlchemy + optional HEC forward
  grafana/              # provisioning + dashboard JSON
  splunk/               # default.yml (HEC + rasp index)
```

## Stop

```bash
cd backend
docker compose --profile grafana --profile splunk down
```

Add `-v` to also wipe Postgres / Grafana / Splunk volumes.
