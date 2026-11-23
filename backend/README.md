# RASP SIEM Backend

FastAPI webhook + Postgres for InsecureBankv2 RASP events (ME-01..ME-15), with optional **Grafana** and/or **Splunk** frontends.

All code for this feature lives in this folder. It does **not** change the Android app, ML collector, or `serverSide/testHook`.

## Quick start

A mode argument is **required**:

```bash
cd backend
./start.sh grafana   # API + Postgres + Grafana
./start.sh splunk    # API + Postgres + Splunk
./start.sh both      # API + Postgres + Grafana + Splunk
```

```bash
./start.sh --help
```

Requirements: Docker with Compose.

`start.sh` builds containers, waits for health, force-loads sample RASP events, runs smoke tests, and prints URLs **only for the mode you started**.

The API also auto-seeds on startup whenever the `events` table is empty.

### grafana

| Service | URL | Creds |
|---------|-----|-------|
| API docs | http://127.0.0.1:8000/docs | — |
| Grafana | http://127.0.0.1:3000 | `admin` / `admin` |

### splunk

| Service | URL | Creds |
|---------|-----|-------|
| API docs | http://127.0.0.1:8000/docs | — |
| Splunk Web | http://127.0.0.1:8001 | `admin` / `Chang3d!Rasp` |
| Splunk HEC | http://127.0.0.1:8088 | token below |

Open the **RASP SIEM** app (left Apps menu), or go directly to:

http://127.0.0.1:8001/en-US/app/rasp_siem/rasp_overview

The default Splunk “Home” page can look empty — that is normal. Use the **RASP SIEM** app or **Search & Reporting**.

### both

Starts Grafana and Splunk together (URLs/creds as above).

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

## Splunk

When you start with `./start.sh splunk` or `./start.sh both`, the API forwards each live webhook event **and** seeded demo events to Splunk **HEC**. A provisioned **RASP SIEM** app includes charts (not just the empty Home page).

| Setting | Value |
|---------|-------|
| Web UI | http://127.0.0.1:8001 |
| Username | `admin` |
| Password | `Chang3d!Rasp` |
| HEC token | `11111111-1111-1111-1111-111111111111` |
| Index | `main` |
| Sourcetype | `rasp:json` |
| App / dashboard | `rasp_siem` → **RASP SIEM Overview** |

Example search in **Search & Reporting**:

```text
index=main sourcetype=rasp:json
| stats count by event_type
```

Threats that were classified also include an `alert` object (severity, title, reason).

First Splunk boot can take **several minutes**. `./start.sh splunk` waits for HEC to accept events **before** seeding, so you should see `splunk_forwarded` > 0.

If HEC never becomes ready, gather diagnostics then reset volumes:

```bash
./scripts/splunk_diag.sh
docker compose --profile splunk down -v
./start.sh splunk
```

Notes:
- First Splunk boot can take 5–15 minutes and needs roughly **2GB+ RAM**.
- HEC is **HTTP** on port `8088` (no TLS) for local lab reliability.
- Events go to `index=main` (`sourcetype=rasp:json`).

Manual reseed after Splunk is up:

```bash
curl -X POST 'http://127.0.0.1:8000/api/seed?force=true'
```


## Layout

```text
backend/
  start.sh                 # REQUIRED arg: grafana | splunk | both
  docker-compose.yml       # profiles: grafana, splunk
  PLAN.md
  api/                     # FastAPI + SQLAlchemy + optional HEC forward
  grafana/                 # provisioning + dashboard JSON
  splunk/
    default.yml            # HEC (HTTP) on main index

    apps/rasp_siem/        # Splunk dashboard app
  scripts/smoke_test.sh
```

## Smoke test

```bash
cd backend
./scripts/smoke_test.sh
```

Checks API health, webhook ingest, event listing, and (when HEC is configured) Splunk HEC health + a direct event post. `start.sh` runs this automatically.

## Stop

```bash
cd backend
docker compose --profile grafana --profile splunk down
```

Add `-v` to also wipe Postgres / Grafana / Splunk volumes.
