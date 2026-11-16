#!/usr/bin/env bash
# Start FastAPI + Postgres + Grafana for the RASP SIEM stack.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required" >&2
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "error: docker compose is required" >&2
  exit 1
fi

echo "==> Building and starting API, Postgres, and Grafana..."
"${COMPOSE[@]}" up --build -d

echo "==> Waiting for API health..."
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:8000/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

if ! curl -fsS "http://127.0.0.1:8000/health" >/dev/null 2>&1; then
  echo "error: API did not become healthy in time" >&2
  "${COMPOSE[@]}" ps
  exit 1
fi

echo "==> Loading sample RASP events into Postgres (force refresh)..."
SEED_RESULT="$(curl -fsS -X POST "http://127.0.0.1:8000/api/seed?force=true")"
echo "$SEED_RESULT"
EVENT_COUNT="$(curl -fsS "http://127.0.0.1:8000/events" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)"
echo "==> Events now in API: ${EVENT_COUNT}"
if [[ "${EVENT_COUNT}" -lt 1 ]]; then
  echo "error: sample data was not loaded" >&2
  exit 1
fi


cat <<EOF

RASP SIEM stack is up.

  API docs:   http://127.0.0.1:8000/docs
  Health:     http://127.0.0.1:8000/health
  Grafana:    http://127.0.0.1:3000  (admin / admin)
  Dashboard:  RASP SIEM Overview (folder: RASP)

Android emulator webhook (unchanged):
  POST http://10.0.2.2:8000/events

Force reseed:
  curl -X POST 'http://127.0.0.1:8000/api/seed?force=true'

Stop:
  cd $ROOT && ${COMPOSE[*]} down

EOF
