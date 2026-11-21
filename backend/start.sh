#!/usr/bin/env bash
# Start FastAPI + Postgres, then Grafana and/or Splunk for the RASP SIEM stack.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

SPLUNK_HEC_TOKEN_DEFAULT="11111111-1111-1111-1111-111111111111"
SPLUNK_PASSWORD_DEFAULT="Chang3d!Rasp"

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

usage() {
  cat <<EOF
Usage: ./start.sh [grafana|splunk|both]

  grafana  API + Postgres + Grafana (:3000)
  splunk   API + Postgres + Splunk Web (:8001) + HEC (:8088)
  both     API + Postgres + Grafana + Splunk

If no argument is given, you will be prompted to choose.
EOF
}

choose_mode() {
  if [[ -n "${1:-}" ]]; then
    case "$1" in
      -h|--help|help) usage; exit 0 ;;
      grafana|splunk|both) echo "$1"; return ;;
      *)
        echo "error: unknown mode '$1'" >&2
        usage >&2
        exit 1
        ;;
    esac
  fi

  if [[ ! -t 0 ]]; then
    echo "error: no mode given and stdin is not a TTY; pass grafana|splunk|both" >&2
    exit 1
  fi

  echo "Select SIEM frontend:"
  echo "  1) Grafana"
  echo "  2) Splunk"
  echo "  3) Both"
  read -r -p "Choice [1/2/3]: " choice
  case "$choice" in
    1|grafana|Grafana) echo "grafana" ;;
    2|splunk|Splunk) echo "splunk" ;;
    3|both|Both) echo "both" ;;
    *)
      echo "error: invalid choice '$choice'" >&2
      exit 1
      ;;
  esac
}

MODE="$(choose_mode "${1:-}")"
PROFILES=()
USE_GRAFANA=0
USE_SPLUNK=0

case "$MODE" in
  grafana)
    PROFILES=(--profile grafana)
    USE_GRAFANA=1
    ;;
  splunk)
    PROFILES=(--profile splunk)
    USE_SPLUNK=1
    ;;
  both)
    PROFILES=(--profile grafana --profile splunk)
    USE_GRAFANA=1
    USE_SPLUNK=1
    ;;
esac

export SPLUNK_HEC_URL=""
export SPLUNK_HEC_TOKEN=""
export SPLUNK_HEC_INDEX="rasp"
export SPLUNK_HEC_SOURCE="rasp_webhook"
export SPLUNK_HEC_SOURCETYPE="rasp:json"
export SPLUNK_HEC_VERIFY_SSL="false"

if [[ "$USE_SPLUNK" -eq 1 ]]; then
  # From the API container, Splunk is reachable on the compose network hostname.
  export SPLUNK_HEC_URL="https://splunk:8088"
  export SPLUNK_HEC_TOKEN="$SPLUNK_HEC_TOKEN_DEFAULT"
fi

echo "==> Mode: ${MODE}"
echo "==> Building and starting services..."
"${COMPOSE[@]}" "${PROFILES[@]}" up --build -d

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

if [[ "$USE_SPLUNK" -eq 1 ]]; then
  echo "==> Waiting for Splunk HEC (first boot can take a few minutes)..."
  for _ in $(seq 1 90); do
    if curl -fk -sS "https://127.0.0.1:8088/services/collector/health" >/dev/null 2>&1; then
      break
    fi
    sleep 5
  done
  if ! curl -fk -sS "https://127.0.0.1:8088/services/collector/health" >/dev/null 2>&1; then
    echo "warning: Splunk HEC not healthy yet; events will retry once Splunk finishes starting" >&2
  else
    echo "==> Splunk HEC is up"
  fi
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

if [[ -x "$ROOT/scripts/smoke_test.sh" ]]; then
  echo "==> Running smoke tests..."
  if [[ "$USE_SPLUNK" -eq 1 ]]; then
    CHECK_SPLUNK=1 "$ROOT/scripts/smoke_test.sh"
  else
    CHECK_SPLUNK=0 "$ROOT/scripts/smoke_test.sh"
  fi
fi

echo
echo "RASP SIEM stack is up (mode: ${MODE})."

echo
echo "  API docs:   http://127.0.0.1:8000/docs"
echo "  Health:     http://127.0.0.1:8000/health"
echo "  SIEM health:http://127.0.0.1:8000/health/siem"

if [[ "$USE_GRAFANA" -eq 1 ]]; then
  echo "  Grafana:    http://127.0.0.1:3000  (admin / admin)"
  echo "  Dashboard:  RASP SIEM Overview (folder: RASP)"
fi

if [[ "$USE_SPLUNK" -eq 1 ]]; then
  echo "  Splunk Web: http://127.0.0.1:8001  (admin / ${SPLUNK_PASSWORD_DEFAULT})"
  echo "  HEC:        https://127.0.0.1:8088"
  echo "  Search:     index=rasp sourcetype=rasp:json"
fi

cat <<EOF

Android emulator webhook (unchanged):
  POST http://10.0.2.2:8000/events

Force reseed:
  curl -X POST 'http://127.0.0.1:8000/api/seed?force=true'

Stop:
  cd $ROOT && ${COMPOSE[*]} --profile grafana --profile splunk down

EOF
