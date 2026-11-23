#!/usr/bin/env bash
# Start FastAPI + Postgres, then Grafana and/or Splunk for the RASP SIEM stack.
# Requires a mode argument: grafana | splunk | both
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
Usage: ./start.sh <grafana|splunk|both>

  grafana   Start API + Postgres + Grafana only
            UI: http://127.0.0.1:3000  (admin / admin)

  splunk    Start API + Postgres + Splunk only
            UI: http://127.0.0.1:8001  (admin / ${SPLUNK_PASSWORD_DEFAULT})
            HEC: http://127.0.0.1:8088

  both      Start API + Postgres + Grafana + Splunk

Examples:
  ./start.sh grafana
  ./start.sh splunk
  ./start.sh both
EOF
}

if [[ $# -lt 1 ]]; then
  echo "error: mode argument is required" >&2
  usage >&2
  exit 1
fi

case "$1" in
  -h|--help|help)
    usage
    exit 0
    ;;
  grafana|splunk|both)
    MODE="$1"
    ;;
  *)
    echo "error: unknown mode '$1' (expected grafana, splunk, or both)" >&2
    usage >&2
    exit 1
    ;;
esac

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
# Use main on first boot (custom indexes can stall Splunk Ansible).
export SPLUNK_HEC_INDEX="main"
export SPLUNK_HEC_SOURCE="rasp_webhook"
export SPLUNK_HEC_SOURCETYPE="rasp:json"
export SPLUNK_HEC_VERIFY_SSL="false"

if [[ "$USE_SPLUNK" -eq 1 ]]; then
  # HTTP HEC (no TLS) — more reliable for local Docker labs.
  export SPLUNK_HEC_URL="http://splunk:8088"
  export SPLUNK_HEC_TOKEN="$SPLUNK_HEC_TOKEN_DEFAULT"
fi


echo "==> Mode: ${MODE}"
echo "==> Building and starting services..."
# Start stack, then recreate API only so SPLUNK_* env matches the chosen mode
# without always wiping a long Splunk first-boot.
"${COMPOSE[@]}" "${PROFILES[@]}" up --build -d
"${COMPOSE[@]}" "${PROFILES[@]}" up -d --force-recreate --no-deps api

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
  echo "==> API logs (last 80 lines):" >&2
  "${COMPOSE[@]}" logs api --tail 80 >&2 || true
  exit 1
fi

if [[ "$USE_SPLUNK" -eq 1 ]]; then
  if ! HEC_TOKEN="$SPLUNK_HEC_TOKEN_DEFAULT" "$ROOT/scripts/wait_hec.sh"; then
    echo "==> Splunk diagnostics (last logs):" >&2
    "${COMPOSE[@]}" --profile splunk logs splunk --tail 100 >&2 || true
    "${COMPOSE[@]}" --profile splunk ps -a >&2 || true
    exit 1
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

if [[ "$USE_SPLUNK" -eq 1 ]]; then
  FORWARDED="$(echo "$SEED_RESULT" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("splunk_forwarded",0))' 2>/dev/null || echo 0)"
  if [[ "${FORWARDED}" -lt 1 ]]; then
    echo "error: seed did not forward any events to Splunk HEC (splunk_forwarded=${FORWARDED})" >&2
    echo "hint: curl -s http://127.0.0.1:8000/health/siem" >&2
    exit 1
  fi
  echo "==> Forwarded ${FORWARDED} seed events to Splunk"
fi

if [[ -x "$ROOT/scripts/smoke_test.sh" ]]; then
  echo "==> Running smoke tests..."
  if [[ "$USE_SPLUNK" -eq 1 ]]; then
    CHECK_SPLUNK=1 HEC_TOKEN="$SPLUNK_HEC_TOKEN_DEFAULT" "$ROOT/scripts/smoke_test.sh"
  else
    CHECK_SPLUNK=0 "$ROOT/scripts/smoke_test.sh"
  fi
fi

echo
echo "============================================================"
echo "  RASP SIEM is up — mode: ${MODE}"
echo "============================================================"
echo
echo "  API"
echo "    docs:   http://127.0.0.1:8000/docs"
echo "    health: http://127.0.0.1:8000/health"
echo "    siem:   http://127.0.0.1:8000/health/siem"
echo "    webhook (emulator): POST http://10.0.2.2:8000/events"

if [[ "$USE_GRAFANA" -eq 1 ]]; then
  echo
  echo "  Grafana"
  echo "    URL:       http://127.0.0.1:3000"
  echo "    login:     admin / admin"
  echo "    dashboard: RASP SIEM Overview (folder RASP)"
fi

if [[ "$USE_SPLUNK" -eq 1 ]]; then
  echo
  echo "  Splunk"
  echo "    URL:        http://127.0.0.1:8001"
  echo "    login:      admin / ${SPLUNK_PASSWORD_DEFAULT}"
  echo "    app:        RASP SIEM (left Apps menu)"
  echo "    dashboard:  http://127.0.0.1:8001/en-US/app/rasp_siem/rasp_overview"
  echo "    HEC:        http://127.0.0.1:8088"
  echo "    token:      ${SPLUNK_HEC_TOKEN_DEFAULT}"
  echo "    search:     index=main sourcetype=rasp:json"
fi


echo
echo "  Reseed:  curl -X POST 'http://127.0.0.1:8000/api/seed?force=true'"
echo "  Stop:    ./stop.sh          (add -v to wipe DB/Splunk volumes)"
echo "============================================================"
echo
