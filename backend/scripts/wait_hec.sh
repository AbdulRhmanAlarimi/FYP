#!/usr/bin/env bash
# Wait until Splunk HEC accepts traffic. Exit 0 when ready, 1 on timeout.
set -euo pipefail

HEC_TOKEN="${HEC_TOKEN:-11111111-1111-1111-1111-111111111111}"
HEC_BASE="${HEC_BASE:-http://127.0.0.1:8088}"
ATTEMPTS="${ATTEMPTS:-150}"
SLEEP_SECS="${SLEEP_SECS:-5}"

hec_ok() {
  local payload
  payload="$(printf '{"event":{"probe":"wait_hec","ts":"%s"},"sourcetype":"rasp:json","source":"wait_hec","index":"main"}' "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"

  if curl -fsS -o /dev/null \
    -X POST "${HEC_BASE}/services/collector/event" \
    -H "Authorization: Splunk ${HEC_TOKEN}" \
    -H "Content-Type: application/json" \
    --connect-timeout 3 \
    --max-time 8 \
    -d "${payload}" 2>/dev/null; then
    return 0
  fi

  if curl -fsS -o /dev/null \
    --connect-timeout 3 --max-time 5 \
    "${HEC_BASE}/services/collector/health/1.0" 2>/dev/null; then
    return 0
  fi
  if curl -fsS -o /dev/null \
    --connect-timeout 3 --max-time 5 \
    "${HEC_BASE}/services/collector/health" 2>/dev/null; then
    return 0
  fi
  return 1
}

web_up() {
  curl -fsS -o /dev/null --connect-timeout 2 --max-time 4 "http://127.0.0.1:8001/" 2>/dev/null \
    || curl -fsS -o /dev/null --connect-timeout 2 --max-time 4 "http://127.0.0.1:8001/en-US/" 2>/dev/null
}

echo "==> Waiting for Splunk HEC at ${HEC_BASE} (up to ~$((ATTEMPTS * SLEEP_SECS / 60)) min on first boot)..."
for i in $(seq 1 "$ATTEMPTS"); do
  if hec_ok; then
    echo "==> Splunk HEC is ready (attempt ${i}/${ATTEMPTS})"
    exit 0
  fi
  if (( i % 6 == 0 )); then
    if web_up; then
      echo "    still waiting for HEC... (${i}/${ATTEMPTS}) — Splunk Web is up, HEC not yet"
    else
      echo "    still waiting... (${i}/${ATTEMPTS}) — Splunk still booting (Web not ready either)"
    fi
  fi
  sleep "$SLEEP_SECS"
done

echo "error: Splunk HEC did not become ready in time" >&2
echo "hint: run: ./scripts/splunk_diag.sh" >&2
echo "hint: clean reset: docker compose --profile splunk down -v && ./start.sh splunk" >&2
exit 1
