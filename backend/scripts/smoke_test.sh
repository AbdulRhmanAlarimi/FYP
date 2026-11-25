#!/usr/bin/env bash
# Smoke-test the RASP API (and optional Splunk HEC) after start.sh.
set -euo pipefail

API_BASE="${API_BASE:-http://127.0.0.1:8000}"
HEC_URL="${HEC_URL:-http://127.0.0.1:8088/services/collector/event}"
HEC_TOKEN="${HEC_TOKEN:-11111111-1111-1111-1111-111111111111}"
CHECK_SPLUNK="${CHECK_SPLUNK:-auto}"

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

retry() {
  local tries="$1"
  shift
  local n=1
  until "$@"; do
    if (( n >= tries )); then
      return 1
    fi
    sleep 2
    n=$((n + 1))
  done
}

echo "==> API health"
curl -fsS "${API_BASE}/health" >/dev/null || fail "API /health"
pass "/health"

echo "==> SIEM health"
SIEM_JSON="$(curl -fsS "${API_BASE}/health/siem")"
echo "$SIEM_JSON"
pass "/health/siem"

echo "==> POST sample webhook event"
TS="$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")"
RESP="$(curl -fsS -X POST "${API_BASE}/events" \
  -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"ME-10\",\"event_type\":\"NETWORK_CONNECTION\",\"timestamp\":\"${TS}\",\"component\":\"SmokeTest\",\"data\":{\"url_path\":\"/login\",\"connection_result\":\"HTTP_200\"},\"seq\":1,\"launch_id\":\"smoke-test\"}")"
echo "$RESP" | grep -q '"action":"allow"' || echo "$RESP" | grep -q '"action": "allow"' || fail "webhook did not return action=allow"
pass "POST /events -> allow"

echo "==> GET events non-empty"
COUNT="$(curl -fsS "${API_BASE}/events?limit=10" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')"
[[ "$COUNT" -ge 1 ]] || fail "GET /events returned no rows"
pass "GET /events count=${COUNT}"

HEC_CONFIGURED="$(echo "$SIEM_JSON" | python3 -c 'import sys,json; print("1" if json.load(sys.stdin).get("splunk_hec_configured") else "0")')"

if [[ "$CHECK_SPLUNK" == "auto" ]]; then
  if [[ "$HEC_CONFIGURED" == "1" ]]; then
    CHECK_SPLUNK=1
  else
    CHECK_SPLUNK=0
  fi
fi

if [[ "$CHECK_SPLUNK" == "1" || "$CHECK_SPLUNK" == "true" ]]; then
  echo "==> Splunk HEC event post"
  if ! retry 15 curl -fsS -o /dev/null \
    --connect-timeout 3 --max-time 10 \
    -X POST "$HEC_URL" \
    -H "Authorization: Splunk ${HEC_TOKEN}" \
    -H 'Content-Type: application/json' \
    -d "{\"event\":{\"event_id\":\"ME-99\",\"event_type\":\"SMOKE_TEST\",\"component\":\"smoke_test.sh\",\"timestamp\":\"${TS}\"},\"sourcetype\":\"rasp:json\",\"source\":\"smoke_test\",\"index\":\"main\"}"; then
    fail "Splunk HEC post — run ./scripts/splunk_diag.sh"
  fi
  pass "HEC event post"
else
  echo "==> Skipping Splunk checks (HEC not configured)"
fi

echo
echo "All smoke checks passed."
