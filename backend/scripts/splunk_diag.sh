#!/usr/bin/env bash
# Print Splunk/HEC diagnostics for local debugging.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
else
  COMPOSE=(docker-compose)
fi

HEC_TOKEN="${HEC_TOKEN:-11111111-1111-1111-1111-111111111111}"

echo "==> compose ps"
"${COMPOSE[@]}" --profile splunk ps -a || true

echo
echo "==> host ports"
(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null || true) | grep -E '8001|8088|8000' || echo "(no listeners matched)"

echo
echo "==> curl Splunk Web :8001"
curl -sS -o /dev/null -w "HTTP %{http_code}\n" --connect-timeout 3 --max-time 5 "http://127.0.0.1:8001/" || echo "Web unreachable"

echo
echo "==> curl HEC health HTTP :8088"
curl -sS -i --connect-timeout 3 --max-time 5 "http://127.0.0.1:8088/services/collector/health" || echo "HEC health unreachable"

echo
echo "==> curl HEC event POST"
curl -sS -i --connect-timeout 3 --max-time 8 \
  -X POST "http://127.0.0.1:8088/services/collector/event" \
  -H "Authorization: Splunk ${HEC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"event":{"probe":"splunk_diag"},"sourcetype":"rasp:json","source":"diag","index":"main"}' \
  || echo "HEC post failed"

echo
echo "==> splunk logs (tail 120)"
"${COMPOSE[@]}" --profile splunk logs splunk --tail 120 || true

echo
echo "==> inside container: splunk status + hec conf"
"${COMPOSE[@]}" --profile splunk exec -T splunk bash -lc '
  /opt/splunk/bin/splunk status || true
  echo ---
  ls -la /opt/splunk/etc/apps/splunk_httpinput/local 2>/dev/null || echo "no httpinput local"
  echo ---
  cat /opt/splunk/etc/apps/splunk_httpinput/local/inputs.conf 2>/dev/null || echo "no inputs.conf"
  echo ---
  ss -ltn 2>/dev/null | grep -E "8000|8088|8089" || netstat -ltn 2>/dev/null | grep -E "8000|8088|8089" || true
' || echo "exec failed (container not running?)"
