#!/usr/bin/env bash
# Stop the RASP SIEM stack, including profile-gated Splunk/Grafana containers.
# Plain `docker compose down` skips profile services — this always passes both.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

REMOVE_VOLUMES=0

usage() {
  cat <<EOF
Usage: ./stop.sh [--volumes|-v]

  Stop API, Postgres, Grafana, and Splunk for this compose project.

  --volumes, -v   Also remove named volumes (Postgres/Grafana/Splunk data).
                  Use for a clean reset; you will lose DB and Splunk indexes.

Examples:
  ./stop.sh
  ./stop.sh -v
EOF
}

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

for arg in "$@"; do
  case "$arg" in
    -h|--help|help)
      usage
      exit 0
      ;;
    -v|--volumes)
      REMOVE_VOLUMES=1
      ;;
    *)
      echo "error: unknown argument '$arg'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# Profiles must be listed or Splunk/Grafana are invisible to `down`.
PROFILES=(--profile grafana --profile splunk)
DOWN_ARGS=(down --remove-orphans)

if [[ "$REMOVE_VOLUMES" -eq 1 ]]; then
  DOWN_ARGS+=(--volumes)
  echo "==> Stopping stack and removing volumes..."
else
  echo "==> Stopping stack (volumes kept)..."
fi

"${COMPOSE[@]}" "${PROFILES[@]}" "${DOWN_ARGS[@]}"

echo "==> Remaining containers for this project:"
"${COMPOSE[@]}" "${PROFILES[@]}" ps -a || true
echo "==> Done. Start again with: ./start.sh <grafana|splunk|both>"
