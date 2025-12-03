#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

BASE_URL="${BASE_URL:-}"
BASE_PATH="${BASE_PATH:-}"
K6_IMAGE="${K6_IMAGE:-grafana/k6:0.54.0}"
CPUS="${CPUS:-1}"
MEMORY="${MEMORY:-512m}"
MOCK_MODE="${MOCK_MODE:-true}"
HOST_ADDR="${HOST_ADDR:-127.0.0.1}"
SCRIPT="${SCRIPT:-eac_report_load.js}"

if [[ -z "${BASE_URL}" ]]; then
  if [[ "${MOCK_MODE}" == "true" ]]; then
    BASE_URL="http://${HOST_ADDR}:18000"
  else
    BASE_URL="http://${HOST_ADDR}:8000"
  fi
fi

if [[ "${MOCK_MODE}" != "true" && -z "${PUBLIC_TOKEN:-}" && -z "${ADMIN_TOKEN:-}" ]]; then
  echo "PUBLIC_TOKEN and/or ADMIN_TOKEN must be set when MOCK_MODE=false." >&2
  exit 1
fi

env_args=(
  "-e" "BASE_URL=${BASE_URL}"
  "-e" "BASE_PATH=${BASE_PATH}"
  "-e" "PUBLIC_TOKEN=${PUBLIC_TOKEN:-}"
  "-e" "ADMIN_TOKEN=${ADMIN_TOKEN:-}"
  "-e" "INTEGRITY_TOKEN=${INTEGRITY_TOKEN:-}"
  "-e" "DURATION=${DURATION:-}"
  "-e" "RATE_PUBLIC=${RATE_PUBLIC:-}"
  "-e" "RATE_ADMIN=${RATE_ADMIN:-}"
  "-e" "VUS=${VUS:-}"
  "-e" "MAX_VUS=${MAX_VUS:-}"
  "-e" "MOCK_MODE=${MOCK_MODE}"
  "-e" "ITERATIONS=${ITERATIONS:-}"
)

docker run --rm \
  --cpus="${CPUS}" \
  --memory="${MEMORY}" \
  --network host \
  -v "${SCRIPT_DIR}:/loadtest" \
  "${env_args[@]}" \
  "${K6_IMAGE}" run /loadtest/${SCRIPT} "$@"
