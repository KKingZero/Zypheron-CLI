#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_DIR="${PROJECT_ROOT}/zypheron-api"
CLI_DIR="${PROJECT_ROOT}/zypheron-go"
API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8000}"
API_URL="http://${API_HOST}:${API_PORT}"
API_PID=""
START_API=true
SKIP_CLI=false
SETUP_API_ENV=false
ALLOW_ONLINE=false

cleanup() {
    if [[ -n "${API_PID}" ]]; then
        kill "${API_PID}" 2>/dev/null || true
        wait "${API_PID}" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-cli)
            SKIP_CLI=true
            shift
            ;;
        --skip-api-start)
            START_API=false
            shift
            ;;
        --setup-api-env)
            SETUP_API_ENV=true
            shift
            ;;
        --allow-online)
            ALLOW_ONLINE=true
            shift
            ;;
        -h|--help)
            cat <<'EOF'
Usage: ./scripts/local_smoke_test.sh [options]

Options:
  --skip-cli         Skip CLI build/version validation
  --skip-api-start   Use an already-running API server
  --setup-api-env    Prepare zypheron-api/.venv before starting the API
  --allow-online     Allow package index access while preparing the API env
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [[ "${SKIP_CLI}" == false ]]; then
    echo "[INFO] Building CLI for smoke validation"
    make -C "${CLI_DIR}" build >/dev/null
    "${CLI_DIR}/build/zypheron" --version
fi

if [[ "${START_API}" == true ]]; then
    if [[ "${SETUP_API_ENV}" == true ]]; then
        if [[ "${ALLOW_ONLINE}" == true ]]; then
            "${PROJECT_ROOT}/scripts/setup_api_test_env.sh" --allow-online
        else
            "${PROJECT_ROOT}/scripts/setup_api_test_env.sh"
        fi
    fi

    if [[ ! -d "${API_DIR}/.venv" ]]; then
        echo "[ERROR] Missing ${API_DIR}/.venv. Run ./scripts/setup_api_test_env.sh first." >&2
        exit 1
    fi

    source "${API_DIR}/.venv/bin/activate"
    (
        cd "${API_DIR}"
        export ENVIRONMENT=development
        export DATABASE_TYPE=sqlite
        export DATABASE_URL="sqlite+aiosqlite:///./zypheron_smoke.db"
        export REDIS_ENABLED=false
        export ENABLE_RATE_LIMITING=false
        export JWT_SECRET_KEY=test-secret-key-for-smoke-tests-only-32chars
        python -m uvicorn app.main:app --host "${API_HOST}" --port "${API_PORT}" --log-level warning
    ) >/tmp/zypheron-api-smoke.log 2>&1 &
    API_PID=$!

    for _ in $(seq 1 30); do
        if curl -fsS "${API_URL}/health" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    curl -fsS "${API_URL}/health" >/dev/null
fi

echo "[INFO] Verifying API health"
curl -fsS "${API_URL}/health"
echo

echo "[INFO] Verifying AI proxy health"
curl -fsS "${API_URL}/ai/health"
echo

echo "[INFO] Verifying OpenAPI surface"
curl -fsS "${API_URL}/openapi.json" >/dev/null

echo "[INFO] Verifying metrics endpoint from localhost"
curl -fsS "${API_URL}/metrics" >/dev/null

echo "[SUCCESS] Local smoke test passed"
