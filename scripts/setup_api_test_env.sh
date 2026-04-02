#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_DIR="${PROJECT_ROOT}/zypheron-api"
VENV_DIR="${API_DIR}/.venv"
LOCKFILE="${API_DIR}/requirements.lock"
WHEELHOUSE="${WHEELHOUSE:-${API_DIR}/wheelhouse}"
ALLOW_ONLINE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --allow-online)
            ALLOW_ONLINE=true
            shift
            ;;
        -h|--help)
            cat <<'EOF'
Usage: ./scripts/setup_api_test_env.sh [--allow-online]

Creates or updates zypheron-api/.venv using requirements.lock.

Default behavior prefers local/offline installation sources:
- uses ./zypheron-api/wheelhouse if present
- otherwise uses normal pip resolution only with --allow-online
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [[ ! -f "${LOCKFILE}" ]]; then
    echo "Lockfile not found: ${LOCKFILE}" >&2
    exit 1
fi

python3 -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip

install_locked() {
    local extra_args=()

    if [[ -d "${WHEELHOUSE}" ]]; then
        extra_args+=(--no-index "--find-links=${WHEELHOUSE}")
        echo "[INFO] Installing API dependencies from local wheelhouse: ${WHEELHOUSE}"
    elif [[ "${ALLOW_ONLINE}" == true ]]; then
        echo "[INFO] Installing API dependencies from package index using requirements.lock"
    else
        echo "[ERROR] No local wheelhouse found at ${WHEELHOUSE} and online installs are disabled." >&2
        echo "[ERROR] Re-run with --allow-online or provide prebuilt wheels." >&2
        exit 1
    fi

    python -m pip install "${extra_args[@]}" -r "${LOCKFILE}"
    python -m pip install "${extra_args[@]}" -e "${API_DIR}" --no-deps
}

install_locked

echo "[SUCCESS] API test environment ready at ${VENV_DIR}"
