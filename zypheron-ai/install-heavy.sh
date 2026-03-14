#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -d "$DIR/venv" ]]; then
  echo "venv not found at $DIR/venv. Create it first (see requirements.txt install)." >&2
  exit 1
fi

"$DIR/venv/bin/python" -m pip install --no-cache-dir -r "$DIR/requirements-heavy.txt"

cat <<'EOF'
Heavy dependencies installed.
Note: Some packages may require system build tools (e.g., cmake) or large disk space.
EOF
