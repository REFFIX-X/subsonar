#!/usr/bin/env bash
# Install subsonar from this checkout and put the `subsonar` command on PATH.
# Uses pipx when it is available. Otherwise installs into the current Python.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if command -v pipx >/dev/null 2>&1; then
  echo "Installing with pipx from ${ROOT}"
  exec pipx install --force "$ROOT"
fi

PYTHON="${PYTHON:-python3}"
echo "pipx was not found; installing into ${PYTHON}."
echo "pipx keeps the tool in its own environment: https://pipx.pypa.io"
exec "$PYTHON" -m pip install "$ROOT"
