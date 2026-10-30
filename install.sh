#!/usr/bin/env bash
# Install subsonar from this checkout and put the `subsonar` command on PATH.
#
# Uses pipx when it is available (isolated environment). Otherwise installs
# into .venv in this checkout. A second run upgrades that same install.
set -euo pipefail

# Resolve the checkout even when `dirname` is not on PATH.
_src="${BASH_SOURCE[0]}"
_dir="${_src%/*}"
if [[ "$_dir" == "$_src" ]]; then
  _dir="."
fi
ROOT="$(cd "$_dir" && pwd)"
cd "$ROOT"

if command -v pipx >/dev/null 2>&1; then
  echo "Installing with pipx from ${ROOT}"
  exec pipx install --force "$ROOT"
fi

PYTHON="${PYTHON:-python3}"
VENV="${SUBSONAR_VENV:-$ROOT/.venv}"
if [[ ! -x "$VENV/bin/python" ]]; then
  echo "Creating ${VENV} with ${PYTHON}"
  "$PYTHON" -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install "$ROOT"
echo ""
echo "Installed into ${VENV}"
echo "Run: ${VENV}/bin/subsonar --help"
