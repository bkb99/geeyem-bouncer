#!/usr/bin/env bash
# Set up the bouncer: a python venv and a config. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/bouncer"

PYTHON="${PYTHON:-python3.11}"
command -v "$PYTHON" >/dev/null || PYTHON=python3
"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
  || { echo "Python 3.11 or newer is needed"; exit 1; }

[[ -d .venv ]] || "$PYTHON" -m venv .venv
.venv/bin/pip -q install --upgrade pip
.venv/bin/pip -q install -r requirements.txt
echo "✓ dependencies installed"

if [[ ! -f config.json ]]; then
  cp config.example.json config.json
  echo "✓ config.json created from the example"
fi

cat <<'NEXT'

Next:
  cd bouncer
  .venv/bin/python -m relay token new "iPhone"   # copy the token
  .venv/bin/python -m relay run
NEXT
