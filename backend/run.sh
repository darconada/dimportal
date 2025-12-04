#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH=$(pwd)

# Activar entorno virtual
if [ -d ".venv" ]; then
  source .venv/bin/activate
fi

if [ -f ".env" ]; then
  set -a
  source .env
  set +a
fi
uvicorn main:app --host 0.0.0.0 --port 4501 --reload
