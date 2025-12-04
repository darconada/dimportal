#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDFILE="$PROJECT_DIR/uvicorn.pid"

if [ -f "$PIDFILE" ]; then
  PID="$(cat "$PIDFILE")"
  if ps -p "$PID" >/dev/null 2>&1; then
    kill "$PID"
    echo "Detenido proceso $PID"
  else
    echo "PID $PID no está activo"
  fi
  rm -f "$PIDFILE"
else
  echo "No hay PID guardado"
fi
