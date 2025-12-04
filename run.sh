#!/usr/bin/env bash
set -euo pipefail

# Activa el entorno virtual del proyecto raíz y lanza el backend en 4500
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if [ ! -d ".venv" ]; then
  echo "El entorno .venv no existe. Crea uno con: python3 -m venv .venv"
  exit 1
fi

source .venv/bin/activate

cd backend
# Ejecuta uvicorn en segundo plano y guarda logs para depurar
LOGFILE="$PROJECT_DIR/backend/uvicorn.out"
uvicorn main:app --host 0.0.0.0 --port 4501 --log-level debug >"$LOGFILE" 2>&1 &
PID=$!
echo $PID > "$PROJECT_DIR/uvicorn.pid"
cd "$PROJECT_DIR"

echo "Backend iniciado en puerto 4500 (PID $PID). Logs: $LOGFILE"
