#!/bin/bash
# Script de inicialização da Intranet TrueNAS
# Usado pelo systemd para iniciar a aplicação

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source "venv/bin/activate"

# Gunicorn com 4 workers
GUNICORN_WORKERS="${GUNICORN_WORKERS:-4}"
GUNICORN_BIND="${GUNICORN_BIND:-127.0.0.1:5000}"

exec gunicorn -w "$GUNICORN_WORKERS" -b "$GUNICORN_BIND" \
  --access-logfile logs/access.log \
  --error-logfile logs/error.log \
  wsgi:app
