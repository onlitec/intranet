#!/bin/bash
# Script de inicialização da Intranet TrueNAS
# Usado pelo systemd para iniciar a aplicação

cd /home/alfreire/app/intranet
source venv/bin/activate

# Gunicorn com 4 workers
exec gunicorn -w 4 -b 0.0.0.0:5000 --access-logfile logs/access.log --error-logfile logs/error.log app:app
