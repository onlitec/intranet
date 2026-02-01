#!/bin/bash

# Script de inicialização do servidor Flask com Gunicorn
# Garante que sempre use o Python do virtualenv

# Diretório base
BASE_DIR="/opt/intranet"
VENV_DIR="$BASE_DIR/venv"
LOG_DIR="$BASE_DIR/logs"

# Criar diretório de logs se não existir
mkdir -p "$LOG_DIR"

# Matar processos antigos do Gunicorn
echo "🔄 Parando processos antigos do Gunicorn..."
pkill -f "gunicorn.*wsgi:app" 2>/dev/null
sleep 2

# Verificar se o venv existe
if [ ! -d "$VENV_DIR" ]; then
    echo "❌ Erro: Virtualenv não encontrado em $VENV_DIR"
    exit 1
fi

# Verificar se o módulo markdown está instalado
echo "🔍 Verificando dependências..."
$VENV_DIR/bin/python3 -c "import markdown" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "📦 Instalando módulo markdown..."
    $VENV_DIR/bin/pip install markdown
fi

# Iniciar Gunicorn com Python do venv
echo "🚀 Iniciando servidor Gunicorn..."
cd "$BASE_DIR"

nohup $VENV_DIR/bin/gunicorn \
    --workers 4 \
    --threads 2 \
    --worker-class gthread \
    --bind 127.0.0.1:5000 \
    --access-logfile "$LOG_DIR/access.log" \
    --error-logfile "$LOG_DIR/error.log" \
    --timeout 120 \
    --graceful-timeout 30 \
    wsgi:app > /dev/null 2>&1 &

# Aguardar inicialização
sleep 3

# Verificar se iniciou corretamente
if pgrep -f "gunicorn.*wsgi:app" > /dev/null; then
    echo "✅ Servidor iniciado com sucesso!"
    echo "📊 Processos ativos:"
    ps aux | grep gunicorn | grep -v grep | head -2
else
    echo "❌ Erro ao iniciar o servidor!"
    echo "📋 Últimas linhas do log de erro:"
    tail -20 "$LOG_DIR/error.log"
    exit 1
fi
