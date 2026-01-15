#!/bin/bash
# Script de Instalação Completa - Intranet TrueNAS
# Para Ubuntu/Debian em container LXC Proxmox

set -e  # Parar em caso de erro

echo "========================================"
echo "  Instalação - Intranet TrueNAS"
echo "========================================"
echo ""

# Verificar se está rodando como root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Este script deve ser executado como root (use sudo)"
    exit 1
fi

# Diretório de instalação
INSTALL_DIR="/opt/intranet"
SERVICE_USER="www-data"

echo "📦 Atualizando repositórios..."
apt-get update -qq

echo "📦 Instalando dependências do sistema..."
apt-get install -y -qq python3 python3-pip python3-venv nginx git

echo "📁 Criando diretório de instalação: $INSTALL_DIR"
mkdir -p $INSTALL_DIR

echo "📋 Copiando arquivos da aplicação..."
# Se estiver instalando do diretório atual
if [ -f "app.py" ]; then
    cp -r . $INSTALL_DIR/
else
    echo "❌ Arquivo app.py não encontrado no diretório atual"
    exit 1
fi

cd $INSTALL_DIR

echo "🐍 Criando ambiente virtual Python..."
python3 -m venv venv

echo "📦 Instalando dependências Python..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo "⚙️  Executando setup inicial..."
if [ ! -f ".env" ]; then
    echo "⚠️  Arquivo .env não encontrado. Execute o setup manualmente:"
    echo "   cd $INSTALL_DIR && python3 setup.py"
else
    echo "✓ Arquivo .env já existe"
fi

echo "📁 Criando diretórios necessários..."
mkdir -p logs
mkdir -p static/images

echo "🔒 Configurando permissões..."
chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
chmod -R 755 $INSTALL_DIR
chmod 640 .env 2>/dev/null || true

echo "🔧 Configurando serviço systemd..."
cat > /etc/systemd/system/intranet.service << 'EOF'
[Unit]
Description=Intranet TrueNAS Integration
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/intranet
Environment="PATH=/opt/intranet/venv/bin"
ExecStart=/opt/intranet/venv/bin/python app.py
Restart=always
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=intranet

[Install]
WantedBy=multi-user.target
EOF

echo "🌐 Configurando nginx..."
cat > /etc/nginx/sites-available/intranet << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Maximum upload size
    client_max_body_size 100M;
    
    # Proxy to Flask
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Static files
    location /static {
        alias /opt/intranet/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
}

# Uncomment lines below to enable HTTPS with SSL certificate
# server {
#     listen 443 ssl http2;
#     server_name _;
#     
#     ssl_certificate /etc/ssl/certs/intranet.crt;
#     ssl_certificate_key /etc/ssl/private/intranet.key;
#     
#     # Same configuration as above
#     ...
# }
EOF

# Ativar site nginx
ln -sf /etc/nginx/sites-available/intranet /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

echo "✓ Testando configuração nginx..."
nginx -t

echo "🔄 Reiniciando serviços..."
systemctl daemon-reload
systemctl enable intranet
systemctl restart nginx

echo ""
echo "========================================"
echo "  ✅ Instalação Concluída!"
echo "========================================"
echo ""
echo "📋 Próximos passos:"
echo ""
echo "1. Configure o arquivo .env:"
echo "   cd $INSTALL_DIR"
echo "   python3 setup.py"
echo ""
echo "2. Inicie o serviço:"
echo "   systemctl start intranet"
echo ""
echo "3. Verifique o status:"
echo "   systemctl status intranet"
echo ""
echo "4. Acesse a intranet:"
echo "   http://$(hostname -I | awk '{print $1}')"
echo ""
echo "📝 Comandos úteis:"
echo "  - Ver logs: journalctl -u intranet -f"
echo "  - Reiniciar: systemctl restart intranet"
echo "  - Parar: systemctl stop intranet"
echo ""

# Mostrar IP do servidor
IP=$(hostname -I | awk '{print $1}')
echo "🌐 IP deste servidor: $IP"
echo ""
