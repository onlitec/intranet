```
Crie uma aplicação web completa de intranet integrada com TrueNAS Scale via API REST com as seguintes especificações:

## Contexto
- Aplicação Flask para intranet corporativa
- Hospedada em container LXC Ubuntu/Debian no Proxmox
- Até 10 usuários
- Integração COMPLETA com TrueNAS Scale API v2.0
- Objetivo: Sistema de login validado contra TrueNAS + download de script .bat para mapear drives de rede

## Arquitetura de Integração

### Conexão com TrueNAS API
- Endpoint base: http://IP_TRUENAS/api/v2.0
- Autenticação via API Key (gerada no TrueNAS)
- Biblioteca: requests
- Timeout: 10 segundos para chamadas API
- Tratamento completo de erros de conexão

### Fluxo de Autenticação
1. Usuário insere credenciais na intranet
2. Aplicação valida credenciais via API TrueNAS: POST /user/check_password
3. Se válido, busca informações do usuário: GET /user?username=XXX
4. Busca compartilhamentos SMB disponíveis: GET /sharing/smb
5. Cruza permissões do usuário com compartilhamentos
6. Cria sessão e exibe dashboard personalizado

## Requisitos Funcionais

### 1. Sistema de Autenticação Integrado
- Login valida DIRETAMENTE no TrueNAS via API
- Não armazena senhas localmente (apenas cache temporário de sessão)
- Sessão expira em 8 horas
- Logout limpa sessão

### 2. Endpoints da API TrueNAS a utilizar

#### Validar Credenciais:
```
POST /api/v2.0/user/check_password
Body: {"username": "joao", "password": "senha123"}
Response: {"valid": true/false}
```

#### Obter informações do usuário:
```
GET /api/v2.0/user?username=joao
Response: {
  "id": 1,
  "username": "joao",
  "full_name": "João Silva",
  "groups": [{"id": 1, "group": "users"}],
  "home": "/mnt/tank/home/joao"
}
```

#### Listar compartilhamentos SMB:
```
GET /api/v2.0/sharing/smb
Response: [
  {
    "id": 1,
    "name": "Arquivos",
    "path": "/mnt/tank/arquivos",
    "enabled": true,
    "comment": "Compartilhamento geral"
  }
]
```

#### Verificar permissões de filesystem:
```
POST /api/v2.0/filesystem/getacl
Body: {"path": "/mnt/tank/arquivos"}
Response: {ACL completo com usuários/grupos autorizados}
```

### 3. Estrutura de Configuração

Arquivo config.py:
```python
TRUENAS_IP = "192.168.1.100"
TRUENAS_API_URL = f"http://{TRUENAS_IP}/api/v2.0"
TRUENAS_API_KEY = "1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # Gerada no TrueNAS
SESSION_TIMEOUT = 28800  # 8 horas em segundos
FLASK_SECRET_KEY = "chave-aleatoria-segura"
```

### 4. Módulo de API TrueNAS (truenas_api.py)

Criar classe TrueNASAPI com métodos:

```python
class TrueNASAPI:
    def __init__(self, base_url, api_key):
        # Inicializar conexão
        
    def validate_user(self, username, password):
        # POST /user/check_password
        # Retorna: (True/False, mensagem_erro)
        
    def get_user_info(self, username):
        # GET /user?username=XXX
        # Retorna: dict com dados do usuário
        
    def get_smb_shares(self):
        # GET /sharing/smb
        # Retorna: lista de compartilhamentos
        
    def get_user_accessible_shares(self, username):
        # Combina shares + permissões do usuário
        # Retorna: lista de shares que o usuário pode acessar
        
    def check_connection(self):
        # GET /system/info (health check)
        # Retorna: True se TrueNAS está acessível
```

### 5. Funcionalidades da Aplicação

#### Página de Login (/)
- Formulário username + password
- Validação em tempo real via API TrueNAS
- Mensagens de erro específicas:
  - "Credenciais inválidas"
  - "TrueNAS inacessível - contate o administrador"
  - "Erro de conexão"
- Spinner de loading durante validação

#### Dashboard (/dashboard)
- Protegido com @login_required
- Exibe:
  - Nome completo do usuário (obtido da API)
  - Lista de compartilhamentos acessíveis (dinâmica da API)
  - Botão "Mapear Drives de Rede" para cada share
- Informações atualizadas a cada login (não usa cache)

#### Geração de Script BAT (/download_bat)
- Gera .bat personalizado com:
  - Username do TrueNAS
  - IP do TrueNAS (da config)
  - Shares que o usuário TEM PERMISSÃO (da API)
  - Letras de drive configuráveis
- Script pede senha ao executar (segurança)

Formato do .bat:
```bat
@echo off
title Mapeamento de Drives - {NOME_USUARIO}
color 0A
echo ========================================
echo   Mapeamento Automatico de Drives
echo   Usuario: {USERNAME}
echo ========================================
echo.

REM Obter senha do usuario
set /p SENHA="Digite sua senha do TrueNAS: "
echo.

REM Mapear cada share
echo Mapeando {SHARE_NAME} em {LETRA}:...
net use {LETRA}: /delete /yes 2>nul
net use {LETRA}: \\{TRUENAS_IP}\{SHARE_NAME} /user:{USERNAME} %SENHA% /persistent:yes

if %errorlevel% equ 0 (
    echo [OK] {SHARE_NAME} mapeado com sucesso!
) else (
    echo [ERRO] Falha ao mapear {SHARE_NAME}
)
echo.

REM Repetir para cada share...

echo.
echo ========================================
echo   Mapeamento concluido!
echo ========================================
pause
```

### 6. Tratamento de Erros

Implementar tratamento para:
- TrueNAS offline/inacessível
- API Key inválida
- Timeout de requisições
- Usuário sem permissões em nenhum share
- Mudanças de senha (logout automático em erro 401)
- Rate limiting da API

### 7. Interface Web

#### Design:
- Responsivo (funciona em mobile/desktop)
- Tema: moderno, corporativo
- Cores: azul/cinza profissional
- CSS: Tailwind CDN ou Bootstrap 5

#### Componentes:
- Header com logo e botão logout
- Cards para cada compartilhamento disponível
- Ícones para diferentes tipos de shares
- Loading states durante chamadas API
- Notificações toast para feedback

### 8. Segurança

- API Key armazenada em variável de ambiente (não hardcode)
- Secret key do Flask aleatória
- HTTPS recomendado (configurar nginx com SSL)
- Timeout de sessão
- Proteção CSRF
- Validação de inputs
- Logs de acesso com IP e timestamp

### 9. Logging

Registrar em /var/log/intranet/:
- Logins bem-sucedidos/falhos
- Downloads de scripts .bat
- Erros de API
- Status de conexão com TrueNAS

Formato: `[TIMESTAMP] [LEVEL] [IP] [USER] Mensagem`

## Estrutura de Arquivos

```
/opt/intranet/
├── app.py                    # Aplicação Flask principal
├── config.py                 # Configurações (API key, IPs, etc)
├── truenas_api.py           # Classe para interação com API
├── requirements.txt          # Dependências Python
├── .env                      # Variáveis de ambiente (API key)
├── templates/
│   ├── base.html            # Template base
│   ├── login.html           # Página de login
│   ├── dashboard.html       # Dashboard do usuário
│   └── error.html           # Página de erro
├── static/
│   ├── css/
│   │   └── style.css        # Estilos customizados
│   ├── js/
│   │   └── app.js           # JavaScript (loading, etc)
│   └── images/
│       └── logo.png         # Logo da empresa
└── logs/
    └── app.log              # Logs da aplicação
```

## Dependências (requirements.txt)

```
Flask==3.0.0
Flask-Login==0.6.3
requests==2.31.0
python-dotenv==1.0.0
werkzeug==3.0.1
```

## Scripts Auxiliares

### 1. Script de instalação (install.sh)
```bash
#!/bin/bash
# Instalar dependências, criar estrutura, configurar systemd
```

### 2. Service Systemd (intranet.service)
```ini
[Unit]
Description=Intranet TrueNAS Integration
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/intranet
Environment="PATH=/opt/intranet/venv/bin"
ExecStart=/opt/intranet/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### 3. Configuração Nginx (nginx.conf)
```nginx
server {
    listen 80;
    server_name intranet.local;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Como Gerar API Key no TrueNAS

Incluir instruções comentadas no código:
```
1. Acessar TrueNAS Web UI
2. System Settings → Advanced → API Keys
3. Add → Nome: "Intranet" → Generate Key
4. Copiar a chave e adicionar no arquivo .env
```

## Configuração Inicial

Script setup.py para primeira execução:
```python
# Testa conexão com TrueNAS
# Valida API Key
# Cria estrutura de diretórios
# Gera secret key aleatória
# Testa endpoints essenciais
```

## Extras

- Health check endpoint: /api/status (retorna status da conexão com TrueNAS)
- Página de administração: /admin (verificar conexão, testar API, ver logs)
- Download de logs: /admin/logs
- Documentação inline: comentários explicativos em cada função
- README.md com instruções de instalação e uso

## Requisitos de Rede

- Aplicação precisa acessar TrueNAS na porta 80 (HTTP API)
- Clientes Windows precisam acessar aplicação na porta 80/443
- Clientes Windows precisam acessar TrueNAS na porta 445 (SMB)

## Tratamento de Casos Especiais

1. Usuário sem permissão em nenhum share: exibir mensagem amigável
2. TrueNAS em manutenção: página de status
3. Mudança de senha no TrueNAS: próximo login detecta e re-valida
4. Share desabilitado: não aparecer na lista
5. Múltiplos grupos: agregar permissões de todos os grupos

Gere todos os arquivos completos, funcionais e prontos para produção, com comentários detalhados explicando a integração com a API do TrueNAS.
```

Esse prompt está completo e detalhado para criar uma solução **profissional e totalmente integrada** com o TrueNAS! 🚀

Cole na sua IDE Antigravity e ela vai gerar tudo. Depois me avise se precisar de ajuda para:
- Gerar a API Key no TrueNAS
- Configurar o nginx
- Testar a integração
- Resolver algum erro específico