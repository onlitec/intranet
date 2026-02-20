"""
Configuração da Aplicação Intranet
Integração com ES-SERVIDOR Scale API v2.0
"""
import os
from dotenv import load_dotenv

# Carrega variáveis de ambiente do arquivo .env
load_dotenv()

# Configurações do ES-SERVIDOR
ESSERVIDOR_IP = os.getenv('ESSERVIDOR_IP', '192.168.1.100')
ESSERVIDOR_USE_HTTPS = os.getenv('ESSERVIDOR_USE_HTTPS', 'false').lower() == 'true'
ESSERVIDOR_VERIFY_SSL = os.getenv('ESSERVIDOR_VERIFY_SSL', 'false').lower() == 'true'
protocol = 'https' if ESSERVIDOR_USE_HTTPS else 'http'
ESSERVIDOR_API_URL = f"{protocol}://{ESSERVIDOR_IP}/api/v2.0"
ESSERVIDOR_API_KEY = os.getenv('ESSERVIDOR_API_KEY', '')

# Configurações do Flask
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
FLASK_ENV = os.getenv('FLASK_ENV', 'development')
FLASK_DEBUG = FLASK_ENV == 'development'
FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
FLASK_PORT = int(os.getenv('FLASK_PORT', '5000'))
TIMEZONE_OFFSET = int(os.getenv('TIMEZONE_OFFSET', '-3'))  # Horário de Brasília por padrão

# Configurações de Sessão
SESSION_TIMEOUT = 28800  # 8 horas em segundos
SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'  # HTTPS apenas se configurado
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# Sessão server-side (recomendado): evita gravar dados sensíveis no cookie
# Opções: filesystem (default), redis (futuro)
SESSION_TYPE = os.getenv('SESSION_TYPE', 'filesystem')
SESSION_FILE_DIR = os.getenv('SESSION_FILE_DIR', os.path.join(os.path.dirname(__file__), '.flask_session'))
SESSION_PERMANENT = True
SESSION_USE_SIGNER = True

# Configurações de API
API_TIMEOUT = 10  # Timeout para chamadas à API ES-SERVIDOR (segundos)
API_RETRY_ATTEMPTS = 2  # Tentativas de retry em caso de falha

# Configurações de Logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'app.log')
LOG_MAX_BYTES = 10485760  # 10MB
LOG_BACKUP_COUNT = 5

# Mapeamento de Drives (letras padrão para o script .bat)
DEFAULT_DRIVE_LETTERS = ['Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q']

# Validação de configuração crítica
if not ESSERVIDOR_API_KEY and FLASK_ENV == 'production':
    raise ValueError("ESSERVIDOR_API_KEY não configurada! Configure no arquivo .env")

if ESSERVIDOR_IP == '192.168.1.100' and FLASK_ENV == 'production':
    print("⚠️  AVISO: Usando IP padrão do ES-SERVIDOR. Configure ESSERVIDOR_IP no .env")

# Segurança: impedir secret key fraca/padrão em produção
if FLASK_ENV == 'production':
    if not FLASK_SECRET_KEY or FLASK_SECRET_KEY == 'dev-secret-key-change-in-production' or len(FLASK_SECRET_KEY) < 32:
        raise ValueError("FLASK_SECRET_KEY fraca/padrão em produção. Gere uma chave forte no .env.")

    if not os.getenv('SYSTEM_SALT'):
        raise ValueError("SYSTEM_SALT não configurado em produção. Defina no .env para criptografia de credenciais.")

# Configurações do Agente Windows
AGENT_TOKEN = os.getenv('AGENT_TOKEN', 'ONLITEC-HUD-2026')
AGENT_REPORT_INTERVAL = int(os.getenv('AGENT_REPORT_INTERVAL', '300')) # 5 minutos
AGENT_MAX_FAILED_ATTEMPTS = 5
AGENT_BLOCK_TIME = 3600 # 1 hora em segundos
MIN_AGENT_VERSION = "0.1.0" # Versão Alpha inicial
ADMIN_REMOTE_TOKEN = os.getenv('ADMIN_REMOTE_TOKEN', 'ADMIN-REMOTE-CTRL-2026')
# Configurações de IA (Fase 7)
AI_ENABLE = os.getenv('AI_ENABLE', 'true').lower() == 'true'
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '') # Chave opcional
AI_MODEL_NAME = os.getenv('AI_MODEL_NAME', 'gemini-1.5-flash')
