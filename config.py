"""
Configuração da Aplicação Intranet
Integração com TrueNAS Scale API v2.0
"""
import os
from dotenv import load_dotenv

# Carrega variáveis de ambiente do arquivo .env
load_dotenv()

# Configurações do TrueNAS
TRUENAS_IP = os.getenv('TRUENAS_IP', '192.168.1.100')
TRUENAS_API_URL = f"http://{TRUENAS_IP}/api/v2.0"
TRUENAS_API_KEY = os.getenv('TRUENAS_API_KEY', '')

# Configurações do Flask
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
FLASK_ENV = os.getenv('FLASK_ENV', 'development')
FLASK_DEBUG = FLASK_ENV == 'development'
FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
FLASK_PORT = int(os.getenv('FLASK_PORT', '5000'))

# Configurações de Sessão
SESSION_TIMEOUT = 28800  # 8 horas em segundos
SESSION_COOKIE_SECURE = FLASK_ENV == 'production'  # HTTPS apenas em produção
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# Configurações de API
API_TIMEOUT = 10  # Timeout para chamadas à API TrueNAS (segundos)
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
if not TRUENAS_API_KEY and FLASK_ENV == 'production':
    raise ValueError("TRUENAS_API_KEY não configurada! Configure no arquivo .env")

if TRUENAS_IP == '192.168.1.100' and FLASK_ENV == 'production':
    print("⚠️  AVISO: Usando IP padrão do TrueNAS. Configure TRUENAS_IP no .env")
