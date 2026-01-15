"""
Aplicação Flask Principal - Intranet TrueNAS v2.0
Sistema de autenticação com gestão de usuários e banco de dados
"""
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime, timedelta
from io import BytesIO

import config
from truenas_api import TrueNASAPI
from models import db, AdminUser, TrueNASUser, AccessLog, init_db
from database import init_crypto, decrypt_api_key
from admin import admin_bp

# Inicializar aplicação Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = config.FLASK_SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=config.SESSION_TIMEOUT)

# Configurar SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(os.path.dirname(__file__), "intranet.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar banco de dados
init_db(app)

# Inicializar criptografia
init_crypto(config.FLASK_SECRET_KEY)

# Registrar Blueprint Admin
app.register_blueprint(admin_bp)

# Configurar logging
if not os.path.exists(config.LOG_DIR):
    os.makedirs(config.LOG_DIR)

file_handler = RotatingFileHandler(
    config.LOG_FILE,
    maxBytes=config.LOG_MAX_BYTES,
    backupCount=config.LOG_BACKUP_COUNT
)
file_handler.setFormatter(logging.Formatter(
    '[%(asctime)s] [%(levelname)s] [%(request_ip)s] [%(username)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

# Adicionar filtro customizado para incluir IP e usuário nos logs
class ContextFilter(logging.Filter):
    def filter(self, record):
        record.request_ip = request.remote_addr if request else 'N/A'
        record.username = current_user.username if hasattr(current_user, 'username') else 'Anonymous'
        return True

file_handler.addFilter(ContextFilter())

app.logger.addHandler(file_handler)
app.logger.setLevel(getattr(logging, config.LOG_LEVEL))

# Também logar no console em desenvolvimento
if config.FLASK_DEBUG:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    app.logger.addHandler(console_handler)

# Inicializar cliente TrueNAS API (para operações administrativas)
truenas = TrueNASAPI(
    base_url=config.TRUENAS_API_URL,
    api_key=config.TRUENAS_API_KEY,
    timeout=config.API_TIMEOUT
)

# Configurar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.login_message_category = 'warning'


class User(UserMixin):
    """Classe de usuário para Flask-Login"""
    
    def __init__(self, username: str, full_name: str = None, user_data: dict = None, db_user_id: int = None):
        self.id = username  # Flask-Login usa 'id' como identificador
        self.username = username
        self.full_name = full_name or username
        self.user_data = user_data or {}
        self.db_user_id = db_user_id  # ID no banco de dados
    
    def __repr__(self):
        return f'<User {self.username}>'


@login_manager.user_loader
def load_user(user_id):
    """
    Carrega usuário da sessão
    Flask-Login chama esta função para cada requisição protegida
    """
    if 'user_data' in session:
        user_data = session['user_data']
        return User(
            username=user_data.get('username'),
            full_name=user_data.get('full_name'),
            user_data=user_data,
            db_user_id=user_data.get('db_user_id')
        )
    return None


@app.route('/')
def home():
    """Página inicial - seleção de tipo de login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/usuario', methods=['GET', 'POST'])
def user_login():
    """Página de login para usuários TrueNAS cadastrados"""
    
    # Se já estiver logado, redireciona para dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Por favor, preencha usuário e senha.', 'error')
            app.logger.warning(f"Tentativa de login com campos vazios")
            return render_template('user_login.html')
        
        app.logger.info(f"Tentativa de login: {username}")
        
        # Buscar usuário no banco de dados
        db_user = TrueNASUser.query.filter_by(username=username).first()
        
        if not db_user:
            app.logger.warning(f"Usuário não cadastrado: {username}")
            AccessLog.log_action(username, 'login', request.remote_addr, 
                               request.user_agent.string[:255] if request.user_agent else None,
                               success=False, details='Usuário não cadastrado')
            flash('Usuário ou senha incorretos.', 'error')
            return render_template('user_login.html')
        
        if not db_user.is_active:
            app.logger.warning(f"Usuário desativado tentou login: {username}")
            AccessLog.log_action(username, 'login', request.remote_addr, 
                               request.user_agent.string[:255] if request.user_agent else None,
                               success=False, user_id=db_user.id, details='Conta desativada')
            flash('Sua conta está desativada. Contate o administrador.', 'error')
            return render_template('user_login.html')
        
        # Verificar senha local
        if not db_user.check_password(password):
            app.logger.warning(f"Senha incorreta para {username}")
            AccessLog.log_action(username, 'login', request.remote_addr,
                               request.user_agent.string[:255] if request.user_agent else None,
                               success=False, user_id=db_user.id, details='Senha incorreta')
            flash('Usuário ou senha incorretos.', 'error')
            return render_template('user_login.html')
        
        # Obter API Key descriptografada do banco
        try:
            stored_api_key = decrypt_api_key(db_user.api_key_encrypted)
        except Exception as e:
            app.logger.error(f"Erro ao descriptografar API Key para {username}: {e}")
            flash('Erro interno. Contate o administrador.', 'error')
            return render_template('user_login.html')
        
        # Validar API Key no TrueNAS (opcional, para garantir que ainda é válida)
        valid, error = truenas.validate_user_with_api_key(username, stored_api_key)
        
        if not valid:
            app.logger.warning(f"API Key inválida no TrueNAS: {username} - {error}")
            AccessLog.log_action(username, 'login', request.remote_addr,
                               request.user_agent.string[:255] if request.user_agent else None,
                               success=False, user_id=db_user.id, details=f'TrueNAS: {error}')
            flash('Erro de conexão com TrueNAS. Contate o administrador.', 'error')
            return render_template('user_login.html')
        
        # Obter informações do usuário do TrueNAS
        success, user_info = truenas.get_user_info(username, stored_api_key)
        
        if not success:
            user_info = {'full_name': db_user.full_name, 'username': username}
        
        # Criar objeto User e fazer login
        user = User(
            username=username,
            full_name=user_info.get('full_name', db_user.full_name),
            user_data=user_info,
            db_user_id=db_user.id
        )
        
        # Armazenar dados na sessão
        session['user_data'] = {
            'username': username,
            'full_name': user_info.get('full_name', db_user.full_name),
            'uid': user_info.get('uid'),
            'groups': user_info.get('groups', []),
            'api_key': stored_api_key,  # Usa API Key do banco
            'db_user_id': db_user.id
        }
        
        login_user(user, remember=True)
        session.permanent = True
        
        # Atualizar último acesso
        db_user.update_last_access()
        
        # Registrar log de sucesso
        AccessLog.log_action(username, 'login', request.remote_addr,
                           request.user_agent.string[:255] if request.user_agent else None,
                           success=True, user_id=db_user.id)
        
        app.logger.info(f"Login bem-sucedido: {username} ({user.full_name})")
        flash(f'Bem-vindo, {user.full_name}!', 'success')
        
        return redirect(url_for('dashboard'))
    
    return render_template('user_login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principal com compartilhamentos disponíveis"""
    
    app.logger.info(f"Usuário {current_user.username} acessou dashboard")
    
    # Obter API Key do usuário da sessão
    user_api_key = session.get('user_data', {}).get('api_key')
    
    if not user_api_key:
        app.logger.error(f"API Key não encontrada na sessão para {current_user.username}")
        flash('Sessão inválida. Por favor, faça login novamente.', 'error')
        return redirect(url_for('do_logout'))
    
    # Criar um TrueNASAPI temporário com a API Key do usuário
    user_truenas = TrueNASAPI(
        base_url=config.TRUENAS_API_URL,
        api_key=user_api_key,
        timeout=config.API_TIMEOUT
    )
    
    # Obter compartilhamentos acessíveis ao usuário
    success, shares = user_truenas.get_user_accessible_shares(current_user.username)
    
    if not success:
        app.logger.error(f"Erro ao carregar shares para {current_user.username}: {shares}")
        flash('Erro ao carregar compartilhamentos. Tente novamente.', 'error')
        shares = []
    
    # Verificar se usuário tem algum compartilhamento
    if len(shares) == 0:
        flash('Você não possui permissão em nenhum compartilhamento.', 'warning')
    
    return render_template('dashboard.html', shares=shares, user=current_user)


@app.route('/download_bat')
@login_required
def download_bat():
    """Gera e baixa script .bat para mapeamento de drives"""
    
    app.logger.info(f"Gerando script .bat para {current_user.username}")
    
    # Obter API Key do usuário da sessão
    user_api_key = session.get('user_data', {}).get('api_key')
    
    if not user_api_key:
        flash('Sessão inválida. Por favor, faça login novamente.', 'error')
        return redirect(url_for('do_logout'))
    
    # Criar cliente TrueNAS com API Key do usuário
    user_truenas = TrueNASAPI(
        base_url=config.TRUENAS_API_URL,
        api_key=user_api_key,
        timeout=config.API_TIMEOUT
    )
    
    # Obter compartilhamentos do usuário
    success, shares = user_truenas.get_user_accessible_shares(current_user.username)
    
    if not success or len(shares) == 0:
        flash('Não há compartilhamentos disponíveis para mapear.', 'error')
        return redirect(url_for('dashboard'))
    
    # Usar IP do TrueNAS (mais confiável - não depende de DNS)
    server_name = config.TRUENAS_IP
    
    # Gerar conteúdo do script .bat usando IP
    bat_content = generate_bat_script(current_user.username, shares, server_name)
    
    # Criar arquivo em memória
    bat_file = BytesIO(bat_content.encode('utf-8'))
    bat_file.seek(0)
    
    filename = f"mapear_drives_{current_user.username}.bat"
    
    # Registrar log
    AccessLog.log_action(current_user.username, 'download_bat', request.remote_addr,
                        request.user_agent.string[:255] if request.user_agent else None,
                        success=True, user_id=current_user.db_user_id,
                        details=f'{len(shares)} share(s)')
    
    app.logger.info(f"Download de script .bat: {filename} ({len(shares)} share(s))")
    
    return send_file(
        bat_file,
        mimetype='application/bat',
        as_attachment=True,
        download_name=filename
    )


def generate_bat_script(username: str, shares: list, server_name: str = None) -> str:
    """
    Gera conteúdo do script .bat para mapeamento de drives
    
    Args:
        username: Nome do usuário
        shares: Lista de compartilhamentos
        server_name: Nome do servidor (hostname ou IP). Se None, usa config.TRUENAS_IP
    """
    # Usar hostname se disponível, senão usa IP
    server = server_name if server_name else config.TRUENAS_IP
    
    lines = [
        '@echo off',
        f'title Mapeamento de Drives - {username}',
        'color 0A',
        'echo ========================================',
        'echo   Mapeamento Automatico de Drives',
        f'echo   Usuario: {username}',
        f'echo   Servidor: {server}',
        'echo ========================================',
        'echo.',
        '',
        'REM Obter senha do usuario',
        'set /p SENHA="Digite sua senha do TrueNAS: "',
        'echo.',
        ''
    ]
    
    # Mapear cada compartilhamento
    for idx, share in enumerate(shares):
        drive_letter = config.DEFAULT_DRIVE_LETTERS[idx] if idx < len(config.DEFAULT_DRIVE_LETTERS) else 'P'
        share_name = share['name']
        
        lines.extend([
            f'echo Mapeando {share_name} em {drive_letter}:...',
            f'net use {drive_letter}: /delete /yes 2>nul',
            f'net use {drive_letter}: \\\\{server}\\{share_name} /user:{username} %SENHA% /persistent:yes',
            '',
            'if %errorlevel% equ 0 (',
            f'    echo [OK] {share_name} mapeado com sucesso em {drive_letter}:!',
            ') else (',
            f'    echo [ERRO] Falha ao mapear {share_name}',
            ')',
            'echo.',
            ''
        ])
    
    lines.extend([
        'echo.',
        'echo ========================================',
        'echo   Mapeamento concluido!',
        'echo ========================================',
        'echo.',
        'pause'
    ])
    
    return '\r\n'.join(lines)


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def do_logout():
    """Encerra sessão do usuário"""
    
    username = current_user.username
    db_user_id = current_user.db_user_id
    
    # Registrar log de logout
    AccessLog.log_action(username, 'logout', request.remote_addr,
                        request.user_agent.string[:255] if request.user_agent else None,
                        success=True, user_id=db_user_id)
    
    app.logger.info(f"Logout: {username}")
    
    logout_user()
    session.clear()
    
    flash('Logout realizado com sucesso.', 'info')
    return redirect(url_for('home'))


@app.route('/api/status')
def api_status():
    """Endpoint de status/health check"""
    
    truenas_connected = truenas.check_connection()
    
    status = {
        'status': 'ok' if truenas_connected else 'degraded',
        'truenas_connection': truenas_connected,
        'truenas_ip': config.TRUENAS_IP,
        'timestamp': datetime.now().isoformat()
    }
    
    return jsonify(status)


@app.errorhandler(404)
def not_found(error):
    """Tratamento de página não encontrada"""
    return render_template('error.html', 
                         error_code=404,
                         error_message='Página não encontrada'), 404


@app.errorhandler(500)
def internal_error(error):
    """Tratamento de erro interno"""
    app.logger.exception(f"Erro interno: {error}")
    return render_template('error.html',
                         error_code=500,
                         error_message='Erro interno do servidor'), 500


if __name__ == '__main__':
    # Verificar conexão com TrueNAS na inicialização
    app.logger.info("Iniciando aplicação Intranet TrueNAS v2.0")
    app.logger.info(f"TrueNAS URL: {config.TRUENAS_API_URL}")
    
    with app.app_context():
        # Verificar se existe admin padrão
        admin_count = AdminUser.query.count()
        user_count = TrueNASUser.query.count()
        app.logger.info(f"Banco de dados: {admin_count} admin(s), {user_count} usuário(s) TrueNAS")
    
    if truenas.check_connection():
        app.logger.info("✓ Conexão com TrueNAS estabelecida")
    else:
        app.logger.warning("✗ Não foi possível conectar ao TrueNAS - verifique config")
    
    app.logger.info("=" * 50)
    app.logger.info("  CREDENCIAIS ADMIN PADRÃO:")
    app.logger.info("  Usuário: admin")
    app.logger.info("  Senha: admin123")
    app.logger.info("  Acesse: /admin/login")
    app.logger.info("=" * 50)
    
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG
    )
