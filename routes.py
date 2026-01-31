"""
Rotas principais (usuário final) e endpoints gerais.

Importante: este módulo expõe endpoints SEM prefixo de blueprint (compatível com
url_for('dashboard'), url_for('user_login'), etc.) usando `endpoint=...`.
"""

from datetime import datetime
from io import BytesIO
import os

from flask import current_app, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

import config
from auth import User
from esservidor_api import ESSERVIDORAPI
from models import AccessLog, ESSERVIDORUser
from database import decrypt_api_key


def _get_admin_esservidor() -> ESSERVIDORAPI:
    return current_app.extensions['esservidor_admin']


def _get_current_api_key_for_user() -> str:
    """
    Retorna a API Key a ser usada nas chamadas ao ES-SERVIDOR para o usuário logado.

    Regra:
    - Se o usuário existe no DB local e tem API key, usamos a dele (descriptografada).
    - Caso contrário, usamos a API key global (admin) do ambiente.
    """
    db_user_id = getattr(current_user, 'db_user_id', None)
    if db_user_id:
        db_user = ESSERVIDORUser.query.get(db_user_id)
        if db_user and db_user.api_key_encrypted:
            try:
                return decrypt_api_key(db_user.api_key_encrypted)
            except Exception as e:
                current_app.logger.error(f"Erro ao descriptografar API Key do usuário {db_user.username}: {e}")
    return config.ESSERVIDOR_API_KEY


def inject_settings():
    """Injecta configurações do sistema em todos os templates."""
    from models import SystemSetting
    settings = {
        'site_title': SystemSetting.get_value('site_title', 'ES-SERVIDOR'),
        'site_logo': SystemSetting.get_value('site_logo', '/static/images/logo.png'),
        'site_favicon': SystemSetting.get_value('site_favicon', '/static/images/logo.png')
    }
    return dict(settings=settings)


def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')


def user_login():
    """Página de login para usuários ES-SERVIDOR cadastrados."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    esservidor = _get_admin_esservidor()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Por favor, preencha usuário e senha.', 'error')
            return render_template('user_login.html')

        current_app.logger.info(f"Tentativa de login: {username}")

        # 1. Tentar validar diretamente no ES-SERVIDOR via API (Basic Auth)
        is_valid_on_truenas, truenas_error = esservidor.validate_user_with_password(username, password)

        db_user = ESSERVIDORUser.query.filter_by(username=username).first()

        # 2. Se a senha do TrueNAS não funcionou, tentar a senha local (se o usuário existir no DB)
        is_authenticated = False
        auth_method = None

        if is_valid_on_truenas:
            is_authenticated = True
            auth_method = 'truenas_api'
        elif db_user and db_user.check_password(password):
            is_authenticated = True
            auth_method = 'local_db'

        if not is_authenticated:
            current_app.logger.warning(f"Falha de autenticação para: {username}")
            AccessLog.log_action(
                username,
                'login',
                request.remote_addr,
                request.user_agent.string[:255] if request.user_agent else None,
                success=False,
                details=f'Falha na autenticação ({truenas_error})'
            )
            flash('Usuário ou senha incorretos.', 'error')
            return render_template('user_login.html')

        # 3. Se autenticado, verificar se o usuário no DB está ativo (se existir)
        if db_user and not db_user.is_active:
            current_app.logger.warning(f"Usuário desativado tentou login: {username}")
            AccessLog.log_action(
                username,
                'login',
                request.remote_addr,
                request.user_agent.string[:255] if request.user_agent else None,
                success=False,
                user_id=db_user.id,
                details='Conta desativada no DB local'
            )
            flash('Sua conta está desativada na intranet. Contate o administrador.', 'error')
            return render_template('user_login.html')

        # 4. Obter informações e API Key
        stored_api_key = None
        if db_user:
            try:
                stored_api_key = decrypt_api_key(db_user.api_key_encrypted)
            except Exception as e:
                current_app.logger.error(f"Erro ao descriptografar API Key para {username}: {e}")

        current_api_key = stored_api_key or config.ESSERVIDOR_API_KEY

        # Obter informações do usuário do ES-SERVIDOR
        success, user_info = esservidor.get_user_info(username, current_api_key if stored_api_key else None)
        if not success:
            user_info = {
                'username': username,
                'full_name': db_user.full_name if db_user else username,
                'uid': None,
                'groups': []
            }

        user = User(
            username=username,
            full_name=user_info.get('full_name', db_user.full_name if db_user else username),
            user_data=user_info,
            db_user_id=db_user.id if db_user else None
        )

        session['user_data'] = {
            'username': username,
            'full_name': user.full_name,
            'uid': user_info.get('uid'),
            'groups': user_info.get('groups', []),
            'db_user_id': db_user.id if db_user else None,
            'auth_method': auth_method
        }

        login_user(user, remember=False)
        session.permanent = True

        if db_user:
            db_user.update_last_access()

        AccessLog.log_action(
            username,
            'login',
            request.remote_addr,
            request.user_agent.string[:255] if request.user_agent else None,
            success=True,
            user_id=db_user.id if db_user else None,
            details=f'Autenticado via {auth_method}'
        )

        flash(f'Bem-vindo, {user.full_name}!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('user_login.html')


@login_required
def dashboard():
    current_app.logger.info(f"Usuário {current_user.username} acessou dashboard")

    user_api_key = _get_current_api_key_for_user()
    if not user_api_key:
        flash('Sessão inválida. Por favor, faça login novamente.', 'error')
        return redirect(url_for('do_logout'))

    user_esservidor = ESSERVIDORAPI(
        base_url=config.ESSERVIDOR_API_URL,
        api_key=user_api_key,
        timeout=config.API_TIMEOUT
    )

    success, shares = user_esservidor.get_user_accessible_shares(current_user.username)
    if not success:
        current_app.logger.error(f"Erro ao carregar shares para {current_user.username}: {shares}")
        flash('Erro ao carregar compartilhamentos. Tente novamente.', 'error')
        shares = []

    if len(shares) == 0:
        flash('Você não possui permissão em nenhum compartilhamento.', 'warning')

    return render_template('dashboard.html', shares=shares, user=current_user)


def generate_bat_script(username: str, shares: list, server_name: str = None) -> str:
    server = server_name if server_name else config.ESSERVIDOR_IP

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
        'set /p SENHA="Digite sua senha do ES-SERVIDOR: "',
        'echo.',
        ''
    ]

    for idx, share in enumerate(shares):
        if idx < len(config.DEFAULT_DRIVE_LETTERS):
            drive_letter = config.DEFAULT_DRIVE_LETTERS[idx]
        else:
            letters = "PONMLKJIHGFEDCBA"
            l_idx = idx - len(config.DEFAULT_DRIVE_LETTERS)
            drive_letter = letters[l_idx] if l_idx < len(letters) else 'M'

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


@login_required
def download_bat():
    current_app.logger.info(f"Gerando script .bat para {current_user.username}")

    user_api_key = _get_current_api_key_for_user()
    if not user_api_key:
        flash('Sessão inválida. Por favor, faça login novamente.', 'error')
        return redirect(url_for('do_logout'))

    user_esservidor = ESSERVIDORAPI(
        base_url=config.ESSERVIDOR_API_URL,
        api_key=user_api_key,
        timeout=config.API_TIMEOUT
    )

    success, shares = user_esservidor.get_user_accessible_shares(current_user.username)
    if not success or len(shares) == 0:
        flash('Não há compartilhamentos disponíveis para mapear.', 'error')
        return redirect(url_for('dashboard'))

    server_name = config.ESSERVIDOR_IP
    bat_content = generate_bat_script(current_user.username, shares, server_name)

    bat_file = BytesIO(bat_content.encode('utf-8'))
    bat_file.seek(0)
    filename = f"mapear_drives_{current_user.username}.bat"

    AccessLog.log_action(
        current_user.username,
        'download_bat',
        request.remote_addr,
        request.user_agent.string[:255] if request.user_agent else None,
        success=True,
        user_id=current_user.db_user_id,
        details=f'{len(shares)} share(s)'
    )

    return send_file(
        bat_file,
        mimetype='application/bat',
        as_attachment=True,
        download_name=filename
    )


@login_required
def do_logout():
    username = current_user.username
    db_user_id = current_user.db_user_id

    AccessLog.log_action(
        username,
        'logout',
        request.remote_addr,
        request.user_agent.string[:255] if request.user_agent else None,
        success=True,
        user_id=db_user_id
    )

    logout_user()
    session.clear()
    flash('Logout realizado com sucesso.', 'info')
    return redirect(url_for('home'))


def api_status():
    """Endpoint de status/health check abrangente com cache curto."""
    from models import InternetSource
    import subprocess

    now_ts = datetime.now().timestamp()
    cache = getattr(current_app, '_status_cache', {})
    if 'data' in cache and now_ts - cache['timestamp'] < 10:
        return jsonify(cache['data'])

    try:
        temp_api = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, config.ESSERVIDOR_API_KEY, timeout=2)
        esservidor_connected = temp_api.check_connection()
    except Exception:
        esservidor_connected = False

    engine_active = False
    try:
        res = subprocess.run(
            ['/usr/bin/systemctl', 'is-active', 'intranet-engine.service'],
            capture_output=True,
            text=True
        )
        engine_active = res.stdout.strip() == 'active'
    except Exception as e:
        current_app.logger.error(f"Erro ao verificar intranet-engine: {e}")

    active_sources = InternetSource.query.filter_by(is_active=True).count()

    status = {
        'status': 'ok' if (esservidor_connected and engine_active) else 'degraded',
        'esservidor_connection': esservidor_connected,
        'monitoring_engine': engine_active,
        'active_sources': active_sources,
        'timestamp': datetime.now().isoformat()
    }

    current_app._status_cache = {'timestamp': now_ts, 'data': status}
    return jsonify(status)


def register_routes(app):
    """Registra as rotas e context processors no app, preservando endpoints legados."""
    app.context_processor(inject_settings)
    app.add_url_rule('/', endpoint='home', view_func=home)
    app.add_url_rule('/usuario', endpoint='user_login', view_func=user_login, methods=['GET', 'POST'])
    app.add_url_rule('/dashboard', endpoint='dashboard', view_func=dashboard)
    app.add_url_rule('/download_bat', endpoint='download_bat', view_func=download_bat)
    app.add_url_rule('/logout', endpoint='do_logout', view_func=do_logout, methods=['GET', 'POST'])
    app.add_url_rule('/api/status', endpoint='api_status', view_func=api_status)

