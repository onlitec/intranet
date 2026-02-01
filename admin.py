"""
Blueprint Administrativo - Intranet ES-SERVIDOR
Rotas para gerenciamento de usuários e visualização de logs
"""
from functools import wraps
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from models import db, AdminUser, ESSERVIDORUser, AccessLog, SMTPConfig, ReportSchedule, ReportLog, KnownDevice
from database import encrypt_api_key, decrypt_api_key
from esservidor_api import ESSERVIDORAPI
from collections import Counter
import config
from werkzeug.utils import secure_filename
import os
import secrets
import subprocess
from ai_engine import ai_engine

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required(f):
    """Decorator para exigir login de admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Faça login como administrador para acessar esta página.', 'error')
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated_function


def get_current_admin():
    """Retorna o admin logado atualmente"""
    if 'admin_id' in session:
        return AdminUser.query.get(session['admin_id'])
    return None


# ==================== LOGIN ====================

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login do administrador"""

    # Se não existe nenhum admin ainda, direciona para bootstrap seguro
    if AdminUser.query.count() == 0:
        return redirect(url_for('admin.bootstrap'))
    
    # Se já logado como admin, redireciona
    if 'admin_id' in session:
        return redirect(url_for('admin.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Preencha usuário e senha.', 'error')
            return render_template('admin_login.html')
        
        admin = AdminUser.query.filter_by(username=username).first()
        
        if admin and admin.check_password(password):
            if not admin.is_active:
                flash('Conta de administrador desativada.', 'error')
                return render_template('admin_login.html')
            
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            session['admin_name'] = admin.full_name
            session['is_admin'] = True  # Flag para exibir menu Admin
            admin.update_last_login()
            
            if admin.must_change_password:
                flash('Por segurança, você deve alterar sua senha no primeiro acesso.', 'warning')
                return redirect(url_for('admin.admins_edit', admin_id=admin.id))

            flash(f'Bem-vindo, {admin.full_name}!', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Usuário ou senha inválidos.', 'error')
    
    return render_template('admin_login.html')


@admin_bp.route('/bootstrap', methods=['GET', 'POST'])
def bootstrap():
    """
    Cria o primeiro administrador do sistema (apenas quando ainda não existem admins).
    Protegido por BOOTSTRAP_TOKEN no .env.
    """
    # Se já existe admin, bootstrap não é mais permitido
    if AdminUser.query.count() > 0:
        return redirect(url_for('admin.login'))

    expected = os.getenv('BOOTSTRAP_TOKEN', '')
    if not expected:
        flash('Bootstrap desabilitado: defina BOOTSTRAP_TOKEN no .env.', 'error')
        return render_template('admin_bootstrap.html')

    if request.method == 'POST':
        provided = (request.form.get('bootstrap_token') or '').strip()
        if not secrets.compare_digest(provided, expected):
            flash('Token de bootstrap inválido.', 'error')
            return render_template('admin_bootstrap.html')

        username = (request.form.get('username') or '').strip()
        full_name = (request.form.get('full_name') or '').strip()
        password = (request.form.get('password') or '').strip()
        email = (request.form.get('email') or '').strip()

        if not username or not full_name or not password:
            flash('Preencha usuário, nome e senha.', 'error')
            return render_template('admin_bootstrap.html')

        if len(password) < 10:
            flash('A senha deve ter pelo menos 10 caracteres.', 'error')
            return render_template('admin_bootstrap.html')

        try:
            admin = AdminUser(
                username=username,
                full_name=full_name,
                email=email or None,
                must_change_password=False,
                is_active=True
            )
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()

            # Login imediato
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            session['admin_name'] = admin.full_name
            session['is_admin'] = True
            admin.update_last_login()

            flash('Administrador criado com sucesso!', 'success')
            return redirect(url_for('admin.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao criar admin: {e}', 'error')

    return render_template('admin_bootstrap.html')


@admin_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """Logout do administrador"""
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    session.pop('is_admin', None)  # Remove flag de admin
    flash('Logout realizado com sucesso.', 'success')
    return redirect(url_for('admin.login'))


# ==================== DASHBOARD ====================

@admin_bp.route('/')
@admin_required
def dashboard():
    """Dashboard administrativo"""
    # Importações necessárias (movidas para o topo para evitar UnboundLocalError)
    from models import InternetAccessLog, ESSERVIDORUser, FileServer
    
    admin = get_current_admin()
    
    # Estatísticas
    stats = {
        'total_users': ESSERVIDORUser.query.count(),
        'active_users': ESSERVIDORUser.query.filter_by(is_active=True).count(),
        'total_admins': AdminUser.query.count(),
        'logins_today': AccessLog.query.filter(
            AccessLog.action == 'login',
            AccessLog.success == True,
            AccessLog.timestamp >= datetime.utcnow().replace(hour=0, minute=0, second=0)
        ).count(),
        'logins_week': AccessLog.query.filter(
            AccessLog.action == 'login',
            AccessLog.success == True,
            AccessLog.timestamp >= datetime.utcnow() - timedelta(days=7)
        ).count(),
        'managed_devices': KnownDevice.query.filter_by(is_active=True).count(),
        'online_agents': KnownDevice.query.filter(
            KnownDevice.is_active == True,
            KnownDevice.last_report >= datetime.utcnow() - timedelta(minutes=10)
        ).count()
    }
    
    # Últimos acessos
    recent_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(10).all()
    
    # --- CACHE DE API DO ES-SERVIDOR (60s) ---
    now_ts = datetime.utcnow().timestamp()
    cache = getattr(current_app, '_esservidor_cache', {})
    
    if 'data' in cache and now_ts - cache['timestamp'] < 60:
        server_stats = cache['data']['server_stats']
        esservidor_online = cache['data']['esservidor_online']
        server_chart_data = cache['data']['chart_data']
    else:
        # Verificar se há algum servidor ES-SERVIDOR configurado e ativo
        from models import FileServer
        has_esservidor = FileServer.query.filter_by(
            server_type='es-servidor', 
            is_active=True
        ).first() is not None
        
        # Verificar conexão APENAS se houver servidor configurado
        esservidor_online = False
        server_stats = {'total_users': 0, 'smb_users': 0, 'shares': 0}
        server_chart_data = {'labels': [], 'action_counts': [], 'folders': [], 'counts': []}
        
        
        if has_esservidor:
            try:
                # Usa um timeout menor (3s) para o dashboard não travar
                esservidor = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, config.ESSERVIDOR_API_KEY, 3)
                esservidor_online = esservidor.check_connection()
            
                if esservidor_online:
                    success, users = esservidor.get_all_users()
                    if success:
                        non_builtin = [u for u in users if not u.get('builtin', False)]
                        server_stats['total_users'] = len(non_builtin)
                        server_stats['smb_users'] = len([u for u in non_builtin if u.get('smb', False)])
                    
                    success, shares = esservidor.get_smb_shares()
                    if success:
                        server_stats['shares'] = len(shares)
     
                    # Auditoria
                    _, audit_data = esservidor.get_audit_logs(limit=300) # Limite menor para rapidez
                    server_chart_data = {
                        'labels': ['Acessos', 'Edições', 'Criações', 'Deletados', 'Negados'],
                        'action_counts': [0, 0, 0, 0, 0],
                        'folders': [],
                        'counts': []
                    }
                    
                    if isinstance(audit_data, list):
                        path_counter = Counter()
                        for log in audit_data:
                            action = log.get('action', '')
                            if 'Acessou' in action: server_chart_data['action_counts'][0] += 1
                            elif 'Editou' in action: server_chart_data['action_counts'][1] += 1
                            elif 'Criou' in action: server_chart_data['action_counts'][2] += 1
                            elif 'Deletou' in action: server_chart_data['action_counts'][3] += 1
                            elif 'Negado' in action: server_chart_data['action_counts'][4] += 1
                            
                            p = log.get('path', 'N/A')
                            if p != 'N/A':
                                # Extrai a primeira pasta após a raiz (se houver)
                                # Ex: /share/folder1/file.txt -> share
                                # Ex: share/folder1/file.txt -> share
                                parts = [part for part in p.split('/') if part]
                                if parts:
                                    folder = parts[0]
                                    path_counter[folder] += 1
                        
                        top_paths = path_counter.most_common(5)
                        server_chart_data['folders'] = [p[0] for p in top_paths]
                        server_chart_data['counts'] = [p[1] for p in top_paths]
                
                # Salva no cache do app
                current_app._esservidor_cache = {
                    'timestamp': now_ts,
                    'data': {
                        'server_stats': server_stats,
                        'esservidor_online': esservidor_online,
                        'chart_data': server_chart_data
                    }
                }
            except Exception as e:
                current_app.logger.error(f"Erro no dashboard ES-SERVIDOR: {e}")

    # --- MONITORAMENTO DE TRÁFEGO (Novo) ---
    from models import InternetAccessLog, ESSERVIDORUser, FileServer
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0)
    
    # Valores padrão em caso de erro
    traffic_stats = {
        'total_requests': 0,
        'blocked_requests': 0,
        'top_user': 'N/A'
    }
    nas_servers = []
    
    try:
        traffic_stats['total_requests'] = InternetAccessLog.query.filter(InternetAccessLog.timestamp >= today_start).count()
        traffic_stats['blocked_requests'] = InternetAccessLog.query.filter(
            InternetAccessLog.timestamp >= today_start,
            InternetAccessLog.action == 'block'
        ).count()
        
        # Top usuário de hoje (simplificado para performance)
        top_user_query = db.session.query(
            InternetAccessLog.user_id, 
            db.func.count(InternetAccessLog.id).label('count')
        ).filter(
            InternetAccessLog.timestamp >= today_start
        ).group_by(InternetAccessLog.user_id).order_by(db.desc('count')).first()
        
        if top_user_query:
            user = ESSERVIDORUser.query.get(top_user_query[0])
            traffic_stats['top_user'] = user.username if user else 'Desconhecido'

        # --- SERVIDORES NAS (Novo) ---
        nas_servers = FileServer.query.filter_by(is_active=True).all()
        
        # Flag para exibir seção legado apenas se houver um ES-SERVIDOR configurado
        has_active_esservidor = any(s.server_type == 'es-servidor' for s in nas_servers)
        
    except Exception as e:
        current_app.logger.error(f"Erro ao carregar dados de monitoramento: {e}")
        has_active_esservidor = False
        # Mantém os valores padrão definidos acima

    return render_template('admin_dashboard.html', 
                         admin=admin, 
                         stats=stats,
                         traffic_stats=traffic_stats,
                         nas_servers=nas_servers,
                         has_active_esservidor=has_active_esservidor,
                         server_stats=server_stats,
                          recent_logs=recent_logs,
                          server_chart_data=server_chart_data,
                          esservidor_online=esservidor_online,
                          esservidor_ip=config.ESSERVIDOR_IP)



# ==================== GESTÃO DE USUÁRIOS ====================

@admin_bp.route('/users')
@admin_required
def users_list():
    """Lista de usuários ES-SERVIDOR cadastrados"""
    users = ESSERVIDORUser.query.order_by(ESSERVIDORUser.created_at.desc()).all()
    return render_template('admin_users.html', users=users, admin=get_current_admin())


@admin_bp.route('/users/new', methods=['GET', 'POST'])
@admin_required
def users_new():
    """Cadastrar novo usuário ES-SERVIDOR"""
    admin = get_current_admin()
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        api_key = request.form.get('api_key', '').strip()
        full_name = request.form.get('full_name', '').strip()
        notes = request.form.get('notes', '').strip()
        
        # Validações
        if not username or not password or not api_key:
            flash('Username, senha e API Key são obrigatórios.', 'error')
            return render_template('admin_user_form.html', admin=admin, user=None)
        
        if len(password) < 4:
            flash('A senha deve ter pelo menos 4 caracteres.', 'error')
            return render_template('admin_user_form.html', admin=admin, user=None)
        
        # Verificar se usuário já existe
        if ESSERVIDORUser.query.filter_by(username=username).first():
            flash('Este usuário já está cadastrado.', 'error')
            return render_template('admin_user_form.html', admin=admin, user=None)
        
        # Validar API Key no ES-SERVIDOR
        try:
            esservidor = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, api_key, config.API_TIMEOUT)
            valid, result = esservidor.validate_user_with_api_key(username, api_key)
            
            if not valid:
                flash(f'API Key inválida: {result}', 'error')
                return render_template('admin_user_form.html', admin=admin, user=None)
            
            # Se não foi fornecido nome, buscar do ES-SERVIDOR
            if not full_name:
                success, user_info = esservidor.get_user_info(username, api_key)
                if success:
                    full_name = user_info.get('full_name', username)
                else:
                    full_name = username
        except Exception as e:
            flash(f'Erro ao validar API Key: {str(e)}', 'error')
            return render_template('admin_user_form.html', admin=admin, user=None)
        
        # Criptografar API Key e salvar
        try:
            encrypted_key = encrypt_api_key(api_key)
            
            user = ESSERVIDORUser(
                username=username,
                api_key_encrypted=encrypted_key,
                full_name=full_name,
                notes=notes,
                created_by_id=admin.id
            )
            user.set_password(password)  # Define a senha do usuário
            
            db.session.add(user)
            db.session.commit()
            
            flash(f'Usuário {username} cadastrado com sucesso! Senha: {password}', 'success')
            return redirect(url_for('admin.users_list'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao salvar usuário: {str(e)}', 'error')
    
    return render_template('admin_user_form.html', admin=admin, user=None)


@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def users_edit(user_id):
    """Editar usuário ES-SERVIDOR"""
    admin = get_current_admin()
    user = ESSERVIDORUser.query.get_or_404(user_id)
    
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        password = request.form.get('password', '').strip()
        api_key = request.form.get('api_key', '').strip()
        notes = request.form.get('notes', '').strip()
        is_active = request.form.get('is_active') == 'on'
        
        # Atualizar nome e notas
        user.full_name = full_name if full_name else user.full_name
        user.notes = notes
        user.is_active = is_active
        
        # Se nova senha foi fornecida, atualizar
        if password:
            if len(password) < 4:
                flash('A senha deve ter pelo menos 4 caracteres.', 'error')
                return render_template('admin_user_form.html', admin=admin, user=user)
            user.set_password(password)
            flash('Senha atualizada.', 'info')
        
        # Se nova API Key foi fornecida, validar e atualizar
        if api_key:
            try:
                esservidor = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, api_key, config.API_TIMEOUT)
                valid, result = esservidor.validate_user_with_api_key(user.username, api_key)
                
                if not valid:
                    flash(f'Nova API Key inválida: {result}', 'error')
                    return render_template('admin_user_form.html', admin=admin, user=user)
                
                user.api_key_encrypted = encrypt_api_key(api_key)
                flash('API Key atualizada.', 'info')
            except Exception as e:
                flash(f'Erro ao validar nova API Key: {str(e)}', 'error')
                return render_template('admin_user_form.html', admin=admin, user=user)
        
        try:
            db.session.commit()
            flash(f'Usuário {user.username} atualizado!', 'success')
            return redirect(url_for('admin.users_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar: {str(e)}', 'error')
    
    return render_template('admin_user_form.html', admin=admin, user=user)


@admin_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def users_toggle(user_id):
    """Ativar/desativar usuário"""
    user = ESSERVIDORUser.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'ativado' if user.is_active else 'desativado'
    flash(f'Usuário {user.username} {status}.', 'success')
    return redirect(url_for('admin.users_list'))


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def users_delete(user_id):
    """Excluir usuário"""
    user = ESSERVIDORUser.query.get_or_404(user_id)
    username = user.username
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'Usuário {username} excluído.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir: {str(e)}', 'error')
    
    return redirect(url_for('admin.users_list'))


# ==================== LOGS ====================

@admin_bp.route('/logs')
@admin_required
def logs():
    """Visualização de logs de acesso"""
    admin = get_current_admin()
    
    # Filtros
    username_filter = request.args.get('username', '')
    action_filter = request.args.get('action', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    page = request.args.get('page', 1, type=int)
    
    # Query base
    query = AccessLog.query
    
    # Aplicar filtros
    if username_filter:
        query = query.filter(AccessLog.username.ilike(f'%{username_filter}%'))
    if action_filter:
        query = query.filter(AccessLog.action == action_filter)
    if date_from:
        try:
            dt_from = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(AccessLog.timestamp >= dt_from)
        except:
            pass
    if date_to:
        try:
            dt_to = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AccessLog.timestamp < dt_to)
        except:
            pass
    
    # Paginação
    logs = query.order_by(AccessLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    
    # Lista de ações para filtro
    actions = db.session.query(AccessLog.action).distinct().all()
    actions = [a[0] for a in actions]
    
    return render_template('admin_logs.html', 
                         admin=admin, 
                         logs=logs,
                         actions=actions,
                         filters={
                             'username': username_filter,
                             'action': action_filter,
                             'date_from': date_from,
                             'date_to': date_to
                         })


@admin_bp.route('/audit')
@admin_required
def audit_logs():
    """Visualização de atividades do servidor (Arquivos/Pastas)"""
    admin = get_current_admin()
    
    # Filtros via URL
    username = request.args.get('username', '')
    event_filter = request.args.get('event', '') # Ação (OPEN, RENAME, etc)
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    offset = (page - 1) * limit
    
    esservidor = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, config.ESSERVIDOR_API_KEY, config.API_TIMEOUT)
    
    # Construir filtros para a API do ES-SERVIDOR se necessário
    api_filters = []
    if username:
        api_filters.append(["user", "=", username])
    if event_filter:
        api_filters.append(["event", "=", event_filter])
        
    success, audit_data = esservidor.get_audit_logs(api_filters, limit=limit, offset=offset)
    
    if not success:
        flash(f'Erro ao carregar logs do ES-SERVIDOR: {audit_data}', 'error')
        audit_data = []

    # --- CACHE DE ESTATÍSTICAS DE AUDITORIA (2 min) ---
    now_ts = datetime.utcnow().timestamp()
    cache = getattr(current_app, '_audit_stats_cache', {})
    
    if 'stats' in cache and now_ts - cache['timestamp'] < 120:
        stats = cache['stats']
    else:
        stats = {'deletions': 0, 'creations': 0, 'edits': 0}
        _, recent_data = esservidor.get_audit_logs(limit=500)
        if isinstance(recent_data, list):
            for log in recent_data:
                action = log.get('action', '')
                if 'Deletou' in action: stats['deletions'] += 1
                elif 'Criou' in action: stats['creations'] += 1
                elif 'Editou' in action: stats['edits'] += 1
        
        current_app._audit_stats_cache = {'timestamp': now_ts, 'stats': stats}

    return render_template('admin_audit.html', 
                         admin=admin, 
                         logs=audit_data,
                         stats=stats,
                         filters={
                             'username': username,
                             'event': event_filter,
                             'page': page,
                             'limit': limit
                         })


@admin_bp.route('/api/audit/data')
@admin_required
def api_audit_data():
    """Endpoint JSON para atualização dinâmica dos logs"""
    username = request.args.get('username', '')
    event_filter = request.args.get('event', '')
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    offset = (page - 1) * limit
    
    esservidor = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, config.ESSERVIDOR_API_KEY, config.API_TIMEOUT)
    
    api_filters = []
    if username:
        api_filters.append(["user", "=", username])
    if event_filter:
        api_filters.append(["event", "=", event_filter])
        
    success, audit_data = esservidor.get_audit_logs(api_filters, limit=limit, offset=offset)
    
    if not success:
        return jsonify({'success': False, 'error': str(audit_data)})

    # Estatísticas rápidas
    stats = {'deletions': 0, 'creations': 0, 'edits': 0}
    _, recent_data = esservidor.get_audit_logs(limit=500)
    if isinstance(recent_data, list):
        for log in recent_data:
            action = log.get('action', '')
            if 'Deletou' in action: stats['deletions'] += 1
            elif 'Criou' in action: stats['creations'] += 1
            elif 'Editou' in action: stats['edits'] += 1

    return jsonify({
        'success': True,
        'logs': audit_data,
        'stats': stats
    })



# ==================== ARMAZENAMENTO (STORAGE) ====================

@admin_bp.route('/storage')
@admin_required
def storage():
    """Visualização de pools de armazenamento e datasets com cache"""
    admin = get_current_admin()
    
    # --- CACHE DE STORAGE (60s) ---
    now_ts = datetime.utcnow().timestamp()
    cache = getattr(current_app, '_storage_cache', {})
    
    if 'data' in cache and now_ts - cache['timestamp'] < 60:
        pools = cache['data']['pools']
        datasets = cache['data']['datasets']
        stats = cache['data']['stats']
    else:
        esservidor = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, config.ESSERVIDOR_API_KEY, config.API_TIMEOUT)
        
        # Obter pools
        pools_success, pools = esservidor.get_pools()
        if not pools_success:
            flash(f'Erro ao carregar pools: {pools}', 'error')
            pools = []
        
        # Obter datasets
        datasets_success, datasets = esservidor.get_datasets()
        if not datasets_success:
            flash(f'Erro ao carregar datasets: {datasets}', 'error')
            datasets = []
        
        # Calcular estatísticas gerais
        total_size = sum(p.get('size', 0) for p in pools)
        total_allocated = sum(p.get('allocated', 0) for p in pools)
        total_free = sum(p.get('free', 0) for p in pools)
        
        stats = {
            'total_pools': len(pools),
            'total_datasets': len(datasets),
            'total_size': total_size,
            'total_allocated': total_allocated,
            'total_free': total_free,
            'usage_percent': round((total_allocated / total_size * 100), 1) if total_size > 0 else 0
        }
        
        # Salva no cache
        current_app._storage_cache = {
            'timestamp': now_ts,
            'data': {
                'pools': pools,
                'datasets': datasets,
                'stats': stats
            }
        }
    
    return render_template('admin_storage.html',
                         admin=admin,
                         pools=pools,
                         datasets=datasets,
                         stats=stats)


# ==================== COMPARTILHAMENTOS SMB ====================

@admin_bp.route('/shares')
@admin_required
def shares():
    """Visualização de compartilhamentos SMB e permissões com cache"""
    admin = get_current_admin()
    
    # --- CACHE DE SHARES (60s) ---
    now_ts = datetime.utcnow().timestamp()
    cache = getattr(current_app, '_shares_cache', {})
    
    # Se quiser ver com ACLs completas, pode passar via flag (ex.: para forçar refresh)
    force_acls = request.args.get('acls', 'false').lower() == 'true'
    
    if not force_acls and 'data' in cache and now_ts - cache['timestamp'] < 60:
        shares_data = cache['data']['shares']
        smb_status = cache['data']['smb_status']
        stats = cache['data']['stats']
    else:
        esservidor = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, config.ESSERVIDOR_API_KEY, config.API_TIMEOUT)
        
        # Obter shares (sem ACL por padrão para ser rápido)
        shares_success, shares_data = esservidor.get_smb_shares_detailed(include_acls=force_acls)
        if not shares_success:
            flash(f'Erro ao carregar compartilhamentos: {shares_data}', 'error')
            shares_data = []
        
        # Obter status do SMB
        smb_success, smb_status = esservidor.get_smb_status()
        if not smb_success:
            smb_status = {'enable': False, 'workgroup': 'N/A', 'netbiosname': 'N/A'}
        
        stats = {
            'total_shares': len(shares_data),
            'active_shares': len([s for s in shares_data if s.get('enabled', False)]),
            'smb_enabled': smb_status.get('enable', False),
            'workgroup': smb_status.get('workgroup', 'N/A'),
            'netbiosname': smb_status.get('netbiosname', 'N/A')
        }
        
        # Salva no cache
        current_app._shares_cache = {
            'timestamp': now_ts,
            'data': {
                'shares': shares_data,
                'smb_status': smb_status,
                'stats': stats
            }
        }
    
    return render_template('admin_shares.html',
                         admin=admin,
                         shares=shares_data,
                         smb_status=smb_status,
                         stats=stats)


# ==================== USUÁRIOS DO SERVIDOR ====================

@admin_bp.route('/server-users')
@admin_required
def server_users():
    """Visualização de usuários e grupos do ES-SERVIDOR com cache"""
    admin = get_current_admin()
    
    # --- CACHE DE SERVER USERS (60s) ---
    now_ts = datetime.utcnow().timestamp()
    cache = getattr(current_app, '_server_users_cache', {})
    
    if 'data' in cache and now_ts - cache['timestamp'] < 60:
        users = cache['data']['users']
        groups = cache['data']['groups']
        stats = cache['data']['stats']
    else:
        esservidor = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, config.ESSERVIDOR_API_KEY, config.API_TIMEOUT)
        
        # Obter usuários
        users_success, users = esservidor.get_all_users()
        if not users_success:
            flash(f'Erro ao carregar usuários: {users}', 'error')
            users = []
        
        # Obter grupos
        groups_success, groups = esservidor.get_all_groups()
        if not groups_success:
            flash(f'Erro ao carregar grupos: {groups}', 'error')
            groups = []
            
        # Criar um mapeamento de GID -> Nome do Grupo
        group_map = {g.get('id'): g.get('name') for g in groups}
        
        # Processar usuários para garantir que grupos mostrem nomes em vez de IDs
        for user in users:
            formatted_groups = []
            current_groups = user.get('group_ids', [])
            for gid in current_groups:
                name = group_map.get(gid)
                if name:
                    formatted_groups.append(name)
                else:
                    formatted_groups.append(str(gid))
            
            if formatted_groups:
                user['groups'] = formatted_groups
        
        stats = {
            'total_users': len(users),
            'smb_users': len([u for u in users if u.get('smb', False)]),
            'locked_users': len([u for u in users if u.get('locked', False)]),
            'total_groups': len(groups),
            'smb_groups': len([g for g in groups if g.get('smb', False)])
        }
        
        # Salva no cache
        current_app._server_users_cache = {
            'timestamp': now_ts,
            'data': {
                'users': users,
                'groups': groups,
                'stats': stats
            }
        }
    
    # Filtragem de builtin não é cacheada para permitir troca dinâmica rápido (os dados base já estão em RAM)
    show_builtin = request.args.get('show_builtin', 'false').lower() == 'true'
    filtered_users = users
    filtered_groups = groups
    if not show_builtin:
        filtered_users = [u for u in users if not u.get('builtin', False)]
        filtered_groups = [g for g in groups if not g.get('builtin', False)]
    
    return render_template('admin_server_users.html',
                         admin=admin,
                         users=filtered_users,
                         groups=filtered_groups,
                         stats=stats,
                         show_builtin=show_builtin)


# ==================== GESTÃO DE ADMINISTRADORES ====================

@admin_bp.route('/admins')
@admin_required
def admins_list():
    """Lista de usuários administradores da intranet"""
    admins = AdminUser.query.order_by(AdminUser.created_at.desc()).all()
    return render_template('admin_admins.html', admins=admins, admin=get_current_admin())


@admin_bp.route('/admins/new', methods=['GET', 'POST'])
@admin_required
def admins_new():
    """Cadastrar novo administrador"""
    admin = get_current_admin()
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        
        if not username or not password or not full_name:
            flash('Usuário, senha e nome completo são obrigatórios.', 'error')
            return render_template('admin_admin_form.html', admin=admin, target_admin=None)
        
        if AdminUser.query.filter_by(username=username).first():
            flash('Este nome de usuário já está em uso.', 'error')
            return render_template('admin_admin_form.html', admin=admin, target_admin=None)
        
        try:
            new_admin = AdminUser(
                username=username,
                full_name=full_name,
                email=email,
                phone=phone
            )
            new_admin.set_password(password)
            db.session.add(new_admin)
            db.session.commit()
            flash(f'Administrador {username} criado com sucesso!', 'success')
            return redirect(url_for('admin.admins_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao salvar: {str(e)}', 'error')
    
    return render_template('admin_admin_form.html', admin=admin, target_admin=None)


@admin_bp.route('/admins/<int:admin_id>/edit', methods=['GET', 'POST'])
@admin_required
def admins_edit(admin_id):
    """Editar administrador"""
    admin = get_current_admin()
    target_admin = AdminUser.query.get_or_404(admin_id)
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        is_active = request.form.get('is_active') == 'on'
        
        if not username or not full_name:
            flash('Usuário e nome completo são obrigatórios.', 'error')
            return render_template('admin_admin_form.html', admin=admin, target_admin=target_admin)
        
        # Verificar se mudou username e se o novo já existe
        if username != target_admin.username:
            if AdminUser.query.filter_by(username=username).first():
                flash('Este nome de usuário já está sendo usado por outro administrador.', 'error')
                return render_template('admin_admin_form.html', admin=admin, target_admin=target_admin)
            target_admin.username = username
            
        target_admin.full_name = full_name
        target_admin.email = email
        target_admin.phone = phone
        
        # Impedir desativar a própria conta
        if admin_id == admin.id:
            target_admin.is_active = True
        else:
            target_admin.is_active = is_active
            
        if password:
            target_admin.set_password(password)
            target_admin.must_change_password = False
            flash('Senha atualizada.', 'info')
            
        try:
            db.session.commit()
            flash(f'Dados de {target_admin.username} atualizados!', 'success')
            return redirect(url_for('admin.admins_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar: {str(e)}', 'error')
            
    return render_template('admin_admin_form.html', admin=admin, target_admin=target_admin)


@admin_bp.route('/admins/<int:admin_id>/delete', methods=['POST'])
@admin_required
def admins_delete(admin_id):
    """Excluir administrador"""
    admin = get_current_admin()
    
    if admin_id == admin.id:
        flash('Você não pode excluir sua própria conta.', 'error')
        return redirect(url_for('admin.admins_list'))
        
    target_admin = AdminUser.query.get_or_404(admin_id)
    username = target_admin.username
    
    try:
        db.session.delete(target_admin)
        db.session.commit()
        flash(f'Administrador {username} excluído.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir: {str(e)}', 'error')
        
    return redirect(url_for('admin.admins_list'))


@admin_bp.route('/admins/<int:admin_id>/toggle', methods=['POST'])
@admin_required
def admins_toggle(admin_id):
    """Ativar/desativar administrador"""
    admin = get_current_admin()
    
    if admin_id == admin.id:
        flash('Você não pode desativar sua própria conta.', 'error')
        return redirect(url_for('admin.admins_list'))
        
    target_admin = AdminUser.query.get_or_404(admin_id)
    target_admin.is_active = not target_admin.is_active
    db.session.commit()
    
    status = 'ativado' if target_admin.is_active else 'desativado'
    flash(f'Administrador {target_admin.username} {status}.', 'success')
    return redirect(url_for('admin.admins_list'))


# ==================== CONFIGURAÇÃO SMTP ====================

@admin_bp.route('/settings/smtp', methods=['GET', 'POST'])
@admin_required
def smtp_settings():
    """Configurações do servidor de e-mail"""
    admin = get_current_admin()
    config_obj = SMTPConfig.query.first()
    
    if request.method == 'POST':
        smtp_server = request.form.get('smtp_server', '').strip()
        smtp_port = int(request.form.get('smtp_port', 587))
        smtp_user = request.form.get('smtp_user', '').strip()
        smtp_password = request.form.get('smtp_password', '')
        from_email = request.form.get('from_email', '').strip()
        from_name = request.form.get('from_name', '').strip()
        use_tls = request.form.get('use_tls') == 'on'
        
        if not config_obj:
            config_obj = SMTPConfig()
            db.session.add(config_obj)
            
        config_obj.smtp_server = smtp_server
        config_obj.smtp_port = smtp_port
        config_obj.smtp_user = smtp_user
        config_obj.from_email = from_email
        config_obj.from_name = from_name
        config_obj.use_tls = use_tls
        
        if smtp_password:
            # Reutiliza a função de criptografia de API Key para a senha do SMTP
            from database import encrypt_api_key
            config_obj.smtp_password_encrypted = encrypt_api_key(smtp_password)
            
        try:
            db.session.commit()
            flash('Configurações SMTP salvas com sucesso!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao salvar: {str(e)}', 'error')
            
    return render_template('admin_smtp.html', admin=admin, config=config_obj)


@admin_bp.route('/settings/smtp/test', methods=['POST'])
@admin_required
def smtp_test():
    """Testa a conexão SMTP enviando um e-mail de teste"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from database import decrypt_api_key
    
    server = request.form.get('smtp_server')
    port = int(request.form.get('smtp_port', 587))
    user = request.form.get('smtp_user')
    password = request.form.get('smtp_password')
    from_email = request.form.get('from_email')
    use_tls = request.form.get('use_tls') == 'on'
    
    # Se senha vazia, tenta pegar a salva
    if not password:
        config_obj = SMTPConfig.query.first()
        if config_obj and config_obj.smtp_password_encrypted:
            try:
                password = decrypt_api_key(config_obj.smtp_password_encrypted)
            except:
                return jsonify({'success': False, 'message': 'Erro ao descriptografar senha salva'})
    
    if not password or not server:
        return jsonify({'success': False, 'message': 'Servidor e senha são necessários para o teste'})
    
    try:
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = from_email # Envia para si mesmo
        msg['Subject'] = 'Teste de Conexão - Intranet ES-SERVIDOR'
        
        body = f"Este é um e-mail de teste enviado pela Intranet ES-SERVIDOR.\nData: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
        msg.attach(MIMEText(body, 'plain'))
        
        smtp = smtplib.SMTP(server, port, timeout=10)
        if use_tls:
            smtp.starttls()
            
        if user and password:
            smtp.login(user, password)
            
        smtp.send_message(msg)
        smtp.quit()
        
        return jsonify({'success': True, 'message': 'E-mail de teste enviado com sucesso!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


# ==================== GESTÃO DE RELATÓRIOS ====================

@admin_bp.route('/reports/schedules')
@admin_required
def report_schedules():
    """Lista agendamentos de relatórios"""
    admin = get_current_admin()
    schedules = ReportSchedule.query.all()
    return render_template('admin_reports.html', admin=admin, schedules=schedules)


@admin_bp.route('/reports/schedules/new', methods=['GET', 'POST'])
@admin_required
def reports_new():
    """Cria novo agendamento de relatório"""
    admin = get_current_admin()
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        frequency = request.form.get('frequency', 'daily')
        recipients = request.form.get('recipients', '').strip()
        
        if not name or not recipients:
            flash('Nome e destinatários são obrigatórios.', 'error')
            return render_template('admin_report_form.html', admin=admin, schedule=None)
            
        new_sched = ReportSchedule(
            name=name,
            frequency=frequency,
            report_type=request.form.get('report_type', 'server_activity'),
            custom_days=int(request.form.get('custom_days', 0)) if frequency == 'custom' else 0,
            recipients=recipients
        )
        # Calcula próxima execução (simplificado)
        now = datetime.utcnow()
        if frequency == 'daily':
            new_sched.next_run = now + timedelta(days=1)
        elif frequency == 'weekly':
            new_sched.next_run = now + timedelta(weeks=1)
        elif frequency == 'monthly':
            new_sched.next_run = now + timedelta(days=30)
        else:
            days = int(request.form.get('custom_days', 1))
            new_sched.next_run = now + timedelta(days=days)
            
        db.session.add(new_sched)
        db.session.commit()
        flash('Agendamento criado!', 'success')
        return redirect(url_for('admin.report_schedules'))
        
    return render_template('admin_report_form.html', admin=admin, schedule=None)


@admin_bp.route('/reports/schedules/<int:schedule_id>/edit', methods=['GET', 'POST'])
@admin_required
def reports_edit(schedule_id):
    """Edita um agendamento de relatório"""
    admin = get_current_admin()
    schedule = ReportSchedule.query.get_or_404(schedule_id)
    
    if request.method == 'POST':
        schedule.name = request.form.get('name', '').strip()
        schedule.frequency = request.form.get('frequency', 'daily')
        schedule.report_type = request.form.get('report_type', 'server_activity')
        schedule.custom_days = int(request.form.get('custom_days', 0)) if schedule.frequency == 'custom' else 0
        schedule.recipients = request.form.get('recipients', '').strip()
        schedule.is_active = request.form.get('is_active') == 'on'
        
        try:
            db.session.commit()
            flash('Agendamento atualizado!', 'success')
            return redirect(url_for('admin.report_schedules'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao salvar: {str(e)}', 'error')
            
    return render_template('admin_report_form.html', admin=admin, schedule=schedule)


@admin_bp.route('/reports/schedules/<int:schedule_id>/send-manual', methods=['POST'])
@admin_required
def report_send_manual(schedule_id):
    """Dispara o envio manual de um relatório agendado"""
    schedule = ReportSchedule.query.get_or_404(schedule_id)
    success, message = send_report(schedule)
    
    if success:
        schedule.last_run = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'message': 'Relatório enviado com sucesso!'})
    else:
        return jsonify({'success': False, 'message': message})


def send_report(schedule):
    """Lógica principal para gerar e enviar o relatório por e-mail"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from database import decrypt_api_key
    from models import SMTPConfig, InternetAccessLog, AccessLog, ReportLog
    from collections import Counter
    
    # 1. Obter config SMTP
    smtp = SMTPConfig.query.first()
    if not smtp: return False, "Configuração SMTP não encontrada"
    try:
        smtp_password = decrypt_api_key(smtp.smtp_password_encrypted)
    except: return False, "Erro ao descriptografar senha SMTP"
    
    # 2. Período
    end_date = datetime.now(timezone.utc)
    if schedule.frequency == 'daily': start_date = end_date - timedelta(days=1)
    elif schedule.frequency == 'weekly': start_date = end_date - timedelta(weeks=1)
    elif schedule.frequency == 'monthly': start_date = end_date - timedelta(days=30)
    elif schedule.frequency == 'custom' and schedule.custom_days > 0: start_date = end_date - timedelta(days=schedule.custom_days)
    else: start_date = end_date - timedelta(days=1)
    
    start_date_naive = start_date.replace(tzinfo=None)
    
    # 3. Gerar conteúdo baseado no tipo
    if schedule.report_type == 'internet_monitoring':
        # Relatório de Internet
        total_requests = InternetAccessLog.query.filter(InternetAccessLog.timestamp >= start_date_naive).count()
        unique_devices = db.session.query(InternetAccessLog.ip_address).filter(InternetAccessLog.timestamp >= start_date_naive).distinct().count()
        
        top_sites = db.session.query(InternetAccessLog.website, db.func.count(InternetAccessLog.id).label('total'))\
            .filter(InternetAccessLog.timestamp >= start_date_naive)\
            .group_by(InternetAccessLog.website)\
            .order_by(db.desc('total')).limit(10).all()
            
        top_devices = db.session.query(InternetAccessLog.ip_address, InternetAccessLog.hostname, db.func.count(InternetAccessLog.id).label('total'))\
            .filter(InternetAccessLog.timestamp >= start_date_naive)\
            .group_by(InternetAccessLog.ip_address, InternetAccessLog.hostname)\
            .order_by(db.desc('total')).limit(10).all()
            
        html_body = render_template('email_monitoring_report.html',
                                   report_name=schedule.name,
                                   start_date=start_date.strftime('%d/%m/%Y'),
                                   end_date=end_date.strftime('%d/%m/%Y'),
                                   stats={'total_requests': total_requests, 'unique_devices': unique_devices},
                                   top_sites=top_sites,
                                   top_devices=top_devices)
    else:
        # Relatório de Servidor (Código original refatorado)
        from esservidor_api import ESSERVIDORAPI
        from config import ESSERVIDOR_API_URL, ESSERVIDOR_API_KEY, API_TIMEOUT
        esservidor = ESSERVIDORAPI(ESSERVIDOR_API_URL, ESSERVIDOR_API_KEY, timeout=API_TIMEOUT)
        
        success, tn_logs = esservidor.get_audit_logs(limit=2000)
        local_logs = AccessLog.query.filter(AccessLog.timestamp >= start_date_naive).order_by(AccessLog.timestamp.desc()).limit(100).all()
        
        combined_logs = []
        if success and isinstance(tn_logs, list):
            for entry in tn_logs:
                log_dt = entry.get('dt')
                if log_dt and start_date <= log_dt <= end_date:
                    entry['timestamp'] = log_dt.replace(tzinfo=None)
                    combined_logs.append(entry)
        
        for l in local_logs:
            combined_logs.append({
                'username': l.username, 'action': f'Login Intranet' if l.action == 'login' else l.action,
                'success': True if l.action == 'login' else l.success, 'timestamp': l.timestamp,
                'path': 'Painel Web' 
            })
        combined_logs.sort(key=lambda x: x.get('timestamp') or datetime.min, reverse=True)
        
        activity_counts = Counter()
        folder_counts = Counter()
        for log in combined_logs:
            act = log.get('action', '')
            if 'Acessou' in act: activity_counts['Acessou'] += 1
            elif 'Editou' in act: activity_counts['Editou'] += 1
            elif 'Criou' in act: activity_counts['Criou'] += 1
            elif 'Deletou' in act: activity_counts['Deletou'] += 1
            elif 'Acesso Negado' in act: activity_counts['Negados'] += 1
            
            p = log.get('path', '')
            if p and p not in ['N/A', 'Painel Web', '.', '']:
                root = p.split('/')[0] if '/' in p else p
                folder_counts[root] += 1
        
        total_acts = sum(activity_counts.values()) or 1
        activity_stats = [
            {'label': 'Acessos', 'count': activity_counts['Acessou'], 'pct': int((activity_counts['Acessou']/total_acts)*100), 'color': '#3b82f6'},
            {'label': 'Edições', 'count': activity_counts['Editou'], 'pct': int((activity_counts['Editou']/total_acts)*100), 'color': '#10b981'},
            {'label': 'Criações', 'count': activity_counts['Criou'], 'pct': int((activity_counts['Criações'] if 'Criações' in activity_counts else activity_counts['Criou'])/total_acts*100), 'color': '#f59e0b'},
            {'label': 'Deletados', 'count': activity_counts['Deletou'], 'pct': int((activity_counts['Deletou']/total_acts)*100), 'color': '#ef4444'},
            {'label': 'Negados', 'count': activity_counts['Negados'], 'pct': int((activity_counts['Negados']/total_acts)*100), 'color': '#6366f1'}
        ]
        
        top_folders = [{'label': f[0], 'count': f[1], 'pct': int((f[1]/max([x[1] for x in folder_counts.most_common(5)] or [1]))*100)} for f in folder_counts.most_common(5)]
        
        stats = {'total': len(combined_logs), 'success': len([l for l in combined_logs if l.get('success', True)]), 'failure': len([l for l in combined_logs if not l.get('success', False)])}
        
        html_body = render_template('email_report_template.html',
                                  report_name=schedule.name, server_info="ES-SERVIDOR",
                                  start_date=start_date.strftime('%d/%m/%Y'), end_date=end_date.strftime('%d/%m/%Y'),
                                  stats=stats, activity_stats=activity_stats, folder_stats=top_folders, recent_logs=combined_logs[:15])

    # 4. Enviar E-mail
    recipients = [r.strip() for r in schedule.recipients.split(',') if r.strip()]
    for recipient in recipients:
        try:
            msg = MIMEMultipart()
            msg['From'] = f"{smtp.from_name} <{smtp.from_email}>"
            msg['To'] = recipient
            msg['Subject'] = f"Relatório: {schedule.name}"
            msg.attach(MIMEText(html_body, 'html'))
            
            with smtplib.SMTP(smtp.smtp_server, smtp.smtp_port, timeout=20) as server:
                if smtp.use_tls: server.starttls()
                if smtp.smtp_user and smtp_password: server.login(smtp.smtp_user, smtp_password)
                server.send_message(msg)
            
            db.session.add(ReportLog(schedule_id=schedule.id, recipient=recipient, status='success'))
        except Exception as e:
            db.session.add(ReportLog(schedule_id=schedule.id, recipient=recipient, status='failure', error_message=str(e)))
            
    db.session.commit()
    return True, "Enviado com sucesso"


# ==================== CONFIGURAÇÃO DA PLATAFORMA ====================

@admin_bp.route('/settings/platform', methods=['GET', 'POST'])
@admin_required
def platform_settings():
    """Configurações visuais da plataforma (Título, Logo, Favicon)"""
    from models import SystemSetting
    admin = get_current_admin()
    
    if request.method == 'POST':
        title = request.form.get('site_title', 'ES-SERVIDOR').strip()
        SystemSetting.set_value('site_title', title)
        
        # Upload de Logo
        logo_file = request.files.get('site_logo')
        if logo_file and logo_file.filename:
            filename = secure_filename(f"logo_{logo_file.filename}")
            filepath = os.path.join(current_app.static_folder, 'images', filename)
            logo_file.save(filepath)
            SystemSetting.set_value('site_logo', f'/static/images/{filename}')
            
        # Upload de Favicon
        favicon_file = request.files.get('site_favicon')
        if favicon_file and favicon_file.filename:
            filename = secure_filename(f"fav_{favicon_file.filename}")
            filepath = os.path.join(current_app.static_folder, 'images', filename)
            favicon_file.save(filepath)
            SystemSetting.set_value('site_favicon', f'/static/images/{filename}')
            
        flash('Configurações da plataforma atualizadas com sucesso!', 'success')
        return redirect(url_for('admin.platform_settings'))
        
    settings = {
        'site_title': SystemSetting.get_value('site_title', 'ES-SERVIDOR'),
        'site_logo': SystemSetting.get_value('site_logo', '/static/images/logo.png'),
        'site_favicon': SystemSetting.get_value('site_favicon', '/static/images/logo.png')
    }
    
    return render_template('admin_platform.html', admin=admin, settings=settings)


# ==================== MONITORAMENTO DE INTERNET ====================

@admin_bp.route('/monitoring')
@admin_required
def monitoring_dashboard():
    """Dashboard de monitoramento de internet enriquecido com cache"""
    from models import InternetAccessLog, InternetSource, KnownDevice
    from datetime import datetime, timedelta
    admin = get_current_admin()
    
    # --- CACHE DE MONITORAMENTO (5 min) ---
    now_ts = datetime.utcnow().timestamp()
    cache = getattr(current_app, '_monitoring_cache', {})
    
    if 'stats' in cache and now_ts - cache['timestamp'] < 300:
        stats = cache['stats']
        known_devices = cache['known_devices']
    else:
        # Estatísticas rápidas
        now = datetime.utcnow()
        today = now.replace(hour=0, minute=0, second=0)
        last_24h = now - timedelta(hours=24)
        
        # Horas para o gráfico (últimas 24h) - Otimizado em 1 única query
        from sqlalchemy import func
        
        hourly_counts = db.session.query(
            func.strftime('%H:00', InternetAccessLog.timestamp).label('hour'),
            func.count(InternetAccessLog.id).label('count')
        ).filter(
            InternetAccessLog.timestamp >= last_24h
        ).group_by('hour').all()
        
        # Mapeia resultados para o formato esperado pelo Chart.js (preservando ordem cronológica)
        counts_map = {h: c for h, c in hourly_counts}
        hours_data = []
        labels = []
        
        for i in range(23, -1, -1):
            h_label = (now - timedelta(hours=i)).strftime('%H:00')
            labels.append(h_label)
            hours_data.append(counts_map.get(h_label, 0))

        # Identificação de dispositivos conhecidos
        known_macs = [d.mac_address for d in KnownDevice.query.all()]
        
        # Total de requisições por dispositivo (para separar conhecido/desconhecido)
        device_requests = db.session.query(InternetAccessLog.mac_address, db.func.count(InternetAccessLog.id))\
            .filter(InternetAccessLog.timestamp >= today)\
            .group_by(InternetAccessLog.mac_address).all()
        
        known_count = 0
        unknown_count = 0
        for mac, count in device_requests:
            if mac in known_macs:
                known_count += count
            else:
                unknown_count += count

        # Distribuição por categoria (apenas conhecidos)
        category_data = db.session.query(KnownDevice.category, db.func.count(InternetAccessLog.id))\
            .join(InternetAccessLog, KnownDevice.mac_address == InternetAccessLog.mac_address)\
            .filter(InternetAccessLog.timestamp >= today)\
            .group_by(KnownDevice.category).all()
        
        cat_labels = [c[0].capitalize() for c in category_data]
        cat_counts = [c[1] for c in category_data]

        stats = {
            'total_requests_today': InternetAccessLog.query.filter(InternetAccessLog.timestamp >= today).count(),
            'active_sources': InternetSource.query.filter_by(is_active=True).count(),
            'known_vs_unknown': [known_count, unknown_count],
            'category_labels': cat_labels,
            'category_data': cat_counts,
            'top_sites': db.session.query(InternetAccessLog.website, db.func.count(InternetAccessLog.id).label('total'))\
                .filter(InternetAccessLog.timestamp >= today, InternetAccessLog.website != None)\
                .group_by(InternetAccessLog.website)\
                .order_by(db.desc('total')).limit(8).all(),
            # Separa dispositivos para filtragem
            'known_devices_stats': [list(row) for row in db.session.query(InternetAccessLog.ip_address, InternetAccessLog.hostname, InternetAccessLog.mac_address, db.func.count(InternetAccessLog.id).label('total'))\
                .filter(InternetAccessLog.timestamp >= today, InternetAccessLog.mac_address.in_(known_macs))\
                .group_by(InternetAccessLog.ip_address, InternetAccessLog.hostname, InternetAccessLog.mac_address)\
                .order_by(db.desc('total')).limit(20).all()],
            'unknown_devices_stats': [list(row) for row in db.session.query(InternetAccessLog.ip_address, InternetAccessLog.hostname, InternetAccessLog.mac_address, db.func.count(InternetAccessLog.id).label('total'))\
                .filter(InternetAccessLog.timestamp >= today, ~InternetAccessLog.mac_address.in_(known_macs))\
                .group_by(InternetAccessLog.ip_address, InternetAccessLog.hostname, InternetAccessLog.mac_address)\
                .order_by(db.desc('total')).limit(20).all()],
            'hostname_distribution': [[row[0], row[1]] for row in db.session.query(InternetAccessLog.hostname, db.func.count(InternetAccessLog.id).label('total'))\
                .filter(InternetAccessLog.timestamp >= today)\
                .group_by(InternetAccessLog.hostname)\
                .order_by(db.desc('total')).all()],
            'chart_labels': labels,
            'chart_data': hours_data
        }
        
        # --- TOP DEVICES COM PRIORIDADE PARA CONHECIDOS ---
        # Mapa de MAC -> hostname cadastrado (KnownDevice)
        known_devices_map = {d.mac_address.upper(): d.hostname for d in KnownDevice.query.all()}
        
        # Busca dispositivos conhecidos primeiro (usando hostname cadastrado)
        known_device_rows = db.session.query(
            InternetAccessLog.ip_address,
            InternetAccessLog.mac_address,
            db.func.count(InternetAccessLog.id).label('total')
        ).filter(
            InternetAccessLog.timestamp >= today,
            InternetAccessLog.mac_address.in_(known_macs)
        ).group_by(InternetAccessLog.ip_address, InternetAccessLog.mac_address)\
         .order_by(db.desc('total')).limit(10).all()
        
        top_devices = []
        for row in known_device_rows:
            mac = row[1].upper() if row[1] else None
            hostname = known_devices_map.get(mac, 'Dispositivo Conhecido')
            top_devices.append([row[0], hostname, row[1], row[2]])
        
        # Se não atingiu 10, completa com desconhecidos
        remaining_slots = 10 - len(top_devices)
        if remaining_slots > 0:
            unknown_device_rows = db.session.query(
                InternetAccessLog.ip_address,
                InternetAccessLog.hostname,
                InternetAccessLog.mac_address,
                db.func.count(InternetAccessLog.id).label('total')
            ).filter(
                InternetAccessLog.timestamp >= today,
                ~InternetAccessLog.mac_address.in_(known_macs) if known_macs else True
            ).group_by(InternetAccessLog.ip_address, InternetAccessLog.hostname, InternetAccessLog.mac_address)\
             .order_by(db.desc('total')).limit(remaining_slots).all()
            
            for row in unknown_device_rows:
                top_devices.append([row[0], row[1] or 'Desconhecido', row[2], row[3]])
        
        stats['top_devices'] = top_devices
        
        # Mapa de dispositivos conhecidos para ícones
        known_devices = {d.mac_address: d.category for d in KnownDevice.query.all()}
        
        # Salva no cache
        current_app._monitoring_cache = {
            'timestamp': now_ts,
            'stats': stats,
            'known_devices': known_devices
        }
    
    return render_template('admin_monitoring_dashboard.html', admin=admin, stats=stats, known_devices=known_devices)


@admin_bp.route('/monitoring/logs')
@admin_required
def monitoring_logs():
    """Logs detalhados de acesso à internet"""
    from models import InternetAccessLog
    admin = get_current_admin()
    
    # Filtros
    ip_filter = request.args.get('ip', '')
    hostname_filter = request.args.get('hostname', '')
    site_filter = request.args.get('site', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    page = request.args.get('page', 1, type=int)
    
    query = InternetAccessLog.query
    
    if ip_filter:
        query = query.filter(InternetAccessLog.ip_address.ilike(f'%{ip_filter}%'))
    if hostname_filter:
        query = query.filter(InternetAccessLog.hostname.ilike(f'%{hostname_filter}%'))
    if site_filter:
        query = query.filter(InternetAccessLog.website.ilike(f'%{site_filter}%'))
    if date_from:
        try:
            query = query.filter(InternetAccessLog.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
        except: pass
    if date_to:
        try:
            query = query.filter(InternetAccessLog.timestamp < datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1))
        except: pass
        
    logs = query.order_by(InternetAccessLog.timestamp.desc()).paginate(page=page, per_page=50)
    
    # Mapa de dispositivos conhecidos para ícones corretos
    from models import KnownDevice
    known_devices = {d.mac_address: d.category for d in KnownDevice.query.all()}
    
    return render_template('admin_monitoring_logs.html', admin=admin, logs=logs, known_devices=known_devices, filters=request.args)


@admin_bp.route('/monitoring/device/<string:identifier>')
@admin_required
def monitoring_device_details(identifier):
    """Página de visualização detalhada de um dispositivo específico"""
    from models import InternetAccessLog, KnownDevice
    from sqlalchemy import func
    admin = get_current_admin()
    
    # Tentamos encontrar o dispositivo pelo Hostname (já que KnownDevice não tem ip_address)
    device = KnownDevice.query.filter(
        KnownDevice.hostname == identifier
    ).first()
    
    # Se não encontrar por hostname, e parecer um IP, tentamos buscar o hostname associado nos logs
    if not device and '.' in identifier:
        # Buscar todos os logs deste IP que tenham MAC address
        log_entries = InternetAccessLog.query.filter(
            InternetAccessLog.ip_address == identifier,
            InternetAccessLog.mac_address.isnot(None),
            InternetAccessLog.mac_address != ""
        ).all()
        
        # Tentar encontrar o dispositivo pelo MAC de qualquer log
        for log_entry in log_entries:
            if log_entry.mac_address:
                device = KnownDevice.query.filter_by(mac_address=log_entry.mac_address).first()
                if device:
                    break
        
        # Se ainda não encontrou, tentar buscar pelo hostname nos logs
        if not device:
            log_with_hostname = InternetAccessLog.query.filter(
                InternetAccessLog.ip_address == identifier,
                InternetAccessLog.hostname.isnot(None),
                InternetAccessLog.hostname != ""
            ).first()
            
            if log_with_hostname and log_with_hostname.hostname:
                device = KnownDevice.query.filter(
                    KnownDevice.hostname == log_with_hostname.hostname
                ).first()
    
    # Se não for um dispositivo cadastrado, criamos um objeto temporário para o template
    if not device:
        # Tenta identificar se é IP ou Hostname para melhor exibição
        is_ip = '.' in identifier and identifier.replace('.', '').isdigit()
        
        # Tenta buscar o hostname real e MAC nos registros de acesso recentes
        detected_hostname = None
        detected_mac = None
        if is_ip:
            last_log = InternetAccessLog.query.filter(
                InternetAccessLog.ip_address == identifier,
                InternetAccessLog.hostname.isnot(None),
                InternetAccessLog.hostname != ""
            ).order_by(InternetAccessLog.timestamp.desc()).first()
            if last_log:
                detected_hostname = last_log.hostname
                detected_mac = last_log.mac_address

        device = KnownDevice(
            hostname=detected_hostname or (identifier if not is_ip else 'Dispositivo Desconhecido'),
            mac_address=detected_mac or '',
            category='other'
        )
        # Atribuímos o IP manualmente se necessário (apenas para exibição no template, não salvamos)
        if is_ip:
            device.temp_ip = identifier

    # Estatísticas de Acesso
    logs_query = InternetAccessLog.query.filter(
        (InternetAccessLog.ip_address == identifier) | 
        (InternetAccessLog.hostname == identifier)
    )
    
    total_requests = logs_query.count()
    
    # Top Sites
    top_sites = logs_query.with_entities(
        InternetAccessLog.website, 
        func.count(InternetAccessLog.id).label('hit_count'),
        func.sum(InternetAccessLog.duration).label('total_duration'),
        func.max(InternetAccessLog.timestamp).label('last_access')
    ).group_by(InternetAccessLog.website).order_by(func.count(InternetAccessLog.id).desc()).limit(10).all()
    
    # Logs recentes para a tabela
    recent_logs = logs_query.order_by(InternetAccessLog.timestamp.desc()).limit(100).all()

    # Geração de Insight por IA (Protótipo/Simulado)
    from ai_service import AIService
    import markdown
    raw_summary = AIService.generate_device_summary(identifier, top_sites)
    
    # Processa o markdown e adiciona suporte a alertas do GitHub (simplificado)
    ai_summary = markdown.markdown(raw_summary, extensions=['extra', 'nl2br'])
    
    # Substituição para os alertas do GitHub (ex: > [!TIP]) para classes CSS
    ai_summary = ai_summary.replace('<blockquote>\n<p>[!TIP]', '<div class="ai-tip"><strong>💡 Dica do Sistema:</strong><br>')
    ai_summary = ai_summary.replace('</p>\n</blockquote>', '</div>')
    
    return render_template('admin_monitoring_device_details.html',
                         admin=admin,
                         device=device,
                         identifier=identifier,
                         total_requests=total_requests,
                         top_sites=top_sites,
                         recent_logs=recent_logs,
                         ai_summary=ai_summary)


@admin_bp.route('/monitoring/network-map')
@admin_required
def monitoring_network_map():
    """Visão topológica da rede"""
    from models import InternetSource, KnownDevice
    admin = get_current_admin()
    sources = InternetSource.query.filter_by(is_active=True).all()
    devices = KnownDevice.query.filter_by(is_active=True).all()
    
    return render_template('admin_network_map.html', 
                         admin=admin, 
                         sources=sources, 
                         devices=devices)


@admin_bp.route('/monitoring/reports/productivity')
@admin_required
def monitoring_report_productivity():
    """Relatório de produtividade correlacionando Agente + Logs"""
    from models import InternetAccessLog, KnownDevice
    from ai_service import AIService
    from sqlalchemy import func
    admin = get_current_admin()
    
    days = request.args.get('days', 7, type=int)
    since = datetime.utcnow() - timedelta(days=days)
    
    # Query agregada por MAC e Website
    stats_query = db.session.query(
        InternetAccessLog.mac_address,
        InternetAccessLog.website,
        func.count(InternetAccessLog.id).label('hits'),
        func.sum(InternetAccessLog.duration).label('total_duration')
    ).filter(
        InternetAccessLog.timestamp >= since,
        InternetAccessLog.mac_address.isnot(None),
        InternetAccessLog.mac_address != ""
    ).group_by(
        InternetAccessLog.mac_address,
        InternetAccessLog.website
    ).order_by(func.count(InternetAccessLog.id).desc()).all()
    
    # Mapear MAC para Nome de Usuário (via Agente)
    devices = {d.mac_address: d for d in KnownDevice.query.all()}
    
    # Processar dados para o template
    user_report = {}
    for mac, site, hits, duration in stats_query:
        device = devices.get(mac)
        user_name = device.logged_user if device and device.logged_user else (device.hostname if device else f"MAC: {mac}")
        
        if user_name not in user_report:
            user_report[user_name] = {
                'name': user_name,
                'device_name': device.hostname if device else '?',
                'sites': [],
                'categories': {},  # Novo: Agregado por categoria
                'total_hits': 0,
                'total_sec': 0,
                'productivity_score': 0,
                'ai_insight': ""
            }
        
        # Obter insight do domínio para categorização
        insight = AIService.get_domain_insight(site)
        category = insight.category if insight else "Outros"
        is_productive = insight.is_productive if insight else False
        icon = insight.icon if insight else "🌐"
        
        # Atualizar estatísticas de categoria
        if category not in user_report[user_name]['categories']:
            user_report[user_name]['categories'][category] = {
                'name': category,
                'hits': 0,
                'duration': 0,
                'icon': icon,
                'is_productive': is_productive
            }
        
        user_report[user_name]['categories'][category]['hits'] += hits
        user_report[user_name]['categories'][category]['duration'] += (duration or 0)
        
        user_report[user_name]['sites'].append({
            'domain': site,
            'hits': hits,
            'duration': duration or 0,
            'category': category,
            'icon': icon,
            'is_productive': is_productive
        })
        user_report[user_name]['total_hits'] += hits
        user_report[user_name]['total_sec'] += (duration or 0)

    # Calcular Scores e Métas de IA
    for user_name, data in user_report.items():
        # Cálculo de Score: (Hits Produtivos / Total Hits) * 100
        productive_hits = sum(cat['hits'] for cat in data['categories'].values() if cat['is_productive'])
        if data['total_hits'] > 0:
            data['productivity_score'] = int((productive_hits / data['total_hits']) * 100)
        
        # Gerar insight da IA
        data['ai_insight'] = AIService.generate_user_productivity_insight(data['categories'])
        
        # Converter categorias para lista para o template
        data['categories_list'] = sorted(data['categories'].values(), key=lambda x: x['hits'], reverse=True)

    # Ordenar por usuários mais ativos
    sorted_users = sorted(user_report.values(), key=lambda x: x['total_hits'], reverse=True)

    return render_template('admin_report_productivity.html', 
                         admin=admin, 
                         users=sorted_users,
                         days=days)


@admin_bp.route('/monitoring/sources', methods=['GET', 'POST'])
@admin_required
def monitoring_sources():
    """Gerenciamento de fontes de monitoramento (Roteadores/Proxies)"""
    from models import InternetSource
    admin = get_current_admin()
    
    if request.method == 'POST':
        name = request.form.get('name')
        stype = request.form.get('source_type')
        provider = request.form.get('provider')
        host = request.form.get('host')
        port = request.form.get('port', type=int)
        username = request.form.get('username')
        password = request.form.get('password') # Senha ou API Key
        
        from core.services.security import encrypt_credential
        
        # Cria a fonte com os parâmetros de conexão
        source = InternetSource(
            name=name,
            source_type=stype,
            provider=provider,
            host=host,
            port=port,
            username=username,
            password_encrypted=encrypt_credential(password),
            is_active=True
        )
        db.session.add(source)
        db.session.commit()
        flash(f'Integração {name} ({provider}) configurada com sucesso!', 'success')
        return redirect(url_for('admin.monitoring_sources'))
        
    sources = InternetSource.query.all()
    return render_template('admin_monitoring_sources.html', admin=admin, sources=sources)


@admin_bp.route('/monitoring/sources/delete/<int:id>', methods=['POST'])
@admin_required
def delete_monitoring_source(id):
    """Exclui uma fonte de monitoramento"""
    from models import InternetSource
    source = InternetSource.query.get_or_404(id)
    
    # Se quiser ser rigoroso, pode apagar logs vinculados também
    # InternetAccessLog.query.filter_by(source_id=id).delete()
    
    db.session.delete(source)
    db.session.commit()
    flash('Fonte de monitoramento removida com sucesso.', 'success')
    return redirect(url_for('admin.monitoring_sources'))


# ==================== DISPOSITIVOS CONHECIDOS ====================

@admin_bp.route('/monitoring/devices')
@admin_required
def monitoring_devices():
    """Lista de dispositivos conhecidos cadastrados"""
    from models import KnownDevice
    admin = get_current_admin()
    devices = KnownDevice.query.order_by(KnownDevice.hostname).all()
    return render_template('admin_monitoring_devices.html', admin=admin, devices=devices)


@admin_bp.route('/monitoring/devices/new', methods=['GET', 'POST'])
@admin_required
def monitoring_device_new():
    """Cadastrar novo dispositivo conhecido"""
    from models import KnownDevice
    import re
    admin = get_current_admin()
    
    if request.method == 'POST':
        mac = request.form.get('mac_address', '').strip().upper()
        hostname = request.form.get('hostname', '').strip()
        category = request.form.get('category', 'pc')
        notes = request.form.get('notes', '')
        
        if not mac or not hostname:
            flash('MAC e Hostname são obrigatórios.', 'error')
            return render_template('admin_monitoring_device_form.html', admin=admin, device=None)
            
        # Validar formato MAC simplificado
        if not re.match(r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', mac):
            flash('Formato de MAC inválido. Use XX:XX:XX:XX:XX:XX', 'error')
            return render_template('admin_monitoring_device_form.html', admin=admin, device=None)

        if KnownDevice.query.filter_by(mac_address=mac).first():
            flash('Este MAC já está cadastrado.', 'error')
            return render_template('admin_monitoring_device_form.html', admin=admin, device=None)
            
        device = KnownDevice(
            mac_address=mac,
            hostname=hostname,
            category=category,
            notes=notes
        )
        db.session.add(device)
        db.session.commit()
        
        flash(f'Dispositivo {hostname} cadastrado com sucesso!', 'success')
        return redirect(url_for('admin.monitoring_devices'))
        
    return render_template('admin_monitoring_device_form.html', admin=admin, device=None)


@admin_bp.route('/monitoring/devices/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def monitoring_device_edit(id):
    """Editar dispositivo conhecido existente"""
    from models import KnownDevice
    import re
    admin = get_current_admin()
    device = KnownDevice.query.get_or_404(id)
    
    if request.method == 'POST':
        mac = request.form.get('mac_address', '').strip().upper()
        hostname = request.form.get('hostname', '').strip()
        category = request.form.get('category', 'pc')
        notes = request.form.get('notes', '')
        
        if not mac or not hostname:
            flash('MAC e Hostname são obrigatórios.', 'error')
            return render_template('admin_monitoring_device_form.html', admin=admin, device=device)
            
        # Validar formato MAC simplificado
        if not re.match(r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', mac):
            flash('Formato de MAC inválido. Use XX:XX:XX:XX:XX:XX', 'error')
            return render_template('admin_monitoring_device_form.html', admin=admin, device=device)

        # Verifica duplicidade (apenas se mudou o MAC)
        if mac != device.mac_address and KnownDevice.query.filter_by(mac_address=mac).first():
            flash('Este MAC já está cadastrado em outro dispositivo.', 'error')
            return render_template('admin_monitoring_device_form.html', admin=admin, device=device)
            
        device.mac_address = mac
        device.hostname = hostname
        device.category = category
        device.notes = notes
        
        db.session.commit()
        
        flash(f'Dispositivo {hostname} atualizado com sucesso!', 'success')
        return redirect(url_for('admin.monitoring_devices'))
        
    return render_template('admin_monitoring_device_form.html', admin=admin, device=device)


@admin_bp.route('/monitoring/devices/delete/<int:id>', methods=['POST'])
@admin_required
def delete_known_device(id):
    """Remove um dispositivo conhecido"""
    from models import KnownDevice, DeviceCommand
    device = KnownDevice.query.get_or_404(id)
    # Limpa comandos órfãos
    DeviceCommand.query.filter_by(device_id=id).delete()
    db.session.delete(device)
    db.session.commit()
    flash('Dispositivo removido com sucesso.', 'success')
    return redirect(url_for('admin.monitoring_devices'))


@admin_bp.route('/monitoring/devices/<int:id>/command', methods=['POST'])
@admin_required
def device_command_send(id):
    """Enfileira um novo comando para o dispositivo"""
    from models import DeviceCommand
    command_text = request.form.get('command')
    if not command_text:
        return jsonify({'success': False, 'message': 'Comando vazio'}), 400
    
    new_cmd = DeviceCommand(device_id=id, command_text=command_text)
    db.session.add(new_cmd)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Comando enfileirado para o Agente', 'command_id': new_cmd.id})


@admin_bp.route('/monitoring/devices/<int:id>/commands/history')
@admin_required
def device_commands_history(id):
    """Retorna o histórico de comandos do dispositivo"""
    from models import DeviceCommand
    commands = DeviceCommand.query.filter_by(device_id=id).order_by(DeviceCommand.created_at.desc()).limit(20).all()
    
    data = []
    for cmd in commands:
        data.append({
            'id': cmd.id,
            'command': cmd.command_text,
            'status': cmd.status,
            'output': cmd.result_output,
            'created_at': cmd.created_at.strftime('%H:%M:%S'),
            'executed_at': cmd.executed_at.strftime('%H:%M:%S') if cmd.executed_at else None
        })
    
    return jsonify({'success': True, 'commands': data})

# Fim do arquivo


@admin_bp.route('/server-status')
@admin_required
def server_status():
    """Visualização de métricas e status do servidor"""
    admin = get_current_admin()
    
    # Obter métricas via comandos shell
    try:
        # Memória
        mem_output = subprocess.check_output(['free', '-m']).decode('utf-8')
        mem_lines = mem_output.split('\n')
        mem_stats = mem_lines[1].split()
        memory = {
            'total': mem_stats[1],
            'used': mem_stats[2],
            'free': mem_stats[3],
            'percent': round(int(mem_stats[2]) / int(mem_stats[1]) * 100, 1)
        }
        
        # Disco
        disk_output = subprocess.check_output(['df', '-h', '/']).decode('utf-8')
        disk_lines = disk_output.split('\n')
        disk_stats = disk_lines[1].split()
        disk = {
            'total': disk_stats[1],
            'used': disk_stats[2],
            'free': disk_stats[3],
            'percent': disk_stats[4].replace('%', '')
        }
        
        # CPU & Uptime
        uptime = subprocess.check_output(['uptime', '-p']).decode('utf-8').replace('up ', '')
        load_avg = subprocess.check_output(['uptime']).decode('utf-8').split('load average:')[1].strip()
        
    except Exception as e:
        current_app.logger.error(f"Erro ao obter métricas do servidor: {e}")
        memory = disk = {'percent': 0, 'total': 'N/A', 'used': 'N/A', 'free': 'N/A'}
        uptime = load_avg = "N/A"

    # Status ES-SERVIDOR (reutilizando lógica do dashboard)
    api = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, config.ESSERVIDOR_API_KEY, timeout=3)
    esservidor_online = api.check_connection()
    
    return render_template('admin_server_status.html', 
                         admin=admin, 
                         memory=memory, 
                         disk=disk, 
                         uptime=uptime, 
                         load_avg=load_avg,
                         esservidor_online=esservidor_online)
@admin_bp.route('/monitoring/device/<mac>')
@admin_required
def device_analytics(mac):
    """Visão granular de acessos por dispositivo com análise de IA"""
    from models import InternetAccessLog, KnownDevice
    admin = get_current_admin()
    mac = mac.upper()
    
    # Período (default 24h)
    days = request.args.get('days', 1, type=int)
    since = datetime.utcnow() - timedelta(days=days)
    
    device = KnownDevice.query.filter_by(mac_address=mac).first()
    
    # Agregação de logs por domínio
    logs_query = db.session.query(
        InternetAccessLog.hostname,
        db.func.count(InternetAccessLog.id).label('count')
    ).filter(
        InternetAccessLog.mac_address == mac,
        InternetAccessLog.timestamp >= since
    ).group_by(InternetAccessLog.hostname).order_by(db.desc('count')).all()
    
    logs_data = [{'hostname': row[0], 'count': row[1]} for row in logs_query]
    
    # Análise de IA
    ai_analysis = ai_engine.analyze_behavior(
        device.hostname if device else f"Dispositivo {mac}", 
        mac, 
        logs_data
    )
    
    return render_template('admin_device_analytics.html',
                         admin=admin,
                         device=device,
                         mac=mac,
                         logs=logs_data,
                         ai_analysis=ai_analysis,
                         days=days)


@admin_bp.route('/monitoring/devices/quick-register', methods=['POST'])
@admin_required
def device_quick_register():
    """Cadastro rápido de dispositivo via AJAX"""
    from models import KnownDevice
    mac = request.form.get('mac_address', '').strip().upper()
    hostname = request.form.get('hostname', '').strip()
    category = request.form.get('category', 'pc')
    
    if not mac or not hostname:
        return jsonify({'success': False, 'message': 'MAC e Nome são obrigatórios.'}), 400
        
    if KnownDevice.query.filter_by(mac_address=mac).first():
        return jsonify({'success': False, 'message': 'Este MAC já está cadastrado.'}), 400
        
    new_device = KnownDevice(
        mac_address=mac,
        hostname=hostname,
        category=category,
        notes="Cadastrado via Fluxo Rápido"
    )
    db.session.add(new_device)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Dispositivo {hostname} cadastrado!'})


# ==================== GERENCIAMENTO DE SERVIDORES NAS ====================

@admin_bp.route('/file-servers')
@admin_required
def file_servers():
    """Listagem de servidores de arquivos NAS"""
    from models import FileServer
    admin = get_current_admin()
    servers = FileServer.query.order_by(FileServer.created_at.desc()).all()
    return render_template('admin_file_servers.html', admin=admin, servers=servers)


@admin_bp.route('/file-servers/new', methods=['GET', 'POST'])
@admin_required
def file_server_new():
    """Criar novo servidor NAS"""
    from models import FileServer
    from database import encrypt_api_key
    admin = get_current_admin()
    
    if request.method == 'POST':
        name = request.form.get('name')
        server_type = request.form.get('server_type')
        protocol = request.form.get('protocol')
        host = request.form.get('host')
        port = request.form.get('port', type=int)
        username = request.form.get('username')
        password = request.form.get('password')
        base_path = request.form.get('base_path', '/')
        api_key = request.form.get('api_key')
        notes = request.form.get('notes')
        
        # Validação
        if not name or not host or not protocol:
            flash('Nome, Host e Protocolo são obrigatórios', 'error')
            return redirect(url_for('admin.file_server_new'))
        
        # Criptografar senha se fornecida
        password_encrypted = None
        if password:
            password_encrypted = encrypt_api_key(password)
        
        server = FileServer(
            name=name,
            server_type=server_type or 'generic',
            protocol=protocol,
            host=host,
            port=port,
            username=username,
            password_encrypted=password_encrypted,
            base_path=base_path,
            api_key=api_key,
            notes=notes
        )
        
        db.session.add(server)
        db.session.commit()
        
        flash(f'Servidor {name} criado com sucesso!', 'success')
        return redirect(url_for('admin.file_servers'))
    
    return render_template('admin_file_server_form.html', admin=admin, server=None)


@admin_bp.route('/file-servers/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def file_server_edit(id):
    """Editar servidor NAS"""
    from models import FileServer
    from database import encrypt_api_key
    admin = get_current_admin()
    server = FileServer.query.get_or_404(id)
    
    if request.method == 'POST':
        server.name = request.form.get('name')
        server.server_type = request.form.get('server_type', 'generic')
        server.protocol = request.form.get('protocol')
        server.host = request.form.get('host')
        server.port = request.form.get('port', type=int)
        server.username = request.form.get('username')
        server.base_path = request.form.get('base_path', '/')
        server.api_key = request.form.get('api_key')
        server.notes = request.form.get('notes')
        server.is_active = request.form.get('is_active') == 'on'
        
        # Atualizar senha apenas se fornecida
        password = request.form.get('password')
        if password:
            server.password_encrypted = encrypt_api_key(password)
        
        db.session.commit()
        flash(f'Servidor {server.name} atualizado!', 'success')
        return redirect(url_for('admin.file_servers'))
    
    return render_template('admin_file_server_form.html', admin=admin, server=server)


@admin_bp.route('/file-servers/<int:id>/delete', methods=['POST'])
@admin_required
def file_server_delete(id):
    """Excluir servidor NAS"""
    from models import FileServer
    server = FileServer.query.get_or_404(id)
    name = server.name
    
    db.session.delete(server)
    db.session.commit()
    
    flash(f'Servidor {name} removido', 'success')
    return redirect(url_for('admin.file_servers'))


@admin_bp.route('/file-servers/<int:id>/test', methods=['POST'])
@admin_required
def file_server_test(id):
    """Testar conexão com servidor NAS via AJAX"""
    from models import FileServer
    from nas_manager import test_file_server
    
    server = FileServer.query.get_or_404(id)
    
    try:
        success, message, info = test_file_server(server)
        db.session.commit()  # Salvar o status atualizado
        
        return jsonify({
            'success': success,
            'message': message,
            'status': server.status,
            'info': info,
            'last_check': server.last_check.strftime('%d/%m/%Y %H:%M:%S') if server.last_check else None
        })
    except Exception as e:
        current_app.logger.error(f"Erro ao testar servidor {id}: {e}")
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500

