"""
Blueprint Administrativo - Intranet ES-SERVIDOR
Rotas para gerenciamento de usuários e visualização de logs
"""
from functools import wraps
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from models import db, AdminUser, ESSERVIDORUser, AccessLog
from database import encrypt_api_key, decrypt_api_key
from esservidor_api import ESSERVIDORAPI
from collections import Counter
import config

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
            session['is_admin'] = True  # Flag para exibir menu Admin
            admin.update_last_login()
            
            flash(f'Bem-vindo, {admin.full_name}!', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Usuário ou senha inválidos.', 'error')
    
    return render_template('admin_login.html')


@admin_bp.route('/logout')
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
        ).count()
    }
    
    # Últimos acessos
    recent_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(10).all()
    
    # Verificar conexão e obter stats do ES-SERVIDOR
    esservidor_online = False
    server_stats = {'total_users': 0, 'smb_users': 0, 'shares': 0}
    try:
        esservidor = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, config.ESSERVIDOR_API_KEY, config.API_TIMEOUT)
        esservidor_online = esservidor.check_connection()
        
        if esservidor_online:
            # Obter usuários do servidor
            success, users = esservidor.get_all_users()
            if success:
                non_builtin = [u for u in users if not u.get('builtin', False)]
                server_stats['total_users'] = len(non_builtin)
                server_stats['smb_users'] = len([u for u in non_builtin if u.get('smb', False)])
            
            # Obter compartilhamentos
            success, shares = esservidor.get_smb_shares()
            if success:
                server_stats['shares'] = len(shares)

            # --- DADOS PARA O GRÁFICO ---
            _, audit_data = esservidor.get_audit_logs(limit=1000)
            chart_data = {
                'labels': ['Acessos', 'Edições', 'Criações', 'Deleções'],
                'action_counts': [0, 0, 0, 0],
                'folders': [],
                'counts': []
            }
            
            if isinstance(audit_data, list):
                path_counter = Counter()
                for log in audit_data:
                    action = log.get('action', '')
                    if 'Acessou' in action: chart_data['action_counts'][0] += 1
                    elif 'Editou' in action: chart_data['action_counts'][1] += 1
                    elif 'Criou' in action: chart_data['action_counts'][2] += 1
                    elif 'Deletou' in action: chart_data['action_counts'][3] += 1
                    
                    raw_path = log.get('path', '')
                    if raw_path and raw_path != 'N/A':
                        root_folder = raw_path.split('/')[0]
                        path_counter[root_folder] += 1
                
                # Top 5 pastas
                top_folders = path_counter.most_common(5)
                chart_data['folders'] = [f[0] for f in top_folders]
                chart_data['counts'] = [f[1] for f in top_folders]
    except Exception as e:
        print(f"Erro no dashboard: {e}")
        pass
    
    # Se der erro ou offline, garante que chart_data existe
    if 'chart_data' not in locals():
        chart_data = {'labels': [], 'action_counts': [], 'folders': [], 'counts': []}
    
    return render_template('admin_dashboard.html', 
                         admin=admin, 
                         stats=stats,
                         server_stats=server_stats,
                          recent_logs=recent_logs,
                          chart_data=chart_data,
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

    # Estatísticas simples para os cards (últimas 24h)
    stats = {
        'deletions': 0,
        'creations': 0,
        'edits': 0
    }
    
    # Busca um conjunto maior para estatísticas rápidas
    _, recent_data = esservidor.get_audit_logs(limit=500)
    if isinstance(recent_data, list):
        for log in recent_data:
            action = log.get('action', '')
            if 'Deletou' in action:
                stats['deletions'] += 1
            elif 'Criou' in action:
                stats['creations'] += 1
            elif 'Editou' in action:
                stats['edits'] += 1

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
    """Visualização de pools de armazenamento e datasets"""
    admin = get_current_admin()
    
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
    
    return render_template('admin_storage.html',
                         admin=admin,
                         pools=pools,
                         datasets=datasets,
                         stats=stats)


# ==================== COMPARTILHAMENTOS SMB ====================

@admin_bp.route('/shares')
@admin_required
def shares():
    """Visualização de compartilhamentos SMB e permissões"""
    admin = get_current_admin()
    
    esservidor = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, config.ESSERVIDOR_API_KEY, config.API_TIMEOUT)
    
    # Obter shares detalhados (com ACL)
    shares_success, shares_data = esservidor.get_smb_shares_detailed()
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
    
    return render_template('admin_shares.html',
                         admin=admin,
                         shares=shares_data,
                         smb_status=smb_status,
                         stats=stats)


# ==================== USUÁRIOS DO SERVIDOR ====================

@admin_bp.route('/server-users')
@admin_required
def server_users():
    """Visualização de usuários e grupos do ES-SERVIDOR"""
    admin = get_current_admin()
    
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
    
    # Filtrar usuários builtin (sistema) se desejado
    show_builtin = request.args.get('show_builtin', 'false').lower() == 'true'
    if not show_builtin:
        users = [u for u in users if not u.get('builtin', False)]
        groups = [g for g in groups if not g.get('builtin', False)]
    
    stats = {
        'total_users': len(users),
        'smb_users': len([u for u in users if u.get('smb', False)]),
        'locked_users': len([u for u in users if u.get('locked', False)]),
        'total_groups': len(groups),
        'smb_groups': len([g for g in groups if g.get('smb', False)])
    }
    
    return render_template('admin_server_users.html',
                         admin=admin,
                         users=users,
                         groups=groups,
                         stats=stats,
                         show_builtin=show_builtin)
