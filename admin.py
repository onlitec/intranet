"""
Blueprint Administrativo - Intranet ES-SERVIDOR
Rotas para gerenciamento de usuários e visualização de logs
"""
from functools import wraps
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from models import db, AdminUser, ESSERVIDORUser, AccessLog, SMTPConfig, ReportSchedule, ReportLog
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
                'labels': ['Acessos', 'Edições', 'Criações', 'Deletados', 'Negados'],
                'action_counts': [0, 0, 0, 0, 0],
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
                    elif 'Acesso Negado' in action: chart_data['action_counts'][4] += 1
                    
                    raw_path = log.get('path', '')
                    if raw_path and raw_path != 'N/A':
                        root_folder = raw_path.split('/')[0]
                        path_counter[root_folder] += 1
                
                # Top 5 pastas
                top_folders = path_counter.most_common(5)
                chart_data['folders'] = [f[0] for f in top_folders]
                chart_data['counts'] = [f[1] for f in top_folders]
    except Exception as e:
        current_app.logger.error(f"Erro ao carregar dados do ES-SERVIDOR para dashboard: {e}")
    
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
        
    # Criar um mapeamento de GID -> Nome do Grupo
    group_map = {g.get('id'): g.get('name') for g in groups}
    
    # Processar usuários para garantir que grupos mostrem nomes em vez de IDs
    for user in users:
        formatted_groups = []
        # user.get('groups') pode vir com nomes se o API conseguiu processar, 
        # ou IDs se vieram puros. Vamos garantir que usemos nomes.
        current_groups = user.get('group_ids', [])
        for gid in current_groups:
            name = group_map.get(gid)
            if name:
                formatted_groups.append(name)
            else:
                formatted_groups.append(str(gid))
        
        if formatted_groups:
            user['groups'] = formatted_groups
    
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
        schedule.recipients = request.form.get('recipients', '').strip()
        schedule.is_active = request.form.get('is_active') == 'on'
        
        if schedule.frequency == 'custom':
            schedule.custom_days = int(request.form.get('custom_days', 0))
        else:
            schedule.custom_days = 0
            
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
    from esservidor_api import ESSERVIDORAPI
    
    # 1. Obter config SMTP
    smtp = SMTPConfig.query.first()
    if not smtp:
        return False, "Configuração SMTP não encontrada"
    
    try:
        smtp_password = decrypt_api_key(smtp.smtp_password_encrypted)
    except:
        return False, "Erro ao descriptografar senha SMTP"
    
    # 2. Obter dados do ES-SERVIDOR (Audit Logs)
    from config import ESSERVIDOR_API_URL, ESSERVIDOR_API_KEY, API_TIMEOUT, ESSERVIDOR_IP
    esservidor = ESSERVIDORAPI(ESSERVIDOR_API_URL, ESSERVIDOR_API_KEY, timeout=API_TIMEOUT)
    
    # Define o período baseado na frequência (Usando UTC para consistência com o ES-SERVIDOR)
    end_date = datetime.now(timezone.utc)
    if schedule.frequency == 'daily':
        start_date = end_date - timedelta(days=1)
    elif schedule.frequency == 'weekly':
        start_date = end_date - timedelta(weeks=1)
    elif schedule.frequency == 'monthly':
        start_date = end_date - timedelta(days=30)
    elif schedule.frequency == 'custom' and schedule.custom_days > 0:
        start_date = end_date - timedelta(days=schedule.custom_days)
    else:
        start_date = end_date - timedelta(days=1)
    
    # Para busca no banco local (AccessLog usa naive UTC)
    start_date_naive = start_date.replace(tzinfo=None)
    
    # Busca logs reais do TrueNAS se possível (Aumentado limite para cobrir período movimentado)
    success, tn_logs = esservidor.get_audit_logs(limit=2000)
    
    # Busca logs locais (Login na Intranet) para complementar
    local_logs = AccessLog.query.filter(AccessLog.timestamp >= start_date_naive).order_by(AccessLog.timestamp.desc()).limit(100).all()
    
    # Combinar logs para o resumo (priorizando TrueNAS, mas incluindo locais se desejar)
    combined_logs = []
    
    # Adiciona logs do TrueNAS processados dentro do intervalo solicitado
    if success and isinstance(tn_logs, list):
        for entry in tn_logs:
            # O sistema agora retorna objeto datetime c/ timezone em 'dt'
            log_dt = entry.get('dt')
            if log_dt:
                # Filtragem rigorosa por data
                if start_date <= log_dt <= end_date:
                    # Normaliza: 'timestamp' no combined_logs deve ser objeto p/ ordenação
                    entry['timestamp'] = log_dt.replace(tzinfo=None) # Volta p/ naive UTC p/ compatibilidade c/ local_logs
                    combined_logs.append(entry)
            
    # Adiciona logs locais formatados como dicionários compatíveis
    for l in local_logs:
        # Para o relatório, não marcamos erro de senha como "ERRO" de sistema/permissão
        report_success = True if l.action == 'login' else l.success
        
        combined_logs.append({
            'username': l.username,
            'action': f'Login Intranet ({l.details or ""})' if l.action == 'login' else l.action,
            'success': report_success,
            'timestamp': l.timestamp, # Já é naive datetime UTC
            'source': 'Intranet',
            'path': 'Painel Web' 
        })
        
    # Reordenar por timestamp desc
    combined_logs.sort(key=lambda x: x.get('timestamp') if isinstance(x.get('timestamp'), datetime) else datetime.min, reverse=True)
    
    # --- CÁLCULO DE ESTATÍSTICAS VISUAIS ---
    activity_counts = Counter() # Acessou, Editou, etc.
    folder_counts = Counter()   # Pastas Top 5
    
    for log in combined_logs:
        # Contagem de Ações
        act = log.get('action', '')
        if 'Acessou' in act: activity_counts['Acessou'] += 1
        elif 'Editou' in act: activity_counts['Editou'] += 1
        elif 'Criou' in act: activity_counts['Criou'] += 1
        elif 'Deletou' in act: activity_counts['Deletou'] += 1
        elif 'Acesso Negado' in act: activity_counts['Negados'] += 1
        
        # Contagem de Pastas (primeiro nível do path)
        p = log.get('path', '')
        if p and p not in ['N/A', 'Painel Web', '.', '']:
            # Pega o primeiro diretório antes da primeira /
            root = p.split('/')[0] if '/' in p else p
            folder_counts[root] += 1
            
    # Preparar dados para o template
    total_acts = sum(activity_counts.values()) or 1
    activity_stats = [
        {'label': 'Acessos', 'count': activity_counts['Acessou'], 'pct': round((activity_counts['Acessou']/total_acts)*100), 'color': '#3b82f6'},
        {'label': 'Edições', 'count': activity_counts['Editou'], 'pct': round((activity_counts['Editou']/total_acts)*100), 'color': '#10b981'},
        {'label': 'Criações', 'count': activity_counts['Criou'], 'pct': round((activity_counts['Criou']/total_acts)*100), 'color': '#f59e0b'},
        {'label': 'Deletados', 'count': activity_counts['Deletou'], 'pct': round((activity_counts['Deletou']/total_acts)*100), 'color': '#ef4444'},
        {'label': 'Negados', 'count': activity_counts['Negados'], 'pct': round((activity_counts['Negados']/total_acts)*100), 'color': '#6366f1'} # Indigo/Roxo para destacar
    ]
    
    top_folders_raw = folder_counts.most_common(5)
    max_folder_count = top_folders_raw[0][1] if top_folders_raw else 1
    folder_stats = [
        {'label': f[0], 'count': f[1], 'pct': round((f[1]/max_folder_count)*100)} 
        for f in top_folders_raw
    ]

    # Estatísticas básicas para o relatório (agora incluindo logins locais)
    stats = {
        'total': len(combined_logs),
        'success': len([l for l in combined_logs if l.get('success', True)]),
        'failure': len([l for l in combined_logs if not l.get('success', False)])
    }
    
    # 3. Gerar HTML do e-mail
    try:
        html_body = render_template('email_report_template.html',
                                  report_name=schedule.name,
                                  server_info="ES-SERVIDOR",
                                  start_date=start_date.strftime('%d/%m/%Y'),
                                  end_date=end_date.strftime('%d/%m/%Y'),
                                  stats=stats,
                                  activity_stats=activity_stats,
                                  folder_stats=folder_stats,
                                  recent_logs=combined_logs[:15])
    except Exception as e:
        current_app.logger.error(f"Erro ao gerar template de e-mail: {e}")
        return False, f"Erro ao gerar template HTML: {str(e)}"
    
    # 4. Enviar E-mail
    error_msgs = []
    recipients = [r.strip() for r in schedule.recipients.split(',') if r.strip()]
    
    for recipient in recipients:
        try:
            msg = MIMEMultipart()
            msg['From'] = f"{smtp.from_name} <{smtp.from_email}>"
            msg['To'] = recipient
            msg['Subject'] = f"Relatório de Atividades: {schedule.name}"
            
            msg.attach(MIMEText(html_body, 'html'))
            
            server = smtplib.SMTP(smtp.smtp_server, smtp.smtp_port, timeout=20)
            if smtp.use_tls:
                server.starttls()
            
            if smtp.smtp_user and smtp_password:
                server.login(smtp.smtp_user, smtp_password)
            
            server.send_message(msg)
            server.quit()
            
            # Log de sucesso
            log = ReportLog(schedule_id=schedule.id, recipient=recipient, status='success')
            db.session.add(log)
        except Exception as e:
            error_msgs.append(f"{recipient}: {str(e)}")
            log = ReportLog(schedule_id=schedule.id, recipient=recipient, status='failure', error_message=str(e))
            db.session.add(log)
            
    db.session.commit()
    
    if error_msgs:
        return False, f"Erros no envio: {'; '.join(error_msgs)}"
    return True, "Enviado com sucesso"
