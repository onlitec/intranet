"""
Blueprint Administrativo - Intranet TrueNAS
Rotas para gerenciamento de usuários e visualização de logs
"""
from functools import wraps
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db, AdminUser, TrueNASUser, AccessLog
from database import encrypt_api_key, decrypt_api_key
from truenas_api import TrueNASAPI
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
        'total_users': TrueNASUser.query.count(),
        'active_users': TrueNASUser.query.filter_by(is_active=True).count(),
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
    
    # Verificar conexão com TrueNAS
    try:
        truenas = TrueNASAPI(config.TRUENAS_API_URL, config.TRUENAS_API_KEY, config.API_TIMEOUT)
        truenas_online = truenas.check_connection()
    except:
        truenas_online = False
    
    return render_template('admin_dashboard.html', 
                         admin=admin, 
                         stats=stats, 
                         recent_logs=recent_logs,
                         truenas_online=truenas_online,
                         truenas_ip=config.TRUENAS_IP)


# ==================== GESTÃO DE USUÁRIOS ====================

@admin_bp.route('/users')
@admin_required
def users_list():
    """Lista de usuários TrueNAS cadastrados"""
    users = TrueNASUser.query.order_by(TrueNASUser.created_at.desc()).all()
    return render_template('admin_users.html', users=users, admin=get_current_admin())


@admin_bp.route('/users/new', methods=['GET', 'POST'])
@admin_required
def users_new():
    """Cadastrar novo usuário TrueNAS"""
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
        if TrueNASUser.query.filter_by(username=username).first():
            flash('Este usuário já está cadastrado.', 'error')
            return render_template('admin_user_form.html', admin=admin, user=None)
        
        # Validar API Key no TrueNAS
        try:
            truenas = TrueNASAPI(config.TRUENAS_API_URL, api_key, config.API_TIMEOUT)
            valid, result = truenas.validate_user_with_api_key(username, api_key)
            
            if not valid:
                flash(f'API Key inválida: {result}', 'error')
                return render_template('admin_user_form.html', admin=admin, user=None)
            
            # Se não foi fornecido nome, buscar do TrueNAS
            if not full_name:
                success, user_info = truenas.get_user_info(username, api_key)
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
            
            user = TrueNASUser(
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
    """Editar usuário TrueNAS"""
    admin = get_current_admin()
    user = TrueNASUser.query.get_or_404(user_id)
    
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
                truenas = TrueNASAPI(config.TRUENAS_API_URL, api_key, config.API_TIMEOUT)
                valid, result = truenas.validate_user_with_api_key(user.username, api_key)
                
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
    user = TrueNASUser.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'ativado' if user.is_active else 'desativado'
    flash(f'Usuário {user.username} {status}.', 'success')
    return redirect(url_for('admin.users_list'))


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def users_delete(user_id):
    """Excluir usuário"""
    user = TrueNASUser.query.get_or_404(user_id)
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
