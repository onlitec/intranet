"""
Modelos de Banco de Dados - Intranet ES-SERVIDOR
Usa SQLAlchemy com SQLite para persistência local
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class AdminUser(db.Model):
    """Administradores da plataforma intranet"""
    __tablename__ = 'admin_users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    must_change_password = db.Column(db.Boolean, default=True)
    
    # Relacionamento com usuários criados por este admin
    created_users = db.relationship('ESSERVIDORUser', backref='created_by_admin', lazy='dynamic')
    
    def set_password(self, password: str):
        """Define a senha do admin (hash bcrypt)"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password: str) -> bool:
        """Verifica a senha do admin"""
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Atualiza timestamp do último login"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def __repr__(self):
        return f'<AdminUser {self.username}>'


class ESSERVIDORUser(db.Model):
    """Usuários do ES-SERVIDOR cadastrados pelo admin"""
    __tablename__ = 'truenas_users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)  # Senha local definida pelo admin
    api_key_encrypted = db.Column(db.Text, nullable=False)  # API Key criptografada
    full_name = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id'))
    last_access = db.Column(db.DateTime)
    must_change_password = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)  # Notas do admin sobre o usuário
    
    # Relacionamento com logs
    access_logs = db.relationship('AccessLog', backref='user', lazy='dynamic')
    
    def set_password(self, password: str):
        """Define a senha do usuário (hash)"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password: str) -> bool:
        """Verifica a senha do usuário"""
        return check_password_hash(self.password_hash, password)
    
    def update_last_access(self):
        """Atualiza timestamp do último acesso"""
        self.last_access = datetime.utcnow()
        db.session.commit()
    
    def __repr__(self):
        return f'<ESSERVIDORUser {self.username}>'


class AccessLog(db.Model):
    """Log de acessos e ações na plataforma"""
    __tablename__ = 'access_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('truenas_users.id'), nullable=True)
    username = db.Column(db.String(50), nullable=False, index=True)
    action = db.Column(db.String(50), nullable=False, index=True)  # login, logout, download_bat, etc
    ip_address = db.Column(db.String(45))  # IPv6 pode ter até 45 chars
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    success = db.Column(db.Boolean, default=True)
    details = db.Column(db.Text)  # Detalhes adicionais em JSON ou texto
    
    def __repr__(self):
        return f'<AccessLog {self.username} - {self.action} at {self.timestamp}>'
    
    @classmethod
    def log_action(cls, username: str, action: str, ip_address: str = None, 
                   user_agent: str = None, success: bool = True, 
                   details: str = None, user_id: int = None):
        """Método helper para criar log de ação"""
        log = cls(
            user_id=user_id,
            username=username,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details=details
        )
        db.session.add(log)
        db.session.commit()
        return log


class SMTPConfig(db.Model):
    """Configuração do servidor de e-mail SMTP"""
    __tablename__ = 'smtp_config'
    
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(100), nullable=False)
    smtp_port = db.Column(db.Integer, default=587)
    smtp_user = db.Column(db.String(100))
    smtp_password_encrypted = db.Column(db.Text)
    use_tls = db.Column(db.Boolean, default=True)
    from_email = db.Column(db.String(100), nullable=False)
    from_name = db.Column(db.String(100), default='ES-SERVIDOR Intranet')
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<SMTPConfig {self.smtp_server}>'


class ReportSchedule(db.Model):
    """Agendamento de relatórios automáticos"""
    __tablename__ = 'report_schedules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    frequency = db.Column(db.String(20), nullable=False)  # daily, weekly, monthly, custom
    custom_days = db.Column(db.Integer, default=0)
    recipients = db.Column(db.Text, nullable=False)  # Lista separada por vírgula
    is_active = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime)
    next_run = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ReportSchedule {self.name} ({self.frequency})>'


class ReportLog(db.Model):
    """Log de envio de relatórios"""
    __tablename__ = 'report_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    schedule_id = db.Column(db.Integer, db.ForeignKey('report_schedules.id'), nullable=True)
    recipient = db.Column(db.String(100))
    status = db.Column(db.String(20))  # success, failure
    error_message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ReportLog to {self.recipient} at {self.timestamp}>'


def init_db(app):
    """Inicializa o banco de dados e cria as tabelas"""
    db.init_app(app)
    with app.app_context():
        db.create_all()
        
        # Criar admin padrão se não existir
        if not AdminUser.query.filter_by(username='admin').first():
            admin = AdminUser(
                username='admin',
                full_name='Administrador',
                email='admin@localhost'
            )
            admin.set_password('admin123')  # Senha padrão - ALTERAR em produção!
            admin.must_change_password = True
            db.session.add(admin)
            db.session.commit()
        
        return db
