"""
Modelos de Banco de Dados - Intranet ES-SERVIDOR
Usa SQLAlchemy com SQLite para persistência local
"""
import os
import fcntl
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
    ip_address = db.Column(db.String(45), index=True) # IP para monitoramento de internet
    is_online = db.Column(db.Boolean, default=False)
    last_activity = db.Column(db.DateTime)
    
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
    report_type = db.Column(db.String(30), default='server_activity')  # 'server_activity', 'internet_monitoring'
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


class SystemSetting(db.Model):
    """Configurações globais da plataforma (Título, Logo, etc)"""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False, index=True)
    value = db.Column(db.Text)
    description = db.Column(db.String(255))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    _cache = {}

    @classmethod
    def get_value(cls, key: str, default: str = None) -> str:
        # Tenta pegar do cache primeiro
        if key in cls._cache:
            return cls._cache[key]
            
        setting = cls.query.filter_by(key=key).first()
        val = setting.value if setting else default
        
        # Salva no cache
        if val is not None:
            cls._cache[key] = val
            
        return val

    @classmethod
    def set_value(cls, key: str, value: str, description: str = None):
        setting = cls.query.filter_by(key=key).first()
        if setting:
            setting.value = value
            if description: setting.description = description
        else:
            setting = cls(key=key, value=value, description=description)
            db.session.add(setting)
        
        db.session.commit()
        # Atualiza ou limpa o cache
        cls._cache[key] = value


class InternetSource(db.Model):
    """Fontes de dados de monitoramento (Roteadores, Proxies)"""
    __tablename__ = 'internet_sources'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    source_type = db.Column(db.String(20), nullable=False)  # 'router_api', 'router_syslog', 'proxy_api', 'proxy_syslog'
    provider = db.Column(db.String(50))  # 'mikrotik', 'squid', 'unifi', 'generic_syslog'
    host = db.Column(db.String(100))
    port = db.Column(db.Integer)
    username = db.Column(db.String(100))
    password_encrypted = db.Column(db.Text)
    api_key_encrypted = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    last_sync = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class KnownDevice(db.Model):
    """Dispositivos conhecidos cadastrados manualmente"""
    __tablename__ = 'known_devices'
    
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(30), default='pc')  # pc, smartphone, camera, pabx, server, other
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Novos campos para Agente
    last_ip = db.Column(db.String(45))
    logged_user = db.Column(db.String(100))
    user_domain = db.Column(db.String(100))
    os_info = db.Column(db.String(100))
    agent_version = db.Column(db.String(20))
    last_report = db.Column(db.DateTime)
    uptime = db.Column(db.String(50))
    login_time = db.Column(db.DateTime)
    
    # Relacionamento com inventário
    software_inventory = db.relationship('SoftwareInventory', backref='device', lazy='dynamic', cascade='all, delete-orphan')

    def get_icon(self):
        icons = {
            'pc': '💻',
            'smartphone': '📱',
            'camera': '📹',
            'pabx': '☎️',
            'server': '🖥️',
            'other': '🔌'
        }
        return icons.get(self.category, '🔌')

    def __repr__(self):
        return f'<KnownDevice {self.hostname} ({self.mac_address})>'


class SoftwareInventory(db.Model):
    """Inventário de software instalado reportado pelo agente"""
    __tablename__ = 'software_inventory'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('known_devices.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    version = db.Column(db.String(100))
    publisher = db.Column(db.String(255))
    install_date = db.Column(db.String(20))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<SoftwareInventory {self.name} on Device {self.device_id}>'


class DeviceCommand(db.Model):
    """Fila de comandos para execução remota no Agente"""
    __tablename__ = 'device_commands'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('known_devices.id'), nullable=False)
    command_text = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending') # pending, running, success, error, cancelled
    result_output = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    executed_at = db.Column(db.DateTime)
    
    # Relacionamento
    device = db.relationship('KnownDevice', backref=db.backref('commands', lazy=True))

    def __repr__(self):
        return f'<DeviceCommand {self.id} for device {self.device_id}: {self.status}>'


class InternetAccessLog(db.Model):
    """Registros processados de acesso à internet"""
    __tablename__ = 'internet_access_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey('internet_sources.id'), nullable=True)
    ip_address = db.Column(db.String(45), index=True)
    hostname = db.Column(db.String(100), index=True)
    mac_address = db.Column(db.String(17))
    website = db.Column(db.String(255), index=True)  # Domínio ou URL parcial
    full_url = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    duration = db.Column(db.Integer)  # Em segundos, se disponível
    bytes_sent = db.Column(db.BigInteger)
    bytes_received = db.Column(db.BigInteger)
    action = db.Column(db.String(20))  # 'allowed', 'blocked'
    source_type = db.Column(db.String(20), default='syslog')  # syslog, agent
    process_name = db.Column(db.String(100))
    user_context = db.Column(db.String(100))


    # Índices compostos para acelerar consultas do dashboard
    __table_args__ = (
        db.Index('idx_website_timestamp', 'website', 'timestamp'),
        db.Index('idx_mac_timestamp', 'mac_address', 'timestamp'),
        db.Index('idx_ip_timestamp', 'ip_address', 'timestamp'),
    )


class DomainCategorization(db.Model):
    """Catalogação inteligente de domínios via IA"""
    __tablename__ = 'domain_categorizations'
    
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    category = db.Column(db.String(50))  # Ex: Rede Social, Streaming, Update, Trabalho
    description = db.Column(db.Text)      # Explicação amigável do que é o domínio
    friendly_name = db.Column(db.String(100)) # Noma amigável (ex: Windows Update, Netflix)
    icon = db.Column(db.String(20))       # Emoji ou ícone sugerido
    is_productive = db.Column(db.Boolean, default=True) # Se o acesso é considerado produtivo
    last_analyzed = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<DomainCategorization {self.domain} -> {self.friendly_name}>'


class RemoteSessionLog(db.Model):
    """Log de sessões de acesso remoto para auditoria"""
    __tablename__ = 'remote_session_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin_users.id'), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('known_devices.id'), nullable=False)
    admin_ip = db.Column(db.String(45))
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    status = db.Column(db.String(20))  # active, completed, error
    critical_actions = db.Column(db.Text)  # JSON list of actions like 'Power Off'
    
    # Relacionamentos
    admin = db.relationship('AdminUser', backref=db.backref('remote_sessions', lazy=True))
    device = db.relationship('KnownDevice', backref=db.backref('remote_sessions', lazy=True))

    def __repr__(self):
        return f'<RemoteSessionLog {self.id}: Admin {self.admin_id} -> Device {self.device_id}>'


def init_db(app):

    """Inicializa o banco de dados e cria as tabelas"""
    db.init_app(app)
    with app.app_context():
        # Evita problemas de concorrência (gunicorn multi-worker) ao inicializar tabelas.
        # Pode ser desabilitado via SKIP_DB_CREATE_ALL=true (ex.: usando migrations).
        if os.getenv('SKIP_DB_CREATE_ALL', 'false').lower() != 'true':
            lock_path = os.path.join(os.path.dirname(__file__), '.db_init.lock')
            try:
                with open(lock_path, 'w') as lock_file:
                    try:
                        fcntl.flock(lock_file, fcntl.LOCK_EX)
                    except Exception:
                        pass
                    db.create_all()
            except Exception:
                # Se falhar (ex.: DB travado), tenta seguir; outro processo pode já ter inicializado.
                try:
                    db.session.rollback()
                except Exception:
                    pass
        # Em produção, NÃO criar admin padrão automaticamente.
        # O primeiro admin deve ser criado via bootstrap seguro (token no .env).
        allow_default_admin = os.getenv('ALLOW_DEFAULT_ADMIN', 'false').lower() == 'true'
        flask_env = os.getenv('FLASK_ENV', 'development').lower()
        is_production = flask_env == 'production'

        if (not is_production or allow_default_admin) and AdminUser.query.count() == 0:
            # Apenas para desenvolvimento/labs, ou quando explicitamente permitido.
            admin = AdminUser(
                username='admin',
                full_name='Administrador',
                email='admin@localhost',
                must_change_password=True
            )
            admin.set_password(os.getenv('DEFAULT_ADMIN_PASSWORD', 'admin123'))
            db.session.add(admin)
            db.session.commit()

        # Configurações padrão do sistema
        if not SystemSetting.query.filter_by(key='site_title').first():
            SystemSetting.set_value('site_title', 'ES-SERVIDOR', 'Título da Plataforma')
        if not SystemSetting.query.filter_by(key='site_logo').first():
            SystemSetting.set_value('site_logo', '/static/images/logo.png', 'Caminho do Logotipo')
        if not SystemSetting.query.filter_by(key='site_favicon').first():
            SystemSetting.set_value('site_favicon', '/static/images/logo.png', 'Caminho do Favicon')
        
        return db


class FileServer(db.Model):
    """Servidores de arquivos NAS configurados (ES-SERVIDOR, Synology, QNAP, TrueNAS, etc.)"""
    __tablename__ = 'file_servers'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Nome amigável
    server_type = db.Column(db.String(30), nullable=False)  # es-servidor, synology, qnap, truenas, generic
    protocol = db.Column(db.String(20), nullable=False)  # smb, nfs, ftp, sftp, webdav
    host = db.Column(db.String(255), nullable=False)  # IP ou hostname
    port = db.Column(db.Integer)  # Porta (opcional, usa padrão do protocolo)
    username = db.Column(db.String(100))  # Usuário para autenticação
    password_encrypted = db.Column(db.Text)  # Senha criptografada
    base_path = db.Column(db.String(500))  # Caminho base (ex: /volume1/data)
    api_key = db.Column(db.String(255))  # Chave API (para ES-SERVIDOR, Synology DSM, etc.)
    is_active = db.Column(db.Boolean, default=True)
    last_check = db.Column(db.DateTime)  # Último teste de conexão
    status = db.Column(db.String(20), default='unknown')  # online, offline, unknown, error
    status_message = db.Column(db.Text)  # Mensagem de erro ou info
    notes = db.Column(db.Text)  # Observações
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def get_icon(self):
        """Retorna ícone baseado no tipo de servidor"""
        icons = {
            'es-servidor': '🖥️',
            'synology': '📦',
            'qnap': '🗄️',
            'truenas': '💾',
            'generic': '🔌'
        }
        return icons.get(self.server_type, '🔌')
    
    def get_protocol_port(self):
        """Retorna porta padrão do protocolo se não especificada"""
        if self.port:
            return self.port
        defaults = {
            'smb': 445,
            'nfs': 2049,
            'ftp': 21,
            'sftp': 22,
            'webdav': 80,
            'webdavs': 443
        }
        return defaults.get(self.protocol, 0)
    
    def __repr__(self):
        return f'<FileServer {self.name} ({self.server_type})>'

