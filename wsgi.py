"""
WSGI entrypoint (Gunicorn) e fábrica da aplicação.

Uso:
- Gunicorn: `gunicorn wsgi:app`
- Dev: `python app.py` (wrapper)
"""

import logging
import os
from datetime import timedelta
from logging.handlers import RotatingFileHandler

from flask import Flask, has_request_context, render_template, request
from flask_login import LoginManager, current_user
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

import config
from admin import admin_bp
from auth import User
from database import init_crypto
from esservidor_api import ESSERVIDORAPI
from models import init_db
from routes import register_routes


csrf = CSRFProtect()
login_manager = LoginManager()
session_ext = Session()


def create_app() -> Flask:
    app = Flask(__name__)

    # Respeitar headers do nginx (X-Forwarded-For/Proto)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.config['SECRET_KEY'] = config.FLASK_SECRET_KEY
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=config.SESSION_TIMEOUT)
    app.config['SESSION_COOKIE_SECURE'] = config.SESSION_COOKIE_SECURE
    app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
    app.config['SESSION_COOKIE_SAMESITE'] = config.SESSION_COOKIE_SAMESITE

    # Limite de upload (defensivo; nginx também limita)
    app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', str(5 * 1024 * 1024)))

    # Sessão server-side
    app.config['SESSION_TYPE'] = config.SESSION_TYPE
    app.config['SESSION_FILE_DIR'] = config.SESSION_FILE_DIR
    app.config['SESSION_PERMANENT'] = config.SESSION_PERMANENT
    app.config['SESSION_USE_SIGNER'] = config.SESSION_USE_SIGNER

    # Banco: permitir override (Postgres opcional) via DATABASE_URL
    db_url = os.getenv('DATABASE_URL')
    if db_url:
        app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'intranet.db')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Ajustes úteis para SQLite em produção/testes (timeout ajuda a reduzir 'database is locked')
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'timeout': 30}}

    csrf.init_app(app)
    session_ext.init_app(app)

    # DB + crypto
    init_db(app)
    init_crypto(config.FLASK_SECRET_KEY)

    # Cliente admin ES-SERVIDOR
    app.extensions['esservidor_admin'] = ESSERVIDORAPI(
        base_url=config.ESSERVIDOR_API_URL,
        api_key=config.ESSERVIDOR_API_KEY,
        timeout=config.API_TIMEOUT
    )

    # Blueprint admin (prefix /admin)
    app.register_blueprint(admin_bp)

    # Rotas principais (endpoints legados sem prefixo)
    register_routes(app)

    # Login manager
    login_manager.init_app(app)
    login_manager.login_view = 'user_login'
    login_manager.login_message = 'Por favor, faça login para acessar esta página.'
    login_manager.login_message_category = 'warning'

    # Logging
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

    class ContextFilter(logging.Filter):
        def filter(self, record):
            if has_request_context():
                # Preferir X-Forwarded-For quando atrás de proxy
                xfwd = request.headers.get('X-Forwarded-For', '')
                record.request_ip = (xfwd.split(',')[0].strip() if xfwd else request.remote_addr) or 'N/A'
                try:
                    record.username = getattr(current_user, 'username', None) or 'Anonymous'
                except Exception:
                    record.username = 'Anonymous'
            else:
                record.request_ip = 'N/A'
                record.username = 'N/A'
            return True

    file_handler.addFilter(ContextFilter())
    app.logger.addHandler(file_handler)
    app.logger.setLevel(getattr(logging, config.LOG_LEVEL))

    if config.FLASK_DEBUG:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        app.logger.addHandler(console_handler)

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return render_template('error.html', error_code=404, error_message='Página não encontrada'), 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.exception(f"Erro interno: {error}")
        return render_template('error.html', error_code=500, error_message='Erro interno do servidor'), 500

    return app


@login_manager.user_loader
def load_user(user_id):
    # O user_id aqui é o `User.id` (username)
    # O estado persistente está em session['user_data']
    from flask import session

    if 'user_data' in session:
        user_data = session['user_data']
        return User(
            username=user_data.get('username'),
            full_name=user_data.get('full_name'),
            user_data=user_data,
            db_user_id=user_data.get('db_user_id')
        )
    return None


app = create_app()

