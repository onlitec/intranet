"""
Entrypoint para migrations (Flask-Migrate/Alembic).

Exemplos:
- Inicializar:  `flask --app migrate.py db init`
- Gerar migração: `flask --app migrate.py db migrate -m "mensagem"`
- Aplicar: `flask --app migrate.py db upgrade`
"""

from flask_migrate import Migrate

from models import db, RouterIntegration
from wsgi import app

migrate = Migrate(app, db)

