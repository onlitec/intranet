from flask_login import UserMixin


class User(UserMixin):
    """Classe de usuário para Flask-Login (usuários finais da intranet)."""

    def __init__(self, username: str, full_name: str = None, user_data: dict = None, db_user_id: int = None):
        self.id = username  # Flask-Login usa 'id' como identificador
        self.username = username
        self.full_name = full_name or username
        self.user_data = user_data or {}
        self.db_user_id = db_user_id  # ID no banco de dados (opcional)

    def __repr__(self):
        return f'<User {self.username}>'

