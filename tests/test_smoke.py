import os
import uuid


def test_app_imports():
    # Evitar usar o DB real (pode estar em uso por serviço rodando).
    os.environ.setdefault("FLASK_ENV", "development")
    os.environ.setdefault("DATABASE_URL", f"sqlite:////tmp/intranet_test_{uuid.uuid4().hex}.db")
    import wsgi  # noqa: F401


def test_basic_routes():
    os.environ.setdefault("FLASK_ENV", "development")
    os.environ.setdefault("DATABASE_URL", f"sqlite:////tmp/intranet_test_{uuid.uuid4().hex}.db")
    from wsgi import app

    client = app.test_client()
    r = client.get("/")
    assert r.status_code in (200, 302)

    # Deve existir endpoint legado para login de usuário
    r2 = client.get("/usuario")
    assert r2.status_code in (200, 302)

