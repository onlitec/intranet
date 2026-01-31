"""
Wrapper para execução direta em desenvolvimento.

Em produção (gunicorn/systemd), use `wsgi:app`.
"""

import config
from wsgi import app  # noqa: F401


if __name__ == '__main__':
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
