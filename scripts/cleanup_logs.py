#!/usr/bin/env python3
"""
Expurgo/retencao de logs para reduzir crescimento do banco.

Variáveis de ambiente:
- INTERNET_LOG_RETENTION_DAYS (default: 90)
- ACCESS_LOG_RETENTION_DAYS (default: 180)
- DRY_RUN=true para apenas mostrar contagens

Uso:
  python3 scripts/cleanup_logs.py
"""

import os
from datetime import datetime, timedelta

from models import AccessLog, InternetAccessLog, db
from wsgi import app


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def main():
    internet_days = _get_int("INTERNET_LOG_RETENTION_DAYS", 90)
    access_days = _get_int("ACCESS_LOG_RETENTION_DAYS", 180)
    dry_run = os.getenv("DRY_RUN", "false").lower() == "true"

    now = datetime.utcnow()
    internet_cutoff = now - timedelta(days=internet_days)
    access_cutoff = now - timedelta(days=access_days)

    with app.app_context():
        q_internet = InternetAccessLog.query.filter(InternetAccessLog.timestamp < internet_cutoff)
        q_access = AccessLog.query.filter(AccessLog.timestamp < access_cutoff)

        internet_count = q_internet.count()
        access_count = q_access.count()

        print(f"[cleanup] InternetAccessLog a remover (< {internet_cutoff.isoformat()}): {internet_count}")
        print(f"[cleanup] AccessLog a remover (< {access_cutoff.isoformat()}): {access_count}")

        if dry_run:
            print("[cleanup] DRY_RUN=true; nenhuma remoção realizada.")
            return

        # Delete em lote
        q_internet.delete(synchronize_session=False)
        q_access.delete(synchronize_session=False)
        db.session.commit()

        print("[cleanup] Remoção concluída com sucesso.")


if __name__ == "__main__":
    main()

