#!/usr/bin/env python3
"""
Expurgo/retenção de logs para reduzir crescimento do banco.

Variáveis de ambiente:
- INTERNET_LOG_RETENTION_DAYS (default: 90) - dias de retenção para InternetAccessLog
- ACCESS_LOG_RETENTION_DAYS (default: 180) - dias de retenção para AccessLog
- DRY_RUN=true para apenas mostrar contagens sem deletar

Uso:
  python3 cleanup_logs.py
  DRY_RUN=true python3 cleanup_logs.py  # Modo dry-run
"""

import os
import sys
from datetime import datetime, timedelta

from models import AccessLog, InternetAccessLog, db
from wsgi import app


def _get_int(name: str, default: int) -> int:
    """Obtém valor inteiro de variável de ambiente com fallback."""
    try:
        return int(os.getenv(name, str(default)))
    except (ValueError, TypeError):
        return default


def main():
    """Executa a limpeza de logs antigos."""
    internet_days = _get_int("INTERNET_LOG_RETENTION_DAYS", 7)
    access_days = _get_int("ACCESS_LOG_RETENTION_DAYS", 30)
    dry_run = os.getenv("DRY_RUN", "false").lower() == "true"

    now = datetime.utcnow()
    internet_cutoff = now - timedelta(days=internet_days)
    access_cutoff = now - timedelta(days=access_days)

    print(f"[cleanup] Iniciando limpeza de logs...")
    print(f"[cleanup] Retenção InternetAccessLog: {internet_days} dias (cutoff: {internet_cutoff.isoformat()})")
    print(f"[cleanup] Retenção AccessLog: {access_days} dias (cutoff: {access_cutoff.isoformat()})")
    print(f"[cleanup] Modo DRY_RUN: {dry_run}")

    try:
        with app.app_context():
            # Conta registros a serem removidos
            q_internet = InternetAccessLog.query.filter(InternetAccessLog.timestamp < internet_cutoff)
            q_access = AccessLog.query.filter(AccessLog.timestamp < access_cutoff)

            internet_count = q_internet.count()
            access_count = q_access.count()

            print(f"[cleanup] InternetAccessLog a remover: {internet_count}")
            print(f"[cleanup] AccessLog a remover: {access_count}")

            if dry_run:
                print("[cleanup] DRY_RUN=true; nenhuma remoção realizada.")
                return 0

            if internet_count == 0 and access_count == 0:
                print("[cleanup] Nenhum registro a remover.")
                return 0

            # Executa remoção
            if internet_count > 0:
                q_internet.delete(synchronize_session=False)
                print(f"[cleanup] Removidos {internet_count} registros de InternetAccessLog.")

            if access_count > 0:
                q_access.delete(synchronize_session=False)
                print(f"[cleanup] Removidos {access_count} registros de AccessLog.")

            db.session.commit()
            print("[cleanup] Remoção concluída com sucesso.")
            
            # Executa VACUUM se houver muitas deleções
            if internet_count > 100000:
                print("[cleanup] Executando VACUUM para recuperar espaço em disco...")
                db.session.execute(db.text("VACUUM"))
                db.session.commit()
                print("[cleanup] VACUUM concluído.")
                
            return 0

    except Exception as e:
        print(f"[cleanup] ERRO: {e}", file=sys.stderr)
        db.session.rollback()
        return 1


if __name__ == "__main__":
    sys.exit(main())

