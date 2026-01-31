"""
Criptografia de credenciais (senhas de integrações, tokens etc).

Unificada com `database.py` (CryptoManager), para evitar múltiplos esquemas e
dependência de arquivo `.crypt_key`.

Compatibilidade:
- Caso encontre dados legados criptografados com `.crypt_key`, tenta descriptografar
  usando o arquivo se ele existir (sem gerar novo).
"""

import os
from cryptography.fernet import Fernet

import config
import database

LEGACY_KEY_FILE = "/opt/intranet/.crypt_key"


def _ensure_crypto_initialized():
    if database.crypto_manager is None:
        # Inicializa com as mesmas regras do app (pode usar INTRANET_MASTER_KEY via env)
        database.init_crypto(config.FLASK_SECRET_KEY)


def encrypt_credential(text: str) -> str:
    if not text:
        return None
    _ensure_crypto_initialized()
    return database.encrypt_api_key(text)


def decrypt_credential(token: str) -> str:
    if not token:
        return None

    # 1) Caminho novo (unificado)
    try:
        _ensure_crypto_initialized()
        return database.decrypt_api_key(token)
    except Exception:
        pass

    # 2) Fallback legado: `.crypt_key` (não gera, apenas tenta ler se existir)
    try:
        if os.path.exists(LEGACY_KEY_FILE):
            with open(LEGACY_KEY_FILE, "rb") as f:
                key = f.read()
            return Fernet(key).decrypt(token.encode()).decode()
    except Exception:
        pass

    # 3) Compatibilidade com dados em texto plano antigos
    return token
