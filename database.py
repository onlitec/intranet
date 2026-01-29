"""
Utilitários de Banco de Dados e Criptografia
"""
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoManager:
    """Gerenciador de criptografia para API Keys"""
    
    def __init__(self, secret_key: str):
        """
        Inicializa o gerenciador de criptografia
        
        Args:
            secret_key: Chave secreta do Flask (usada para derivar chave de criptografia)
        """
        # Tenta carregar o salt do ambiente, senão usa o padrão (com aviso)
        env_salt = os.getenv('SYSTEM_SALT')
        if env_salt:
            salt = env_salt.encode()
        else:
            salt = b'intranet_truenas_salt_v1'
            if os.getenv('FLASK_ENV') == 'production':
                print("⚠️ AVISO DE SEGURANÇA: SYSTEM_SALT não configurado no .env. Usando salt padrão.")
                
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
        self.fernet = Fernet(key)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Criptografa uma string
        
        Args:
            plaintext: Texto a ser criptografado
            
        Returns:
            String criptografada em base64
        """
        if not plaintext:
            return ''
        encrypted = self.fernet.encrypt(plaintext.encode())
        return encrypted.decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Descriptografa uma string
        
        Args:
            ciphertext: Texto criptografado em base64
            
        Returns:
            String descriptografada
        """
        if not ciphertext:
            return ''
        try:
            decrypted = self.fernet.decrypt(ciphertext.encode())
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Erro ao descriptografar: {e}")


# Instância global (inicializada no app)
crypto_manager = None


def init_crypto(secret_key: str):
    """Inicializa o gerenciador de criptografia"""
    global crypto_manager
    crypto_manager = CryptoManager(secret_key)
    return crypto_manager


def encrypt_api_key(api_key: str) -> str:
    """Criptografa uma API Key"""
    if crypto_manager is None:
        raise RuntimeError("CryptoManager não inicializado. Chame init_crypto() primeiro.")
    return crypto_manager.encrypt(api_key)


def decrypt_api_key(encrypted_key: str) -> str:
    """Descriptografa uma API Key"""
    if crypto_manager is None:
        raise RuntimeError("CryptoManager não inicializado. Chame init_crypto() primeiro.")
    return crypto_manager.decrypt(encrypted_key)
