"""
Gerenciador de Conexões NAS
Suporta múltiplos protocolos: SMB/CIFS, NFS, FTP/SFTP, WebDAV
"""
import logging
from datetime import datetime
from typing import Tuple, Dict, Any
import socket
import os

logger = logging.getLogger('flask.app')


class NASManager:
    """Gerenciador de conexões com servidores NAS"""
    
    def __init__(self, file_server):
        """
        Inicializa o gerenciador com um objeto FileServer
        
        Args:
            file_server: Instância do modelo FileServer
        """
        self.file_server = file_server
        self.protocol = file_server.protocol.lower()
        self.host = file_server.host
        self.port = file_server.get_protocol_port()
        self.username = file_server.username
        self.password = self._decrypt_password(file_server.password_encrypted)
        self.base_path = file_server.base_path or '/'
    
    def _decrypt_password(self, encrypted: str) -> str:
        """Descriptografa a senha usando o sistema existente"""
        if not encrypted:
            return None
        try:
            from database import decrypt_api_key
            return decrypt_api_key(encrypted)
        except Exception as e:
            logger.error(f"Erro ao descriptografar senha: {e}")
            return None
    
    def test_connection(self) -> Tuple[bool, str]:
        """
        Testa a conexão com o servidor NAS
        
        Returns:
            Tuple[bool, str]: (sucesso, mensagem)
        """
        try:
            if self.protocol == 'smb':
                return self._test_smb()
            elif self.protocol == 'nfs':
                return self._test_nfs()
            elif self.protocol in ['ftp', 'sftp']:
                return self._test_ftp()
            elif self.protocol in ['webdav', 'webdavs']:
                return self._test_webdav()
            else:
                return False, f"Protocolo não suportado: {self.protocol}"
        except Exception as e:
            logger.error(f"Erro no teste de conexão {self.protocol}: {e}")
            return False, f"Erro: {str(e)}"
    
    def _test_smb(self) -> Tuple[bool, str]:
        """Testa conexão SMB/CIFS"""
        try:
            # Teste básico de porta (não requer biblioteca SMB)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            
            if result == 0:
                return True, f"Porta {self.port} acessível em {self.host}"
            else:
                return False, f"Porta {self.port} inacessível em {self.host}"
        except Exception as e:
            return False, f"Erro SMB: {str(e)}"
    
    def _test_nfs(self) -> Tuple[bool, str]:
        """Testa conexão NFS"""
        try:
            # Teste de porta TCP 2049 (NFSv3/v4)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            
            if result == 0:
                return True, f"Servidor NFS respondendo em {self.host}:{self.port}"
            else:
                return False, f"Servidor NFS inacessível em {self.host}:{self.port}"
        except Exception as e:
            return False, f"Erro NFS: {str(e)}"
    
    def _test_ftp(self) -> Tuple[bool, str]:
        """Testa conexão FTP/SFTP"""
        try:
            import ftplib
            
            if self.protocol == 'ftp':
                ftp = ftplib.FTP(timeout=5)
                ftp.connect(self.host, self.port)
                
                if self.username:
                    ftp.login(self.username, self.password or '')
                else:
                    ftp.login()
                
                # Tenta listar o diretório
                ftp.cwd(self.base_path)
                ftp.quit()
                
                return True, f"FTP conectado com sucesso em {self.host}"
            
            elif self.protocol == 'sftp':
                # Teste de porta SSH (SFTP usa SSH)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((self.host, self.port))
                sock.close()
                
                if result == 0:
                    return True, f"Porta SSH/SFTP acessível em {self.host}:{self.port}"
                else:
                    return False, f"Porta SSH/SFTP inacessível em {self.host}:{self.port}"
        except ftplib.error_perm as e:
            return False, f"Erro de autenticação FTP: {str(e)}"
        except Exception as e:
            return False, f"Erro FTP/SFTP: {str(e)}"
    
    def _test_webdav(self) -> Tuple[bool, str]:
        """Testa conexão WebDAV"""
        try:
            import requests
            
            protocol_scheme = 'https' if self.protocol == 'webdavs' else 'http'
            url = f"{protocol_scheme}://{self.host}:{self.port}{self.base_path}"
            
            auth = None
            if self.username:
                auth = (self.username, self.password or '')
            
            # Tenta um OPTIONS request (comum em WebDAV)
            response = requests.options(url, auth=auth, timeout=5, verify=False)
            
            if response.status_code in [200, 204, 401]:  # 401 indica que o servidor está respondendo
                return True, f"Servidor WebDAV respondendo em {url}"
            else:
                return False, f"Servidor retornou status {response.status_code}"
        except requests.exceptions.Timeout:
            return False, "Timeout ao conectar no servidor WebDAV"
        except requests.exceptions.ConnectionError:
            return False, f"Não foi possível conectar em {self.host}:{self.port}"
        except Exception as e:
            return False, f"Erro WebDAV: {str(e)}"
    
    def get_server_info(self) -> Dict[str, Any]:
        """
        Obtém informações do servidor (se suportado)
        
        Returns:
            Dict com informações disponíveis
        """
        info = {
            'name': self.file_server.name,
            'type': self.file_server.server_type,
            'protocol': self.protocol,
            'host': self.host,
            'port': self.port,
            'status': self.file_server.status
        }
        
        # Para ES-SERVIDOR, pode consultar a API
        if self.file_server.server_type == 'es-servidor' and self.file_server.api_key:
            try:
                from esservidor_api import ESSERVIDORAPI
                import config
                
                # Usa a API key do servidor específico ou a configuração global
                api_url = f"http://{self.host}/api/v2.0" if self.port == 80 else f"http://{self.host}:{self.port}/api/v2.0"
                api = ESSERVIDORAPI(api_url, self.file_server.api_key, timeout=3)
                
                if api.check_connection():
                    success, users = api.get_all_users()
                    if success:
                        info['total_users'] = len(users)
                    
                    success, shares = api.get_smb_shares()
                    if success:
                        info['total_shares'] = len(shares)
            except Exception as e:
                logger.error(f"Erro ao obter info do ES-SERVIDOR: {e}")
        
        return info


def test_file_server(file_server) -> Tuple[bool, str, Dict]:
    """
    Função helper para testar um FileServer e atualizar seu status
    
    Args:
        file_server: Instância do modelo FileServer
    
    Returns:
        Tuple[bool, str, Dict]: (sucesso, mensagem, info)
    """
    manager = NASManager(file_server)
    success, message = manager.test_connection()
    
    # Atualiza o status do servidor
    file_server.last_check = datetime.utcnow()
    file_server.status = 'online' if success else 'offline'
    file_server.status_message = message
    
    # Obtém informações adicionais se online
    info = {}
    if success:
        info = manager.get_server_info()
    
    return success, message, info
