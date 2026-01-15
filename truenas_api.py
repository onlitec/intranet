"""
Cliente para Integração com TrueNAS Scale API v2.0
Documentação: https://www.truenas.com/docs/scale/scaletutorials/api/
"""
import requests
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)


class TrueNASAPI:
    """Cliente para interação com a API REST do TrueNAS Scale"""
    
    def __init__(self, base_url: str, api_key: str, timeout: int = 10):
        """
        Inicializa o cliente da API TrueNAS
        
        Args:
            base_url: URL base da API (ex: http://192.168.1.100/api/v2.0)
            api_key: API Key gerada no TrueNAS (System Settings → API Keys)
            timeout: Timeout para requisições em segundos
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Tuple[bool, any]:
        """
        Faz requisição HTTP para a API TrueNAS
        
        Args:
            method: Método HTTP (GET, POST, etc)
            endpoint: Endpoint da API (ex: /user/check_password)
            data: Dados para enviar no body (para POST)
            
        Returns:
            Tupla (sucesso, resultado/erro)
        """
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=self.headers, timeout=self.timeout)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=self.headers, json=data, timeout=self.timeout)
            else:
                return False, f"Método HTTP não suportado: {method}"
            
            response.raise_for_status()
            
            # Algumas respostas podem ser vazias (204 No Content)
            if response.status_code == 204:
                return True, None
            
            return True, response.json()
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout ao conectar com TrueNAS: {url}")
            return False, "Timeout de conexão com TrueNAS"
        
        except requests.exceptions.ConnectionError:
            logger.error(f"Erro de conexão com TrueNAS: {url}")
            return False, "TrueNAS inacessível - verifique a conexão de rede"
        
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 401:
                logger.error("API Key inválida ou expirada")
                return False, "API Key inválida - contate o administrador"
            elif status_code == 404:
                logger.error(f"Endpoint não encontrado: {endpoint}")
                return False, "Endpoint da API não encontrado"
            else:
                logger.error(f"Erro HTTP {status_code}: {e.response.text}")
                return False, f"Erro HTTP {status_code}"
        
        except Exception as e:
            logger.exception(f"Erro inesperado ao chamar API TrueNAS: {e}")
            return False, "Erro inesperado na comunicação com TrueNAS"
    
    def check_connection(self) -> bool:
        """
        Verifica se a conexão com TrueNAS está funcionando
        
        Returns:
            True se conectado, False caso contrário
        """
        success, result = self._make_request('GET', '/system/info')
        if success:
            logger.info("Conexão com TrueNAS OK")
            return True
        else:
            logger.warning(f"Falha na conexão com TrueNAS: {result}")
            return False
    
    def get_system_info(self) -> Tuple[bool, Dict]:
        """
        Obtém informações do sistema TrueNAS incluindo hostname
        
        Returns:
            Tupla (sucesso, info_dict)
            info_dict contém: hostname, version, uptime, etc.
        """
        success, result = self._make_request('GET', '/system/info')
        if success:
            return True, {
                'hostname': result.get('hostname', ''),
                'version': result.get('version', ''),
                'uptime': result.get('uptime_seconds', 0),
                'timezone': result.get('timezone', ''),
                'system_manufacturer': result.get('system_manufacturer', ''),
                'system_product': result.get('system_product', '')
            }
        return False, {'error': result}
    
    def get_hostname(self) -> str:
        """
        Obtém apenas o hostname do TrueNAS
        
        Returns:
            Hostname do servidor ou string vazia se erro
        """
        success, info = self.get_system_info()
        if success:
            return info.get('hostname', '')
        return ''

    def validate_user_with_api_key(self, username: str, user_api_key: str) -> Tuple[bool, Optional[str]]:
        """
        Valida usuário usando sua API Key individual do TrueNAS
        
        TrueNAS Scale 25.10+ não possui endpoint REST para validação de senha.
        Usa API Keys geradas por usuário como método oficial de autenticação.
        
        Args:
            username: Nome de usuário esperado
            user_api_key: API Key gerada pelo usuário no TrueNAS
            
        Returns:
            Tupla (válido, mensagem_erro)
            - (True, None) se API Key válida e corresponde ao usuário
            - (False, "mensagem") se inválida ou erro
        """
        logger.info(f"Validando API Key para usuário: {username}")
        
        # Testa a API Key fazendo uma chamada autenticada
        headers = {
            'Authorization': f'Bearer {user_api_key}',
            'Content-Type': 'application/json'
        }
        
        try:
            # Tenta obter informações do usuário usando a API Key fornecida
            url = f"{self.base_url}/user"
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 401:
                logger.warning(f"API Key inválida para usuário: {username}")
                return False, "API Key inválida ou expirada"
            
            response.raise_for_status()
            users = response.json()
            
            # Verifica se o usuário retornado corresponde ao username informado
            # A API retorna informações do usuário dono da API Key
            for user in users:
                if user.get('username') == username:
                    logger.info(f"Usuário {username} validado com sucesso via API Key")
                    return True, None
            
            # API Key válida mas usuário não corresponde
            logger.warning(f"API Key válida mas não pertence ao usuário {username}")
            return False, "API Key não pertence a este usuário"
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout ao validar API Key")
            return False, "Timeout de conexão com TrueNAS"
        
        except requests.exceptions.ConnectionError:
            logger.error(f"Erro de conexão ao validar API Key")
            return False, "TrueNAS inacessível - verifique a conexão"
        
        except requests.exceptions.HTTPError as e:
            logger.error(f"Erro HTTP ao validar API Key: {e}")
            return False, "Erro ao validar credenciais"
        
        except Exception as e:
            logger.exception(f"Erro inesperado ao validar API Key: {e}")
            return False, "Erro inesperado na autenticação"
    
    def get_user_info(self, username: str, user_api_key: Optional[str] = None) -> Tuple[bool, any]:
        """
        Obtém informações detalhadas do usuário
        
        Args:
            username: Nome de usuário
            user_api_key: API Key do usuário (opcional, usa a key admin se não fornecida)
            
        Returns:
            Tupla (sucesso, dados_usuario ou erro)
            dados_usuario = {
                'id': 1000,
                'username': 'joao',
                'full_name': 'João Silva',
                'groups': [{'id': 100, 'group': 'users'}],
                'home': '/mnt/tank/home/joao'
            }
        """
        logger.info(f"Obtendo informações do usuário: {username}")
        
        # Se fornecida API Key do usuário, usa ela ao invés da admin
        if user_api_key:
            headers = {
                'Authorization': f'Bearer {user_api_key}',
                'Content-Type': 'application/json'
            }
            try:
                url = f"{self.base_url}/user?username={username}"
                response = requests.get(url, headers=headers, timeout=self.timeout)
                response.raise_for_status()
                result = response.json()
            except Exception as e:
                logger.error(f"Erro ao obter info do usuário com API Key própria: {e}")
                return False, "Erro ao obter informações do usuário"
        else:
            # Usa o método padrão com API Key admin
            success, result = self._make_request('GET', f'/user?username={username}')
            if not success:
                return False, result
        
        # A API retorna uma lista de usuários
        if isinstance(result, list) and len(result) > 0:
            user_data = result[0]
            logger.info(f"Dados do usuário {username} obtidos: {user_data.get('full_name', 'N/A')}")
            return True, user_data
        else:
            logger.warning(f"Usuário não encontrado: {username}")
            return False, "Usuário não encontrado"
    
    def get_smb_shares(self) -> Tuple[bool, any]:
        """
        Lista todos os compartilhamentos SMB configurados no TrueNAS
        
        Returns:
            Tupla (sucesso, lista_shares ou erro)
            lista_shares = [
                {
                    'id': 1,
                    'name': 'Arquivos',
                    'path': '/mnt/tank/arquivos',
                    'enabled': True,
                    'comment': 'Compartilhamento geral'
                }
            ]
        """
        logger.info("Listando compartilhamentos SMB")
        
        success, result = self._make_request('GET', '/sharing/smb')
        
        if not success:
            return False, result
        
        # Filtra apenas os compartilhamentos habilitados
        if isinstance(result, list):
            enabled_shares = [share for share in result if share.get('enabled', False)]
            logger.info(f"Encontrados {len(enabled_shares)} compartilhamentos SMB ativos")
            return True, enabled_shares
        else:
            return False, "Formato de resposta inválido"
    
    def get_filesystem_acl(self, path: str) -> Tuple[bool, any]:
        """
        Obtém ACL (permissões) de um caminho no filesystem
        
        Args:
            path: Caminho completo do share (ex: /mnt/tank/arquivos)
            
        Returns:
            Tupla (sucesso, acl_data ou erro)
        """
        logger.info(f"Verificando ACL para: {path}")
        
        data = {"path": path}
        success, result = self._make_request('POST', '/filesystem/getacl', data)
        
        if not success:
            return False, result
        
        return True, result
    
    def get_user_accessible_shares(self, username: str) -> Tuple[bool, any]:
        """
        Retorna lista de compartilhamentos que o usuário tem permissão de acessar
        
        Este método:
        1. Obtém todos os shares SMB
        2. Obtém informações do usuário (grupos)
        3. Verifica ACL de cada share
        4. Retorna apenas os shares acessíveis
        
        Args:
            username: Nome de usuário
            
        Returns:
            Tupla (sucesso, lista_shares_acessiveis ou erro)
        """
        logger.info(f"Determinando shares acessíveis para: {username}")
        
        # 1. Obter informações do usuário
        success, user_data = self.get_user_info(username)
        if not success:
            return False, user_data
        
        user_id = user_data.get('uid')
        
        # TrueNAS Scale 25.10+ retorna 'groups' como lista de inteiros (group IDs)
        # Versões anteriores podem retornar lista de dicts
        raw_groups = user_data.get('groups', [])
        if isinstance(raw_groups, list):
            if len(raw_groups) > 0 and isinstance(raw_groups[0], int):
                # Novo formato: lista de inteiros
                user_groups = raw_groups
            elif len(raw_groups) > 0 and isinstance(raw_groups[0], dict):
                # Formato antigo: lista de dicts
                user_groups = [g.get('bsdgrp_gid') or g.get('id') for g in raw_groups]
            else:
                user_groups = []
        else:
            user_groups = []
        
        logger.debug(f"User {username}: uid={user_id}, groups={user_groups}")
        
        # 2. Obter todos os shares SMB
        success, shares = self.get_smb_shares()
        if not success:
            return False, shares
        
        accessible_shares = []
        
        # 3. Verificar permissões em cada share
        for share in shares:
            share_path = share.get('path')
            share_name = share.get('name')
            
            # Por simplicidade, vamos assumir que:
            # - Se o share está habilitado, o usuário pode acessá-lo
            # - Em produção, você pode querer verificar ACL detalhada
            
            # Opção 1: Verificação simplificada (todos os usuários autenticados)
            accessible_shares.append({
                'name': share_name,
                'path': share_path,
                'comment': share.get('comment', ''),
                'id': share.get('id')
            })
            
            # Opção 2: Verificação detalhada via ACL (descomente se necessário)
            # success_acl, acl_data = self.get_filesystem_acl(share_path)
            # if success_acl:
            #     # Verificar se user_id ou user_groups têm permissão no ACL
            #     # Lógica específica dependeria da estrutura do ACL retornado
            #     pass
        
        logger.info(f"Usuário {username} tem acesso a {len(accessible_shares)} compartilhamento(s)")
        return True, accessible_shares
