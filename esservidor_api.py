"""
Cliente para Integração com ES-SERVIDOR Scale API v2.0
Documentação: https://www.truenas.com/docs/scale/scaletutorials/api/
"""
import requests
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)


class ESSERVIDORAPI:
    """Cliente para interação com a API REST do ES-SERVIDOR Scale"""
    
    def __init__(self, base_url: str, api_key: str, timeout: int = 10):
        """
        Inicializa o cliente da API ES-SERVIDOR
        
        Args:
            base_url: URL base da API (ex: http://192.168.1.100/api/v2.0)
            api_key: API Key gerada no ES-SERVIDOR (System Settings → API Keys)
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
        Faz requisição HTTP para a API ES-SERVIDOR
        
        Args:
            method: Método HTTP (GET, POST, etc)
            endpoint: Endpoint da API (ex: /user/check_password)
            data: Dados para enviar no body (para POST)
            
        Returns:
            Tupla (sucesso, resultado/erro)
        """
        url = f"{self.base_url}{endpoint}"
        
        try:
            import config
            start_time = time.time()
            if method.upper() == 'GET':
                response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=config.ESSERVIDOR_VERIFY_SSL)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=self.headers, json=data, timeout=self.timeout, verify=config.ESSERVIDOR_VERIFY_SSL)
            else:
                return False, f"Método HTTP não suportado: {method}"
            
            duration = time.time() - start_time
            if duration > 1.0:
                logger.warning(f"Resposta LENTA do ES-SERVIDOR: {endpoint} levou {duration:.2f}s")
            else:
                logger.debug(f"API {endpoint} respondeu em {duration:.2f}s")
                
            response.raise_for_status()
            
            # Algumas respostas podem ser vazias (204 No Content)
            if response.status_code == 204:
                return True, None
            
            return True, response.json()
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout ao conectar com ES-SERVIDOR: {url}")
            return False, "Timeout de conexão com ES-SERVIDOR"
        
        except requests.exceptions.ConnectionError:
            logger.error(f"Erro de conexão com ES-SERVIDOR: {url}")
            return False, "ES-SERVIDOR inacessível - verifique a conexão de rede"
        
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
            logger.exception(f"Erro inesperado ao chamar API ES-SERVIDOR: {e}")
            return False, "Erro inesperado na comunicação com ES-SERVIDOR"
    
    def check_connection(self) -> bool:
        """
        Verifica se a conexão com ES-SERVIDOR está funcionando
        
        Returns:
            True se conectado, False caso contrário
        """
        success, result = self._make_request('GET', '/system/info')
        if success:
            logger.info("Conexão com ES-SERVIDOR OK")
            return True
        else:
            logger.warning(f"Falha na conexão com ES-SERVIDOR: {result}")
            return False
    
    def get_system_info(self) -> Tuple[bool, Dict]:
        """
        Obtém informações do sistema ES-SERVIDOR incluindo hostname
        
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
        Obtém apenas o hostname do ES-SERVIDOR
        
        Returns:
            Hostname do servidor ou string vazia se erro
        """
        import config
        success, info = self.get_system_info()
        if success:
            return info.get('hostname', '')
        return ''

    def validate_user_with_password(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Valida usuário/senha usando Basic Auth contra a API do ES-SERVIDOR
        
        Args:
            username: Nome de usuário
            password: Senha do usuário
            
        Returns:
            Tupla (válido, mensagem_erro)
        """
        logger.info(f"Validando credenciais via Basic Auth para: {username}")
        
        url = f"{self.base_url}/user"
        try:
            # Tenta acessar /user com Basic Auth
            response = requests.get(url, auth=(username, password), timeout=self.timeout)
            
            if response.status_code == 200:
                logger.info(f"Credenciais de {username} validadas com sucesso via Basic Auth")
                return True, None
            elif response.status_code == 401:
                return False, "Usuário ou senha incorretos no ES-SERVIDOR"
            else:
                return False, f"Erro na API do ES-SERVIDOR: {response.status_code}"
                
        except Exception as e:
            logger.error(f"Erro ao validar credenciais via Basic Auth: {e}")
            return False, "Não foi possível conectar ao ES-SERVIDOR para validar a senha"

    def validate_user_with_api_key(self, username: str, user_api_key: str) -> Tuple[bool, Optional[str]]:
        """
        Valida usuário usando sua API Key individual do ES-SERVIDOR
        
        ES-SERVIDOR Scale 25.10+ não possui endpoint REST para validação de senha.
        Usa API Keys geradas por usuário como método oficial de autenticação.
        
        Args:
            username: Nome de usuário esperado
            user_api_key: API Key gerada pelo usuário no ES-SERVIDOR
            
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
            return False, "Timeout de conexão com ES-SERVIDOR"
        
        except requests.exceptions.ConnectionError:
            logger.error(f"Erro de conexão ao validar API Key")
            return False, "ES-SERVIDOR inacessível - verifique a conexão"
        
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
        Lista todos os compartilhamentos SMB configurados no ES-SERVIDOR
        
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
        
        # ES-SERVIDOR Scale 25.10+ retorna 'groups' como lista de inteiros (group IDs)
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
            
            # Opção 2: Verificação detalhada via ACL
            success_acl, acl_data = self.get_filesystem_acl(share_path)
            if success_acl:
                # Se o ACL retornar dados, verificamos se o usuário tem algum tipo de permissão
                # No TrueNAS Scale, se o usuário não tiver NENHUMA permissão, o SHARE não deve aparecer
                # Para simplificar e ser seguro: se conseguimos ler o ACL, verificamos entradas para o owner, group ou de todos
                # Em um cenário real, percorreríamos as entradas (ACEs)
                has_access = False
                for ace in acl_data.get('acl', []):
                    # Se houver uma entrada para o usuário ou para um grupo que ele pertence, ou 'EVERYONE'
                    if (ace.get('who') == username or 
                        (ace.get('id') and int(ace['id']) in user_groups) or 
                        ace.get('tag') in ['EVERYONE@', 'group@', 'owner@']):
                        # Se for um ALLOW, ele tem algum nível de acesso
                        if ace.get('type') == 'ALLOW':
                            has_access = True
                            break
                
                if has_access:
                    accessible_shares.append({
                        'name': share_name,
                        'path': share_path,
                        'comment': share.get('comment', ''),
                        'id': share.get('id')
                    })
            else:
                # Se falhar em ler o ACL (erro 403 por exemplo), o usuário provavelmente não tem acesso
                logger.debug(f"Falha ao ler ACL para {share_path}: {acl_data}")
        
        logger.info(f"Usuário {username} tem acesso a {len(accessible_shares)} compartilhamento(s)")
        return True, accessible_shares
    def get_audit_logs(self, query_filters: Optional[List[List]] = None, limit: int = 50, offset: int = 0) -> Tuple[bool, any]:
        """
        Consulta os logs de auditoria do ES-SERVIDOR usando o endpoint de query
        
        Args:
            query_filters: Lista de filtros no formato ES-SERVIDOR (ex: [["event", "=", "CLOSE"]])
            limit: Limite de registros
            offset: Deslocamento para paginação
            
        Returns:
            Tupla (sucesso, dados_logs)
        """
        logger.info(f"Consultando logs de auditoria (limit={limit}, offset={offset})")
        
        # Filtros base para focar em SMB
        base_filters = [
            ["service", "=", "SMB"]
        ]
        
        if query_filters:
            base_filters.extend(query_filters)
            
        # Parâmetros para o endpoint audit/query
        data = {
            "query-filters": base_filters,
            "query-options": {
                "limit": limit,
                "offset": offset,
                "order_by": ["-timestamp"]
            }
        }
        
        # O endpoint correto para consulta via REST é POST /audit/query
        success, result = self._make_request('POST', '/audit/query', data=data)
        
        if not success:
            return False, result
            
        if not isinstance(result, list):
            logger.error(f"Resposta inesperada da API de auditoria: {type(result)}")
            return False, "Formato de resposta inválido"

        # Processamento e mapeamento amigável
        processed_logs = []
        # Cache para deduplicação (user:action:path -> timestamp)
        dedup_cache = {}
        
        for entry in result:
            if not isinstance(entry, dict):
                continue

            event = entry.get('event', '')
            # Mapeamento de eventos SMB para ações humanas
            # Ações comuns no TrueNAS Scale: 
            # OPEN, CLOSE, RENAME, UNLINK (Delete), MKDIR, RMDIR, WRITE, CREATE
            action_map = {
                'OPEN': 'Acessou',
                'CREATE': 'Criou',
                'CLOSE': 'Fechou',
                'RENAME': 'Renomeou',
                'UNLINK': 'Deletou',
                'MKDIR': 'Criou Pasta',
                'RMDIR': 'Deletou Pasta',
                'WRITE': 'Editou',
                'SET_ATTR': 'Editou',
                'AUTH': 'Login SMB'
            }
            
            # Refinamento para eventos
            event_data = entry.get('event_data', {})
            
            if event == 'CREATE':
                disp = event_data.get('parameters', {}).get('CreateDisposition', '')
                if disp in ['OPEN', 'OPEN_IF']:
                    friendly_action = 'Acessou'
                else:
                    friendly_action = 'Criou'
            elif event == 'CLOSE':
                # No TrueNAS, o CLOSE reporta se houve escrita durante a sessão
                ops = event_data.get('operations', {})
                if isinstance(ops, dict):
                    w_cnt = int(ops.get('write_cnt', 0))
                    w_bytes = int(ops.get('write_bytes', 0))
                    if w_cnt > 0 or w_bytes > 0:
                        friendly_action = 'Editou'
                    else:
                        friendly_action = 'Fechou'
                else:
                    friendly_action = 'Fechou'
            else:
                friendly_action = action_map.get(event, event)
            
            # Filtro de "logs inúteis" conforme solicitado pelo usuário
            # Se não for uma das ações principais, podemos ignorar
            monitored_events = ['OPEN', 'CREATE', 'RENAME', 'UNLINK', 'MKDIR', 'RMDIR', 'WRITE', 'SET_ATTR', 'CLOSE']
            if event not in monitored_events:
                # Permitir Acessou se veio de um CREATE:OPEN
                if friendly_action != 'Acessou':
                    continue
            
            # Se for um CLOSE sem escrita, geralmente é ruído (Windows abrindo/fechando pra ler ícones)
            if event == 'CLOSE' and friendly_action == 'Fechou':
                continue

            # Extração de timestamp
            ts_val = None
            ts_obj = entry.get('timestamp')
            
            if isinstance(ts_obj, dict) and '$date' in ts_obj:
                ts_val = ts_obj['$date'] / 1000
            elif entry.get('message_timestamp'):
                ts_val = entry['message_timestamp']
            elif isinstance(ts_obj, (int, float)):
                ts_val = ts_obj
                
            if ts_val:
                try:
                    ts_str = datetime.fromtimestamp(ts_val).strftime('%d/%m/%Y %H:%M:%S')
                except:
                    ts_str = 'N/A'
            else:
                ts_str = 'N/A'

            # Extração do caminho
            path = 'N/A'
            if isinstance(event_data, dict):
                if event == 'RENAME':
                    src = event_data.get('src_file', {}).get('path', '?')
                    dst = event_data.get('dst_file', {}).get('path', '?')
                    path = f"{src} -> {dst}"
                else:
                    file_obj = event_data.get('file')
                    if isinstance(file_obj, dict):
                        path = file_obj.get('path', 'N/A')
                    elif 'path' in event_data:
                        path = event_data['path']
            
            # Extração do resultado (sucesso/erro) e detecção de Acesso Negado
            res_val = event_data.get('result', {}).get('value_parsed', '') if isinstance(event_data, dict) else ''
            is_access_denied = (res_val == 'NT_STATUS_ACCESS_DENIED')
            
            if is_access_denied:
                friendly_action = '🛑 Acesso Negado'
            
            # Filtro para ocultar falhas de "Arquivo não encontrado" (Ruído SMB do Windows)
            if not entry.get('success', True) and not is_access_denied:
                if res_val == 'NT_STATUS_OBJECT_NAME_NOT_FOUND':
                    continue

            # Filtro adicional para remover caminhos inúteis e arquivos temporários (Excel/Word)
            # - '.' representa o acesso à raiz (ruído)
            # - Filename iniciando com '~$' são arquivos temporários de proprietário do Office
            # - Extensão '.tmp' são arquivos temporários genéricos
            # - Filename iniciando com '._' são arquivos de metadados (Apple/System)
            filename = path.split('/')[-1] if '/' in path else path
            if (path in ['.', '', 'N/A'] or 
                filename.startswith('~$') or 
                filename.endswith('.tmp') or 
                filename.startswith('._') or
                'desktop.ini' in filename.lower()):
                continue
            
            # --- Lógica de Deduplicação ---
            # Ignora se for o mesmo usuário, ação e caminho num intervalo de 2 segundos
            username = entry.get('username', 'N/A')
            dedup_key = f"{username}:{friendly_action}:{path}"
            
            if ts_val:
                last_ts = dedup_cache.get(dedup_key)
                # Reduzir para 0.5s para evitar esconder ações rápidas, mas ainda limpar ruído do Windows
                if last_ts and abs(ts_val - last_ts) <= 0.5:
                    continue
                dedup_cache[dedup_key] = ts_val

            processed_logs.append({
                'timestamp': ts_str,
                'dt': datetime.fromtimestamp(ts_val, tz=timezone.utc) if ts_val else None,
                'username': username,
                'action': friendly_action,
                'path': path,
                'ip': entry.get('address', 'N/A'),
                'success': entry.get('success', True),
                'details': event_data
            })
            
        return True, processed_logs

    def get_pools(self) -> Tuple[bool, any]:
        """
        Obtém lista de pools de armazenamento do ES-SERVIDOR
        
        Returns:
            Tupla (sucesso, lista_pools ou erro)
            lista_pools = [
                {
                    'id': 1,
                    'name': 'tank',
                    'status': 'ONLINE',
                    'healthy': True,
                    'size': 1099511627776,  # em bytes
                    'allocated': 549755813888,
                    'free': 549755813888,
                    'topology': {...}
                }
            ]
        """
        success, data = self._make_request('GET', '/pool')
        if not success:
            return False, data
        
        pools = []
        for pool in data:
            pools.append({
                'id': pool.get('id'),
                'name': pool.get('name'),
                'status': pool.get('status'),
                'healthy': pool.get('healthy', False),
                'size': pool.get('size', 0),
                'allocated': pool.get('allocated', 0),
                'free': pool.get('free', 0),
                'topology': pool.get('topology', {}),
                'scan': pool.get('scan', {})
            })
        return True, pools

    def get_datasets(self, pool_name: Optional[str] = None) -> Tuple[bool, any]:
        """
        Obtém lista de datasets do ES-SERVIDOR
        
        Args:
            pool_name: Nome do pool para filtrar (opcional)
            
        Returns:
            Tupla (sucesso, lista_datasets ou erro)
        """
        success, data = self._make_request('GET', '/pool/dataset')
        if not success:
            return False, data
        
        datasets = []
        for ds in data:
            ds_name = ds.get('name', '')
            
            # Filtrar por pool se especificado
            if pool_name and not ds_name.startswith(pool_name):
                continue
            
            # Extrair informações de quota e uso
            used = ds.get('used', {})
            available = ds.get('available', {})
            
            datasets.append({
                'id': ds.get('id'),
                'name': ds_name,
                'pool': ds_name.split('/')[0] if '/' in ds_name or ds_name else ds_name,
                'type': ds.get('type', 'FILESYSTEM'),
                'used_bytes': used.get('parsed', 0) if isinstance(used, dict) else 0,
                'available_bytes': available.get('parsed', 0) if isinstance(available, dict) else 0,
                'compression': ds.get('compression', {}).get('value', 'off'),
                'mountpoint': ds.get('mountpoint'),
                'comments': ds.get('comments', {}).get('value', ''),
                'readonly': ds.get('readonly', {}).get('value', False),
                'children': ds.get('children', [])
            })
        return True, datasets

    def get_all_users(self) -> Tuple[bool, any]:
        """
        Obtém lista de todos os usuários locais do ES-SERVIDOR
        
        Returns:
            Tupla (sucesso, lista_usuarios ou erro)
        """
        success, data = self._make_request('GET', '/user')
        if not success:
            return False, data
        
        users = []
        for user in data:
            # Processa grupos - pode ser lista de IDs ou lista de dicts
            raw_groups = user.get('groups', [])
            group_names = []
            group_ids = []
            
            for g in raw_groups:
                if isinstance(g, dict):
                    group_names.append(g.get('group', g.get('name', '')))
                    group_ids.append(g.get('id'))
                elif isinstance(g, int):
                    group_ids.append(g)
                    # ID puro, não temos o nome
            
            users.append({
                'id': user.get('id'),
                'uid': user.get('uid'),
                'username': user.get('username'),
                'full_name': user.get('full_name', ''),
                'email': user.get('email', ''),
                'home': user.get('home', ''),
                'shell': user.get('shell', '/usr/sbin/nologin'),
                'builtin': user.get('builtin', False),
                'smb': user.get('smb', True),
                'locked': user.get('locked', False),
                'groups': group_names if group_names else group_ids,
                'group_ids': group_ids
            })
        return True, users


    def get_all_groups(self) -> Tuple[bool, any]:
        """
        Obtém lista de todos os grupos locais do ES-SERVIDOR
        
        Returns:
            Tupla (sucesso, lista_grupos ou erro)
        """
        success, data = self._make_request('GET', '/group')
        if not success:
            return False, data
        
        groups = []
        for group in data:
            groups.append({
                'id': group.get('id'),
                'gid': group.get('gid'),
                'name': group.get('group', group.get('name', '')),
                'builtin': group.get('builtin', False),
                'smb': group.get('smb', True),
                'users': group.get('users', [])
            })
        return True, groups

    def get_smb_shares_detailed(self) -> Tuple[bool, any]:
        """
        Obtém lista detalhada de compartilhamentos SMB incluindo ACLs
        
        Returns:
            Tupla (sucesso, lista_shares ou erro)
        """
        # Primeiro obtém os shares básicos
        success, shares = self.get_smb_shares()
        if not success:
            return False, shares
        
        detailed_shares = []
        for share in shares:
            share_info = {
                'id': share.get('id'),
                'name': share.get('name'),
                'path': share.get('path'),
                'enabled': share.get('enabled', True),
                'comment': share.get('comment', ''),
                'acl': None,
                'acl_error': None
            }
            
            # Tenta obter ACL do share
            if share.get('path'):
                acl_success, acl_data = self.get_filesystem_acl(share['path'])
                if acl_success:
                    # Processa ACL para formato amigável
                    acl_entries = []
                    for ace in acl_data.get('acl', []):
                        acl_entries.append({
                            'tag': ace.get('tag', 'unknown'),
                            'id': ace.get('id'),
                            'who': ace.get('who', ''),
                            'type': ace.get('type', 'ALLOW'),
                            'perms': ace.get('perms', {})
                        })
                    share_info['acl'] = acl_entries
                    share_info['owner'] = acl_data.get('uid')
                    share_info['group'] = acl_data.get('gid')
                else:
                    share_info['acl_error'] = acl_data
            
            detailed_shares.append(share_info)
        
        return True, detailed_shares

    def get_smb_status(self) -> Tuple[bool, any]:
        """
        Obtém status do serviço SMB
        
        Returns:
            Tupla (sucesso, status_dict ou erro)
        """
        # Obter configuração SMB
        success, smb_config = self._make_request('GET', '/smb')
        if not success:
            return False, smb_config
        
        # Obter estado real do serviço
        svc_success, services = self._make_request('GET', '/service')
        service_running = False
        if svc_success and isinstance(services, list):
            for svc in services:
                if svc.get('service') == 'cifs':
                    service_running = svc.get('state') == 'RUNNING'
                    break
        
        return True, {
            'enable': service_running,  # Usar estado real do serviço
            'netbiosname': smb_config.get('netbiosname', ''),
            'workgroup': smb_config.get('workgroup', 'WORKGROUP'),
            'description': smb_config.get('description', ''),
            'guest': smb_config.get('guest', 'nobody')
        }

