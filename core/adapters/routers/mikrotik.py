from ..base import BaseAdapter
import time

class MikroTikAdapter(BaseAdapter):
    """
    Adapter para integração com Roteadores MikroTik via API.
    Sempre usa importações dinâmicas para manter dependências isoladas.
    """
    
    def __init__(self, config=None):
        super().__init__(config)
        self.api = None
        self.connection = None

    def _get_api_client(self):
        try:
            import routeros_api
            return routeros_api
        except ImportError:
            self.logger.error("Biblioteca 'routeros-api' não encontrada. Instale com 'pip install routeros-api'")
            return None

    def connect(self) -> bool:
        ros = self._get_api_client()
        if not ros: return False

        host = self.config.get('host')
        user = self.config.get('username')
        port = int(self.config.get('port') or 0)
        
        # Auto-detecta SSL baseado na porta padrão do MikroTik se não especificado
        use_ssl = self.config.get('use_ssl')
        if use_ssl is None:
            use_ssl = True if port == 8729 else False
        
        if port == 0:
            port = 8729 if use_ssl else 8728

        self.logger.info(f"Tentando conexão MikroTik em {host}:{port} (SSL: {use_ssl})")

        try:
            self.connection = ros.RouterOsApiPool(
                host,
                username=user,
                password=self.config.get('password'),
                port=port,
                use_ssl=use_ssl,
                ssl_verify=False,
                ssl_verify_hostname=False,
                plaintext_login=True
            )
            self.api = self.connection.get_api()
            self.is_connected = True
            return True
        except Exception as e:
            error_msg = str(e) or "Erro desconhecido (verifique porta/SSL/Credenciais)"
            self.logger.error(f"Falha ao conectar no MikroTik ({host}:{port}): {error_msg}")
            self.is_connected = False
            return False

    def test_connection(self) -> bool:
        if not self.is_connected: return self.connect()
        try:
            self.api.get_resource('/system/identity').get()
            return True
        except:
            return self.connect()

    def get_status(self) -> dict:
        if not self.test_connection(): return {"status": "offline"}
        
        resource = self.api.get_resource('/system/resource').get()[0]
        identity = self.api.get_resource('/system/identity').get()[0]
        
        return {
            "status": "online",
            "name": identity.get('name'),
            "cpu_load": f"{resource.get('cpu-load')}%",
            "uptime": resource.get('uptime'),
            "version": resource.get('version'),
            "model": resource.get('board-name')
        }

    def get_devices(self) -> list:
        if not self.test_connection(): return []
        
        devices = []
        # Obtém leases do DHCP
        leases = self.api.get_resource('/ip/dhcp-server/lease').get()
        for lease in leases:
            devices.append({
                'ip': lease.get('address'),
                'mac': lease.get('mac-address'),
                'hostname': lease.get('host-name', 'Unknown'),
                'status': 'active' if lease.get('status') == 'bound' else 'inactive'
            })
        return devices

    def get_usage(self) -> list:
        if not self.test_connection(): return []
        
        usage_data = []
        # Obtém tráfego por fila (Simple Queues) ou Interfaces
        # Exemplo simplificado via Interfaces
        interfaces = self.api.get_resource('/interface').get()
        for iface in interfaces:
            if iface.get('type') in ['ether', 'wlan', 'vlan']:
                usage_data.append({
                    'interface': iface.get('name'),
                    'rx': int(iface.get('rx-byte', 0)),
                    'tx': int(iface.get('tx-byte', 0)),
                    'type': 'interface_usage'
                })
        
        # Se o user quiser por IP, o MikroTik precisaria de Accounting ou Kid Control ativado
        # Mock de processamento de Kid Control para exemplo
        try:
            kid_stats = self.api.get_resource('/ip/kid-control/device').get()
            for kid in kid_stats:
                usage_data.append({
                    'ip': kid.get('ip-address'),
                    'download': int(kid.get('bytes-down', 0)),
                    'upload': int(kid.get('bytes-up', 0)),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                })
        except:
            pass # Nem todo mikrotik tem kid control configurado

        return usage_data

    def get_dns_queries(self) -> list:
        # MikroTik DNS cache doesn't store history logs unless logging is specifically pointing here
        return []

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()
        super().disconnect()
