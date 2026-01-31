from ..base import BaseAdapter
import os
import re
import time

class SquidAdapter(BaseAdapter):
    """
    Adapter para Squid Proxy.
    Focado em leitura e parse do access.log do Squid.
    """
    
    def connect(self) -> bool:
        self.log_path = self.config.get('log_path', '/var/log/squid/access.log')
        if os.path.exists(self.log_path):
            self.is_connected = True
            return True
        # Se não local, pode ser via SSH ou Syslog (simplificado aqui para local)
        return False

    def test_connection(self) -> bool:
        return self.connect()

    def get_status(self) -> dict:
        return {
            "status": "online" if self.is_connected else "offline",
            "log_source": self.log_path
        }

    def get_usage(self) -> list:
        if not self.is_connected: return []
        
        usage = []
        try:
            # Lê as últimas N linhas do log (exemplo simplificado)
            with open(self.log_path, 'r') as f:
                # Seek para o final ou ler pequeno chunk
                lines = f.readlines()[-100:] 
                
                for line in lines:
                    # Formato padrão Squid: timestamp duration client_address result_code/status bytes method url rfc931 peer_info/peer_host content_type
                    parts = line.split()
                    if len(parts) >= 10:
                        usage.append({
                            'timestamp': parts[0],
                            'ip': parts[2],
                            'action': 'allowed' if 'TCP_MISS' in parts[3] or 'TCP_HIT' in parts[3] else 'blocked',
                            'download': int(parts[4]),
                            'url': parts[6]
                        })
        except Exception as e:
            self.logger.error(f"Erro ao ler log do Squid: {e}")
            
        return usage

    def get_dns_queries(self) -> list:
        # Squid registra URLs, que podem ser convertidas em domínios
        usage = self.get_usage()
        domains = []
        for item in usage:
            url = item.get('url', '')
            # Extrair domínio simples
            domain = url.split('//')[-1].split('/')[0].split(':')[0]
            domains.append({
                'timestamp': item['timestamp'],
                'client_ip': item['ip'],
                'domain': domain,
                'status': item['action']
            })
        return domains

    def get_devices(self) -> list:
        usage = self.get_usage()
        ips = list(set(d['ip'] for d in usage))
        return [{'ip': ip} for ip in ips]
