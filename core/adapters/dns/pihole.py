from ..base import BaseAdapter
import requests
import time

class PiHoleAdapter(BaseAdapter):
    """
    Adapter para Pi-hole (DNS Sinkhole).
    Utiliza a API do Pi-hole para coletar queries e estatísticas.
    """
    
    def connect(self) -> bool:
        # Pi-hole geralmente usa token API
        self.api_url = f"http://{self.config.get('host')}:{self.config.get('port', 80)}/admin/api.php"
        self.api_token = self.config.get('password') # Usamos o campo password para o token
        
        try:
            # Teste básico sem token (algumas APIs são abertas para stats básicos)
            response = requests.get(f"{self.api_url}?summary", timeout=5)
            if response.status_code == 200:
                self.is_connected = True
                return True
        except:
            pass
        return False

    def test_connection(self) -> bool:
        return self.connect()

    def get_status(self) -> dict:
        if not self.is_connected: return {"status": "offline"}
        
        try:
            data = requests.get(f"{self.api_url}?summary", timeout=5).json()
            return {
                "status": data.get('status', 'unknown'),
                "queries_today": data.get('dns_queries_today'),
                "ads_blocked": data.get('ads_blocked_today'),
                "ads_percentage": data.get('ads_percentage_today')
            }
        except:
            return {"status": "error"}

    def get_dns_queries(self) -> list:
        """
        Coleta queries DNS recentes.
        Requer API Token para dados detalhados.
        """
        if not self.api_token:
            self.logger.warning("Pi-hole: API Token não fornecido. Não é possível coletar queries detalhadas.")
            return []

        try:
            # getAllQueries retorna as últimas queries
            url = f"{self.api_url}?getAllQueries&auth={self.api_token}"
            data = requests.get(url, timeout=10).json()
            
            normalized_queries = []
            for q in data.get('data', []):
                # q format: [timestamp, type, domain, client_ip, status]
                normalized_queries.append({
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(q[0]))),
                    'domain': q[2],
                    'client_ip': q[3],
                    'status': 'blocked' if int(q[4]) in [1, 4, 5, 9, 10, 11] else 'allowed'
                })
            return normalized_queries
        except Exception as e:
            self.logger.error(f"Erro ao coletar queries do Pi-hole: {e}")
            return []

    def get_usage(self) -> list:
        # DNS não provê uso de banda diretamente, mas podemos inferir atividade
        return []

    def get_devices(self) -> list:
        try:
            # Top clients pode ser usado para identificar dispositivos
            url = f"{self.api_url}?getQuerySources&auth={self.api_token}"
            data = requests.get(url, timeout=5).json()
            clients = []
            for ip, count in data.get('top_sources', {}).items():
                clients.append({'ip': ip, 'queries': count})
            return clients
        except:
            return []
