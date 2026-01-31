import csv
import os
from .base import BaseAdapter

class CSVAdapter(BaseAdapter):
    """
    Adapter para processamento de logs baseados em arquivos CSV.
    Utilizado para fins de teste e compatibilidade com sistemas legados.
    """
    
    def connect(self) -> bool:
        file_path = self.config.get('file_path')
        if not file_path:
            self.logger.error("Caminho do arquivo CSV não configurado.")
            return False
        
        if os.path.exists(file_path):
            self.is_connected = True
            return True
        return False

    def test_connection(self) -> bool:
        return self.connect()

    def get_status(self) -> dict:
        return {
            "status": "online" if self.is_connected else "offline",
            "type": "File System",
            "source": self.config.get('file_path')
        }

    def get_usage(self) -> list:
        if not self.is_connected:
            return []
            
        data = []
        try:
            with open(self.config.get('file_path'), mode='r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    # Normalização dos dados para o formato padrão do core
                    data.append({
                        'ip': row.get('ip'),
                        'download': float(row.get('download', 0)),
                        'upload': float(row.get('upload', 0)),
                        'timestamp': row.get('timestamp')
                    })
        except Exception as e:
            self.logger.error(f"Erro ao ler CSV: {e}")
            
        return data

    def get_devices(self) -> list:
        # No CSV, os dispositivos são derivados do log de uso
        usage = self.get_usage()
        ips = list(set(d['ip'] for d in usage))
        return [{'ip': ip, 'hostname': f'User-{ip}'} for ip in ips]

    def get_dns_queries(self) -> list:
        return [] # CSV padrão não tem logs DNS detalhados neste esquema
