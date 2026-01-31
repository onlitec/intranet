from datetime import datetime

class DataNormalizer:
    """
    Serviço para normalizar diferentes formatos de dados em um padrão único para o Banco de Dados.
    """
    
    @staticmethod
    def normalize_usage(raw_data: dict) -> dict:
        """Normaliza registros de consumo (Upload/Download)"""
        ts = raw_data.get('timestamp')
        if isinstance(ts, str):
            try:
                ts = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
            except:
                ts = datetime.utcnow()
        
        return {
            'ip': raw_data.get('ip'),
            'mac': raw_data.get('mac'),
            'hostname': raw_data.get('hostname'),
            'download': int(raw_data.get('download', 0) or raw_data.get('rx', 0)),
            'upload': int(raw_data.get('upload', 0) or raw_data.get('tx', 0)),
            'timestamp': ts or datetime.utcnow(),
            'interface': raw_data.get('interface')
        }

    @staticmethod
    def normalize_dns(raw_data: dict) -> dict:
        """Normaliza registros de consultas DNS"""
        ts = raw_data.get('timestamp')
        if isinstance(ts, str):
            try:
                ts = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
            except:
                ts = datetime.utcnow()

        return {
            'ip': raw_data.get('client_ip') or raw_data.get('ip'),
            'domain': raw_data.get('domain'),
            'action': raw_data.get('status', 'allowed'), # allowed/blocked
            'timestamp': ts or datetime.utcnow()
        }
