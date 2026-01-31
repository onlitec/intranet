from abc import ABC, abstractmethod
import logging

class BaseAdapter(ABC):
    """
    Interface básica para todos os adapters (DNS, Roteadores, Proxies).
    Garante que todos os fabricantes exponham os mesmos métodos para o core.
    """
    
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger(f"adapter.{self.__class__.__name__}")
        self.is_connected = False

    @abstractmethod
    def connect(self) -> bool:
        """Estabelece conexão com o equipamento/serviço."""
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """Verifica se a conexão está ativa e funcional."""
        pass

    @abstractmethod
    def get_status(self) -> dict:
        """Retorna o status atual do dispositivo (CPU, RAM, Uptime, etc)."""
        pass

    @abstractmethod
    def get_devices(self) -> list:
        """Retorna lista de dispositivos conectados (IP, MAC, Hostname)."""
        return []

    @abstractmethod
    def get_usage(self) -> list:
        """Retorna dados de consumo de tráfego normalizados."""
        return []

    @abstractmethod
    def get_dns_queries(self) -> list:
        """Retorna consultas DNS registradas (se aplicável)."""
        return []

    def disconnect(self):
        """Fecha a conexão de forma segura."""
        self.is_connected = False
