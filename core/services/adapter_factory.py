import importlib
import logging

class AdapterFactory:
    """
    Fábrica dinâmica para carregar adapters sob demanda.
    Garante que a plataforma continue funcionando mesmo se uma integração falhar.
    """
    
    # Mapeamento de tipos para caminhos de classe
    _MAPPING = {
        'csv': 'core.adapters.csv_adapter.CSVAdapter',
        'mikrotik': 'core.adapters.routers.mikrotik.MikroTikAdapter',
        'pihole': 'core.adapters.dns.pihole.PiHoleAdapter',
        'squid': 'core.adapters.proxies.squid.SquidAdapter',
    }

    @staticmethod
    def get_adapter(adapter_type: str, config: dict):
        logger = logging.getLogger("core.factory")
        
        class_path = AdapterFactory._MAPPING.get(adapter_type.lower())
        if not class_path:
            logger.error(f"Adapter tipo '{adapter_type}' não suportado.")
            return None

        try:
            module_path, class_name = class_path.rsplit('.', 1)
            module = importlib.import_module(module_path)
            adapter_class = getattr(module, class_name)
            return adapter_class(config)
        except Exception as e:
            logger.error(f"Erro ao carregar adapter {adapter_type}: {e}")
            return None
