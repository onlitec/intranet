import time
import logging
import sys
import os

# Adiciona o diretório atual ao path para importar core e models
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from wsgi import app
from models import db
from models import InternetSource, InternetAccessLog, ESSERVIDORUser
from core.services.adapter_factory import AdapterFactory
from monitoring_engine import MonitoringEngine

# Configuração de Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("engine.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("internet_engine")

def process_source(source):
    """Processa uma fonte específica usando seu respectivo adapter"""
    logger.info(f"Processando fonte: {source.name} ({source.provider})")
    
    from core.services.security import decrypt_credential
    
    # Prepara configuração para o adapter
    config = {
        'host': source.host,
        'port': source.port,
        'username': source.username,
        'password': decrypt_credential(source.password_encrypted),
        'file_path': '/opt/intranet/internet_usage.csv' if source.provider == 'csv' else None
    }
    
    adapter = AdapterFactory.get_adapter(source.provider, config)
    if not adapter:
        logger.error(f"Não foi possível carregar adapter para {source.provider}")
        return

    if not adapter.connect():
        logger.error(f"Falha na conexão com {source.name}")
        return

    try:
        from core.normalizers.base_normalizer import DataNormalizer
        
        # 1. Coletar e Normalizar dados de uso
        raw_usage = adapter.get_usage()
        logger.info(f"Coletados {len(raw_usage)} registros de uso de {source.name}")
        
        for raw_item in raw_usage:
            item = DataNormalizer.normalize_usage(raw_item)
            if item['ip'] and (item['download'] > 0 or item['upload'] > 0):
                log = InternetAccessLog(
                    source_id=source.id,
                    ip_address=item['ip'],
                    bytes_sent=item['upload'],
                    bytes_received=item['download'],
                    timestamp=item['timestamp'],
                    action='allowed'
                )
                db.session.add(log)
                
                # Atualizar usuário
                user = ESSERVIDORUser.query.filter_by(ip_address=item['ip']).first()
                if user:
                    user.last_activity = db.func.now()
                    user.is_online = True
        
        # 2. Coletar e Normalizar DNS
        raw_dns = adapter.get_dns_queries()
        if raw_dns:
            logger.info(f"Coletadas {len(raw_dns)} queries DNS de {source.name}")
            for raw_q in raw_dns:
                q = DataNormalizer.normalize_dns(raw_q)
                log = InternetAccessLog(
                    source_id=source.id,
                    ip_address=q['ip'],
                    website=q['domain'],
                    action=q['action'],
                    timestamp=q['timestamp']
                )
                db.session.add(log)

        # 3. Atualizar carimbo de sincronização
        source.last_sync = db.func.now()
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Erro ao processar dados de {source.name}: {e}")
        db.session.rollback()
    finally:
        adapter.disconnect()

def run_engine():
    """Loop principal da engine de coleta"""
    logger.info("Iniciando Engine de Monitoramento Modular...")
    
    with app.app_context():
        # Inicia receptor de Syslog
        monitoring = MonitoringEngine(app)
        monitoring.start()
        
        while True:
            try:
                # Busca todas as fontes ativas
                sources = InternetSource.query.filter_by(is_active=True).all()
                if not sources:
                    logger.warning("Nenhuma fonte de dados ativa encontrada no banco.")
                
                for source in sources:
                    process_source(source)
                
                logger.info("Ciclo de coleta finalizado. Aguardando 60 segundos...")
                time.sleep(60)
            except Exception as e:
                logger.error(f"Erro crítico no loop da engine: {e}")
                db.session.rollback() # Garante limpeza da transação
                time.sleep(10)

if __name__ == "__main__":
    run_engine()
