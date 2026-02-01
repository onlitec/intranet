import logging
import time
from flask import Blueprint, request, jsonify, current_app
from models import db, KnownDevice, DeviceCommand
from datetime import datetime
import config

agent_api = Blueprint('agent_api', __name__)
logger = logging.getLogger('agent_api')

# Cache simples em memória para bloqueio de IPs (Brute-force protection)
failed_attempts = {}

# Cache de IDs de dispositivos por MAC para evitar lookups redundantes
# { 'MAC': device_id }
device_id_cache = {}

def check_rate_limit(ip):
    """Verifica se o IP está bloqueado por excesso de falhas"""
    now = time.time()
    if ip in failed_attempts:
        stats = failed_attempts[ip]
        if stats['blocked_until'] > now:
            return False, stats['blocked_until'] - now
        if stats['fails'] >= config.AGENT_MAX_FAILED_ATTEMPTS:
            # Reset se o tempo de bloqueio já passou
            stats['fails'] = 0
            stats['blocked_until'] = 0
    return True, 0

@agent_api.route('/api/v1/agent/report', methods=['POST'])
def report_telemetry():
    """Recebe telemetria do agente Windows"""
    ip = request.remote_addr
    
    # 1. Verificar Bloqueio
    allowed, remain = check_rate_limit(ip)
    if not allowed:
        logger.warning(f"🚫 Tentativa de reporte vinda de IP bloqueado: {ip}")
        return jsonify({'status': 'error', 'message': f'IP temporarily blocked. Try again in {int(remain)}s'}), 429

    # 2. Autenticação
    auth_token = request.headers.get('X-Agent-Token')
    if auth_token != config.AGENT_TOKEN:
        # Incrementar falha
        if ip not in failed_attempts:
            failed_attempts[ip] = {'fails': 0, 'blocked_until': 0}
        
        failed_attempts[ip]['fails'] += 1
        fails = failed_attempts[ip]['fails']
        
        if fails >= config.AGENT_MAX_FAILED_ATTEMPTS:
            failed_attempts[ip]['blocked_until'] = time.time() + config.AGENT_BLOCK_TIME
            logger.error(f"🚨 IP bloqueado por Brute Force na API do Agente: {ip}")
        
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    # Se chegou aqui, token ok, resetar falhas do IP (opcional, por cortesia)
    if ip in failed_attempts:
        failed_attempts[ip]['fails'] = 0

    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'No data'}), 400
    
    mac = data.get('mac_address', '').upper()
    if not mac:
        return jsonify({'status': 'error', 'message': 'MAC address required'}), 400
    
    try:
        # Busca ID no cache para evitar lookup pesado
        device_id = device_id_cache.get(mac)
        device = None
        
        if device_id:
            device = KnownDevice.query.get(device_id)
        
        if not device:
            # Fallback para busca por MAC (se cache expirou ou device novo)
            device = KnownDevice.query.filter_by(mac_address=mac).first()
            
            if not device:
                device = KnownDevice(
                    mac_address=mac,
                    hostname=data.get('hostname', 'New Device'),
                    category='pc'
                )
                db.session.add(device)
                db.session.flush() # Gerar ID
                logger.info(f"🆕 Novo dispositivo auto-descoberto via agente: {mac} ({data.get('hostname')})")
            
            # Atualizar cache
            device_id_cache[mac] = device.id

        # Atualiza telemetria
        device.last_ip = data.get('ip_address') or ip
        device.hostname = data.get('hostname', device.hostname)
        device.logged_user = data.get('logged_user')
        device.os_info = data.get('os_info')
        device.agent_version = data.get('agent_version')
        device.last_report = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'status': 'ok',
            'message': 'Report received',
            'server_time': datetime.utcnow().isoformat(),
            'pending_commands': DeviceCommand.query.filter_by(device_id=device.id, status='pending').count()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Erro ao processar reporte do agente ({mac}): {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@agent_api.route('/api/v1/agent/commands', methods=['GET'])
def get_pending_commands():
    """Retorna comandos pendentes para o dispositivo"""
    auth_token = request.headers.get('X-Agent-Token')
    if auth_token != config.AGENT_TOKEN:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    mac = request.args.get('mac_address', '').upper()
    if not mac:
        return jsonify({'status': 'error', 'message': 'MAC address required'}), 400
    
    device = KnownDevice.query.filter_by(mac_address=mac).first()
    if not device:
        return jsonify({'status': 'error', 'message': 'Device not found'}), 404
    
    # Busca o comando mais antigo pendente
    command = DeviceCommand.query.filter_by(device_id=device.id, status='pending').order_by(DeviceCommand.created_at.asc()).first()
    
    if not command:
        return jsonify({'status': 'ok', 'commands': []})
    
    # Marca como 'running' para evitar duplicidade (se o agente demorar)
    command.status = 'running'
    db.session.commit()
    
    return jsonify({
        'status': 'ok',
        'commands': [{
            'id': command.id,
            'text': command.command_text
        }]
    })


@agent_api.route('/api/v1/agent/commands/<int:command_id>/result', methods=['POST'])
def report_command_result(command_id):
    """Recebe o resultado da execução de um comando"""
    auth_token = request.headers.get('X-Agent-Token')
    if auth_token != config.AGENT_TOKEN:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'No data'}), 400
    
    command = DeviceCommand.query.get_or_404(command_id)
    
    command.status = data.get('status', 'success') # success ou error
    command.result_output = data.get('output', '')
    command.executed_at = datetime.utcnow()
    
    db.session.commit()
    logger.info(f"💾 Resultado do comando {command_id} recebido para o dispositivo {command.device_id}")
    
    return jsonify({'status': 'ok', 'message': 'Result received'})
