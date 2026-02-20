import logging
import json
from flask import Blueprint, request, jsonify
from flask_socketio import emit, join_room, leave_room
from models import db, KnownDevice, RemoteSessionLog, AdminUser
from datetime import datetime
import config

remote_mgmt = Blueprint('remote_mgmt', __name__)
logger = logging.getLogger('remote_mgmt')

# Dicionário para rastrear conexões ativas { sid: { 'type': 'agent'|'admin', 'id': mac|admin_id } }
active_connections = {}

# Mapeamento de salas por dispositivo { mac: [sid1, sid2, ...] }
device_rooms = {}

# --- REST API Endpoints ---

@remote_mgmt.route('/api/v1/remote/sessions/start', methods=['POST'])
def start_session():
    """Inicia o registro de uma sessão de acesso remoto"""
    auth_token = request.headers.get('X-Admin-Token')
    if auth_token != config.ADMIN_REMOTE_TOKEN:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    data = request.json
    if not data: return jsonify({'status': 'error', 'message': 'No data'}), 400
    
    mac = data.get('mac_address')
    admin_id = data.get('admin_id')
    
    device = KnownDevice.query.filter_by(mac_address=mac).first()
    if not device: return jsonify({'status': 'error', 'message': 'Device not found'}), 404
    
    session = RemoteSessionLog(
        admin_id=admin_id,
        device_id=device.id,
        admin_ip=request.remote_addr,
        status='active'
    )
    db.session.add(session)
    db.session.commit()
    
    logger.info(f"🖥️ Sessão remota iniciada: Admin {admin_id} -> {mac}")
    return jsonify({'status': 'ok', 'session_id': session.id})

@remote_mgmt.route('/api/v1/remote/sessions/stop', methods=['POST'])
def stop_session():
    """Finaliza uma sessão de acesso remoto"""
    auth_token = request.headers.get('X-Admin-Token')
    if auth_token != config.ADMIN_REMOTE_TOKEN:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    data = request.json
    session_id = data.get('session_id')
    
    session = RemoteSessionLog.query.get(session_id)
    if not session: return jsonify({'status': 'error', 'message': 'Session not found'}), 404
    
    session.end_time = datetime.utcnow()
    session.status = 'completed'
    db.session.commit()
    
    return jsonify({'status': 'ok'})

@remote_mgmt.route('/api/v1/remote/agents/online', methods=['GET'])
def get_online_agents():
    """Lista detalhada de agentes online nos últimos 120 segundos"""
    auth_token = request.headers.get('X-Admin-Token')
    # Aceita tanto o ADMIN_REMOTE_TOKEN quanto o novo ONLITEC-ADMIN-2026 para flexibilidade
    if auth_token not in [config.ADMIN_REMOTE_TOKEN, "ONLITEC-ADMIN-2026"]:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    from datetime import timedelta
    threshold = datetime.utcnow() - timedelta(seconds=120)
    
    # Busca dispositivos que reportaram recentemente
    online_devices = KnownDevice.query.filter(KnownDevice.last_report >= threshold).all()
    
    # MACs conectados via WebSocket (prontos para remoto imediato)
    websocket_macs = [info['id'] for info in active_connections.values() if info.get('type') == 'agent']
    
    result = []
    for d in online_devices:
        result.append({
            "mac_address": d.mac_address,
            "hostname": d.hostname,
            "ip_address": d.last_ip,
            "logged_user": d.logged_user,
            "user_domain": d.user_domain,
            "os_info": d.os_info,
            "last_seen": d.last_report.isoformat() if d.last_report else None,
            "uptime": d.uptime,
            "can_remote": d.mac_address in websocket_macs
        })
        
    return jsonify(result)

# --- WebSocket Events (Signal & Relay) ---

def init_socketio_events(socketio):
    @socketio.on('connect')
    def handle_connect():
        logger.info(f"🔗 Nova conexão WebSocket: {request.sid}")

    @socketio.on('register')
    def handle_register(data):
        """Registra a conexão como Agente ou Admin"""
        conn_type = data.get('type') # 'agent' ou 'admin'
        identifier = (data.get('id') or '').upper().replace('-', ':')   # MAC se for agente, AdminID se for admin
        token = data.get('token')
        
        # Validar Token
        if conn_type == 'agent' and token != config.AGENT_TOKEN:
            return emit('error', {'message': 'Invalid Agent Token'})
        if conn_type == 'admin' and token != config.ADMIN_REMOTE_TOKEN:
            return emit('error', {'message': 'Invalid Admin Token'})

        active_connections[request.sid] = {'type': conn_type, 'id': identifier}
        
        if conn_type == 'agent':
            join_room(f"device_{identifier}")
            logger.info(f"🤖 Agente {identifier} registrado na sala device_{identifier}")
        else:
            logger.info(f"👨‍💻 Admin {identifier} registrado")

    @socketio.on('request_access')
    def handle_request_access(data):
        """Admin solicita acesso a um dispositivo"""
        mac = (data.get('target_mac') or d.get('mac') or '').upper().replace('-', ':')
        admin_info = active_connections.get(request.sid)
        
        if not admin_info or admin_info['type'] != 'admin':
            return emit('error', {'message': 'Only admins can request access'})
        
        # Notificar o agente alvo
        emit('incoming_connection', {
            'admin_id': admin_info['id'],
            'session_type': data.get('session_type', 'view') # view, control
        }, room=f"device_{mac}")
        
        # Entrar na sala do dispositivo para receber o relay
        join_room(f"device_{mac}")
        logger.info(f"📣 Admin {admin_info['id']} solicitou acesso ao {mac}")

    @socketio.on('relay_signal')
    def handle_relay_signal(data):
        """Passagem direta de sinais (WebRTC Handshake, Input, etc)"""
        mac = (data.get('target_mac') or d.get('mac') or '').upper().replace('-', ':')
        meta = data.get('meta') # sdp, candidate, input_event
        
        # Envia para a sala do dispositivo (exceto quem enviou)
        emit('signal', {
            'sender_sid': request.sid,
            'source_type': active_connections.get(request.sid, {}).get('type'),
            'data': data.get('data')
        }, room=f"device_{mac}", include_self=False)

    @socketio.on('binary_stream')
    def handle_stream(data):
        """Relay de pacotes binários (Video/Audio)"""
        # data: { mac: string, chunk: bytes }
        mac = data.get('mac')
        emit('stream_data', data.get('chunk'), room=f"device_{mac}", include_self=False)

    @socketio.on('disconnect')
    def handle_disconnect():
        info = active_connections.pop(request.sid, None)
        if info:
            if info['type'] == 'agent':
                logger.info(f"🔌 Agente {info['id']} desconectado")
            else:
                logger.info(f"🔌 Admin {info['id']} desconectado")
