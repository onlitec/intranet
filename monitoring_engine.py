import socket
import threading
import logging
import re
import time
from datetime import datetime
from models import db, InternetAccessLog, InternetSource, ESSERVIDORUser, KnownDevice
import os
import routeros_api
from core.services.security import decrypt_credential
from core.adapters.routers.mikrotik import MikroTikAdapter

# Filtros de ruído (sites que devem ser ignorados por padrão)
NOISE_FILTERS = [
    'microsoft.com', 'windows.com', 'live.com', 'office.com', 'google-analytics.com',
    'doubleclick.net', 'googleadservices.com', 'crashlytics.com', 'apple.com',
    'icloud.com', 'googleapis.com', 'gstatic.com', 'fbcdn.net', 'akamai.net',
    'cloudfront.net', 'telemetry', 'update', 'api.'
]

class MonitoringEngine:
    def __init__(self, app):
        self.app = app
        self.logger = app.logger
        self.stop_event = threading.Event()
        self.syslog_thread = None
        self.device_info_cache = {}  # IP -> {'hostname': ..., 'mac': ...}
        self.last_sync_time = 0
        self.syslog_port = int(os.getenv('SYSLOG_PORT', '0') or 0)

    def start(self):
        """Inicia o servidor Syslog em segundo plano"""
        self.syslog_thread = threading.Thread(target=self._run_syslog_server, daemon=True)
        self.syslog_thread.start()
        self.logger.info("📡 Motor de Monitoramento iniciado (Syslog UDP/514)")

    def stop(self):
        self.stop_event.set()
        if self.syslog_thread:
            self.syslog_thread.join(timeout=1)

    def _run_syslog_server(self):
        """Receptor UDP para Syslog"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Se SYSLOG_PORT estiver definido, usa exatamente essa porta.
            if self.syslog_port:
                sock.bind(('0.0.0.0', self.syslog_port))
                self.logger.info(f"✅ Servidor Syslog ouvindo na porta UDP/{self.syslog_port}")
            else:
                # Tenta porta 514 (padrão). Se falhar por permissão, tenta 1514.
                try:
                    sock.bind(('0.0.0.0', 514))
                    self.logger.info("✅ Servidor Syslog ouvindo na porta UDP/514")
                except PermissionError:
                    sock.bind(('0.0.0.0', 1514))
                    self.logger.info("✅ Servidor Syslog ouvindo na porta UDP/1514")
            
            sock.settimeout(1.0)
        except PermissionError:
            self.logger.error("❌ Erro: Permissão negada para porta UDP/514. Execute como Root ou use outra porta.")
            return
        except Exception as e:
            self.logger.error(f"❌ Erro ao iniciar servidor Syslog: {e}")
            return

        while not self.stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                msg = data.decode('utf-8', errors='ignore')
                self._handle_syslog_msg(msg, addr[0])
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Erro no processamento Syslog: {e}")

    def _sync_device_info(self):
        """Sincroniza informações de dispositivos (DHCP/ARP, Banco Local e Dispositivos Conhecidos)"""
        with self.app.app_context():
            # 1. Sincroniza do banco de dados local (ESSERVIDORUser)
            users = ESSERVIDORUser.query.filter(ESSERVIDORUser.ip_address != None).all()
            for user in users:
                self.device_info_cache[user.ip_address] = {
                    'hostname': user.full_name or user.username,
                    'mac': None
                }

            # 2. Sincroniza de Dispositivos Conhecidos (Cadastrados manualmente via MAC)
            known = KnownDevice.query.filter_by(is_active=True).all()
            mac_to_info = {k.mac_address: {'hostname': k.hostname, 'category': k.category} for k in known}

            # 3. Sincroniza do MikroTik (usando o Adapter existente)
            sources = InternetSource.query.filter_by(provider='mikrotik', is_active=True).all()
            for src in sources:
                try:
                    password = decrypt_credential(src.password_encrypted)
                    adapter = MikroTikAdapter({
                        'host': src.host,
                        'username': src.username,
                        'password': password,
                        'port': src.port
                    })
                    
                    if adapter.connect():
                        devices = adapter.get_devices()
                        for d in devices:
                            ip = d.get('ip')
                            if ip:
                                if ip not in self.device_info_cache:
                                    self.device_info_cache[ip] = {}
                                
                                # Prioriza hostname do DHCP se não tiver vindo do banco local
                                if d.get('hostname') != 'Unknown' and not self.device_info_cache[ip].get('hostname'):
                                    self.device_info_cache[ip]['hostname'] = d.get('hostname')
                                
                                mac = d.get('mac')
                                if mac:
                                    # Normaliza para Upper Case para garantir o match
                                    mac = mac.upper()
                                    self.device_info_cache[ip]['mac'] = mac
                                    
                                    # Se este MAC for um dispositivo conhecido, sobrepõe o hostname
                                    if mac in mac_to_info:
                                        self.logger.info(f"📍 Match de dispositivo conhecido: {mac} -> {mac_to_info[mac]['hostname']}")
                                        self.device_info_cache[ip]['hostname'] = mac_to_info[mac]['hostname']
                                        self.device_info_cache[ip]['category'] = mac_to_info[mac]['category']
                        
                        adapter.disconnect()
                except Exception as e:
                    self.logger.error(f"Erro ao sincronizar dispositivos MikroTik ({src.host}): {e}")
            
            self.last_sync_time = time.time()
            self.logger.info(f"🔄 Sincronização de dispositivos concluída ({len(self.device_info_cache)} IPs mapeados)")

    def _handle_syslog_msg(self, msg, source_ip):
        """Processa a mensagem recebida e tenta extrair logs de acesso"""
        with self.app.app_context():
            # Tenta encontrar a fonte pelo IP (host)
            source = InternetSource.query.filter_by(host=source_ip, is_active=True).first()
            source_id = source.id if source else None
            
            # Tenta identificar o formato
            log_entry = None
            
            # Formato Squid Proxy: 123456789.123    123 192.168.1.50 TCP_MISS/200 1234 GET http://example.com/ ...
            if 'TCP_MISS' in msg or 'TCP_HIT' in msg:
                log_entry = self._parse_squid(msg)
            
            # Formato MikroTik DNS: dns: query: www.google.com from 192.168.1.50
            elif 'dns:' in msg and 'query:' in msg:
                log_entry = self._parse_mikrotik_dns(msg)
                
            # Fallback genérico para logs que contenham IP e Domínio
            if not log_entry:
                log_entry = self._parse_generic(msg)

            if log_entry:
                # Filtrar ruído
                for noise in NOISE_FILTERS:
                    if noise in log_entry['website'].lower():
                        return

                # Salvar no banco
                try:
                    # Sincroniza cache a cada 10 minutos
                    if time.time() - self.last_sync_time > 600:
                        self._sync_device_info()

                    ip = log_entry['ip_address']
                    info = self.device_info_cache.get(ip, {})
                    
                    # Nome amigável e MAC
                    hostname = info.get('hostname')
                    mac = info.get('mac')

                    # Tenta Reverse DNS se ainda não tem hostname e o IP é privado
                    if not hostname and (ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.')):
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                            # Limpa hostnames externos que vazam (como o problema relatado)
                            if 'fbcdn.net' in hostname or 'google' in hostname:
                                hostname = None
                        except:
                            hostname = None
                    
                    new_log = InternetAccessLog(
                        source_id=source_id,
                        ip_address=ip,
                        mac_address=mac,
                        hostname=hostname,
                        website=log_entry['website'],
                        full_url=log_entry.get('full_url'),
                        action=log_entry.get('action', 'allowed'),
                        duration=log_entry.get('duration', 0)
                    )
                    db.session.add(new_log)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    self.logger.error(f"Erro ao salvar log de acesso: {e}")

    def _parse_squid(self, msg):
        """Parser básico para logs do Squid"""
        # Ex: 192.168.1.50 TCP_MISS/200 1234 GET http://example.com/
        parts = msg.split()
        try:
            # Procura pelo IP na mensagem (Regex sem grupos de captura para evitar retornos parciais)
            ip_match = re.search(r'(?:\d{1,3}\.){3}\d{1,3}', msg)
            if not ip_match: return None
            
            ip = ip_match.group()
            
            # Tenta pegar a URL (geralmente começa com http)
            url_match = re.search(r'https?://[^\s?]+', msg)
            if url_match:
                full_url = url_match.group()
                parts = full_url.split('/')
                if len(parts) > 2:
                    website = parts[2] # Pega o domínio
                    return {'ip_address': ip, 'website': website, 'full_url': full_url}
        except:
            pass
        return None

    def _parse_mikrotik_dns(self, msg):
        """Parser para logs de DNS do MikroTik"""
        # Ex: dns: query: www.google.com from 192.168.1.50
        try:
            match = re.search(r'query: ([^\s]+) from ([\d\.]+)', msg)
            if match:
                return {
                    'website': match.group(1),
                    'ip_address': match.group(2),
                    'action': 'allowed'
                }
        except: pass
        return None

    def _parse_generic(self, msg):
        """Parser genérico heurístico (melhorado para ignorar cabeçalhos)"""
        try:
            # Ignora IPs de roteadores/cabeçalhos comuns (normalmente no início)
            # Regex corrigida: usa non-capturing group (?:...) para não quebrar o findall
            ips = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', msg)
            if not ips: return None
            
            # Em logs de navegação, o IP do cliente costuma ser o que começa com 192/10/172
            # Se houver mais de um, pegamos o primeiro que parece rede interna
            ip = ips[-1]
            for candidate in ips:
                if candidate.startswith(('192.168.', '10.', '172.')):
                    ip = candidate
                    break
            
            # Website (Domínio) - Evitar que pegue partes de IP como domínio
            domain_match = re.search(r'(?![0-9.]+$)([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}', msg, re.I)
            
            if ip and domain_match:
                website = domain_match.group().lower()
                # Validação extra: IP não pode ser igual ao website parcialmente
                if website in ip or ip in website: return None
                
                return {
                    'ip_address': ip,
                    'website': website
                }
        except: pass
        return None
