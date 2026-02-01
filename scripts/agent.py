import requests
import socket
import getpass
import platform
import uuid
import time
import json
import subprocess

# Configurações do Servidor
BASE_URL = "http://172.20.120.10/api/v1/agent"
AGENT_TOKEN = "ONLITEC-HUD-2026"
REPORT_INTERVAL = 300  # 5 minutos
POLL_INTERVAL = 30     # 30 segundos para comandos

def get_mac_address():
    """Obtém o endereço MAC da interface principal"""
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                    for ele in range(0, 8*6, 8)][::-1])
    return mac.upper()

def collect_telemetry():
    """Coleta dados do sistema local"""
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        mac_address = get_mac_address()
        logged_user = getpass.getuser()
        os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        
        return {
            "hostname": hostname,
            "ip_address": ip_address,
            "mac_address": mac_address,
            "logged_user": logged_user,
            "os_info": os_info,
            "agent_version": "1.1.0-alpha"
        }
    except Exception as e:
        print(f"Erro ao coletar telemetria: {e}")
        return None

def send_report(data):
    """Envia os dados para a plataforma ES-SERVIDOR"""
    headers = {"X-Agent-Token": AGENT_TOKEN}
    try:
        url = f"{BASE_URL}/report"
        response = requests.post(url, headers=headers, json=data, timeout=10)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"Erro ao enviar reporte: {e}")
        return None

def fetch_commands():
    """Busca comandos pendentes no servidor"""
    headers = {"X-Agent-Token": AGENT_TOKEN}
    mac = get_mac_address()
    try:
        url = f"{BASE_URL}/commands?mac_address={mac}"
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json().get('commands', [])
        return []
    except Exception as e:
        return []

def execute_command(cmd_id, cmd_text):
    """Executa o comando e envia o resultado"""
    print(f"[{time.strftime('%H:%M:%S')}] Executando: {cmd_text}")
    try:
        # Executa comando no shell (Windows)
        process = subprocess.Popen(cmd_text, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        status = "success" if process.returncode == 0 else "error"
        output = stdout if process.returncode == 0 else stderr
        
        # Reportar resultado
        headers = {"X-Agent-Token": AGENT_TOKEN}
        url = f"{BASE_URL}/commands/{cmd_id}/result"
        requests.post(url, headers=headers, json={
            "status": status,
            "output": output
        }, timeout=10)
        
    except Exception as e:
        headers = {"X-Agent-Token": AGENT_TOKEN}
        url = f"{BASE_URL}/commands/{cmd_id}/result"
        requests.post(url, headers=headers, json={
            "status": "error",
            "output": str(e)
        }, timeout=10)

def main():
    print("=== ES-SERVIDOR Agent v1.1 ===")
    print(f"Server: {BASE_URL}")
    print(f"MAC: {get_mac_address()}")
    
    last_report = 0
    
    while True:
        now = time.time()
        
        # 1. Reporte Periódico de Telemetria
        if now - last_report >= REPORT_INTERVAL:
            data = collect_telemetry()
            if data:
                res = send_report(data)
                last_report = now
                if res and res.get('pending_commands', 0) > 0:
                    print("Ordens pendentes detectadas via reporte!")
        
        # 2. Polling de Comandos
        commands = fetch_commands()
        for cmd in commands:
            execute_command(cmd['id'], cmd['text'])
        
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
