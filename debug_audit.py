#!/usr/bin/env python3
"""
Debug script para investigar logs de auditoria do ES-SERVIDOR
"""
import sys
sys.path.insert(0, '/opt/intranet')

from dotenv import load_dotenv
load_dotenv('/opt/intranet/.env')

import config
import requests
import json

def main():
    print("="*60)
    print("  DEBUG: LOGS DE AUDITORIA ES-SERVIDOR")
    print("="*60)
    
    url = config.ESSERVIDOR_API_URL
    api_key = config.ESSERVIDOR_API_KEY
    
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    
    # 1. Testar endpoint de auditoria diretamente
    print("\n1. TESTANDO ENDPOINT /audit/query")
    print("-"*40)
    
    # Payload para buscar logs SMB
    payload = {
        "services": ["SMB"],
        "query-filters": [],
        "query-options": {
            "limit": 50,
            "order_by": ["-message_timestamp"]
        }
    }
    
    try:
        response = requests.post(
            f"{url}/audit/query",
            headers=headers,
            json=payload,
            verify=False,
            timeout=30
        )
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   Registros retornados: {len(data)}")
            
            if data:
                print("\n   Últimos 10 registros:")
                for i, entry in enumerate(data[:10]):
                    timestamp = entry.get('message_timestamp', 'N/A')
                    event = entry.get('event', 'N/A')
                    username = entry.get('username', 'N/A')
                    svc_data = entry.get('event_data', {})
                    file_name = svc_data.get('file', {}).get('name', 'N/A') if isinstance(svc_data.get('file'), dict) else svc_data.get('file', 'N/A')
                    
                    print(f"   [{i+1}] {timestamp}")
                    print(f"       Evento: {event}")
                    print(f"       Usuário: {username}")
                    print(f"       Arquivo: {file_name}")
                    print()
            else:
                print("\n   ⚠️  NENHUM REGISTRO DE AUDITORIA ENCONTRADO!")
        else:
            print(f"   Erro: {response.text[:500]}")
    except Exception as e:
        print(f"   Exceção: {e}")
    
    # 2. Verificar configuração de auditoria do SMB
    print("\n2. VERIFICANDO CONFIGURAÇÃO DE AUDITORIA SMB")
    print("-"*40)
    
    try:
        response = requests.get(
            f"{url}/smb",
            headers=headers,
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            smb_config = response.json()
            print(f"   SMB Habilitado: {smb_config.get('enable', 'N/A')}")
            print(f"   Auditoria: {smb_config.get('enable_smb1', 'N/A')}")
            
            # Mostrar config de auditoria se existir
            audit_cfg = smb_config.get('audit', {})
            if audit_cfg:
                print(f"   Config Auditoria: {json.dumps(audit_cfg, indent=2)}")
            else:
                print("   ⚠️  Configuração de auditoria não encontrada no SMB config")
        else:
            print(f"   Erro: {response.status_code}")
    except Exception as e:
        print(f"   Exceção: {e}")
    
    # 3. Verificar shares e suas configurações de auditoria
    print("\n3. VERIFICANDO AUDITORIA NOS COMPARTILHAMENTOS")
    print("-"*40)
    
    try:
        response = requests.get(
            f"{url}/sharing/smb",
            headers=headers,
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            shares = response.json()
            for share in shares:
                name = share.get('name', 'N/A')
                path = share.get('path', 'N/A')
                audit_enabled = share.get('audit', {}).get('enable', False) if share.get('audit') else False
                
                print(f"   📁 {name}")
                print(f"      Path: {path}")
                print(f"      Auditoria: {'✅ Habilitada' if audit_enabled else '❌ DESABILITADA'}")
                
                # Mostrar config de audit se existir
                if share.get('audit'):
                    audit = share['audit']
                    print(f"      Config: {json.dumps(audit, indent=6)}")
                print()
        else:
            print(f"   Erro: {response.status_code}")
    except Exception as e:
        print(f"   Exceção: {e}")
    
    # 4. Tentar endpoint alternativo
    print("\n4. TESTANDO ENDPOINTS ALTERNATIVOS")
    print("-"*40)
    
    endpoints = [
        "/audit",
        "/audit/config",
        "/system/audit"
    ]
    
    for ep in endpoints:
        try:
            response = requests.get(
                f"{url}{ep}",
                headers=headers,
                verify=False,
                timeout=5
            )
            print(f"   {ep}: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    print(f"      Keys: {list(data.keys())[:5]}")
        except Exception as e:
            print(f"   {ep}: Erro - {e}")

if __name__ == '__main__':
    main()
