#!/usr/bin/env python3
"""
Debug detalhado da estrutura dos logs de auditoria
"""
import sys
sys.path.insert(0, '/opt/intranet')

from dotenv import load_dotenv
load_dotenv('/opt/intranet/.env')

import config
import requests
import json

def main():
    url = config.ESSERVIDOR_API_URL
    api_key = config.ESSERVIDOR_API_KEY
    
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    
    # Buscar todos os tipos de eventos
    payload = {
        "services": ["SMB"],
        "query-filters": [],
        "query-options": {
            "limit": 100,
            "order_by": ["-message_timestamp"]
        }
    }
    
    response = requests.post(
        f"{url}/audit/query",
        headers=headers,
        json=payload,
        verify=False,
        timeout=30
    )
    
    if response.status_code == 200:
        data = response.json()
        
        # Contar tipos de eventos
        event_counts = {}
        for entry in data:
            event = entry.get('event', 'UNKNOWN')
            event_counts[event] = event_counts.get(event, 0) + 1
        
        print("="*60)
        print("  TIPOS DE EVENTOS ENCONTRADOS")
        print("="*60)
        for event, count in sorted(event_counts.items(), key=lambda x: -x[1]):
            print(f"   {event}: {count}")
        
        # Mostrar estrutura completa de um registro
        print("\n" + "="*60)
        print("  ESTRUTURA COMPLETA DE UM REGISTRO")
        print("="*60)
        if data:
            print(json.dumps(data[0], indent=2, default=str))
        
        # Buscar especificamente eventos UNLINK (delete)
        print("\n" + "="*60)
        print("  BUSCANDO EVENTOS DE DELEÇÃO (UNLINK)")
        print("="*60)
        
        delete_events = [e for e in data if e.get('event') in ['UNLINK', 'DELETE', 'RMDIR']]
        if delete_events:
            print(f"   Encontrados: {len(delete_events)} eventos de deleção")
            for i, ev in enumerate(delete_events[:5]):
                print(f"\n   [{i+1}]")
                print(json.dumps(ev, indent=4, default=str))
        else:
            print("   ⚠️  NENHUM evento UNLINK/DELETE encontrado nos últimos 100 registros")
            print("\n   Isso pode indicar que:")
            print("   1. As deleções não estão sendo registradas pelo SMB")
            print("   2. O tipo de evento é diferente (verificar docs do TrueNAS)")
            print("   3. O arquivo foi deletado há mais de 100 operações atrás")
        
        # Verificar se há eventos recentes (últimos 5 min)
        print("\n" + "="*60)
        print("  VERIFICANDO TIMESTAMPS")
        print("="*60)
        
        import time
        now = int(time.time())
        
        for entry in data[:5]:
            ts = entry.get('message_timestamp', 0)
            if isinstance(ts, int):
                age_seconds = now - ts
                age_minutes = age_seconds / 60
                print(f"   Timestamp: {ts} (há {age_minutes:.1f} minutos)")
            else:
                print(f"   Timestamp: {ts} (formato desconhecido)")

if __name__ == '__main__':
    main()
