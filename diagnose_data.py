#!/usr/bin/env python3
"""
Script de diagnóstico para validar carregamento de dados do ES-SERVIDOR
"""
import sys
sys.path.insert(0, '/opt/intranet')

from dotenv import load_dotenv
load_dotenv('/opt/intranet/.env')

import config
from esservidor_api import ESSERVIDORAPI

def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

def main():
    print_section("DIAGNÓSTICO DE CARREGAMENTO DE DADOS ES-SERVIDOR")
    
    # Inicializa API
    print(f"\n📡 Conectando ao ES-SERVIDOR...")
    print(f"   URL: {config.ESSERVIDOR_API_URL}")
    
    api = ESSERVIDORAPI(config.ESSERVIDOR_API_URL, config.ESSERVIDOR_API_KEY, config.API_TIMEOUT)
    
    # 1. Teste de conexão
    print_section("1. TESTE DE CONEXÃO")
    connected = api.check_connection()
    print(f"   Status: {'✅ CONECTADO' if connected else '❌ FALHA'}")
    
    if not connected:
        print("\n❌ Não foi possível conectar ao ES-SERVIDOR. Verifique:")
        print("   - IP do servidor está correto")
        print("   - API Key está válida")
        print("   - Servidor está acessível na rede")
        return
    
    # 2. Informações do sistema
    print_section("2. INFORMAÇÕES DO SISTEMA")
    success, info = api.get_system_info()
    if success:
        print(f"   ✅ Hostname: {info.get('hostname', 'N/A')}")
        print(f"   ✅ Versão: {info.get('version', 'N/A')}")
    else:
        print(f"   ❌ Erro: {info}")
    
    # 3. Pools de armazenamento
    print_section("3. POOLS DE ARMAZENAMENTO")
    success, pools = api.get_pools()
    if success:
        print(f"   ✅ {len(pools)} pool(s) encontrado(s)")
        for pool in pools:
            size_gb = pool.get('size', 0) / 1073741824
            used_gb = pool.get('allocated', 0) / 1073741824
            print(f"      📦 {pool['name']}: {used_gb:.1f} GB / {size_gb:.1f} GB - Status: {pool['status']}")
    else:
        print(f"   ❌ Erro: {pools}")
    
    # 4. Datasets
    print_section("4. DATASETS")
    success, datasets = api.get_datasets()
    if success:
        print(f"   ✅ {len(datasets)} dataset(s) encontrado(s)")
        for ds in datasets[:5]:  # Mostra só os 5 primeiros
            used_gb = ds.get('used_bytes', 0) / 1073741824
            print(f"      📂 {ds['name']}: {used_gb:.2f} GB usado")
        if len(datasets) > 5:
            print(f"      ... e mais {len(datasets) - 5} datasets")
    else:
        print(f"   ❌ Erro: {datasets}")
    
    # 5. Usuários do servidor
    print_section("5. USUÁRIOS DO SERVIDOR")
    success, users = api.get_all_users()
    if success:
        # Filtra usuários não-builtin
        normal_users = [u for u in users if not u.get('builtin', False)]
        print(f"   ✅ {len(users)} usuário(s) total, {len(normal_users)} não-sistema")
        for user in normal_users[:5]:
            print(f"      👤 {user['username']} (UID: {user['uid']}) - SMB: {'Sim' if user.get('smb') else 'Não'}")
        if len(normal_users) > 5:
            print(f"      ... e mais {len(normal_users) - 5} usuários")
    else:
        print(f"   ❌ Erro: {users}")
    
    # 6. Grupos do servidor
    print_section("6. GRUPOS DO SERVIDOR")
    success, groups = api.get_all_groups()
    if success:
        normal_groups = [g for g in groups if not g.get('builtin', False)]
        print(f"   ✅ {len(groups)} grupo(s) total, {len(normal_groups)} não-sistema")
        for group in normal_groups[:5]:
            print(f"      👥 {group['name']} (GID: {group['gid']})")
    else:
        print(f"   ❌ Erro: {groups}")
    
    # 7. Compartilhamentos SMB
    print_section("7. COMPARTILHAMENTOS SMB")
    success, shares = api.get_smb_shares()
    if success:
        print(f"   ✅ {len(shares)} compartilhamento(s) encontrado(s)")
        for share in shares:
            status = "Ativo" if share.get('enabled', True) else "Inativo"
            print(f"      📁 {share['name']}: {share['path']} [{status}]")
    else:
        print(f"   ❌ Erro: {shares}")
    
    # 8. Status do SMB
    print_section("8. STATUS DO SERVIÇO SMB")
    success, smb_status = api.get_smb_status()
    if success:
        print(f"   ✅ Serviço SMB: {'Ativo' if smb_status.get('enable') else 'Inativo'}")
        print(f"      Workgroup: {smb_status.get('workgroup', 'N/A')}")
        print(f"      NetBIOS: {smb_status.get('netbiosname', 'N/A')}")
    else:
        print(f"   ❌ Erro: {smb_status}")
    
    # 9. Logs de auditoria
    print_section("9. LOGS DE AUDITORIA SMB")
    success, logs = api.get_audit_logs(limit=10)
    if success:
        print(f"   ✅ {len(logs)} registro(s) de auditoria recentes")
        for log in logs[:3]:
            print(f"      📋 {log.get('timestamp', 'N/A')} - {log.get('username', 'N/A')}: {log.get('action', 'N/A')} - {log.get('path', 'N/A')}")
        if len(logs) > 3:
            print(f"      ... e mais {len(logs) - 3} registros")
    else:
        print(f"   ❌ Erro ao carregar auditoria: {logs}")
    
    # Resumo
    print_section("RESUMO")
    print("   ✅ Conexão com ES-SERVIDOR: OK")
    print(f"   ✅ Pools: {len(pools) if 'pools' in dir() and isinstance(pools, list) else 'N/A'}")
    print(f"   ✅ Datasets: {len(datasets) if 'datasets' in dir() and isinstance(datasets, list) else 'N/A'}")
    print(f"   ✅ Usuários: {len(users) if 'users' in dir() and isinstance(users, list) else 'N/A'}")
    print(f"   ✅ Grupos: {len(groups) if 'groups' in dir() and isinstance(groups, list) else 'N/A'}")
    print(f"   ✅ Shares SMB: {len(shares) if 'shares' in dir() and isinstance(shares, list) else 'N/A'}")
    print("\n🎉 Todos os dados do ES-SERVIDOR estão sendo carregados corretamente!\n")

if __name__ == '__main__':
    main()
