#!/usr/bin/env python3
"""
Script de Configuração Inicial da Intranet TrueNAS
Configura o ambiente e testa a conexão com o TrueNAS
"""
import os
import sys
import secrets
from pathlib import Path

def print_header(text):
    """Imprime cabeçalho formatado"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60 + "\n")

def print_success(text):
    """Imprime mensagem de sucesso"""
    print(f"✓ {text}")

def print_error(text):
    """Imprime mensagem de erro"""
    print(f"✗ {text}")

def print_warning(text):
    """Imprime mensagem de aviso"""
    print(f"⚠ {text}")

def generate_secret_key():
    """Gera uma chave secreta aleatória para o Flask"""
    return secrets.token_urlsafe(32)

def create_env_file():
    """Cria arquivo .env com configurações"""
    print_header("Configuração da Aplicação")
    
    # Verificar se .env já existe
    if os.path.exists('.env'):
        overwrite = input("Arquivo .env já existe. Deseja sobrescrever? (s/N): ")
        if overwrite.lower() != 's':
            print("Mantendo configurações existentes.")
            return True
    
    # Solicitar configurações
    print("\nInforme as configurações do TrueNAS:\n")
    
    truenas_ip = input("IP do TrueNAS [192.168.1.100]: ").strip() or "192.168.1.100"
    
    print("\n" + "-" * 60)
    print("⚠ IMPORTANTE: Como gerar a API Key no TrueNAS")
    print("-" * 60)
    print("1. Acesse a interface web do TrueNAS")
    print("2. Vá em: System Settings → Advanced → API Keys")
    print("3. Clique em 'Add'")
    print("4. Nome: Intranet")
    print("5. Clique em 'Generate Key' e copie a chave")
    print("-" * 60 + "\n")
    
    api_key = input("API Key do TrueNAS: ").strip()
    
    if not api_key:
        print_error("API Key é obrigatória!")
        return False
    
    # Gerar secret key
    secret_key = generate_secret_key()
    
    # Ambiente
    environment = input("\nAmbiente (development/production) [production]: ").strip() or "production"
    
    # Criar conteúdo do .env
    env_content = f"""# Configurações do TrueNAS
TRUENAS_IP={truenas_ip}
TRUENAS_API_KEY={api_key}

# Configurações do Flask
FLASK_SECRET_KEY={secret_key}
FLASK_ENV={environment}
FLASK_HOST=0.0.0.0
FLASK_PORT=5000

# Configurações de Log
LOG_LEVEL=INFO
"""
    
    # Salvar arquivo
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print_success("Arquivo .env criado com sucesso!")
    return True

def test_truenas_connection():
    """Testa conexão com TrueNAS"""
    print_header("Teste de Conectividade")
    
    try:
        # Importar módulos necessários
        from dotenv import load_dotenv
        import requests
        
        # Carregar configurações
        load_dotenv()
        
        truenas_ip = os.getenv('TRUENAS_IP')
        api_key = os.getenv('TRUENAS_API_KEY')
        
        print(f"Testando conexão com TrueNAS em {truenas_ip}...")
        
        # Fazer requisição de teste
        url = f"http://{truenas_ip}/api/v2.0/system/info"
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        print_success(f"Conexão estabelecida com sucesso!")
        print(f"\n  TrueNAS Versão: {data.get('version', 'N/A')}")
        print(f"  Hostname: {data.get('hostname', 'N/A')}")
        print(f"  Uptime: {data.get('uptime', 'N/A')}\n")
        
        return True
        
    except requests.exceptions.ConnectionError:
        print_error(f"Não foi possível conectar ao TrueNAS em {truenas_ip}")
        print_warning("Verifique se o endereço IP está correto e o TrueNAS está acessível")
        return False
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            print_error("API Key inválida ou expirada")
            print_warning("Verifique se a API Key foi copiada corretamente")
        else:
            print_error(f"Erro HTTP {e.response.status_code}: {e}")
        return False
        
    except Exception as e:
        print_error(f"Erro ao testar conexão: {e}")
        return False

def create_directory_structure():
    """Cria estrutura de diretórios necessária"""
    print_header("Criação de Diretórios")
    
    directories = [
        'logs',
        'static/images'
    ]
    
    for directory in directories:
        path = Path(directory)
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            print_success(f"Diretório criado: {directory}")
        else:
            print(f"  Diretório já existe: {directory}")
    
    return True

def check_dependencies():
    """Verifica se as dependências estão instaladas"""
    print_header("Verificação de Dependências")
    
    required_packages = [
        'flask',
        'flask_login',
        'requests',
        'dotenv'
    ]
    
    missing = []
    
    for package in required_packages:
        try:
            __import__(package)
            print_success(f"{package}")
        except ImportError:
            print_error(f"{package} - NÃO INSTALADO")
            missing.append(package)
    
    if missing:
        print_warning("\nDependências faltando. Execute:")
        print("  pip install -r requirements.txt\n")
        return False
    
    return True

def main():
    """Função principal"""
    print("\n" + "=" * 60)
    print("  SETUP - Intranet TrueNAS")
    print("=" * 60)
    
    # Verificar se está no diretório correto
    if not os.path.exists('app.py'):
        print_error("Execute este script a partir do diretório raiz do projeto!")
        sys.exit(1)
    
    # Passo 1: Verificar dependências
    if not check_dependencies():
        sys.exit(1)
    
    # Passo 2: Criar estrutura de diretórios
    create_directory_structure()
    
    # Passo 3: Criar arquivo .env
    if not create_env_file():
        sys.exit(1)
    
    # Passo 4: Testar conexão
    connection_ok = test_truenas_connection()
    
    # Sumário final
    print_header("Resumo da Configuração")
    
    if connection_ok:
        print_success("Setup concluído com sucesso!")
        print("\nPróximos passos:")
        print("  1. Revise o arquivo .env se necessário")
        print("  2. Execute a aplicação:")
        print("     python app.py")
        print("  3. Acesse: http://localhost:5000\n")
    else:
        print_warning("Setup concluído com avisos")
        print("\nProblemas encontrados:")
        print("  - Falha na conexão com TrueNAS")
        print("\nAções recomendadas:")
        print("  1. Verifique o IP do TrueNAS no arquivo .env")
        print("  2. Verifique a API Key")
        print("  3. Certifique-se que o TrueNAS está acessível")
        print("  4. Execute novamente: python setup.py\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelado pelo usuário.")
        sys.exit(0)
