# Intranet TrueNAS

Plataforma de intranet para gerenciamento de compartilhamentos SMB do TrueNAS Scale.

## Funcionalidades

- 🔐 **Login duplo**: Usuários TrueNAS e Administradores
- 📁 **Dashboard de compartilhamentos**: Visualização dos shares SMB do usuário
- 📥 **Script de mapeamento**: Download de .bat para mapear drives automaticamente
- 👥 **Gestão de usuários**: Painel admin para gerenciar usuários
- 📊 **Logs de acesso**: Registro de todas as atividades

## Requisitos

- Python 3.10+
- TrueNAS Scale com API habilitada
- Rede interna com acesso ao TrueNAS

## Instalação

```bash
# Clonar repositório
git clone https://github.com/onlitec/intranet.git
cd intranet

# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt

# Configurar variáveis de ambiente
cp .env.example .env
# Editar .env com suas configurações

# Iniciar aplicação
python app.py
```

## Configuração

Edite o arquivo `.env` com:

```env
TRUENAS_IP=172.20.120.23
TRUENAS_API_KEY=sua_api_key_aqui
FLASK_SECRET_KEY=sua_chave_secreta
```

## Estrutura de Branches

| Branch | Descrição |
|--------|-----------|
| `main` | Produção estável |
| `beta` | Testes de novas features |
| `dev` | Desenvolvimento ativo |

## Licença

Proprietary - Onlitec © 2026
