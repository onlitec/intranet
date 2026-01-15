# 🚀 Guia Rápido de Início - Intranet TrueNAS (ATUALIZADO)

## Teste em Modo Desenvolvimento (Servidor Linux)

### 1. Instalar Dependências do Sistema

**IMPORTANTE**: Primeiro instale as dependências do sistema:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip
```

### 2. Criar Ambiente Virtual

```bash
cd /home/alfreire/app/intranet
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar Dependências Python

```bash
pip install -r requirements.txt
```

### 4. Configurar Ambiente

Execute o script de setup interativo:

```bash
python3 setup.py
```

Você será solicitado a informar:
- **IP do TrueNAS**: Por exemplo `192.168.1.100`
- **API Key do TrueNAS**: Gerada em System Settings → Advanced → API Keys

> **📝 Nota**: O setup testará automaticamente a conexão com o TrueNAS

### 5. Iniciar Aplicação

```bash
python3 app.py
```

Você verá algo como:

```
[INFO] Iniciando aplicação Intranet TrueNAS
[INFO] TrueNAS URL: http://192.168.1.100/api/v2.0
[INFO] ✓ Conexão com TrueNAS estabelecida
 * Running on http://0.0.0.0:5000
```

### 6. Acessar Interface

Abra seu navegador em: **http://localhost:5000** ou **http://<IP-do-servidor>:5000**

### 7. Testar Login

Faça login com as credenciais de um usuário do TrueNAS.

---

## Script de Comandos Rápidos

Execute todos os comandos de uma vez (após instalar dependências do sistema):

```bash
cd /home/alfreire/app/intranet
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 setup.py
```

Depois de configurado, para iniciar a aplicação:

```bash
cd /home/alfreire/app/intranet
source venv/bin/activate
python3 app.py
```

---

## Instalação em Produção (Container LXC)

### Pré-requisitos

- Container LXC Ubuntu/Debian no Proxmox
- Acesso root ao container
- Acesso de rede ao TrueNAS

### Passos

```bash
# 1. Acessar o container
# (via console Proxmox ou SSH)

# 2. Navegar para o diretório do projeto
cd /home/seu-usuario/app/intranet

# 3. Executar instalação (como root)
sudo ./install.sh

# 4. Configurar aplicação
cd /opt/intranet
sudo -u www-data python3 setup.py

# 5. Iniciar serviço
sudo systemctl start intranet
sudo systemctl enable intranet

# 6. Verificar status
sudo systemctl status intranet
```

### Acessar Aplicação

- **HTTP**: `http://<IP-do-container>`
- **Logs**: `sudo journalctl -u intranet -f`

---

## Troubleshooting Rápido

### Erro "python3-venv is not available"

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip
```

### Erro "pip not found"

```bash
sudo apt install -y python3-pip
```

### Erro "python not found"

Use `python3` ao invés de `python`:

```bash
python3 setup.py
python3 app.py
```

### Aplicação não inicia

```bash
# Verificar logs
journalctl -u intranet -n 50

# Testar manualmente
cd /opt/intranet
source venv/bin/activate
python3 app.py
```

### Erro "TrueNAS inacessível"

```bash
# Testar conectividade
ping <IP-do-TrueNAS>

# Testar API
curl http://<IP-do-TrueNAS>/api/v2.0/system/info

# Verificar .env
cat .env
```

### API Key inválida

1. Gere nova API Key no TrueNAS
2. Edite o `.env`:
   ```bash
   nano .env
   ```
3. Atualize `TRUENAS_API_KEY`
4. Reinicie:
   ```bash
   # Se em produção
   sudo systemctl restart intranet
   
   # Se em desenvolvimento
   # Pare com Ctrl+C e execute novamente:
   python3 app.py
   ```

---

## Comandos Úteis

### Desenvolvimento

```bash
# Ativar ambiente virtual
source venv/bin/activate

# Desativar ambiente virtual
deactivate

# Reinstalar dependências
pip install -r requirements.txt --upgrade

# Ver logs da aplicação
tail -f logs/app.log
```

### Produção (systemd)

```bash
# Parar serviço
sudo systemctl stop intranet

# Reiniciar serviço
sudo systemctl restart intranet

# Ver logs em tempo real
sudo journalctl -u intranet -f

# Ver status
sudo systemctl status intranet

# Verificar configuração nginx
sudo nginx -t

# Reiniciar nginx
sudo systemctl restart nginx

# Verificar porta 5000
sudo netstat -tulpn | grep 5000
```

---

## Próximos Passos Sugeridos

1. ✅ **Instalar dependências do sistema** (`python3-venv`, `python3-pip`)
2. ✅ **Criar ambiente virtual** e instalar pacotes Python
3. ✅ **Executar setup** e configurar TrueNAS
4. ✅ **Iniciar aplicação** em modo desenvolvimento
5. ✅ **Validar login** com usuário do TrueNAS
6. ✅ **Baixar script .bat** e testar em máquina Windows
7. ✅ **Verificar painel admin** em `/admin`
8. 🔒 **Configurar HTTPS** (ver README.md seção SSL)
9. 📦 **Deploy em produção** (install.sh)

---

## Estrutura de Arquivos

```
✅ /home/alfreire/app/intranet/
   ├── venv/                   # Ambiente virtual Python (criado)
   ├── app.py                  # Aplicação Flask
   ├── config.py               # Configurações
   ├── truenas_api.py         # Cliente API
   ├── setup.py               # Setup interativo
   ├── requirements.txt       # Dependências instaladas ✅
   ├── templates/             # Templates HTML
   ├── static/                # CSS, JS, logo
   └── logs/                  # Logs (criado automaticamente)
```

---

## Suporte

- 📖 **Documentação Completa**: [README.md](file:///home/alfreire/app/intranet/README.md)
- 📝 **Walkthrough Detalhado**: Veja artifacts no brain/
- ⚙️ **Requisitos Originais**: [requisitos.md](file:///home/alfreire/app/intranet/requisitos.md)

**Sistema pronto para teste! 🎉**
