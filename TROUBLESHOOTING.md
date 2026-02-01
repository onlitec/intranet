# 🔧 Guia de Solução de Problemas - Servidor Flask

## ⚠️ Erro 500 (Internal Server Error)

### Causa Raiz Identificada
O erro `ModuleNotFoundError: No module named 'markdown'` ocorria porque o Gunicorn estava sendo executado com o Python do sistema (`/usr/bin/python3`) ao invés do Python do virtualenv (`/opt/intranet/venv/bin/python3`).

### ✅ Solução Implementada

#### 1. Script de Inicialização Automática
Criado o arquivo `/opt/intranet/start_server.sh` que:
- ✅ Garante uso do Python do virtualenv
- ✅ Verifica e instala dependências faltantes
- ✅ Para processos antigos antes de iniciar novos
- ✅ Valida se o servidor iniciou corretamente
- ✅ Exibe logs em caso de erro

#### 2. Como Usar o Script

**Iniciar o servidor:**
```bash
cd /opt/intranet
./start_server.sh
```

**Reiniciar o servidor:**
```bash
cd /opt/intranet
./start_server.sh  # O script já mata processos antigos
```

**Parar o servidor:**
```bash
pkill -f "gunicorn.*wsgi:app"
```

#### 3. Comando Manual (se necessário)
Se precisar iniciar manualmente, use SEMPRE o caminho completo do venv:

```bash
cd /opt/intranet
nohup /opt/intranet/venv/bin/gunicorn \
    --workers 4 \
    --threads 2 \
    --worker-class gthread \
    --bind 127.0.0.1:5000 \
    --access-logfile /opt/intranet/logs/access.log \
    --error-logfile /opt/intranet/logs/error.log \
    wsgi:app > /dev/null 2>&1 &
```

**❌ NUNCA USE:**
```bash
gunicorn wsgi:app  # Usa Python do sistema!
```

### 🔍 Diagnóstico de Problemas

#### Verificar qual Python o Gunicorn está usando:
```bash
ps aux | grep gunicorn | grep -v grep
```

**✅ Correto:** `/opt/intranet/venv/bin/python3`  
**❌ Incorreto:** `/usr/bin/python3` ou `/home/*/...local/bin/...`

#### Ver logs de erro em tempo real:
```bash
tail -f /opt/intranet/logs/error.log
```

#### Testar se o servidor está respondendo:
```bash
curl -I http://127.0.0.1:5000/admin/login
```

**Resposta esperada:** `HTTP/1.1 200 OK`

### 📋 Checklist de Solução de Problemas

Quando ocorrer erro 500, siga esta ordem:

1. ✅ **Verificar logs:**
   ```bash
   tail -50 /opt/intranet/logs/error.log
   ```

2. ✅ **Verificar Python do Gunicorn:**
   ```bash
   ps aux | grep gunicorn | grep -v grep | head -1
   ```

3. ✅ **Reiniciar com script correto:**
   ```bash
   cd /opt/intranet && ./start_server.sh
   ```

4. ✅ **Verificar se módulos estão instalados:**
   ```bash
   /opt/intranet/venv/bin/python3 -c "import markdown; import flask; print('OK')"
   ```

5. ✅ **Testar endpoint:**
   ```bash
   curl -I http://127.0.0.1:5000/admin/login
   ```

### 🚀 Prevenção Futura

Para evitar que o problema ocorra novamente:

1. **SEMPRE** use o script `start_server.sh` para iniciar o servidor
2. **NUNCA** use `gunicorn` sem o caminho completo do venv
3. **Verifique** os logs regularmente
4. **Documente** qualquer nova dependência no `requirements.txt`

### 🛠️ Manutenção

#### Atualizar dependências:
```bash
cd /opt/intranet
source venv/bin/activate
pip install -r requirements.txt
deactivate
./start_server.sh
```

#### Adicionar nova dependência:
```bash
cd /opt/intranet
source venv/bin/activate
pip install nome-do-pacote
pip freeze > requirements.txt
deactivate
./start_server.sh
```

### 📞 Suporte

Se o problema persistir após seguir este guia:

1. Capture os logs completos:
   ```bash
   tail -100 /opt/intranet/logs/error.log > error_debug.txt
   ```

2. Verifique processos ativos:
   ```bash
   ps aux | grep gunicorn > processes.txt
   ```

3. Teste o ambiente Python:
   ```bash
   /opt/intranet/venv/bin/python3 -c "import sys; print(sys.path)" > python_path.txt
   ```

---

**Última atualização:** 2026-02-01  
**Status:** ✅ Problema resolvido com script de inicialização
