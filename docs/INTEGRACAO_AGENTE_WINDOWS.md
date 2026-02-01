# Guia de Integração: Agente Windows ES-SERVIDOR

Este documento detalha as especificações técnicas para que o Agente Windows se comunique com a plataforma central.

## 1. Configuração de Comunicação

### Endereço Base da API
As requisições devem ser enviadas para:
`http://[IP_DA_PLATAFORMA]/api/v1/agent`

### Autenticação
Todas as requisições enviadas pelo agente **DEVEM** incluir o seguinte header HTTP:
`X-Agent-Token: ONLITEC-HUD-2026`

> [!IMPORTANT]
> O token acima é o padrão de fábrica. Em ambientes de produção, verifique o arquivo `.env` da plataforma para confirmar se o `AGENT_TOKEN` foi alterado.

---

## 2. Endpoints de Envio (Agente -> Plataforma)

### 2.1. Reporte de Telemetria (Frequência sugerida: 5 min)
Informa o status básico do dispositivo e garante que ele apareça como "Online".

- **Endpoint:** `/report`
- **Método:** `POST`
- **Payload (JSON):**
```json
{
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "hostname": "NOME-PC-PROD",
  "ip_address": "192.168.1.50",
  "logged_user": "pedro.silva",
  "os_info": "Windows 11 Pro 23H2",
  "agent_version": "0.1.0"
}
```

### 2.2. Reporte de Logs de Acesso (Frequência sugerida: 30 seg)
Envia os dados de navegação capturados localmente, correlacionando o site com o processo.

- **Endpoint:** `/access-logs`
- **Método:** `POST`
- **Payload (JSON):**
```json
{
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "logs": [
    {
      "local_ip": "192.168.1.50",
      "remote_host": "www.youtube.com",
      "process_name": "chrome.exe",
      "user_context": "pedro.silva"
    },
    {
      "local_ip": "192.168.1.50",
      "remote_host": "github.com",
      "process_name": "brave.exe",
      "user_context": "pedro.silva"
    }
  ]
}
```

---

## 3. Controle e Comandos (Push vs Pull)

A plataforma utiliza um modelo híbrido para enviar comandos aos agentes.

### 3.1. Polling de Comandos (Agente -> Plataforma)
O agente deve consultar comandos pendentes periodicamente.

- **Endpoint:** `/commands?mac_address=AA:BB:CC:DD:EE:FF`
- **Método:** `GET`
- **Resposta:**
```json
{
  "status": "ok",
  "commands": [
    {
      "id": 12,
      "text": "kill chrome.exe"
    }
  ]
}
```

### 3.2. Reporte de Resultado (Agente -> Plataforma)
Após executar um comando, o agente deve reportar o sucesso ou erro.

- **Endpoint:** `/commands/{id}/result`
- **Método:** `POST`
- **Payload (JSON):**
```json
{
  "status": "success",
  "output": "Process killed successfully"
}
```

### 3.3. API Local do Agente (Plataforma -> Agente)
Para ações instantâneas, o agente **deve rodar um servidor HTTP local na porta 9090**.

- `GET /status`: Saúde do agente.
- `GET /proc/list`: Lista de processos e consumo.
- `GET /net/connections`: Conexões TCP/UDP ativas.
- `POST /action/kill`: Encerrar processo (requer o mesmo `X-Agent-Token`).

---

## 4. Prontidão da Plataforma

A plataforma já está configurada com:
- [x] Interface de visualização em **Monitoramento > Dispositivos**.
- [x] Exibição de processos e usuários em **Monitoramento > Logs de Acesso**.
- [x] Relatórios de produtividade baseados no usuário logado via agente.
