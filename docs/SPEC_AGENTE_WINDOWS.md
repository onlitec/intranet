# Especificação Técnica: Agente Windows ES-SERVIDOR (V2)

Este documento define os requisitos e a arquitetura para o desenvolvimento do agente que será instalado nas estações de trabalho Windows, permitindo a visibilidade granular do tráfego de rede e interação direta pela plataforma.

## 1. Arquitetura de Comunicação

O agente deve operar em modo híbrido:
1.  **Push (Ativo):** O agente envia dados de telemetria e logs de conexão para a API central a cada X segundos.
2.  **Pull (Reconexão):** O agente deve expor um pequeno servidor HTTP local (Porta padrão: `9090`) protegido por token, permitindo que a plataforma se conecte diretamente a ele para:
    *   Solicitar lista de processos em tempo real.
    *   Forçar atualização de políticas.
    *   Executar comandos instantâneos sem esperar o intervalo de polling.

## 2. Requisitos Técnicos

*   **Linguagem Sugerida:** Python (compilado com PyInstaller) ou C# (.NET Core).
*   **Modo de Execução:** Serviço do Windows (LocalSystem) para garantir persistência.
*   **Segurança:**
    *   Uso do header `X-Agent-Token` em todas as requisições.
    *   Criptografia TLS na comunicação com a API.
    *   Assinatura digital do executável para evitar bloqueios de antivírus.

## 3. Módulos de Coleta de Dados

### 3.1. Monitoramento de Conexões (Internet)
O agente deve listar as conexões TCP/UDP ativas e correlacioná-las com o processo.
*   **Dados Necessários:** Protocolo, IP Local, Porta Local, IP Remoto, Porta Remota, Process ID (PID), Nome do Processo (ex: `chrome.exe`).
*   **Frequência:** Captura a cada 10-30 segundos de conexões em estado `ESTABLISHED`.

### 3.2. Contexto de Usuário
*   Identificar o usuário Windows logado no momento.
*   Tempo de atividade (Uptime) do sistema e do usuário.

### 3.3. Inventário de Software
*   Lista de aplicações instaladas e versões.

## 4. Endpoints da API Local (Server-Side no Agente)

Para que a plataforma se conecte ao agente, ele deve responder em `http://IP_DA_ESTACAO:9090/`:

| Rota | Método | Descrição |
| :--- | :--- | :--- |
| `/status` | GET | Retorna saúde do agente e versão. |
| `/proc/list` | GET | Retorna todos os processos rodando com consumo de CPU/RAM. |
| `/net/connections` | GET | Retorna conexões ativas no instante da consulta. |
| `/action/kill` | POST | Encerra um processo específico (requer confirmação via Token). |

## 5. Fluxo de Instalação e Provisionamento

1.  O instalador (.msi ou .exe) solicita o endereço da plataforma e o Token de Segurança.
2.  O agente gera um ID único (UUID) baseado no hardware e MAC.
3.  Primeiro reporte: O agente se cadastra no servidor e o servidor abre uma regra de firewall (se necessário) para permitir o tráfego na porta 9090.
