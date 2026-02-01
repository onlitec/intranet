# Plano de Implementação: Coleta de Dados via Agente e Relatórios

Este plano detalha as etapas necessárias para adaptar a plataforma ES-SERVIDOR para processar dados vindos do novo Agente Windows.

## Fase 1: Atualização do Modelo de Dados e API

1.  **Alteração em `InternetAccessLog`:**
    *   Adicionar campo `source_type` (Enum: `syslog`, `agent`).
    *   Adicionar campo `process_name` (String) para identificar o app.
    *   Adicionar campo `user_context` (String) para o usuário local.

2.  **Novo Endpoint em `agent_api.py`:**
    *   `/api/v1/agent/access-logs` (POST): Recebe um JSON com lista de conexões capturadas pelo agente.
    *   Lógica: Desduplicar registros e salvar na `InternetAccessLog`.

## Fase 2: Motor de Processamento (Engine)

1.  **Criação do `AgentProcessor`:**
    *   Serviço secundário que analisa os logs recebidos pelos agentes.
    *   Integração com o `DomainCategorization` para classificar o domínio acessado por aplicativos específicos.

2.  **Comunicação Servidor -> Agente:**
    *   Implementar em `admin.py` a lógica de "Ping para Agente". Antes de abrir o dashboard de um dispositivo, a plataforma tenta conectar no IP do agente (porta 9090) para pegar dados em tempo real.

## Fase 3: Visualização e Relatórios

1.  **Dashboard de Monitoramento:**
    *   Filtro para ver "Acessos por Aplicativo".
    *   Gráfico de pizza: "Top Apps que mais acessam a internet".
    *   Na linha do log, exibir o ícone ou nome do processo (ex: "Chrome", "Windows Update").

2.  **Relatórios de Produtividade (IA):**
    *   Atualizar o `ai_service.py` para considerar o nome do processo.
    *   *Insight de IA:* "O usuário passou 2h no Chrome acessando YouTube, mas o processo Spotify também consumiu 500MB de banda em segundo plano."

3.  **Alertas:**
    *   Notificar se um processo desconhecido ou malicioso (ex: miners, botnets) iniciar conexões externas.

## Cronograma Estimado

| Semana | Foco | Entregáveis |
| :--- | :--- | :--- |
| 1 | Backend & API | Endpoints de recepção de dados e migração de banco. |
| 2 | Integração de UI | Dashboards atualizados com nomes de processos. |
| 3 | Relatórios & IA | Inclusão de contexto de aplicativo nos relatórios de IA. |
