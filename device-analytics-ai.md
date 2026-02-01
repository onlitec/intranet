# Plano: Inteligência de Dispositivo (Fase 7)

Este plano detalha a implementação da visualização granular por dispositivo, integração com IA para análise de comportamento e o fluxo de cadastro rápido a partir dos logs de tráfego.

## User Review Required

> [!IMPORTANT]
> **API de IA**: Para a análise de comportamento, utilizaremos o modelo Gemini (ou OpenAI). Se não houver uma chave de API configurada, utilizaremos um sistema de "Mocks de IA" baseados em regras heurísticas extensíveis até que a chave seja fornecida.
> 
> **Performance**: A agregação de logs de grandes períodos (ex: 30 dias) pode ser lenta. Implementaremos cache para consultas de histórico longo.

## Proposta de Mudanças

### [Backend - Núcleo de Inteligência]
#### [NEW] [ai_engine.py](file:///opt/intranet/ai_engine.py)
- Módulo para processar logs agregados e gerar perfis de comportamento via LLM.
- Heurísticas para classificação de domínios (Trabalho, Entretenimento, Suspeito).

#### [MODIFY] [admin.py](file:///opt/intranet/admin.py)
- Rota `/admin/monitoring/device/<mac>`: Dashboard individual do dispositivo.
- Lógica de agregação de `InternetAccessLog` filtrada por MAC/IP.
- Endpoint para o "Cadastro Rápido".

### [Frontend - Dashboards Granulares]
#### [NEW] [admin_device_analytics.html](file:///opt/intranet/templates/admin_device_analytics.html)
- Visualização de "Timeline de Acessos" do dispositivo.
- Seção "Análise da IA": Resumo textual do comportamento.
- Gráficos de categorias de acesso específicas do dispositivo.

#### [MODIFY] [admin_monitoring.html](file:///opt/intranet/templates/admin_monitoring.html) (Logs Gerais)
- Adição de botão "📝 Cadastrar" ao lado de MACs desconhecidos.
- Link direto no MAC para a nova visão de analytics.

## Plano de Tarefas

| ID | Tarefa | Agente | Prioridade | Descrição |
|:---|:---|:---|:---|:---|
| 1 | **Log Aggregator** | `backend-specialist` | P0 | Criar serviço de agregação de logs por MAC com suporte a filtros de data. |
| 2 | **AI Interface** | `backend-specialist` | P1 | Implementar o módulo de integração com IA (Gemini/OpenAI) ou Fallback Heurístico. |
| 3 | **Analytics UI** | `frontend-specialist` | P1 | Desenvolver o template de dashboard individual (Visão por Dispositivo). |
| 4 | **Quick Register** | `frontend-specialist` | P2 | Implementar o modal/fluxo de cadastro rápido na tabela de logs gerais. |
| 5 | **History Selector** | `frontend-specialist` | P2 | Adicionar seletor de período (24h, 7d, 30d) no analytics do dispositivo. |

## Verificação (Phase X)

- [ ] Validar agregação de dados para dispositivos com > 10.000 logs.
- [ ] Confirmar se a IA explica corretamente acessos a domínios de entretenimento vs produtividade.
- [ ] Testar fluxo de cadastro "Log -> Inventário" sem recarregar a página (AJAX).
- [ ] Verificar responsividade do novo dashboard.
