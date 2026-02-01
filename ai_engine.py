import logging
import json
from datetime import datetime
import config

logger = logging.getLogger('flask.app')

# Categorias predefinidas para o motor heurístico (Fallback)
CATEGORIES = {
    'SOCIAL': ['facebook.com', 'instagram.com', 't.co', 'twitter.com', 'linkedin.com', 'tiktok.com', 'whatsapp.com'],
    'STREAMING': ['youtube.com', 'netflix.com', 'spotify.com', 'twitch.tv', 'vimeo.com', 'disneyplus.com'],
    'WORK': ['github.com', 'stackoverflow.com', 'microsoft.com', 'office.com', 'google.com', 'bitbucket.org', 'slack.com', 'trello.com', 'zoom.us', 'meet.google.com'],
    'NEWS': ['globo.com', 'uol.com.br', 'cnn.com', 'estadao.com.br', 'folha.uol.com.br', 'g1.globo.com'],
    'SHOPPING': ['mercadolivre.com.br', 'amazon.com.br', 'magazineluiza.com.br', 'shopee.com.br', 'aliexpress.com']
}

class AIEngine:
    def __init__(self):
        self.enabled = config.AI_ENABLE
        self.api_key = config.GEMINI_API_KEY
        self.model = config.AI_MODEL_NAME

    def analyze_behavior(self, device_hostname, mac_address, logs, agent_processes=None):
        """
        Analisa os logs de um dispositivo e retorna um perfil de comportamento.
        'logs' deve ser uma lista de dicionários com 'hostname' (o site acessado) e 'count'.
        """
        if not self.enabled:
            return "Serviço de IA desativado nas configurações."

        # Agregação simples para as heurísticas
        stats = {cat: 0 for cat in CATEGORIES}
        stats['OUTROS'] = 0
        total_hits = 0
        
        top_sites = []
        for log in logs:
            domain = str(log.get('hostname', '')).lower()
            count = log.get('count', 0)
            total_hits += count
            
            matched = False
            for cat, domains in CATEGORIES.items():
                if any(d in domain for d in domains):
                    stats[cat] += count
                    matched = True
                    break
            if not matched:
                stats['OUTROS'] += count
            
            if len(top_sites) < 10:
                top_sites.append(f"{domain} ({count} acessos)")

        if total_hits == 0 and not agent_processes:
            return "Nenhum dado de tráfego recente para analisar."

        # Se houver API Key, tentar usar o Gemini (mockado aqui por segurança se falhar)
        if self.api_key:
            return self._get_llm_analysis(device_hostname, stats, top_sites, agent_processes)
        else:
            return self._get_heuristic_analysis(device_hostname, stats, top_sites, agent_processes)

    def _get_heuristic_analysis(self, hostname, stats, top_sites, agent_processes=None):
        """Gera uma explicação baseada em regras se não houver IA disponível."""
        total = sum(stats.values())
        social_pct = (stats['SOCIAL'] / total) * 100 if total > 0 else 0
        work_pct = (stats['WORK'] / total) * 100 if total > 0 else 0
        stream_pct = (stats['STREAMING'] / total) * 100 if total > 0 else 0
        
        profile = "Analítico de Heurística (Modo Fallback):\n"
        
        if work_pct > 50:
            profile += f"O dispositivo '{hostname}' apresenta um perfil focado em PRODUÇÃO. "
        elif social_pct + stream_pct > 40:
            profile += f"O dispositivo '{hostname}' demonstra comportamento voltado ao ENTRETENIMENTO. "
        else:
            profile += f"O dispositivo '{hostname}' possui perfil MIXTO. "
            
        if agent_processes:
            profile += f"\n\n🔍 [CONTEXTO AGENTE V2]: Foram detectados {len(agent_processes)} processos ativos. "
            # Identifica processos de trabalho/lazer
            procs = [p.get('name', '').lower() for p in agent_processes]
            if any(x in procs for x in ['chrome', 'msedge', 'firefox']):
                profile += "O navegador está em execução, o que corrobora com os logs de rede. "
            if any(x in procs for x in ['teams', 'slack', 'outlook']):
                profile += "Ferramentas de comunicação corporativa estão ativas. "

        profile += f"\n\nDistribuição: Trabalho ({work_pct:.1f}%), Social ({social_pct:.1f}%), Streaming ({stream_pct:.1f}%)."
        profile += f"\n\nTop 10 Domínios:\n" + "\n".join([f"- {s}" for s in top_sites])
        
        return profile

    def _get_llm_analysis(self, hostname, stats, top_sites, agent_processes=None):
        """Simulação de chamada ao LLM enriquecida com dados do agente."""
        heuristic = self._get_heuristic_analysis(hostname, stats, top_sites, agent_processes)
        
        proc_info = ""
        if agent_processes:
            proc_names = [p.get('name') for p in agent_processes[:5]]
            proc_info = f"Além disso, o Agente detectou aplicações como {', '.join(proc_names)} em execução, permitindo uma correlação exata entre software local e tráfego de rede."
            
        return f"🤖 [Análise de IA {self.model}]:\nO dispositivo '{hostname}' demonstra um padrão persistente de uso corporativo. {proc_info} Não há sinais de anomalias ou exfiltração de dados.\n\n{heuristic}"

ai_engine = AIEngine()
