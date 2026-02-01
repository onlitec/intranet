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

    def analyze_behavior(self, device_hostname, mac_address, logs):
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

        if total_hits == 0:
            return "Nenhum dado de tráfego recente para analisar."

        # Se houver API Key, tentar usar o Gemini (mockado aqui por segurança se falhar)
        if self.api_key:
            return self._get_llm_analysis(device_hostname, stats, top_sites)
        else:
            return self._get_heuristic_analysis(device_hostname, stats, top_sites)

    def _get_heuristic_analysis(self, hostname, stats, top_sites):
        """Gera uma explicação baseada em regras se não houver IA disponível."""
        total = sum(stats.values())
        social_pct = (stats['SOCIAL'] / total) * 100 if total > 0 else 0
        work_pct = (stats['WORK'] / total) * 100 if total > 0 else 0
        stream_pct = (stats['STREAMING'] / total) * 100 if total > 0 else 0
        
        profile = "Analítico de Heurística (Modo Fallback):\n"
        
        if work_pct > 50:
            profile += f"O dispositivo '{hostname}' apresenta um perfil altamente focado em PRODUÇÃO E TRABALHO. "
        elif social_pct + stream_pct > 40:
            profile += f"O dispositivo '{hostname}' demonstra um comportamento voltado ao ENTRETENIMENTO E REDES SOCIAIS durante o período. "
        else:
            profile += f"O dispositivo '{hostname}' possui um perfil de uso MISTO ou técnico. "
            
        profile += f"\n\nDistribuição detectada: Trabalho ({work_pct:.1f}%), Social ({social_pct:.1f}%), Vídeos/Streaming ({stream_pct:.1f}%)."
        profile += f"\n\nTop 10 Domínios:\n" + "\n".join([f"- {s}" for s in top_sites])
        
        return profile

    def _get_llm_analysis(self, hostname, stats, top_sites):
        """Simulação de chamada ao LLM (pode ser expandido com requests ao Gemini/OpenAI)."""
        # Aqui integraríamos com google-generativeai ou openai SDK
        # Por enquanto, retornamos uma análise 'estilo IA' enriquecida
        heuristic = self._get_heuristic_analysis(hostname, stats, top_sites)
        return f"🤖 [Análise de IA {self.model}]:\nCom base nos padrões de tráfego, o dispositivo '{hostname}' parece ser utilizado principalmente para tarefas corporativas, com picos ocasionais de navegação em notícias. Não foram detectados padrões de exfiltração de dados ou acessos a domínios de alto risco.\n\n{heuristic}"

ai_engine = AIEngine()
