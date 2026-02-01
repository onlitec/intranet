import os
import json
import logging
import markdown
from datetime import datetime, timedelta
import config
from models import DomainCategorization, db

logger = logging.getLogger(__name__)

class AIService:
    """Serviço de Inteligência Artificial para análise de monitoramento"""

    COMMON_DOMAINS = {
        'google.com': {'name': 'Google Search', 'cat': 'Busca', 'desc': 'Serviços de busca e navegação do Google.', 'icon': '🔍', 'prod': True},
        'google.com.br': {'name': 'Google Search', 'cat': 'Busca', 'desc': 'Serviços de busca do Google (Brasil).', 'icon': '🔍', 'prod': True},
        'gstatic.com': {'name': 'Google Static Content', 'cat': 'Busca', 'desc': 'Recursos estáticos do Google (scripts/estilos).', 'icon': '⚙️', 'prod': True},
        'googleapis.com': {'name': 'Google APIs', 'cat': 'Busca', 'desc': 'Serviços de integração e APIs do Google.', 'icon': '🔗', 'prod': True},
        'microsoft.com': {'name': 'Microsoft Services', 'cat': 'Sistema', 'desc': 'Atualizações e serviços do Windows/Microsoft.', 'icon': '🪟', 'prod': True},
        'windowsupdate.com': {'name': 'Windows Update', 'cat': 'Sistema', 'desc': 'Servidores de atualização do Windows.', 'icon': '🔄', 'prod': True},
        'office.com': {'name': 'Microsoft Office 365', 'cat': 'Produtividade', 'desc': 'Suíte de ferramentas de escritório da Microsoft.', 'icon': '📄', 'prod': True},
        'office365.com': {'name': 'Microsoft Office 365', 'cat': 'Produtividade', 'desc': 'Serviços na nuvem do Office 365.', 'icon': '📄', 'prod': True},
        'outlook.com': {'name': 'Outlook Email', 'cat': 'Comunicação', 'desc': 'Serviço de email e calendário da Microsoft.', 'icon': '📧', 'prod': True},
        'teams.microsoft.com': {'name': 'Microsoft Teams', 'cat': 'Comunicação', 'desc': 'Plataforma de colaboração e reuniões.', 'icon': '👥', 'prod': True},
        'whatsapp.com': {'name': 'WhatsApp Web', 'cat': 'Comunicação', 'desc': 'Plataforma de mensagens WhatsApp Web.', 'icon': '💬', 'prod': True},
        'whatsapp.net': {'name': 'WhatsApp Media', 'cat': 'Comunicação', 'desc': 'Servidores de mídia e conexão do WhatsApp.', 'icon': '📷', 'prod': True},
        'slack.com': {'name': 'Slack', 'cat': 'Comunicação', 'desc': 'Plataforma de comunicação corporativa.', 'icon': '💬', 'prod': True},
        'github.com': {'name': 'GitHub', 'cat': 'Desenvolvimento', 'desc': 'Hospedagem de código e controle de versão.', 'icon': '🐙', 'prod': True},
        'stackoverflow.com': {'name': 'Stack Overflow', 'cat': 'Desenvolvimento', 'desc': 'Comunidade de perguntas e respostas para programadores.', 'icon': '💻', 'prod': True},
        'linkedin.com': {'name': 'LinkedIn', 'cat': 'Profissional', 'desc': 'Rede social profissional e networking.', 'icon': '👔', 'prod': True},
        'facebook.com': {'name': 'Facebook', 'cat': 'Rede Social', 'desc': 'Rede social Facebook.', 'icon': '👥', 'prod': False},
        'instagram.com': {'name': 'Instagram', 'cat': 'Rede Social', 'desc': 'Rede social de fotos e vídeos.', 'icon': '📸', 'prod': False},
        'fbcdn.net': {'name': 'Facebook Content', 'cat': 'Rede Social', 'desc': 'Servidores de mídia do Facebook/Instagram.', 'icon': '🖼️', 'prod': False},
        'netflix.com': {'name': 'Netflix', 'cat': 'Streaming', 'desc': 'Serviço de streaming de filmes e séries.', 'icon': '📺', 'prod': False},
        'youtube.com': {'name': 'YouTube', 'cat': 'Streaming/Vídeo', 'desc': 'Plataforma de compartilhamento de vídeos.', 'icon': '🎥', 'prod': False},
        'googlevideo.com': {'name': 'YouTube Video Store', 'cat': 'Streaming/Vídeo', 'desc': 'Servidores de conteúdo de vídeo do YouTube.', 'icon': '🎞️', 'prod': False},
        'spotify.com': {'name': 'Spotify', 'cat': 'Música', 'desc': 'Serviço de streaming de música.', 'icon': '🎵', 'prod': False},
        'globo.com': {'name': 'Portal Globo', 'cat': 'Notícias', 'desc': 'Portal de notícias e entretenimento brasileiro.', 'icon': '📰', 'prod': False},
        'uol.com.br': {'name': 'Portal UOL', 'cat': 'Notícias', 'desc': 'Portal de notícias e serviços brasileiro.', 'icon': '📰', 'prod': False},
        'estadao.com.br': {'name': 'Estadão', 'cat': 'Notícias', 'desc': 'Portal do jornal O Estado de S. Paulo.', 'icon': '📰', 'prod': False},
        'folha.uol.com.br': {'name': 'Folha de S. Paulo', 'cat': 'Notícias', 'desc': 'Portal da Folha de S. Paulo.', 'icon': '📰', 'prod': False},
        'mercadolivre.com.br': {'name': 'Mercado Livre', 'cat': 'Compras', 'desc': 'Plataforma de e-commerce e pagamentos.', 'icon': '🛒', 'prod': False},
        'amazon.com.br': {'name': 'Amazon Brasil', 'cat': 'Compras', 'desc': 'Loja virtual da Amazon.', 'icon': '🛒', 'prod': False},
        'akamaized.net': {'name': 'Akamai CDN', 'cat': 'Infraestrutura', 'desc': 'Rede de entrega de conteúdo global (CDN).', 'icon': '🌐', 'prod': True},
    }

    @staticmethod
    def get_domain_insight(domain):
        """Busca insight sobre um domínio, usando cache ou 'IA'"""
        # 1. Tenta cache no banco
        from models import DomainCategorization
        cached = DomainCategorization.query.filter_by(domain=domain).first()
        if cached:
            return cached

        # 2. Tenta base de conhecimento local (simulando IA de resposta rápida)
        for d, info in AIService.COMMON_DOMAINS.items():
            if d in domain:
                new_cat = DomainCategorization(
                    domain=domain,
                    friendly_name=info['name'],
                    category=info['cat'],
                    description=info['desc'],
                    icon=info.get('icon', '✨'),
                    is_productive=info.get('prod', True)
                )
                db.session.add(new_cat)
                db.session.commit()
                return new_cat

        # 3. Fallback genérico para domínios desconhecidos
        return None

    @staticmethod
    def generate_user_productivity_insight(category_stats):
        """Gera uma análise textual amigável baseada na distribuição de categorias"""
        if not category_stats:
            return "Não há dados suficientes para analisar o perfil deste usuário no momento."

        total_hits = sum(cat['hits'] for cat in category_stats.values())
        if total_hits == 0:
            return "Pouca atividade detectada para gerar um perfil conclusivo."

        # Ordenar categorias por relevância
        sorted_cats = sorted(category_stats.items(), key=lambda x: x[1]['hits'], reverse=True)
        top_cat_name, top_cat_data = sorted_cats[0]
        top_percent = (top_cat_data['hits'] / total_hits) * 100

        # Detecção de perfil
        if top_cat_name in ['Produtividade', 'Desenvolvimento', 'Busca', 'Sistema']:
            profile = "Foco Profissional"
            tone = "Este usuário mantém um alto nível de concentração em tarefas técnicas e operacionais."
        elif top_cat_name in ['Rede Social', 'Streaming', 'Streaming/Vídeo', 'Música', 'Compras']:
            profile = "Perfil de Lazer/Descompressão"
            tone = "Há uma predominância de atividades de entretenimento ou redes sociais neste período."
        elif top_cat_name == 'Comunicação':
            profile = "Perfil de Colaboração"
            tone = "Foco intenso em comunicação e alinhamento com a equipe."
        else:
            profile = "Perfil Misto"
            tone = "Uso equilibrado entre diferentes tipos de recursos da internet."

        insight = f"**Perfil: {profile}**\n\n"
        insight += f"{tone}\n\n"
        # Exibir "acesso normal" ao invés de "Outros"
        display_category = "acesso normal" if top_cat_name == "Outros" else top_cat_name
        insight += f"O uso principal é focado em **{display_category}** ({top_percent:.1f}% do tráfego)."

        # Adicionar comentário sobre categoria secundária se relevante
        if len(sorted_cats) > 1:
            sec_cat_name, sec_cat_data = sorted_cats[1]
            sec_percent = (sec_cat_data['hits'] / total_hits) * 100
            if sec_percent > 20:
                insight += f" Também apresenta atividade significativa em **{sec_cat_name}**."

        # Converte Markdown para HTML para renderização no template
        return markdown.markdown(insight)

    @staticmethod
    def generate_device_summary(identifier, top_sites):
        """Gera um resumo de análise de comportamento para um dispositivo específico"""
        if not top_sites or len(top_sites) == 0:
            return "Não há dados suficientes para gerar uma análise deste dispositivo no momento."
        
        # Analisar os top sites para identificar padrões
        total_hits = sum(site[1] for site in top_sites)
        total_duration = sum(site[2] or 0 for site in top_sites)
        
        # Categorizar sites
        productive_count = 0
        leisure_count = 0
        categories_seen = set()
        
        for site_domain, hits, duration, last_access in top_sites:
            # Tentar obter categorização
            for domain_key, info in AIService.COMMON_DOMAINS.items():
                if domain_key in site_domain:
                    if info.get('prod', True):
                        productive_count += hits
                    else:
                        leisure_count += hits
                    categories_seen.add(info.get('cat', 'Outros'))
                    break
        
        # Gerar resumo baseado nos padrões
        summary = f"**Análise de Comportamento: {identifier}**\n\n"
        
        # Estatísticas gerais
        summary += f"📊 **Estatísticas Gerais**\n"
        summary += f"- Total de acessos únicos: **{len(top_sites)}** sites diferentes\n"
        summary += f"- Volume total de requisições: **{total_hits}** acessos\n"
        summary += f"- Tempo médio estimado: **{int(total_duration / 60)}** minutos\n\n"
        
        # Análise de perfil
        if productive_count > leisure_count:
            productivity_ratio = (productive_count / total_hits) * 100 if total_hits > 0 else 0
            summary += f"✅ **Perfil Produtivo** ({productivity_ratio:.0f}%)\n"
            summary += f"Este dispositivo demonstra um padrão de uso predominantemente voltado para atividades produtivas e profissionais.\n\n"
        elif leisure_count > productive_count:
            leisure_ratio = (leisure_count / total_hits) * 100 if total_hits > 0 else 0
            summary += f"🎮 **Perfil de Lazer** ({leisure_ratio:.0f}%)\n"
            summary += f"Há uma predominância de acessos a conteúdos de entretenimento e redes sociais.\n\n"
        else:
            summary += f"⚖️ **Perfil Equilibrado**\n"
            summary += f"O dispositivo apresenta um uso balanceado entre atividades produtivas e de lazer.\n\n"
        
        # Categorias detectadas
        if categories_seen:
            summary += f"🏷️ **Categorias Detectadas**: {', '.join(sorted(categories_seen))}\n\n"
        
        # Top sites
        summary += f"🌐 **Sites Mais Acessados**\n"
        for i, (site_domain, hits, duration, last_access) in enumerate(top_sites[:5], 1):
            # Tentar obter nome amigável
            friendly_name = site_domain
            for domain_key, info in AIService.COMMON_DOMAINS.items():
                if domain_key in site_domain:
                    friendly_name = info.get('name', site_domain)
                    break
            summary += f"{i}. **{friendly_name}** - {hits} acessos\n"
        
        summary += f"\n> [!TIP]\n> Use os filtros de data e site para análises mais detalhadas."
        
        return summary

