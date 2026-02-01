import os
import json
import logging
from datetime import datetime, timedelta
import config
from models import DomainCategorization, db

logger = logging.getLogger(__name__)

class AIService:
    """Serviço de Inteligência Artificial para análise de monitoramento"""

    COMMON_DOMAINS = {
        'google.com': {'name': 'Google Search', 'cat': 'Busca', 'desc': 'Serviços de busca e navegação do Google.', 'icon': '🔍'},
        'google.com.br': {'name': 'Google Search', 'cat': 'Busca', 'desc': 'Serviços de busca do Google (Brasil).', 'icon': '🔍'},
        'gstatic.com': {'name': 'Google Static Content', 'cat': 'Busca', 'desc': 'Recursos estáticos do Google (scripts/estilos).', 'icon': '⚙️'},
        'googleapis.com': {'name': 'Google APIs', 'cat': 'Busca', 'desc': 'Serviços de integração e APIs do Google.', 'icon': '🔗'},
        'microsoft.com': {'name': 'Microsoft Services', 'cat': 'Sistema', 'desc': 'Atualizações e serviços do Windows/Microsoft.', 'icon': '🪟'},
        'windowsupdate.com': {'name': 'Windows Update', 'cat': 'Sistema', 'desc': 'Servidores de atualização do Windows.', 'icon': '🔄'},
        'whatsapp.com': {'name': 'WhatsApp Web', 'cat': 'Comunicação', 'desc': 'Plataforma de mensagens WhatsApp Web.', 'icon': '💬'},
        'whatsapp.net': {'name': 'WhatsApp Media', 'cat': 'Comunicação', 'desc': 'Servidores de mídia e conexão do WhatsApp.', 'icon': '📷'},
        'facebook.com': {'name': 'Facebook', 'cat': 'Rede Social', 'desc': 'Rede social Facebook.', 'icon': '👥'},
        'fbcdn.net': {'name': 'Facebook Content', 'cat': 'Rede Social', 'desc': 'Servidores de mídia do Facebook/Instagram.', 'icon': '🖼️'},
        'netflix.com': {'name': 'Netflix', 'cat': 'Streaming', 'desc': 'Serviço de streaming de filmes e séries.', 'icon': '📺'},
        'youtube.com': {'name': 'YouTube', 'cat': 'Streaming/Vídeo', 'desc': 'Plataforma de compartilhamento de vídeos.', 'icon': '🎥'},
        'googlevideo.com': {'name': 'YouTube Video Store', 'cat': 'Streaming/Vídeo', 'desc': 'Servidores de conteúdo de vídeo do YouTube.', 'icon': '🎞️'},
        'github.com': {'name': 'GitHub', 'cat': 'Desenvolvimento', 'desc': 'Hospedagem de código e controle de versão.', 'icon': '🐙'},
        'akamaized.net': {'name': 'Akamai CDN', 'cat': 'Infraestrutura', 'desc': 'Rede de entrega de conteúdo global (CDN).', 'icon': '🌐'},
    }

    @staticmethod
    def get_domain_insight(domain):
        """Busca insight sobre um domínio, usando cache ou 'IA'"""
        # 1. Tenta cache no banco
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
                    icon='✨'
                )
                db.session.add(new_cat)
                db.session.commit()
                return new_cat

        # 3. Aqui integraria com OpenAI/Anthropic/Ollama
        # Por enquanto, retorna um fallback amigável
        return None

    @staticmethod
    def generate_device_summary(device_identifier, top_sites):
        """Gera um resumo textual inteligente sobre o comportamento do dispositivo"""
        rows = []
        categories = {}

        for site in top_sites:
            domain = site[0]
            count = site[1]
            duration = site[2] or 0
            last_access = site[3]
            
            info = AIService.get_domain_insight(domain)
            
            # Formatação do nome amigável ou domínio bruto com ícone
            if info:
                name = f"{info.icon or '🌐'} **{info.friendly_name}**"
            else:
                name = f"🌐 `{domain}`"
            
            # Formatação simplificada da duração acumulada
            if duration > 3600:
                dur_str = f"{int(duration // 3600)}h {int((duration % 3600) // 60)}m"
            elif duration > 60:
                dur_str = f"{int(duration // 60)}m {int(duration % 60)}s"
            elif duration > 0:
                dur_str = f"{int(duration)}s"
            else:
                # Se a duração for 0 mas houver acessos, indica que o método de captura
                # (ex: DNS) não fornece tempo de sessão ou os acessos são instantâneos.
                dur_str = "Frequente" if count > 50 else "Instantâneo"
                
            # Data e hora do último acesso com ajuste de fuso horário
            if last_access:
                local_access = last_access + timedelta(hours=config.TIMEZONE_OFFSET)
                ts_str = local_access.strftime('%d/%m %H:%M')
            else:
                ts_str = "---"
            
            rows.append(f"| {name} | {dur_str} | {count} | {ts_str} |")
            
            if info:
                categories[info.category] = categories.get(info.category, 0) + count

        if not rows:
            return "Não há dados suficientes para uma análise profunda no momento."

        summary = "### 🛸 Comportamento de Rede\n\n"
        summary += "Analisei os logs recentes e identifiquei os seguintes destinos principais:\n\n"
        
        # Estrutura de Tabela Markdown
        summary += "| Destino | Tempo de Acesso | Qtd. Acessos | Último Acesso |\n"
        summary += "| :--- | :--- | :--- | :--- |\n"
        summary += "\n".join(rows[:10]) # Exibe até 10 linhas
        
        if categories:
            top_cat = max(categories, key=categories.get)
            summary += f"\n\n### 🚀 Resumo de Atividade\nEste dispositivo está utilizando a rede principalmente para **{top_cat}**."
        
        summary += "\n\n> [!TIP]\n> IAs locais como esta protegem sua privacidade pois nenhum dado sai da rede interna para análise."
        
        return summary
