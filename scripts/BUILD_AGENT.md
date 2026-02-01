# Guia de Compilação: Agente Windows ES-SERVIDOR

Este guia descreve como transformar o script `agent.py` em um executável (.exe) standalone para distribuição simplificada em estações de trabalho Windows.

## Pré-requisitos
- Windows 10/11
- Python 3.10+ instalado
- Token da empresa configurado no código ou via variável de ambiente.

## Passo 1: Preparar o Ambiente
Abra o terminal (PowerShell ou CMD) e instale o `PyInstaller`:
```bash
pip install pyinstaller requests
```

## Passo 2: Compilar o Executável
Execute o comando abaixo na pasta `scripts/`:
```bash
pyinstaller --onefile --noconsole --icon=icon.ico agent.py
```
- `--onefile`: Consolida tudo em um único .exe.
- `--noconsole`: Impede que uma janela de terminal apareça para o usuário final.
- `--icon`: (Opcional) Adiciona o ícone da empresa ao arquivo.

## Passo 3: Distribuição (GPO)
Para ambientes corporativos, o executável gerado na pasta `dist/` pode ser distribuído via **Group Policy Object (GPO)** ou ferramentas como SCCM/PDQ Deploy.

### Recomendação de Instalação:
1. Criar uma pasta em `C:\ProgramData\ES-Agent\`.
2. Copiar o `agent.exe` para esta pasta.
3. Criar uma tarefa agendada no Windows (Task Scheduler) para iniciar com o sistema ("At Log On").

## Notas de Segurança
- Certifique-se de que o `AGENT_TOKEN` no código compilado corresponde ao configurado no servidor.
- O executável utiliza a porta HTTPS (443) ou HTTP (5000 por padrão) para se comunicar com o servidor.
