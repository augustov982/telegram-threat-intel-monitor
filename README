# 📡 Telegram Threat Intelligence Monitor 

> **Ferramenta de monitoramento em tempo real (Real-Time Monitoring) focada em Data Loss Prevention (DLP) e detecção de ameaças no ecossistema Telegram.**

Esta solução utiliza a API do Telegram (via Telethon) para monitorar grupos e canais em busca de vazamentos de credenciais corporativas, compartilhamento de bases de dados sensíveis e atividades suspeitas, gerando alertas imediatos para equipes de SOC/Blue Team.

## 🚀 Funcionalidades

- 🕵️ **DLP (Data Loss Prevention):** Monitora fluxo de mensagens em busca de padrões sensíveis (ex: "email:pass", "corp dump", "vazamento").
- 🔗 **Auto-Discovery (Crawler):** Identifica e acessa automaticamente novos grupos compartilhados via links de convite para expandir o escopo de monitoramento.
- 📂 **File Intelligence:** Detecta o envio de arquivos estruturados suspeitos (`.sql`, `.csv`, `.txt`) comumente usados para exfiltração de dados.
- 📝 **Auditoria:** Gera logs detalhados para auditoria.

## ⚙️ Instalação

1. Clone o repositório e instale as dependências:
   ```bash
   pip install -r requirements.txt

🔐 Configuração (OpSec)
Este projeto segue boas práticas de segurança e não armazena credenciais no código. Configure suas variáveis de ambiente:
Linux / Mac:
export TG_API_ID="123456"
export TG_API_HASH="sua_hash_aqui"
export TG_PHONE="+5511999999999"
Windows (Powershell):
$env:TG_API_ID="123456"
$env:TG_API_HASH="sua_hash_aqui"
$env:TG_PHONE="+5511999999999"

💻 Uso
Execute o monitor:
python telegram_leak_monitor.py

⚠️ Disclaimer
Esta ferramenta foi desenvolvida para fins educacionais e monitoramento defensivo. O autor não se responsabiliza pelo mau uso.
👨‍💻 Autor
Desenvolvido por Augusto V.
