#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
------------------------------------------------------------------------------
 Project: Telegram Threat Intelligence Monitor
 Author: Augusto V.
 Version: 1.0.0
 
 Description:
    Ferramenta de monitoramento em tempo real (Real-Time Monitoring) para 
    Telegram. Utiliza a API (Telethon) para identificar palavras-chave de risco,
    vazamentos de credenciais (DLP) e compartilhamento de arquivos maliciosos
    em grupos monitorados.

 Features:
    - 🕵️ Real-time Keyword Alerting (DLP).
    - 🔗 Auto-discovery de novos grupos via links de convite.
    - 📂 Detecção de arquivos suspeitos (Dumps SQL, Combo lists).
    - 📝 Logging automático para auditoria.

 Disclaimer:
    Esta ferramenta foi desenvolvida para fins educacionais e monitoramento defensivo. O autor não se responsabiliza pelo mau uso.
------------------------------------------------------------------------------
"""

import os
import re
import sys
import asyncio
import logging
from datetime import datetime
from telethon import TelegramClient, events
from telethon.tl.types import MessageMediaDocument
from telethon.tl.functions.messages import ImportChatInviteRequest
from telethon.tl.functions.account import UpdateNotifySettingsRequest
from telethon.tl.types import InputPeerNotifySettings
from telethon.errors import (
    UserAlreadyParticipantError, InviteHashExpiredError, 
    FloodWaitError, PeerFloodError
)

# ==============================================================================
# CONFIGURAÇÃO DE AMBIENTE (OpSec)
# ==============================================================================
# As credenciais devem estar nas Variáveis de Ambiente do Sistema
API_ID = os.getenv('TG_API_ID')
API_HASH = os.getenv('TG_API_HASH')
PHONE_NUMBER = os.getenv('TG_PHONE')

if not API_ID or not API_HASH:
    print("[-] Erro: Variáveis de ambiente TG_API_ID e TG_API_HASH não configuradas.")
    sys.exit(1)

# Palavras-chave para Monitoramento (DLP / Threat Intel)
KEYWORDS_LEAK = [
    "combo", "email:pass", "senha", "login", "database", "db dump", 
    "vazamento", "leak", "cpf", "tse", "serasa", "auth", "bradesco", 
    "itau", "nubank", "bin", "cc full", "banco de dados", "sql dump",
    "root", "admin", "access", "config", "password"
]

# Configuração de Logs
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, 'threat_alerts.log')
LINKS_FILE = os.path.join(BASE_DIR, 'discovered_groups.txt')

# Cores ANSI
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'      # High Risk
    GREEN = '\033[92m'    # Info
    YELLOW = '\033[93m'   # Warning
    BLUE = '\033[94m'     # Network
    MAGENTA = '\033[95m'  # System
    CYAN = '\033[96m'     # Files
    BOLD = '\033[1m'

logging.basicConfig(filename='system_error.log', level=logging.ERROR)
client = TelegramClient('session_monitor', int(API_ID), API_HASH)

# ==============================================================================
# UTILITÁRIOS
# ==============================================================================

def log_alert(text):
    """Registra alertas em arquivo para auditoria."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] {text}\n")

# ==============================================================================
# ENGINE DE MONITORAMENTO
# ==============================================================================

@client.on(events.NewMessage)
async def monitor_handler(event):
    try:
        chat = await event.get_chat()
        chat_title = getattr(chat, 'title', 'Private/Unknown')
        sender = await event.get_sender()
        username = getattr(sender, 'username', 'Unknown')
        message_text = event.raw_text.lower()

        # [1] Auto-Discovery: Detectar Links de Grupos
        links = re.findall(r"(https?://t\.me/(joinchat/|[\+])[a-zA-Z0-9_-]+)", event.raw_text)
        if links:
            for url, _ in links:
                print(f"{Colors.BLUE}[🔎] Link detectado em '{chat_title}': {url}{Colors.RESET}")
                with open(LINKS_FILE, 'a') as f:
                    f.write(f"{url}\n")
                
                # Crawler: Tentar entrar automaticamente
                try:
                    invite_hash = url.split("/")[-1].replace("+", "")
                    await client(ImportChatInviteRequest(invite_hash))
                    print(f"{Colors.GREEN}[+] Crawler: Acesso obtido a novo grupo via link.{Colors.RESET}")
                except Exception:
                    pass 

        # [2] DLP: Detecção de Palavras-Chave
        found_keywords = [kw for kw in KEYWORDS_LEAK if kw in message_text]
        
        if found_keywords:
            print(f"\n{Colors.RED}{Colors.BOLD}🚨 THREAT DETECTED 🚨{Colors.RESET}")
            print(f"{Colors.YELLOW}Source:{Colors.RESET} {chat_title}")
            print(f"{Colors.YELLOW}Actor:{Colors.RESET} @{username}")
            print(f"{Colors.RED}Tags:{Colors.RESET} {found_keywords}")
            print(f"{Colors.MAGENTA}Payload:{Colors.RESET} {event.raw_text[:100].replace(chr(10), ' ')}...")
            print("-" * 50)
            
            log_alert(f"THREAT_MATCH | Src: {chat_title} | Actor: {username} | Tags: {found_keywords}")

        # [3] File Intelligence: Detecção de Dumps
        if event.media and isinstance(event.media, MessageMediaDocument):
            filename = getattr(event.file, 'name', 'unnamed')
            if filename:
                ext = filename.split('.')[-1].lower()
                if ext in ['txt', 'sql', 'csv', 'json', 'rar', 'zip']:
                    print(f"{Colors.CYAN}[📂] Arquivo Suspeito: {filename} (em {chat_title}){Colors.RESET}")
                    log_alert(f"FILE_DETECTED | Src: {chat_title} | File: {filename}")

    except Exception as e:
        logging.error(f"Handler Error: {e}")

async def main():
    print(f"{Colors.GREEN}╔════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.GREEN}║    TELEGRAM THREAT INTELLIGENCE MONITOR    ║{Colors.RESET}")
    print(f"{Colors.GREEN}║        Status: Online | Mode: Passive      ║{Colors.RESET}")
    print(f"{Colors.GREEN}╚════════════════════════════════════════════╝{Colors.RESET}")
    
    print(f"{Colors.BLUE}[*] Inicializando sessão segura...{Colors.RESET}")
    await client.start(phone=PHONE_NUMBER)
    
    me = await client.get_me()
    print(f"{Colors.GREEN}[+] Conectado: {me.first_name} (@{me.username}){Colors.RESET}")
    print(f"{Colors.MAGENTA}[*] Carregadas {len(KEYWORDS_LEAK)} assinaturas de ameaça...{Colors.RESET}")
    print(f"{Colors.YELLOW}[!] Monitoramento Ativo. (Ctrl+C para encerrar){Colors.RESET}\n")

    await client.run_until_disconnected()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Monitoramento encerrado.{Colors.RESET}")
