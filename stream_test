"""
Controle de acesso por email no Streamlit
==========================================
Objetivo: rastrear QUEM acessa, QUANDO e por QUANTO TEMPO,
sem armazenar o email em texto claro.

Princípios aplicados:
  - Hash SHA-256 do email (irreversível, mas auditável)
  - Consentimento explícito (LGPD art. 7 e 8)
  - Rate limiting por IP para evitar abuso
  - Logs estruturados em CSV (fácil de auditar offline)
  - Nenhuma lib externa além do Streamlit

Instalar: pip install streamlit
Rodar:    streamlit run app_com_controle_acesso.py
"""

import streamlit as st
import hashlib
import re
import csv
import os
import time
from datetime import datetime, timezone
from collections import defaultdict

# ──────────────────────────────────────────────
# CONFIGURAÇÕES
# ──────────────────────────────────────────────

LOG_FILE = "access_log.csv"          # Arquivo de auditoria (nunca contém email puro)
MAX_TENTATIVAS_POR_IP = 5            # Rate limit: máx. tentativas por IP em 10 min
JANELA_RATE_LIMIT_SEG = 600          # 10 minutos em segundos
DOMINIOS_BLOQUEADOS = [              # Rejeitar emails descartáveis (opcional)
    "mailinator.com", "tempmail.com", "guerrillamail.com"
]

# ──────────────────────────────────────────────
# FUNÇÕES DE SEGURANÇA
# ──────────────────────────────────────────────

def hash_email(email: str) -> str:
    """
    Converte o email em um hash SHA-256 irreversível.
    - Nunca armazena o email original
    - O hash é consistente: mesmo email → mesmo hash (permite auditoria)
    - Normaliza para minúsculas antes de hashar (evita duplicatas)
    """
    email_normalizado = email.strip().lower()
    return hashlib.sha256(email_normalizado.encode("utf-8")).hexdigest()


def validar_email(email: str) -> tuple[bool, str]:
    """
    Valida formato e domínio do email.
    Retorna (válido, mensagem_de_erro).
    """
    email = email.strip().lower()

    # Regex básica de validação de formato
    padrao = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    if not re.match(padrao, email):
        return False, "Formato de email inválido."

    # Bloquear domínios descartáveis
    dominio = email.split("@")[-1]
    if dominio in DOMINIOS_BLOQUEADOS:
        return False, "Domínio de email não permitido."

    return True, ""


def obter_ip_usuario() -> str:
    """
    Tenta obter o IP real do usuário via headers do Streamlit.
    Se não disponível (ex.: desenvolvimento local), usa placeholder.
    ATENÇÃO: em produção atrás de proxy/CDN, use o header X-Forwarded-For.
    """
    try:
        # Em Streamlit Cloud e alguns deploys, o IP vem nos headers
        headers = st.context.headers
        ip = (
            headers.get("x-forwarded-for", "").split(",")[0].strip()
            or headers.get("x-real-ip", "")
            or "ip-desconhecido"
        )
        return ip
    except Exception:
        return "ip-desconhecido"


# ──────────────────────────────────────────────
# RATE LIMITING (em memória — simples e eficaz)
# ──────────────────────────────────────────────

# Armazena tentativas por IP: {ip: [timestamp1, timestamp2, ...]}
# Em produção com múltiplos workers, use Redis ou banco de dados
if "rate_limit_store" not in st.session_state:
    st.session_state.rate_limit_store = defaultdict(list)

def checar_rate_limit(ip: str) -> tuple[bool, int]:
    """
    Verifica se o IP ultrapassou o limite de tentativas.
    Retorna (permitido, tentativas_restantes).
    """
    agora = time.time()
    store = st.session_state.rate_limit_store

    # Remove timestamps fora da janela de tempo
    store[ip] = [t for t in store[ip] if agora - t < JANELA_RATE_LIMIT_SEG]

    tentativas = len(store[ip])
    permitido = tentativas < MAX_TENTATIVAS_POR_IP
    restantes = max(0, MAX_TENTATIVAS_POR_IP - tentativas - 1)

    return permitido, restantes

def registrar_tentativa(ip: str):
    """Registra uma tentativa de acesso para o IP."""
    st.session_state.rate_limit_store[ip].append(time.time())


# ──────────────────────────────────────────────
# LOGGING SEGURO
# ──────────────────────────────────────────────

def garantir_cabecalho_log():
    """Cria o arquivo de log com cabeçalho se não existir."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp_utc",    # Ex.: 2025-07-15T14:32:01Z
                "email_hash",       # SHA-256 — nunca o email real
                "ip_hash",          # Hash do IP (privacidade extra)
                "evento",           # "acesso" | "logout" | "tentativa_invalida"
                "duracao_seg",      # Preenchido no logout
                "user_agent_hash",  # Hash do browser (opcional, para análise)
            ])

def gravar_log(email_hash: str, ip: str, evento: str, duracao_seg: float = 0.0):
    """
    Grava uma linha no log de auditoria.
    - email_hash: hash SHA-256 do email (nunca o email puro)
    - ip: anonimizado via hash
    - evento: tipo de evento
    - duracao_seg: tempo de sessão em segundos (no logout)
    """
    garantir_cabecalho_log()

    # Hash do IP também — proteção extra de privacidade
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]  # Primeiros 16 chars bastam

    # User-agent (opcional)
    try:
        ua = st.context.headers.get("user-agent", "desconhecido")
        ua_hash = hashlib.sha256(ua.encode()).hexdigest()[:12]
    except Exception:
        ua_hash = "n/a"

    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            email_hash,
            ip_hash,
            evento,
            f"{duracao_seg:.1f}",
            ua_hash,
        ])


# ──────────────────────────────────────────────
# INTERFACE DE COLETA DE EMAIL
# ──────────────────────────────────────────────

def tela_de_acesso():
    """Renderiza a tela de identificação com consentimento LGPD."""

    st.title("🔐 Identificação de Acesso")

    # Aviso de privacidade — obrigatório pela LGPD
    st.info(
        "**Por que pedimos seu email?**\n\n"
        "Seu email é usado **apenas** para controle de acesso e auditoria interna. "
        "Armazenamos apenas um *hash* irreversível — nunca o email em texto claro. "
        "Não compartilhamos com terceiros. Conforme LGPD Art. 9º."
    )

    with st.form("form_acesso", clear_on_submit=False):
        email_input = st.text_input(
            "Seu email corporativo",
            placeholder="nome@empresa.com.br",
            help="Use seu email institucional. Emails descartáveis são bloqueados.",
        )

        consentimento = st.checkbox(
            "Concordo com o uso do meu email para fins de auditoria e controle de acesso, "
            "conforme descrito acima (LGPD Art. 7º, inciso I).",
            value=False,
        )

        enviado = st.form_submit_button("Entrar", use_container_width=True)

    if enviado:
        _processar_acesso(email_input, consentimento)


def _processar_acesso(email: str, consentimento: bool):
    """Valida, aplica rate limit e registra o acesso."""

    ip = obter_ip_usuario()

    # 1. Verificar rate limit ANTES de qualquer processamento
    permitido, restantes = checar_rate_limit(ip)
    if not permitido:
        st.error(
            f"⛔ Muitas tentativas. Aguarde {JANELA_RATE_LIMIT_SEG // 60} minutos e tente novamente."
        )
        gravar_log("rate-limit-bloqueado", ip, "tentativa_bloqueada")
        return

    # 2. Verificar consentimento
    if not consentimento:
        st.warning("⚠️ É necessário aceitar os termos para continuar.")
        return

    # 3. Validar formato do email
    valido, erro = validar_email(email)
    if not valido:
        registrar_tentativa(ip)
        st.error(f"❌ {erro}")
        gravar_log("email-invalido", ip, "tentativa_invalida")
        return

    # 4. Tudo certo — registrar acesso
    registrar_tentativa(ip)
    email_hash = hash_email(email)
    gravar_log(email_hash, ip, "acesso")

    # 5. Gravar na sessão (nunca o email puro — só o hash e o timestamp de início)
    st.session_state["autenticado"] = True
    st.session_state["email_hash"] = email_hash
    st.session_state["inicio_sessao"] = time.time()
    st.session_state["tentativas_restantes"] = restantes

    st.rerun()


# ──────────────────────────────────────────────
# CONTEÚDO PROTEGIDO
# ──────────────────────────────────────────────

def tela_principal():
    """Conteúdo da aplicação — só acessível após identificação."""

    email_hash = st.session_state.get("email_hash", "?")
    inicio = st.session_state.get("inicio_sessao", time.time())
    duracao = time.time() - inicio

    st.title("✅ Aplicação protegida")

    # Mostra apenas o hash — nunca o email real
    with st.expander("ℹ️ Sua sessão"):
        st.code(f"ID de sessão (hash): {email_hash[:20]}...{email_hash[-8:]}")
        st.caption(f"Tempo de sessão: {duracao:.0f} segundos")

    # ── Coloque aqui o conteúdo real da sua aplicação ──
    st.write("Aqui vai o conteúdo do seu dashboard, análise, ou ferramenta.")
    st.bar_chart({"Jan": 10, "Fev": 25, "Mar": 18, "Abr": 30})

    st.divider()

    if st.button("🚪 Sair", use_container_width=True):
        _logout(email_hash, inicio)


def _logout(email_hash: str, inicio: float):
    """Registra o logout com duração da sessão e limpa o estado."""
    duracao = time.time() - inicio
    ip = obter_ip_usuario()
    gravar_log(email_hash, ip, "logout", duracao_seg=duracao)

    for chave in ["autenticado", "email_hash", "inicio_sessao"]:
        st.session_state.pop(chave, None)

    st.rerun()


# ──────────────────────────────────────────────
# ROTEAMENTO PRINCIPAL
# ──────────────────────────────────────────────

def main():
    st.set_page_config(
        page_title="App Seguro",
        page_icon="🔐",
        layout="centered",
    )

    if st.session_state.get("autenticado"):
        tela_principal()
    else:
        tela_de_acesso()


if __name__ == "__main__":
    main()
