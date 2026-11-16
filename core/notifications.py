"""Correo saliente: códigos OTP y recibos de compras autorizadas (7.1).

Cambios del 7.1 (P-06, P-07):
- Sin IMAP: el inbox (GET /inbox/messages) se retiró, y con él la lectura del Gmail.
- El recibo ya no lo dispara un endpoint ni un webhook: es un servicio interno que
  llama la compra (core/agent_loop.py). Antes se armaba con f-strings SIN escapar (la
  descripción de la oferta, que viene del LLM, entraba cruda al HTML) e inventaba casi
  todo: un PNR que nadie emitió, un vuelo "a 3 días a las 14:00", mch_vuelaya y
  FLT-COR-130 fijos, "TOTAL PAID", "Fiscal receipt". Ahora es una plantilla en archivo
  (templates/emails, Jinja2 con autoescape) con los datos reales de la compra.
- El destinatario es el DUEÑO VERIFICADO del mandato (el email del token con el que se
  creó), no el campo `human.email` que manda el cliente: ese campo no está firmado y
  permitía dirigir los recibos a cualquier dirección.
- Todo envío SMTP tiene timeout (SMTP_TIMEOUT_SECONDS): un servidor colgado no
  bloquea la compra ni el login.

Configuración (variables de entorno, ver .env.example):
    SMTP_USER / SMTP_PASS     credenciales (sin ellas no se envía nada)
    SMTP_HOST / SMTP_PORT     servidor SMTP con TLS implícito (default smtp.gmail.com:465)
    SMTP_TIMEOUT_SECONDS      timeout de conexión y envío (default 10)
"""
from __future__ import annotations

import os
import smtplib
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from core.email_otp import env_positive_int

TEMPLATES_PATH = Path(__file__).resolve().parents[1] / "templates" / "emails"
DEFAULT_SMTP_HOST = "smtp.gmail.com"
DEFAULT_SMTP_PORT = 465
DEFAULT_SMTP_TIMEOUT_SECONDS = 10
RECEIPT_SUBJECT = "Purchase authorized under your permission"

# Autoescape para las plantillas HTML; el texto plano no es HTML. StrictUndefined: una
# variable que falta es un error, no un hueco silencioso en el correo.
_templates = Environment(
    loader=FileSystemLoader(str(TEMPLATES_PATH)),
    autoescape=lambda name: bool(name) and name.endswith(".html.j2"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
)


@dataclass(frozen=True)
class SmtpConfig:
    user: str
    password: str
    host: str
    port: int
    timeout_seconds: int

    @classmethod
    def from_env(cls) -> "SmtpConfig":
        return cls(
            user=os.environ.get("SMTP_USER", ""),
            password=os.environ.get("SMTP_PASS", ""),
            host=(os.environ.get("SMTP_HOST") or "").strip() or DEFAULT_SMTP_HOST,
            port=env_positive_int("SMTP_PORT", DEFAULT_SMTP_PORT),
            timeout_seconds=env_positive_int("SMTP_TIMEOUT_SECONDS", DEFAULT_SMTP_TIMEOUT_SECONDS),
        )

    @property
    def configured(self) -> bool:
        return bool(self.user and self.password)

    @property
    def sender(self) -> str:
        return f"Saturday Agent <{self.user}>" if self.user else "Saturday Agent <no-reply@example.com>"


def _deliver(config: SmtpConfig, message, recipient: str) -> None:
    """Envía por SMTP con TLS implícito y timeout. Lanza la excepción del envío."""
    with smtplib.SMTP_SSL(config.host, config.port, timeout=config.timeout_seconds) as server:
        server.login(config.user, config.password)
        server.sendmail(config.user, [recipient], message.as_string())


# ── Códigos OTP ─────────────────────────────────────────────────────────────

# Qué autoriza cada código: el correo lo dice, para que la persona sepa qué está
# aprobando. Un código de "registrar llave" que no pidió es la señal de que alguien
# usa su sesión.
OTP_PURPOSE_LOGIN = "login"
OTP_PURPOSE_REGISTER_KEY = "register-key"
_OTP_EMAIL_TEXT = {
    OTP_PURPOSE_LOGIN: (
        "Your Aegis verification code",
        "🛡️ Zero-Trust Verification Code (Aegis):\n\nYour 6-digit verification code is: {code}\n\n",
    ),
    OTP_PURPOSE_REGISTER_KEY: (
        "Confirm a new security key",
        "Someone signed in to your account is registering a new security key for signing "
        "purchase permissions.\n\nIf it was you, your confirmation code is: {code}\n\n"
        "If it wasn't you, do NOT use this code: someone may have access to your session. "
        "Sign out and sign back in.\n\n",
    ),
}


def enviar_token_otp(correo_destino: str, codigo_otp: str, minutos_validez: int = 10,
                     proposito: str = OTP_PURPOSE_LOGIN) -> dict:
    """
    Sends the 6-digit verification code (OTP) from the configured SMTP account.

    The code travels ONLY in the email body: never in the subject, logs, or the
    returned dict. Returns sent_via="smtp" only when delivery actually succeeded.
    `proposito` selects what the email says the code authorizes (login vs. registering a key).
    """
    dest = (correo_destino or "").strip().lower()
    if not dest or "@" not in dest:
        return {"status": 400, "message": "Invalid email address.", "sent_via": "error"}
    if proposito not in _OTP_EMAIL_TEXT:
        raise ValueError(f"Propósito de OTP desconocido: {proposito!r}.")

    config = SmtpConfig.from_env()
    subject, intro = _OTP_EMAIL_TEXT[proposito]
    msg = MIMEText(
        intro.format(code=codigo_otp)
        + f"This code expires in {minutos_validez} minutes and can be used only once. "
        f"Do not share it with anyone.",
        "plain",
        "utf-8"
    )
    msg["Subject"] = subject
    msg["From"] = config.sender
    msg["To"] = dest

    if config.configured:
        try:
            _deliver(config, msg, dest)
            print(f"[Gmail SMTP OTP] Verification code sent to {dest}")
            return {"status": 200, "message": f"Verification code sent to {dest}", "sent_via": "smtp"}
        except Exception as err:
            # Solo el tipo de error: el detalle del servidor SMTP podría reflejar el mensaje.
            print(f"[Gmail SMTP ERROR] Failed to send verification code to {dest}: {type(err).__name__}")
            return {"status": 500, "message": "Email delivery failed.", "sent_via": "error"}

    return {"status": 200, "message": "SMTP not configured; email not sent.", "sent_via": "memory"}


# ── Recibo de una compra autorizada ─────────────────────────────────────────

@dataclass(frozen=True)
class PurchaseReceipt:
    """Datos REALES de una compra aprobada (los que verificó /verify y registró el ledger)."""
    recipient_email: str          # dueño verificado del mandato
    mandate_id: str
    attempt_id: str
    description: str              # descripción de la oferta (dato no confiable: se escapa)
    merchant_name: str            # nombre que mostró la oferta (no confiable: se escapa)
    merchant_id: str              # derivado del dominio de la oferta (core/merchant_identity)
    amount_cents: int
    currency: str
    authorized_at: str            # instante del evento del ledger
    offer_url: Optional[str] = None
    ledger_event_id: Optional[str] = None
    holder_name: Optional[str] = None


def _http_url(url: Optional[str]) -> Optional[str]:
    """Solo enlaces http(s); cualquier otro esquema (javascript:, data:) no se enlaza."""
    if not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None
    return url.strip() if parsed.scheme in ("http", "https") and parsed.hostname else None


def render_purchase_receipt(receipt: PurchaseReceipt) -> tuple[str, str, str]:
    """(asunto, texto, html). El asunto es fijo: sin datos personales ni de la compra."""
    from core.money import format_money

    context = {
        "holder_name": (receipt.holder_name or "").strip() or None,
        "description": receipt.description,
        "amount": format_money(receipt.amount_cents),
        "currency": receipt.currency,
        "merchant_name": receipt.merchant_name,
        "merchant_id": receipt.merchant_id,
        "offer_url": _http_url(receipt.offer_url),
        "authorized_at": receipt.authorized_at,
        "mandate_id": receipt.mandate_id,
        "attempt_id": receipt.attempt_id,
        "ledger_event_id": receipt.ledger_event_id,
    }
    text = _templates.get_template("purchase_receipt.txt.j2").render(context)
    html = _templates.get_template("purchase_receipt.html.j2").render(context)
    return RECEIPT_SUBJECT, text, html


def send_purchase_receipt(receipt: PurchaseReceipt) -> dict:
    """Envía el recibo al dueño del mandato. Nunca rompe la compra: devuelve el
    resultado (sent / skipped / failed) para que quien llama lo registre."""
    dest = (receipt.recipient_email or "").strip().lower()
    if not dest or "@" not in dest:
        return {"status": "skipped", "reason": "The mandate has no verified owner email."}
    subject, text, html = render_purchase_receipt(receipt)
    config = SmtpConfig.from_env()
    if not config.configured:
        return {"status": "skipped", "reason": "SMTP is not configured."}

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = config.sender
    message["To"] = dest
    message.attach(MIMEText(text, "plain", "utf-8"))
    message.attach(MIMEText(html, "html", "utf-8"))
    try:
        _deliver(config, message, dest)
    except Exception as error:  # timeout, rechazo del servidor, credenciales…
        return {"status": "failed", "reason": type(error).__name__}
    return {"status": "sent"}
