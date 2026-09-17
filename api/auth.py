"""Autenticación por email: único mecanismo de login.

POST /auth/email/start  → emite un código de 6 dígitos y lo envía por correo.
POST /auth/email/check  → verifica el código (uso único, con TTL y límite de intentos).

El código NUNCA viaja en la respuesta, salvo con AUTH_DEV_MODE=true (desarrollo
local sin SMTP). Ni siquiera si el envío falla: en ese caso se invalida y se
responde 503. Una verificación exitosa emite un access token (JWT) cuyo sub es el
email verificado; ningún endpoint lo exige todavía (ver api/security.py).
"""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from core.auth_config import auth_dev_mode_enabled
from core.auth_tokens import create_access_token, role_for_email, validate_token_config
from core.email_otp import EmailOtpService, OtpCheck, OtpRateLimited
from core.notifications import enviar_token_otp

router = APIRouter()

# Instancia del proceso; los tests la sustituyen por una con reloj controlado.
otp_service = EmailOtpService.from_env()

_EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


class EmailStartRequest(BaseModel):
    email: str


class EmailCheckRequest(BaseModel):
    email: str
    code: str


def send_verification_email(email: str, code: str, ttl_seconds: int) -> bool:
    """True solo si el correo se entregó de verdad al servidor SMTP."""
    result = enviar_token_otp(email, code, minutos_validez=max(1, ttl_seconds // 60))
    return result.get("sent_via") == "smtp"


def _normalize_email(raw: str) -> str:
    email = raw.strip().lower()
    if not _EMAIL_PATTERN.fullmatch(email):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Invalid email address.")
    return email


def _email_hint(email: str) -> str:
    local, domain = email.split("@", 1)
    return f"***{local[-3:]}@{domain}"


@router.post("/auth/email/start")
def auth_email_start(payload: EmailStartRequest):
    email = _normalize_email(payload.email)

    try:
        code = otp_service.issue(email)
    except OtpRateLimited as limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many verification code requests for this email. Try again later.",
            headers={"Retry-After": str(limited.retry_after_seconds)},
        ) from None

    dev_mode = auth_dev_mode_enabled()
    delivered = send_verification_email(email, code, otp_service.ttl_seconds)
    if not delivered and not dev_mode:
        # Fail-closed: un código que nadie recibió no debe quedar vivo, y jamás se revela.
        otp_service.invalidate(email)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="We couldn't send the verification email. Try again later.",
        )

    body = {
        "ok": True,
        "status": "pending",
        "email_hint": _email_hint(email),
        "sent_via": "smtp" if delivered else "dev",
        "expires_in_seconds": otp_service.ttl_seconds,
        "message": f"Verification code sent to {email}",
    }
    if dev_mode:
        body["code_demo"] = code
    return body


@router.post("/auth/email/check")
def auth_email_check(payload: EmailCheckRequest):
    email = _normalize_email(payload.email)
    # Antes de verificar: una configuración de tokens inválida (JWT_SECRET o
    # JWT_TTL_SECONDS) no debe consumir el código de un solo uso.
    token_ttl = validate_token_config()
    result = otp_service.verify(email, payload.code)

    if result is OtpCheck.VALID:
        return {
            "ok": True,
            "verified": True,
            "email": email,
            "message": "Email verified successfully.",
            "access_token": create_access_token(email, role=role_for_email(email), ttl_seconds=token_ttl),
            "token_type": "bearer",
            "expires_in": token_ttl,
        }
    if result is OtpCheck.LOCKED:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Request a new verification code.",
        )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect or expired Email OTP code.")
