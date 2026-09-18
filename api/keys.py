"""Llaves públicas del dueño autenticado: registrar (POST /keys) y listar (GET /keys),
más el step-up y el challenge de la prueba de posesión (core/key_challenges.py).

El dueño es SIEMPRE el subject del token (owner_email_for), nunca el cuerpo: un
campo owner/owner_email en el body se ignora, igual que al crear un mandato.
Aditivo: registrar una llave todavía no cambia la verificación de mandatos, y
POST /keys todavía no exige la prueba de posesión (eso es el sub-paso 2.4).
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from api.security import Principal, owner_email_for, require_principal
from core.auth_config import auth_dev_mode_enabled
from core.email_otp import EmailOtpService, OtpCheck, OtpRateLimited
from core.key_challenges import REGISTER_KEY_PURPOSE, KeyChallengeService
from core.notifications import OTP_PURPOSE_REGISTER_KEY, enviar_token_otp
from core.owner_keys import (
    InvalidPublicKey,
    KeyConflict,
    list_active_key_records,
    register_key,
)

router = APIRouter()

# Instancias del proceso; los tests las sustituyen por otras con reloj controlado.
# El OTP de step-up es un servicio APARTE del de login (api/auth.otp_service): un
# código de login no confirma un registro de llave, ni al revés, y cada uno lleva
# su propio rate limit.
step_up_otp_service = EmailOtpService.from_env()
challenge_service = KeyChallengeService()

# Lo único que se expone de una llave: nada privado (el servidor no tiene nada
# privado del dueño) y sin el email, que ya es el del propio token.
_PUBLIC_FIELDS = ("key_id", "public_key", "alg", "created_at")


class RegisterKeyRequest(BaseModel):
    # Campos extra (p. ej. owner_email) se IGNORAN: Pydantic los descarta por defecto.
    public_key: str


def _owner(principal: Principal) -> str:
    owner = owner_email_for(principal)
    if owner is None:  # require_principal solo deja pasar user/admin; defensa en profundidad
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only a person can own keys.")
    return owner


def _public_view(record: dict) -> dict:
    return {field: record[field] for field in _PUBLIC_FIELDS}


@router.post("/keys", status_code=status.HTTP_201_CREATED)
def register_public_key(payload: RegisterKeyRequest, principal: Principal = Depends(require_principal)):
    """Registra una llave pública Ed25519 (64 hex) bajo el email del token."""
    owner = _owner(principal)
    try:
        key_id = register_key(owner, payload.public_key)
    except InvalidPublicKey as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)) from None
    except KeyConflict as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from None
    record = next(record for record in list_active_key_records(owner) if record["key_id"] == key_id)
    return _public_view(record)


@router.get("/keys")
def list_public_keys(principal: Principal = Depends(require_principal)):
    """Llaves ACTIVAS del dueño del token (las revocadas no aparecen)."""
    return {"keys": [_public_view(record) for record in list_active_key_records(_owner(principal))]}


# ── Prueba de posesión: step-up OTP + challenge (sub-paso 2.3) ──────────────

class ChallengeRequest(BaseModel):
    # El OTP de step-up recibido en el correo del dueño del token.
    code: str


def send_step_up_email(email: str, code: str, ttl_seconds: int) -> bool:
    """True solo si el correo se entregó de verdad al servidor SMTP."""
    result = enviar_token_otp(email, code, minutos_validez=max(1, ttl_seconds // 60), proposito=OTP_PURPOSE_REGISTER_KEY)
    return result.get("sent_via") == "smtp"


def _email_hint(email: str) -> str:
    local, domain = email.split("@", 1)
    return f"***{local[-3:]}@{domain}"


@router.post("/keys/step-up/start")
def start_key_step_up(principal: Principal = Depends(require_principal)):
    """Envía un OTP de confirmación al email DEL TOKEN (no se acepta otro destino).

    Registrar una llave de firma es sensible: la sesión sola no alcanza. Quien tenga
    el token pero no el correo no podrá pasar al challenge."""
    owner = _owner(principal)
    try:
        code = step_up_otp_service.issue(owner)
    except OtpRateLimited as limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many confirmation code requests. Try again later.",
            headers={"Retry-After": str(limited.retry_after_seconds)},
        ) from None

    dev_mode = auth_dev_mode_enabled()
    delivered = send_step_up_email(owner, code, step_up_otp_service.ttl_seconds)
    if not delivered and not dev_mode:
        # Fail-closed, igual que el login: un código que nadie recibió no queda vivo.
        step_up_otp_service.invalidate(owner)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="We couldn't send the confirmation email. Try again later.",
        )

    body = {
        "ok": True,
        "email_hint": _email_hint(owner),
        "sent_via": "smtp" if delivered else "dev",
        "expires_in_seconds": step_up_otp_service.ttl_seconds,
    }
    if dev_mode:
        body["code_demo"] = code
    return body


@router.post("/keys/challenge", status_code=status.HTTP_201_CREATED)
def issue_key_challenge(payload: ChallengeRequest, principal: Principal = Depends(require_principal)):
    """Canjea un OTP de step-up FRESCO (de uso único) por un challenge para la
    prueba de posesión, atado al email del token y válido CHALLENGE_TTL_SECONDS.

    Un código incorrecto o vencido es 403, NO 401: la sesión es válida (401 haría
    que el frontend cerrara la sesión por un código mal tecleado)."""
    owner = _owner(principal)
    result = step_up_otp_service.verify(owner, payload.code)
    if result is OtpCheck.LOCKED:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Request a new confirmation code.",
        )
    if result is not OtpCheck.VALID:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A fresh confirmation code is required to register a key.",
        )

    challenge = challenge_service.issue(owner)
    return {
        "challenge_id": challenge.challenge_id,
        "nonce": challenge.nonce,
        "expires_in": challenge_service.ttl_seconds,
        # El cliente firma canonical({purpose, challenge_id, nonce, owner, public_key}):
        # ver core/key_challenges.registration_message.
        "purpose": REGISTER_KEY_PURPOSE,
    }
