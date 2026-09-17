"""Access tokens (JWT HS256) que se emiten al verificar el email.

Creación y validación viven aquí, sin FastAPI; la dependencia HTTP que los exige
está en api/security.py.

Claims:
    iss   emisor fijo (ISSUER); se valida al decodificar.
    sub   email verificado (identidad del usuario).
    role  tipo de principal. Hoy solo "user"; habrá roles de servicio/auditoría.
    iat   emitido en (epoch UTC).
    exp   expira en (epoch UTC) = iat + JWT_TTL_SECONDS (default 3600).
    jti   id único del token, para poder revocarlo más adelante.
"""
from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from core.auth_config import auth_dev_mode_enabled
from core.email_otp import env_positive_int

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"
ISSUER = "agentbuyer-api"
ROLE_USER = "user"
KNOWN_ROLES = frozenset({ROLE_USER})
DEFAULT_TTL_SECONDS = 3600
MIN_SECRET_BYTES = 32  # RFC 7518 §3.2: la clave HMAC de HS256 debe tener al menos 256 bits
_REQUIRED_CLAIMS = ["iss", "sub", "role", "iat", "exp"]

# ADVERTENCIA: SOLO para desarrollo local. Está en el repositorio, así que cualquiera
# podría falsificar tokens firmados con ella. Por construcción solo se usa con
# AUTH_DEV_MODE=true y sin JWT_SECRET; en cualquier otro caso falta de clave = error.
_DEV_ONLY_SECRET = "dev-only-insecure-jwt-secret-do-not-use-in-production"
_dev_secret_warned = False

_GENERATE_SECRET_HINT = 'python -c "import secrets; print(secrets.token_urlsafe(48))"'


class InvalidAccessToken(Exception):
    """Token mal formado, con firma inválida, expirado o con claims inválidos."""


class TokenConfigError(ValueError):
    """La configuración de firma de tokens es inválida: la app no debe operar."""


def _signing_secret() -> str:
    """Clave de firma. Reglas, en orden:
      1. JWT_SECRET definido → se usa si tiene al menos MIN_SECRET_BYTES; si no, error
         (una clave explícita inválida NUNCA cae a la de desarrollo, ni en modo dev).
      2. Sin JWT_SECRET y AUTH_DEV_MODE=true → clave de desarrollo, con advertencia.
      3. Sin JWT_SECRET en cualquier otro caso → error. Único camino en producción.
    """
    global _dev_secret_warned
    secret = os.getenv("JWT_SECRET", "").strip()
    if secret:
        # PyJWT solo advierte con claves cortas y firma igual: aquí se falla cerrado.
        if len(secret.encode("utf-8")) < MIN_SECRET_BYTES:
            raise TokenConfigError(
                f"JWT_SECRET tiene {len(secret.encode('utf-8'))} bytes; se requieren al menos "
                f"{MIN_SECRET_BYTES}. Genera uno con: {_GENERATE_SECRET_HINT}"
            )
        return secret

    if not auth_dev_mode_enabled():
        raise TokenConfigError(
            "JWT_SECRET no está definido. Es OBLIGATORIO fuera de desarrollo: define JWT_SECRET "
            f"con al menos {MIN_SECRET_BYTES} bytes aleatorios (genera uno con: {_GENERATE_SECRET_HINT}). "
            "Solo para desarrollo local puedes usar AUTH_DEV_MODE=true, que habilita una clave "
            "de desarrollo insegura; nunca en producción."
        )

    if not _dev_secret_warned:
        logger.warning(
            "AUTH_DEV_MODE=true y JWT_SECRET no está definido: se firman tokens con una clave de "
            "DESARROLLO que está en el repositorio. Nunca usar esta configuración en producción."
        )
        _dev_secret_warned = True
    return _DEV_ONLY_SECRET


def access_token_ttl_seconds() -> int:
    return env_positive_int("JWT_TTL_SECONDS", DEFAULT_TTL_SECONDS)


def validate_token_config() -> int:
    """Valida TODA la configuración de firma (JWT_SECRET, AUTH_DEV_MODE y
    JWT_TTL_SECONDS) y devuelve el TTL. Lanza TokenConfigError si algo es inválido.
    Se ejecuta al arrancar la app (api/main.py) y antes de consumir un OTP."""
    _signing_secret()
    try:
        return access_token_ttl_seconds()
    except ValueError as error:
        raise TokenConfigError(str(error)) from None


def create_access_token(
    subject: str,
    role: str = ROLE_USER,
    *,
    ttl_seconds: int | None = None,
    now: datetime | None = None,
) -> str:
    """Firma un access token para `subject`. `now` permite fijar el instante de
    emisión (p. ej. en tests, para obtener un token ya expirado)."""
    if not subject:
        raise ValueError("El subject del token no puede estar vacío.")
    if role not in KNOWN_ROLES:
        raise ValueError(f"Rol desconocido: {role!r}.")

    issued_at = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    lifetime = ttl_seconds if ttl_seconds is not None else access_token_ttl_seconds()
    payload = {
        "iss": ISSUER,
        "sub": subject,
        "role": role,
        "iat": issued_at,
        "exp": issued_at + timedelta(seconds=lifetime),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, _signing_secret(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Valida firma (solo HS256), emisor, expiración y claims obligatorios.
    Cualquier problema se reporta como InvalidAccessToken, sin distinguir causa."""
    try:
        claims = jwt.decode(
            token,
            _signing_secret(),
            algorithms=[ALGORITHM],  # lista cerrada: impide "alg": "none" y confusión de algoritmos
            issuer=ISSUER,
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as error:
        raise InvalidAccessToken(type(error).__name__) from None

    if not isinstance(claims["sub"], str) or not claims["sub"]:
        raise InvalidAccessToken("InvalidSubject")
    if claims["role"] not in KNOWN_ROLES:
        raise InvalidAccessToken("UnknownRole")
    return claims
