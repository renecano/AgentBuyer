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
# podría falsificar tokens firmados con ella. En producción JWT_SECRET debe venir
# del entorno (gestor de secretos), con al menos 32 bytes aleatorios.
_DEV_ONLY_SECRET = "dev-only-insecure-jwt-secret-do-not-use-in-production"
_dev_secret_warned = False


class InvalidAccessToken(Exception):
    """Token mal formado, con firma inválida, expirado o con claims inválidos."""


def _signing_secret() -> str:
    global _dev_secret_warned
    secret = os.getenv("JWT_SECRET", "").strip()
    if secret:
        # PyJWT solo advierte con claves cortas y firma igual: aquí se falla cerrado.
        if len(secret.encode("utf-8")) < MIN_SECRET_BYTES:
            raise ValueError(f"JWT_SECRET debe tener al menos {MIN_SECRET_BYTES} bytes.")
        return secret
    if not _dev_secret_warned:
        logger.warning(
            "JWT_SECRET no está definido: se firman tokens con una clave de DESARROLLO. "
            "En producción JWT_SECRET debe venir del entorno."
        )
        _dev_secret_warned = True
    return _DEV_ONLY_SECRET


def access_token_ttl_seconds() -> int:
    return env_positive_int("JWT_TTL_SECONDS", DEFAULT_TTL_SECONDS)


def validated_token_ttl_seconds() -> int:
    """Valida TODA la configuración de firma (JWT_SECRET y JWT_TTL_SECONDS) y
    devuelve el TTL. Lanza ValueError si algo es inválido, antes de emitir nada."""
    _signing_secret()
    return access_token_ttl_seconds()


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
