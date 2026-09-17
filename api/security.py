"""Dependencias de FastAPI para las tres identidades.

- user     humano verificado por OTP de email → JWT con role="user".
- admin    humano cuyo email está en ADMIN_EMAILS → JWT con role="admin".
- service  máquina → API key estática en el header X-Service-Key (sin OTP ni JWT).

Semántica de errores (no se confunden):
- 401 Unauthorized: no autenticado (falta credencial, o es inválida/expirada).
- 403 Forbidden:    autenticado, pero sin el rol que exige el endpoint.

Ninguna se aplica todavía a endpoints que consume React.
"""
from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from core.auth_config import ServiceKeyConfigError, admin_emails, service_api_keys
from core.auth_tokens import ROLE_ADMIN, InvalidAccessToken, decode_access_token

logger = logging.getLogger(__name__)

ROLE_SERVICE = "service"
SERVICE_KEY_HEADER = "X-Service-Key"

# auto_error=False en ambos esquemas: la ausencia de la credencial se responde con
# 401 desde aquí (con auto_error=True el código depende de la versión de FastAPI).
# Declararlos como esquemas hace que OpenAPI documente qué credencial pide cada endpoint.
_bearer_scheme = HTTPBearer(auto_error=False)
_service_key_scheme = APIKeyHeader(name=SERVICE_KEY_HEADER, auto_error=False)


@dataclass(frozen=True)
class Principal:
    subject: str  # email verificado (user/admin) o identificador del servicio
    role: str


def _unauthorized(detail: str, www_authenticate: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": www_authenticate},
    )


def require_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> Principal:
    """Exige `Authorization: Bearer <token>` con firma, emisor y expiración válidos
    (rol user o admin). Responde 401 si falta o si es inválido/expirado, sin
    revelar la causa exacta."""
    if credentials is None:
        raise _unauthorized("Missing bearer token.", "Bearer")
    try:
        claims = decode_access_token(credentials.credentials)
    except InvalidAccessToken:
        raise _unauthorized("Invalid or expired token.", 'Bearer error="invalid_token"') from None
    return Principal(subject=claims["sub"], role=claims["role"])


def require_admin(principal: Principal = Depends(require_principal)) -> Principal:
    """Exige un JWT válido (401 si no) con role="admin" (403 si no).

    Además el email debe SEGUIR en ADMIN_EMAILS: quitarlo de la lista retira el
    acceso de inmediato, sin esperar a que caduque un token admin ya emitido."""
    if principal.role != ROLE_ADMIN or principal.subject.lower() not in admin_emails():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required.")
    return principal


def require_service(provided_key: str | None = Depends(_service_key_scheme)) -> Principal:
    """Exige `X-Service-Key` igual a alguna key de SERVICE_API_KEY.

    - Comparación en tiempo constante contra TODAS las keys (sin cortar en la
      primera coincidencia): el tiempo no revela cuál key ni cuántos bytes acertó.
    - Fail-closed: sin SERVICE_API_KEY configurada (o si es inválida) no existe
      ninguna key válida y todo se rechaza con 401.
    - Sin key o key inválida → 401. Un JWT (aunque sea admin) no sirve aquí.
    """
    try:
        valid_keys = service_api_keys()
    except ServiceKeyConfigError as error:
        # Config inválida (p. ej. cambiada en caliente tras arrancar): nunca se
        # acepta una key débil; se cierra como si no hubiera keys.
        logger.error("%s Se rechaza toda llamada de servicio.", error)
        valid_keys = []
    if not valid_keys:
        logger.warning("SERVICE_API_KEY no está configurada: se rechaza toda llamada de servicio.")

    if not provided_key:
        raise _unauthorized("Missing service key.", SERVICE_KEY_HEADER)

    candidate = provided_key.encode("utf-8")
    matched = False
    for key in valid_keys:
        matched |= hmac.compare_digest(candidate, key)
    if not matched:
        raise _unauthorized("Invalid service key.", SERVICE_KEY_HEADER)
    return Principal(subject="service", role=ROLE_SERVICE)
