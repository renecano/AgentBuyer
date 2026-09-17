"""Dependencias de FastAPI para las tres identidades.

- user     humano verificado por OTP de email → JWT con role="user".
- admin    humano cuyo email está en ADMIN_EMAILS → JWT con role="admin".
- service  máquina → API key estática en el header X-Service-Key (sin OTP ni JWT).

Semántica de errores (no se confunden):
- 401 Unauthorized: no autenticado (falta credencial, o es inválida/expirada).
- 403 Forbidden:    autenticado, pero sin el rol que exige el endpoint.

De los endpoints que consume React, hoy solo POST /mandates exige credencial:
crear un mandato necesita una persona, porque quien lo crea queda como su dueño.
"""
from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from core.auth_config import ServiceKeyConfigError, admin_emails, service_api_keys
from core.auth_tokens import ROLE_ADMIN, ROLE_USER, InvalidAccessToken, decode_access_token
from core.mandate_store import get_mandate_owner, mandate_exists

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


def owner_email_for(principal: Optional[Principal]) -> Optional[str]:
    """Propiedad: email que queda como DUEÑO de un recurso creado por `principal`.
    Solo humanos autenticados (user/admin) son dueños; sin principal o con un
    servicio, no hay dueño (None).

    Los dos endpoints de creación (POST /mandates y POST /mandates/create) pasan
    por aquí su Principal: el dueño sale SIEMPRE del token, nunca del cuerpo."""
    if principal is None or principal.role not in (ROLE_USER, ROLE_ADMIN):
        return None
    return principal.subject.strip().lower()


def require_admin(principal: Principal = Depends(require_principal)) -> Principal:
    """Exige un JWT válido (401 si no) con role="admin" (403 si no).

    Además el email debe SEGUIR en ADMIN_EMAILS: quitarlo de la lista retira el
    acceso de inmediato, sin esperar a que caduque un token admin ya emitido."""
    if principal.role != ROLE_ADMIN or principal.subject.lower() not in admin_emails():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required.")
    return principal


def _service_key_matches(provided_key: str) -> bool:
    """Compara la key contra TODAS las configuradas en tiempo constante (sin cortar
    en la primera coincidencia): el tiempo no revela cuál key ni cuántos bytes acertó.

    Fail-closed: sin SERVICE_API_KEY configurada (o si es inválida) no hay ninguna
    key válida y nada coincide."""
    try:
        valid_keys = service_api_keys()
    except ServiceKeyConfigError as error:
        # Config inválida (p. ej. cambiada en caliente tras arrancar): nunca se
        # acepta una key débil; se cierra como si no hubiera keys.
        logger.error("%s Se rechaza toda llamada de servicio.", error)
        valid_keys = []
    if not valid_keys:
        logger.warning("SERVICE_API_KEY no está configurada: se rechaza toda llamada de servicio.")

    candidate = provided_key.encode("utf-8")
    matched = False
    for key in valid_keys:
        matched |= hmac.compare_digest(candidate, key)
    return matched


def require_service(provided_key: str | None = Depends(_service_key_scheme)) -> Principal:
    """Exige `X-Service-Key` igual a alguna key de SERVICE_API_KEY.

    Sin key o key inválida → 401. Un JWT (aunque sea admin) no sirve aquí.
    """
    if not provided_key:
        raise _unauthorized("Missing service key.", SERVICE_KEY_HEADER)
    if not _service_key_matches(provided_key):
        raise _unauthorized("Invalid service key.", SERVICE_KEY_HEADER)
    return Principal(subject="service", role=ROLE_SERVICE)


def require_human_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    provided_key: str | None = Depends(_service_key_scheme),
) -> Principal:
    """Exige una PERSONA autenticada (user/admin): quien crea un mandato es su dueño.

    Mira también la key de servicio para poder distinguir los dos errores, que no
    son lo mismo: un servicio con key válida SÍ está autenticado, pero no es dueño
    de nada (403); cualquier otra cosa es falta de credencial válida (401).
    Un rol "service" no puede llegar por el bearer: ese rol nunca se emite en un JWT.
    """
    if credentials is None and provided_key and _service_key_matches(provided_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A service cannot own mandates; use a personal token.",
        )
    return require_principal(credentials)


def is_admin(principal: Principal) -> bool:
    """Admin efectivo: el token dice "admin" y el email SIGUE en ADMIN_EMAILS
    (misma regla que require_admin: quitarlo de la lista retira el poder ya)."""
    return principal.role == ROLE_ADMIN and principal.subject.strip().lower() in admin_emails()


def assert_can_access_mandate(principal: Principal, mandate_id: str) -> None:
    """Autorización por mandato: pasa si `principal` es su dueño o es admin.

    - Mandato inexistente → 404 (no hay propiedad que evaluar).
    - Dueño (owner == subject, normalizado) o admin efectivo → pasa.
    - Mandato HUÉRFANO (owner None, p. ej. creado antes de exigir token o por el
      seed sin email): solo admin. Un user recibe 403 — ante duda de propiedad se
      deniega, en vez de regalar el mandato a quien lo pida primero.
    - Cualquier otro rol (service) → 403: no es dueño de nada.
    - Un admin degradado (fuera de ADMIN_EMAILS) cae al camino de dueño: conserva
      sus propios mandatos, pierde los ajenos.

    Devuelve None; lanza HTTPException. No se aplica aún a revoke/reset/get/etc.
    """
    if not mandate_exists(mandate_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mandate not found")
    if is_admin(principal):
        return
    owner = get_mandate_owner(mandate_id)
    # El 403 revela que el mandato existe. Es aceptable: los ids los genera el
    # cliente y ya se distinguen hoy (404) sin credencial alguna.
    if owner is None or principal.role not in (ROLE_USER, ROLE_ADMIN) or owner != principal.subject.strip().lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This mandate belongs to another account.",
        )
