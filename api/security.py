"""Dependencia de FastAPI que exige un access token válido.

Lista para usarse con `Depends(require_principal)`, pero TODAVÍA NO se aplica a
ningún endpoint: activarla en los endpoints que consume React obliga a cablear
el token en el frontend.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.auth_tokens import InvalidAccessToken, decode_access_token

# auto_error=False: la ausencia del header también se responde con 401 desde aquí
# (con auto_error=True la respuesta depende de la versión de FastAPI).
_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    subject: str  # email verificado
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
    """Exige `Authorization: Bearer <token>` con firma, emisor y expiración válidos.
    Responde 401 si falta o si es inválido/expirado, sin revelar la causa exacta."""
    if credentials is None:
        raise _unauthorized("Missing bearer token.", "Bearer")
    try:
        claims = decode_access_token(credentials.credentials)
    except InvalidAccessToken:
        raise _unauthorized("Invalid or expired token.", 'Bearer error="invalid_token"') from None
    return Principal(subject=claims["sub"], role=claims["role"])
