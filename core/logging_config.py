"""Logging estructurado (paso 7.3).

- Un logger por módulo (`logging.getLogger(__name__)`); nada de `print`.
- Nivel por entorno: LOG_LEVEL (default INFO).
- Cada línea lleva el request id de la petición HTTP que la produjo (`req=`): la
  cabecera X-Request-ID si el cliente manda una válida, o una nueva. La respuesta la
  devuelve, así un error que ve una persona se encuentra en el log.
- Nunca datos personales ni secretos: ni emails completos (mask_email), ni códigos
  OTP, ni tokens, ni firmas. tests/test_hygiene.py recorre los flujos de auth con el
  log en DEBUG y lo comprueba.
"""
from __future__ import annotations

import contextvars
import logging
import os
import re
import uuid

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s [req=%(request_id)s] %(message)s"
_REQUEST_ID_SHAPE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_HANDLER_MARK = "_agentbuyer_handler"


class RequestIdFilter(logging.Filter):
    """Agrega `request_id` a cada registro (el de la petición en curso, o "-")."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


def configure_logging() -> None:
    """Configura el logger raíz una sola vez por proceso (idempotente)."""
    root = logging.getLogger()
    level = (os.getenv("LOG_LEVEL") or "INFO").strip().upper()
    root.setLevel(getattr(logging, level, logging.INFO))
    if any(getattr(handler, _HANDLER_MARK, False) for handler in root.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    handler.addFilter(RequestIdFilter())
    setattr(handler, _HANDLER_MARK, True)
    root.addHandler(handler)


def new_request_id(incoming: str | None) -> str:
    """El id que manda el cliente si es seguro (sin espacios ni saltos de línea: no
    puede inyectar líneas falsas en el log); si no, uno nuevo."""
    if incoming and _REQUEST_ID_SHAPE.fullmatch(incoming):
        return incoming
    return uuid.uuid4().hex


def mask_email(email: object) -> str:
    """"maria.perez@example.com" → "m***@example.com". Para logs: identifica el dominio
    sin exponer a la persona."""
    if not isinstance(email, str) or "@" not in email:
        return "***"
    local, _, domain = email.strip().partition("@")
    return f"{local[:1]}***@{domain}"
