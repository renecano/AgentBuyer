"""Identidad del comercio derivada de la FUENTE de la oferta (paso 5.3).

El nombre de comercio que devuelve la búsqueda web lo AFIRMA el LLM: no se acepta
como identidad. El comercio de una oferta es el del dominio de su URL, y ese es el
que se compara con allowed_merchants. Así un LLM (o una página manipulada) no puede
hacer pasar una oferta de "otro-sitio.com" por una de un comercio autorizado.

Regla (simple y documentada, sin la Public Suffix List completa): se toma el nombre
registrable del host, quitando "www." y un sufijo de segundo nivel común (com.ar,
co.uk…). "www.despegar.com.ar" → "mch_despegar"; "flights.kayak.com" → "mch_kayak".
Una URL que no sea http(s) con host no tiene identidad verificable → None.
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlparse

_SECOND_LEVEL = {"com", "co", "org", "net", "gob", "gov", "edu", "ac"}
_LABEL = re.compile(r"^[a-z0-9-]+$")


def merchant_id_from_url(url: Any) -> Optional[str]:
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https") or not host:
        return None
    labels = [label for label in host.split(".") if label]
    if labels and labels[0] == "www":
        labels = labels[1:]
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return None
    name = labels[-3] if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL else labels[-2]
    return f"mch_{name.replace('-', '_')}"
