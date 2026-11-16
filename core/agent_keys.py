"""Llaves del AGENTE, del lado del servidor (P-02, 4.2).

El agente es un servicio de la plataforma, no una persona: su llave identifica a ese
servicio y es correcto que la guarde el servidor. Las llaves de las PERSONAS no viven
aquí: cada titular firma en su dispositivo y el servidor solo guarda su pubkey
(core/owner_keys).

Firma del intento (4.2): el agente firma con Ed25519 los bytes canónicos (2.0,
mandate/canonical.py) del intento SIN el campo `agent_signature`. /verify la exige
cuando el intento la declara: un intento firmado por una llave que no es la del
agente que dice presentarlo, o alterado después de firmar, se rechaza.

En memoria, como el resto del estado efímero: se pierde al reiniciar (Fase 6).
"""
from __future__ import annotations

import threading
from typing import Any, Dict, Optional

from mandate.canonical import CanonicalizationError, canonicalize
from mandate.sign import generate_keypair, verify_ed25519_bytes

AGENT_SIGNATURE_FIELD = "agent_signature"

_registry: Dict[str, Dict[str, str]] = {}
_lock = threading.Lock()


def get_or_create_agent_keys(agent_id: str) -> Dict[str, str]:
    """{"priv", "pub"} del agente (se crea la primera vez)."""
    with _lock:
        if agent_id not in _registry:
            priv, pub = generate_keypair()
            _registry[agent_id] = {"priv": priv, "pub": pub}
        return dict(_registry[agent_id])


def agent_public_key(agent_id: Any) -> Optional[str]:
    """Pubkey del agente, o None si el servidor no lo conoce (no se crea aquí)."""
    if not isinstance(agent_id, str):
        return None
    with _lock:
        keys = _registry.get(agent_id)
        return keys["pub"] if keys else None


def attempt_signing_bytes(attempt: dict) -> bytes:
    """Bytes que firma el agente: el intento canónico sin `agent_signature`."""
    unsigned = {key: value for key, value in attempt.items() if key != AGENT_SIGNATURE_FIELD}
    return canonicalize(unsigned)


def sign_attempt(agent_id: str, attempt: dict) -> str:
    """Firma Ed25519 (hex) del agente sobre el intento."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(get_or_create_agent_keys(agent_id)["priv"]))
    return private.sign(attempt_signing_bytes(attempt)).hex()


def verify_attempt_signature(agent_id: Any, attempt: dict) -> bool:
    """¿La firma declarada del intento es del agente `agent_id` sobre ESTE intento?
    Fail-closed: agente desconocido, firma ausente o intento no canonicalizable → False."""
    public_key = agent_public_key(agent_id)
    signature = attempt.get(AGENT_SIGNATURE_FIELD)
    if public_key is None or not isinstance(signature, str):
        return False
    try:
        message = attempt_signing_bytes(attempt)
    except CanonicalizationError:
        return False
    return verify_ed25519_bytes(public_key, message, signature)


def clear() -> None:
    with _lock:
        _registry.clear()
