"""Mandatos firmados por el HUMANO: alta verificada (3.3) y verificación en /verify.

Desde el 3.5 es el ÚNICO camino para que un usuario cree un mandato: POST /mandates
exige el formato del 3.2 (key_id + nonce + created_at + signature) firmado con SU
llave registrada, y el servidor ya no firma por nadie. El sello de sistema solo
existe para el mandato semilla que se carga al arrancar (hasta el 7.2).

Al crear (create_signed_mandate), en este orden:
    1. forma del cuerpo                                         → 422 (SignedMandateError)
    2. la llave: (owner del TOKEN, key_id) existe, es suya y está ACTIVA; si el
       cuerpo trae public_key, debe ser la registrada            → 403, sin revelar si existe
    3. el mensaje del 3.2 (mandate/mandate_message.py) desde el cuerpo, con montos
       Decimal (nunca float), owner del token y public_key del REGISTRO → 422 si la spec lo rechaza
    4. la firma Ed25519 sobre esos bytes exactos                 → 403
    5. created_at dentro de la ventana [-10 min, +2 min]          → 422
    6. nonce no usado antes por ese dueño (anti-replay)          → 409
    7. se guarda LO FIRMADO: las constraints que usa el engine salen del payload
       firmado (normalizado), no del cuerpo crudo.

En /verify (verify_signed_mandate, ambas líneas): se reconstruye el mensaje desde el
mandato GUARDADO (lo mismo que lee el engine), el owner de MANDATE_OWNERS y la
public_key de MANDATE_SIGNERS; su sha256 debe ser el message_hash del alta y la firma
debe verificar. La llave debe seguir perteneciendo al dueño. Así, alterar cualquier
campo que el engine usa después de firmar rompe la verificación.

Revocación (P-01 a, desde el 3.5): la llave debe PERTENECER al dueño y además seguir
ACTIVA. Revocarla deja sin efecto todo lo firmado con ella (check signing_key_active),
sin mutar el estado del mandato: el titular re-firma con su llave nueva.
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, Optional, Tuple

from core.owner_keys import find_key, normalize_owner_email
from core.money import MoneyError, cents_to_text
from mandate.mandate_message import (
    MandateMessageError,
    mandate_signing_message,
)
from mandate.sign import verify_ed25519_bytes

# Ventana de created_at: un reloj de cliente algo adelantado se tolera; un mandato
# firmado hace más de 10 min ya no se acepta (y su nonce puede olvidarse).
MAX_CLOCK_SKEW = timedelta(minutes=2)
MAX_AGE = timedelta(minutes=10)

KIND_HUMAN = "human"
# Solo el mandato semilla cargado al arrancar (core/mandate_store.seal_seed_mandate):
# ningún endpoint puede crearlo. Desaparece con el seed en el 7.2 (P-11).
KIND_SYSTEM_SEAL = "system_seal"

SIGNED_FORMAT_REQUIRED = ("signature", "key_id", "created_at", "nonce")
SIGNED_BODY_KEYS = frozenset({
    "mandate_id", "human", "agent", "constraints", "search_fields",
    "expires_at", "created_at", "nonce", "key_id", "signature", "public_key",
})
_AGENT_KEYS = frozenset({"id", "display_name"})

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _utcnow() -> datetime:
    """Reloj del módulo (los tests lo sustituyen: nada de esperas reales)."""
    return datetime.now(timezone.utc)


class SignedMandateError(Exception):
    """Rechazo del alta firmada, con el código HTTP que corresponde."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _unprocessable(detail: str) -> SignedMandateError:
    return SignedMandateError(422, detail)


# Mismo mensaje para "no existe", "es de otra cuenta" y "revocada": no se revela cuál.
def _key_forbidden() -> SignedMandateError:
    return SignedMandateError(403, "The signing key is not valid for this account.")


# ── Anti-replay de creación ─────────────────────────────────────────────────

class _NonceRegistry:
    """Nonces de creación usados, por dueño. Acotado: un nonce cuyo created_at ya
    salió de la ventana se olvida, porque ese mandato se rechazaría por viejo."""

    def __init__(self) -> None:
        self._seen: Dict[Tuple[str, str], datetime] = {}
        self._lock = threading.Lock()

    def claim(self, owner: str, nonce: str, created_at: datetime, now: datetime) -> bool:
        with self._lock:
            horizon = now - MAX_AGE - MAX_CLOCK_SKEW
            for key in [key for key, seen_at in self._seen.items() if seen_at < horizon]:
                del self._seen[key]
            if (owner, nonce) in self._seen:
                return False
            self._seen[(owner, nonce)] = created_at
            return True

    def release(self, owner: str, nonce: str) -> None:
        with self._lock:
            self._seen.pop((owner, nonce), None)

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


used_nonces = _NonceRegistry()


# ── Utilidades ──────────────────────────────────────────────────────────────

def issue_payment_token(mandate_id: str, digest: str) -> dict:
    """El payment_token lo emite SIEMPRE el servidor, después de verificar (o sellar),
    atado a ESTE mandato y a ESTOS bytes firmados. El cliente nunca lo aporta."""
    return {
        "token_id": f"vtok_{uuid.uuid4().hex[:12]}",
        "token_type": "SCOPED_VIRTUAL_TOKEN",
        "masked_card": "•••• 4242",
        "bank_issuer": "Galicia AI Payments",
        "bound_mandate_id": mandate_id,
        "bound_message_hash": digest,
    }


def message_hash(message: bytes) -> str:
    return hashlib.sha256(message).hexdigest()


def parse_signed_body(raw: bytes) -> Any:
    """JSON con los montos como Decimal (nunca float): lo que firmó el cliente es texto
    decimal y así se conserva hasta convertirlo a centavos."""
    return json.loads(raw, parse_float=Decimal)


def _parse_timestamp(text: str) -> datetime:
    return datetime.strptime(text, _TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)


def _active_key_of(owner: str, key_id: Any) -> dict:
    """Registro de la llave ACTIVA `key_id` de `owner`, o 403 sin decir por qué."""
    if not isinstance(key_id, str) or not key_id:
        raise _key_forbidden()
    found = find_key(key_id)
    if found is None:
        raise _key_forbidden()
    holder, record = found
    if holder != owner or record["revoked_at"] is not None:
        raise _key_forbidden()
    return record


def _stored_constraints_as_inputs(constraints: Any) -> Any:
    """Las constraints se GUARDAN como se firmaron (centavos, 5.1). Para reconstruir el
    mensaje se vuelven a la forma de entrada de la spec con texto decimal EXACTO
    (15010 → "150.10"), que la spec convierte otra vez a los mismos centavos. Algo que
    no tenga esa forma se devuelve tal cual y la spec lo rechaza (fail-closed)."""
    if not isinstance(constraints, dict):
        return constraints
    try:
        converted = {key: value for key, value in constraints.items()
                     if key not in ("max_amount_per_purchase_cents", "conditions")}
        converted["max_amount_per_purchase"] = cents_to_text(constraints["max_amount_per_purchase_cents"])
        converted["conditions"] = [
            {"type": condition["type"], "value": cents_to_text(condition["value_cents"])}
            for condition in constraints.get("conditions", [])
        ]
        return converted
    except (KeyError, TypeError, MoneyError):
        return constraints


def signing_inputs(mandate: dict, owner: Optional[str], public_key: Optional[str]) -> dict:
    """Entradas de mandate_signing_message a partir de un mandato GUARDADO."""
    agent = mandate.get("agent")
    return {
        "mandate_id": mandate.get("mandate_id"),
        "owner_email": owner,
        "key_id": mandate.get("key_id"),
        "public_key": public_key,
        "agent_id": agent.get("id") if isinstance(agent, dict) else None,
        "constraints": _stored_constraints_as_inputs(mandate.get("constraints")),
        "search_fields": mandate.get("search_fields"),
        "expires_at": mandate.get("expires_at"),
        "created_at": mandate.get("created_at"),
        "nonce": mandate.get("nonce"),
    }


# ── Alta ────────────────────────────────────────────────────────────────────

def build_signed_mandate(body: Any, owner_email: str) -> Tuple[dict, dict, str]:
    """Valida y verifica un alta firmada. Devuelve (mandato a guardar, registro de
    firmante, nonce). No guarda nada: el llamador lo hace de forma atómica."""
    if not isinstance(body, dict):
        raise _unprocessable("The mandate must be a JSON object.")
    missing = [field for field in SIGNED_FORMAT_REQUIRED if field not in body]
    if missing:
        raise _unprocessable(f"A signed mandate needs {', '.join(SIGNED_FORMAT_REQUIRED)}; missing: {', '.join(missing)}.")
    unknown = sorted(set(body) - SIGNED_BODY_KEYS)
    if unknown:
        # valid_until, scope, payment_token, human_pubkey, owner_email...: nada que no
        # esté firmado puede viajar en un mandato firmado.
        raise _unprocessable(f"Field(s) not allowed in a signed mandate: {', '.join(unknown)}.")
    agent = body.get("agent")
    if not isinstance(agent, dict) or not set(agent) <= _AGENT_KEYS or "id" not in agent:
        raise _unprocessable('agent must be {"id": ..., "display_name"?: ...}.')
    human = body.get("human", {})
    if not isinstance(human, dict):
        raise _unprocessable("human must be an object.")
    signature = body["signature"]
    if not isinstance(signature, str):
        raise _unprocessable("signature must be a hex string.")

    owner = normalize_owner_email(owner_email)
    key = _active_key_of(owner, body["key_id"])
    if "public_key" in body:
        presented = body["public_key"]
        if not isinstance(presented, str) or presented.strip().lower() != key["public_key"]:
            raise SignedMandateError(403, "The public key does not match the registered signing key.")

    try:
        message = mandate_signing_message(
            mandate_id=body.get("mandate_id"),
            owner_email=owner,
            key_id=body["key_id"],
            public_key=key["public_key"],
            agent_id=agent.get("id"),
            constraints=body.get("constraints"),
            search_fields=body.get("search_fields"),
            expires_at=body.get("expires_at"),
            created_at=body["created_at"],
            nonce=body["nonce"],
        )
    except MandateMessageError as error:
        raise _unprocessable(str(error)) from None

    if not verify_ed25519_bytes(key["public_key"], message, signature):
        raise SignedMandateError(403, "The mandate signature is not valid for this key.")

    payload = json.loads(message)  # el payload normalizado que se firmó
    now = _utcnow()
    created_at = _parse_timestamp(payload["created_at"])
    if created_at > now + MAX_CLOCK_SKEW:
        raise _unprocessable("created_at is in the future. Check the device clock and sign again.")
    if now - created_at > MAX_AGE:
        raise _unprocessable("The signed mandate is too old. Sign it again.")

    # 5.1 (P-09): se guarda LO FIRMADO, en centavos enteros: es exactamente lo que
    # compara el engine (sin conversión a dólares ni flotantes de por medio).
    constraints = dict(payload["constraints"])
    digest = message_hash(message)
    mandate_id = payload["mandate_id"]
    mandate = {
        "mandate_id": mandate_id,
        "human": human,  # contacto (PII): no autoriza nada y no se firma
        "agent": {"id": payload["agent_id"], **({"display_name": agent["display_name"]} if "display_name" in agent else {})},
        "constraints": constraints,
        "search_fields": payload["search_fields"],
        "expires_at": payload["expires_at"],
        "created_at": payload["created_at"],
        "nonce": payload["nonce"],
        "key_id": payload["key_id"],
        "signature": signature.lower(),
        # Lo emite el servidor DESPUÉS de verificar, atado a los bytes firmados.
        "payment_token": issue_payment_token(mandate_id, digest),
    }
    # Defensa en profundidad: lo guardado reconstruye EXACTAMENTE lo firmado.
    if mandate_signing_message(**signing_inputs(mandate, owner, key["public_key"])) != message:
        raise _unprocessable("The mandate cannot be stored exactly as signed.")

    signer = {
        "kind": KIND_HUMAN,
        "key_id": payload["key_id"],
        "public_key": key["public_key"],
        "message_hash": digest,
        "signed_at": payload["created_at"],
    }
    return mandate, signer, payload["nonce"]


# ── Verificación (ambas líneas de /verify) ──────────────────────────────────

def verify_signed_mandate(mandate: dict, owner: Optional[str], signer: dict) -> Tuple[bool, str]:
    """¿El mandato guardado sigue siendo exactamente lo que firmó su dueño con una
    llave suya? (ok, detalle legible). Fail-closed ante cualquier dato raro."""
    if not owner or signer.get("kind") != KIND_HUMAN:
        return False, "Firma humana inválida: falta el dueño o el registro del firmante."
    if mandate.get("key_id") != signer.get("key_id"):
        return False, "Firma humana inválida: la llave del mandato no es la registrada al firmar."
    found = find_key(signer.get("key_id") or "")
    if found is None or found[0] != owner or found[1]["public_key"] != signer.get("public_key"):
        return False, "Firma humana inválida: la llave ya no pertenece al titular."
    try:
        message = mandate_signing_message(**signing_inputs(mandate, owner, signer["public_key"]))
    except (MandateMessageError, KeyError, TypeError, AttributeError):
        return False, "Firma humana inválida: el mandato guardado no cumple la especificación firmada."
    if message_hash(message) != signer.get("message_hash"):
        return False, "Firma humana inválida: el mandato cambió después de firmarse."
    if not verify_ed25519_bytes(signer["public_key"], message, mandate.get("signature")):
        return False, "Firma humana inválida: la firma no verifica con la llave registrada."
    return True, "Firma humana Ed25519 válida (llave registrada del titular)."


def verify_signing_key_active(signer: dict) -> Tuple[bool, str]:
    """P-01 (a): una llave revocada deja sin efecto lo que firmó (el titular re-firma)."""
    found = find_key(signer.get("key_id") or "")
    if found is None or found[1]["revoked_at"] is not None:
        return False, "La llave que firmó este mandato fue revocada: el titular debe firmarlo de nuevo."
    return True, "La llave que firmó el mandato sigue activa."


def verify_payment_token_binding(mandate: dict, signer: dict) -> Tuple[bool, str]:
    """El payment_token debe estar atado a ESTE mandato y a ESTOS bytes firmados."""
    token = mandate.get("payment_token")
    if not isinstance(token, dict):
        return False, "El mandato no tiene un token de pago emitido por el servidor."
    if token.get("bound_mandate_id") != mandate.get("mandate_id") or token.get("bound_message_hash") != signer.get("message_hash"):
        return False, "El token de pago no está atado a este mandato firmado."
    return True, "Token de pago atado al mandato firmado."


def missing_signature_detail(body: Any) -> Optional[str]:
    """Si `body` no trae el formato firmado completo, el motivo (422); si lo trae, None."""
    if not isinstance(body, dict):
        return "The mandate must be a JSON object."
    missing = [field for field in SIGNED_FORMAT_REQUIRED if field not in body]
    if missing:
        return (
            "A cardholder signature is required: sign the mandate with your registered device key "
            f"(missing: {', '.join(missing)})."
        )
    return None
