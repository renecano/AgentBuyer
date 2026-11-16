"""Firma de mandatos: Ed25519 sobre JSON canónico.

Un solo algoritmo por función, sin adivinar ni degradar:
- sign_payload(private_key_hex, payload): SOLO Ed25519. Una llave malformada es
  un SignatureError, nunca una firma de otro tipo.
- verify_signature(...): fail-closed. True SOLO si la firma Ed25519 verifica
  contra esa llave pública y ese payload; cualquier otra cosa es False.
(7.2: el token HMAC del flujo de consola, sign_hmac_token, se retiró con aegis_core.py.)

Antes sign_payload decidía el algoritmo por el tipo y el largo de la llave: si no
medía 64 hex, o si Ed25519 fallaba, devolvía EN SILENCIO un JWT HMAC firmado con
un secreto de desarrollo. Eso ya no ocurre.
"""
import json
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ED25519_KEY_HEX_LENGTH = 64  # 32 bytes en hex (llave privada o pública)


class SignatureError(ValueError):
    """No se puede firmar con lo recibido (llave o payload inválidos)."""


def canonical_json(data: Any) -> bytes:
    """Serializes data to canonical JSON (sorted keys, no whitespace) for signature stability."""
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _ed25519_private_key(private_key_hex: Any) -> ed25519.Ed25519PrivateKey:
    if not isinstance(private_key_hex, str) or len(private_key_hex) != ED25519_KEY_HEX_LENGTH:
        raise SignatureError(
            f"La llave privada Ed25519 debe ser un texto de {ED25519_KEY_HEX_LENGTH} caracteres hex."
        )
    try:
        raw = bytes.fromhex(private_key_hex)
    except ValueError:
        raise SignatureError("La llave privada Ed25519 no es hexadecimal válido.") from None
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def sign_payload(private_key_hex: str, payload: Dict[str, Any]) -> str:
    """Firma `payload` (JSON canónico) con Ed25519 y devuelve la firma en hex (128 chars).

    Lanza SignatureError si la llave no es una privada Ed25519 en hex o si el
    payload no es un dict serializable. No hay algoritmo de respaldo."""
    if not isinstance(payload, dict):
        raise SignatureError("El payload a firmar debe ser un dict.")
    key = _ed25519_private_key(private_key_hex)
    try:
        message = canonical_json(payload)
    except (TypeError, ValueError) as error:
        raise SignatureError(f"El payload no es serializable a JSON canónico: {error}") from None
    return key.sign(message).hex()


def generate_keypair() -> Tuple[str, str]:
    """Generates an Ed25519 asymmetric signing keypair returning (private_key_hex, public_key_hex)."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes.hex(), pub_bytes.hex()


def verify_ed25519_bytes(public_key_hex: Any, message: Any, signature_hex: Any) -> bool:
    """Verifica una firma Ed25519 sobre BYTES exactos. FAIL-CLOSED.

    Es la primitiva para firmas hechas fuera del servidor (navegador): el llamador
    reconstruye los bytes canónicos que el cliente firmó (mandate/canonical.py) y
    se verifica sobre ellos, sin re-serializar nada aquí.

    True SOLO si la firma es válida para esa llave pública y esos bytes. Llave o
    firma ausentes, de otro tipo, no hex o de largo incorrecto, o un mensaje que no
    son bytes → False. Solo se capturan los errores esperables de datos inválidos:
    un error inesperado se propaga (nunca se convierte en aprobación)."""
    if not isinstance(public_key_hex, str) or not isinstance(signature_hex, str):
        return False
    if not isinstance(message, (bytes, bytearray)):
        return False
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), bytes(message))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def verify_signature(public_key_hex: Any, payload_dict: Any, signature_hex: Any) -> bool:
    """Verifica una firma Ed25519 sobre el JSON canónico (legado) de `payload_dict`. FAIL-CLOSED.

    Es la firma que produce el SERVIDOR (sign_payload). Un payload no serializable
    → False. La verificación en sí es verify_ed25519_bytes."""
    try:
        message = canonical_json(payload_dict)
    except (TypeError, ValueError):
        return False
    return verify_ed25519_bytes(public_key_hex, message, signature_hex)
