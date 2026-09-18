"""Firma de mandatos: Ed25519 sobre JSON canónico.

Un solo algoritmo por función, sin adivinar ni degradar:
- sign_payload(private_key_hex, payload): SOLO Ed25519. Una llave malformada es
  un SignatureError, nunca una firma de otro tipo.
- verify_signature(...): fail-closed. True SOLO si la firma Ed25519 verifica
  contra esa llave pública y ese payload; cualquier otra cosa es False.
- sign_hmac_token(payload, secret_key): el token HS256 del flujo legado de consola
  (aegis_core.py → core.verify.evaluar_intento_compra). Explícito y sin secreto
  por defecto: se pide por su nombre, no se cae en él por accidente.

Antes sign_payload decidía el algoritmo por el tipo y el largo de la llave: si no
medía 64 hex, o si Ed25519 fallaba, devolvía EN SILENCIO un JWT HMAC firmado con
un secreto de desarrollo. Eso ya no ocurre.
"""
import base64
import hashlib
import hmac
import json
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ED25519_KEY_HEX_LENGTH = 64  # 32 bytes en hex (llave privada o pública)


class SignatureError(ValueError):
    """No se puede firmar con lo recibido (llave o payload inválidos)."""


def encode_b64url(data: bytes) -> str:
    """Codifica en formato seguro para URLs (estándar JWT/JWS)."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


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


def sign_hmac_token(payload: Dict[str, Any], secret_key: bytes) -> str:
    """Token JWT HS256 del flujo legado de consola (aegis_core.py).

    Es un mecanismo DISTINTO de la firma de mandatos (simétrico: quien verifica
    puede firmar, así que no da no-repudio). Exige un secreto explícito."""
    if not isinstance(payload, dict):
        raise SignatureError("El payload del token debe ser un dict.")
    if not isinstance(secret_key, bytes) or not secret_key:
        raise SignatureError("El token HMAC exige un secreto explícito en bytes (no hay valor por defecto).")
    header = encode_b64url(b'{"alg":"HS256","typ":"JWT"}')
    body = encode_b64url(json.dumps(payload, sort_keys=True).encode('utf-8'))
    message = f"{header}.{body}".encode('utf-8')
    signature = encode_b64url(hmac.new(secret_key, message, hashlib.sha256).digest())
    return f"{header}.{body}.{signature}"


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


def verify_signature(public_key_hex: Any, payload_dict: Any, signature_hex: Any) -> bool:
    """Verifica una firma Ed25519 sobre el JSON canónico de `payload_dict`. FAIL-CLOSED.

    True SOLO si la firma es válida para esa llave pública y ese payload. Llave o
    firma ausentes, de otro tipo, no hex, de largo incorrecto, o un payload no
    serializable → False. Solo se capturan los errores esperables de datos
    inválidos: un error inesperado se propaga (nunca se convierte en aprobación)."""
    if not isinstance(public_key_hex, str) or not isinstance(signature_hex, str):
        return False
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), canonical_json(payload_dict))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
