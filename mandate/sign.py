"""Primitivas Ed25519 del servidor (7.3).

- canonical_json: JSON canónico (claves ordenadas, sin espacios) del ledger.
- generate_keypair: llaves del AGENTE (core/agent_keys.py).
- verify_ed25519_bytes: verificación fail-closed de firmas hechas FUERA del servidor
  (llaves de dispositivo, intentos del agente, challenges).

7.3: sign_payload y verify_signature (firma sobre el JSON de un payload) se retiraron
del producto: solo los usaban la línea estricta y el seed. Los tests que fabrican una
firma "legada" para probar que el sistema NO la acepta usan tests/legacy_signing.py.
"""
import json
from typing import Any, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ED25519_KEY_HEX_LENGTH = 64  # 32 bytes en hex (llave privada o pública)


def canonical_json(data: Any) -> bytes:
    """Serializes data to canonical JSON (sorted keys, no whitespace) for signature stability."""
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')


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
