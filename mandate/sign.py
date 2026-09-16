import hmac
import hashlib
import base64
import json
from typing import Tuple, Union, Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def encode_b64url(data: bytes) -> str:
    """Codifica en formato seguro para URLs (estándar JWT/JWS)."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def sign_payload(arg1: Any, arg2: Any = b"aegis_zero_trust_enterprise_2026") -> str:
    """Sella criptográficamente el mandato para evitar manipulación (Tamper-proofing)."""
    if isinstance(arg1, dict):
        payload_dict = arg1
        secret_key = arg2
    else:
        payload_dict = arg2 if isinstance(arg2, dict) else {}
        secret_key = arg1

    if isinstance(secret_key, str):
        # Si es una clave privada Ed25519 en hex (64 chars)
        if len(secret_key) == 64:
            try:
                priv_bytes = bytes.fromhex(secret_key)
                priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
                canonical_bytes = canonical_json(payload_dict)
                sig_bytes = priv_key.sign(canonical_bytes)
                return sig_bytes.hex()
            except Exception:
                pass
        key_bytes = secret_key.encode('utf-8')
    elif isinstance(secret_key, bytes):
        key_bytes = secret_key
    else:
        key_bytes = b"aegis_zero_trust_enterprise_2026"

    header = encode_b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload = encode_b64url(json.dumps(payload_dict, sort_keys=True).encode('utf-8'))
    message = f"{header}.{payload}".encode('utf-8')
    signature = encode_b64url(hmac.new(key_bytes, message, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


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


def canonical_json(data: Any) -> bytes:
    """Serializes data to canonical JSON (sorted keys, no whitespace) for signature stability."""
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')


def verify_signature(public_key_hex: str, payload_dict: Dict[str, Any], signature_hex: str) -> bool:
    """Verifies an Ed25519 digital signature over canonical payload JSON."""
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        canonical_bytes = canonical_json(payload_dict)
        public_key.verify(sig_bytes, canonical_bytes)
        return True
    except Exception:
        return False
