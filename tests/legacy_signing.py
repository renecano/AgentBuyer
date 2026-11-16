"""Firma "legada" para tests de ataque (7.3).

El producto ya no firma ni verifica payloads JSON con una llave suelta (eso era la
línea estricta y el seed). Algunos tests necesitan FABRICAR una firma así —válida con
su propia llave— para probar que el sistema no la acepta como firma del titular.
"""
from cryptography.hazmat.primitives.asymmetric import ed25519

from mandate.sign import canonical_json, generate_keypair

__all__ = ["generate_keypair", "sign_payload"]


def sign_payload(private_key_hex: str, payload: dict) -> str:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return key.sign(canonical_json(payload)).hex()
