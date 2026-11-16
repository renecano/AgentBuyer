"""mandate/sign.py: verificación Ed25519 fail-closed de firmas hechas fuera del servidor.

(7.3: los tests de sign_payload/verify_signature se retiraron con esas funciones,
que el producto ya no usaba.)"""

import pytest

from mandate.sign import generate_keypair, verify_ed25519_bytes

# ── verify_ed25519_bytes: la primitiva para firmas hechas fuera del servidor ──

def test_bytes_verification_roundtrip_and_tamper():
    private_key, public_key = generate_keypair()
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed

    signer = _ed.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
    message = '{"owner":"josé@ejemplo.com"}'.encode("utf-8")
    signature = signer.sign(message).hex()

    assert verify_ed25519_bytes(public_key, message, signature) is True
    assert verify_ed25519_bytes(public_key, message + b" ", signature) is False
    assert verify_ed25519_bytes(public_key, bytearray(message), signature) is True


def test_bytes_verification_accepts_the_rfc8032_shared_vector():
    """Ata el contrato del 2.3 (shared/key_registration_vectors.json) con la
    verificación que usa POST /keys."""
    import json
    import pathlib

    vectors = json.loads((pathlib.Path(__file__).resolve().parent.parent / "shared"
                          / "key_registration_vectors.json").read_text(encoding="utf-8"))
    public_key = vectors["rfc8032_test1"]["public_key_hex"]
    for vector in vectors["vectors"]:
        message = bytes.fromhex(vector["expected_message_utf8_hex"])
        assert verify_ed25519_bytes(public_key, message, vector["expected_signature_hex"]) is True


@pytest.mark.parametrize(
    "public_key, message, signature",
    [
        (None, b"m", "ab" * 64),
        ("ab" * 32, "texto, no bytes", "ab" * 64),
        ("ab" * 32, b"m", None),
        ("zz" * 32, b"m", "ab" * 64),
        ("ab" * 32, b"m", "ab" * 10),
        ("ab" * 32, b"m", "ab" * 64),
    ],
    ids=["no-pubkey", "message-str", "no-signature", "pubkey-no-hex", "signature-short", "garbage"],
)
def test_bytes_verification_fails_closed(public_key, message, signature):
    assert verify_ed25519_bytes(public_key, message, signature) is False
