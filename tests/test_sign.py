"""mandate/sign.py: un algoritmo por función, sin degradación silenciosa.

Antes, sign_payload con una llave que no medía 64 hex (o si Ed25519 fallaba)
devolvía EN SILENCIO un JWT HMAC firmado con un secreto de desarrollo. Ahora es
un SignatureError explícito, y verify_signature es fail-closed."""
import base64
import hashlib
import hmac

import pytest

from mandate.sign import (
    SignatureError,
    generate_keypair,
    sign_hmac_token,
    sign_payload,
    verify_ed25519_bytes,
    verify_signature,
)

PAYLOAD = {"max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"]}


@pytest.fixture()
def keys() -> tuple[str, str]:
    return generate_keypair()


# ── sign_payload: SOLO Ed25519 ──────────────────────────────────────────────

def test_sign_and_verify_roundtrip(keys):
    priv, pub = keys
    signature = sign_payload(priv, PAYLOAD)

    assert len(signature) == 128 and int(signature, 16) >= 0  # 64 bytes en hex
    assert verify_signature(pub, PAYLOAD, signature) is True


@pytest.mark.parametrize(
    "bad_key",
    ["short-key", "zz" * 32, "ab" * 33, b"\x00" * 32, None, 12345],
    ids=["short", "64-non-hex", "too-long", "bytes", "none", "int"],
)
def test_malformed_private_key_is_an_explicit_error_not_a_jwt(bad_key):
    with pytest.raises(SignatureError):
        sign_payload(bad_key, PAYLOAD)


def test_swapped_arguments_are_an_error_not_a_guess(keys):
    """Antes aceptaba (payload, llave) o (llave, payload) adivinando por tipo."""
    priv, _ = keys
    with pytest.raises(SignatureError):
        sign_payload(PAYLOAD, priv)  # type: ignore[arg-type]


def test_non_serializable_payload_is_an_error(keys):
    priv, _ = keys
    with pytest.raises(SignatureError):
        sign_payload(priv, {"when": object()})


def test_signature_never_looks_like_a_jwt(keys):
    priv, _ = keys
    assert "." not in sign_payload(priv, PAYLOAD)


# ── verify_signature: fail-closed ───────────────────────────────────────────

def test_tampered_payload_does_not_verify(keys):
    priv, pub = keys
    signature = sign_payload(priv, PAYLOAD)

    assert verify_signature(pub, {**PAYLOAD, "max_amount_per_purchase": 99999}, signature) is False


def test_signature_from_another_key_does_not_verify(keys):
    _, pub = keys
    other_priv, _ = generate_keypair()

    assert verify_signature(pub, PAYLOAD, sign_payload(other_priv, PAYLOAD)) is False


@pytest.mark.parametrize(
    "pubkey, signature",
    [
        (None, "ab" * 64),
        ("ab" * 32, None),
        ("", ""),
        ("zz" * 32, "ab" * 64),
        ("ab" * 10, "ab" * 64),
        ("ab" * 32, "x"),
        ("ab" * 32, "ab" * 64),
        (123, 456),
    ],
    ids=["no-pubkey", "no-signature", "empty", "pubkey-non-hex", "pubkey-short",
         "signature-short", "garbage", "non-strings"],
)
def test_malformed_inputs_never_verify(pubkey, signature):
    assert verify_signature(pubkey, PAYLOAD, signature) is False


def test_non_serializable_payload_never_verifies(keys):
    _, pub = keys
    assert verify_signature(pub, {"when": object()}, "ab" * 64) is False


# ── sign_hmac_token: explícito, sin secreto por defecto ─────────────────────

def test_hmac_token_is_a_valid_hs256_jwt_with_an_explicit_secret():
    secret = b"explicit-test-secret"
    token = sign_hmac_token({"mandate_id": "m1"}, secret)

    header, body, signature = token.split(".")
    expected = base64.urlsafe_b64encode(
        hmac.new(secret, f"{header}.{body}".encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    assert signature == expected


@pytest.mark.parametrize("secret", [b"", "a-string-secret", None], ids=["empty", "str", "none"])
def test_hmac_token_requires_an_explicit_bytes_secret(secret):
    with pytest.raises(SignatureError):
        sign_hmac_token({"mandate_id": "m1"}, secret)


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
