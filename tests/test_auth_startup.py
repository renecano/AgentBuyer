"""La clave de firma de desarrollo es inutilizable fuera de AUTH_DEV_MODE=true,
por construcción: la app no arranca y no se emite ni valida ningún token."""
import jwt
import pytest
from fastapi.testclient import TestClient

import api.auth as auth_api
import core.auth_tokens as auth_tokens
from api.main import app
from core.auth_tokens import (
    ISSUER,
    TokenConfigError,
    create_access_token,
    decode_access_token,
    validate_token_config,
)
from core.email_otp import EmailOtpService

EMAIL = "test.user@example.com"
NOT_DEV_MODE = [None, "", "false", "0", "1", "yes", "on"]


def set_dev_mode(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("AUTH_DEV_MODE", raising=False)
    else:
        monkeypatch.setenv("AUTH_DEV_MODE", value)


# ── Producción: sin JWT_SECRET válido la app no arranca ─────────────────────

@pytest.mark.parametrize("dev_mode", NOT_DEV_MODE)
def test_app_refuses_to_start_without_secret_outside_dev_mode(monkeypatch, caplog, dev_mode):
    monkeypatch.delenv("JWT_SECRET")
    set_dev_mode(monkeypatch, dev_mode)

    with caplog.at_level("CRITICAL", logger="agentbuyer.startup"):
        with pytest.raises(TokenConfigError):
            with TestClient(app):
                pass

    message = caplog.text
    assert "no puede arrancar" in message
    assert "JWT_SECRET" in message and "AUTH_DEV_MODE" in message  # explica qué configurar


@pytest.mark.parametrize("dev_mode", [None, "true"])
def test_app_refuses_to_start_with_short_secret_even_in_dev_mode(monkeypatch, dev_mode):
    """Una clave explícita inválida nunca cae a la de desarrollo."""
    monkeypatch.setenv("JWT_SECRET", "x" * 31)
    set_dev_mode(monkeypatch, dev_mode)

    with pytest.raises(TokenConfigError, match="32"):
        with TestClient(app):
            pass


def test_app_refuses_to_start_with_invalid_ttl(monkeypatch):
    monkeypatch.setenv("JWT_TTL_SECONDS", "0")
    with pytest.raises(TokenConfigError, match="JWT_TTL_SECONDS"):
        with TestClient(app):
            pass


def test_token_creation_and_validation_rejected_without_secret_outside_dev_mode(monkeypatch):
    """Defensa en profundidad: aunque algo eludiera el arranque, no hay tokens."""
    dev_signed = jwt.encode(
        {"iss": ISSUER, "sub": EMAIL, "role": "user", "iat": 1_900_000_000, "exp": 1_900_003_600},
        auth_tokens._DEV_ONLY_SECRET,
        algorithm="HS256",
    )
    monkeypatch.delenv("JWT_SECRET")

    with pytest.raises(TokenConfigError):
        validate_token_config()
    with pytest.raises(TokenConfigError):
        create_access_token(EMAIL)
    with pytest.raises(TokenConfigError):
        decode_access_token(dev_signed)  # un token forjado con la clave pública no se acepta


def test_app_starts_with_valid_secret():
    # auth_config (conftest) ya define un JWT_SECRET válido y AUTH_DEV_MODE apagado.
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200


# ── Desarrollo: AUTH_DEV_MODE=true sin JWT_SECRET usa la clave de dev ───────

def test_dev_mode_without_secret_starts_and_issues_dev_signed_tokens(monkeypatch, caplog):
    monkeypatch.delenv("JWT_SECRET")
    monkeypatch.setenv("AUTH_DEV_MODE", "true")
    monkeypatch.setattr(auth_tokens, "_dev_secret_warned", False)
    monkeypatch.setattr(auth_api, "otp_service", EmailOtpService())
    monkeypatch.setattr(auth_api, "send_verification_email", lambda email, code, ttl_seconds: False)

    with caplog.at_level("WARNING", logger="core.auth_tokens"):
        with TestClient(app) as client:
            code = client.post("/auth/email/start", json={"email": EMAIL}).json()["code_demo"]
            body = client.post("/auth/email/check", json={"email": EMAIL, "code": code}).json()

    claims = jwt.decode(body["access_token"], auth_tokens._DEV_ONLY_SECRET, algorithms=["HS256"], issuer=ISSUER)
    assert claims["sub"] == EMAIL and claims["role"] == "user"
    assert decode_access_token(body["access_token"])["sub"] == EMAIL
    assert "DESARROLLO" in caplog.text  # la advertencia existente se sigue emitiendo


def test_dev_mode_prefers_explicit_secret_over_dev_key(monkeypatch):
    explicit = "explicit-secret-even-in-dev-mode-0123456789abcdef"
    monkeypatch.setenv("JWT_SECRET", explicit)
    monkeypatch.setenv("AUTH_DEV_MODE", "true")

    token = create_access_token(EMAIL)

    assert jwt.decode(token, explicit, algorithms=["HS256"], issuer=ISSUER)["sub"] == EMAIL
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, auth_tokens._DEV_ONLY_SECRET, algorithms=["HS256"], issuer=ISSUER)
