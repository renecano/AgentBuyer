"""Access tokens JWT (core/auth_tokens.py) y la dependencia que los exige
(api/security.py). La dependencia se prueba sobre una app mínima: todavía no
protege ningún endpoint real."""
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import core.auth_tokens as auth_tokens
from api.security import Principal, require_principal
from core.auth_tokens import ISSUER, InvalidAccessToken, create_access_token, decode_access_token

SECRET = "unit-test-jwt-secret-64-bytes-long-so-hs512-forgeries-do-not-warn!"
EMAIL = "test.user@example.com"


@pytest.fixture(autouse=True)
def jwt_env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.delenv("JWT_TTL_SECONDS", raising=False)


protected_app = FastAPI()


@protected_app.get("/whoami")
def whoami(principal: Principal = Depends(require_principal)):
    return {"subject": principal.subject, "role": principal.role}


@pytest.fixture()
def client():
    return TestClient(protected_app)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def valid_claims(**overrides) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    claims = {"iss": ISSUER, "sub": EMAIL, "role": "user", "iat": now, "exp": now + timedelta(hours=1)}
    claims.update(overrides)
    return {key: value for key, value in claims.items() if value is not None}


# ── Creación ────────────────────────────────────────────────────────────────

def test_token_has_expected_claims():
    before = int(time.time())
    claims = jwt.decode(create_access_token(EMAIL), SECRET, algorithms=["HS256"], issuer=ISSUER)

    assert claims["sub"] == EMAIL
    assert claims["role"] == "user"
    assert claims["iss"] == ISSUER
    assert before - 1 <= claims["iat"] <= int(time.time())
    assert claims["exp"] - claims["iat"] == 3600
    assert claims["exp"] > time.time()
    assert isinstance(claims["jti"], str) and len(claims["jti"]) == 32


def test_ttl_is_configurable(monkeypatch):
    monkeypatch.setenv("JWT_TTL_SECONDS", "120")
    claims = decode_access_token(create_access_token(EMAIL))
    assert claims["exp"] - claims["iat"] == 120


@pytest.mark.parametrize("value", ["abc", "0", "-5"])
def test_invalid_ttl_env_is_rejected(monkeypatch, value):
    monkeypatch.setenv("JWT_TTL_SECONDS", value)
    with pytest.raises(ValueError):
        create_access_token(EMAIL)


def test_short_jwt_secret_is_rejected(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 31)
    with pytest.raises(ValueError):
        create_access_token(EMAIL)
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    assert decode_access_token(create_access_token(EMAIL))["sub"] == EMAIL


def test_create_rejects_unknown_role_and_empty_subject():
    with pytest.raises(ValueError):
        create_access_token(EMAIL, role="admin")
    with pytest.raises(ValueError):
        create_access_token("")


def test_each_token_has_a_unique_jti():
    first = decode_access_token(create_access_token(EMAIL))
    second = decode_access_token(create_access_token(EMAIL))
    assert first["jti"] != second["jti"]


# ── Dependencia require_principal ───────────────────────────────────────────

def test_dependency_accepts_valid_token(client):
    response = client.get("/whoami", headers=bearer(create_access_token(EMAIL)))
    assert response.status_code == 200
    assert response.json() == {"subject": EMAIL, "role": "user"}


def test_dependency_rejects_missing_header(client):
    response = client.get("/whoami")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_dependency_rejects_non_bearer_scheme(client):
    token = create_access_token(EMAIL)
    response = client.get("/whoami", headers={"Authorization": f"Basic {token}"})
    assert response.status_code == 401


INVALID_TOKENS = {
    # Firma y formato
    "garbage": lambda: "not-a-jwt",
    "wrong-signature": lambda: jwt.encode(valid_claims(), "some-other-secret-0123456789-abcdefghijk", algorithm="HS256"),
    "tampered-payload": lambda: _tamper_subject(create_access_token(EMAIL), "attacker@example.com"),
    "alg-none": lambda: jwt.encode(valid_claims(), None, algorithm="none"),
    "other-hmac-alg": lambda: jwt.encode(valid_claims(), SECRET, algorithm="HS512"),
    # Expiración (exp en el pasado, sin esperas reales)
    "expired": lambda: create_access_token(EMAIL, now=datetime.now(timezone.utc) - timedelta(hours=2)),
    "expired-one-second-ago": lambda: create_access_token(
        EMAIL, ttl_seconds=60, now=datetime.now(timezone.utc) - timedelta(seconds=61)
    ),
    # Claims
    "wrong-issuer": lambda: jwt.encode(valid_claims(iss="someone-else"), SECRET, algorithm="HS256"),
    "missing-exp": lambda: jwt.encode(valid_claims(exp=None), SECRET, algorithm="HS256"),
    "missing-sub": lambda: jwt.encode(valid_claims(sub=None), SECRET, algorithm="HS256"),
    "missing-role": lambda: jwt.encode(valid_claims(role=None), SECRET, algorithm="HS256"),
    "unknown-role": lambda: jwt.encode(valid_claims(role="admin"), SECRET, algorithm="HS256"),
}


def _tamper_subject(token: str, new_subject: str) -> str:
    """Cambia el payload conservando la firma original."""
    header, _, signature = token.split(".")
    forged_payload = jwt.utils.base64url_encode(
        jwt.api_jws.json.dumps({**jwt.decode(token, options={"verify_signature": False}), "sub": new_subject}).encode()
    ).decode()
    return f"{header}.{forged_payload}.{signature}"


@pytest.mark.parametrize("make_token", INVALID_TOKENS.values(), ids=INVALID_TOKENS.keys())
def test_dependency_rejects_invalid_token_with_401(client, make_token):
    response = client.get("/whoami", headers=bearer(make_token()))

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token."  # sin revelar la causa
    assert response.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'


@pytest.mark.parametrize("make_token", INVALID_TOKENS.values(), ids=INVALID_TOKENS.keys())
def test_decode_raises_for_invalid_token(make_token):
    with pytest.raises(InvalidAccessToken):
        decode_access_token(make_token())


# ── Clave de desarrollo ─────────────────────────────────────────────────────

def test_dev_secret_warns_and_its_tokens_fail_once_real_secret_is_set(monkeypatch, caplog):
    monkeypatch.delenv("JWT_SECRET")
    monkeypatch.setenv("AUTH_DEV_MODE", "true")  # único caso en que se permite la clave de dev
    monkeypatch.setattr(auth_tokens, "_dev_secret_warned", False)

    with caplog.at_level("WARNING", logger="core.auth_tokens"):
        dev_token = create_access_token(EMAIL)
    assert "JWT_SECRET" in caplog.text
    assert decode_access_token(dev_token)["sub"] == EMAIL

    monkeypatch.setenv("JWT_SECRET", SECRET)
    with pytest.raises(InvalidAccessToken):
        decode_access_token(dev_token)
