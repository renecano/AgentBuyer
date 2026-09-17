"""OTP de email endurecido (api/auth.py + core/email_otp.py): TTL, uso único,
límite de intentos, rate limit por destino y el código jamás expuesto fuera del
cuerpo del correo (salvo AUTH_DEV_MODE=true)."""
import email as email_lib
import time

import jwt
import pytest
from fastapi.testclient import TestClient

import api.auth as auth_api
import core.notifications as notifications
from api.main import app
from core.auth_tokens import ISSUER, decode_access_token
from core.email_otp import EmailOtpService

EMAIL = "test.user@example.com"
TTL, MAX_ATTEMPTS, COOLDOWN, MAX_SENDS, WINDOW = 600, 5, 60, 5, 3600


class FakeClock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def clock():
    return FakeClock()


@pytest.fixture()
def otp(monkeypatch, clock):
    monkeypatch.delenv("AUTH_DEV_MODE", raising=False)
    service = EmailOtpService(
        ttl_seconds=TTL, max_attempts=MAX_ATTEMPTS, resend_cooldown_seconds=COOLDOWN,
        max_sends_per_window=MAX_SENDS, send_window_seconds=WINDOW, clock=clock,
    )
    monkeypatch.setattr(auth_api, "otp_service", service)
    return service


@pytest.fixture()
def outbox(monkeypatch):
    """Sustituye el envío real: guarda el código que 'llegó' al correo."""
    sent = []

    def fake_send(email, code, ttl_seconds):
        sent.append({"email": email, "code": code})
        return True

    monkeypatch.setattr(auth_api, "send_verification_email", fake_send)
    return sent


@pytest.fixture()
def client(otp):
    with TestClient(app) as test_client:
        yield test_client


def start(client, address=EMAIL):
    return client.post("/auth/email/start", json={"email": address})


def check(client, code, address=EMAIL):
    return client.post("/auth/email/check", json={"email": address, "code": code})


def wrong(code: str) -> str:
    return f"{(int(code) + 1) % 1_000_000:06d}"


# ── code_demo solo con AUTH_DEV_MODE=true ───────────────────────────────────

@pytest.mark.parametrize("flag", [None, "", "false", "1", "yes", "on"])
def test_start_never_returns_code_without_dev_flag(client, outbox, monkeypatch, flag):
    if flag is not None:
        monkeypatch.setenv("AUTH_DEV_MODE", flag)

    response = start(client)

    assert response.status_code == 200
    assert "code_demo" not in response.json()
    assert outbox[-1]["code"] not in response.text


def test_code_never_returned_when_delivery_fails(client, monkeypatch):
    issued = []

    def failing_send(email, code, ttl_seconds):
        issued.append(code)
        return False

    monkeypatch.setattr(auth_api, "send_verification_email", failing_send)

    response = start(client)

    assert response.status_code == 503
    assert issued[0] not in response.text
    # Fail-closed: el código que nadie recibió quedó invalidado.
    assert check(client, issued[0]).status_code == 401


def test_dev_mode_returns_code_even_without_smtp(client, monkeypatch):
    monkeypatch.setenv("AUTH_DEV_MODE", "true")
    monkeypatch.setattr(auth_api, "send_verification_email", lambda email, code, ttl_seconds: False)

    body = start(client).json()

    assert body["sent_via"] == "dev"
    assert check(client, body["code_demo"]).status_code == 200


# ── Uso único y TTL ─────────────────────────────────────────────────────────

def test_valid_code_is_single_use(client, outbox):
    start(client)
    code = outbox[-1]["code"]

    first = check(client, code)
    second = check(client, code)

    assert first.status_code == 200 and first.json()["verified"] is True
    assert second.status_code == 401


def test_code_is_valid_until_ttl(client, outbox, clock):
    start(client)
    clock.advance(TTL - 1)
    assert check(client, outbox[-1]["code"]).status_code == 200


def test_expired_code_is_rejected(client, outbox, clock):
    start(client)
    clock.advance(TTL)

    response = check(client, outbox[-1]["code"])

    assert response.status_code == 401
    assert outbox[-1]["code"] not in response.text


# ── Límite de intentos ──────────────────────────────────────────────────────

def test_failed_attempts_limit_invalidates_code(client, outbox):
    start(client)
    code = outbox[-1]["code"]

    for _ in range(MAX_ATTEMPTS - 1):
        response = check(client, wrong(code))
        assert response.status_code == 401
        assert code not in response.text

    locked = check(client, wrong(code))
    assert locked.status_code == 429
    assert code not in locked.text

    # El código correcto ya no sirve: hay que pedir uno nuevo.
    assert check(client, code).status_code == 401


# ── Rate limit por destino ──────────────────────────────────────────────────

def test_resend_cooldown(client, outbox, clock):
    assert start(client).status_code == 200

    too_soon = start(client)
    assert too_soon.status_code == 429
    assert too_soon.headers["Retry-After"] == str(COOLDOWN)
    assert len(outbox) == 1  # no se envió un segundo correo

    clock.advance(COOLDOWN - 1)
    assert start(client).headers["Retry-After"] == "1"

    clock.advance(1)
    assert start(client).status_code == 200
    assert len(outbox) == 2


def test_hourly_send_limit(client, outbox, clock):
    for _ in range(MAX_SENDS):
        assert start(client).status_code == 200
        clock.advance(COOLDOWN)

    elapsed = COOLDOWN * MAX_SENDS
    blocked = start(client)
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == str(WINDOW - elapsed)
    assert len(outbox) == MAX_SENDS

    clock.advance(WINDOW - elapsed)  # el primer envío sale de la ventana
    assert start(client).status_code == 200


def test_rate_limit_is_per_email(client, outbox):
    assert start(client).status_code == 200
    assert start(client).status_code == 429
    assert start(client, "someone.else@example.com").status_code == 200


def test_new_code_replaces_previous_one(client, outbox, clock):
    start(client)
    old_code = outbox[-1]["code"]
    clock.advance(COOLDOWN)
    start(client)
    new_code = outbox[-1]["code"]

    if old_code != new_code:
        assert check(client, old_code).status_code == 401
    assert check(client, new_code).status_code == 200


# ── Validación y superficie retirada ────────────────────────────────────────

def test_invalid_email_is_rejected(client, outbox):
    assert start(client, "not-an-email").status_code == 422
    assert start(client, "a@b.com\r\nBcc: victim@example.com").status_code == 422
    assert outbox == []


def test_sms_login_endpoints_are_gone(client):
    assert client.post("/auth/sms/start", json={"phone_number": "+520000000000"}).status_code == 404
    assert client.post("/auth/sms/check", json={"phone_number": "+520000000000", "code": "000000"}).status_code == 404


def test_otp_policy_env_values_are_validated(monkeypatch):
    monkeypatch.setenv("AUTH_OTP_TTL_SECONDS", "")
    assert EmailOtpService.from_env().ttl_seconds == 600
    monkeypatch.setenv("AUTH_OTP_TTL_SECONDS", "abc")
    with pytest.raises(ValueError):
        EmailOtpService.from_env()
    monkeypatch.setenv("AUTH_OTP_TTL_SECONDS", "0")
    with pytest.raises(ValueError):
        EmailOtpService.from_env()


# ── El código solo viaja en el cuerpo del correo ────────────────────────────

def test_real_email_carries_code_only_in_body(client, monkeypatch, capsys):
    """Envío real (enviar_token_otp) contra un SMTP simulado."""
    delivered = []

    class FakeSMTP:
        def __init__(self, host, port):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def login(self, user, password):
            pass

        def sendmail(self, sender, recipients, raw_message):
            delivered.append(raw_message)

    monkeypatch.setenv("SMTP_USER", "sender@example.com")
    monkeypatch.setenv("SMTP_PASS", "app-password")
    monkeypatch.setattr(notifications.smtplib, "SMTP_SSL", FakeSMTP)

    response = start(client)

    assert response.status_code == 200 and response.json()["sent_via"] == "smtp"
    message = email_lib.message_from_string(delivered[0])
    body = message.get_payload(decode=True).decode("utf-8")
    code = next(token for token in body.split() if token.isdigit() and len(token) == 6)

    assert code not in message["Subject"]
    assert code not in response.text
    output = capsys.readouterr()
    assert code not in output.out and code not in output.err
    assert check(client, code).status_code == 200


# ── Access token emitido al verificar ───────────────────────────────────────

def test_successful_check_returns_valid_access_token(client, outbox, monkeypatch):
    secret = "otp-endpoint-test-secret-0123456789-abcdefghij"
    monkeypatch.setenv("JWT_SECRET", secret)
    monkeypatch.delenv("JWT_TTL_SECONDS", raising=False)
    start(client)

    body = check(client, outbox[-1]["code"]).json()

    # Aditivo: la respuesta anterior sigue intacta.
    assert body["ok"] is True and body["verified"] is True and body["email"] == EMAIL
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 3600

    claims = jwt.decode(body["access_token"], secret, algorithms=["HS256"], issuer=ISSUER)
    assert claims["sub"] == EMAIL
    assert claims["role"] == "user"
    assert claims["exp"] > time.time()
    assert claims["exp"] - claims["iat"] == 3600
    assert decode_access_token(body["access_token"])["sub"] == EMAIL


def test_failed_check_issues_no_token(client, outbox):
    start(client)
    response = check(client, wrong(outbox[-1]["code"]))

    assert response.status_code == 401
    assert "access_token" not in response.text


def test_invalid_token_config_does_not_consume_the_code(client, outbox, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "too-short")
    start(client)
    code = outbox[-1]["code"]

    with pytest.raises(ValueError):
        check(client, code)  # error de configuración del servidor

    monkeypatch.setenv("JWT_SECRET", "otp-endpoint-test-secret-0123456789-abcdefghij")
    assert check(client, code).status_code == 200  # el código sigue disponible
