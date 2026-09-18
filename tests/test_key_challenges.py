"""Prueba de posesión, lado servidor (sub-paso 2.3): step-up OTP + challenge + mensaje.

El registro que CONSUME el challenge es el sub-paso 2.4: aquí se prueba que sin un
OTP fresco del correo del dueño no se obtiene challenge, y cómo se gestiona.
Todos los tiempos usan reloj inyectable (sin esperas reales)."""
import email as email_lib
import json
import pathlib

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

import api.auth as auth_api
import api.keys as keys_api
import core.notifications as notifications
from api.main import app
from core.auth_tokens import create_access_token
from core.email_otp import EmailOtpService
from core.key_challenges import (
    CHALLENGE_TTL_SECONDS,
    REGISTER_KEY_PURPOSE,
    ChallengeRejected,
    ChallengeRejection,
    KeyChallengeService,
    registration_message,
    registration_payload,
)
from core.owner_keys import InvalidPublicKey
from mandate.canonical import canonicalize
from tests.conftest import TEST_USER_EMAIL

OTHER_EMAIL = "someone.else@example.com"
OTP_TTL, OTP_MAX_ATTEMPTS = 600, 5
VECTORS = json.loads(
    (pathlib.Path(__file__).resolve().parent.parent / "shared" / "key_registration_vectors.json").read_text(encoding="utf-8")
)
RFC8032_PUBLIC = VECTORS["rfc8032_test1"]["public_key_hex"]


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
def challenges(monkeypatch, clock):
    service = KeyChallengeService(clock=clock)
    monkeypatch.setattr(keys_api, "challenge_service", service)
    return service


@pytest.fixture()
def step_up(monkeypatch, clock):
    monkeypatch.delenv("AUTH_DEV_MODE", raising=False)
    service = EmailOtpService(
        ttl_seconds=OTP_TTL, max_attempts=OTP_MAX_ATTEMPTS, resend_cooldown_seconds=60,
        max_sends_per_window=5, send_window_seconds=3600, clock=clock,
    )
    monkeypatch.setattr(keys_api, "step_up_otp_service", service)
    return service


@pytest.fixture()
def outbox(monkeypatch):
    """Sustituye el envío real del step-up: guarda a quién llegó qué código."""
    sent = []

    def fake_send(email, code, ttl_seconds):
        sent.append({"email": email, "code": code})
        return True

    monkeypatch.setattr(keys_api, "send_step_up_email", fake_send)
    return sent


@pytest.fixture()
def client(challenges, step_up, outbox):
    with TestClient(app) as test_client:
        yield test_client


def bearer(email: str) -> dict:
    return {"Authorization": f"Bearer {create_access_token(email)}"}


# ── KeyChallengeService (gestión del challenge) ─────────────────────────────

def test_issue_binds_the_challenge_to_the_normalized_owner(challenges, clock):
    challenge = challenges.issue("  Marta@Example.COM ")

    assert challenge.owner_email == "marta@example.com"
    assert challenge.challenge_id.startswith("chl_") and len(challenge.challenge_id) == 4 + 32
    assert len(challenge.nonce) == 64 and int(challenge.nonce, 16) >= 0  # 32 bytes aleatorios
    assert challenge.expires_at == clock.now + CHALLENGE_TTL_SECONDS == clock.now + 120


def test_ids_and_nonces_are_unique(challenges):
    issued = [challenges.issue(TEST_USER_EMAIL) for _ in range(200)]
    assert len({c.challenge_id for c in issued}) == len({c.nonce for c in issued}) == 200


def test_challenge_is_single_use(challenges):
    challenge = challenges.issue(TEST_USER_EMAIL)

    assert challenges.consume(challenge.challenge_id, TEST_USER_EMAIL) == challenge
    with pytest.raises(ChallengeRejected) as rejected:
        challenges.consume(challenge.challenge_id, TEST_USER_EMAIL)
    assert rejected.value.reason is ChallengeRejection.USED


def test_challenge_expires(challenges, clock):
    fresh = challenges.issue(TEST_USER_EMAIL)
    stale = challenges.issue(TEST_USER_EMAIL)

    clock.advance(CHALLENGE_TTL_SECONDS - 0.1)
    assert challenges.consume(fresh.challenge_id, TEST_USER_EMAIL) == fresh  # justo antes: vale

    clock.advance(0.1)
    with pytest.raises(ChallengeRejected) as rejected:
        challenges.consume(stale.challenge_id, TEST_USER_EMAIL)
    assert rejected.value.reason is ChallengeRejection.EXPIRED


def test_challenge_of_one_account_does_not_work_for_another_and_is_not_burned(challenges):
    challenge = challenges.issue(TEST_USER_EMAIL)

    with pytest.raises(ChallengeRejected) as rejected:
        challenges.consume(challenge.challenge_id, OTHER_EMAIL)
    assert rejected.value.reason is ChallengeRejection.WRONG_OWNER
    # Otra cuenta no puede usarlo, y tampoco puede sabotear al dueño quemándolo.
    assert challenges.consume(challenge.challenge_id, TEST_USER_EMAIL) == challenge


def test_unknown_challenge_is_rejected(challenges):
    with pytest.raises(ChallengeRejected) as rejected:
        challenges.consume("chl_" + "0" * 32, TEST_USER_EMAIL)
    assert rejected.value.reason is ChallengeRejection.UNKNOWN


def test_expired_challenges_are_purged_on_issue(challenges, clock):
    for _ in range(5):
        challenges.issue(TEST_USER_EMAIL)
    clock.advance(CHALLENGE_TTL_SECONDS)
    challenges.issue(TEST_USER_EMAIL)

    assert len(challenges._entries) == 1


# ── Mensaje a firmar (contrato con el frontend) ─────────────────────────────

@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=[v["name"] for v in VECTORS["vectors"]])
def test_registration_message_matches_the_shared_vector_byte_for_byte(vector):
    message = registration_message(**vector["inputs"])

    assert message == vector["expected_message"].encode("utf-8")
    assert message.hex() == vector["expected_message_utf8_hex"]


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=[v["name"] for v in VECTORS["vectors"]])
def test_vector_signature_verifies_and_every_field_is_bound(vector):
    """La firma del vector (RFC 8032 TEST 1) verifica sobre NUESTRO mensaje, y cambiar
    cualquier campo firmado (incluido el purpose) la invalida."""
    public = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(RFC8032_PUBLIC))
    signature = bytes.fromhex(vector["expected_signature_hex"])
    public.verify(signature, registration_message(**vector["inputs"]))  # no lanza

    payload = registration_payload(**vector["inputs"])
    for field, other in [("challenge_id", "chl_" + "1" * 32), ("nonce", "ff" * 32),
                         ("owner", "attacker@example.com"), ("public_key", "ab" * 32),
                         ("purpose", "agentbuyer:mandate:v1")]:
        with pytest.raises(InvalidSignature):
            public.verify(signature, canonicalize({**payload, field: other}))


def test_registration_message_is_the_shared_canonicalization_of_exactly_five_fields():
    inputs = VECTORS["vectors"][0]["inputs"]
    payload = registration_payload(**inputs)

    assert set(payload) == {"purpose", "challenge_id", "nonce", "owner", "public_key"}
    assert payload["purpose"] == REGISTER_KEY_PURPOSE == "agentbuyer:register-key:v1"
    assert registration_message(**inputs) == canonicalize(payload)
    assert registration_message(**inputs) == registration_message(**inputs)  # determinista


@pytest.mark.parametrize(
    "overrides, error",
    [({"public_key": "zz" * 32}, InvalidPublicKey), ({"public_key": "ab" * 10}, InvalidPublicKey),
     ({"owner_email": "   "}, ValueError), ({"challenge_id": ""}, ValueError), ({"nonce": ""}, ValueError)],
    ids=["pubkey-no-hex", "pubkey-corta", "owner-vacio", "challenge-vacio", "nonce-vacio"],
)
def test_malformed_message_inputs_are_errors(overrides, error):
    with pytest.raises(error):
        registration_message(**{**VECTORS["vectors"][0]["inputs"], **overrides})


# ── POST /keys/step-up/start ────────────────────────────────────────────────

def test_step_up_start_without_token_is_401(client, outbox):
    assert client.post("/keys/step-up/start").status_code == 401
    assert outbox == []


def test_step_up_code_goes_to_the_token_email_only(client, outbox, auth_headers):
    response = client.post("/keys/step-up/start", json={"email": "attacker@example.com"}, headers=auth_headers)

    assert response.status_code == 200
    assert [sent["email"] for sent in outbox] == [TEST_USER_EMAIL]  # el cuerpo no elige destino
    body = response.json()
    assert "code_demo" not in body and outbox[0]["code"] not in response.text
    assert body["expires_in_seconds"] == OTP_TTL


def test_step_up_code_is_shown_only_in_dev_mode(client, outbox, auth_headers, monkeypatch):
    monkeypatch.setenv("AUTH_DEV_MODE", "true")
    body = client.post("/keys/step-up/start", headers=auth_headers).json()
    assert body["code_demo"] == outbox[0]["code"]


def test_step_up_is_rate_limited(client, auth_headers):
    assert client.post("/keys/step-up/start", headers=auth_headers).status_code == 200
    again = client.post("/keys/step-up/start", headers=auth_headers)

    assert again.status_code == 429
    assert int(again.headers["Retry-After"]) > 0


def test_undelivered_step_up_code_is_invalidated(client, auth_headers, monkeypatch):
    sent = []
    monkeypatch.setattr(keys_api, "send_step_up_email", lambda email, code, ttl: sent.append(code) or False)

    assert client.post("/keys/step-up/start", headers=auth_headers).status_code == 503
    # El código que nadie recibió no sirve para nada.
    assert client.post("/keys/challenge", json={"code": sent[0]}, headers=auth_headers).status_code == 403


def test_step_up_email_says_what_the_code_authorizes(monkeypatch):
    """Envío real contra un SMTP simulado: el correo dice que confirma una LLAVE (una
    alerta si la persona no lo pidió) y el código no va en el asunto."""
    delivered = []

    class FakeSMTP:
        def __init__(self, host, port): pass
        def __enter__(self): return self
        def __exit__(self, *exc): return False
        def login(self, user, password): pass
        def sendmail(self, sender, recipients, raw): delivered.append(raw)

    monkeypatch.setenv("SMTP_USER", "sender@example.com")
    monkeypatch.setenv("SMTP_PASS", "app-password")
    monkeypatch.setattr(notifications.smtplib, "SMTP_SSL", FakeSMTP)

    assert keys_api.send_step_up_email(TEST_USER_EMAIL, "123456", 600) is True
    assert notifications.enviar_token_otp(TEST_USER_EMAIL, "654321")["sent_via"] == "smtp"

    step_up_mail, login_mail = (email_lib.message_from_string(raw) for raw in delivered)
    assert step_up_mail["Subject"] == "Confirm a new security key"
    step_up_body = step_up_mail.get_payload(decode=True).decode("utf-8")
    assert "123456" in step_up_body and "123456" not in step_up_mail["Subject"]
    assert "security key" in step_up_body and "If it wasn't you" in step_up_body
    assert login_mail["Subject"] == "Your Aegis verification code"  # el de login no cambió


# ── POST /keys/challenge: el step-up es obligatorio ─────────────────────────

def test_challenge_without_token_is_401(client, outbox, auth_headers):
    client.post("/keys/step-up/start", headers=auth_headers)
    assert client.post("/keys/challenge", json={"code": outbox[0]["code"]}).status_code == 401


def test_session_alone_cannot_get_a_challenge(client, challenges, auth_headers):
    """Sin OTP fresco no hay challenge. Es 403 y NO 401: la sesión es válida (un 401
    haría que el frontend cerrara la sesión por un código mal tecleado)."""
    response = client.post("/keys/challenge", json={"code": "000000"}, headers=auth_headers)

    assert response.status_code == 403
    assert challenges._entries == {}


def test_fresh_step_up_code_yields_a_challenge_bound_to_the_token_email(client, challenges, outbox, auth_headers):
    client.post("/keys/step-up/start", headers=auth_headers)
    response = client.post("/keys/challenge", json={"code": outbox[0]["code"]}, headers=auth_headers)

    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"challenge_id", "nonce", "expires_in", "purpose"}
    assert body["expires_in"] == CHALLENGE_TTL_SECONDS and body["purpose"] == REGISTER_KEY_PURPOSE
    with pytest.raises(ChallengeRejected):
        challenges.consume(body["challenge_id"], OTHER_EMAIL)  # atado al dueño del token
    assert challenges.consume(body["challenge_id"], TEST_USER_EMAIL).nonce == body["nonce"]


def test_step_up_code_is_single_use(client, outbox, auth_headers):
    client.post("/keys/step-up/start", headers=auth_headers)
    code = outbox[0]["code"]

    assert client.post("/keys/challenge", json={"code": code}, headers=auth_headers).status_code == 201
    assert client.post("/keys/challenge", json={"code": code}, headers=auth_headers).status_code == 403


def test_expired_step_up_code_does_not_yield_a_challenge(client, outbox, clock, auth_headers):
    client.post("/keys/step-up/start", headers=auth_headers)
    clock.advance(OTP_TTL)

    assert client.post("/keys/challenge", json={"code": outbox[0]["code"]}, headers=auth_headers).status_code == 403


def test_too_many_wrong_codes_lock_the_step_up(client, outbox, auth_headers):
    client.post("/keys/step-up/start", headers=auth_headers)
    codes = [client.post("/keys/challenge", json={"code": "000000" if outbox[0]["code"] != "000000" else "111111"},
                         headers=auth_headers).status_code for _ in range(OTP_MAX_ATTEMPTS)]

    assert codes[:-1] == [403] * (OTP_MAX_ATTEMPTS - 1) and codes[-1] == 429
    # Bloqueado: ni el código correcto sirve ya; hay que pedir otro.
    assert client.post("/keys/challenge", json={"code": outbox[0]["code"]}, headers=auth_headers).status_code == 403


def test_a_login_code_is_not_a_step_up_code(client, monkeypatch, clock, auth_headers):
    """Separación de propósito: el OTP de login no confirma un registro de llave."""
    login_otp = EmailOtpService(clock=clock)
    monkeypatch.setattr(auth_api, "otp_service", login_otp)
    login_code = login_otp.issue(TEST_USER_EMAIL)

    assert client.post("/keys/challenge", json={"code": login_code}, headers=auth_headers).status_code == 403


def test_step_up_code_of_one_account_does_not_work_with_another_token(client, outbox, auth_headers):
    client.post("/keys/step-up/start", headers=auth_headers)
    victims_code = outbox[0]["code"]

    assert client.post("/keys/challenge", json={"code": victims_code}, headers=bearer(OTHER_EMAIL)).status_code == 403


def test_stolen_token_without_mailbox_access_cannot_obtain_a_challenge(client, challenges, outbox, auth_headers):
    """El escenario que motiva el step-up: el atacante tiene el token de la víctima
    pero no su correo. Puede disparar el envío (que ALERTA a la víctima), pero no
    conoce el código, así que no obtiene challenge; sin challenge, el 2.4 no
    registrará su llave."""
    attacker_sees = client.post("/keys/step-up/start", headers=auth_headers)
    assert attacker_sees.status_code == 200
    assert outbox[0]["email"] == TEST_USER_EMAIL and outbox[0]["code"] not in attacker_sees.text

    for guess in ("000000", "123456", "999999"):
        assert client.post("/keys/challenge", json={"code": guess}, headers=auth_headers).status_code in (403, 429)
    assert challenges._entries == {}


# ── Cableado de producción (SIN sustituir los servicios) ────────────────────
# Los fixtures de arriba reemplazan step_up_otp_service; estos tests miran las
# instancias reales, para que conectar el step-up al OTP de login no pase inadvertido.

def test_step_up_and_login_use_separate_otp_services():
    assert keys_api.step_up_otp_service is not auth_api.otp_service
    assert isinstance(keys_api.step_up_otp_service, EmailOtpService)


def test_real_login_code_is_rejected_by_the_real_step_up(monkeypatch):
    """Extremo a extremo con las instancias reales: un código de LOGIN recién emitido
    por /auth/email/start no sirve como confirmación en /keys/challenge."""
    import secrets

    monkeypatch.setenv("AUTH_DEV_MODE", "true")  # para recibir code_demo sin SMTP
    monkeypatch.setattr(auth_api, "send_verification_email", lambda email, code, ttl: False)
    email = f"wiring-{secrets.token_hex(4)}@example.com"  # sin choques con el rate limit real

    with TestClient(app) as test_client:
        login = test_client.post("/auth/email/start", json={"email": email}).json()
        response = test_client.post("/keys/challenge", json={"code": login["code_demo"]}, headers=bearer(email))

    assert response.status_code == 403
