"""Paso 7.3: logging estructurado sin datos personales, idioma consistente y limpieza.

- Cada petición tiene un request id (X-Request-ID) que aparece en sus líneas de log.
- Los flujos de auth no dejan en el log emails completos, códigos OTP, tokens ni firmas.
- La API responde en inglés (P-12): un guardián recorre los flujos principales.
- GET /mandates sobrevive a un registro corrupto; la integridad del ledger está en
  GET /ledger/verify (con sesión) y ya no choca con GET /audit/{mandate_id}.
"""
import email as email_lib
import logging
import re
import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

import api.auth as auth_api
import core.notifications as notifications
from api.main import app
from core.db import write_tx
from core.db_schema import mandates
from core.email_otp import EmailOtpService
from core.logging_config import LOG_FORMAT, RequestIdFilter, mask_email
from tests.conftest import TEST_USER_EMAIL, KeyRegistrar, SignedMandatePoster, verify_as_service

pytestmark = pytest.mark.usefixtures("service_key")

MANDATE = {
    "mandate_id": "mnd_hygiene", "human": {"id": "hum_x", "display_name": "X"}, "agent": {"id": "agt_saturday"},
    "constraints": {"max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
                    "allowed_merchants": ["mch_vuelaya"], "max_uses": 3},
}


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


def attempt(mandate_id: str, cents: int = 12000, currency: str = "USD") -> dict:
    return {"attempt_id": f"att_{secrets.token_hex(4)}", "mandate_id": mandate_id, "presented_by_agent": "agt_saturday",
            "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount_cents": cents,
                         "currency": currency, "description": "Flight BUE-COR", "metadata": {"price_cents": cents}}}


# ── Request id ──────────────────────────────────────────────────────────────

def test_every_response_carries_a_request_id(client):
    first = client.get("/health").headers["X-Request-ID"]
    second = client.get("/health").headers["X-Request-ID"]
    assert re.fullmatch(r"[0-9a-f]{32}", first) and first != second


@pytest.mark.parametrize("incoming, echoed", [
    ("trace-abc_123.x", True),
    ("two words", False), ("line\\nbreak", False), ("x" * 65, False),
])
def test_a_safe_incoming_request_id_is_kept_and_an_unsafe_one_replaced(client, incoming, echoed):
    """Un id con espacios o saltos de línea podría inyectar líneas falsas en el log."""
    returned = client.get("/health", headers={"X-Request-ID": incoming}).headers["X-Request-ID"]
    assert (returned == incoming) is echoed


def test_log_lines_carry_the_request_id_of_their_request(client, monkeypatch):
    poster = SignedMandatePoster(client, KeyRegistrar(client, monkeypatch))
    poster.create(MANDATE)
    with write_tx() as connection:  # un registro corrupto provoca un warning durante la petición
        connection.execute(update(mandates).where(mandates.c.mandate_id == "mnd_hygiene").values(document="{not json"))

    lines: list = []

    class Collect(logging.Handler):
        def emit(self, record):
            lines.append(self.format(record))
    handler = Collect()
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    handler.addFilter(RequestIdFilter())
    logging.getLogger().addHandler(handler)
    try:
        response = client.get("/mandates", headers={**KeyRegistrar.bearer(TEST_USER_EMAIL), "X-Request-ID": "req-7-3"})
    finally:
        logging.getLogger().removeHandler(handler)
    assert response.status_code == 200 and response.json() == []  # el corrupto se omite, no tumba la lista
    assert any("[req=req-7-3]" in line and "mnd_hygiene" in line and "unreadable" in line for line in lines)


# ── Sin datos personales ni secretos en el log ──────────────────────────────

class FakeSMTP:
    sent: list = []

    def __init__(self, host, port, timeout=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def login(self, user, password):
        pass

    def sendmail(self, sender, recipients, raw):
        FakeSMTP.sent.append(raw)


def code_in(raw: str) -> str:
    body = email_lib.message_from_string(raw).get_payload(decode=True).decode("utf-8")
    return next(token for token in body.split() if token.isdigit() and len(token) == 6)


def test_auth_flows_log_no_email_code_token_or_signature(client, monkeypatch, caplog):
    FakeSMTP.sent = []
    monkeypatch.setenv("SMTP_USER", "sender@example.com")
    monkeypatch.setenv("SMTP_PASS", "app-password")
    monkeypatch.setattr(notifications.smtplib, "SMTP_SSL", FakeSMTP)
    monkeypatch.setattr(auth_api, "otp_service", EmailOtpService())
    email = "private.person@example.com"
    secrets_seen: list = []

    with caplog.at_level(logging.DEBUG):
        assert client.post("/auth/email/start", json={"email": email}).status_code == 200
        code = code_in(FakeSMTP.sent[-1])
        token = client.post("/auth/email/check", json={"email": email, "code": code}).json()["access_token"]
        secrets_seen += [code, token]
        # Llave del dispositivo y mandato firmado (step-up con el SMTP simulado de KeyRegistrar).
        poster = SignedMandatePoster(client, KeyRegistrar(client, monkeypatch), default_email=email)
        body = poster.body(MANDATE)
        secrets_seen += [body["signature"], body["nonce"]]
        assert client.post("/mandates", json=body, headers={"Authorization": f"Bearer {token}"}).status_code == 201
        verify_as_service(client, attempt("mnd_hygiene"))

    assert caplog.records, "el flujo debería haber dejado alguna línea de log"
    text = caplog.text
    assert email not in text and "private.person" not in text
    for secret in secrets_seen:
        assert secret not in text
    assert mask_email(email) in text  # el envío sí quedó registrado, enmascarado


def test_mask_email():
    assert mask_email("maria.perez@example.com") == "m***@example.com"
    assert mask_email("not-an-email") == "***" and mask_email(None) == "***"


# ── Rutas ───────────────────────────────────────────────────────────────────

def test_ledger_verification_needs_a_session_and_no_longer_collides(client, monkeypatch):
    assert client.get("/ledger/verify").status_code == 401
    assert client.get("/ledger/verify", headers=KeyRegistrar.bearer(TEST_USER_EMAIL)).json()["valid"] is True
    # Un mandato llamado "verify" ya puede ver su historial (antes la ruta lo tapaba).
    SignedMandatePoster(client, KeyRegistrar(client, monkeypatch)).create({**MANDATE, "mandate_id": "verify"})
    trail = client.get("/audit/verify", headers=KeyRegistrar.bearer(TEST_USER_EMAIL))
    assert trail.status_code == 200 and isinstance(trail.json(), list) and trail.json()


# ── Idioma (P-12) ───────────────────────────────────────────────────────────

SPANISH = re.compile(r"[áéíóúñ¿¡]|\b(el|la|los|las|del|que|una|por|para|con|sin|mandato|compra|firma|llave|titular|intento|comercio)\b", re.I)


def texts(value) -> list:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for key, item in value.items() if key not in ("mandate_id", "attempt_id") for text in texts(item)]
    if isinstance(value, list):
        return [text for item in value for text in texts(item)]
    return []


def test_the_api_answers_in_english(client, monkeypatch):
    """Guardián de P-12: los textos que ve la persona (checks, veredictos, historial,
    disputas, errores) no traen español."""
    poster = SignedMandatePoster(client, KeyRegistrar(client, monkeypatch))
    poster.create({**MANDATE, "human": {"id": "hum_x", "display_name": "Test"}})
    owner = KeyRegistrar.bearer(TEST_USER_EMAIL)
    responses = [
        verify_as_service(client, attempt("mnd_hygiene")).json(),                        # APPROVE
        verify_as_service(client, attempt("mnd_hygiene", 40000)).json(),                 # ESCALATE
        verify_as_service(client, attempt("mnd_hygiene", currency="EUR")).json(),        # REJECT
        verify_as_service(client, attempt("mnd_unknown")).json(),                        # REJECT, sin mandato
        client.post("/agent/run", json={"mandate_id": "mnd_hygiene"}, headers=owner).json(),
        client.post("/mandates/mnd_hygiene/approve_escalation", json={"purchase_attempt_id": "att_x", "decision": "approve"}, headers=owner).json(),
        client.post("/disputes/file", json={"attempt_id": "att_x", "mandate_id": "mnd_hygiene"}, headers=owner).json(),
        client.get("/audit", headers=owner).json(),
        client.get("/mandates/mnd_nope", headers=owner).json(),
    ]
    spanish = [text for response in responses for text in texts(response) if SPANISH.search(text)]
    assert spanish == []
