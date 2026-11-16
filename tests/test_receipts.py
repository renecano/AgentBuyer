"""Paso 7.1: recibo de compra con plantilla segura y datos reales (P-07).

- La plantilla escapa todo lo que viene de la oferta (dato no confiable del LLM).
- Muestra los datos REALES de la compra, sin nada inventado (PNR, vuelo fijo, "PAID").
- Va al DUEÑO verificado del mandato, no al human.email que manda el cliente.
- El asunto no lleva datos personales ni de la compra.
- El envío tiene timeout y un fallo nunca rompe la compra.
"""
import email as email_lib
import json

import pytest
from fastapi.testclient import TestClient

import core.notifications as notifications
from api.main import app
from audit.log import get_trail_events
from core import merchant_search
from core.notifications import PurchaseReceipt, render_purchase_receipt, send_purchase_receipt
from tests.conftest import TEST_USER_EMAIL, KeyRegistrar, SignedMandatePoster

RECEIPT = PurchaseReceipt(
    recipient_email="owner@example.com", mandate_id="mnd_r", attempt_id="att_r1",
    description="Flight BUE-COR", merchant_name="Despegar", merchant_id="mch_despegar",
    amount_cents=13999, currency="USD", authorized_at="2026-11-16T12:00:00+00:00",
    offer_url="https://www.despegar.example/offer/1", ledger_event_id="evt_abc", holder_name="Marta",
)
FABRICATED = ("PNR", "FLT-COR-130", "mch_vuelaya", "TOTAL PAID", "Fiscal", "check-in", "Google Calendar",
              "VuelaYa Travel & Logistics", "Aegis Zero-Trust Autonomous Protocol")


class FakeSMTP:
    instances: list = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout, self.sent = host, port, timeout, []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def login(self, user, password):
        pass

    def sendmail(self, sender, recipients, raw):
        self.sent.append((recipients, raw))


@pytest.fixture()
def smtp(monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setenv("SMTP_USER", "sender@example.com")
    monkeypatch.setenv("SMTP_PASS", "app-password")
    monkeypatch.setattr(notifications.smtplib, "SMTP_SSL", FakeSMTP)
    return FakeSMTP


def parts(raw: str) -> tuple:
    message = email_lib.message_from_string(raw)
    text, html = (part.get_payload(decode=True).decode("utf-8") for part in message.get_payload())
    return message, text, html


# ── Plantilla ───────────────────────────────────────────────────────────────

def test_the_receipt_shows_the_real_purchase_and_nothing_invented():
    subject, text, html = render_purchase_receipt(RECEIPT)
    for body in (text, html):
        for real in ("Flight BUE-COR", "139.99", "USD", "Despegar", "mch_despegar", "mnd_r", "att_r1", "evt_abc",
                     "2026-11-16T12:00:00+00:00", "https://www.despegar.example/offer/1"):
            assert real in body, real
        for invented in FABRICATED:
            assert invented not in body, invented
        assert "does not move money yet" in body  # honesto: es una autorización, no un pago
    assert subject == "Purchase authorized under your permission"


def test_the_subject_carries_no_personal_or_purchase_data():
    subject, _, _ = render_purchase_receipt(RECEIPT)
    for private in ("Marta", "owner@example.com", "139.99", "Despegar", "mnd_r"):
        assert private not in subject


@pytest.mark.parametrize("field", ["description", "merchant_name", "holder_name"])
def test_offer_text_is_escaped_in_the_html(field):
    """La descripción y el nombre vienen de la oferta (LLM): no pueden inyectar HTML."""
    hostile = '<script>alert(1)</script><a href="https://evil.example">Click</a>'
    subject, text, html = render_purchase_receipt(PurchaseReceipt(**{**RECEIPT.__dict__, field: hostile}))
    assert "<script>" not in html and '<a href="https://evil.example">' not in html
    assert "&lt;script&gt;" in html


@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,<b>x</b>", "ftp://example.com/x", "", None])
def test_only_http_offer_links_are_linked(url):
    _, text, html = render_purchase_receipt(PurchaseReceipt(**{**RECEIPT.__dict__, "offer_url": url}))
    assert "Offer" not in text and "href" not in html


# ── Envío ───────────────────────────────────────────────────────────────────

def test_sending_uses_a_timeout_and_reaches_only_the_given_owner(smtp):
    assert send_purchase_receipt(RECEIPT) == {"status": "sent"}
    (server,) = smtp.instances
    assert server.timeout == 10
    ((recipients, raw),) = server.sent
    assert recipients == ["owner@example.com"]
    message, text, html = parts(raw)
    assert message["To"] == "owner@example.com" and "Flight BUE-COR" in text and "Flight BUE-COR" in html


def test_timeout_is_configurable_and_malformed_config_is_an_error(smtp, monkeypatch):
    monkeypatch.setenv("SMTP_TIMEOUT_SECONDS", "3")
    send_purchase_receipt(RECEIPT)
    assert smtp.instances[-1].timeout == 3
    monkeypatch.setenv("SMTP_TIMEOUT_SECONDS", "never")
    with pytest.raises(ValueError):
        send_purchase_receipt(RECEIPT)


def test_without_smtp_or_owner_nothing_is_sent(monkeypatch, smtp):
    assert send_purchase_receipt(PurchaseReceipt(**{**RECEIPT.__dict__, "recipient_email": ""}))["status"] == "skipped"
    monkeypatch.delenv("SMTP_PASS")
    assert send_purchase_receipt(RECEIPT)["status"] == "skipped"
    assert all(not server.sent for server in smtp.instances)


def test_an_smtp_failure_is_reported_not_raised(smtp, monkeypatch):
    class Hanging(FakeSMTP):
        def login(self, user, password):
            raise TimeoutError("timed out")
    monkeypatch.setattr(notifications.smtplib, "SMTP_SSL", Hanging)
    assert send_purchase_receipt(RECEIPT) == {"status": "failed", "reason": "TimeoutError"}


# ── De punta a punta: la compra del agente dispara el recibo ────────────────

MANDATE = {
    "mandate_id": "mnd_receipt",
    # El cliente dice que el titular es otra persona: el recibo NO va ahí.
    "human": {"id": "hum_x", "display_name": "Marta", "email": "someone.else@example.com"},
    "agent": {"id": "agt_saturday"},
    "search_fields": {"origin": "BUE", "destination": "COR", "departure_date": "2026-12-05"},
    "constraints": {"max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
                    "allowed_merchants": ["mch_despegar"], "max_uses": 3},
}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    offers = [{"merchant": "Despegar", "price": 139.99, "currency": "USD", "details": "AR1504 <b>nonstop</b>",
               "url": "https://www.despegar.example/offer/1"}]
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: json.dumps(offers))
    with TestClient(app) as test_client:
        yield test_client


def test_an_agent_purchase_emails_the_verified_owner_with_the_real_data(client, monkeypatch, smtp):
    SignedMandatePoster(client, KeyRegistrar(client, monkeypatch)).create(MANDATE)
    run = client.post("/agent/run", json={"mandate_id": "mnd_receipt"}, headers=KeyRegistrar.bearer(TEST_USER_EMAIL)).json()
    assert run["purchase_completed"] is True, run

    sent = [item for server in smtp.instances for item in server.sent]
    assert len(sent) == 1
    recipients, raw = sent[0]
    assert recipients == [TEST_USER_EMAIL]  # el dueño verificado, no someone.else@example.com
    _, text, html = parts(raw)
    completed = next(e for e in get_trail_events(mandate_id="mnd_receipt") if e["type"] == "purchase_completed")
    for real in ("139.99", "mch_despegar", run["attempt_id"], completed["event_id"], "https://www.despegar.example/offer/1"):
        assert real in text and real in html
    assert "<b>nonstop</b>" not in html and "&lt;b&gt;nonstop&lt;/b&gt;" in html


def test_a_receipt_failure_does_not_undo_the_purchase(client, monkeypatch, smtp):
    class Broken(FakeSMTP):
        def login(self, user, password):
            raise OSError("smtp down")
    monkeypatch.setattr(notifications.smtplib, "SMTP_SSL", Broken)
    SignedMandatePoster(client, KeyRegistrar(client, monkeypatch)).create(MANDATE)
    run = client.post("/agent/run", json={"mandate_id": "mnd_receipt"}, headers=KeyRegistrar.bearer(TEST_USER_EMAIL)).json()
    assert run["purchase_completed"] is True
    assert run["verification"]["verdict"] == "APPROVE"
