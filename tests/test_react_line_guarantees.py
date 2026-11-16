"""Paso 7.2: garantías que probaba la línea estricta, portadas a la línea del producto.

La línea estricta (core/verify.py y sus tests: test_circuit.py, test_live_state.py)
se retiró (P-08). Cada garantía que probaba y que no tenía equivalente en la línea de
React/API se prueba aquí. Al portarlas apareció un bug real en las disputas: un
intento RECHAZADO se resolvía como "compra verificada y aprobada" a cargo del titular.
"""
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import api.verify as verify_api
import core.mandate_store as mandate_store_module
from api.disputes import _resolve
from api.main import app
from audit.log import get_trail_events
from core import merchant_search
from core.mandate_store import get_mandate
from tests.conftest import TEST_ADMIN_EMAIL, TEST_USER_EMAIL, KeyRegistrar, SignedMandatePoster, verify_as_service
from tests.storage import tamper_document

pytestmark = pytest.mark.usefixtures("service_key")

MANDATE = {
    "mandate_id": "mnd_react", "human": {"id": "hum_x", "display_name": "X"}, "agent": {"id": "agt_saturday"},
    "search_fields": {"origin": "BUE", "destination": "COR", "departure_date": "2026-12-05"},
    "constraints": {"max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
                    "allowed_merchants": ["mch_vuelaya"], "max_uses": 3},
}


def owner() -> dict:
    return KeyRegistrar.bearer(TEST_USER_EMAIL)


def attempt(mandate_id: str = "mnd_react", cents: int = 12000, currency: str = "USD") -> dict:
    return {"attempt_id": f"att_{secrets.token_hex(4)}", "mandate_id": mandate_id, "presented_by_agent": "agt_saturday",
            "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount_cents": cents,
                         "currency": currency, "description": "Flight BUE-COR", "metadata": {"price_cents": cents}}}


def check(result: dict, rule: str) -> dict:
    return next(item for item in result["checks"] if item["rule"] == rule)


def verifications(attempt_id: str) -> list:
    return [event for event in get_trail_events(attempt_id=attempt_id) if event["type"] == "verification"]


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: "[]")
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def poster(client, monkeypatch) -> SignedMandatePoster:
    return SignedMandatePoster(client, KeyRegistrar(client, monkeypatch))


@pytest.fixture()
def mine(poster) -> str:
    poster.create(MANDATE)
    return "mnd_react"


# ── Cada decisión queda en el ledger (de test_circuit) ──────────────────────

def test_an_unknown_mandate_is_rejected_and_recorded(client):
    body = attempt("mnd_does_not_exist")
    result = verify_as_service(client, body).json()
    assert result["verdict"] == "REJECT"
    assert check(result, "mandate_exists")["pass"] is False
    assert [event["verdict"] for event in verifications(body["attempt_id"])] == ["REJECT"]


@pytest.mark.parametrize("cents, currency, verdict", [
    (12000, "USD", "APPROVE"), (20000, "USD", "ESCALATE"), (12000, "EUR", "REJECT"),
])
def test_every_verdict_is_recorded_exactly_once(client, mine, cents, currency, verdict):
    body = attempt(cents=cents, currency=currency)
    assert verify_as_service(client, body).json()["verdict"] == verdict
    assert [event["verdict"] for event in verifications(body["attempt_id"])] == [verdict]


def test_the_firewall_receives_the_signed_limit_and_the_price_in_cents(client, mine, monkeypatch):
    seen = {}

    def spy(**kwargs):
        seen.update(kwargs)
        return {"veredicto": "APPROVE", "resumen_para_humano": "ok"}
    monkeypatch.setattr(verify_api, "auditoria_cognitiva_firewall", spy)
    assert verify_as_service(client, attempt(cents=13999)).json()["verdict"] == "APPROVE"
    assert seen["mandate_constraints"]["max_amount_per_purchase_cents"] == 15000
    assert seen["price_cents"] == 13999


# ── Estado vivo y expiración (de test_live_state) ───────────────────────────

def test_an_unreadable_stored_expiry_fails_closed(client, mine):
    tamper_document("mnd_react", lambda document: document.__setitem__("expires_at", "not-a-date"))
    result = verify_as_service(client, attempt()).json()
    assert result["verdict"] == "REJECT"
    assert check(result, "signature")["pass"] is False


def test_expiry_is_visible_in_get_mandate_and_rejects(client, poster, monkeypatch):
    signed = poster.create(MANDATE)
    expires_at = datetime.strptime(signed["mandate"]["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    monkeypatch.setattr(mandate_store_module, "_utcnow", lambda: expires_at + timedelta(seconds=1))
    assert client.get("/mandates/mnd_react", headers=owner()).json()["live_state"]["status"] == "expired"
    result = verify_as_service(client, attempt()).json()
    assert result["verdict"] == "REJECT" and check(result, "status")["pass"] is False


def test_pause_resume_and_revoke_are_what_get_mandate_and_verify_see(client, mine):
    def status() -> str:
        return client.get("/mandates/mnd_react", headers=owner()).json()["live_state"]["status"]

    assert client.post("/mandates/mnd_react/pause", headers=owner()).status_code == 200
    assert status() == "paused" and verify_as_service(client, attempt()).json()["verdict"] == "REJECT"
    assert client.post("/mandates/mnd_react/resume", headers=owner()).status_code == 200
    assert status() == "active" and verify_as_service(client, attempt()).json()["verdict"] == "APPROVE"
    revoked = client.post("/mandates/mnd_react/revoke", headers=owner()).json()
    assert revoked["live_state"]["status"] == "revoked" and status() == "revoked"
    assert verify_as_service(client, attempt()).json()["verdict"] == "REJECT"
    # Pausar ya no reescribe el documento firmado (antes le agregaba "status").
    assert "status" not in get_mandate("mnd_react")["mandate"]


# ── Disputas (de test_circuit; aquí apareció el bug) ────────────────────────

def dispute(client, attempt_id: str) -> dict:
    response = client.post("/disputes/file", json={"attempt_id": attempt_id, "mandate_id": "mnd_react"}, headers=owner())
    assert response.status_code == 200, response.text
    return response.json()


def test_a_valid_approved_purchase_is_the_cardholders(client, mine):
    body = attempt()
    assert verify_as_service(client, body).json()["verdict"] == "APPROVE"
    assert dispute(client, body["attempt_id"])["verdict"] == "HUMAN_LIABLE_VALID_MANDATE"


@pytest.mark.parametrize("cents, currency, verdict", [(12000, "EUR", "REJECT"), (20000, "USD", "ESCALATE")])
def test_a_purchase_that_was_never_approved_protects_the_cardholder(client, mine, cents, currency, verdict):
    """7.2 (bug): bastaba un evento de verificación (aunque dijera REJECT) para
    resolver "compra verificada y aprobada" a cargo del titular."""
    body = attempt(cents=cents, currency=currency)
    assert verify_as_service(client, body).json()["verdict"] == verdict
    result = dispute(client, body["attempt_id"])
    assert result["verdict"] == "MERCHANT_LIABLE_UNVERIFIED" and result["refund_issued"] is True


def test_an_escalation_approved_by_the_person_is_the_cardholders(client, mine):
    body = attempt(cents=20000)
    assert verify_as_service(client, body).json()["verdict"] == "ESCALATE"
    assert client.post("/mandates/mnd_react/approve_escalation",
                       json={"purchase_attempt_id": body["attempt_id"], "decision": "approve"}, headers=owner()).status_code == 200
    assert dispute(client, body["attempt_id"])["verdict"] == "HUMAN_LIABLE_VALID_MANDATE"


def test_an_approval_after_the_revocation_is_the_merchants(client, mine):
    """Rama defensiva: el flujo ya no permite aprobar tras revocar, pero si el trail lo
    mostrara (p. ej. un comercio que cobró igual), el titular queda protegido."""
    client.post("/mandates/mnd_react/revoke", headers=owner())
    revoked_at = datetime.fromisoformat(get_mandate("mnd_react")["live_state"]["revoked_at"])
    late = (revoked_at + timedelta(minutes=1)).isoformat()
    evidence = [{"attempt_id": "att_late", "type": "verification", "verdict": "APPROVE", "timestamp": late}]
    assert _resolve("att_late", "mnd_react", evidence)["verdict"] == "MERCHANT_LIABLE_POST_REVOCATION"


# ── GET /mandates: cada uno ve lo suyo (7.2) ────────────────────────────────

def test_listing_mandates_shows_only_your_own(client, poster, admin_headers):
    """Antes devolvía TODOS los mandatos del sistema a cualquier usuario autenticado,
    con los payment_token de otras personas."""
    poster.create(MANDATE)
    poster.create({**MANDATE, "mandate_id": "mnd_other_person"}, email="other.person@example.com")

    mine = client.get("/mandates", headers=owner()).json()
    assert [record["mandate"]["mandate_id"] for record in mine] == ["mnd_react"]
    theirs = client.get("/mandates", headers=KeyRegistrar.bearer("other.person@example.com")).json()
    assert [record["mandate"]["mandate_id"] for record in theirs] == ["mnd_other_person"]
    assert client.get("/mandates", headers=KeyRegistrar.bearer("nobody@example.com")).json() == []
    everything = client.get("/mandates", headers=admin_headers).json()
    assert {record["mandate"]["mandate_id"] for record in everything} == {"mnd_react", "mnd_other_person"}
    assert TEST_ADMIN_EMAIL  # el admin lo es por ADMIN_EMAILS (fixture admin_headers)


def test_the_mandate_reset_route_no_longer_exists(client, mine):
    """P-17: reiniciar los contadores autorizaba más compras sin la firma del dispositivo."""
    for _ in range(3):
        assert verify_as_service(client, attempt()).json()["verdict"] == "APPROVE"
    assert client.post("/mandates/mnd_react/reset", headers=owner()).status_code in (404, 405)
    assert get_mandate("mnd_react")["live_state"]["uses_count"] == 3
    assert verify_as_service(client, attempt()).json()["verdict"] != "APPROVE"  # agotado: se firma otro
