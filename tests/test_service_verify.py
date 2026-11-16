"""Paso 4.2 (P-03): /verify es la verificación del comercio/agente, y la demo pasa
por /agent/run con escenarios explícitos que nunca compran.

Todo por HTTP con credenciales reales; red y LLM simulados (firewall offline)."""
import copy
import secrets

import pytest
from fastapi.testclient import TestClient

import api.agent as agent_api
import api.verify as verify_api
from api.main import app
from audit.log import get_trail_events
from core import agent_keys, mandate_store, merchant_search
from core.agent_keys import AGENT_SIGNATURE_FIELD, sign_attempt
from core.auth_tokens import create_access_token
from core.quotas import PerSubjectQuota
from tests.conftest import TEST_SERVICE_KEY, TEST_USER_EMAIL, FakeClock, verify_as_service
from tests.storage import live_state

pytestmark = pytest.mark.usefixtures("service_key")

OTHER = "otra.persona@example.com"


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)  # firewall offline y determinista
    searches: list = []
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: searches.append(prompt) or "[]")
    mandate_store.mandate_store.clear()
    agent_keys.clear()
    with TestClient(app) as test_client:
        test_client.searches = searches
        yield test_client
    mandate_store.mandate_store.clear()
    agent_keys.clear()


@pytest.fixture()
def mine(signed_poster) -> str:
    signed_poster.create({
        "mandate_id": "mnd_mine",
        "human": {"id": "hum_x", "display_name": "X"},
        "agent": {"id": "agt_saturday"},
        "search_fields": {"origin": "BUE", "destination": "COR", "departure_date": "2026-12-05"},
        "constraints": {
            "max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"], "max_uses": 3,
            "conditions": [{"type": "price_below", "value": 150}],
        },
    }, email=TEST_USER_EMAIL)
    return "mnd_mine"


def bearer(email: str) -> dict:
    return {"Authorization": f"Bearer {create_access_token(email)}"}


def attempt(mandate_id: str, attempt_id: str = "att_1", currency: str = "USD", **extra) -> dict:
    return {
        "attempt_id": attempt_id, "mandate_id": mandate_id, "presented_by_agent": "agt_saturday",
        # 6.3: intento reciente, ANTES de firmarlo (la firma del agente cubre created_at).
        "created_at": verify_api.attempt_timestamp(verify_api._utcnow()),
        "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount_cents": 10000,
                     "currency": currency, "metadata": {"price_cents": 10000}},
        **extra,
    }


def check(result: dict, rule: str) -> dict:
    return next(item for item in result["checks"] if item["rule"] == rule)


# ── Credencial: solo el comercio/agente ─────────────────────────────────────

def test_verify_requires_a_service_credential(client, mine, auth_headers, admin_headers):
    body = attempt(mine, nonce=secrets.token_hex(16))
    assert client.post("/verify", json=body).status_code == 401
    assert client.post("/verify", json=body, headers=auth_headers).status_code == 401  # un JWT no es una key
    assert client.post("/verify", json=body, headers=admin_headers).status_code == 401
    assert client.post("/verify", json=body, headers={"X-Service-Key": "wrong-key-0123456789"}).status_code == 401
    assert live_state(mine)["uses_count"] == 0  # nada se ejecutó

    response = client.post("/verify", json=body, headers={"X-Service-Key": TEST_SERVICE_KEY})
    assert response.status_code == 200 and response.json()["verdict"] == "APPROVE"


# ── Anti-replay ─────────────────────────────────────────────────────────────

def test_replayed_nonce_is_rejected(client, mine):
    nonce = secrets.token_hex(16)
    assert verify_as_service(client, attempt(mine, "att_1"), nonce=nonce).json()["verdict"] == "APPROVE"
    replay = verify_as_service(client, attempt(mine, "att_2"), nonce=nonce).json()

    assert replay["verdict"] == "REJECT"
    assert check(replay, "nonce_fresh")["pass"] is False
    assert live_state(mine)["uses_count"] == 1  # el replay no compró


@pytest.mark.parametrize("nonce", [None, "", "short", "x" * 129, 12345])
def test_attempt_without_a_valid_nonce_is_rejected(client, mine, nonce):
    body = attempt(mine)
    if nonce is not None:
        body["nonce"] = nonce
    result = client.post("/verify", json=body, headers={"X-Service-Key": TEST_SERVICE_KEY}).json()
    assert result["verdict"] == "REJECT"
    assert check(result, "nonce_fresh")["pass"] is False


def test_a_rejected_attempt_also_burns_its_nonce(client, mine):
    nonce = secrets.token_hex(16)
    assert verify_as_service(client, attempt(mine, currency="EUR"), nonce=nonce).json()["verdict"] == "REJECT"
    assert check(verify_as_service(client, attempt(mine), nonce=nonce).json(), "nonce_fresh")["pass"] is False


# ── Firma del agente (cuando el intento la declara) ─────────────────────────

def signed(body: dict, agent_id: str = "agt_saturday") -> dict:
    body = {**body, "nonce": secrets.token_hex(16)}
    body[AGENT_SIGNATURE_FIELD] = sign_attempt(agent_id, body)
    return body


def test_declared_agent_signature_is_verified(client, mine):
    result = verify_as_service(client, signed(attempt(mine))).json()
    assert result["verdict"] == "APPROVE"
    assert check(result, "agent_signature")["pass"] is True


def test_undeclared_agent_signature_is_not_required(client, mine):
    result = verify_as_service(client, attempt(mine)).json()
    assert result["verdict"] == "APPROVE"
    assert "agent_signature" not in {item["rule"] for item in result["checks"]}


@pytest.mark.parametrize("forgery", ["garbage", "other_agent_key", "tampered_amount"])
def test_bad_agent_signature_is_rejected(client, mine, forgery):
    if forgery == "garbage":
        body = {**attempt(mine), "nonce": secrets.token_hex(16), AGENT_SIGNATURE_FIELD: "00" * 64}
    elif forgery == "other_agent_key":
        body = signed(attempt(mine), agent_id="agt_mallory")  # firmado por otro agente
    else:
        body = signed(attempt(mine))
        body = copy.deepcopy(body)
        body["purchase"]["amount"] = 1.0  # alterado después de firmar
    result = verify_as_service(client, body).json()
    assert result["verdict"] == "REJECT"
    assert check(result, "agent_signature")["pass"] is False
    assert live_state(mine)["uses_count"] == 0


def test_agent_runs_sign_their_attempts(client, mine, monkeypatch):
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: '[{"merchant": "VuelaYa", "price": 120.0, "currency": "USD", "details": "d", "url": "https://vuelaya.example/1"}]')
    run = client.post("/agent/run", json={"mandate_id": mine}, headers=bearer(TEST_USER_EMAIL)).json()
    assert run["purchase_completed"] is True
    assert check(run["verification"], "agent_signature")["pass"] is True
    assert check(run["verification"], "nonce_fresh")["pass"] is True


# ── Moneda (en todo mandato) ────────────────────────────────────────────────

def test_currency_must_match_on_every_mandate(client, mine):
    """Moneda distinta → REJECT. (7.2: antes también se probaba sobre el seed sellado.)"""
    result = verify_as_service(client, attempt(mine, currency="EUR")).json()
    assert result["verdict"] == "REJECT"
    assert check(result, "currency")["pass"] is False


# ── Escenarios de la demo vía /agent/run ────────────────────────────────────

def run(client, mandate_id: str, scenario: str, email: str = TEST_USER_EMAIL):
    return client.post("/agent/run", json={"mandate_id": mandate_id, "scenario": scenario}, headers=bearer(email))


def test_trap_offer_is_caught_and_never_buys(client, mine):
    response = run(client, mine, "trap_offer")
    assert response.status_code == 200
    result = response.json()

    assert result["discovery_source"] == "scenario"
    assert result["verification"]["verdict"] == "REJECT"
    assert check(result["verification"], "semantic_firewall")["pass"] is False
    assert result["purchase_completed"] is False
    assert "Escenario de demostración" in result["human_readable"]
    assert client.searches == []  # sin búsqueda web
    assert live_state(mine)["uses_count"] == 0
    types = [event["type"] for event in get_trail_events(mandate_id=mine)]
    assert "scenario_verification" in types and "verification" not in types  # no parece una compra


def test_after_revocation_needs_a_revoked_mandate(client, mine):
    assert run(client, mine, "after_revocation").status_code == 409  # sin revocar no fabrica una compra
    assert client.post(f"/mandates/{mine}/revoke", headers=bearer(TEST_USER_EMAIL)).status_code == 200

    result = run(client, mine, "after_revocation").json()
    assert result["verification"]["verdict"] == "REJECT"
    assert check(result["verification"], "status")["detail"] == "mandato revocado"
    assert result["purchase_completed"] is False


def test_scenarios_are_only_for_the_owner_and_must_be_known(client, mine):
    assert run(client, mine, "trap_offer", email=OTHER).status_code == 403
    assert run(client, mine, "free_money").status_code == 422
    assert client.post("/agent/run", json={"mandate_id": mine, "scenario": "trap_offer"}).status_code == 401


def test_scenarios_do_not_spend_the_agent_quota(client, mine, monkeypatch):
    monkeypatch.setattr(agent_api, "agent_run_quota", PerSubjectQuota(limit=1, window_seconds=3600, clock=FakeClock()))
    for _ in range(3):
        assert run(client, mine, "trap_offer").status_code == 200
    assert client.post("/agent/run", json={"mandate_id": mine}, headers=bearer(TEST_USER_EMAIL)).status_code == 200


def test_a_scenario_that_would_approve_still_buys_nothing(client, mine, monkeypatch):
    """Si un escenario llegara a APPROVE (p. ej. un firewall que no lo atrape), igual
    no se compra: es verificación sin efecto."""
    monkeypatch.setattr(verify_api, "auditoria_cognitiva_firewall", lambda **kwargs: {"veredicto": "APPROVE"})
    result = run(client, mine, "trap_offer").json()
    assert result["verification"]["verdict"] == "APPROVE"
    assert result["purchase_completed"] is False
    assert live_state(mine)["uses_count"] == 0
    assert "no se realizó ninguna compra" in result["verification"]["human_readable"]


def test_scenario_events_cannot_be_disputed_as_purchases(client, mine):
    run(client, mine, "trap_offer")
    attempt_id = next(event["attempt_id"] for event in get_trail_events(mandate_id=mine) if event["type"] == "scenario_verification")
    claim = client.post("/disputes/file", json={"attempt_id": attempt_id, "mandate_id": mine}, headers=bearer(TEST_USER_EMAIL)).json()
    # No hay verificación de COMPRA de ese intento: el árbitro no lo trata como un cargo aprobado.
    assert claim["liable_party"] == "MERCHANT" and claim["verdict"] == "MERCHANT_LIABLE_UNVERIFIED"
