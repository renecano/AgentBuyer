"""Paso 5.1 por HTTP: dinero en centavos de punta a punta, estados que no compran y
el agente que no intenta lo que no cabe. (Las reglas puras del engine y la gramática
están en engine/tests/test_evaluator.py.)"""
import json

import pytest
from fastapi.testclient import TestClient

from api.main import app
from audit.log import get_trail_events, reset_trail
from core import mandate_store, merchant_search, owner_keys
from core.auth_tokens import create_access_token
from core.mandate_store import MANDATES, apply_approved_purchase
from tests.conftest import TEST_USER_EMAIL, verify_as_service

pytestmark = pytest.mark.usefixtures("service_key")


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: "[]")
    mandate_store.mandate_store.clear()
    owner_keys.clear()
    reset_trail()
    with TestClient(app) as test_client:
        yield test_client
    mandate_store.mandate_store.clear()
    owner_keys.clear()
    reset_trail()


@pytest.fixture()
def mine(signed_poster) -> str:
    signed_poster.create({
        "mandate_id": "mnd_money",
        "human": {"id": "hum_x", "display_name": "X"},
        "agent": {"id": "agt_saturday"},
        "search_fields": {"origin": "BUE", "destination": "COR", "departure_date": "2026-12-05"},
        "constraints": {
            "max_amount_per_purchase": "150", "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"], "max_uses": 3,
            "conditions": [{"type": "price_below", "value": "140"}],
        },
    })
    return "mnd_money"


def headers() -> dict:
    return {"Authorization": f"Bearer {create_access_token(TEST_USER_EMAIL)}"}


def attempt(mandate_id: str, attempt_id: str, cents: int) -> dict:
    return {"attempt_id": attempt_id, "mandate_id": mandate_id, "presented_by_agent": "agt_saturday",
            "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount_cents": cents,
                         "currency": "USD", "metadata": {"price_cents": cents}}}


def offers(*prices) -> str:
    return json.dumps([{"merchant": "VuelaYa", "price": price, "currency": "USD", "details": f"offer {price}",
                        "url": f"https://vuelaya.example/{index}"} for index, price in enumerate(prices)])


# ── Dinero exacto ───────────────────────────────────────────────────────────

def test_signed_mandate_is_stored_in_cents(client, mine):
    constraints = MANDATES[mine]["mandate"]["constraints"]
    assert constraints["max_amount_per_purchase_cents"] == 15000
    assert constraints["conditions"] == [{"type": "price_below", "value_cents": 14000}]
    assert "max_amount_per_purchase" not in constraints


def test_spend_accumulates_exactly_in_cents(client, mine):
    """10 + 20 céntimos son exactamente 30 (con float: 0.1 + 0.2 = 0.30000000000000004)."""
    for index, cents in enumerate((10, 20)):
        assert verify_as_service(client, attempt(mine, f"att_{index}", cents)).json()["verdict"] == "APPROVE"
    assert MANDATES[mine]["live_state"]["amount_spent_cents"] == 30


@pytest.mark.parametrize("amount", [130.0, 13000.5, -100, 0, "13000", True])
def test_verify_rejects_amounts_that_are_not_positive_integer_cents(client, mine, amount):
    result = verify_as_service(client, attempt(mine, "att_bad", amount)).json()
    assert result["verdict"] == "REJECT"
    assert MANDATES[mine]["live_state"]["uses_count"] == 0


@pytest.mark.parametrize("amount", [130.0, -1, 0, True, "100"])
def test_apply_approved_purchase_refuses_anything_but_positive_cents(client, mine, amount):
    with pytest.raises(ValueError):
        apply_approved_purchase(mine, amount)
    assert MANDATES[mine]["live_state"] == {"status": "active", "uses_count": 0, "amount_spent_cents": 0, "revoked_at": None}


def test_seed_is_loaded_in_cents(client, active_seed):
    with TestClient(app):
        constraints = MANDATES[active_seed["mandate_id"]]["mandate"]["constraints"]
    assert constraints["max_amount_per_purchase_cents"] == 15000
    assert constraints["monthly_budget_cents"] == 50000
    assert constraints["conditions"] == [{"type": "price_below", "value_cents": 15000}]
    assert "max_amount_per_tx" not in constraints


# ── Solo un mandato ACTIVO compra (ambas líneas) ────────────────────────────

def test_paused_mandate_is_rejected_on_the_react_line(client, mine):
    """Antes del 5.1, /verify solo miraba revoked/expired: un mandato PAUSADO aprobaba."""
    assert client.post(f"/mandates/{mine}/pause", headers=headers()).status_code == 200
    result = verify_as_service(client, attempt(mine, "att_paused", 10000)).json()
    assert result["verdict"] == "REJECT"
    assert next(check for check in result["checks"] if check["rule"] == "status")["detail"] == "mandato pausado"
    assert MANDATES[mine]["live_state"]["uses_count"] == 0

    assert client.post(f"/mandates/{mine}/resume", headers=headers()).status_code == 200
    assert verify_as_service(client, attempt(mine, "att_resumed", 10000)).json()["verdict"] == "APPROVE"


@pytest.mark.parametrize("action", ["pause", "revoke"])
def test_non_active_mandate_is_rejected_on_the_strict_line(client, action):
    from core.agent_loop import PurchasingAgent
    from core.merchant import vuelaya_merchant
    from mandate.issue import create_mandate
    from mandate.sign import generate_keypair
    from shared.schemas import VerificationStatus

    h_priv, h_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    strict = create_mandate(human_id="hum_s", human_privkey=h_priv, human_pubkey=h_pub, agent_id="agent_s",
                            agent_pubkey=a_pub, max_amount_per_tx=150.0, allowed_categories=["travel.flights"])
    mandate_store.mandate_store.save_mandate(strict)
    getattr(mandate_store.mandate_store, f"{action}_mandate")(strict.mandate_id)

    agent = PurchasingAgent("agent_s", a_priv, a_pub)
    _, result = agent.attempt_purchase(mandate_store.mandate_store.get_mandate(strict.mandate_id),
                                       vuelaya_merchant.get_item("FLIGHT_COR_130"), merchant=vuelaya_merchant)
    assert result.status == VerificationStatus.REJECTED


# ── El agente no intenta lo que no cabe ─────────────────────────────────────

def test_agent_does_not_attempt_when_no_offer_fits(client, mine, monkeypatch):
    """Antes: si ninguna oferta cabía, el agente intentaba igual la más barata."""
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: offers(160, 200))
    run = client.post("/agent/run", json={"mandate_id": mine}, headers=headers()).json()

    assert run["no_fit"] is True and run["selected_flight"] is None and run["purchase_completed"] is False
    assert "attempt" not in run and "verification" not in run
    assert [event["type"] for event in get_trail_events(mandate_id=mine) if event["type"] == "verification"] == []
    assert [offer["price_cents"] for offer in run["flights_seen"]] == [16000, 20000]


def test_agent_uses_the_same_price_rule_as_the_engine(client, mine, monkeypatch):
    """price_below es ESTRICTO (<) en el agente y en el engine: 140.00 no cabe en
    price_below 140, así que el agente elige la de 139.99 aunque haya una igual al límite."""
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: offers(140, 139.99))
    run = client.post("/agent/run", json={"mandate_id": mine}, headers=headers()).json()
    assert run["selected_flight"]["price_cents"] == 13999
    assert run["verification"]["verdict"] == "APPROVE"

    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: offers(140))
    only_at_limit = client.post("/agent/run", json={"mandate_id": mine}, headers=headers()).json()
    assert only_at_limit["no_fit"] is True  # antes: <= en el agente → intentaba y el engine escalaba


def test_agent_attempts_are_in_cents(client, mine, monkeypatch):
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: offers(120.5))
    run = client.post("/agent/run", json={"mandate_id": mine}, headers=headers()).json()
    purchase = run["attempt"]["purchase"]
    assert purchase["amount_cents"] == 12050 and purchase["metadata"]["price_cents"] == 12050
    assert "amount" not in purchase
    assert MANDATES[mine]["live_state"]["amount_spent_cents"] == 12050
