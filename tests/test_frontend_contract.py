"""Contrato de API que consume el frontend React (frontend/src) — red de seguridad
para refactorizar el backend sin romper la UI.

Estos tests congelan la FORMA de las respuestas tal como las leen App.tsx,
AccountView.tsx y AuditView.tsx hoy. No validan que la lógica de negocio sea
correcta: cuando un test fija un veredicto o un estado es solo para garantizar
que se ejerce la rama cuya forma se quiere congelar.

Datos: el mandato semilla shared/seed_mandates.json (mnd_marta_001), cargado por
el lifespan de la app. La búsqueda web SIEMPRE va mockeada (sin red).
"""
import json
from datetime import datetime
from numbers import Real

import pytest
from fastapi.testclient import TestClient

from api.main import app
from audit.log import reset_trail
from core import mandate_store, merchant_search

SEED_MANDATE_ID = "mnd_marta_001"
SEED_AGENT_ID = "agt_saturday"
VERDICTS = {"APPROVE", "ESCALATE", "REJECT"}
LIVE_STATUSES = {"active", "revoked", "expired"}
LIABLE_PARTIES = {"HUMAN", "MERCHANT", "FRAUDSTER", "AGENT"}

WEB_OFFERS = [
    {"merchant": "VuelaYa", "price": 130.0, "currency": "USD",
     "details": "BUE-COR directo", "url": "https://vuelaya.example/1"},
    {"merchant": "VuelaYa", "price": 140.0, "currency": "USD",
     "details": "BUE-COR 1 escala", "url": "https://vuelaya.example/2"},
]


# ── Aislamiento ──────────────────────────────────────────────────────────────

def _clear_backend_state() -> None:
    # Único punto acoplado a internals del backend: si el refactor cambia dónde
    # vive el estado, solo hay que ajustar esta función, no las aserciones.
    mandate_store.MANDATES.clear()
    reset_trail()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Por defecto la búsqueda web no devuelve nada (nunca se llama a OpenAI)."""
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: "[]")


@pytest.fixture()
def client(active_seed):
    # active_seed (tests/conftest.py): el seed expira relativo a "ahora", así cada
    # test ejerce la rama que dice congelar sin depender de la fecha del sistema.
    _clear_backend_state()
    with TestClient(app) as test_client:  # el lifespan carga el seed
        yield test_client
    _clear_backend_state()


@pytest.fixture()
def web_offers(monkeypatch):
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: json.dumps(WEB_OFFERS))


# ── Aserciones de forma (espejo de los tipos de frontend/src) ────────────────

def _is_number(value) -> bool:
    return isinstance(value, Real) and not isinstance(value, bool)


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_iso_timestamp(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def assert_mandate_record(record: dict) -> None:
    """App.tsx `MandateRecord` + AccountView.tsx `MandateRecord`."""
    assert isinstance(record, dict)
    assert {"mandate", "live_state"} <= set(record)

    mandate = record["mandate"]
    assert isinstance(mandate["mandate_id"], str) and mandate["mandate_id"]

    human = mandate["human"]
    assert isinstance(human, dict)
    for key in ("id", "display_name"):
        assert isinstance(human[key], str)
    # App.tsx lee human.name como opcional: el seed lo trae, MandateCreator no.
    assert human.get("name") is None or isinstance(human["name"], str)

    agent = mandate["agent"]
    assert isinstance(agent, dict)
    assert isinstance(agent["id"], str)

    constraints = mandate["constraints"]
    assert isinstance(constraints, dict)
    assert _is_number(constraints["max_amount_per_purchase"])
    assert isinstance(constraints["currency"], str)
    assert isinstance(constraints["allowed_categories"], list)
    assert all(isinstance(item, str) for item in constraints["allowed_categories"])
    assert isinstance(constraints["allowed_merchants"], list)
    assert all(isinstance(item, str) for item in constraints["allowed_merchants"])
    assert _is_int(constraints["max_uses"])
    assert isinstance(constraints["conditions"], list)
    for condition in constraints["conditions"]:
        assert isinstance(condition["type"], str)
        assert _is_number(condition["value"])

    search_fields = mandate["search_fields"]
    assert isinstance(search_fields, dict)
    for key in ("origin", "destination", "departure_date"):
        assert isinstance(search_fields[key], str)

    live_state = record["live_state"]
    assert isinstance(live_state, dict)
    assert isinstance(live_state["status"], str)
    assert live_state["status"] == live_state["status"].lower()
    assert live_state["status"] in LIVE_STATUSES
    assert _is_int(live_state["uses_count"])
    assert _is_number(live_state["amount_spent"])
    assert live_state["revoked_at"] is None or _is_iso_timestamp(live_state["revoked_at"])


def assert_verification(verification: dict) -> None:
    """App.tsx `Verification` + `Check`."""
    assert isinstance(verification, dict)
    assert isinstance(verification["attempt_id"], str)
    assert isinstance(verification["mandate_id"], str)
    assert verification["verdict"] in VERDICTS
    assert isinstance(verification["human_readable"], str)
    checks = verification["checks"]
    assert isinstance(checks, list) and checks
    for check in checks:
        assert isinstance(check["rule"], str)
        assert isinstance(check["pass"], bool)
        assert isinstance(check["detail"], str)


def assert_flight(flight: dict) -> None:
    """App.tsx `Flight`."""
    assert isinstance(flight["id"], str)
    assert isinstance(flight["route"], str)
    assert _is_number(flight["price"])
    assert isinstance(flight["category"], str)
    assert isinstance(flight["merchant_id"], str)
    assert isinstance(flight["merchant"], str)
    assert isinstance(flight["details"], str)
    assert isinstance(flight["url"], str)
    assert flight["source"] == "web"


def assert_audit_events(events: list) -> None:
    """AuditView.tsx / AccountView.tsx `AuditEvent` (newest first)."""
    assert isinstance(events, list)
    for event in events:
        assert isinstance(event["event_id"], str) and event["event_id"]
        assert _is_iso_timestamp(event["timestamp"])
        assert isinstance(event["type"], str)
        assert isinstance(event["mandate_id"], str)
        assert isinstance(event["summary"], str)
        # verdict y attempt_id son opcionales; verdict puede venir null (DISPUTE_RESOLVED).
        assert event.get("verdict") is None or event["verdict"] in VERDICTS
        assert event.get("attempt_id") is None or isinstance(event["attempt_id"], str)
    timestamps = [datetime.fromisoformat(event["timestamp"]) for event in events]
    assert timestamps == sorted(timestamps, reverse=True), "el trail debe venir del más nuevo al más viejo"


def assert_dispute(dispute: dict) -> None:
    """AccountView.tsx `DisputeClaim`."""
    assert isinstance(dispute["dispute_id"], str) and dispute["dispute_id"]
    assert isinstance(dispute["attempt_id"], str)
    assert isinstance(dispute["verdict"], str)
    assert dispute["liable_party"] in LIABLE_PARTIES
    assert isinstance(dispute["refund_issued"], bool)
    assert isinstance(dispute["explanation"], str)


# ── Helpers de escenario (mismos payloads que envía React) ──────────────────

def demo_attempt(attempt_id: str, amount: float, mandate_id: str = SEED_MANDATE_ID) -> dict:
    """Mismo shape que demoPurchase() en App.tsx."""
    return {
        "attempt_id": attempt_id,
        "mandate_id": mandate_id,
        "presented_by_agent": SEED_AGENT_ID,
        "purchase": {
            "merchant_id": "mch_vuelaya",
            "category": "travel.flights",
            "amount": amount,
            "currency": "USD",
            "description": "Contract test flight",
            "metadata": {"price": amount, "source": "demo"},
        },
    }


def mandate_creator_payload(mandate_id: str = "mnd_test_user_contract") -> dict:
    """Mismo payload que submitMandate() en MandateCreator.tsx (categoría vuelos)."""
    return {
        "mandate_id": mandate_id,
        "human": {
            "id": "hum_test_user_contract",
            "display_name": "Test User",
            "id_document": "XXXXXX",
            "phone": "+520000000000",
            "email": "test.user@example.com",
        },
        "agent": {"id": SEED_AGENT_ID, "display_name": "Saturday"},
        "search_fields": {"origin": "BUE", "destination": "COR", "departure_date": "2026-10-01"},
        "constraints": {
            "max_amount_per_purchase": 150,
            "currency": "USD",
            "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"],
            "max_uses": 3,
            "conditions": [{"type": "price_below", "value": 150}],
            "off_session_consent": True,
        },
        "authentication": {
            "passkey_biometrics": "verified_webauthn_touch_id",
            "receipt_email": "test.user@example.com",
        },
        "payment_token": {
            "token_id": "vtok_contract",
            "token_type": "SCOPED_VIRTUAL_TOKEN",
            "masked_card": "•••• 4242",
            "bank_issuer": "Stripe Elements / Galicia AI Payments",
        },
        "valid_until": "2026-09-30",
        "signature": "ed25519_passkey_signed_jwt_token",
    }


def run_agent(client: TestClient) -> dict:
    """Mismo body que runAgent() en App.tsx."""
    record = client.get(f"/mandates/{SEED_MANDATE_ID}").json()
    response = client.post("/agent/run", json={
        "mandate_id": SEED_MANDATE_ID,
        "search_fields": record["mandate"]["search_fields"],
    })
    assert response.status_code == 200, response.text
    return response.json()


def populate_trail(client: TestClient) -> None:
    """Genera los tipos de evento que la UI renderiza: agent_run,
    verification, purchase_completed, DISPUTE_*, revocation."""
    run = run_agent(client)
    assert client.post("/verify", json=demo_attempt("att_contract_escalate", 300.0)).status_code == 200
    assert client.post("/disputes/file", json={
        "attempt_id": run["attempt_id"],
        "mandate_id": SEED_MANDATE_ID,
        "claimant_id": "hum_marta",
        "reason": "I don't recognize this charge.",
    }).status_code == 200
    assert client.post(f"/mandates/{SEED_MANDATE_ID}/revoke").status_code == 200


# ── GET /mandates/{id} ───────────────────────────────────────────────────────

def test_get_mandate_returns_mandate_record(client):
    response = client.get(f"/mandates/{SEED_MANDATE_ID}")
    assert response.status_code == 200
    assert_mandate_record(response.json())


# ── POST /mandates (MandateCreator.tsx:404) ─────────────────────────────────

def test_create_mandate_from_mandate_creator_shape(client):
    """Forma ACTUAL: 201 y el registro {mandate, live_state} con el payload
    devuelto tal cual. React ignora el body: solo mira response.ok y navega con
    el mandate_id que generó él mismo, así que ese id debe quedar consultable."""
    payload = mandate_creator_payload()
    response = client.post("/mandates", json=payload)

    assert response.status_code == 201, response.text
    record = response.json()
    assert_mandate_record(record)
    assert record["mandate"] == payload  # hoy el mandato se guarda y devuelve sin transformar
    assert record["live_state"] == {"status": "active", "uses_count": 0, "amount_spent": 0, "revoked_at": None}

    # El id del cliente es el que usa Mission Control a continuación (GET /mandates/{id}).
    follow_up = client.get(f"/mandates/{payload['mandate_id']}")
    assert follow_up.status_code == 200
    assert_mandate_record(follow_up.json())

    # Un id repetido es un error no-ok con `detail` (React muestra "El sistema respondió 409").
    duplicate = client.post("/mandates", json=payload)
    assert duplicate.status_code == 409
    assert isinstance(duplicate.json()["detail"], str)


# ── POST /mandates/{id}/approve_escalation (App.tsx:336) ────────────────────

EXPENSIVE_OFFERS = [
    {"merchant": "VuelaYa", "price": 300.0, "currency": "USD",
     "details": "BUE-COR premium", "url": "https://vuelaya.example/premium"},
]


@pytest.mark.parametrize(
    "decision, expected_verdict",
    [("approve", "APPROVE"), ("decline", "REJECT")],
    ids=["approve", "decline"],
)
def test_approve_escalation_shape(client, monkeypatch, decision, expected_verdict):
    """Mismo flujo que React: /agent/run escala, y reviewEscalation() envía
    {purchase_attempt_id, decision} esperando la forma `verification`."""
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: json.dumps(EXPENSIVE_OFFERS))
    run = run_agent(client)
    assert run["verification"]["verdict"] == "ESCALATE"  # garantiza que hay algo que revisar

    url = f"/mandates/{SEED_MANDATE_ID}/approve_escalation"
    body = {"purchase_attempt_id": run["attempt_id"], "decision": decision}
    response = client.post(url, json=body)

    assert response.status_code == 200, response.text
    verification = response.json()
    assert_verification(verification)
    assert verification["verdict"] == expected_verdict  # garantiza cada rama
    assert verification["attempt_id"] == run["attempt_id"]
    assert verification["mandate_id"] == SEED_MANDATE_ID

    # Los errores llegan como no-ok con `detail` string, que App.tsx traduce y muestra.
    repeated = client.post(url, json=body)
    assert repeated.status_code == 409
    assert isinstance(repeated.json()["detail"], str)

    unknown = client.post(url, json={"purchase_attempt_id": "att_contract_unknown", "decision": decision})
    assert unknown.status_code == 404
    assert isinstance(unknown.json()["detail"], str)


# ── POST /agent/run ──────────────────────────────────────────────────────────

def test_agent_run_with_offers_shape(client, web_offers):
    run = run_agent(client)

    assert isinstance(run["attempt_id"], str)
    assert isinstance(run["flights_seen"], list) and run["flights_seen"]
    for flight in run["flights_seen"]:
        assert_flight(flight)
    assert run["selected_flight"] is not None  # garantiza la rama con selección
    assert_flight(run["selected_flight"])
    assert_verification(run["verification"])
    assert isinstance(run["purchase_completed"], bool)
    assert isinstance(run["human_readable"], str)
    # Hoy "no_offers" solo existe en la rama sin ofertas (React lo trata como opcional).
    assert run.get("no_offers") in (None, False)


def test_agent_run_without_offers_shape(client):
    run = run_agent(client)  # no_network devuelve [] → rama sin ofertas

    assert run["no_offers"] is True
    assert run["attempt_id"] is None
    assert run["flights_seen"] == []
    assert run["selected_flight"] is None
    assert run["purchase_completed"] is False
    assert isinstance(run["human_readable"], str)
    assert "verification" not in run


# ── POST /verify ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "attempt, expected_verdict",
    [
        (demo_attempt("att_contract_approve", 100.0), "APPROVE"),
        (demo_attempt("att_contract_escalate", 300.0), "ESCALATE"),
        (demo_attempt("att_contract_reject", 100.0, mandate_id="mnd_contract_missing"), "REJECT"),
    ],
    ids=["approve", "escalate", "reject"],
)
def test_verify_returns_verification_shape(client, attempt, expected_verdict):
    response = client.post("/verify", json=attempt)
    assert response.status_code == 200
    verification = response.json()
    assert_verification(verification)
    assert verification["verdict"] == expected_verdict  # garantiza que se ejerce cada rama


# ── POST /mandates/{id}/revoke y /reset ──────────────────────────────────────

def test_revoke_returns_mandate_record(client):
    response = client.post(f"/mandates/{SEED_MANDATE_ID}/revoke")
    assert response.status_code == 200
    assert_mandate_record(response.json())


def test_reset_returns_mandate_record(client):
    client.post(f"/mandates/{SEED_MANDATE_ID}/revoke")
    response = client.post(f"/mandates/{SEED_MANDATE_ID}/reset")
    assert response.status_code == 200
    assert_mandate_record(response.json())


# ── GET /audit y /audit/{id} ─────────────────────────────────────────────────

def test_audit_trail_shape(client, web_offers):
    populate_trail(client)
    response = client.get("/audit")
    assert response.status_code == 200
    events = response.json()
    assert events  # hay eventos de todos los tipos que genera populate_trail
    assert_audit_events(events)


def test_mandate_audit_trail_shape(client, web_offers):
    populate_trail(client)
    response = client.get(f"/audit/{SEED_MANDATE_ID}")
    assert response.status_code == 200
    events = response.json()
    assert events
    assert_audit_events(events)
    assert all(event["mandate_id"] == SEED_MANDATE_ID for event in events)


# ── POST /disputes/file ──────────────────────────────────────────────────────

def test_dispute_on_completed_purchase_shape(client, web_offers):
    run = run_agent(client)
    response = client.post("/disputes/file", json={
        "attempt_id": run["attempt_id"],
        "mandate_id": SEED_MANDATE_ID,
        "claimant_id": "hum_marta",
        "reason": "I don't recognize this charge.",
    })
    assert response.status_code == 200
    assert_dispute(response.json())


def test_dispute_on_unknown_attempt_shape(client):
    response = client.post("/disputes/file", json={
        "attempt_id": "att_contract_unknown",
        "mandate_id": SEED_MANDATE_ID,
        "claimant_id": "hum_marta",
        "reason": "I don't recognize this charge.",
    })
    assert response.status_code == 200
    assert_dispute(response.json())
