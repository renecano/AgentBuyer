"""Integración end-to-end: /verify con el engine REAL ya cableado.

Cubre lo que los tests unitarios del engine no pueden ver:
  - el orden seguridad-primero (firma, agente, status) antes del engine
  - que uses_count/amount_spent se actualizan SOLO al aprobar
  - que revocar corta la siguiente compra (trial by fire)
  - que el seed de la demo carga al startup

El store es memoria a nivel de módulo, así que cada test limpia el estado
y crea su propio mandato — ningún test depende de otro.
"""
import pytest
from fastapi.testclient import TestClient

from audit.log import AUDIT_TRAIL
from api.main import app
from core import mandate_store

ENGINE_RULES = {"amount", "category", "merchant", "uses", "condition.price_below"}
SECURITY_RULES = {"signature", "agent_identity", "status"}


@pytest.fixture()
def client():
    # El context manager dispara el startup (que carga el seed); limpiamos
    # después para que cada test empiece con memoria vacía y estado propio.
    with TestClient(app) as test_client:
        mandate_store.MANDATES.clear()
        AUDIT_TRAIL.clear()
        yield test_client
    mandate_store.MANDATES.clear()
    AUDIT_TRAIL.clear()


def make_mandate(mandate_id: str = "mnd_test_001", **overrides) -> dict:
    mandate = {
        "mandate_id": mandate_id,
        "human": {"id": "hum_test", "name": "Test Human"},
        "agent": {"id": "agt_test"},
        "constraints": {
            "max_amount_per_purchase": 150.00,
            "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"],
            "max_uses": 3,
            "conditions": [{"type": "price_below", "value": 150.00}],
        },
        "signature": "firma-de-prueba",
    }
    mandate.update(overrides)
    return mandate


def make_attempt(
    mandate_id: str = "mnd_test_001",
    agent_id: str = "agt_test",
    amount: float = 130.0,
    category: str = "travel.flights",
    merchant_id: str = "mch_vuelaya",
    attempt_id: str = "att_test_001",
) -> dict:
    return {
        "attempt_id": attempt_id,
        "mandate_id": mandate_id,
        "presented_by_agent": agent_id,
        "purchase": {
            "merchant_id": merchant_id,
            "category": category,
            "amount": amount,
            "currency": "USD",
            "metadata": {"price": amount},
        },
    }


def create_mandate(client: TestClient, mandate: dict) -> None:
    response = client.post("/mandates", json=mandate)
    assert response.status_code == 201, response.text


def rules_of(result: dict) -> list[str]:
    return [check["rule"] for check in result["checks"]]


# ── Camino feliz ─────────────────────────────────────────────────────────────

def test_approve_runs_security_then_engine_and_updates_state(client):
    create_mandate(client, make_mandate())
    response = client.post("/verify", json=make_attempt())
    result = response.json()

    assert response.status_code == 200
    assert result["verdict"] == "APPROVE"
    # Seguridad primero, engine después — y todas las reglas presentes.
    rules = rules_of(result)
    assert rules[:3] == ["signature", "agent_identity", "status"]
    assert set(rules[3:]) == ENGINE_RULES

    # El estado vivo se actualizó tras aprobar.
    live_state = client.get("/mandates/mnd_test_001").json()["live_state"]
    assert live_state["uses_count"] == 1
    assert live_state["amount_spent"] == 130.0


def test_uses_exhaust_after_three_approvals(client):
    create_mandate(client, make_mandate())
    for n in range(3):
        result = client.post(
            "/verify", json=make_attempt(attempt_id=f"att_{n}")
        ).json()
        assert result["verdict"] == "APPROVE", result

    fourth = client.post("/verify", json=make_attempt(attempt_id="att_3")).json()
    assert fourth["verdict"] == "ESCALATE"
    failed = {c["rule"] for c in fourth["checks"] if not c["pass"]}
    assert failed == {"uses"}
    # El intento escalado no consumió un uso.
    assert client.get("/mandates/mnd_test_001").json()["live_state"]["uses_count"] == 3


def test_escalate_does_not_touch_live_state(client):
    create_mandate(client, make_mandate())
    result = client.post("/verify", json=make_attempt(amount=300.0)).json()

    assert result["verdict"] == "ESCALATE"
    live_state = client.get("/mandates/mnd_test_001").json()["live_state"]
    assert live_state["uses_count"] == 0
    assert live_state["amount_spent"] == 0


# ── Seguridad primero: el engine ni se entera ────────────────────────────────

def test_revoked_mandate_rejects_before_engine(client):
    """El trial by fire: revocar y la SIGUIENTE compra muere en status."""
    create_mandate(client, make_mandate())
    assert client.post("/verify", json=make_attempt()).json()["verdict"] == "APPROVE"

    assert client.post("/mandates/mnd_test_001/revoke").status_code == 200

    result = client.post("/verify", json=make_attempt(attempt_id="att_post_revoke")).json()
    assert result["verdict"] == "REJECT"
    rules = rules_of(result)
    assert "status" in rules
    # Ninguna regla del engine fue evaluada: se corta antes.
    assert not ENGINE_RULES.intersection(rules)


def test_wrong_agent_rejects(client):
    create_mandate(client, make_mandate())
    result = client.post(
        "/verify", json=make_attempt(agent_id="agt_impostor")
    ).json()
    assert result["verdict"] == "REJECT"
    failed = {c["rule"] for c in result["checks"] if not c["pass"]}
    assert failed == {"agent_identity"}
    assert not ENGINE_RULES.intersection(rules_of(result))


def test_missing_signature_rejects(client):
    create_mandate(client, make_mandate(signature=""))
    result = client.post("/verify", json=make_attempt()).json()
    assert result["verdict"] == "REJECT"
    failed = {c["rule"] for c in result["checks"] if not c["pass"]}
    assert failed == {"signature"}


def test_unknown_mandate_rejects(client):
    result = client.post(
        "/verify", json=make_attempt(mandate_id="mnd_no_existe")
    ).json()
    assert result["verdict"] == "REJECT"
    assert rules_of(result) == ["mandate_exists"]


# ── Contratos del endpoint ───────────────────────────────────────────────────

def test_non_dict_purchase_is_422_before_engine(client):
    create_mandate(client, make_mandate())
    attempt = make_attempt()
    attempt["purchase"] = "no-soy-un-dict"
    response = client.post("/verify", json=attempt)
    assert response.status_code == 422


def test_engine_escalation_reports_engine_checks_alongside_security(client):
    """En un ESCALATE la respuesta combina los checks de seguridad (pass)
    con los del engine — el trail completo para el humano que decide."""
    create_mandate(client, make_mandate())
    result = client.post("/verify", json=make_attempt(category="hotel")).json()

    assert result["verdict"] == "ESCALATE"
    by_rule = {c["rule"]: c["pass"] for c in result["checks"]}
    for rule in SECURITY_RULES:
        assert by_rule[rule] is True
    assert by_rule["category"] is False


def test_verification_events_are_recorded(client):
    create_mandate(client, make_mandate())
    client.post("/verify", json=make_attempt())
    client.post("/verify", json=make_attempt(amount=300.0, attempt_id="att_2"))

    verdicts = [event["verdict"] for event in AUDIT_TRAIL if event["type"] == "verification"]
    assert verdicts == ["APPROVE", "ESCALATE"]


# ── Seed de la demo ──────────────────────────────────────────────────────────

def test_seed_mandate_loads_on_startup():
    """El startup carga shared/seed_mandates.json — Marta existe sin POST previo."""
    mandate_store.MANDATES.clear()
    with TestClient(app) as fresh_client:
        response = fresh_client.get("/mandates/mnd_marta_001")
        assert response.status_code == 200
        record = response.json()
        assert record["live_state"]["status"] == "active"
        assert record["mandate"]["constraints"]["max_uses"] == 3
    mandate_store.MANDATES.clear()
    AUDIT_TRAIL.clear()
