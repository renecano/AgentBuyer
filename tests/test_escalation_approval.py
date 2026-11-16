"""Integración de la revisión humana de escalaciones:
POST /mandates/{mandate_id}/approve_escalation."""
import pytest
from fastapi.testclient import TestClient
from tests.conftest import verify_as_service

from api.main import app
from audit.log import get_trail_events
from core import mandate_store

# 4.2 (P-03): /verify es la verificación del comercio/agente: credencial `service`.
pytestmark = pytest.mark.usefixtures("service_key")

MANDATE_ID = "mnd_esc_001"


@pytest.fixture()
def client(auth_headers):
    # Autenticado como usuario real: crear mandatos exige token (POST /mandates).
    with TestClient(app, headers=auth_headers) as test_client:
        mandate_store.mandate_store.clear()
        yield test_client
    mandate_store.mandate_store.clear()


def make_mandate() -> dict:
    return {
        "mandate_id": MANDATE_ID,
        "human": {"id": "hum_test", "name": "Test"},
        "agent": {"id": "agt_test"},
        "constraints": {
            "max_amount_per_purchase": 150.00,
            "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"],
            "max_uses": 3,
            "conditions": [{"type": "price_below", "value": 150.00}],
        },
        # 3.5: lo firma el titular (signed_poster, como el navegador).
    }


def escalate_attempt(client: TestClient, attempt_id: str = "att_esc_1", amount_cents: int = 30000) -> dict:
    """Crea un intento que escala (monto sobre el límite) y devuelve el resultado."""
    result = verify_as_service(client, {
        "attempt_id": attempt_id,
        "mandate_id": MANDATE_ID,
        "presented_by_agent": "agt_test",
        "purchase": {
            "merchant_id": "mch_vuelaya",
            "category": "travel.flights",
            "amount_cents": amount_cents,
            "currency": "USD",
            "metadata": {"price_cents": amount_cents},
        },
    }).json()
    assert result["verdict"] == "ESCALATE", result
    return result


def review(client: TestClient, decision: str, attempt_id: str = "att_esc_1"):
    return client.post(
        f"/mandates/{MANDATE_ID}/approve_escalation",
        json={"purchase_attempt_id": attempt_id, "decision": decision},
    )


def live_state(client: TestClient) -> dict:
    return client.get(f"/mandates/{MANDATE_ID}").json()["live_state"]


def test_human_approves_escalation_updates_state_and_audit(client, signed_poster):
    signed_poster.create(make_mandate())
    escalate_attempt(client, amount_cents=30000)
    assert live_state(client)["uses_count"] == 0  # la escalación no tocó nada

    response = review(client, "approve")
    assert response.status_code == 200
    result = response.json()
    assert result["verdict"] == "APPROVE"
    assert result["checks"][0]["rule"] == "human_review" and result["checks"][0]["pass"]

    # Estado actualizado exactamente como un APPROVE normal.
    state = live_state(client)
    assert state["uses_count"] == 1
    assert state["amount_spent_cents"] == 30000

    # El trail cuenta la historia completa: escalada -> aprobada por humano.
    types = [e["type"] for e in get_trail_events()]
    assert "verification" in types and "human_override_approved" in types
    override = next(e for e in get_trail_events() if e["type"] == "human_override_approved")
    assert override["attempt_id"] == "att_esc_1"
    assert "amount" in override["escalation_reason"]["failed_rules"]
    assert "APROBADA" in override["summary"]


def test_human_declines_no_state_change(client, signed_poster):
    signed_poster.create(make_mandate())
    escalate_attempt(client)

    response = review(client, "decline")
    assert response.status_code == 200
    assert response.json()["verdict"] == "REJECT"

    state = live_state(client)
    assert state["uses_count"] == 0
    assert state["amount_spent_cents"] == 0

    override = next(e for e in get_trail_events() if e["type"] == "human_override_declined")
    assert "RECHAZADA" in override["summary"]


def test_cannot_approve_on_revoked_mandate(client, signed_poster):
    """Revocado después de escalar: la revisión humana no puede pasar por encima."""
    signed_poster.create(make_mandate())
    escalate_attempt(client)
    client.post(f"/mandates/{MANDATE_ID}/revoke")

    response = review(client, "approve")
    assert response.status_code == 409
    assert "revocado" in response.json()["detail"] or "revoked" in response.json()["detail"]

    # Cero cambios de estado y ningún evento de override en el trail.
    assert live_state(client)["uses_count"] == 0
    assert not any(e["type"].startswith("human_override") for e in get_trail_events())


def test_unknown_attempt_id_is_clean_404(client, signed_poster):
    signed_poster.create(make_mandate())
    response = review(client, "approve", attempt_id="att_no_existe")
    assert response.status_code == 404
    assert "intento" in response.json()["detail"]


def test_cannot_review_twice(client, signed_poster):
    signed_poster.create(make_mandate())
    escalate_attempt(client)
    assert review(client, "approve").status_code == 200
    second = review(client, "decline")
    assert second.status_code == 409
    assert live_state(client)["uses_count"] == 1  # el segundo intento no tocó nada


def test_cannot_review_an_approved_attempt(client, signed_poster):
    """Solo lo escalado admite revisión — un APPROVE normal no se 're-aprueba'."""
    signed_poster.create(make_mandate())
    result = verify_as_service(client, {
        "attempt_id": "att_ok_1",
        "mandate_id": MANDATE_ID,
        "presented_by_agent": "agt_test",
        "purchase": {
            "merchant_id": "mch_vuelaya", "category": "travel.flights",
            "amount_cents": 10000, "currency": "USD", "metadata": {"price_cents": 10000},
        },
    }).json()
    assert result["verdict"] == "APPROVE"
    assert review(client, "approve", attempt_id="att_ok_1").status_code == 409


def test_invalid_body_is_422(client, signed_poster):
    signed_poster.create(make_mandate())
    assert review(client, "quizas").status_code == 422
    response = client.post(
        f"/mandates/{MANDATE_ID}/approve_escalation", json={"decision": "approve"}
    )
    assert response.status_code == 422
