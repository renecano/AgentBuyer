"""Dueño de mandato (owner_email): dato INTERNO, derivado del servidor.

Todavía no se exige el chequeo de dueño en ningún endpoint; aquí solo se
verifica que el dato existe, viene de la identidad autenticada (nunca del
cuerpo) y no se filtra a la forma pública que lee React."""
import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.security import Principal, owner_email_for
from audit.log import reset_trail
from core import mandate_store
from core.mandate_store import MANDATE_OWNERS, get_mandate_owner
from tests.conftest import TEST_ADMIN_EMAIL, TEST_USER_EMAIL

SEED_ID = "mnd_marta_001"


@pytest.fixture()
def client(active_seed):
    mandate_store.mandate_store.clear()
    reset_trail()
    with TestClient(app) as test_client:
        yield test_client
    mandate_store.mandate_store.clear()
    reset_trail()


def react_payload(mandate_id: str, **extra) -> dict:
    payload = {
        "mandate_id": mandate_id,
        "human": {"id": "hum_owner_test", "display_name": "Test User", "email": "human.in.body@example.com"},
        "agent": {"id": "agt_saturday"},
        "constraints": {"max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"]},
        "signature": "test-signature-placeholder",
    }
    payload.update(extra)
    return payload


# ── El seed tiene dueño ─────────────────────────────────────────────────────

def test_seed_mandate_has_owner(client, active_seed):
    assert get_mandate_owner(SEED_ID) == active_seed["human"]["email"] == "test.user@example.com"


# ── /mandates/create (con token): el dueño sale del token ───────────────────

def test_mandate_created_with_user_token_records_owner(client, auth_headers):
    response = client.post("/mandates/create", json={"human_id": "hum_x", "max_amount_per_tx": 150}, headers=auth_headers)
    assert response.status_code == 200

    assert get_mandate_owner(response.json()["mandate_id"]) == TEST_USER_EMAIL


def test_mandate_created_with_admin_token_records_admin_as_owner(client, admin_headers):
    response = client.post("/mandates/create", json={"human_id": "hum_x", "max_amount_per_tx": 150}, headers=admin_headers)
    assert get_mandate_owner(response.json()["mandate_id"]) == TEST_ADMIN_EMAIL


# ── POST /mandates (React, aún sin token): sin dueño, y el cuerpo no lo decide ──

def test_react_mandate_without_token_has_no_owner_yet(client):
    payload = react_payload("mnd_owner_anon")
    response = client.post("/mandates", json=payload)

    assert response.status_code == 201
    assert "mnd_owner_anon" in MANDATE_OWNERS  # la estructura existe para todo mandato
    assert get_mandate_owner("mnd_owner_anon") is None
    # human.email del cuerpo NO convierte a nadie en dueño.
    assert get_mandate_owner("mnd_owner_anon") != "human.in.body@example.com"


def test_client_cannot_declare_itself_owner_in_body(client):
    payload = react_payload("mnd_owner_forged", owner_email="attacker@example.com", owner="attacker@example.com")
    response = client.post("/mandates", json=payload)

    assert response.status_code == 201
    assert get_mandate_owner("mnd_owner_forged") is None
    # El cuerpo se sigue guardando tal cual (contrato congelado): esos campos son
    # datos del cliente sin ningún efecto sobre el dueño real.
    stored = response.json()["mandate"]
    assert stored["owner_email"] == stored["owner"] == "attacker@example.com"


# ── El dueño no se filtra a la forma pública ────────────────────────────────

def _keys_deep(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in _keys_deep(child)}
    if isinstance(value, list):
        return {key for child in value for key in _keys_deep(child)}
    return set()


def test_public_mandate_record_shape_is_unchanged(client, auth_headers):
    created = client.post("/mandates/create", json={"human_id": "hum_x", "max_amount_per_tx": 150}, headers=auth_headers)
    strict_id = created.json()["mandate_id"]

    for mandate_id in (SEED_ID, strict_id):
        record = client.get(f"/mandates/{mandate_id}").json()
        assert set(record) == {"mandate", "live_state"}
        assert set(record["live_state"]) == {"status", "uses_count", "amount_spent", "revoked_at"}
        assert not any("owner" in key for key in _keys_deep(record))

    # El email del token no aparece en la respuesta del mandato estricto.
    assert TEST_USER_EMAIL not in client.get(f"/mandates/{strict_id}").text


def test_revoke_and_reset_keep_the_owner(client, active_seed):
    owner = get_mandate_owner(SEED_ID)
    client.post(f"/mandates/{SEED_ID}/revoke")
    client.post(f"/mandates/{SEED_ID}/reset")
    assert get_mandate_owner(SEED_ID) == owner


def test_store_clear_forgets_owners_and_reused_id_starts_without_owner(client):
    mandate_store.create_mandate(react_payload("mnd_owner_reuse"), owner_email="first@example.com")
    assert get_mandate_owner("mnd_owner_reuse") == "first@example.com"

    mandate_store.mandate_store.clear()
    assert get_mandate_owner("mnd_owner_reuse") is None

    mandate_store.create_mandate(react_payload("mnd_owner_reuse"))
    assert get_mandate_owner("mnd_owner_reuse") is None


# ── Gancho owner_email_for ──────────────────────────────────────────────────

@pytest.mark.parametrize(
    "principal, expected",
    [
        (None, None),
        (Principal(subject="Marta@Example.COM ", role="user"), "marta@example.com"),
        (Principal(subject="ops@example.com", role="admin"), "ops@example.com"),
        (Principal(subject="service", role="service"), None),  # una máquina no es dueña
    ],
    ids=["anonymous", "user-normalized", "admin", "service"],
)
def test_owner_email_for(principal, expected):
    assert owner_email_for(principal) == expected
