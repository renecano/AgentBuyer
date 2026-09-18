"""Dueño de mandato (owner_email): dato INTERNO, derivado del servidor.

Crear un mandato exige token de persona y registra a quien lo crea como dueño.
El chequeo de propiedad (assert_can_access_mandate) ya existe y se testea aquí,
pero todavía NO se aplica a revoke/reset/get/approve_escalation."""
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.main import app
from api.security import Principal, assert_can_access_mandate, owner_email_for
from audit.log import reset_trail
from core import mandate_store
from core.mandate_store import MANDATE_OWNERS, get_mandate_owner
from tests.conftest import TEST_ADMIN_EMAIL, TEST_SERVICE_KEY, TEST_USER_EMAIL

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


# ── POST /mandates (el de React): exige token y el dueño sale de ahí ────────

def test_react_mandate_without_token_is_401(client):
    response = client.post("/mandates", json=react_payload("mnd_owner_anon"))

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    # Sin credencial no se creó nada: el rechazo ocurre antes de tocar el store.
    assert "mnd_owner_anon" not in MANDATE_OWNERS
    assert mandate_store.get_mandate("mnd_owner_anon") is None


def test_react_mandate_with_user_token_records_owner(client, auth_headers):
    payload = react_payload("mnd_owner_user")
    response = client.post("/mandates", json=payload, headers=auth_headers)

    assert response.status_code == 201
    assert get_mandate_owner("mnd_owner_user") == TEST_USER_EMAIL
    # human.email del cuerpo NO convierte a nadie en dueño.
    assert get_mandate_owner("mnd_owner_user") != "human.in.body@example.com"


def test_client_cannot_declare_itself_owner_in_body(client, auth_headers):
    payload = react_payload("mnd_owner_forged", owner_email="attacker@example.com", owner="attacker@example.com")
    response = client.post("/mandates", json=payload, headers=auth_headers)

    assert response.status_code == 201
    # El dueño real es el del token, no el que declaró el cuerpo.
    assert get_mandate_owner("mnd_owner_forged") == TEST_USER_EMAIL
    # El cuerpo se sigue guardando tal cual (contrato congelado): esos campos son
    # datos del cliente sin ningún efecto sobre el dueño real.
    stored = response.json()["mandate"]
    assert stored["owner_email"] == stored["owner"] == "attacker@example.com"


def test_admin_creating_a_react_mandate_owns_it(client, admin_headers):
    response = client.post("/mandates", json=react_payload("mnd_owner_admin"), headers=admin_headers)

    assert response.status_code == 201
    assert get_mandate_owner("mnd_owner_admin") == TEST_ADMIN_EMAIL


def test_service_key_cannot_create_mandates(client, service_headers):
    """Un servicio se autentica, pero no es dueño de nada: 403, no 401."""
    response = client.post("/mandates", json=react_payload("mnd_owner_service"), headers=service_headers)

    assert response.status_code == 403
    assert mandate_store.get_mandate("mnd_owner_service") is None


def test_invalid_service_key_is_401_not_403(client, monkeypatch):
    """Key de servicio que no coincide: no está autenticado -> 401 (fail-closed)."""
    monkeypatch.setenv("SERVICE_API_KEY", TEST_SERVICE_KEY)
    response = client.post(
        "/mandates", json=react_payload("mnd_owner_badkey"), headers={"X-Service-Key": "not-the-key"}
    )

    assert response.status_code == 401
    assert mandate_store.get_mandate("mnd_owner_badkey") is None


# ── El dueño no se filtra a la forma pública ────────────────────────────────

def _keys_deep(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in _keys_deep(child)}
    if isinstance(value, list):
        return {key for child in value for key in _keys_deep(child)}
    return set()


def test_public_mandate_record_shape_is_unchanged(client, auth_headers, seed_owner_headers):
    created = client.post("/mandates/create", json={"human_id": "hum_x", "max_amount_per_tx": 150}, headers=auth_headers)
    strict_id = created.json()["mandate_id"]

    # Cada mandato se lee con el token de SU dueño (leerlos exige propiedad).
    for mandate_id, headers in ((SEED_ID, seed_owner_headers), (strict_id, auth_headers)):
        record = client.get(f"/mandates/{mandate_id}", headers=headers).json()
        assert set(record) == {"mandate", "live_state"}
        assert set(record["live_state"]) == {"status", "uses_count", "amount_spent", "revoked_at"}
        assert not any("owner" in key for key in _keys_deep(record))

    # El email del token no aparece en la respuesta del mandato estricto.
    assert TEST_USER_EMAIL not in client.get(f"/mandates/{strict_id}", headers=auth_headers).text


def test_revoke_and_reset_keep_the_owner(client, active_seed, seed_owner_headers):
    owner = get_mandate_owner(SEED_ID)
    assert client.post(f"/mandates/{SEED_ID}/revoke", headers=seed_owner_headers).status_code == 200
    assert client.post(f"/mandates/{SEED_ID}/reset", headers=seed_owner_headers).status_code == 200
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


# ── assert_can_access_mandate (aún NO aplicada a revoke/reset/get/...) ──────

OWNER_EMAIL = "owner@example.com"
OWNED_ID, ORPHAN_ID = "mnd_access_owned", "mnd_access_orphan"


@pytest.fixture()
def mandates_with_and_without_owner(client):
    """Un mandato con dueño y otro huérfano (owner None), como los creados antes
    de exigir token."""
    mandate_store.create_mandate(react_payload(OWNED_ID), owner_email=OWNER_EMAIL)
    mandate_store.create_mandate(react_payload(ORPHAN_ID))
    return OWNED_ID, ORPHAN_ID


@pytest.fixture()
def admin_principal(monkeypatch) -> Principal:
    monkeypatch.setenv("ADMIN_EMAILS", TEST_ADMIN_EMAIL)
    return Principal(subject=TEST_ADMIN_EMAIL, role="admin")


def assert_forbidden(principal: Principal, mandate_id: str) -> None:
    with pytest.raises(HTTPException) as raised:
        assert_can_access_mandate(principal, mandate_id)
    assert raised.value.status_code == 403


def test_owner_can_access_own_mandate(mandates_with_and_without_owner):
    # No lanza: el dueño pasa. La comparación normaliza mayúsculas y espacios.
    assert_can_access_mandate(Principal(subject=" Owner@Example.COM ", role="user"), OWNED_ID)


def test_another_user_cannot_access_someone_elses_mandate(mandates_with_and_without_owner):
    assert_forbidden(Principal(subject="intruder@example.com", role="user"), OWNED_ID)


def test_admin_can_access_a_mandate_owned_by_someone_else(mandates_with_and_without_owner, admin_principal):
    assert_can_access_mandate(admin_principal, OWNED_ID)


def test_orphan_mandate_is_admin_only(mandates_with_and_without_owner, admin_principal):
    """Ante duda de propiedad se deniega: un huérfano no se regala al primero que pase."""
    assert_can_access_mandate(admin_principal, ORPHAN_ID)
    assert_forbidden(Principal(subject=OWNER_EMAIL, role="user"), ORPHAN_ID)
    assert_forbidden(Principal(subject="anyone@example.com", role="user"), ORPHAN_ID)


def test_service_principal_can_access_nothing(mandates_with_and_without_owner):
    service = Principal(subject="service", role="service")
    assert_forbidden(service, OWNED_ID)
    assert_forbidden(service, ORPHAN_ID)


def test_admin_removed_from_admin_emails_keeps_only_its_own_mandates(mandates_with_and_without_owner, monkeypatch):
    """Token con role admin pero email ya fuera de ADMIN_EMAILS: se le trata como
    user (misma regla que require_admin), así que solo conserva lo suyo."""
    monkeypatch.delenv("ADMIN_EMAILS", raising=False)
    demoted = Principal(subject=TEST_ADMIN_EMAIL, role="admin")
    assert_forbidden(demoted, OWNED_ID)
    assert_forbidden(demoted, ORPHAN_ID)

    mandate_store.create_mandate(react_payload("mnd_access_ex_admin"), owner_email=TEST_ADMIN_EMAIL)
    assert_can_access_mandate(demoted, "mnd_access_ex_admin")


def test_unknown_mandate_is_404_not_403(admin_principal):
    """No hay propiedad que evaluar: el mandato no existe."""
    with pytest.raises(HTTPException) as raised:
        assert_can_access_mandate(admin_principal, "mnd_does_not_exist")
    assert raised.value.status_code == 404
