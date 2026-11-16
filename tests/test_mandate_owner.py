"""Dueño de mandato (owner_email): dato INTERNO, derivado del servidor.

Crear un mandato exige token de persona y registra a quien lo crea como dueño.
El chequeo de propiedad (assert_can_access_mandate) se testea aquí en aislamiento
(su aplicación por HTTP está en test_mandate_access.py). Desde el 3.5 todo mandato
de usuario va firmado por su titular (helper signed_poster)."""
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.main import app
from api.security import Principal, assert_can_access_mandate, owner_email_for
from core import mandate_store
from core.mandate_store import get_mandate_owner
from tests.conftest import TEST_ADMIN_EMAIL, TEST_SERVICE_KEY, TEST_USER_EMAIL
from tests.storage import all_mandate_ids, insert_mandate_without_signer, mandate_exists

@pytest.fixture()
def client():
    mandate_store.mandate_store.clear()
    with TestClient(app) as test_client:
        yield test_client
    mandate_store.mandate_store.clear()


def react_payload(mandate_id: str, **extra) -> dict:
    payload = {
        "mandate_id": mandate_id,
        "human": {"id": "hum_owner_test", "display_name": "Test User", "email": "human.in.body@example.com"},
        "agent": {"id": "agt_saturday"},
        "constraints": {
            "max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"], "max_uses": 3,
        },
    }
    payload.update(extra)
    return payload


# ── POST /mandates/create ya no existe (3.5, P-02) ──────────────────────────

@pytest.mark.parametrize("headers_fixture", ["auth_headers", "admin_headers"])
def test_mandates_create_route_was_retired(client, request, headers_fixture):
    """Firmaba con llaves "humanas" que guardaba el servidor: se retiró. Ni un usuario
    ni un admin pueden crear mandatos por ahí; el único alta es POST /mandates firmado."""
    headers = request.getfixturevalue(headers_fixture)
    response = client.post("/mandates/create", json={"human_id": "hum_x", "max_amount_per_tx": 150}, headers=headers)
    assert response.status_code in (404, 405)
    assert all_mandate_ids() == set()  # 7.2: no hay mandatos precargados


# ── POST /mandates (el de React): exige token y el dueño sale de ahí ────────

def test_react_mandate_without_token_is_401(client):
    response = client.post("/mandates", json=react_payload("mnd_owner_anon"))

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    # Sin credencial no se creó nada: el rechazo ocurre antes de tocar el store.
    assert not mandate_exists("mnd_owner_anon")
    assert mandate_store.get_mandate("mnd_owner_anon") is None


def test_react_mandate_with_user_token_records_owner(client, signed_poster):
    payload = react_payload("mnd_owner_user")
    response = signed_poster.post(payload)

    assert response.status_code == 201
    assert get_mandate_owner("mnd_owner_user") == TEST_USER_EMAIL
    # human.email del cuerpo NO convierte a nadie en dueño.
    assert get_mandate_owner("mnd_owner_user") != "human.in.body@example.com"


def test_client_cannot_declare_itself_owner_in_body(client, signed_poster, auth_headers):
    """3.5 (cambio deliberado, más estricto): antes owner/owner_email del cuerpo se
    guardaban como datos sin efecto. Ahora un mandato firmado no admite campos fuera
    de la spec: 422 y no se crea nada. El dueño sigue saliendo SOLO del token."""
    body = signed_poster.body(react_payload("mnd_owner_forged"))
    body.update(owner_email="attacker@example.com", owner="attacker@example.com")
    response = client.post("/mandates", json=body, headers=auth_headers)

    assert response.status_code == 422
    assert get_mandate_owner("mnd_owner_forged") is None
    assert mandate_store.get_mandate("mnd_owner_forged") is None

    # Y el mismo mandato sin esos campos queda a nombre del token, no del cuerpo.
    assert signed_poster.post(react_payload("mnd_owner_forged")).status_code == 201
    assert get_mandate_owner("mnd_owner_forged") == TEST_USER_EMAIL


def test_admin_creating_a_react_mandate_owns_it(client, signed_poster, admin_headers):
    response = signed_poster.post(react_payload("mnd_owner_admin"), email=TEST_ADMIN_EMAIL, headers=admin_headers)

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


def test_public_mandate_record_shape_is_unchanged(client, signed_poster, auth_headers):
    signed_poster.create(react_payload("mnd_owner_shape"))

    # El mandato se lee con el token de SU dueño (leerlo exige propiedad).
    record = client.get("/mandates/mnd_owner_shape", headers=auth_headers).json()
    assert set(record) == {"mandate", "live_state"}
    assert set(record["live_state"]) == {"status", "uses_count", "amount_spent_cents", "revoked_at"}
    assert not any("owner" in key for key in _keys_deep(record))

    # El email del token no aparece en la respuesta del mandato firmado.
    assert TEST_USER_EMAIL not in client.get("/mandates/mnd_owner_shape", headers=auth_headers).text


def test_revoke_keeps_the_owner(client, signed_poster, auth_headers):
    """(7.2, P-17: /reset se retiró.)"""
    signed_poster.create(react_payload("mnd_owner_revoke"))
    assert client.post("/mandates/mnd_owner_revoke/revoke", headers=auth_headers).status_code == 200
    assert get_mandate_owner("mnd_owner_revoke") == TEST_USER_EMAIL


def test_store_clear_forgets_owners_and_reused_id_does_not_inherit_owner(client, signed_poster):
    signed_poster.create(react_payload("mnd_owner_reuse"), email="first@example.com")
    assert get_mandate_owner("mnd_owner_reuse") == "first@example.com"

    mandate_store.mandate_store.clear()
    assert get_mandate_owner("mnd_owner_reuse") is None
    assert mandate_store.get_mandate_signer("mnd_owner_reuse") is None

    # El mismo id, creado por OTRA persona, es suyo: no hereda dueño ni firmante.
    signed_poster.create(react_payload("mnd_owner_reuse"), email="second@example.com")
    assert get_mandate_owner("mnd_owner_reuse") == "second@example.com"


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
def mandates_with_and_without_owner(client, signed_poster):
    """Un mandato con dueño (firmado por él) y otro huérfano (owner None). Desde el 7.2
    ningún flujo crea huérfanos (no hay seed): se inserta directo en la base, porque
    la regla de acceso debe seguir siendo segura si una base vieja lo trae."""
    signed_poster.create(react_payload(OWNED_ID), email=OWNER_EMAIL)
    insert_mandate_without_signer(ORPHAN_ID, react_payload(ORPHAN_ID), owner_email=None)
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


def test_admin_removed_from_admin_emails_keeps_only_its_own_mandates(mandates_with_and_without_owner, signed_poster, monkeypatch):
    """Token con role admin pero email ya fuera de ADMIN_EMAILS: se le trata como
    user (misma regla que is_admin), así que solo conserva lo suyo."""
    monkeypatch.delenv("ADMIN_EMAILS", raising=False)
    demoted = Principal(subject=TEST_ADMIN_EMAIL, role="admin")
    assert_forbidden(demoted, OWNED_ID)
    assert_forbidden(demoted, ORPHAN_ID)

    signed_poster.create(react_payload("mnd_access_ex_admin"), email=TEST_ADMIN_EMAIL)
    assert_can_access_mandate(demoted, "mnd_access_ex_admin")


def test_unknown_mandate_is_404_not_403(admin_principal):
    """No hay propiedad que evaluar: el mandato no existe."""
    with pytest.raises(HTTPException) as raised:
        assert_can_access_mandate(admin_principal, "mnd_does_not_exist")
    assert raised.value.status_code == 404
