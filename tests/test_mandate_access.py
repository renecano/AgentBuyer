"""Propiedad APLICADA: los endpoints por-mandato solo los opera su dueño (o un admin).

Complementa test_mandate_owner.py (que prueba la función assert_can_access_mandate
en aislamiento): aquí se prueba por HTTP, con tokens reales, que la autorización
ocurre ANTES del efecto — un no-dueño recibe 403 y el mandato no se mueve.
"""
import pytest
from fastapi.testclient import TestClient

from api.main import app
from audit.log import reset_trail
from core import mandate_store
from core.auth_tokens import create_access_token
from tests.conftest import TEST_USER_EMAIL

OTHER_USER_EMAIL = "someone.else@example.com"
MANDATE_ID = "mnd_access_http"


@pytest.fixture()
def client():
    # Sin headers por defecto: cada llamada declara explícitamente su credencial.
    mandate_store.mandate_store.clear()
    reset_trail()
    with TestClient(app) as test_client:
        yield test_client
    mandate_store.mandate_store.clear()
    reset_trail()


@pytest.fixture()
def other_headers(auth_config) -> dict[str, str]:
    """Token válido de OTRO usuario: autenticado, pero no dueño de nada."""
    return {"Authorization": f"Bearer {create_access_token(OTHER_USER_EMAIL)}"}


def react_payload(mandate_id: str = MANDATE_ID) -> dict:
    """Payload que manda MandateCreator.tsx (sin firma ni dueño: los pone el servidor)."""
    return {
        "mandate_id": mandate_id,
        "human": {"id": "hum_access", "display_name": "Owner", "email": TEST_USER_EMAIL},
        "agent": {"id": "agt_saturday", "display_name": "Saturday"},
        "search_fields": {"origin": "BUE", "destination": "COR", "departure_date": "2026-10-01"},
        "constraints": {
            "max_amount_per_purchase": 150, "currency": "USD",
            "allowed_categories": ["travel.flights"], "allowed_merchants": ["mch_vuelaya"],
            "max_uses": 3, "conditions": [{"type": "price_below", "value": 150}],
            "off_session_consent": True,
        },
    }


@pytest.fixture()
def owned_mandate(client, auth_headers) -> str:
    """Mandato creado por el usuario de auth_headers, que queda como su dueño."""
    response = client.post("/mandates", json=react_payload(), headers=auth_headers)
    assert response.status_code == 201, response.text
    return MANDATE_ID


def status_of(client, headers) -> str:
    return client.get(f"/mandates/{MANDATE_ID}", headers=headers).json()["live_state"]["status"]


# (método, ruta, body) de cada endpoint por-mandato protegido.
PROTECTED = [
    ("GET", "/mandates/{id}", None),
    ("POST", "/mandates/{id}/revoke", None),
    ("POST", "/mandates/{id}/reset", None),
    ("POST", "/mandates/{id}/pause", None),
    ("POST", "/mandates/{id}/resume", None),
    ("GET", "/mandates/{id}/activity", None),
    ("GET", "/audit/{id}", None),
    ("POST", "/mandates/{id}/approve_escalation", {"purchase_attempt_id": "att_x", "decision": "approve"}),
]
PROTECTED_IDS = [f"{method} {path}" for method, path, _ in PROTECTED]


def call(client, method, path, body, headers=None):
    return client.request(method, path.replace("{id}", MANDATE_ID), json=body, headers=headers)


# ── La matriz completa: 401 sin token, 403 si no es tuyo ────────────────────

@pytest.mark.parametrize("endpoint", PROTECTED, ids=PROTECTED_IDS)
def test_without_token_is_401(client, owned_mandate, endpoint):
    response = call(client, *endpoint)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize("endpoint", PROTECTED, ids=PROTECTED_IDS)
def test_another_user_is_403(client, owned_mandate, other_headers, endpoint):
    response = call(client, *endpoint, headers=other_headers)

    assert response.status_code == 403


@pytest.mark.parametrize("endpoint", PROTECTED, ids=PROTECTED_IDS)
def test_owner_passes_authorization(client, owned_mandate, auth_headers, endpoint):
    """El dueño pasa el control de acceso. Lo que responda después es cosa del
    endpoint (approve_escalation da 404 sin un intento escalado real), pero nunca
    es un rechazo de autorización."""
    response = call(client, *endpoint, headers=auth_headers)

    assert response.status_code not in (401, 403), response.text


@pytest.mark.parametrize("endpoint", PROTECTED, ids=PROTECTED_IDS)
def test_admin_passes_authorization_on_someone_elses_mandate(client, owned_mandate, admin_headers, endpoint):
    response = call(client, *endpoint, headers=admin_headers)

    assert response.status_code not in (401, 403), response.text


# ── Y además: el efecto no ocurre cuando se deniega ─────────────────────────

def test_another_user_cannot_revoke_and_the_mandate_stays_active(client, owned_mandate, auth_headers, other_headers):
    assert client.post(f"/mandates/{MANDATE_ID}/revoke", headers=other_headers).status_code == 403

    assert status_of(client, auth_headers) == "active"  # el 403 fue antes del efecto


def test_owner_revokes_and_admin_can_reset_it(client, owned_mandate, auth_headers, admin_headers):
    revoked = client.post(f"/mandates/{MANDATE_ID}/revoke", headers=auth_headers)
    assert revoked.status_code == 200
    assert status_of(client, auth_headers) == "revoked"

    # Un admin opera mandatos ajenos (soporte), y el efecto sí ocurre.
    assert client.post(f"/mandates/{MANDATE_ID}/reset", headers=admin_headers).status_code == 200
    assert status_of(client, admin_headers) == "active"


def test_another_user_cannot_pause_the_mandate(client, owned_mandate, auth_headers, other_headers):
    assert client.post(f"/mandates/{MANDATE_ID}/pause", headers=other_headers).status_code == 403

    assert status_of(client, auth_headers) == "active"


def test_audit_trail_of_a_mandate_is_owner_only(client, owned_mandate, auth_headers, other_headers):
    owner_view = client.get(f"/audit/{MANDATE_ID}", headers=auth_headers)
    assert owner_view.status_code == 200
    assert isinstance(owner_view.json(), list)

    assert client.get(f"/audit/{MANDATE_ID}", headers=other_headers).status_code == 403


def test_unknown_mandate_is_404_for_an_authenticated_user(client, auth_headers):
    assert client.get("/mandates/mnd_nope", headers=auth_headers).status_code == 404


# ── El flujo de React de punta a punta ──────────────────────────────────────

def test_react_flow_create_then_operate_with_the_same_token(client, auth_headers, other_headers):
    """Lo que hace el navegador: crear con el token de la sesión y seguir usando
    ESE mismo token para leer, revocar y resetear. Es el flujo central de la UI."""
    assert client.post("/mandates", json=react_payload(), headers=auth_headers).status_code == 201

    record = client.get(f"/mandates/{MANDATE_ID}", headers=auth_headers)
    assert record.status_code == 200
    assert set(record.json()) == {"mandate", "live_state"}

    assert client.post(f"/mandates/{MANDATE_ID}/revoke", headers=auth_headers).status_code == 200
    assert client.post(f"/mandates/{MANDATE_ID}/reset", headers=auth_headers).status_code == 200
    assert client.get(f"/audit/{MANDATE_ID}", headers=auth_headers).status_code == 200

    # Otra sesión, aunque esté autenticada, no ve ni toca ese mandato.
    for method, path in [
        ("GET", f"/mandates/{MANDATE_ID}"),
        ("POST", f"/mandates/{MANDATE_ID}/revoke"),
        ("POST", f"/mandates/{MANDATE_ID}/reset"),
        ("GET", f"/audit/{MANDATE_ID}"),
    ]:
        assert client.request(method, path, headers=other_headers).status_code == 403


def test_owner_email_from_the_token_survives_case_and_spacing(client):
    """El token trae el email como lo escribió la persona; el dueño se guarda
    normalizado y el chequeo normaliza igual. Si esto se rompiera, React crearía
    un mandato que no podría volver a leer."""
    messy = "  Owner.Person@Example.COM  "
    headers = {"Authorization": f"Bearer {create_access_token(messy)}"}

    assert client.post("/mandates", json=react_payload(), headers=headers).status_code == 201
    assert mandate_store.get_mandate_owner(MANDATE_ID) == "owner.person@example.com"
    assert client.get(f"/mandates/{MANDATE_ID}", headers=headers).status_code == 200
