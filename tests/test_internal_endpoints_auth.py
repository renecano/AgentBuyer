"""Endpoints internos (React no los llama) protegidos con require_principal:
sin token válido → 401 y el efecto NO ocurre; con token válido → funcionan."""
import pytest
from fastapi.testclient import TestClient

import api.auth as auth_api
import core.notifications as notifications
from api.main import app
from audit.log import get_trail_events, reset_trail
from core.email_otp import EmailOtpService

# (método, ruta) → body mínimo. Bodies vacíos o inválidos a propósito: la auth
# debe rechazar ANTES de validar el body (401, no 422).
PROTECTED_ENDPOINTS = {
    ("GET", "/inbox/messages"): None,
    ("POST", "/notifications/send-ticket"): {},
    ("POST", "/purchases/att_x/approve-exception"): {},
    ("GET", "/mandates"): None,
    ("POST", "/mandates/create"): {},
    ("POST", "/mandates/mnd_x/pause"): None,
    ("POST", "/mandates/mnd_x/resume"): None,
    ("GET", "/mandates/mnd_x/activity"): None,
    ("POST", "/purchases/execute"): {},
    ("POST", "/adversarial/run"): None,
    ("GET", "/disputes"): None,
    ("POST", "/merchant/search"): {},
}

EXPECTED_PROTECTED_ROUTES = {
    ("GET", "/inbox/messages"),
    ("POST", "/notifications/send-ticket"),
    ("POST", "/purchases/{purchase_id}/approve-exception"),
    ("GET", "/mandates"),
    ("POST", "/mandates/create"),
    ("POST", "/mandates/{mandate_id}/pause"),
    ("POST", "/mandates/{mandate_id}/resume"),
    ("GET", "/mandates/{mandate_id}/activity"),
    ("POST", "/purchases/execute"),
    ("POST", "/adversarial/run"),
    ("GET", "/disputes"),
    ("POST", "/merchant/search"),
}


@pytest.fixture()
def client():
    reset_trail()
    with TestClient(app) as test_client:
        yield test_client
    reset_trail()


def call(client, method, path, body=None, headers=None):
    return client.request(method, path, json=body, headers=headers)


# ── Todos: sin token o con token inválido → 401 ─────────────────────────────

@pytest.mark.parametrize("endpoint", PROTECTED_ENDPOINTS.items(), ids=[f"{m} {p}" for m, p in PROTECTED_ENDPOINTS])
def test_protected_endpoint_without_token_is_401(client, endpoint):
    (method, path), body = endpoint
    response = call(client, method, path, body)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize("endpoint", PROTECTED_ENDPOINTS.items(), ids=[f"{m} {p}" for m, p in PROTECTED_ENDPOINTS])
def test_protected_endpoint_with_invalid_token_is_401(client, endpoint):
    (method, path), body = endpoint
    response = call(client, method, path, body, headers={"Authorization": "Bearer not-a-valid-jwt"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token."


# Endpoints que el frontend React llama hoy SIN token (frontend/src): protegerlos
# rompería la UI hasta que el frontend envíe el header.
REACT_ROUTES = {
    ("POST", "/mandates"),
    ("GET", "/mandates/{mandate_id}"),
    ("POST", "/mandates/{mandate_id}/revoke"),
    ("POST", "/mandates/{mandate_id}/reset"),
    ("POST", "/mandates/{mandate_id}/approve_escalation"),
    ("POST", "/agent/run"),
    ("POST", "/verify"),
    ("POST", "/audit/reset"),
    ("GET", "/audit"),
    ("GET", "/audit/{mandate_id}"),
    ("POST", "/disputes/file"),
}


def _openapi_operations_by_security() -> tuple[set, set]:
    """(protegidas, todas) según el esquema OpenAPI: contrato PÚBLICO de FastAPI,
    estable entre versiones (a diferencia de app.routes / route.dependant, que
    cambió en 0.141 con include_router)."""
    schema = app.openapi()
    bearer_schemes = {
        name
        for name, scheme in schema.get("components", {}).get("securitySchemes", {}).items()
        if scheme.get("type") == "http" and scheme.get("scheme", "").lower() == "bearer"
    }
    protected, every = set(), set()
    for path, operations in schema["paths"].items():
        for method, operation in operations.items():
            key = (method.upper(), path)
            every.add(key)
            if any(bearer_schemes & set(requirement) for requirement in operation.get("security", [])):
                protected.add(key)
    return protected, every


def test_exactly_the_internal_endpoints_require_auth():
    """Guardia: ni se desprotege uno de estos, ni se protege por error un endpoint
    de React (eso rompería el frontend, que todavía no envía token)."""
    protected, every = _openapi_operations_by_security()

    # Las listas de la guardia apuntan a operaciones que existen (evita que un
    # renombre de ruta deje la guardia comprobando nada).
    assert EXPECTED_PROTECTED_ROUTES <= every
    assert REACT_ROUTES <= every

    assert protected == EXPECTED_PROTECTED_ROUTES
    assert not protected & REACT_ROUTES


# ── Pares sin token / con token en los endpoints críticos ───────────────────

def test_inbox_messages_requires_token(client, monkeypatch, auth_headers):
    reads = []

    def fake_inbox(limite=10):
        reads.append(limite)
        return {"status": 200, "connected": True, "messages": [{"subject": "hello"}]}

    monkeypatch.setattr(notifications, "leer_correos_recibidos", fake_inbox)

    unauthenticated = client.get("/inbox/messages?limit=3")
    assert unauthenticated.status_code == 401
    assert reads == []  # el Gmail no se leyó

    authenticated = client.get("/inbox/messages?limit=3", headers=auth_headers)
    assert authenticated.status_code == 200
    assert authenticated.json()["messages"] == [{"subject": "hello"}]
    assert reads == [3]


def test_send_ticket_requires_token(client, monkeypatch, auth_headers):
    sent = []

    def fake_send(correo_destino, detalles_reserva):
        sent.append(correo_destino)
        return {"status": 200, "message": "sent", "sent_to": correo_destino}

    monkeypatch.setattr(notifications, "enviar_ticket_confirmacion", fake_send)
    payload = {"email": "victim@example.com", "passenger": "<b>phish</b>"}

    assert client.post("/notifications/send-ticket", json=payload).status_code == 401
    assert sent == []  # ningún correo salió

    response = client.post("/notifications/send-ticket", json=payload, headers=auth_headers)
    assert response.status_code == 200
    assert sent == ["victim@example.com"]


def test_approve_exception_requires_token(client, auth_headers):
    def approvals():
        return [event for event in get_trail_events() if event["type"] == "hitl_approved"]

    assert client.post("/purchases/att_forged/approve-exception", json={}).status_code == 401
    assert approvals() == []  # no quedó una aprobación humana falsa en el ledger

    response = client.post("/purchases/att_forged/approve-exception", json={}, headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED_BY_HUMAN_OVERRIDE"
    assert [event["attempt_id"] for event in approvals()] == ["att_forged"]


def test_list_mandates_requires_token(client, auth_headers):
    assert client.get("/mandates").status_code == 401

    response = client.get("/mandates", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


# ── Un token obtenido con el login real también sirve ───────────────────────

def test_token_from_real_email_login_opens_protected_endpoint(client, monkeypatch):
    codes = []
    monkeypatch.setattr(auth_api, "otp_service", EmailOtpService())
    monkeypatch.setattr(
        auth_api, "send_verification_email",
        lambda email, code, ttl_seconds: codes.append(code) or True,
    )

    client.post("/auth/email/start", json={"email": "real.client@example.com"})
    login = client.post("/auth/email/check", json={"email": "real.client@example.com", "code": codes[-1]}).json()

    response = client.get("/disputes", headers={"Authorization": f"Bearer {login['access_token']}"})
    assert response.status_code == 200
