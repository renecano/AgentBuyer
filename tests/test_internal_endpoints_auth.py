"""Endpoints internos (React no los llama) protegidos por rol:
- user    (require_principal): JWT válido.
- admin   (require_admin):     JWT válido con role="admin" y email en ADMIN_EMAILS.
- service (require_service):   header X-Service-Key contra SERVICE_API_KEY.

401 = no autenticado; 403 = autenticado sin el rol. El efecto nunca ocurre sin
la credencial correcta."""
import jwt
import pytest
from fastapi.testclient import TestClient

import api.auth as auth_api
import api.main as api_main
import core.notifications as notifications
from api.main import app
from audit.log import get_trail_events, reset_trail
from core.auth_config import MIN_SERVICE_KEY_BYTES, ServiceKeyConfigError, service_api_keys
from core.auth_tokens import ISSUER, create_access_token
from core.email_otp import EmailOtpService
from tests.conftest import TEST_ADMIN_EMAIL, TEST_JWT_SECRET, TEST_SERVICE_KEY

USER, ADMIN, SERVICE = "user", "admin", "service"

# (método, ruta concreta) → (body, rol exigido). Bodies vacíos o inválidos a
# propósito: la autorización debe rechazar ANTES de validar el body (401/403, no 422).
ENDPOINTS = {
    ("GET", "/inbox/messages"): (None, ADMIN),
    ("POST", "/notifications/send-ticket"): ({}, ADMIN),
    ("POST", "/purchases/att_x/approve-exception"): ({}, ADMIN),
    ("GET", "/mandates"): (None, USER),
    ("POST", "/mandates/create"): ({}, USER),
    ("POST", "/mandates/mnd_x/pause"): (None, USER),
    ("POST", "/mandates/mnd_x/resume"): (None, USER),
    ("GET", "/mandates/mnd_x/activity"): (None, USER),
    ("POST", "/purchases/execute"): ({}, USER),
    ("POST", "/adversarial/run"): (None, SERVICE),
    ("GET", "/disputes"): (None, USER),
    ("POST", "/merchant/search"): ({}, USER),
}

BEARER_ENDPOINTS = {key: value for key, value in ENDPOINTS.items() if value[1] in (USER, ADMIN)}
ADMIN_ENDPOINTS = {key: value for key, value in ENDPOINTS.items() if value[1] == ADMIN}
SERVICE_ENDPOINTS = {key: value for key, value in ENDPOINTS.items() if value[1] == SERVICE}


def ids(endpoints):
    return [f"{method} {path}" for method, path in endpoints]


@pytest.fixture()
def client():
    reset_trail()
    with TestClient(app) as test_client:
        yield test_client
    reset_trail()


def call(client, method, path, body=None, headers=None):
    return client.request(method, path, json=body, headers=headers)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── 401: sin credencial o con credencial inválida ───────────────────────────

@pytest.mark.parametrize("endpoint", BEARER_ENDPOINTS.items(), ids=ids(BEARER_ENDPOINTS))
def test_bearer_endpoint_without_token_is_401(client, endpoint):
    (method, path), (body, _) = endpoint
    response = call(client, method, path, body)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize("endpoint", BEARER_ENDPOINTS.items(), ids=ids(BEARER_ENDPOINTS))
def test_bearer_endpoint_with_invalid_token_is_401(client, endpoint):
    (method, path), (body, _) = endpoint
    response = call(client, method, path, body, headers=bearer("not-a-valid-jwt"))

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token."


@pytest.mark.parametrize("endpoint", SERVICE_ENDPOINTS.items(), ids=ids(SERVICE_ENDPOINTS))
@pytest.mark.parametrize(
    "headers",
    [{}, {"X-Service-Key": ""}, {"X-Service-Key": "wrong-key"}, {"X-Service-Key": TEST_SERVICE_KEY + "x"}],
    ids=["missing", "empty", "wrong", "prefix-of-longer"],
)
def test_service_endpoint_without_valid_key_is_401(client, service_headers, endpoint, headers):
    (method, path), (body, _) = endpoint
    response = call(client, method, path, body, headers=headers)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "X-Service-Key"


# ── 403: autenticado, pero sin el rol ───────────────────────────────────────

@pytest.mark.parametrize("endpoint", ADMIN_ENDPOINTS.items(), ids=ids(ADMIN_ENDPOINTS))
def test_admin_endpoint_rejects_user_with_403(client, auth_headers, endpoint):
    (method, path), (body, _) = endpoint
    response = call(client, method, path, body, headers=auth_headers)

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin role required."
    assert "WWW-Authenticate" not in response.headers  # no es un problema de autenticación


def test_admin_role_is_revoked_when_email_leaves_admin_emails(client, admin_headers, monkeypatch):
    assert client.get("/disputes", headers=admin_headers).status_code == 200  # sigue siendo usuario válido
    monkeypatch.setenv("ADMIN_EMAILS", "someone.else@example.com")

    response = client.post("/purchases/att_x/approve-exception", json={}, headers=admin_headers)
    assert response.status_code == 403


def test_user_token_of_listed_email_is_not_admin(client, admin_headers):
    """El rol lo fija el token al emitirse: un token "user" no se vuelve admin."""
    user_token_same_email = create_access_token(TEST_ADMIN_EMAIL)
    response = client.get("/inbox/messages", headers=bearer(user_token_same_email))
    assert response.status_code == 403


def test_forged_admin_claim_is_401_not_403(client, admin_headers):
    forged = jwt.encode(
        {"iss": ISSUER, "sub": TEST_ADMIN_EMAIL, "role": "admin", "iat": 1_900_000_000, "exp": 4_000_000_000},
        "attacker-secret-0123456789-abcdefghijklmnopqrstuv",
        algorithm="HS256",
    )
    assert client.get("/inbox/messages", headers=bearer(forged)).status_code == 401


# ── Credenciales que no se mezclan ──────────────────────────────────────────

def test_admin_jwt_does_not_open_service_endpoint(client, admin_headers, service_headers):
    response = client.post("/adversarial/run", headers=admin_headers)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "X-Service-Key"


def test_service_key_does_not_open_bearer_endpoints(client, service_headers):
    assert client.get("/disputes", headers=service_headers).status_code == 401
    assert client.get("/inbox/messages", headers=service_headers).status_code == 401


def test_service_endpoint_fails_closed_without_configured_key(client, monkeypatch, caplog):
    monkeypatch.delenv("SERVICE_API_KEY", raising=False)
    with caplog.at_level("WARNING", logger="api.security"):
        response = client.post("/adversarial/run", headers={"X-Service-Key": "anything"})
    assert response.status_code == 401
    assert "SERVICE_API_KEY" in caplog.text


# ── Pares sin credencial / credencial correcta (el efecto solo ocurre con ella) ──

def test_inbox_messages_requires_admin(client, monkeypatch, auth_headers, admin_headers):
    reads = []

    def fake_inbox(limite=10):
        reads.append(limite)
        return {"status": 200, "connected": True, "messages": [{"subject": "hello"}]}

    monkeypatch.setattr(notifications, "leer_correos_recibidos", fake_inbox)

    assert client.get("/inbox/messages?limit=3").status_code == 401
    assert client.get("/inbox/messages?limit=3", headers=auth_headers).status_code == 403
    assert reads == []  # el Gmail no se leyó

    authenticated = client.get("/inbox/messages?limit=3", headers=admin_headers)
    assert authenticated.status_code == 200
    assert authenticated.json()["messages"] == [{"subject": "hello"}]
    assert reads == [3]


def test_send_ticket_requires_admin(client, monkeypatch, auth_headers, admin_headers):
    sent = []

    def fake_send(correo_destino, detalles_reserva):
        sent.append(correo_destino)
        return {"status": 200, "message": "sent", "sent_to": correo_destino}

    monkeypatch.setattr(notifications, "enviar_ticket_confirmacion", fake_send)
    payload = {"email": "victim@example.com", "passenger": "<b>phish</b>"}

    assert client.post("/notifications/send-ticket", json=payload).status_code == 401
    assert client.post("/notifications/send-ticket", json=payload, headers=auth_headers).status_code == 403
    assert sent == []  # ningún correo salió

    response = client.post("/notifications/send-ticket", json=payload, headers=admin_headers)
    assert response.status_code == 200
    assert sent == ["victim@example.com"]


def test_approve_exception_requires_admin(client, auth_headers, admin_headers):
    def approvals():
        return [event for event in get_trail_events() if event["type"] == "hitl_approved"]

    assert client.post("/purchases/att_forged/approve-exception", json={}).status_code == 401
    assert client.post("/purchases/att_forged/approve-exception", json={}, headers=auth_headers).status_code == 403
    assert approvals() == []  # no quedó una aprobación humana falsa en el ledger

    response = client.post("/purchases/att_forged/approve-exception", json={}, headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED_BY_HUMAN_OVERRIDE"
    assert [event["attempt_id"] for event in approvals()] == ["att_forged"]


def test_adversarial_run_requires_service_key(client, monkeypatch, auth_headers, service_headers):
    runs = []
    monkeypatch.setattr(api_main, "run_adversarial_suite", lambda: runs.append(1) or True)

    assert client.post("/adversarial/run").status_code == 401
    assert client.post("/adversarial/run", headers=auth_headers).status_code == 401  # un JWT no es una key
    assert client.post("/adversarial/run", headers={"X-Service-Key": "wrong-key"}).status_code == 401
    assert runs == []  # la suite no se ejecutó

    response = client.post("/adversarial/run", headers=service_headers)
    assert response.status_code == 200
    assert response.json()["success"] is True
    assert runs == [1]


def test_service_key_rotation_accepts_any_configured_key(client, monkeypatch):
    monkeypatch.setattr(api_main, "run_adversarial_suite", lambda: True)
    monkeypatch.setenv("SERVICE_API_KEY", "old-service-key-0123456789, new-service-key-0123456789")

    assert client.post("/adversarial/run", headers={"X-Service-Key": "old-service-key-0123456789"}).status_code == 200
    assert client.post("/adversarial/run", headers={"X-Service-Key": "new-service-key-0123456789"}).status_code == 200
    assert client.post("/adversarial/run", headers={"X-Service-Key": "retired-key"}).status_code == 401


def test_admin_can_also_use_user_endpoints(client, admin_headers):
    assert client.get("/mandates", headers=admin_headers).status_code == 200


def test_list_mandates_requires_token(client, auth_headers):
    assert client.get("/mandates").status_code == 401

    response = client.get("/mandates", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


# ── Rol emitido por el login real (/auth/email/check) ───────────────────────

def _login(client, monkeypatch, email: str) -> dict:
    codes = []
    monkeypatch.setattr(auth_api, "otp_service", EmailOtpService())
    monkeypatch.setattr(
        auth_api, "send_verification_email",
        lambda address, code, ttl_seconds: codes.append(code) or True,
    )
    client.post("/auth/email/start", json={"email": email})
    return client.post("/auth/email/check", json={"email": email, "code": codes[-1]}).json()


def _role(access_token: str) -> str:
    return jwt.decode(access_token, TEST_JWT_SECRET, algorithms=["HS256"], issuer=ISSUER)["role"]


def test_login_of_admin_email_issues_admin_token(client, monkeypatch):
    monkeypatch.setenv("ADMIN_EMAILS", "ops@example.com, Boss@Example.com")

    token = _login(client, monkeypatch, "boss@example.com")["access_token"]  # sin distinguir mayúsculas

    assert _role(token) == "admin"
    monkeypatch.setattr(notifications, "leer_correos_recibidos", lambda limite=10: {"messages": []})
    assert client.get("/inbox/messages", headers=bearer(token)).status_code == 200


def test_login_of_non_admin_email_issues_user_token(client, monkeypatch):
    monkeypatch.setenv("ADMIN_EMAILS", "ops@example.com")

    token = _login(client, monkeypatch, "real.client@example.com")["access_token"]

    assert _role(token) == "user"
    assert client.get("/disputes", headers=bearer(token)).status_code == 200
    assert client.get("/inbox/messages", headers=bearer(token)).status_code == 403


def test_login_without_admin_emails_configured_is_always_user(client, monkeypatch):
    token = _login(client, monkeypatch, TEST_ADMIN_EMAIL)["access_token"]
    assert _role(token) == "user"


# ── Guardia: cada endpoint declara el esquema correcto en OpenAPI ───────────

# Operación → esquemas que DEBE declarar. POST /mandates declara los dos porque
# su dependencia mira ambas credenciales para distinguir 401 (sin credencial) de
# 403 (servicio autenticado, que no puede ser dueño de un mandato).
EXPECTED_SECURITY = {
    ("POST", "/mandates"): {"bearer", "service_key"},
    ("GET", "/inbox/messages"): "bearer",
    ("POST", "/notifications/send-ticket"): "bearer",
    ("POST", "/purchases/{purchase_id}/approve-exception"): "bearer",
    ("GET", "/mandates"): "bearer",
    ("POST", "/mandates/create"): "bearer",
    ("POST", "/mandates/{mandate_id}/pause"): "bearer",
    ("POST", "/mandates/{mandate_id}/resume"): "bearer",
    ("GET", "/mandates/{mandate_id}/activity"): "bearer",
    ("POST", "/purchases/execute"): "bearer",
    ("GET", "/disputes"): "bearer",
    ("POST", "/merchant/search"): "bearer",
    ("POST", "/adversarial/run"): "service_key",
}

# Endpoints que el frontend React llama hoy SIN credencial (frontend/src):
# protegerlos rompería la UI hasta que el frontend envíe el header.
# POST /mandates ya NO está aquí: desde 2D-3 exige token (React lo manda).
REACT_ROUTES = {
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


def _openapi_security_by_operation() -> dict[tuple[str, str], set[str]]:
    """Operación → tipos de esquema declarados ("bearer" / "service_key" / otro),
    según el esquema OpenAPI: contrato PÚBLICO de FastAPI, estable entre versiones
    (a diferencia de app.routes / route.dependant, que cambió en 0.141)."""
    schema = app.openapi()

    def kind(scheme: dict) -> str:
        if scheme.get("type") == "http" and scheme.get("scheme", "").lower() == "bearer":
            return "bearer"
        if scheme.get("type") == "apiKey" and scheme.get("in") == "header" and scheme.get("name") == "X-Service-Key":
            return "service_key"
        return f"other:{scheme}"

    kinds = {name: kind(scheme) for name, scheme in schema.get("components", {}).get("securitySchemes", {}).items()}
    return {
        (method.upper(), path): {kinds[name] for requirement in operation.get("security", []) for name in requirement}
        for path, operations in schema["paths"].items()
        for method, operation in operations.items()
    }


def test_each_internal_endpoint_declares_the_right_security_scheme():
    """Guardia: cada endpoint protegido declara exactamente sus esquemas (bearer
    para user/admin, API key para service), ningún otro endpoint declara seguridad,
    y los de React que siguen abiertos no declaran nada (protegerlos sin avisar
    rompería el frontend)."""
    security = _openapi_security_by_operation()

    # Las listas apuntan a operaciones que existen (un renombre no deja la guardia vacía).
    assert set(EXPECTED_SECURITY) <= set(security)
    assert REACT_ROUTES <= set(security)

    declared = {operation: kinds for operation, kinds in security.items() if kinds}
    expected = {
        operation: {kinds} if isinstance(kinds, str) else set(kinds)
        for operation, kinds in EXPECTED_SECURITY.items()
    }
    assert declared == expected
    assert all(not security[operation] for operation in REACT_ROUTES)


# ── Salvaguarda de SERVICE_API_KEY (largo mínimo) ───────────────────────────

def test_short_service_key_is_rejected_as_invalid_config(monkeypatch, caplog):
    # Una key corta, aunque venga junto a una válida, invalida la configuración.
    monkeypatch.setenv("SERVICE_API_KEY", "valid-service-key-0123456789," + "x" * (MIN_SERVICE_KEY_BYTES - 1))
    with pytest.raises(ServiceKeyConfigError, match="#2"):
        service_api_keys()

    # Al arrancar: error claro y la app no inicia.
    with caplog.at_level("CRITICAL", logger="agentbuyer.startup"):
        with pytest.raises(ServiceKeyConfigError):
            with TestClient(app):
                pass
    assert "SERVICE_API_KEY" in caplog.text and str(MIN_SERVICE_KEY_BYTES) in caplog.text


def test_short_service_key_set_after_startup_fails_closed(client, monkeypatch):
    """Config cambiada en caliente a una key débil: nunca se acepta (401, no 500)."""
    runs = []
    monkeypatch.setattr(api_main, "run_adversarial_suite", lambda: runs.append(1) or True)
    monkeypatch.setenv("SERVICE_API_KEY", "short-key")

    assert client.post("/adversarial/run", headers={"X-Service-Key": "short-key"}).status_code == 401
    assert runs == []


def test_service_key_of_minimum_length_works(client, monkeypatch):
    key = "k" * MIN_SERVICE_KEY_BYTES
    monkeypatch.setattr(api_main, "run_adversarial_suite", lambda: True)
    monkeypatch.setenv("SERVICE_API_KEY", key)

    assert service_api_keys() == [key.encode()]
    assert client.post("/adversarial/run", headers={"X-Service-Key": key}).status_code == 200


def test_app_starts_without_service_key_and_service_endpoint_is_closed(monkeypatch):
    monkeypatch.delenv("SERVICE_API_KEY", raising=False)
    runs = []
    monkeypatch.setattr(api_main, "run_adversarial_suite", lambda: runs.append(1) or True)

    with TestClient(app) as started_client:  # arranca sin error
        assert started_client.get("/health").status_code == 200
        response = started_client.post("/adversarial/run", headers={"X-Service-Key": "any-key-at-all-0123456789"})

    assert response.status_code == 401
    assert runs == []
