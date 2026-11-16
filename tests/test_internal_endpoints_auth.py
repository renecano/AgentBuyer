"""Endpoints internos (React no los llama) protegidos por rol:
- user    (require_principal): JWT válido.
- admin   (is_admin):          JWT válido con role="admin" y email en ADMIN_EMAILS.
                               7.1: ya no hay rutas solo-admin (inbox, send-ticket y
                               approve-exception se retiraron, P-06/P-07); el poder
                               admin es ver TODO en GET /audit y GET /disputes, y ahí
                               se prueba.
- service (require_service):   header X-Service-Key contra SERVICE_API_KEY.

401 = no autenticado; 403 = autenticado sin el rol. El efecto nunca ocurre sin
la credencial correcta.

3.5: se retiraron POST /mandates/create (P-02) y POST /adversarial/run (creaba
mandatos sellados por el servidor en el registro vivo). Este era el único endpoint
de producto con identidad `service`; hasta que /verify lo sea (4.2, P-03), la
mecánica de require_service se prueba contra una ruta de prueba (SERVICE_PROBE) que
solo depende de ella y no aparece en el esquema OpenAPI."""
import jwt
import pytest
from fastapi import Depends
from fastapi.testclient import TestClient

import api.auth as auth_api
import core.notifications as notifications
from api.main import app
from audit.log import append_entry, get_trail_events
from core.auth_config import MIN_SERVICE_KEY_BYTES, ServiceKeyConfigError, service_api_keys
from core.auth_tokens import ISSUER, create_access_token
from api.security import Principal, require_service
from core.email_otp import EmailOtpService
from tests.conftest import TEST_ADMIN_EMAIL, TEST_JWT_SECRET, TEST_SERVICE_KEY

USER, ADMIN, SERVICE = "user", "admin", "service"

# Ruta de prueba con identidad service (ver docstring del módulo).
SERVICE_PROBE = "/__tests__/service-probe"

# (método, ruta concreta) → (body, rol exigido). Bodies vacíos o inválidos a
# propósito: la autorización debe rechazar ANTES de validar el body (401/403, no 422).
ENDPOINTS = {
    ("GET", "/mandates"): (None, USER),
    ("POST", "/mandates/mnd_x/pause"): (None, USER),
    ("POST", "/mandates/mnd_x/resume"): (None, USER),
    ("GET", "/mandates/mnd_x/activity"): (None, USER),
    ("POST", SERVICE_PROBE): (None, SERVICE),
    ("GET", "/disputes"): (None, USER),
    ("POST", "/merchant/search"): ({}, USER),
}

BEARER_ENDPOINTS = {key: value for key, value in ENDPOINTS.items() if value[1] in (USER, ADMIN)}
SERVICE_ENDPOINTS = {key: value for key, value in ENDPOINTS.items() if value[1] == SERVICE}


def ids(endpoints):
    return [f"{method} {path}" for method, path in endpoints]


@pytest.fixture(autouse=True)
def service_probe():
    """Monta SERVICE_PROBE (solo require_service) durante el test; devuelve los sujetos
    que la atravesaron, para comprobar que el efecto solo ocurre con la key correcta."""
    calls: list[str] = []

    def probe(principal: Principal = Depends(require_service)):
        calls.append(principal.subject)
        return {"ok": True}

    app.add_api_route(SERVICE_PROBE, probe, methods=["POST"], include_in_schema=False)
    yield calls
    app.router.routes[:] = [route for route in app.router.routes if getattr(route, "path", None) != SERVICE_PROBE]


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


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


# ── El rol admin: ver TODO el trail (GET /audit) ────────────────────────────

FOREIGN_EVENT = "only an admin sees this"


def sees_everything(client, headers) -> bool:
    """¿Estas credenciales ven un evento de un mandato que no es de nadie? Solo un admin."""
    if not any(event["summary"] == FOREIGN_EVENT for event in get_trail_events()):
        append_entry({"type": "verification", "mandate_id": "mnd_nobodys", "summary": FOREIGN_EVENT})
    response = client.get("/audit", headers=headers)
    assert response.status_code == 200, response.text
    return any(event["summary"] == FOREIGN_EVENT for event in response.json())


def test_admin_sees_the_whole_trail_and_a_user_does_not(client, auth_headers, admin_headers):
    assert sees_everything(client, admin_headers) is True
    assert sees_everything(client, auth_headers) is False


def test_admin_role_is_revoked_when_email_leaves_admin_emails(client, admin_headers, monkeypatch):
    assert sees_everything(client, admin_headers) is True
    monkeypatch.setenv("ADMIN_EMAILS", "someone.else@example.com")
    # El mismo token admin, todavía vigente, ya no ve lo ajeno: sigue siendo un usuario válido.
    assert sees_everything(client, admin_headers) is False


def test_user_token_of_listed_email_is_not_admin(client, admin_headers):
    """El rol lo fija el token al emitirse: un token "user" no se vuelve admin."""
    user_token_same_email = create_access_token(TEST_ADMIN_EMAIL)
    assert sees_everything(client, bearer(user_token_same_email)) is False


def test_forged_admin_claim_is_401_not_403(client, admin_headers):
    forged = jwt.encode(
        {"iss": ISSUER, "sub": TEST_ADMIN_EMAIL, "role": "admin", "iat": 1_900_000_000, "exp": 4_000_000_000},
        "attacker-secret-0123456789-abcdefghijklmnopqrstuv",
        algorithm="HS256",
    )
    assert client.get("/audit", headers=bearer(forged)).status_code == 401


# ── Credenciales que no se mezclan ──────────────────────────────────────────

def test_admin_jwt_does_not_open_service_endpoint(client, admin_headers, service_headers):
    response = client.post(SERVICE_PROBE, headers=admin_headers)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "X-Service-Key"


def test_service_key_does_not_open_bearer_endpoints(client, service_headers):
    assert client.get("/disputes", headers=service_headers).status_code == 401
    assert client.get("/audit", headers=service_headers).status_code == 401


def test_service_endpoint_fails_closed_without_configured_key(client, monkeypatch, caplog):
    monkeypatch.delenv("SERVICE_API_KEY", raising=False)
    with caplog.at_level("WARNING", logger="api.security"):
        response = client.post(SERVICE_PROBE, headers={"X-Service-Key": "anything"})
    assert response.status_code == 401
    assert "SERVICE_API_KEY" in caplog.text


# ── Pares sin credencial / credencial correcta (el efecto solo ocurre con ella) ──

@pytest.mark.parametrize("method, path, body", [
    ("GET", "/inbox/messages", None),
    ("POST", "/notifications/send-ticket", {"email": "victim@example.com"}),
    ("POST", "/purchases/att_forged/approve-exception", {}),
    ("POST", "/webhooks/stripe", {"data": {"object": {"metadata": {"mandate_id": "mnd_x"}, "amount": 13000}}}),
    ("POST", "/webhooks/travel-provider", {"email": "victim@example.com", "mandate_id": "mnd_x"}),
])
def test_demo_routes_retired_in_7_1_are_gone(client, admin_headers, monkeypatch, method, path, body):
    """7.1 (P-06, P-07): ni siquiera un admin las alcanza, y nada se escribe ni se envía.
    Los webhooks ni siquiera pedían credencial: cualquiera podía escribir en el ledger."""
    sent = []
    monkeypatch.setattr(notifications, "_deliver", lambda *args: sent.append(args))
    before = len(get_trail_events())
    assert call(client, method, path, body, headers=admin_headers).status_code in (404, 405)
    assert call(client, method, path, body).status_code in (404, 405)
    assert len(get_trail_events()) == before and sent == []


def test_service_identity_requires_service_key(client, service_probe, auth_headers, service_headers):
    assert client.post(SERVICE_PROBE).status_code == 401
    assert client.post(SERVICE_PROBE, headers=auth_headers).status_code == 401  # un JWT no es una key
    assert client.post(SERVICE_PROBE, headers={"X-Service-Key": "wrong-key"}).status_code == 401
    assert service_probe == []  # el efecto no ocurrió

    response = client.post(SERVICE_PROBE, headers=service_headers)
    assert response.status_code == 200
    assert service_probe == ["service"]


def test_retired_routes_are_gone(client, auth_headers, service_headers):
    """3.5: POST /mandates/create (P-02) y POST /adversarial/run ya no existen."""
    assert client.post("/mandates/create", json={}, headers=auth_headers).status_code in (404, 405)
    assert client.post("/adversarial/run", headers=service_headers).status_code in (404, 405)


def test_service_key_rotation_accepts_any_configured_key(client, monkeypatch):
    monkeypatch.setenv("SERVICE_API_KEY", "old-service-key-0123456789, new-service-key-0123456789")

    assert client.post(SERVICE_PROBE, headers={"X-Service-Key": "old-service-key-0123456789"}).status_code == 200
    assert client.post(SERVICE_PROBE, headers={"X-Service-Key": "new-service-key-0123456789"}).status_code == 200
    assert client.post(SERVICE_PROBE, headers={"X-Service-Key": "retired-key"}).status_code == 401


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
    assert sees_everything(client, bearer(token)) is True


def test_login_of_non_admin_email_issues_user_token(client, monkeypatch):
    monkeypatch.setenv("ADMIN_EMAILS", "ops@example.com")

    token = _login(client, monkeypatch, "real.client@example.com")["access_token"]

    assert _role(token) == "user"
    assert client.get("/disputes", headers=bearer(token)).status_code == 200
    assert sees_everything(client, bearer(token)) is False


def test_login_without_admin_emails_configured_is_always_user(client, monkeypatch):
    token = _login(client, monkeypatch, TEST_ADMIN_EMAIL)["access_token"]
    assert _role(token) == "user"


# ── Guardia: cada endpoint declara el esquema correcto en OpenAPI ───────────

# Operación → esquemas que DEBE declarar. POST /mandates declara los dos porque
# su dependencia mira ambas credenciales para distinguir 401 (sin credencial) de
# 403 (servicio autenticado, que no puede ser dueño de un mandato).
EXPECTED_SECURITY = {
    ("POST", "/mandates"): {"bearer", "service_key"},
    # Por-mandato: token + ser dueño o admin (require_mandate_access).
    ("GET", "/mandates/{mandate_id}"): "bearer",
    ("POST", "/mandates/{mandate_id}/revoke"): "bearer",
    ("POST", "/mandates/{mandate_id}/approve_escalation"): "bearer",
    ("GET", "/audit/{mandate_id}"): "bearer",
    # Registro de llaves públicas: el dueño sale del token (require_principal).
    ("POST", "/keys"): "bearer",
    ("GET", "/keys"): "bearer",
    # Prueba de posesión: step-up OTP al email del token y challenge (sesión + OTP).
    ("POST", "/keys/step-up/start"): "bearer",
    ("POST", "/keys/challenge"): "bearer",
    ("DELETE", "/keys/{key_id}"): "bearer",
    ("GET", "/mandates"): "bearer",
    ("POST", "/mandates/{mandate_id}/pause"): "bearer",
    ("POST", "/mandates/{mandate_id}/resume"): "bearer",
    ("GET", "/mandates/{mandate_id}/activity"): "bearer",
    ("GET", "/disputes"): "bearer",
    ("POST", "/merchant/search"): "bearer",
    # 4.1: las rutas de React que seguían abiertas exigen sesión (P-04, P-05).
    ("POST", "/agent/run"): "bearer",
    ("GET", "/audit"): "bearer",
    ("POST", "/disputes/file"): "bearer",
    # 4.2 (P-03): la verificación es del comercio/agente.
    ("POST", "/verify"): "service_key",
}

# Endpoints que el frontend React llama hoy SIN credencial (frontend/src):
# protegerlos rompería la UI hasta que el frontend envíe el header.
# Los de por-mandato ya NO están aquí: exigen token y propiedad (EXPECTED_SECURITY).
# 4.2: ninguna ruta que llame React queda sin seguridad (/verify pasó a `service`).
REACT_ROUTES: set = set()


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


def test_short_service_key_set_after_startup_fails_closed(client, service_probe, monkeypatch):
    """Config cambiada en caliente a una key débil: nunca se acepta (401, no 500)."""
    monkeypatch.setenv("SERVICE_API_KEY", "short-key")

    assert client.post(SERVICE_PROBE, headers={"X-Service-Key": "short-key"}).status_code == 401
    assert service_probe == []


def test_service_key_of_minimum_length_works(client, monkeypatch):
    key = "k" * MIN_SERVICE_KEY_BYTES
    monkeypatch.setenv("SERVICE_API_KEY", key)

    assert service_api_keys() == [key.encode()]
    assert client.post(SERVICE_PROBE, headers={"X-Service-Key": key}).status_code == 200


def test_app_starts_without_service_key_and_service_endpoint_is_closed(monkeypatch, service_probe):
    monkeypatch.delenv("SERVICE_API_KEY", raising=False)

    with TestClient(app) as started_client:  # arranca sin error
        assert started_client.get("/health").status_code == 200
        response = started_client.post(SERVICE_PROBE, headers={"X-Service-Key": "any-key-at-all-0123456789"})

    assert response.status_code == 401
    assert service_probe == []
