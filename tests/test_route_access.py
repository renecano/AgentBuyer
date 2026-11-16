"""Paso 4.1: las rutas de React que seguían abiertas exigen sesión y propiedad.

/agent/run (dueño + cuota), GET /audit (P-04: lo suyo; admin todo), /disputes/file
(dueño; el intento debe ser de ESE mandato; evidencia sin eventos ajenos), GET
/disputes (lo suyo), /audit/reset (P-05: utilidad de desarrollo, admin +
AUTH_DEV_MODE) y escalaciones sobre mandatos que ya no son válidos (409).
Todo por HTTP con tokens reales; mandatos firmados por su titular; red simulada.
"""
import pytest
from fastapi.testclient import TestClient

import api.agent as agent_api
from api.main import app
from audit.log import append_entry, get_trail_events, get_trail_for, reset_trail
from core import mandate_store, merchant_search, owner_keys
from core.auth_tokens import create_access_token
from core.quotas import PerSubjectQuota
from tests.conftest import FakeClock, TEST_ADMIN_EMAIL, TEST_USER_EMAIL

OTHER = "otra.persona@example.com"


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: "[]")  # sin red
    mandate_store.mandate_store.clear()
    owner_keys.clear()
    reset_trail()
    with TestClient(app) as test_client:
        yield test_client
    mandate_store.mandate_store.clear()
    owner_keys.clear()
    reset_trail()


@pytest.fixture()
def quota(monkeypatch) -> tuple[PerSubjectQuota, FakeClock]:
    clock = FakeClock()
    fresh = PerSubjectQuota(limit=3, window_seconds=3600, clock=clock)
    monkeypatch.setattr(agent_api, "agent_run_quota", fresh)
    return fresh, clock


def bearer(email: str) -> dict:
    return {"Authorization": f"Bearer {create_access_token(email)}"}


def mandate(mandate_id: str) -> dict:
    return {
        "mandate_id": mandate_id,
        "human": {"id": "hum_x", "display_name": "X"},
        "agent": {"id": "agt_saturday"},
        "search_fields": {"origin": "BUE", "destination": "COR", "departure_date": "2026-12-05"},
        "constraints": {
            "max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"], "max_uses": 3,
            "conditions": [{"type": "price_below", "value": 150}],
        },
    }


@pytest.fixture()
def two_users(signed_poster):
    """El usuario de la suite y OTRO, cada uno con su mandato firmado."""
    signed_poster.create(mandate("mnd_mine"), email=TEST_USER_EMAIL)
    signed_poster.create(mandate("mnd_theirs"), email=OTHER)
    return "mnd_mine", "mnd_theirs"


def verify(client, mandate_id: str, attempt_id: str, amount: float = 100.0) -> dict:
    return client.post("/verify", json={
        "attempt_id": attempt_id, "mandate_id": mandate_id, "presented_by_agent": "agt_saturday",
        "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount": amount,
                     "currency": "USD", "metadata": {"price": amount}},
    }).json()


# ── POST /agent/run ─────────────────────────────────────────────────────────

def test_agent_run_matrix(client, two_users, quota, admin_headers):
    body = {"mandate_id": "mnd_mine"}
    assert client.post("/agent/run", json=body).status_code == 401
    assert client.post("/agent/run", json=body, headers={"Authorization": "Bearer not-a-valid-jwt"}).status_code == 401
    assert client.post("/agent/run", json=body, headers=bearer(OTHER)).status_code == 403
    assert client.post("/agent/run", json={"mandate_id": "mnd_nope"}, headers=bearer(TEST_USER_EMAIL)).status_code == 404
    assert client.post("/agent/run", json=body, headers=bearer(TEST_USER_EMAIL)).status_code == 200
    assert client.post("/agent/run", json=body, headers=admin_headers).status_code == 200


def test_agent_run_quota_429_with_retry_after(client, two_users, quota):
    limiter, clock = quota
    headers = bearer(TEST_USER_EMAIL)
    for _ in range(limiter.limit):
        assert client.post("/agent/run", json={"mandate_id": "mnd_mine"}, headers=headers).status_code == 200
    clock.advance(600)
    exceeded = client.post("/agent/run", json={"mandate_id": "mnd_mine"}, headers=headers)

    assert exceeded.status_code == 429
    assert exceeded.headers["Retry-After"] == str(3600 - 600)
    assert "retry-after" in client.post("/agent/run", json={"mandate_id": "mnd_mine"},
                                        headers={**headers, "Origin": "http://localhost:5173"}
                                        ).headers.get("access-control-expose-headers", "").lower()
    # La cuota es POR usuario: otra persona sigue pudiendo usar el agente en su mandato.
    assert client.post("/agent/run", json={"mandate_id": "mnd_theirs"}, headers=bearer(OTHER)).status_code == 200
    # Y vuelve cuando la ventana pasa.
    clock.advance(3000)
    assert client.post("/agent/run", json={"mandate_id": "mnd_mine"}, headers=headers).status_code == 200


def test_agent_run_rejected_before_searching_does_not_spend_quota(client, two_users, quota):
    limiter, _ = quota
    headers = bearer(TEST_USER_EMAIL)
    other_fields = {"origin": "MEX", "destination": "MIA", "departure_date": "2026-12-05"}
    for _ in range(limiter.limit + 2):
        response = client.post("/agent/run", json={"mandate_id": "mnd_mine", "search_fields": other_fields}, headers=headers)
        assert response.status_code == 422  # el 422 devuelve el uso
    # Ni un no-dueño gasta la cuota del dueño.
    for _ in range(limiter.limit + 2):
        assert client.post("/agent/run", json={"mandate_id": "mnd_mine"}, headers=bearer(OTHER)).status_code == 403
    assert client.post("/agent/run", json={"mandate_id": "mnd_mine"}, headers=headers).status_code == 200


# ── GET /audit (P-04) ───────────────────────────────────────────────────────

def test_audit_matrix_user_sees_only_own_and_admin_sees_all(client, two_users, admin_headers):
    verify(client, "mnd_mine", "att_mine")
    verify(client, "mnd_theirs", "att_theirs")

    assert client.get("/audit").status_code == 401
    mine = client.get("/audit", headers=bearer(TEST_USER_EMAIL)).json()
    theirs = client.get("/audit", headers=bearer(OTHER)).json()
    everything = client.get("/audit", headers=admin_headers).json()

    assert {event["mandate_id"] for event in mine} == {"mnd_mine"}
    assert {event["mandate_id"] for event in theirs} == {"mnd_theirs"}
    assert {event["mandate_id"] for event in everything} == {"mnd_mine", "mnd_theirs"}
    assert client.get("/audit", headers=bearer("nobody@example.com")).json() == []


def test_trail_filters_by_attempt_id(client, two_users):
    verify(client, "mnd_mine", "att_one")
    verify(client, "mnd_mine", "att_two")
    assert {event["attempt_id"] for event in get_trail_for("auditor", attempt_id="att_one")} == {"att_one"}
    assert {event["attempt_id"] for event in get_trail_for("human", "mnd_mine", attempt_id="att_two")} == {"att_two"}


# ── POST /disputes/file y GET /disputes ─────────────────────────────────────

def dispute(client, headers, mandate_id: str, attempt_id: str):
    return client.post("/disputes/file", json={
        "attempt_id": attempt_id, "mandate_id": mandate_id, "claimant_id": "hum_x", "reason": "I don't recognize it.",
    }, headers=headers)


def test_dispute_matrix(client, two_users, admin_headers):
    verify(client, "mnd_mine", "att_mine")
    assert dispute(client, None, "mnd_mine", "att_mine").status_code == 401
    assert dispute(client, bearer(OTHER), "mnd_mine", "att_mine").status_code == 403
    assert dispute(client, bearer(TEST_USER_EMAIL), "mnd_mine", "att_mine").status_code == 200
    assert dispute(client, admin_headers, "mnd_mine", "att_mine").status_code == 200


def test_dispute_evidence_has_no_foreign_events(client, two_users):
    verify(client, "mnd_mine", "att_mine")
    verify(client, "mnd_theirs", "att_theirs")
    claim = dispute(client, bearer(TEST_USER_EMAIL), "mnd_mine", "att_mine").json()

    assert claim["liable_party"] == "HUMAN"  # compra verificada y aprobada
    assert {event["mandate_id"] for event in claim["audit_evidence"]} == {"mnd_mine"}


def test_cannot_dispute_someone_elses_attempt_under_your_own_mandate(client, two_users):
    """Antes: el intento ajeno no aparecía en la evidencia del mandato propio y el
    árbitro fallaba "comercio responsable + reembolso". Ahora es 403 y no se resuelve nada."""
    verify(client, "mnd_theirs", "att_theirs")
    response = dispute(client, bearer(TEST_USER_EMAIL), "mnd_mine", "att_theirs")

    assert response.status_code == 403
    assert not [event for event in get_trail_events() if event.get("type", "").startswith("DISPUTE")]


def test_list_disputes_shows_only_own(client, two_users, admin_headers):
    verify(client, "mnd_mine", "att_mine")
    verify(client, "mnd_theirs", "att_theirs")
    dispute(client, bearer(TEST_USER_EMAIL), "mnd_mine", "att_mine")
    dispute(client, bearer(OTHER), "mnd_theirs", "att_theirs")

    assert {claim["mandate_id"] for claim in client.get("/disputes", headers=bearer(TEST_USER_EMAIL)).json()} == {"mnd_mine"}
    assert {claim["mandate_id"] for claim in client.get("/disputes", headers=admin_headers).json()} >= {"mnd_mine", "mnd_theirs"}


# ── POST /audit/reset (P-05) ────────────────────────────────────────────────

def test_audit_reset_is_out_of_the_product(client, two_users, auth_headers, admin_headers, monkeypatch):
    append_entry({"type": "verification", "mandate_id": "mnd_mine", "summary": "keep me"})
    before = len(get_trail_events())

    assert client.post("/audit/reset").status_code == 401
    assert client.post("/audit/reset", headers=auth_headers).status_code == 403
    assert client.post("/audit/reset", headers=admin_headers).status_code == 404  # sin AUTH_DEV_MODE no existe
    assert len(get_trail_events()) == before  # el ledger sigue intacto

    monkeypatch.setenv("AUTH_DEV_MODE", "true")
    assert client.post("/audit/reset", headers=auth_headers).status_code == 403  # ni en dev un user
    assert client.post("/audit/reset", headers=admin_headers).status_code == 200
    assert get_trail_events() == []


def test_audit_reset_is_registered_once(client):
    routes = [route for route in app.routes if getattr(route, "path", None) == "/audit/reset"]
    assert len(routes) == 1


# ── Escalaciones sobre mandatos que ya no son válidos ───────────────────────

def escalated(client, mandate_id: str) -> str:
    result = verify(client, mandate_id, "att_big", amount=300.0)
    assert result["verdict"] == "ESCALATE"
    return "att_big"


def approve(client, mandate_id: str, attempt_id: str, headers):
    return client.post(f"/mandates/{mandate_id}/approve_escalation",
                       json={"purchase_attempt_id": attempt_id, "decision": "approve"}, headers=headers)


@pytest.mark.parametrize("action", ["revoke", "pause"])
def test_cannot_approve_escalation_on_revoked_or_paused_mandate(client, two_users, action):
    headers = bearer(TEST_USER_EMAIL)
    attempt = escalated(client, "mnd_mine")
    assert client.post(f"/mandates/mnd_mine/{action}", headers=headers).status_code == 200
    assert approve(client, "mnd_mine", attempt, headers).status_code == 409


def test_cannot_approve_escalation_on_expired_mandate(client, two_users, monkeypatch):
    from datetime import datetime, timedelta, timezone
    headers = bearer(TEST_USER_EMAIL)
    attempt = escalated(client, "mnd_mine")
    expires = datetime.strptime(mandate_store.MANDATES["mnd_mine"]["mandate"]["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
    monkeypatch.setattr(mandate_store, "_utcnow", lambda: expires.replace(tzinfo=timezone.utc) + timedelta(seconds=1))
    assert approve(client, "mnd_mine", attempt, headers).status_code == 409


def test_cannot_approve_escalation_when_the_signing_key_was_revoked(client, signed_poster):
    signed_poster.create(mandate("mnd_mine"), email=TEST_USER_EMAIL)
    headers = bearer(TEST_USER_EMAIL)
    attempt = escalated(client, "mnd_mine")
    key_id = mandate_store.MANDATES["mnd_mine"]["mandate"]["key_id"]
    assert client.delete(f"/keys/{key_id}", headers=headers).status_code == 200

    response = approve(client, "mnd_mine", attempt, headers)
    assert response.status_code == 409
    assert "revocada" in response.json()["detail"]
    assert mandate_store.MANDATES["mnd_mine"]["live_state"]["uses_count"] == 0


def test_strict_line_escalation_on_revoked_mandate_is_rejected():
    """core/verify.resolve_escalation: aprobar sobre un mandato revocado no compra."""
    from core.agent_loop import PurchasingAgent
    from core.merchant import vuelaya_merchant
    from core.verify import resolve_escalation
    from mandate.issue import create_mandate
    from mandate.sign import generate_keypair
    from shared.schemas import VerificationStatus

    mandate_store.mandate_store.clear()
    h_priv, h_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    strict = create_mandate(human_id="hum_s", human_privkey=h_priv, human_pubkey=h_pub,
                            agent_id="agent_s", agent_pubkey=a_pub, max_amount_per_tx=50.0)
    mandate_store.mandate_store.save_mandate(strict)
    agent = PurchasingAgent("agent_s", a_priv, a_pub)
    _, result = agent.attempt_purchase(strict, vuelaya_merchant.get_item("FLIGHT_COR_130"), merchant=vuelaya_merchant)
    assert result.escalation_id, result.reason

    mandate_store.mandate_store.revoke_mandate(strict.mandate_id)
    resolved = resolve_escalation(result.escalation_id, True, h_priv, h_pub, "approve")
    assert resolved.status == VerificationStatus.REJECTED
    assert mandate_store.get_mandate(strict.mandate_id)["live_state"]["uses_count"] == 0
    mandate_store.mandate_store.clear()
