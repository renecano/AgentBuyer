"""Estado vivo unificado: live_state es la ÚNICA fuente de verdad de status,
uses_count y amount_spent, sin importar qué línea (estricta o permisiva) procesó
la compra. Es exactamente lo que React lee en GET /mandates/{id}."""
import json
from dataclasses import fields
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import api.main as api_main
from api.main import app
from core.agent_loop import PurchasingAgent
from core.auth_tokens import create_access_token
from core.mandate_store import (
    apply_approved_purchase,
    get_mandate,
    mandate_store,
    revoke_mandate,
)
from core.merchant import vuelaya_merchant
from core.verify import resolve_escalation
from engine.state import MandateRollingState
from datetime import datetime, timedelta, timezone

import core.mandate_store as mandate_store_module
from mandate.issue import create_mandate
from tests.conftest import TEST_USER_EMAIL, verify_as_service
from mandate.sign import generate_keypair
from shared.schemas import MandateStatus, VerificationStatus

# 4.2 (P-03): /verify es la verificación del comercio/agente: credencial `service`.
pytestmark = pytest.mark.usefixtures("service_key")

LIVE_STATE_KEYS = {"status", "uses_count", "amount_spent_cents", "revoked_at"}  # 5.1: centavos


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)  # firewall offline: tests herméticos
    mandate_store.clear()
    yield
    mandate_store.clear()


def strict_mandate(**overrides):
    h_priv, h_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    params = dict(
        human_id="hum_live", human_privkey=h_priv, human_pubkey=h_pub,
        agent_id="agent_marta", agent_pubkey=a_pub, max_amount_per_tx=150.0,
    )
    params.update(overrides)
    mandate = create_mandate(**params)
    mandate_store.save_mandate(mandate)
    return mandate, PurchasingAgent("agent_marta", a_priv, a_pub)


@pytest.fixture()
def client():
    """Cliente de la app (lo usa key_registrar para registrar llaves por el flujo real)."""
    with TestClient(app) as test_client:
        yield test_client


def live(mandate_id: str) -> dict:
    return get_mandate(mandate_id)["live_state"]


# ── La línea estricta escribe en lo que lee React ───────────────────────────

def test_strict_purchase_is_visible_in_get_mandate(auth_headers):
    """/purchases/execute (estricta) → GET /mandates/{id} (lo que lee la UI).

    3.5: POST /mandates/create se retiró (P-02). La línea estricta (legado D-01) solo
    entiende mandatos de mandate/issue.py, que ya no tienen endpoint de alta: aquí se
    crea uno por dentro, con la llave de AGENTE que el servidor usa en
    /purchases/execute. Esa línea y este sello se retiran en el 7.2 (P-08)."""
    with TestClient(app) as client:
        agent_keys = api_main._get_or_create_agent_keys("agent_marta")
        h_priv, h_pub = generate_keypair()
        mandate = create_mandate(
            human_id="hum_live", human_privkey=h_priv, human_pubkey=h_pub,
            agent_id="agent_marta", agent_pubkey=agent_keys["pub"], max_amount_per_tx=150.0,
        )
        mandate_store.save_mandate(mandate, owner_email=TEST_USER_EMAIL)
        mandate_id = mandate.mandate_id

        response = client.post("/purchases/execute", json={
            "mandate_id": mandate_id, "agent_id": "agent_marta", "item_id": "FLIGHT_COR_130",
        }, headers=auth_headers)
        assert response.json()["verification_result"]["status"] == "APPROVED"

        live_state = client.get(f"/mandates/{mandate_id}", headers=auth_headers).json()["live_state"]

    assert set(live_state) == LIVE_STATE_KEYS
    assert live_state == {"status": "active", "uses_count": 1, "amount_spent_cents": 13000, "revoked_at": None}
    assert isinstance(live_state["uses_count"], int) and not isinstance(live_state["uses_count"], bool)


def test_strict_approval_counts_exactly_once():
    mandate, agent = strict_mandate()
    agent.attempt_purchase(mandate, vuelaya_merchant.get_item("FLIGHT_COR_130"))
    agent.attempt_purchase(mandate, vuelaya_merchant.get_item("HOTEL_COR_90"))  # categoría fuera → escala, no consume

    assert live(mandate.mandate_id)["uses_count"] == 1
    assert live(mandate.mandate_id)["amount_spent_cents"] == 13000


def test_hitl_approval_on_strict_line_updates_live_state():
    mandate, agent = strict_mandate()
    _, escalated = agent.attempt_purchase(mandate, vuelaya_merchant.get_item("FLIGHT_COR_300"))
    assert escalated.status == VerificationStatus.ESCALATED_HITL
    assert live(mandate.mandate_id)["uses_count"] == 0

    resolution = resolve_escalation(escalated.escalation_id, approved=True, human_privkey="", human_pubkey="")

    assert resolution.status == VerificationStatus.APPROVED
    assert live(mandate.mandate_id)["uses_count"] == 1
    assert live(mandate.mandate_id)["amount_spent_cents"] == 30000


# ── Una sola verdad para ambos pipelines ────────────────────────────────────

def test_both_pipelines_consume_and_read_the_same_counters():
    """Un uso consumido con la función de la línea permisiva cuenta para los
    límites de la estricta, y viceversa: no hay dos contadores que diverjan."""
    mandate, agent = strict_mandate(max_executions_per_month=2)

    apply_approved_purchase(mandate.mandate_id, 4000)  # lo que hacen api/verify y api/escalations (centavos)
    assert live(mandate.mandate_id)["uses_count"] == 1

    _, second = agent.attempt_purchase(mandate, vuelaya_merchant.get_item("FLIGHT_COR_130"))
    assert second.status == VerificationStatus.APPROVED
    assert live(mandate.mandate_id) == {"status": "active", "uses_count": 2, "amount_spent_cents": 17000, "revoked_at": None}

    _, third = agent.attempt_purchase(mandate, vuelaya_merchant.get_item("FLIGHT_COR_130"))
    assert third.authorized is False
    assert next(check for check in third.checks if check["rule"] == "uses")["pass"] is False
    assert live(mandate.mandate_id)["uses_count"] == 2  # el intento bloqueado no consumió


def test_state_manager_holds_no_counters():
    """Solo nonces anti-replay: ningún número de uso/gasto vive fuera de live_state."""
    field_names = {field.name for field in fields(MandateRollingState)}
    assert not {"count_this_month", "spent_this_month"} & field_names


# ── Status expuesto único ───────────────────────────────────────────────────

def test_status_seen_by_ui_and_strict_line_is_the_same():
    mandate, _ = strict_mandate()

    mandate_store.pause_mandate(mandate.mandate_id)
    assert live(mandate.mandate_id)["status"] == "paused"
    assert mandate_store.get_mandate(mandate.mandate_id).status == MandateStatus.PAUSED

    mandate_store.resume_mandate(mandate.mandate_id)
    revoked = revoke_mandate(mandate.mandate_id)  # variante funcional: solo toca live_state
    strict_view = mandate_store.get_mandate(mandate.mandate_id)
    assert revoked["live_state"]["status"] == "revoked"
    assert strict_view.status == MandateStatus.REVOKED
    assert strict_view.revoked_at == revoked["live_state"]["revoked_at"]


def test_expiry_is_exposed_without_a_prior_strict_read(client, auth_headers, signed_poster, monkeypatch):
    """Antes, GET /mandates/{id} mostraba "active" en un mandato vencido hasta que
    alguien lo leía por la clase. Ahora ambos lectores aplican la misma regla.

    3.5: el mandato lo firma el titular (un expires_at pasado ni se firmaría: debe ser
    posterior a created_at), así que se vence adelantando el reloj del almacén."""
    expiring = {
        "mandate_id": "mnd_live_expired",
        "human": {"id": "hum_live", "display_name": "Test User"},
        "agent": {"id": "agt_saturday"},
        "constraints": {
            "max_amount_per_purchase": 150.0, "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"], "max_uses": 3,
        },
    }
    signed = signed_poster.create(expiring)
    expires_at = datetime.strptime(signed["mandate"]["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    monkeypatch.setattr(mandate_store_module, "_utcnow", lambda: expires_at + timedelta(seconds=1))

    live_state = client.get("/mandates/mnd_live_expired", headers=auth_headers).json()["live_state"]
    assert live_state["status"] == "expired"
    assert mandate_store.get_mandate("mnd_live_expired").status == MandateStatus.EXPIRED

    verification = verify_as_service(client, {
        "attempt_id": "att_live_expired", "mandate_id": "mnd_live_expired", "presented_by_agent": "agt_saturday",
        "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount_cents": 10000, "metadata": {"price_cents": 10000}},
    }).json()
    assert verification["verdict"] == "REJECT"
    assert next(check for check in verification["checks"] if check["rule"] == "status")["pass"] is False


def test_expired_seed_is_still_rejected(monkeypatch, tmp_path):
    """Contraprueba del fixture active_seed: la expiración NO se debilitó. El mismo
    seed, con un expires_at realmente vencido y cargado por el arranque normal,
    se ve EXPIRED desde ambos lectores (UI y línea estricta) y /verify lo rechaza."""
    seeds = json.loads(Path(api_main.SEED_PATH).read_text(encoding="utf-8"))
    for seed in seeds:
        seed["expires_at"] = "2020-01-01T00:00:00Z"
    expired_seed = tmp_path / "seed_mandates.json"
    expired_seed.write_text(json.dumps(seeds, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(api_main, "SEED_PATH", str(expired_seed))
    seed_id = seeds[0]["mandate_id"]
    # Leer un mandato exige ser su dueño: el del seed es su human.email.
    owner_headers = {"Authorization": f"Bearer {create_access_token(seeds[0]['human']['email'])}"}

    with TestClient(app) as client:
        assert client.get(f"/mandates/{seed_id}", headers=owner_headers).json()["live_state"]["status"] == "expired"
        assert mandate_store.get_mandate(seed_id).status == MandateStatus.EXPIRED

        verification = verify_as_service(client, {
            "attempt_id": "att_expired_seed", "mandate_id": seed_id,
            "presented_by_agent": seeds[0]["agent"]["id"],
            "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount_cents": 10000, "metadata": {"price_cents": 10000}},
        }).json()
        assert verification["verdict"] == "REJECT"
        assert next(check for check in verification["checks"] if check["rule"] == "status")["pass"] is False
