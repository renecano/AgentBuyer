"""Paso 5.2: "verificar y consumir" atómico y presupuesto mensual real.

- max_uses y el presupuesto se re-chequean y consumen en UNA operación atómica
  (core/mandate_store.reserve_purchase): 50 compras simultáneas no superan el límite.
- monthly_budget_cents se aplica por mes calendario UTC y se reinicia al cambiar de
  mes (reloj inyectado, sin esperas). En la spec firmada v1 no existe (D-17): lo
  declaran el seed y la línea estricta.
"""
import secrets
import threading
import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import core.mandate_store as store_module
from api.main import app
from api.verify import verify_attempt
from audit.log import reset_trail
from core import mandate_store, owner_keys
from core.auth_tokens import create_access_token
from core.mandate_store import MANDATES, period_usage, seal_seed_mandate
from engine.evaluator import evaluate
from tests.conftest import TEST_USER_EMAIL


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    mandate_store.mandate_store.clear()
    owner_keys.clear()
    reset_trail()
    with TestClient(app) as test_client:
        yield test_client
    mandate_store.mandate_store.clear()
    owner_keys.clear()
    reset_trail()


@pytest.fixture()
def clock(monkeypatch):
    class Clock:
        now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(store_module, "_utcnow", lambda: Clock.now)
    return Clock


def attempt(mandate_id: str, cents: int = 10000) -> dict:
    return {
        "attempt_id": f"att_{secrets.token_hex(6)}", "mandate_id": mandate_id, "presented_by_agent": "agt_saturday",
        "nonce": secrets.token_hex(16),
        "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount_cents": cents,
                     "currency": "USD", "metadata": {"price_cents": cents}},
    }


def sealed(mandate_id: str, **constraints) -> str:
    """Mandato con presupuesto mensual (camino del seed: el único que lo declara en v1)."""
    seal_seed_mandate({
        "mandate_id": mandate_id, "human": {"id": "hum_x", "display_name": "X"}, "agent": {"id": "agt_saturday"},
        "constraints": {"max_amount_per_purchase": 150, "currency": "USD", "allowed_categories": ["travel.flights"],
                        "allowed_merchants": ["mch_vuelaya"], "max_uses": 50, **constraints},
    }, owner_email=TEST_USER_EMAIL)
    return mandate_id


def race(mandate_id: str, n: int, monkeypatch, cents: int = 10000) -> list[str]:
    """`n` compras a la vez. La costura _reservation_pause ensancha la carrera: con el
    lock no cambia nada; sin él, varias verían el mismo uso libre."""
    monkeypatch.setattr(store_module, "_reservation_pause", lambda: time.sleep(0.002))
    barrier = threading.Barrier(n)
    verdicts: list[str] = []
    lock = threading.Lock()

    def buy():
        body = attempt(mandate_id, cents)
        barrier.wait()
        verdict = verify_attempt(body)["verdict"]
        with lock:
            verdicts.append(verdict)

    threads = [threading.Thread(target=buy) for _ in range(n)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return verdicts


# ── Atomicidad ──────────────────────────────────────────────────────────────

def test_fifty_concurrent_purchases_against_max_uses_3_approve_exactly_3(client, signed_poster, monkeypatch):
    signed_poster.create({
        "mandate_id": "mnd_race", "human": {"id": "hum_x", "display_name": "X"}, "agent": {"id": "agt_saturday"},
        "constraints": {"max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
                        "allowed_merchants": ["mch_vuelaya"], "max_uses": 3},
    })
    verdicts = race("mnd_race", 50, monkeypatch)

    assert verdicts.count("APPROVE") == 3
    assert MANDATES["mnd_race"]["live_state"]["uses_count"] == 3
    assert MANDATES["mnd_race"]["live_state"]["amount_spent_cents"] == 30000
    assert set(verdicts) <= {"APPROVE", "ESCALATE"}  # las demás quedan para la persona, ninguna compra de más


def test_concurrent_purchases_never_exceed_the_monthly_budget(client, clock, monkeypatch):
    sealed("mnd_budget_race", monthly_budget=250)  # caben exactamente 2 de 100
    verdicts = race("mnd_budget_race", 30, monkeypatch)

    assert verdicts.count("APPROVE") == 2
    assert period_usage("mnd_budget_race")["spent_cents"] == 20000
    assert MANDATES["mnd_budget_race"]["live_state"]["amount_spent_cents"] == 20000


# ── Presupuesto mensual ─────────────────────────────────────────────────────

def test_monthly_budget_is_applied_and_resets_with_the_calendar_month(client, clock):
    mandate_id = sealed("mnd_budget", monthly_budget=200)
    first = verify_attempt(attempt(mandate_id, 12000))
    assert first["verdict"] == "APPROVE"
    second = verify_attempt(attempt(mandate_id, 12000))  # 120 + 120 > 200
    assert second["verdict"] == "ESCALATE"
    assert next(c for c in second["checks"] if c["rule"] == "monthly_budget")["pass"] is False
    assert MANDATES[mandate_id]["live_state"]["uses_count"] == 1

    clock.now = datetime(2026, 12, 1, 0, 0, 1, tzinfo=timezone.utc)  # cambia el mes (UTC)
    assert verify_attempt(attempt(mandate_id, 12000))["verdict"] == "APPROVE"
    assert period_usage(mandate_id) == {"month": "2026-12", "uses": 1, "spent_cents": 12000}
    # El total de por vida no se reinicia: max_uses es de por vida.
    assert MANDATES[mandate_id]["live_state"]["uses_count"] == 2
    assert MANDATES[mandate_id]["live_state"]["amount_spent_cents"] == 24000


def test_month_boundary_is_utc(client, clock):
    mandate_id = sealed("mnd_utc", monthly_budget=100)
    clock.now = datetime(2026, 11, 30, 23, 59, 59, tzinfo=timezone.utc)
    assert verify_attempt(attempt(mandate_id, 10000))["verdict"] == "APPROVE"
    assert verify_attempt(attempt(mandate_id, 10000))["verdict"] == "ESCALATE"
    clock.now = datetime(2026, 12, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert verify_attempt(attempt(mandate_id, 10000))["verdict"] == "APPROVE"


def test_human_override_can_exceed_the_monthly_budget_on_purpose(client, clock):
    """Una escalación aprobada por la persona autoriza lo que el mandato no cubría."""
    mandate_id = sealed("mnd_override", monthly_budget=100)
    assert verify_attempt(attempt(mandate_id, 10000))["verdict"] == "APPROVE"
    escalated = verify_attempt(attempt(mandate_id, 5000))
    assert escalated["verdict"] == "ESCALATE"
    response = client.post(f"/mandates/{mandate_id}/approve_escalation",
                           json={"purchase_attempt_id": escalated["attempt_id"], "decision": "approve"},
                           headers={"Authorization": f"Bearer {create_access_token(TEST_USER_EMAIL)}"})
    assert response.status_code == 200 and response.json()["verdict"] == "APPROVE"
    assert period_usage(mandate_id)["spent_cents"] == 15000


# ── Usos de por vida vs. del mes (engine) ───────────────────────────────────

def engine_mandate(**extra) -> dict:
    return {"constraints": {"currency": "USD", "max_amount_per_purchase_cents": 15000,
                            "allowed_categories": ["travel.flights"], "allowed_merchants": ["mch_vuelaya"], **extra}}


def engine_attempt() -> dict:
    return {"category": "travel.flights", "merchant_id": "mch_vuelaya", "amount_cents": 10000, "currency": "USD"}


def test_max_uses_counts_lifetime_and_max_executions_per_month_counts_the_month():
    lifetime = evaluate(engine_mandate(max_uses=3), {"uses_count": 3, "month_uses": 0}, engine_attempt())
    assert lifetime["verdict"] == "ESCALATE"
    monthly = evaluate(engine_mandate(max_executions_per_month=3), {"uses_count": 30, "month_uses": 2}, engine_attempt())
    assert monthly["verdict"] == "APPROVE"
    exhausted = evaluate(engine_mandate(max_executions_per_month=3), {"uses_count": 30, "month_uses": 3}, engine_attempt())
    assert exhausted["verdict"] == "ESCALATE"


def test_without_month_data_the_engine_uses_the_lifetime_totals():
    """Fail-closed: sin el dato del mes se compara con el total, que nunca es menor."""
    result = evaluate(engine_mandate(monthly_budget_cents=20000), {"uses_count": 1, "amount_spent_cents": 15000}, engine_attempt())
    assert result["verdict"] == "ESCALATE"
    assert next(c for c in result["checks"] if c["rule"] == "monthly_budget")["pass"] is False
