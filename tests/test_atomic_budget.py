"""Paso 5.2: "verificar y consumir" atómico y presupuesto mensual real.

- max_uses y el presupuesto se re-chequean y consumen en UNA operación atómica
  (core/mandate_store.reserve_purchase): 50 compras simultáneas no superan el límite.
- monthly_budget_cents se aplica por mes calendario UTC y se reinicia al cambiar de
  mes (reloj inyectado, sin esperas).

7.2 (P-11): el seed y la línea estricta eran los únicos que DECLARABAN un presupuesto
mensual (la spec firmada v1 no lo incluye, D-17), y se retiraron. El mecanismo sigue
en el almacén (reserve_purchase) y en el engine, y aquí se prueba a ese nivel, sobre
un registro de mandato con monthly_budget_cents. Ningún mandato firmado puede
declararlo hasta una spec v2: límite documentado en docs/PLAN.md.
"""
import secrets
import threading
import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import api.verify as verify_api
import core.mandate_store as store_module
from api.main import app
from api.verify import verify_attempt
from core import mandate_store
from core.mandate_store import apply_approved_purchase, period_usage, reserve_purchase
from engine.evaluator import evaluate
from tests.conftest import TEST_USER_EMAIL
from tests.storage import insert_mandate_without_signer, live_state


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    mandate_store.mandate_store.clear()
    with TestClient(app) as test_client:
        yield test_client
    mandate_store.mandate_store.clear()


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
        "created_at": verify_api.attempt_timestamp(verify_api._utcnow()),
        "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount_cents": cents,
                     "currency": "USD", "metadata": {"price_cents": cents}},
    }


BUDGETED = {"max_amount_per_purchase_cents": 15000, "currency": "USD", "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"], "max_uses": 50}


def budgeted(mandate_id: str, monthly_budget_cents: int) -> dict:
    """Registro de mandato con presupuesto mensual, directo en el almacén (ver docstring)."""
    constraints = {**BUDGETED, "monthly_budget_cents": monthly_budget_cents}
    insert_mandate_without_signer(mandate_id, {"mandate_id": mandate_id, "constraints": constraints}, TEST_USER_EMAIL)
    return constraints


def reserve_race(mandate_id: str, constraints: dict, n: int, monkeypatch, cents: int = 10000) -> list:
    """`n` reservas a la vez sobre el almacén (la misma costura que race())."""
    monkeypatch.setattr(store_module, "_reservation_pause", lambda: time.sleep(0.002))
    barrier = threading.Barrier(n)
    outcomes: list = []
    lock = threading.Lock()

    def reserve():
        barrier.wait()
        outcome = reserve_purchase(mandate_id, cents, constraints)
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=reserve) for _ in range(n)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(outcomes) == n, f"{n - len(outcomes)} reservas simultáneas terminaron en error"
    return outcomes


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
    # 6.2: CADA compra simultánea recibe un veredicto. Un hilo que muere por un error de
    # la base (p. ej. una transacción que no tomó el lock de escritura al empezar y
    # choca al escribir) no deja veredicto y antes pasaba desapercibido.
    assert len(verdicts) == n, f"{n - len(verdicts)} compras simultáneas terminaron en error"
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
    assert live_state("mnd_race")["uses_count"] == 3
    assert live_state("mnd_race")["amount_spent_cents"] == 30000
    assert set(verdicts) <= {"APPROVE", "ESCALATE"}  # las demás quedan para la persona, ninguna compra de más


def test_concurrent_purchases_never_exceed_the_monthly_budget(client, clock, monkeypatch):
    constraints = budgeted("mnd_budget_race", 25000)  # caben exactamente 2 de 100
    outcomes = reserve_race("mnd_budget_race", constraints, 30, monkeypatch)

    assert outcomes.count(None) == 2
    assert set(outcomes) == {None, "monthly_budget"}
    assert period_usage("mnd_budget_race")["spent_cents"] == 20000
    assert live_state("mnd_budget_race")["amount_spent_cents"] == 20000


# ── Presupuesto mensual ─────────────────────────────────────────────────────

def test_monthly_budget_is_applied_and_resets_with_the_calendar_month(client, clock):
    constraints = budgeted("mnd_budget", 20000)
    assert reserve_purchase("mnd_budget", 12000, constraints) is None
    assert reserve_purchase("mnd_budget", 12000, constraints) == "monthly_budget"  # 120 + 120 > 200
    assert live_state("mnd_budget")["uses_count"] == 1

    clock.now = datetime(2026, 12, 1, 0, 0, 1, tzinfo=timezone.utc)  # cambia el mes (UTC)
    assert reserve_purchase("mnd_budget", 12000, constraints) is None
    assert period_usage("mnd_budget") == {"month": "2026-12", "uses": 1, "spent_cents": 12000}
    # El total de por vida no se reinicia: max_uses es de por vida.
    assert live_state("mnd_budget")["uses_count"] == 2
    assert live_state("mnd_budget")["amount_spent_cents"] == 24000


def test_the_engine_escalates_over_the_monthly_budget():
    """El engine (la decisión que ve /verify) marca el check monthly_budget."""
    mandate = {"constraints": {**BUDGETED, "monthly_budget_cents": 20000}}
    attempt_ = {"category": "travel.flights", "merchant_id": "mch_vuelaya", "amount_cents": 12000, "currency": "USD"}
    result = evaluate(mandate, {"uses_count": 1, "amount_spent_cents": 12000, "month_uses": 1, "month_spent_cents": 12000}, attempt_)
    assert result["verdict"] == "ESCALATE"
    assert next(c for c in result["checks"] if c["rule"] == "monthly_budget")["pass"] is False


def test_month_boundary_is_utc(client, clock):
    constraints = budgeted("mnd_utc", 10000)
    clock.now = datetime(2026, 11, 30, 23, 59, 59, tzinfo=timezone.utc)
    assert reserve_purchase("mnd_utc", 10000, constraints) is None
    assert reserve_purchase("mnd_utc", 10000, constraints) == "monthly_budget"
    clock.now = datetime(2026, 12, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert reserve_purchase("mnd_utc", 10000, constraints) is None


def test_human_override_can_exceed_the_monthly_budget_on_purpose(client, clock):
    """Una escalación aprobada por la persona autoriza lo que el mandato no cubría:
    apply_approved_purchase consume sin re-chequear límites."""
    constraints = budgeted("mnd_override", 10000)
    assert reserve_purchase("mnd_override", 10000, constraints) is None
    assert reserve_purchase("mnd_override", 5000, constraints) == "monthly_budget"
    apply_approved_purchase("mnd_override", 5000)
    assert period_usage("mnd_override")["spent_cents"] == 15000


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
