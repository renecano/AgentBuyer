"""Paso 6.3: ledger persistente con verificación al arrancar y anti-replay durable.

- El ledger es append-only EN LA BASE: la app no puede editar ni borrar, ni agregar
  una entrada que no extienda la cabeza.
- Alterar una fila (como quien edita el archivo) o borrar las últimas (H4): la API no
  arranca y dice por qué.
- Replay de un intento tras un reinicio: REJECT (H1). Un intento viejo o del futuro,
  también, y sin gastar su nonce.
- Dos aprobaciones humanas simultáneas del mismo intento: una sola compra (H2).
- Disputas y cuota sobreviven al reinicio.
"""
import json
import os
import secrets
import subprocess
import sys
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError

import api.agent as agent_api
import api.verify as verify_api
from api.main import app
from audit.log import LedgerIntegrityError, append_entry, audit_ledger, get_trail_events
from core import db, merchant_search
from core.agent_keys import AGENT_SIGNATURE_FIELD, get_or_create_agent_keys, sign_attempt
from core.db_schema import audit_ledger as LEDGER
from core.db_schema import ledger_head as HEAD
from core.mandate_store import get_mandate
from core.quotas import PerSubjectQuota
from tests.conftest import TEST_SERVICE_KEY, TEST_USER_EMAIL, KeyRegistrar, SignedMandatePoster, verify_as_service
from tests.storage import tamper_ledger_row

pytestmark = pytest.mark.usefixtures("service_key")

MANDATE = {
    "mandate_id": "mnd_ledger", "human": {"id": "hum_x", "display_name": "X"}, "agent": {"id": "agt_saturday"},
    "search_fields": {"origin": "BUE", "destination": "COR", "departure_date": "2026-12-05"},
    "constraints": {"max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
                    "allowed_merchants": ["mch_vuelaya"], "max_uses": 3},
}


def owner() -> dict:
    return KeyRegistrar.bearer(TEST_USER_EMAIL)


def restart() -> None:
    db.dispose()


def attempt(mandate_id: str = "mnd_ledger", cents: int = 12000, **extra) -> dict:
    return {"attempt_id": f"att_{secrets.token_hex(4)}", "mandate_id": mandate_id, "presented_by_agent": "agt_saturday",
            "created_at": verify_api.attempt_timestamp(verify_api._utcnow()),
            "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount_cents": cents,
                         "currency": "USD", "description": "Flight BUE-COR", "metadata": {"price_cents": cents}},
            **extra}


def check(result: dict, rule: str) -> dict:
    return next(item for item in result["checks"] if item["rule"] == rule)


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: "[]")
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def mine(client, monkeypatch) -> str:
    SignedMandatePoster(client, KeyRegistrar(client, monkeypatch)).create(MANDATE)
    return "mnd_ledger"


# ── Append-only en la base ──────────────────────────────────────────────────

def two_entries() -> None:
    append_entry({"type": "verification", "mandate_id": "mnd_x", "summary": "one"})
    append_entry({"type": "verification", "mandate_id": "mnd_x", "summary": "two"})


def test_the_app_cannot_update_or_delete_ledger_rows():
    two_entries()
    with pytest.raises(IntegrityError, match="append-only"):
        with db.write_tx() as connection:
            connection.execute(update(LEDGER).where(LEDGER.c.idx == 0).values(details="{}"))
    with pytest.raises(IntegrityError, match="append-only"):
        with db.write_tx() as connection:
            connection.execute(delete(LEDGER).where(LEDGER.c.idx == 1))
    assert audit_ledger.verify_chain_integrity()[0] is True


def test_an_insert_that_does_not_extend_the_head_is_refused():
    two_entries()
    head_hash = audit_ledger.get_all_entries()[-1].hash
    row = {"entry_id": "evt_forged", "hash": "f" * 64, "timestamp": "2026-11-16T00:00:00+00:00", "event_type": "verification",
           "actor_type": "GATEWAY", "actor_id": "x", "details": "{}"}
    for idx, prev_hash in ((5, head_hash), (2, "0" * 64), (1, head_hash)):
        with pytest.raises(IntegrityError, match="extend the head"):
            with db.write_tx() as connection:
                connection.execute(insert(LEDGER).values(idx=idx, prev_hash=prev_hash, **row))


def test_the_head_only_moves_forward_and_cannot_be_deleted():
    two_entries()
    with pytest.raises(IntegrityError, match="only advances"):
        with db.write_tx() as connection:
            connection.execute(update(HEAD).values(last_idx=0))
    with pytest.raises(IntegrityError, match="cannot be deleted"):
        with db.write_tx() as connection:
            connection.execute(delete(HEAD))


def test_the_head_follows_every_append():
    two_entries()
    with db.read_tx() as connection:
        head = connection.execute(select(HEAD.c.last_idx, HEAD.c.last_hash)).one()
    assert (head.last_idx, head.last_hash) == (1, audit_ledger.get_all_entries()[-1].hash)


# ── Verificación al arrancar ────────────────────────────────────────────────

def test_the_ledger_survives_a_restart_and_still_verifies(client, mine):
    assert verify_as_service(client, attempt()).json()["verdict"] == "APPROVE"
    append_entry({"type": "verification", "mandate_id": "mnd_x", "summary": "ünïcödé € 0.1 + 0.2", "ratio": 0.30000000000000004})
    before = [entry.model_dump() for entry in audit_ledger.get_all_entries()]
    restart()
    with TestClient(app) as again:
        assert [entry.model_dump() for entry in audit_ledger.get_all_entries()] == before
        body = again.get("/audit/verify").json()
        assert body["valid"] is True and body["total_blocks"] == len(before)


def test_a_tampered_row_stops_the_api_from_starting(caplog):
    two_entries()
    tamper_ledger_row(0, lambda details: details.__setitem__("summary", "rewritten"))
    restart()
    with pytest.raises(LedgerIntegrityError, match="Tampered entry at index 0"):
        with TestClient(app):
            pass
    assert "no puede arrancar" in caplog.text


def test_removing_the_last_entries_stops_the_api_from_starting():
    """H4: sin la cabeza, borrar el final dejaba una cadena "válida"."""
    two_entries()
    append_entry({"type": "verification", "mandate_id": "mnd_x", "summary": "three"})
    with db.write_tx() as connection:  # quien tiene acceso al archivo puede quitar el trigger
        connection.exec_driver_sql("DROP TRIGGER audit_ledger_no_delete")
        connection.execute(delete(LEDGER).where(LEDGER.c.idx == 2))
    restart()
    with pytest.raises(LedgerIntegrityError, match="does not end at its recorded head"):
        with TestClient(app):
            pass


def test_the_cli_verifies_without_starting_the_api(monkeypatch, database):
    two_entries()
    restart()
    env = {**os.environ, "DATABASE_URL": database}
    ok = subprocess.run([sys.executable, "-m", "scripts.verify_ledger"], cwd=str(db.ROOT), env=env,
                        capture_output=True, text=True)
    assert ok.returncode == 0 and ok.stdout.startswith("OK:"), ok.stdout + ok.stderr

    db.configure(database, migrate=False)
    tamper_ledger_row(1, lambda details: details.__setitem__("summary", "rewritten"))
    restart()
    broken = subprocess.run([sys.executable, "-m", "scripts.verify_ledger"], cwd=str(db.ROOT), env=env,
                            capture_output=True, text=True)
    assert broken.returncode == 1 and "Tampered entry at index 1" in broken.stdout


# ── Anti-replay durable (H1) ────────────────────────────────────────────────

def test_a_replay_after_a_restart_is_rejected(client, mine, monkeypatch):
    captured = attempt(nonce=secrets.token_hex(16))
    assert verify_as_service(client, captured).json()["verdict"] == "APPROVE"
    restart()
    with TestClient(app) as again:
        replay = verify_as_service(again, {**captured, "attempt_id": "att_replayed"}).json()
    assert replay["verdict"] == "REJECT"
    assert check(replay, "nonce_fresh")["pass"] is False
    assert get_mandate("mnd_ledger")["live_state"]["uses_count"] == 1


NOW_VARIANTS = {
    "missing": lambda now: None, "empty": lambda now: "", "words": lambda now: "yesterday", "epoch": lambda now: int(now.timestamp()),
    # La hora ACTUAL en formatos no canónicos: el intento firma un texto exacto (UTC, "Z").
    "offset": lambda now: now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    "fraction": lambda now: now.strftime("%Y-%m-%dT%H:%M:%S.123Z"),
    "naive": lambda now: now.strftime("%Y-%m-%dT%H:%M:%S"),
    "lowercase": lambda now: now.strftime("%Y-%m-%dt%H:%M:%Sz"),
}


@pytest.mark.parametrize("variant", sorted(NOW_VARIANTS))
def test_an_attempt_without_a_valid_created_at_is_rejected(client, mine, variant):
    body = attempt()
    body["created_at"] = NOW_VARIANTS[variant](verify_api._utcnow())
    result = client.post("/verify", json={**body, "nonce": secrets.token_hex(16)},
                         headers={"X-Service-Key": TEST_SERVICE_KEY}).json()
    assert result["verdict"] == "REJECT"
    assert check(result, "attempt_fresh")["pass"] is False


@pytest.mark.parametrize("offset, fresh", [
    (timedelta(minutes=-10), True), (timedelta(minutes=-10, seconds=-1), False),
    (timedelta(minutes=2), True), (timedelta(minutes=2, seconds=1), False),
])
def test_attempt_age_window(client, mine, monkeypatch, offset, fresh):
    now = verify_api._utcnow().replace(microsecond=0)
    monkeypatch.setattr(verify_api, "_utcnow", lambda: now)
    body = attempt(created_at=verify_api.attempt_timestamp(now + offset))
    result = verify_as_service(client, body).json()
    assert check(result, "attempt_fresh")["pass"] is fresh
    assert (result["verdict"] == "APPROVE") is fresh


def test_an_old_attempt_is_rejected_without_burning_its_nonce(client, mine, monkeypatch):
    now = verify_api._utcnow().replace(microsecond=0)
    monkeypatch.setattr(verify_api, "_utcnow", lambda: now)
    nonce = secrets.token_hex(16)
    old = verify_as_service(client, attempt(created_at=verify_api.attempt_timestamp(now - timedelta(hours=1))), nonce=nonce).json()
    assert old["verdict"] == "REJECT" and "nonce_fresh" not in {item["rule"] for item in old["checks"]}
    assert verify_as_service(client, attempt(), nonce=nonce).json()["verdict"] == "APPROVE"


def test_a_captured_attempt_is_dead_once_its_nonce_could_be_forgotten(client, mine, monkeypatch):
    """El nonce se purga a los 12 min; para entonces el intento ya se rechaza por viejo."""
    start = verify_api._utcnow().replace(microsecond=0)
    clock = {"now": start}
    monkeypatch.setattr(verify_api, "_utcnow", lambda: clock["now"])
    captured = attempt(created_at=verify_api.attempt_timestamp(start), nonce=secrets.token_hex(16))
    assert verify_as_service(client, captured).json()["verdict"] == "APPROVE"

    clock["now"] = start + timedelta(minutes=13)
    verify_as_service(client, attempt(created_at=verify_api.attempt_timestamp(clock["now"])))  # dispara la purga
    replay = verify_as_service(client, {**captured, "attempt_id": "att_late"}).json()
    assert replay["verdict"] == "REJECT"
    assert check(replay, "attempt_fresh")["pass"] is False
    assert get_mandate("mnd_ledger")["live_state"]["uses_count"] == 2


def test_created_at_is_covered_by_the_agent_signature(client, mine):
    get_or_create_agent_keys("agt_saturday")
    body = attempt(nonce=secrets.token_hex(16))
    body[AGENT_SIGNATURE_FIELD] = sign_attempt("agt_saturday", body)
    moved = {**body, "created_at": verify_api.attempt_timestamp(verify_api._utcnow() + timedelta(seconds=30))}
    result = verify_as_service(client, moved).json()
    assert result["verdict"] == "REJECT"
    assert check(result, "agent_signature")["pass"] is False


def test_agent_runs_stamp_and_sign_created_at(client, mine, monkeypatch):
    offers = [{"merchant": "VuelaYa", "price": 120, "currency": "USD", "details": "d", "url": "https://vuelaya.example/1"}]
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: json.dumps(offers))
    seen = {}
    real = verify_api.verify_attempt

    def spy(body, **kwargs):
        seen.update(body)
        return real(body, **kwargs)
    monkeypatch.setattr(verify_api, "verify_attempt", spy)
    run = client.post("/agent/run", json={"mandate_id": "mnd_ledger"}, headers=owner()).json()
    assert run["verification"]["verdict"] == "APPROVE"
    assert verify_api._parse_attempt_time(seen["created_at"]) is not None
    assert AGENT_SIGNATURE_FIELD in seen


# ── Decisión humana atómica (H2) ────────────────────────────────────────────

def escalated_attempt(client) -> str:
    body = attempt(cents=20000)  # sobre el tope de 150: escala
    result = verify_as_service(client, body).json()
    assert result["verdict"] == "ESCALATE", result
    return body["attempt_id"]


def test_two_approvals_that_both_passed_the_precheck_buy_once(client, mine, monkeypatch):
    """H2. La carrera real: dos revisiones llegan a la vez y las DOS pasan el chequeo
    previo ("¿ya hay una decisión en el ledger?") antes de que la otra escriba. Se
    simula esa ventana anulando el chequeo previo; la base (PK por intento, en la
    misma transacción que la compra) debe impedir la segunda compra.
    (Un test con hilos sobre TestClient no sirve: serializa las peticiones y pasaba
    aunque la garantía no existiera; lo detectó la prueba de mutación.)"""
    import api.escalations as escalations_api

    attempt_id = escalated_attempt(client)
    monkeypatch.setattr(escalations_api, "_existing_override", lambda attempt_id: None)
    decide = lambda: client.post("/mandates/mnd_ledger/approve_escalation",
                                 json={"purchase_attempt_id": attempt_id, "decision": "approve"}, headers=owner())
    assert decide().status_code == 200
    second = decide()
    assert second.status_code == 409 and second.json()["detail"] == "Este intento ya fue revisado por una persona."
    assert get_mandate("mnd_ledger")["live_state"]["uses_count"] == 1
    overrides = [e for e in get_trail_events(attempt_id=attempt_id) if e["type"].startswith("human_override")]
    assert len(overrides) == 1  # el evento de la segunda se revirtió con su transacción


def test_a_decision_survives_a_restart(client, mine):
    attempt_id = escalated_attempt(client)
    assert client.post("/mandates/mnd_ledger/approve_escalation",
                       json={"purchase_attempt_id": attempt_id, "decision": "decline"}, headers=owner()).status_code == 200
    restart()
    with TestClient(app) as again:
        response = again.post("/mandates/mnd_ledger/approve_escalation",
                              json={"purchase_attempt_id": attempt_id, "decision": "approve"}, headers=owner())
    assert response.status_code == 409
    assert get_mandate("mnd_ledger")["live_state"]["uses_count"] == 0


# ── Disputas y cuota ────────────────────────────────────────────────────────

def test_disputes_survive_a_restart(client, mine):
    body = attempt()
    assert verify_as_service(client, body).json()["verdict"] == "APPROVE"
    filed = client.post("/disputes/file", json={"attempt_id": body["attempt_id"], "mandate_id": "mnd_ledger"}, headers=owner()).json()
    restart()
    with TestClient(app) as again:
        listed = again.get("/disputes", headers=owner()).json()
    assert listed == [filed]


def test_the_agent_quota_survives_a_restart(client, mine, monkeypatch):
    monkeypatch.setattr(agent_api, "agent_run_quota", PerSubjectQuota(limit=1, window_seconds=3600))
    assert client.post("/agent/run", json={"mandate_id": "mnd_ledger"}, headers=owner()).status_code == 200
    restart()
    with TestClient(app) as again:
        response = again.post("/agent/run", json={"mandate_id": "mnd_ledger"}, headers=owner())
    assert response.status_code == 429
