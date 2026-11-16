"""Paso 6.2: persistencia de mandatos, dueños, firmantes y llaves (SQLite + Alembic).

Qué se prueba:
- Las migraciones construyen exactamente el esquema que espera el código, y bajan y
  suben limpias.
- El estado SOBREVIVE A UN REINICIO: se crea todo por la API, se "reinicia" la app
  (se cierran las conexiones y se levanta otra app sobre el mismo archivo) y se lee.
- Las invariantes viven EN LA BASE: aunque alguien se salte el código, la base
  rechaza una pubkey repetida, un firmante humano sin llave, un estado inválido...
- Las transacciones reemplazan a los locks: registrar llaves en paralelo respeta el tope.
- Fuera de desarrollo, sin DATABASE_URL la API no arranca.
"""
import secrets
import threading

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import insert, inspect
from sqlalchemy.exc import IntegrityError

from api.main import app
from core import db
from core.db_schema import mandate_signers, mandates, metadata, owner_keys
from core.mandate_store import get_mandate, get_mandate_owner, get_mandate_signer, period_usage
from core.owner_keys import MAX_ACTIVE_KEYS_PER_OWNER, KeyConflict, get_active_keys, register_key
from tests.conftest import TEST_USER_EMAIL, KeyRegistrar, SignedMandatePoster, verify_as_service
from tests.storage import key_records

pytestmark = pytest.mark.usefixtures("service_key")

MANDATE = {
    "mandate_id": "mnd_persist", "human": {"id": "hum_x", "display_name": "X"}, "agent": {"id": "agt_saturday"},
    "search_fields": {"origin": "BUE", "destination": "COR", "departure_date": "2026-12-05"},
    "constraints": {"max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
                    "allowed_merchants": ["mch_vuelaya"], "max_uses": 3},
}


def attempt(mandate_id: str, cents: int = 12000) -> dict:
    return {"attempt_id": f"att_{secrets.token_hex(4)}", "mandate_id": mandate_id, "presented_by_agent": "agt_saturday",
            "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount_cents": cents,
                         "currency": "USD", "description": "Flight BUE-COR", "metadata": {"price_cents": cents}}}


def restart() -> None:
    """Simula un reinicio del proceso: se cierran todas las conexiones y el siguiente
    uso vuelve a abrir el MISMO archivo (DATABASE_URL) desde cero."""
    db.dispose()


# ── Migraciones ─────────────────────────────────────────────────────────────

def test_migrations_build_the_schema_the_code_expects(tmp_path):
    engine = db.build_engine(f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}")
    db.migrate_to_head(engine)
    with engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), metadata) == []
    engine.dispose()


def test_migrations_downgrade_and_upgrade_cleanly(tmp_path):
    engine = db.build_engine(f"sqlite:///{(tmp_path / 'cycle.db').as_posix()}")
    db.migrate_to_head(engine)
    with engine.connect() as connection, connection.begin():
        command.downgrade(db.alembic_config(connection), "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    db.migrate_to_head(engine)
    assert {"owner_keys", "mandates", "mandate_signers", "mandate_periods", "mandate_creation_nonces"} <= set(
        inspect(engine).get_table_names())
    engine.dispose()


def test_migrating_twice_is_a_no_op(tmp_path):
    engine = db.build_engine(f"sqlite:///{(tmp_path / 'twice.db').as_posix()}")
    db.migrate_to_head(engine)
    db.migrate_to_head(engine)
    with engine.connect() as connection:
        head = ScriptDirectory.from_config(db.alembic_config()).get_current_head()
        assert MigrationContext.configure(connection).get_current_revision() == head
    engine.dispose()


# ── Sobrevivir a un reinicio ────────────────────────────────────────────────

def test_mandates_keys_and_usage_survive_a_restart(monkeypatch):
    with TestClient(app) as client:
        poster = SignedMandatePoster(client, KeyRegistrar(client, monkeypatch))
        poster.create(MANDATE)
        assert verify_as_service(client, attempt("mnd_persist")).json()["verdict"] == "APPROVE"
        before = get_mandate("mnd_persist")
        signer_before = get_mandate_signer("mnd_persist")
        keys_before = get_active_keys(TEST_USER_EMAIL)

    restart()

    with TestClient(app) as client:
        after = get_mandate("mnd_persist")
        assert after == before
        assert after["live_state"]["uses_count"] == 1 and after["live_state"]["amount_spent_cents"] == 12000
        assert get_mandate_owner("mnd_persist") == TEST_USER_EMAIL
        assert get_mandate_signer("mnd_persist") == signer_before
        assert get_active_keys(TEST_USER_EMAIL) == keys_before
        assert period_usage("mnd_persist")["uses"] == 1
        # Tras el reinicio, el mandato guardado sigue VERIFICANDO (firma, llave, token)
        # y el consumo continúa sobre lo ya gastado.
        result = verify_as_service(client, attempt("mnd_persist")).json()
        assert result["verdict"] == "APPROVE", result
        assert get_mandate("mnd_persist")["live_state"]["uses_count"] == 2


def test_creation_nonce_still_blocks_a_replay_after_restart(monkeypatch):
    with TestClient(app) as client:
        signer = SignedMandatePoster(client, KeyRegistrar(client, monkeypatch)).signer_for(TEST_USER_EMAIL)
        first = signer.create(mandate_id="mnd_persist")

    restart()

    with TestClient(app) as client:
        # Mismo nonce, otro mandato, firma válida: antes del 6.2 el reinicio olvidaba el nonce.
        replay = signer.body(mandate_id="mnd_persist_replay", nonce=first["nonce"])
        response = client.post("/mandates", json=replay, headers=signer.headers)
        assert response.status_code == 409, response.text
        assert get_mandate("mnd_persist_replay") is None


def test_revoked_key_stays_revoked_after_restart(monkeypatch):
    with TestClient(app) as client:
        poster = SignedMandatePoster(client, KeyRegistrar(client, monkeypatch))
        poster.create(MANDATE)
        key_id = key_records(TEST_USER_EMAIL)[0]["key_id"]
        assert client.delete(f"/keys/{key_id}", headers=KeyRegistrar.bearer(TEST_USER_EMAIL)).status_code == 200

    restart()

    with TestClient(app) as client:
        assert key_records(TEST_USER_EMAIL)[0]["revoked_at"] is not None
        result = verify_as_service(client, attempt("mnd_persist")).json()
        assert result["verdict"] == "REJECT"
        assert next(c for c in result["checks"] if c["rule"] == "signing_key_active")["pass"] is False


def test_the_seed_is_not_reset_or_duplicated_by_a_restart(active_seed):
    with TestClient(app) as client:
        seed_id = active_seed["mandate_id"]
        assert client.post(f"/mandates/{seed_id}/revoke", headers=KeyRegistrar.bearer(active_seed["human"]["email"])).status_code == 200
    restart()
    with TestClient(app):
        # Antes del 6.2 el seed se re-creaba ACTIVO en cada arranque.
        assert get_mandate(seed_id)["live_state"]["status"] == "revoked"


# ── Las invariantes viven en la base ────────────────────────────────────────

PUB = "ab" * 32


def raw_insert(table, **values):
    with db.write_tx() as connection:
        connection.execute(insert(table).values(**values))


def a_key(**changes) -> dict:
    return {"key_id": f"key_{secrets.token_hex(16)}", "owner_email": "a@example.com", "public_key": PUB, "alg": "ed25519",
            "created_at": "2026-11-16T00:00:00+00:00", "revoked_at": None, **changes}


def a_mandate(**changes) -> dict:
    return {"mandate_id": f"mnd_{secrets.token_hex(4)}", "owner_email": "a@example.com", "document": "{}", "status": "active",
            "uses_count": 0, "amount_spent_cents": 0, "revoked_at": None, "created_at": "2026-11-16T00:00:00+00:00", **changes}


def test_database_rejects_the_same_public_key_for_two_owners_even_bypassing_the_code():
    raw_insert(owner_keys, **a_key())
    with pytest.raises(IntegrityError):
        raw_insert(owner_keys, **a_key(owner_email="b@example.com"))


@pytest.mark.parametrize("changes", [
    {"alg": "rsa"}, {"owner_email": "Mixed@Example.com"}, {"owner_email": " a@example.com"}, {"owner_email": ""},
    {"public_key": "ab" * 31},
], ids=["alg", "owner-case", "owner-space", "owner-empty", "short-key"])
def test_database_rejects_malformed_keys(changes):
    with pytest.raises(IntegrityError):
        raw_insert(owner_keys, **a_key(**changes))


@pytest.mark.parametrize("changes", [
    {"status": "approved"}, {"uses_count": -1}, {"amount_spent_cents": -5}, {"owner_email": "Mixed@Example.com"},
], ids=["status", "uses", "spent", "owner-case"])
def test_database_rejects_invalid_mandate_rows(changes):
    with pytest.raises(IntegrityError):
        raw_insert(mandates, **a_mandate(**changes))


def test_database_rejects_a_human_signer_without_key_and_a_key_that_does_not_exist():
    row = a_mandate()
    raw_insert(mandates, **row)
    with pytest.raises(IntegrityError):
        raw_insert(mandate_signers, mandate_id=row["mandate_id"], kind="human", key_id=None, signed_at="2026-11-16T00:00:00+00:00")
    with pytest.raises(IntegrityError):
        raw_insert(mandate_signers, mandate_id=row["mandate_id"], kind="human", key_id="key_missing", signed_at="2026-11-16T00:00:00+00:00")
    with pytest.raises(IntegrityError):
        raw_insert(mandate_signers, mandate_id=row["mandate_id"], kind="stranger", signed_at="2026-11-16T00:00:00+00:00")


# ── Transacciones donde había locks ─────────────────────────────────────────

def test_concurrent_key_registration_respects_the_active_key_cap():
    """Contar las llaves activas e insertar la nueva es UNA transacción BEGIN
    IMMEDIATE: 25 registros simultáneos del mismo dueño dejan exactamente el tope."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    keys = [ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex() for _ in range(25)]
    outcomes: list = []
    barrier = threading.Barrier(len(keys))

    def worker(public_key: str) -> None:
        barrier.wait()
        try:
            outcomes.append(register_key("racer@example.com", public_key))
        except KeyConflict:
            outcomes.append(None)

    threads = [threading.Thread(target=worker, args=(key,)) for key in keys]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(outcomes) == len(keys), "algún registro simultáneo terminó en un error de la base"
    assert sum(outcome is not None for outcome in outcomes) == MAX_ACTIVE_KEYS_PER_OWNER
    assert len(get_active_keys("racer@example.com")) == MAX_ACTIVE_KEYS_PER_OWNER


# ── Configuración ───────────────────────────────────────────────────────────

def test_without_database_url_the_api_refuses_to_start_outside_dev_mode(monkeypatch):
    restart()
    monkeypatch.delenv("DATABASE_URL")
    with pytest.raises(db.DatabaseConfigError):
        with TestClient(app):
            pass


def test_dev_mode_uses_a_local_file_outside_version_control(monkeypatch, tmp_path):
    restart()
    monkeypatch.delenv("DATABASE_URL")
    monkeypatch.setenv("AUTH_DEV_MODE", "true")
    monkeypatch.setattr(db, "DEV_DATABASE_PATH", tmp_path / "var" / "agentbuyer.db")
    assert db.database_url() == f"sqlite:///{(tmp_path / 'var' / 'agentbuyer.db').as_posix()}"
    db.get_engine()  # crea y migra
    assert (tmp_path / "var" / "agentbuyer.db").exists()


def test_var_directory_is_ignored_by_git():
    from pathlib import Path

    ignored = (Path(db.ROOT) / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "var/" in [line.strip() for line in ignored]


def test_the_api_migrates_an_empty_database_on_startup(monkeypatch, tmp_path):
    restart()
    fresh = tmp_path / "fresh-start.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{fresh.as_posix()}")
    with TestClient(app) as client:
        poster = SignedMandatePoster(client, KeyRegistrar(client, monkeypatch))
        poster.create(MANDATE)
        assert get_mandate("mnd_persist") is not None
    assert "mandates" in inspect(db.get_engine()).get_table_names()
