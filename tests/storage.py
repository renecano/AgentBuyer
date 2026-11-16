"""Acceso directo a la base para tests (6.2).

Antes los tests leían y escribían los diccionarios en memoria (MANDATES, OWNER_KEYS).
Ahora el estado vive en SQLite. Estos helpers hacen lo mismo de forma explícita:
- leer el estado vivo por la API pública (get_mandate);
- simular MANIPULACIÓN DEL ALMACENAMIENTO (alguien edita la base por fuera de la app)
  con UPDATE/INSERT reales. Es la versión realista de lo que antes era mutar un dict.
"""
import json
from typing import Callable, Optional

from sqlalchemy import insert, select, update

from core.db import write_tx
from core.db_schema import mandates, owner_keys
from core.mandate_store import get_mandate, mandate_exists


def live_state(mandate_id: str) -> dict:
    record = get_mandate(mandate_id)
    assert record is not None, f"el mandato {mandate_id} no existe"
    return record["live_state"]


def stored_document(mandate_id: str) -> dict:
    record = get_mandate(mandate_id)
    assert record is not None, f"el mandato {mandate_id} no existe"
    return record["mandate"]


def tamper_document(mandate_id: str, change: Callable[[dict], None]) -> None:
    """Edita el documento guardado del mandato por fuera de la app."""
    with write_tx() as connection:
        raw = connection.execute(select(mandates.c.document).where(mandates.c.mandate_id == mandate_id)).scalar_one()
        document = json.loads(raw)
        change(document)
        connection.execute(update(mandates).where(mandates.c.mandate_id == mandate_id)
                           .values(document=json.dumps(document, ensure_ascii=False)))


def insert_mandate_without_signer(mandate_id: str, document: dict, owner_email: Optional[str], *,
                                  status: str = "active", uses_count: int = 0, amount_spent_cents: int = 0) -> None:
    """Un mandato que existe sin registro de firmante (estado que ningún flujo de la
    app produce): para probar que la verificación falla cerrada."""
    with write_tx() as connection:
        connection.execute(insert(mandates).values(
            mandate_id=mandate_id, owner_email=owner_email, document=json.dumps(document, ensure_ascii=False),
            status=status, uses_count=uses_count, amount_spent_cents=amount_spent_cents, revoked_at=None,
            created_at="2026-01-01T00:00:00.000000+00:00",
        ))


def move_key_to_owner(key_id: str, new_owner_email: str) -> None:
    """Reasigna una llave a otro dueño por fuera de la app."""
    with write_tx() as connection:
        connection.execute(update(owner_keys).where(owner_keys.c.key_id == key_id).values(owner_email=new_owner_email))


def set_owner(mandate_id: str, owner_email: Optional[str]) -> None:
    """Cambia el dueño registrado del mandato por fuera de la app."""
    with write_tx() as connection:
        connection.execute(update(mandates).where(mandates.c.mandate_id == mandate_id).values(owner_email=owner_email))


def all_mandate_ids() -> set:
    with write_tx() as connection:
        return set(connection.execute(select(mandates.c.mandate_id)).scalars())


def key_records(owner_email: Optional[str] = None) -> list:
    """Todas las llaves (activas y revocadas), en orden de alta, con su dueño."""
    query = select(owner_keys).order_by(owner_keys.c.id)
    if owner_email is not None:
        query = query.where(owner_keys.c.owner_email == owner_email)
    with write_tx() as connection:
        return [dict(row._mapping) for row in connection.execute(query)]


def move_keys_of_owner(owner_email: str, new_owner_email: str) -> None:
    """Reasigna TODAS las llaves de un dueño a otro por fuera de la app."""
    with write_tx() as connection:
        connection.execute(update(owner_keys).where(owner_keys.c.owner_email == owner_email)
                           .values(owner_email=new_owner_email))


def tamper_ledger_row(idx: int, change: Callable[[dict], None]) -> None:
    """Edita los `details` de una fila del ledger como lo haría alguien con acceso de
    escritura al ARCHIVO: quita el trigger append-only, escribe y lo vuelve a poner.
    (La app no puede hacerlo: tests/test_ledger_persistence.py.)"""
    from core.db_schema import audit_ledger
    with write_tx() as connection:
        connection.exec_driver_sql("DROP TRIGGER audit_ledger_no_update")
        raw = connection.execute(select(audit_ledger.c.details).where(audit_ledger.c.idx == idx)).scalar_one()
        details = json.loads(raw)
        change(details)
        connection.execute(update(audit_ledger).where(audit_ledger.c.idx == idx)
                           .values(details=json.dumps(details, ensure_ascii=False)))
        connection.exec_driver_sql(
            "CREATE TRIGGER audit_ledger_no_update BEFORE UPDATE ON audit_ledger "
            "BEGIN SELECT RAISE(ABORT, 'audit_ledger is append-only'); END")


__all__ = [
    "live_state", "stored_document", "tamper_document", "insert_mandate_without_signer", "move_key_to_owner",
    "set_owner", "all_mandate_ids", "key_records", "move_keys_of_owner", "tamper_ledger_row", "mandate_exists",
]
