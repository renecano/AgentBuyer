"""Verifica el ledger de auditoría SIN levantar la API (paso 6.3).

Uso (desde la raíz del repo):
    python -m scripts.verify_ledger
Lee DATABASE_URL (mismas reglas que la app: core/db.database_url). No escribe nada
ni migra: si la base no está en la última versión, lo dice y termina con error.

Para qué: si la API se negó a arrancar porque la cadena no verifica, esto dice
dónde está el primer eslabón roto, para investigar sin exponer la API.
Salida: 0 = la cadena verifica; 1 = no verifica o no se puede leer.
"""
from __future__ import annotations

import sys

from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory


def main() -> int:
    from audit.log import audit_ledger
    from core import db

    try:
        url = db.database_url()
    except db.DatabaseConfigError as error:
        print(f"ERROR: {error}")
        return 1
    engine = db.build_engine(url)
    with engine.connect() as connection:
        current = MigrationContext.configure(connection).get_current_revision()
    head = ScriptDirectory.from_config(db.alembic_config()).get_current_head()
    if current != head:
        print(f"ERROR: the database is at revision {current!r}, the code expects {head!r}. Nothing was verified.")
        engine.dispose()
        return 1
    engine.dispose()

    db.configure(url, migrate=False)
    try:
        valid, detail = audit_ledger.verify_chain_integrity()
        total = audit_ledger.count()
    finally:
        db.dispose()
    print(f"{'OK' if valid else 'BROKEN'}: {detail} ({total} entries)")
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
