"""Entorno de Alembic. Dos usos:
- Programático (core/db.migrate_to_head): recibe la conexión en config.attributes.
- CLI (`alembic upgrade head`, con alembic.ini en la raíz): usa DATABASE_URL, con
  las mismas reglas que la app (core/db.database_url)."""
from alembic import context

from core.db_schema import metadata

config = context.config


def _run(connection) -> None:
    # render_as_batch: SQLite no soporta ALTER de restricciones; Alembic recrea la tabla.
    context.configure(connection=connection, target_metadata=metadata, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


connection = config.attributes.get("connection")
if connection is not None:
    _run(connection)
else:
    from core.db import build_engine, database_url

    engine = build_engine(database_url())
    with engine.connect() as cli_connection:
        _run(cli_connection)
    engine.dispose()
