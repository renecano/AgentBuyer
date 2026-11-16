"""Conexión a la base (paso 6.2, P-10): SQLite con SQLAlchemy 2 Core + Alembic.

- DATABASE_URL por entorno. Sin ella, SOLO en desarrollo (AUTH_DEV_MODE=true) se usa
  un archivo local fuera del control de versiones (var/agentbuyer.db, en .gitignore).
  Fuera de desarrollo, sin DATABASE_URL la API no arranca: un despliegue que escriba
  en un archivo efímero creyendo que persiste es peor que uno que no arranca.
- Pragmas por conexión: claves foráneas activas, WAL (lectores sin bloquear al
  escritor) y busy_timeout (un escritor espera al otro en vez de fallar).
- write_tx(): BEGIN IMMEDIATE. Toma el lock de escritura AL EMPEZAR, así que "leer,
  decidir y escribir" es atómico entre hilos y procesos. Reemplaza a los locks de
  proceso que había alrededor de los diccionarios (5.2: reserve_purchase).
- read_tx(): BEGIN diferido; una foto consistente para lecturas de varias tablas.

Detalle de pysqlite: el driver abre transacciones por su cuenta; se apaga
(isolation_level=None) y el BEGIN lo emite el listener "begin" de abajo. Es la
receta documentada por SQLAlchemy para controlar el modo de BEGIN en SQLite.
"""
from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from sqlalchemy import Connection, Engine, create_engine, event

ROOT = Path(__file__).resolve().parents[1]
DEV_DATABASE_PATH = ROOT / "var" / "agentbuyer.db"
MIGRATIONS_PATH = ROOT / "migrations"
BUSY_TIMEOUT_MS = 5000


class DatabaseConfigError(RuntimeError):
    """Configuración de base inválida: la API no debe arrancar así."""


def _dev_mode() -> bool:
    return os.getenv("AUTH_DEV_MODE", "").strip().lower() == "true"


def database_url() -> str:
    url = (os.getenv("DATABASE_URL") or "").strip()
    if url:
        return url
    if _dev_mode():
        DEV_DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{DEV_DATABASE_PATH.as_posix()}"
    raise DatabaseConfigError(
        "DATABASE_URL is not set. Outside AUTH_DEV_MODE the API requires an explicit database "
        "(for example sqlite:////data/agentbuyer.db on a persistent disk)."
    )


def validate_database_config() -> None:
    """Fail-fast al arrancar (api/main lifespan), igual que validate_token_config."""
    database_url()


def _install_sqlite_listeners(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection, _record):  # pragma: no cover - lo ejercita cada test
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _on_begin(connection: Connection):
        mode = "BEGIN IMMEDIATE" if connection.get_execution_options().get("immediate") else "BEGIN"
        connection.exec_driver_sql(mode)


def build_engine(url: str) -> Engine:
    engine = create_engine(url, future=True)
    if engine.dialect.name == "sqlite":
        _install_sqlite_listeners(engine)
    return engine


_engine: Optional[Engine] = None
_engine_lock = threading.Lock()


def configure(url: str, *, migrate: bool = True) -> Engine:
    """Apunta el proceso a `url` (y opcionalmente lo migra a la última versión).
    Los tests lo usan con una copia ya migrada de la plantilla (migrate=False)."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.dispose()
        _engine = build_engine(url)
        engine = _engine
    if migrate:
        migrate_to_head(engine)
    return engine


def get_engine() -> Engine:
    """Engine del proceso. La primera vez lo crea desde DATABASE_URL y migra."""
    engine = _engine
    if engine is None:
        engine = configure(database_url())
    return engine


def dispose() -> None:
    """Cierra las conexiones (fin de un test o del proceso); el próximo uso reconfigura."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None


def alembic_config(connection: Optional[Connection] = None):
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", MIGRATIONS_PATH.as_posix())
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def migrate_to_head(engine: Engine) -> None:
    from alembic import command

    with engine.connect() as connection, connection.begin():
        command.upgrade(alembic_config(connection), "head")


@contextmanager
def write_tx() -> Iterator[Connection]:
    """Transacción de escritura: BEGIN IMMEDIATE (lock de escritura desde el inicio)."""
    with get_engine().connect() as connection:
        connection.execution_options(immediate=True)
        with connection.begin():
            yield connection


@contextmanager
def read_tx() -> Iterator[Connection]:
    with get_engine().connect() as connection, connection.begin():
        yield connection


@contextmanager
def write_tx_or(connection: Optional[Connection] = None) -> Iterator[Connection]:
    """Usa la transacción del llamador si la hay; si no, abre una de escritura.
    Permite que varias escrituras (decisión + compra + evento del ledger) sean UNA."""
    if connection is not None:
        yield connection
    else:
        with write_tx() as own:
            yield own
