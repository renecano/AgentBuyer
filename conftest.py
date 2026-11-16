"""Base de datos por test (6.2): cada test corre sobre su PROPIA base SQLite, copia
de una plantilla migrada una sola vez por sesión (Alembic no corre 900 veces). Así
ningún test ve datos de otro y no hay que "limpiar" almacenes globales."""
import shutil

import pytest

from core import db


@pytest.fixture(scope="session")
def database_template(tmp_path_factory):
    path = tmp_path_factory.mktemp("db-template") / "template.db"
    engine = db.build_engine(f"sqlite:///{path.as_posix()}")
    db.migrate_to_head(engine)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    engine.dispose()
    return path


@pytest.fixture(autouse=True)
def database(database_template, tmp_path, monkeypatch):
    path = tmp_path / "agentbuyer.db"
    shutil.copyfile(database_template, path)
    url = f"sqlite:///{path.as_posix()}"
    monkeypatch.setenv("DATABASE_URL", url)
    db.configure(url, migrate=False)
    yield url
    db.dispose()
