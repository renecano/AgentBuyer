"""Fixtures compartidos de la suite."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import api.main as api_main

# Holgura de la expiración relativa del seed. Solo tiene que cubrir la duración de
# un test; un año evita cualquier borde de reloj.
SEED_VALIDITY = timedelta(days=365)


@pytest.fixture()
def active_seed(monkeypatch, tmp_path) -> dict:
    """Carga el mandato semilla con una expiración RELATIVA al momento del test.

    shared/seed_mandates.json trae un expires_at absoluto que en algún momento
    queda en el pasado. Los tests que necesitan el seed ACTIVO no deben depender
    de la fecha del sistema, así que se usa una copia idéntica del seed real con
    expires_at = ahora + 1 año, y el lifespan de la app la carga por el camino
    normal (load_seed_mandates leyendo SEED_PATH).

    No toca la regla de expiración: un mandato realmente vencido se sigue
    rechazando (ver test_expired_seed_is_still_rejected). Si SEED_PATH deja de
    existir, monkeypatch falla con AttributeError en vez de ignorarse en silencio.
    Devuelve el seed tal como se cargó.
    """
    seeds = json.loads(Path(api_main.SEED_PATH).read_text(encoding="utf-8"))
    expires_at = (datetime.now(timezone.utc) + SEED_VALIDITY).strftime("%Y-%m-%dT%H:%M:%SZ")
    for seed in seeds:
        seed["expires_at"] = expires_at

    relative_seed = tmp_path / "seed_mandates.json"
    relative_seed.write_text(json.dumps(seeds, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(api_main, "SEED_PATH", str(relative_seed))
    return seeds[0]
