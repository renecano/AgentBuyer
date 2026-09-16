"""Regresión: GET /mandates se colgaba por deadlock en MandateStore.

list_mandates() toma el lock y luego llama a get_mandate(), que vuelve a
tomar el mismo lock. Con threading.Lock (no reentrante) el primer request
quedaba bloqueado para siempre y envenenaba el lock para todo el proceso.
Se corre en un hilo con timeout para que el test falle en vez de colgarse.
"""

import threading

from fastapi.testclient import TestClient

from api.main import app
from core.mandate_store import mandate_store, MANDATES


def test_list_mandates_no_deadlock():
    # El context manager dispara el evento de startup que carga el seed
    with TestClient(app) as client:
        assert MANDATES, "el seed debería cargar al menos un mandato"

        result: dict = {}

        def worker():
            result["mandates"] = mandate_store.list_mandates()
            result["response"] = client.get("/mandates")

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=10)

        assert not t.is_alive(), "list_mandates() / GET /mandates sigue en deadlock"
        assert result["response"].status_code == 200
        assert len(result["response"].json()) >= 1
