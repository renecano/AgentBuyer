"""GET /mandates bajo escrituras concurrentes (antes: regresión de un deadlock).

Hasta el 7.2 este test cubría un deadlock del lock de MandateStore.list_mandates(),
que ya no existe: el listado es una lectura de la base (core/mandate_store.list_mandates)
y las escrituras son transacciones. Lo que se sigue probando: listar mientras otro
hilo escribe termina (sin colgarse ni fallar) y devuelve los mandatos del usuario.
"""
import threading

from fastapi.testclient import TestClient

from api.main import app
from tests.conftest import KeyRegistrar, SignedMandatePoster, TEST_USER_EMAIL

MANDATE = {
    "mandate_id": "mnd_list", "human": {"id": "hum_x", "display_name": "X"}, "agent": {"id": "agt_saturday"},
    "constraints": {"max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
                    "allowed_merchants": ["mch_vuelaya"], "max_uses": 3},
}


def test_listing_while_another_thread_writes_finishes(monkeypatch):
    with TestClient(app) as client:
        SignedMandatePoster(client, KeyRegistrar(client, monkeypatch)).create(MANDATE)
        headers = KeyRegistrar.bearer(TEST_USER_EMAIL)
        listings: list = []
        errors: list = []

        def writer():
            try:
                for _ in range(20):
                    client.post("/mandates/mnd_list/pause", headers=headers)
                    client.post("/mandates/mnd_list/resume", headers=headers)
            except Exception as error:  # pragma: no cover - solo si algo se rompe
                errors.append(error)

        def reader():
            for _ in range(20):
                listings.append(client.get("/mandates", headers=headers))

        threads = [threading.Thread(target=writer, daemon=True), threading.Thread(target=reader, daemon=True)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        assert not any(thread.is_alive() for thread in threads), "el listado o las escrituras se colgaron"
        assert errors == []
        assert len(listings) == 20 and all(response.status_code == 200 for response in listings)
        assert all([record["mandate"]["mandate_id"] for record in response.json()] == ["mnd_list"] for response in listings)
