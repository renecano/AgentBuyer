import json

from fastapi.testclient import TestClient
from api.main import app
from core import merchant_search, owner_keys
from tests.conftest import KeyRegistrar, SignedMandatePoster

client = TestClient(app)

WEB_OFFERS = [
    {"merchant": "VuelaYa", "price": 130.0, "currency": "USD",
     "details": "BUE-COR directo", "url": "https://vuelaya.example/1"},
]

SEARCH_FIELDS = {"origin": "BUE", "destination": "COR", "departure_date": "2026-09-15"}


def test_full_pipeline_headless(monkeypatch, auth_headers):
    # La búsqueda web SIEMPRE va mockeada en tests (sin red).
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda p: json.dumps(WEB_OFFERS))
    # 1. Health check
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    # 2. Create mandate: desde el 3.5 lo firma el titular con su llave registrada
    # (mismo flujo que el navegador: tests/conftest.py SignedMandatePoster).
    owner_keys.clear()
    poster = SignedMandatePoster(client, KeyRegistrar(client, monkeypatch))
    mandate_payload = {
        "mandate_id": "mandate_test_001",
        "human": {"id": "marta", "display_name": "Marta"},
        "agent": {"id": "agt_saturday"},
        "search_fields": SEARCH_FIELDS,
        "constraints": {
            "max_amount_per_purchase": 150.0,
            "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"],
            "max_uses": 3,
            "conditions": [
                {"type": "price_below", "value": 150.0}
            ]
        }
    }
    # Crear mandato exige token de persona: el dueño sale de ahí (api/security.py).
    resp = poster.post(mandate_payload, headers=auth_headers)
    assert resp.status_code == 201, resp.text

    # 3. Get flights
    resp = client.get("/merchant/flights")
    assert resp.status_code == 200
    flights = resp.json()
    assert len(flights) > 0

    # 4. Run agent (descubrimiento web real, mockeado arriba)
    resp = client.post("/agent/run", json={"mandate_id": "mandate_test_001", "search_fields": SEARCH_FIELDS})
    assert resp.status_code == 200
    agent_res = resp.json()
    assert "attempt" in agent_res
    assert "verification" in agent_res

    # 5. Revoke mandate (Kill Switch)
    resp = client.post("/mandates/mandate_test_001/revoke", headers=auth_headers)
    assert resp.status_code == 200

    # 6. Run agent after revocation -> Must fail immediately
    resp2 = client.post("/agent/run", json={"mandate_id": "mandate_test_001", "search_fields": SEARCH_FIELDS})
    assert resp2.status_code == 200
    agent_res2 = resp2.json()
    assert agent_res2["purchase_completed"] is False
    assert agent_res2["verification"]["verdict"] == "REJECT"
