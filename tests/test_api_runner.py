import json

from fastapi.testclient import TestClient
from api.main import app
from core import merchant_search

client = TestClient(app)

WEB_OFFERS = [
    {"merchant": "VuelaYa", "price": 130.0, "currency": "USD",
     "details": "BUE-COR directo", "url": "https://vuelaya.example/1"},
]

SEARCH_FIELDS = {"origin": "BUE", "destination": "COR", "departure_date": "2026-09-15"}


def test_full_pipeline_headless(monkeypatch):
    # La búsqueda web SIEMPRE va mockeada en tests (sin red).
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda p: json.dumps(WEB_OFFERS))
    # 1. Health check
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    # 2. Create mandate (dict format expected by team endpoints)
    mandate_payload = {
        "mandate_id": "mandate_test_001",
        "human_id": "marta",
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
    resp = client.post("/mandates", json=mandate_payload)
    assert resp.status_code == 201

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
    resp = client.post("/mandates/mandate_test_001/revoke")
    assert resp.status_code == 200

    # 6. Run agent after revocation -> Must fail immediately
    resp2 = client.post("/agent/run", json={"mandate_id": "mandate_test_001", "search_fields": SEARCH_FIELDS})
    assert resp2.status_code == 200
    agent_res2 = resp2.json()
    assert agent_res2["purchase_completed"] is False
    assert agent_res2["verification"]["verdict"] == "REJECT"
