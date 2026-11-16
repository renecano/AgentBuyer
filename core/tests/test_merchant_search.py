"""Tests de core/merchant_search.py — la API de OpenAI SIEMPRE va mockeada
(se parcha _call_web_search, la única frontera con la red)."""
import json

import pytest

from core import merchant_search
from core.merchant_search import OFFER_KEYS, offer_to_attempt, search_merchant_offers

VALID_OFFERS = [
    {"merchant": "Despegar", "price": 120.5, "currency": "usd",
     "details": "BUE->COR directo 08:00", "url": "https://despegar.example/1"},
    {"merchant": "Kayak", "price": 133.0, "currency": "USD",
     "details": "BUE->COR 1 escala", "url": "https://kayak.example/2"},
    {"merchant": "Expedia", "price": "145.25", "currency": "USD",
     "details": "BUE->COR directo 21:00", "url": "https://expedia.example/3"},
]

FLIGHT_FIELDS = {"origin": "BUE", "destination": "COR", "departure_date": "2026-09-10"}


def patch_search(monkeypatch, reply):
    """Parcha la frontera de red; reply puede ser str o una función(prompt)->str."""
    calls = []

    def fake(prompt: str) -> str:
        calls.append(prompt)
        return reply(prompt) if callable(reply) else reply

    monkeypatch.setattr(merchant_search, "_call_web_search", fake)
    return calls


def test_valid_category_returns_offer_dicts_with_right_keys(monkeypatch):
    patch_search(monkeypatch, json.dumps(VALID_OFFERS))
    offers = search_merchant_offers("flights", FLIGHT_FIELDS)

    assert isinstance(offers, list) and len(offers) == 3
    for offer in offers:
        # 5.1 (P-09): el precio sale en centavos ENTEROS exactos (borde con la web).
        assert set(offer) == (OFFER_KEYS - {"price"}) | {"price_cents"}
        assert isinstance(offer["price_cents"], int)
        assert offer["currency"] == "USD"  # "usd" fue normalizado
    assert [offer["price_cents"] for offer in offers] == [12050, 13300, 14525]  # "145.25" (texto) exacto


@pytest.mark.parametrize("price", [120.555, -5, 0, "abc", None, 1e-7])
def test_offer_price_that_is_not_exact_cents_is_dropped(monkeypatch, price):
    """Un precio con más de 2 decimales, negativo, cero o no numérico NO se redondea:
    la oferta se descarta (5.1)."""
    patch_search(monkeypatch, json.dumps([VALID_OFFERS[0] | {"price": price}, VALID_OFFERS[1]]))
    offers = search_merchant_offers("flights", FLIGHT_FIELDS)
    assert [offer["merchant"] for offer in offers] == ["Kayak"]


def test_malformed_api_response_returns_empty_list(monkeypatch):
    for garbage in ["lo siento, no encontré nada", "{not json", '{"a": 1}', ""]:
        patch_search(monkeypatch, garbage)
        assert search_merchant_offers("flights", FLIGHT_FIELDS) == []


def test_markdown_fenced_json_still_parses(monkeypatch):
    patch_search(monkeypatch, f"```json\n{json.dumps(VALID_OFFERS[:1])}\n```")
    offers = search_merchant_offers("flights", FLIGHT_FIELDS, max_results=1)
    assert len(offers) == 1 and offers[0]["merchant"] == "Despegar"


def test_subscriptions_single_offer_no_merchant_comparison(monkeypatch):
    calls = patch_search(monkeypatch, json.dumps(VALID_OFFERS))  # modelo devuelve 3
    offers = search_merchant_offers("subscriptions", {"service_name": "Netflix"})

    assert len(offers) == 1  # se fuerza max_results=1 aunque lleguen más
    prompt = calls[0]
    assert "Netflix" in prompt
    for comparison_site in ("Expedia", "Kayak", "Booking", "Ticketmaster"):
        assert comparison_site not in prompt


def test_api_exception_returns_empty_list(monkeypatch):
    def explode(prompt):
        raise RuntimeError("OpenAI caído")

    patch_search(monkeypatch, explode)
    assert search_merchant_offers("flights", FLIGHT_FIELDS) == []


def test_unknown_category_and_missing_fields_return_empty():
    # Sin red: la validación corta antes de llamar a la API.
    assert search_merchant_offers("yates", {"a": 1}) == []
    assert search_merchant_offers("flights", {"origin": "BUE"}) == []
    assert search_merchant_offers("tickets", {"city": "CDMX"}) == []  # falta artist/fecha
    assert search_merchant_offers("flights", "no-un-dict") == []


def test_offer_to_attempt_matches_verify_pipeline_shape():
    attempt = offer_to_attempt(
        {key: value for key, value in VALID_OFFERS[0].items() if key != "price"} | {"price_cents": 12050},
        category="flights",
        mandate_id="mnd_x",
        agent_id="agt_x",
        attempt_id="att_x",
    )
    assert attempt["presented_by_agent"] == "agt_x"
    purchase = attempt["purchase"]
    assert purchase["merchant_id"] == "mch_despegar"
    assert purchase["category"] == "travel.flights"
    assert purchase["amount_cents"] == 12050
    assert purchase["metadata"]["price_cents"] == 12050
