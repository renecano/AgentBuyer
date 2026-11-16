"""Paso 5.3 (P-15): un solo cliente LLM y heurísticas sin trucos. Hermético: el
cliente se sustituye (core.llm.set_llm_client) o se intercepta el SDK; nada sale a
la red ni a OpenAI."""
import json
import logging
import secrets

import httpx
import openai
import pytest
from fastapi.testclient import TestClient

import core.llm as llm
from api.main import app
from core import mandate_store, merchant_search
from core.auth_tokens import create_access_token
from core.llm import DEFAULT_MODEL, LLMConfig, LLMError, OpenAIResponsesClient, get_llm, set_llm_client
from core.merchant_identity import merchant_id_from_url
from core.semantic_firewall import auditoria_cognitiva_firewall
from tests.conftest import TEST_USER_EMAIL, verify_as_service
from tests.storage import live_state

SECRET = "sk-test-NOT-A-REAL-KEY-0123456789"


class FakeLLM:
    """Cliente simulado: devuelve `answer` o lanza `error`; registra las llamadas."""

    def __init__(self, answer=None, error=None, search_text="[]"):
        self.answer, self.error, self.search_text = answer, error, search_text
        self.calls: list = []

    def structured(self, *, system, user, schema_name, schema):
        self.calls.append(("structured", schema_name, user))
        if self.error:
            raise self.error
        return self.answer

    def web_search(self, prompt):
        self.calls.append(("web_search", prompt))
        if self.error:
            raise self.error
        return self.search_text


@pytest.fixture(autouse=True)
def no_real_llm(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    set_llm_client(None)
    yield
    set_llm_client(None)


# ── El cliente único ────────────────────────────────────────────────────────

def test_without_api_key_the_llm_is_unavailable_not_guessed():
    assert llm.llm_configured() is False
    with pytest.raises(LLMError) as raised:
        get_llm()
    assert raised.value.kind == "unavailable"


def test_config_defaults_to_the_verified_model_and_is_overridable(monkeypatch):
    assert LLMConfig.from_env().model == DEFAULT_MODEL == "gpt-6-luna"
    monkeypatch.setenv("OPENAI_MODEL", "gpt-6.1-sol")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "7")
    monkeypatch.setenv("LLM_MAX_RETRIES", "0")
    config = LLMConfig.from_env()
    assert (config.model, config.timeout_seconds, config.max_retries) == ("gpt-6.1-sol", 7, 0)
    monkeypatch.setenv("LLM_MAX_RETRIES", "-1")
    with pytest.raises(ValueError):
        LLMConfig.from_env()


def test_every_request_has_an_output_token_budget(monkeypatch):
    """P-15: presupuesto por request. Configurable; mal formado → error, no se adivina."""
    assert LLMConfig.from_env().max_output_tokens == 2000
    monkeypatch.setenv("LLM_MAX_OUTPUT_TOKENS", "300")
    assert LLMConfig.from_env().max_output_tokens == 300
    monkeypatch.setenv("LLM_MAX_OUTPUT_TOKENS", "0")
    with pytest.raises(ValueError):
        LLMConfig.from_env()


def sdk_client(monkeypatch, behaviour):
    client = OpenAIResponsesClient(SECRET, LLMConfig("gpt-6-luna", 5, 0))
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        return behaviour()
    monkeypatch.setattr(client._client.responses, "create", create)
    return client, calls


REQUEST = httpx.Request("POST", "https://api.openai.com/v1/responses")


@pytest.mark.parametrize("error, kind", [
    (lambda: openai.APITimeoutError(request=REQUEST), "timeout"),
    (lambda: openai.AuthenticationError(f"Incorrect API key provided: {SECRET}", response=httpx.Response(401, request=REQUEST), body={"error": {"message": SECRET}}), "upstream"),
    (lambda: openai.APIConnectionError(request=REQUEST), "upstream"),
])
def test_sdk_failures_become_llm_errors_without_leaking_secrets(monkeypatch, caplog, error, kind):
    def boom():
        raise error()
    client, _ = sdk_client(monkeypatch, boom)
    with caplog.at_level(logging.DEBUG, logger="core.llm"), pytest.raises(LLMError) as raised:
        client.structured(system="s", user="u", schema_name="x", schema={"type": "object"})
    assert raised.value.kind == kind
    assert SECRET not in str(raised.value) and SECRET not in caplog.text


@pytest.mark.parametrize("output_text", ["not json", "[1, 2]", None])
def test_malformed_structured_answer_is_an_error(monkeypatch, output_text):
    client, _ = sdk_client(monkeypatch, lambda: type("R", (), {"output_text": output_text})())
    with pytest.raises(LLMError) as raised:
        client.structured(system="s", user="u", schema_name="x", schema={"type": "object"})
    assert raised.value.kind == "malformed"


@pytest.mark.parametrize("operation", ["structured", "web_search"])
def test_an_answer_cut_by_the_token_budget_is_not_used(monkeypatch, operation):
    """Una respuesta incompleta (p. ej. choca con max_output_tokens) puede ser JSON válido
    a medias o texto truncado: no se usa."""
    client, _ = sdk_client(monkeypatch, lambda: type("R", (), {"status": "incomplete", "output_text": '{"verdict": "APPROVE"}'})())
    with pytest.raises(LLMError) as raised:
        if operation == "structured":
            client.structured(system="s", user="u", schema_name="x", schema={"type": "object"})
        else:
            client.web_search("find flights")
    assert raised.value.kind == "malformed"


def test_structured_and_web_search_requests_have_the_right_shape(monkeypatch):
    client, calls = sdk_client(monkeypatch, lambda: type("R", (), {"output_text": '{"ok": true}'})())
    assert client.structured(system="sys", user="usr", schema_name="audit", schema={"type": "object"}) == {"ok": True}
    client.web_search("find flights")
    structured, search = calls
    assert structured["max_output_tokens"] == search["max_output_tokens"] == 2000
    assert structured["model"] == "gpt-6-luna" and structured["text"]["format"]["type"] == "json_schema"
    assert structured["text"]["format"]["strict"] is True
    assert search["tools"] == [{"type": "web_search"}] and search["tool_choice"] == "required"


# ── Firewall semántico ──────────────────────────────────────────────────────

MANDATE = {"max_amount_per_purchase_cents": 15000, "currency": "USD", "allowed_categories": ["travel.flights"]}


def firewall(description: str, price_cents: int = 12000) -> dict:
    return auditoria_cognitiva_firewall(mandate_constraints=MANDATE, title=description, description=description,
                                        price_cents=price_cents, category="travel.flights", metadata={})


@pytest.mark.parametrize("fake", [
    FakeLLM(error=LLMError("timeout", "slow")),
    FakeLLM(error=LLMError("malformed", "bad")),
    FakeLLM(answer={"verdict": "MAYBE", "risks": [], "summary": "?"}),
    FakeLLM(answer={"verdict": "APPROVE", "risks": []}),  # sin summary
], ids=["timeout", "malformed", "unknown-verdict", "missing-summary"])
def test_firewall_llm_failures_never_approve(fake):
    set_llm_client(fake)
    result = firewall("Flight BUE-COR")
    assert result["veredicto"] == "ESCALATE" and result["source"] == "llm"


def test_firewall_uses_the_llm_verdict_when_valid():
    set_llm_client(FakeLLM(answer={"verdict": "REJECT", "risks": ["voucher"], "summary": "Bundled voucher."}))
    assert firewall("Flight BUE-COR")["veredicto"] == "REJECT"


@pytest.mark.parametrize("description", ["Flight 10:20 departure, seat 20A", "Vuelo AR1020, 20 kg de equipaje", "Hotel near terminal 10"])
def test_heuristic_no_longer_flags_charges_because_of_a_10_or_20(description):
    """Antes: "upgrade"/"extra" + un "10" o "20" en cualquier parte = cargo oculto."""
    assert firewall(description)["veredicto"] == "APPROVE"


def test_heuristic_reads_english_and_spanish_and_says_what_it_found():
    over = firewall("Flight BUE-COR, automatic upgrade charged separately: $40", price_cents=12000)
    assert over["veredicto"] == "REJECT"
    assert "160" in over["resumen_para_humano"] and "upgrade" in over["resumen_para_humano"].lower()

    unknown = firewall("Vuelo BUE-COR, cargo adicional no incluido")
    assert unknown["veredicto"] == "ESCALATE" and "amount not stated" in unknown["resumen_para_humano"]

    gift = firewall("Fare bundled with a travel gift card")
    assert gift["veredicto"] == "REJECT" and "gift card" in gift["resumen_para_humano"].lower()
    # El resumen ya no es el texto fijo de antes (que hablaba de un upgrade y de 48 h).
    assert "48" not in gift["resumen_para_humano"] and "upgrade" not in gift["resumen_para_humano"].lower()

    hold = firewall("Vuelo con escala de 48 horas")
    assert hold["veredicto"] == "ESCALATE"


# ── El LLM nunca aprueba lo que el código no aprobó; ESCALATE escala ────────

@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: "[]")
    mandate_store.mandate_store.clear()
    with TestClient(app) as test_client:
        yield test_client
    mandate_store.mandate_store.clear()


@pytest.fixture()
def mine(signed_poster, service_key) -> str:
    signed_poster.create({
        "mandate_id": "mnd_llm", "human": {"id": "hum_x", "display_name": "X"}, "agent": {"id": "agt_saturday"},
        "search_fields": {"origin": "BUE", "destination": "COR", "departure_date": "2026-12-05"},
        "constraints": {"max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
                        "allowed_merchants": ["mch_vuelaya"], "max_uses": 3},
    })
    return "mnd_llm"


def attempt(mandate_id: str, cents: int, description: str = "Flight BUE-COR", merchant: str = "mch_vuelaya", url=None) -> dict:
    metadata = {"price_cents": cents, **({"url": url} if url else {})}
    return {"attempt_id": f"att_{secrets.token_hex(4)}", "mandate_id": mandate_id, "presented_by_agent": "agt_saturday",
            "purchase": {"merchant_id": merchant, "category": "travel.flights", "amount_cents": cents, "currency": "USD",
                         "description": description, "metadata": metadata}}


def test_the_llm_cannot_approve_what_the_engine_did_not(client, mine):
    fake = FakeLLM(answer={"verdict": "APPROVE", "risks": [], "summary": "Looks fine."})
    set_llm_client(fake)
    result = verify_as_service(client, attempt(mine, 30000)).json()  # sobre el tope
    assert result["verdict"] == "ESCALATE"
    assert fake.calls == []  # ni siquiera se le preguntó


def test_firewall_escalate_escalates_on_the_react_line(client, mine):
    set_llm_client(FakeLLM(answer={"verdict": "ESCALATE", "risks": ["odd"], "summary": "A person should check this."}))
    result = verify_as_service(client, attempt(mine, 12000)).json()
    assert result["verdict"] == "ESCALATE"
    assert live_state(mine)["uses_count"] == 0


def test_firewall_failure_does_not_approve_on_the_react_line(client, mine):
    set_llm_client(FakeLLM(error=LLMError("timeout", "slow")))
    assert verify_as_service(client, attempt(mine, 12000)).json()["verdict"] == "ESCALATE"


# ── Identidad del comercio: la del dominio, no la que afirma el LLM ─────────

def test_merchant_claimed_by_the_llm_different_from_the_domain_is_rejected(client, mine):
    result = verify_as_service(client, attempt(mine, 12000, merchant="mch_vuelaya", url="https://evil.example/vuelaya")).json()
    assert result["verdict"] == "REJECT"
    assert next(c for c in result["checks"] if c["rule"] == "merchant_identity")["pass"] is False


def test_agent_uses_the_domain_merchant_not_the_claimed_name(client, mine, monkeypatch):
    """El LLM dice "VuelaYa" pero la oferta es de despegar.example: el agente presenta
    mch_despegar, que el mandato no autoriza → escala, nunca compra como VuelaYa."""
    offers = [{"merchant": "VuelaYa", "price": 120, "currency": "USD", "details": "d", "url": "https://www.despegar.example/x"}]
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: json.dumps(offers))
    run = client.post("/agent/run", json={"mandate_id": mine},
                      headers={"Authorization": f"Bearer {create_access_token(TEST_USER_EMAIL)}"}).json()
    assert run["selected_flight"]["merchant_id"] == "mch_despegar"
    assert run["verification"]["verdict"] == "ESCALATE"
    assert run["purchase_completed"] is False


def test_offers_without_a_verifiable_url_are_dropped(client, mine, monkeypatch):
    offers = [{"merchant": "VuelaYa", "price": 120, "currency": "USD", "details": "d", "url": "javascript:alert(1)"}]
    monkeypatch.setattr(merchant_search, "_call_web_search", lambda prompt: json.dumps(offers))
    run = client.post("/agent/run", json={"mandate_id": mine},
                      headers={"Authorization": f"Bearer {create_access_token(TEST_USER_EMAIL)}"}).json()
    assert run["flights_seen"] == [] and run["purchase_completed"] is False


@pytest.mark.parametrize("url, expected", [
    ("https://www.despegar.com.ar/x", "mch_despegar"), ("https://flights.kayak.com/a", "mch_kayak"),
    ("https://vuelaya.example/1", "mch_vuelaya"), ("https://evil.example/vuelaya.com", "mch_evil"),
    ("ftp://vuelaya.com", None), ("https://localhost/x", None), ("", None), (None, None),
])
def test_merchant_identity_from_url(url, expected):
    assert merchant_id_from_url(url) == expected


# ── Búsqueda web, por el cliente único ───────────────────────────────

def test_web_search_goes_through_the_single_client_and_fails_closed(monkeypatch):
    fields = {"origin": "BUE", "destination": "COR", "departure_date": "2026-12-05"}
    fake = FakeLLM(search_text=json.dumps([{"merchant": "VuelaYa", "price": 120, "currency": "USD", "details": "d", "url": "https://vuelaya.example/1"}]))
    set_llm_client(fake)
    assert [offer["price_cents"] for offer in merchant_search.search_merchant_offers("flights", fields)] == [12000]
    assert fake.calls and fake.calls[0][0] == "web_search"

    set_llm_client(FakeLLM(error=LLMError("timeout", "slow")))
    assert merchant_search.search_merchant_offers("flights", fields) == []
