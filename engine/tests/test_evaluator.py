"""Engine simbólico (5.1): los 5 casos del contrato (A–E) y los huecos de la auditoría.

Dinero en CENTAVOS enteros con moneda explícita (P-09). Mandato de referencia:
tope 150.00 USD, travel.flights, mch_vuelaya, 3 usos, price_below 150.00.

Cambios deliberados de contrato (R4), cada uno con su test:
- un monto inválido (ausente, ≤ 0, no entero, bool) era ESCALATE o pasaba → REJECT;
- un mandato sin límite de monto aprobaba "vacuamente" → REJECT;
- categoría/comercio se aceptaban por substring/endswith → igualdad exacta;
- una lista de comercios vacía dejaba pasar a cualquiera → REJECT ("*" es explícito);
- una condición desconocida escalaba → REJECT (no hay nada que una persona apruebe);
- la moneda distinta no se miraba → REJECT.
"""
import pytest

from engine.evaluator import evaluate
from engine.grammar import MAX_SEQUENCE_LENGTH, parse_and_evaluate

CAP = 15000


def make_mandate() -> dict:
    return {
        "constraints": {
            "currency": "USD",
            "max_amount_per_purchase_cents": CAP,
            "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"],
            "max_uses": 3,
            "conditions": [{"type": "price_below", "value_cents": CAP}],
        }
    }


def make_attempt(amount_cents, category: str = "travel.flights", merchant_id: str = "mch_vuelaya", currency: str = "USD") -> dict:
    return {
        "category": category,
        "merchant_id": merchant_id,
        "amount_cents": amount_cents,
        "currency": currency,
        "metadata": {"price_cents": amount_cents},
    }


def make_live_state(uses_count: int) -> dict:
    return {"uses_count": uses_count, "amount_spent_cents": 0}


def rules_failed(result: dict) -> set:
    return {check["rule"] for check in result["checks"] if not check["pass"]}


CASES = [
    # (id, amount_cents, category,     merchant,        uses, verdict,    regla que falla)
    ("A", 13000, "travel.flights", "mch_vuelaya",   0, "APPROVE",  None),
    ("B", 30000, "travel.flights", "mch_vuelaya",   0, "ESCALATE", "amount"),
    ("C", 13000, "hotel",          "mch_vuelaya",   0, "ESCALATE", "category"),
    ("D", 13000, "travel.flights", "mch_vuelaya",   3, "ESCALATE", "uses"),
    ("E", 13000, "travel.flights", "otro_comercio", 0, "ESCALATE", "merchant"),
]


@pytest.mark.parametrize(
    "amount, category, merchant, uses, expected_verdict, failing_rule",
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_contract_cases(amount, category, merchant, uses, expected_verdict, failing_rule):
    result = evaluate(make_mandate(), make_live_state(uses), make_attempt(amount, category, merchant))

    assert result["verdict"] == expected_verdict, result["reason"]
    assert [c["rule"] for c in result["checks"]] == ["amount", "category", "merchant", "uses", "condition.price_below"]
    for check in result["checks"]:
        assert isinstance(check["pass"], bool) and isinstance(check["detail"], str) and check["detail"]
    assert rules_failed(result) == (set() if failing_rule is None else {failing_rule} | ({"condition.price_below"} if failing_rule == "amount" else set()))
    assert isinstance(result["reason"], str) and result["reason"]


def test_nested_attempt_shape_from_core_is_flattened():
    nested = {"attempt_id": "att_x", "mandate_id": "mnd_x", "presented_by_agent": "agt_1",
              "purchase": make_attempt(13000)}
    assert evaluate(make_mandate(), make_live_state(0), nested)["verdict"] == "APPROVE"


def test_never_raises_always_returns_contract_shape():
    result = evaluate({"constraints": {"max_amount_per_purchase_cents": "no-un-numero"}}, {}, {"amount_cents": 10})
    assert result["verdict"] == "REJECT"
    assert result["checks"] and not result["checks"][0]["pass"]
    assert result["reason"]


# ── Límites exactos (en centavos, sin flotantes) ────────────────────────────

def test_amount_exactly_at_cap_passes_amount_but_fails_price_below():
    """amount usa <= y price_below usa <: en exactamente 150.00 el primero pasa."""
    result = evaluate(make_mandate(), make_live_state(0), make_attempt(CAP))
    by_rule = {c["rule"]: c["pass"] for c in result["checks"]}
    assert by_rule["amount"] is True and by_rule["condition.price_below"] is False
    assert result["verdict"] == "ESCALATE"


def test_one_cent_below_the_cap_approves():
    assert evaluate(make_mandate(), make_live_state(0), make_attempt(CAP - 1))["verdict"] == "APPROVE"


def test_last_available_use_approves():
    assert evaluate(make_mandate(), make_live_state(2), make_attempt(13000))["verdict"] == "APPROVE"


def test_multiple_failures_all_reported():
    result = evaluate(make_mandate(), make_live_state(3), make_attempt(30000, "hotel", "otro_comercio"))
    assert result["verdict"] == "ESCALATE"
    assert rules_failed(result) == {"amount", "category", "merchant", "uses", "condition.price_below"}
    for rule in rules_failed(result):
        assert rule in result["reason"]


# ── Montos inválidos → REJECT (5.1) ─────────────────────────────────────────

@pytest.mark.parametrize("amount", [None, 0, -100, -1, 150.5, 1500.0, "1500", True], ids=[
    "missing", "zero", "negative", "minus-one-cent", "float-fraction", "float-integral", "text", "bool"])
def test_invalid_amount_is_rejected_not_escalated(amount):
    """Antes: un monto ausente escalaba y uno negativo o un float pasaban. Un monto
    que no es un entero de centavos > 0 no tiene nada que una persona pueda aprobar."""
    attempt = make_attempt(amount)
    if amount is None:
        del attempt["amount_cents"]
    result = evaluate(make_mandate(), make_live_state(0), attempt)
    assert result["verdict"] == "REJECT"
    assert "amount" in rules_failed(result)


def test_currency_mismatch_is_rejected():
    result = evaluate(make_mandate(), make_live_state(0), make_attempt(13000, currency="EUR"))
    assert result["verdict"] == "REJECT" and rules_failed(result) == {"currency"}


def test_missing_currency_is_rejected():
    attempt = make_attempt(13000)
    del attempt["currency"]
    assert evaluate(make_mandate(), make_live_state(0), attempt)["verdict"] == "REJECT"


def test_currency_is_compared_normalized():
    assert evaluate(make_mandate(), make_live_state(0), make_attempt(13000, currency=" usd "))["verdict"] == "APPROVE"


# ── Mandatos que no autorizan nada → REJECT (5.1) ───────────────────────────

def test_mandate_without_amount_limit_is_rejected():
    """Antes: constraints vacías aprobaban "vacuamente" cualquier monto."""
    mandate = make_mandate()
    del mandate["constraints"]["max_amount_per_purchase_cents"]
    result = evaluate(mandate, make_live_state(0), make_attempt(13000))
    assert result["verdict"] == "REJECT" and "amount" in rules_failed(result)
    assert evaluate({"constraints": {}}, make_live_state(0), make_attempt(99999999))["verdict"] == "REJECT"


@pytest.mark.parametrize("key", ["allowed_categories", "allowed_merchants"])
@pytest.mark.parametrize("value", [None, []], ids=["missing", "empty"])
def test_mandate_without_categories_or_merchants_is_rejected(key, value):
    """Antes: lista de comercios vacía = cualquiera pasa; sin categorías no se miraba."""
    mandate = make_mandate()
    if value is None:
        del mandate["constraints"][key]
    else:
        mandate["constraints"][key] = value
    assert evaluate(mandate, make_live_state(0), make_attempt(13000))["verdict"] == "REJECT"


def test_unknown_or_malformed_condition_is_rejected():
    """REJECT por la regla de la condición (no por un error interno del engine)."""
    mandate = make_mandate()
    mandate["constraints"]["conditions"].append({"type": "frequency_per_month", "value": 2})
    result = evaluate(mandate, make_live_state(0), make_attempt(13000))
    assert result["verdict"] == "REJECT"
    assert rules_failed(result) == {"condition.frequency_per_month"}

    mandate = make_mandate()
    mandate["constraints"]["conditions"] = [{"type": "price_below", "value": 150.0}]  # en unidades: mal formada
    result = evaluate(mandate, make_live_state(0), make_attempt(13000))
    assert result["verdict"] == "REJECT"
    assert rules_failed(result) == {"condition.price_below"}


# ── Igualdad exacta (5.1) ───────────────────────────────────────────────────

@pytest.mark.parametrize("allowed, presented, ok", [
    (["travel"], "travel_giftcards", False),          # antes: substring → pasaba
    (["flights"], "travel.flights", False),           # antes: endswith → pasaba
    (["travel.flights"], "travel.flights.giftcards", False),
    (["travel.flights"], " Travel.Flights ", True),    # normalizado
    (["*"], "lo.que.sea", True),                       # comodín explícito
])
def test_category_is_exact_normalized_equality(allowed, presented, ok):
    mandate = make_mandate()
    mandate["constraints"]["allowed_categories"] = allowed
    by_rule = {c["rule"]: c["pass"] for c in evaluate(mandate, make_live_state(0), make_attempt(13000, presented))["checks"]}
    assert by_rule["category"] is ok


@pytest.mark.parametrize("presented, ok", [("mch_vuelaya", True), ("MCH_VuelaYa", True), ("mch_vuelaya_fake", False), ("vuelaya", False), (None, False)])
def test_merchant_is_exact_normalized_equality(presented, ok):
    by_rule = {c["rule"]: c["pass"] for c in evaluate(make_mandate(), make_live_state(0), make_attempt(13000, merchant_id=presented))["checks"]}
    assert by_rule["merchant"] is ok


# ── Datos del intento ───────────────────────────────────────────────────────

def test_missing_uses_count_defaults_to_zero():
    by_rule = {c["rule"]: c["pass"] for c in evaluate(make_mandate(), {}, make_attempt(13000))["checks"]}
    assert by_rule["uses"] is True


def test_price_below_falls_back_to_amount_without_metadata():
    attempt = make_attempt(13000)
    del attempt["metadata"]
    assert evaluate(make_mandate(), make_live_state(0), attempt)["verdict"] == "APPROVE"


def test_metadata_price_disagreeing_with_amount_is_caught():
    """Evil agent: monto dentro del límite pero metadata.price_cents inflado."""
    attempt = make_attempt(13000)
    attempt["metadata"]["price_cents"] = 50000
    assert evaluate(make_mandate(), make_live_state(0), attempt)["verdict"] == "ESCALATE"


def test_non_integer_metadata_price_fails_price_below():
    attempt = make_attempt(13000)
    attempt["metadata"]["price_cents"] = 129.99
    assert "condition.price_below" in rules_failed(evaluate(make_mandate(), make_live_state(0), attempt))


def test_multiple_conditions_each_get_their_own_check():
    mandate = make_mandate()
    mandate["constraints"]["conditions"].append({"type": "price_below", "value_cents": 10000})
    result = evaluate(mandate, make_live_state(0), make_attempt(13000))
    condition_checks = [c for c in result["checks"] if c["rule"].startswith("condition.")]
    assert [c["pass"] for c in condition_checks] == [True, False]
    assert result["verdict"] == "ESCALATE"


def test_verdict_is_always_one_of_the_three_contract_values():
    for mandate, live_state, attempt in [({}, {}, {}), ({"constraints": None}, {}, {}), (None, None, None),
                                         ({"constraints": {"conditions": [{}]}}, {}, {"amount_cents": 1})]:
        result = evaluate(mandate, live_state, attempt)
        assert result["verdict"] in ("APPROVE", "REJECT", "ESCALATE")
        assert isinstance(result["checks"], list) and isinstance(result["reason"], str)


# ── Gramática de expresiones (5.1) ──────────────────────────────────────────

def test_missing_field_does_not_satisfy_not_equal():
    """Antes: `merchant != 'mch_x'` era True si el intento no traía comercio (fail-open)."""
    assert parse_and_evaluate("merchant != 'mch_x'", {}) is False
    assert parse_and_evaluate("merchant != 'mch_x'", {"merchant": "mch_y"}) is True
    assert parse_and_evaluate("price < 150", {}) is False


@pytest.mark.parametrize("expression", [
    f"'a' * {MAX_SEQUENCE_LENGTH + 1} != ''",      # sin tope sería True
    f"[0] * {MAX_SEQUENCE_LENGTH + 1} != []",      # sin tope sería True
    f"{MAX_SEQUENCE_LENGTH + 1} * 'ab' != ''",     # el orden de los operandos no importa
])
def test_sequence_repetition_is_bounded(expression):
    """Antes: 'a'*999999999 construía un string de 1 GB (DoS). Ahora se corta antes de
    construirlo: una expresión que SIN tope sería verdadera falla cerrado."""
    assert parse_and_evaluate(expression, {}) is False


def test_huge_repetition_fails_closed_without_allocating():
    assert parse_and_evaluate("'a' * 999999999 != ''", {}) is False


def test_small_repetition_still_works():
    assert parse_and_evaluate("'ab' * 2 == 'abab'", {}) is True


def test_deep_or_long_expressions_fail_closed():
    assert parse_and_evaluate("not " * 100 + "True", {}) is False   # profundidad del AST
    assert parse_and_evaluate("1 + " * 600 + "1 > 0", {}) is False  # largo
    assert parse_and_evaluate("not not True", {}) is True
