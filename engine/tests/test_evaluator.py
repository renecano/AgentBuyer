"""Los 5 casos del contrato (A–E) — la definición de "engine is ready".

Mandato de referencia: max 150, categoría travel.flights, comercio mch_vuelaya,
máximo 3 usos, condición price_below 150.
"""
import pytest

from engine.evaluator import evaluate


def make_mandate() -> dict:
    return {
        "constraints": {
            "max_amount_per_purchase": 150.00,
            "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"],
            "max_uses": 3,
            "conditions": [
                {"type": "price_below", "value": 150.00},
            ],
        }
    }


def make_attempt(amount: float, category: str, merchant_id: str) -> dict:
    return {
        "category": category,
        "merchant_id": merchant_id,
        "amount": amount,
        "metadata": {"price": amount},
    }


def make_live_state(uses_count: int) -> dict:
    return {"uses_count": uses_count, "amount_spent": 0.00}


CASES = [
    # (id, amount, category,          merchant,        uses, verdict,    regla que falla)
    ("A", 130, "travel.flights", "mch_vuelaya",   0, "APPROVE",  None),
    ("B", 300, "travel.flights", "mch_vuelaya",   0, "ESCALATE", "amount"),
    ("C", 130, "hotel",          "mch_vuelaya",   0, "ESCALATE", "category"),
    ("D", 130, "travel.flights", "mch_vuelaya",   3, "ESCALATE", "uses"),
    ("E", 130, "travel.flights", "otro_comercio", 0, "ESCALATE", "merchant"),
]


@pytest.mark.parametrize(
    "amount, category, merchant, uses, expected_verdict, failing_rule",
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_contract_cases(amount, category, merchant, uses, expected_verdict, failing_rule):
    result = evaluate(
        make_mandate(),
        make_live_state(uses),
        make_attempt(amount, category, merchant),
    )

    assert result["verdict"] == expected_verdict, result["reason"]

    # Un check por regla evaluada: 4 restricciones + 1 condición.
    rules = [c["rule"] for c in result["checks"]]
    assert rules == ["amount", "category", "merchant", "uses", "condition.price_below"]

    # Todos los checks tienen la forma del contrato.
    for check in result["checks"]:
        assert isinstance(check["pass"], bool)
        assert isinstance(check["detail"], str) and check["detail"]

    failed_rules = {c["rule"] for c in result["checks"] if not c["pass"]}
    if failing_rule is None:
        assert failed_rules == set()
    else:
        assert failing_rule in failed_rules

    assert isinstance(result["reason"], str) and result["reason"]


def test_nested_attempt_shape_from_core_is_flattened():
    """core/ envía el intento con los campos anidados en attempt["purchase"];
    el normalizador debe aplanarlo — sin él, todo escalaría por campos ausentes."""
    nested_attempt = {
        "attempt_id": "att_x",
        "mandate_id": "mnd_x",
        "presented_by_agent": "agt_1",
        "purchase": make_attempt(130, "travel.flights", "mch_vuelaya"),
    }
    result = evaluate(make_mandate(), make_live_state(0), nested_attempt)
    assert result["verdict"] == "APPROVE", result["reason"]


def test_never_raises_always_returns_contract_shape():
    """El contrato prohíbe propagar excepciones: hasta con basura debe
    devolver el dict completo con verdict REJECT y un check explicativo."""
    garbage_mandate = {"constraints": {"max_amount_per_purchase": "no-un-numero"}}
    result = evaluate(garbage_mandate, {}, {"amount": 10})

    assert result["verdict"] == "REJECT"
    assert result["checks"] and not result["checks"][0]["pass"]
    assert result["reason"]


# ── Límites exactos ──────────────────────────────────────────────────────────

def test_amount_exactly_at_cap_passes_amount_but_fails_price_below():
    """amount usa <= y price_below usa < : en exactamente 150 el primero pasa
    y el segundo no. Vale la pena tenerlo escrito porque confunde en la demo."""
    result = evaluate(make_mandate(), make_live_state(0),
                      make_attempt(150.00, "travel.flights", "mch_vuelaya"))
    by_rule = {c["rule"]: c["pass"] for c in result["checks"]}
    assert by_rule["amount"] is True
    assert by_rule["condition.price_below"] is False
    assert result["verdict"] == "ESCALATE"


def test_rounding_trick_just_over_the_cap_escalates():
    """El truco del redondeo del evil agent: 150.0000001 NO es < 150."""
    result = evaluate(make_mandate(), make_live_state(0),
                      make_attempt(150.0000001, "travel.flights", "mch_vuelaya"))
    assert result["verdict"] == "ESCALATE"


def test_just_below_the_cap_approves():
    result = evaluate(make_mandate(), make_live_state(0),
                      make_attempt(149.99, "travel.flights", "mch_vuelaya"))
    assert result["verdict"] == "APPROVE"


def test_last_available_use_approves():
    """uses_count 2 de max 3: todavía queda un uso."""
    result = evaluate(make_mandate(), make_live_state(2),
                      make_attempt(130, "travel.flights", "mch_vuelaya"))
    assert result["verdict"] == "APPROVE"


# ── Fallas múltiples ─────────────────────────────────────────────────────────

def test_multiple_failures_all_reported():
    """Todas las reglas violadas aparecen en checks[] y en el reason —
    no se corta en la primera falla (eso es lo que hace el trail explicable)."""
    result = evaluate(make_mandate(), make_live_state(3),
                      make_attempt(300, "hotel", "otro_comercio"))
    assert result["verdict"] == "ESCALATE"
    failed = {c["rule"] for c in result["checks"] if not c["pass"]}
    assert failed == {"amount", "category", "merchant", "uses", "condition.price_below"}
    for rule in failed:
        assert rule in result["reason"]


# ── Datos faltantes / defensivo ──────────────────────────────────────────────

def test_missing_amount_fails_amount_check_not_crash():
    attempt = {"category": "travel.flights", "merchant_id": "mch_vuelaya"}
    result = evaluate(make_mandate(), make_live_state(0), attempt)
    assert result["verdict"] == "ESCALATE"
    by_rule = {c["rule"]: c["pass"] for c in result["checks"]}
    assert by_rule["amount"] is False


def test_missing_uses_count_defaults_to_zero():
    result = evaluate(make_mandate(), {},
                      make_attempt(130, "travel.flights", "mch_vuelaya"))
    by_rule = {c["rule"]: c["pass"] for c in result["checks"]}
    assert by_rule["uses"] is True


def test_price_below_falls_back_to_amount_without_metadata():
    attempt = make_attempt(130, "travel.flights", "mch_vuelaya")
    del attempt["metadata"]
    result = evaluate(make_mandate(), make_live_state(0), attempt)
    assert result["verdict"] == "APPROVE"


def test_metadata_price_disagreeing_with_amount_is_caught():
    """Evil agent: amount dentro del límite pero metadata.price inflado —
    price_below evalúa metadata.price, así que la discrepancia escala."""
    attempt = make_attempt(130, "travel.flights", "mch_vuelaya")
    attempt["metadata"]["price"] = 500.0
    result = evaluate(make_mandate(), make_live_state(0), attempt)
    assert result["verdict"] == "ESCALATE"


def test_nested_purchase_that_is_not_a_dict_is_treated_as_flat():
    """attempt["purchase"] con basura no-dict no debe romper el normalizador."""
    attempt = make_attempt(130, "travel.flights", "mch_vuelaya")
    attempt["purchase"] = "no-soy-un-dict"
    result = evaluate(make_mandate(), make_live_state(0), attempt)
    assert result["verdict"] == "APPROVE"


# ── Restricciones parciales / trial by fire ──────────────────────────────────

def test_missing_constraint_keys_are_simply_not_checked():
    """Un mandato solo con max_amount: se evalúa solo esa regla, sin checks fantasma."""
    mandate = {"constraints": {"max_amount_per_purchase": 150.00}}
    result = evaluate(mandate, make_live_state(0),
                      make_attempt(130, "cualquier.cosa", "quien_sea"))
    assert result["verdict"] == "APPROVE"
    assert [c["rule"] for c in result["checks"]] == ["amount"]


def test_empty_constraints_approves_vacuously():
    """Sin restricciones no hay nada que violar. Documentado a propósito:
    si el equipo prefiere ESCALATE aquí, se decide en grupo y se cambia el test."""
    result = evaluate({"constraints": {}}, make_live_state(0),
                      make_attempt(999999, "x", "y"))
    assert result["verdict"] == "APPROVE"
    assert result["checks"] == []


def test_empty_allowed_merchants_means_anyone_passes():
    """Acordado en el contrato: lista vacía de comercios = cualquiera pasa."""
    mandate = make_mandate()
    mandate["constraints"]["allowed_merchants"] = []
    result = evaluate(mandate, make_live_state(0),
                      make_attempt(130, "travel.flights", "comercio_random"))
    by_rule = {c["rule"]: c["pass"] for c in result["checks"]}
    assert by_rule["merchant"] is True
    assert result["verdict"] == "APPROVE"


def test_unknown_condition_type_fails_closed():
    """Trial by fire: un juez inyecta una condición que no existe todavía.
    Fail-closed = check fallido + ESCALATE, nunca aprobar en silencio."""
    mandate = make_mandate()
    mandate["constraints"]["conditions"].append({"type": "frequency_per_month", "value": 2})
    result = evaluate(mandate, make_live_state(0),
                      make_attempt(130, "travel.flights", "mch_vuelaya"))
    assert result["verdict"] == "ESCALATE"
    by_rule = {c["rule"]: c["pass"] for c in result["checks"]}
    assert by_rule["condition.frequency_per_month"] is False


def test_multiple_conditions_each_get_their_own_check():
    mandate = make_mandate()
    mandate["constraints"]["conditions"].append({"type": "price_below", "value": 100.00})
    result = evaluate(mandate, make_live_state(0),
                      make_attempt(130, "travel.flights", "mch_vuelaya"))
    condition_checks = [c for c in result["checks"] if c["rule"].startswith("condition.")]
    assert len(condition_checks) == 2
    assert [c["pass"] for c in condition_checks] == [True, False]  # <150 sí, <100 no
    assert result["verdict"] == "ESCALATE"


def test_verdict_is_always_one_of_the_three_contract_values():
    weird_inputs = [
        ({}, {}, {}),
        ({"constraints": None}, {}, {}),
        (None, None, None),
        ({"constraints": {"conditions": [{}]}}, {}, {"amount": 1}),
    ]
    for mandate, live_state, attempt in weird_inputs:
        result = evaluate(mandate, live_state, attempt)
        assert result["verdict"] in ("APPROVE", "REJECT", "ESCALATE")
        assert isinstance(result["checks"], list)
        assert isinstance(result["reason"], str)
