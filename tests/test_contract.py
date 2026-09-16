import pytest
from engine.evaluator import evaluate


@pytest.fixture
def base_mandate():
    return {
        "constraints": {
            "max_amount_per_purchase": 150.00,
            "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"],
            "max_uses": 3,
            "conditions": [
                {"type": "price_below", "value": 150.00}
            ]
        }
    }


def test_case_a_approve(base_mandate):
    """A. amount 130, flight, vuelaya, price 130, usos 0 -> APPROVE"""
    live_state = {"uses_count": 0, "amount_spent": 0.00}
    attempt = {
        "category": "travel.flights",
        "merchant_id": "mch_vuelaya",
        "amount": 130.00,
        "metadata": {"price": 130.00}
    }

    result = evaluate(base_mandate, live_state, attempt)

    assert result["verdict"] == "APPROVE"
    assert result["reason"] == "Todas las restricciones satisfechas"
    assert all(c["pass"] is True for c in result["checks"])
    assert len(result["checks"]) >= 5


def test_case_b_escalate_amount(base_mandate):
    """B. amount 300, flight, vuelaya, price 300, usos 0 -> ESCALATE (monto)"""
    live_state = {"uses_count": 0, "amount_spent": 0.00}
    attempt = {
        "category": "travel.flights",
        "merchant_id": "mch_vuelaya",
        "amount": 300.00,
        "metadata": {"price": 300.00}
    }

    result = evaluate(base_mandate, live_state, attempt)

    assert result["verdict"] == "ESCALATE"
    assert any(c["rule"] == "amount" and c["pass"] is False for c in result["checks"])
    assert "Monto" in result["reason"]


def test_case_c_escalate_category(base_mandate):
    """C. amount 130, hotel, vuelaya, usos 0 -> ESCALATE (categoria)"""
    live_state = {"uses_count": 0, "amount_spent": 0.00}
    attempt = {
        "category": "travel.hotel",
        "merchant_id": "mch_vuelaya",
        "amount": 130.00,
        "metadata": {"price": 130.00}
    }

    result = evaluate(base_mandate, live_state, attempt)

    assert result["verdict"] == "ESCALATE"
    assert any(c["rule"] == "category" and c["pass"] is False for c in result["checks"])
    assert "Categoría" in result["reason"]


def test_case_d_escalate_uses_exhausted(base_mandate):
    """D. amount 130, flight, vuelaya, usos 3 -> ESCALATE (usos agotados)"""
    live_state = {"uses_count": 3, "amount_spent": 390.00}
    attempt = {
        "category": "travel.flights",
        "merchant_id": "mch_vuelaya",
        "amount": 130.00,
        "metadata": {"price": 130.00}
    }

    result = evaluate(base_mandate, live_state, attempt)

    assert result["verdict"] == "ESCALATE"
    assert any(c["rule"] == "uses" and c["pass"] is False for c in result["checks"])
    assert "Usos agotados" in result["reason"]


def test_case_e_escalate_merchant_disallowed(base_mandate):
    """E. amount 130, flight, otro_comercio, usos 0 -> ESCALATE (comercio)"""
    live_state = {"uses_count": 0, "amount_spent": 0.00}
    attempt = {
        "category": "travel.flights",
        "merchant_id": "mch_otro_comercio",
        "amount": 130.00,
        "metadata": {"price": 130.00}
    }

    result = evaluate(base_mandate, live_state, attempt)

    assert result["verdict"] == "ESCALATE"
    assert any(c["rule"] == "merchant" and c["pass"] is False for c in result["checks"])
    assert "Comercio" in result["reason"]


def test_fail_closed_on_corrupt_input():
    """Fails closed safely, returns dict with REJECT, never raises exceptions or returns None."""
    result = evaluate(None, None, None)
    assert isinstance(result, dict)
    assert result["verdict"] in ["REJECT", "ESCALATE"]
    assert "checks" in result
    assert "reason" in result
