from __future__ import annotations
from typing import Any, Dict, List, Tuple

from engine.grammar import parse_and_evaluate


def _normalize_attempt(attempt: dict) -> dict:
    """Acepta el shape plano del contrato Y el anidado que envía core/
    ({"purchase": {...}}) — el engine es defensivo con cualquiera de los dos."""
    if not isinstance(attempt, dict):
        return {}
    purchase = attempt.get("purchase")
    if isinstance(purchase, dict):
        # Flatten metadata and fields while preserving attempt_id/mandate_id
        merged = {**attempt, **purchase}
        return merged
    return attempt


def _fmt(n: Any) -> str:
    """150.0 -> '150', 149.99 -> '149.99' — keeps details readable in the demo UI."""
    if isinstance(n, float) and n == int(n):
        return str(int(n))
    return str(n)


def _check_amount(constraints: dict, live_state: dict, attempt: dict) -> dict:
    cap = constraints.get("max_amount_per_purchase")
    if cap is None:
        cap = constraints.get("max_amount", constraints.get("max_amount_per_tx"))
    amount = attempt.get("amount")
    ok = amount is not None and cap is not None and amount <= cap
    detail = (
        f"{_fmt(amount)} <= {_fmt(cap)}" if ok
        else f"{_fmt(amount)} excede el máximo de {_fmt(cap)}"
    )
    return {"rule": "amount", "pass": ok, "detail": detail}


def _check_category(constraints: dict, live_state: dict, attempt: dict) -> dict:
    allowed = constraints.get("allowed_categories", ["*"])
    category = str(attempt.get("category", "")).strip().lower()
    
    # Matching case-insensitive and wildcard
    if "*" in allowed:
        ok = True
    else:
        ok = any(
            category == str(a).strip().lower() or category.endswith(str(a).strip().lower()) or str(a).strip().lower() in category
            for a in allowed
        )
    detail = f"{attempt.get('category')} permitida" if ok else f"{attempt.get('category')} no está en {allowed}"
    return {"rule": "category", "pass": ok, "detail": detail}


def _check_merchant(constraints: dict, live_state: dict, attempt: dict) -> dict:
    allowed = constraints.get("allowed_merchants", [])
    merchant = attempt.get("merchant_id")
    # lista vacia o '*' = cualquier comercio pasa (acordado en el contrato).
    ok = not allowed or "*" in allowed or merchant in allowed
    detail = f"{merchant} permitido" if ok else f"{merchant} no está en {allowed}"
    return {"rule": "merchant", "pass": ok, "detail": detail}


def _check_uses(constraints: dict, live_state: dict, attempt: dict) -> dict:
    max_uses = constraints.get("max_uses", constraints.get("max_executions_per_month"))
    used = live_state.get("uses_count", 0)
    if max_uses is not None:
        ok = used < max_uses
        detail = f"{used}/{max_uses}" if ok else f"usos agotados ({used}/{max_uses})"
    else:
        ok = True
        detail = "sin límite"
    return {"rule": "uses", "pass": ok, "detail": detail}


def _check_condition_price_below(condition: dict, live_state: dict, attempt: dict) -> dict:
    limit = condition.get("value")
    price = attempt.get("metadata", {}).get("price", attempt.get("amount"))
    ok = price is not None and limit is not None and price < limit
    detail = (
        f"{_fmt(price)} < {_fmt(limit)}" if ok
        else f"{_fmt(price)} no es menor que {_fmt(limit)}"
    )
    return {"rule": "condition.price_below", "pass": ok, "detail": detail}


_CONDITION_CHECKS = {
    "price_below": _check_condition_price_below,
}

_CONSTRAINT_CHECKS = [
    ("max_amount_per_purchase", _check_amount),
    ("allowed_categories", _check_category),
    ("allowed_merchants", _check_merchant),
    ("max_uses", _check_uses),
]


def evaluate(mandate: dict, live_state: dict, attempt: dict) -> dict:
    """
    evaluate(mandate, live_state, attempt) -> dict
    Punto de entrada acordado para el Engine Simbólico.
    """
    try:
        if not isinstance(mandate, dict) or not isinstance(attempt, dict):
            return {
                "verdict": "REJECT",
                "checks": [{"rule": "input_error", "pass": False, "detail": "Entrada inválida"}],
                "reason": "Entrada inválida al evaluador"
            }

        constraints = mandate.get("constraints") or mandate.get("scope", {})
        live_state_safe = live_state if isinstance(live_state, dict) else {}
        norm_attempt = _normalize_attempt(attempt)
        checks: list[dict] = []

        # 1. Reglas directas de constraints
        if any(k in constraints for k in ["max_amount_per_purchase", "max_amount", "max_amount_per_tx"]):
            checks.append(_check_amount(constraints, live_state_safe, norm_attempt))
        if "allowed_categories" in constraints:
            checks.append(_check_category(constraints, live_state_safe, norm_attempt))
        if "allowed_merchants" in constraints:
            checks.append(_check_merchant(constraints, live_state_safe, norm_attempt))
        if any(k in constraints for k in ["max_uses", "max_executions_per_month"]):
            checks.append(_check_uses(constraints, live_state_safe, norm_attempt))

        # 2. Condiciones estructuradas
        for condition in constraints.get("conditions", []):
            if isinstance(condition, dict):
                cond_type = condition.get("type")
                check_fn = _CONDITION_CHECKS.get(cond_type)
                if check_fn is not None:
                    checks.append(check_fn(condition, live_state_safe, norm_attempt))
                else:
                    field = condition.get("field", "destination")
                    val = condition.get("value")
                    actual = norm_attempt.get("metadata", {}).get(field)
                    ok = str(actual).lower() == str(val).lower() if actual is not None else False
                    checks.append({
                        "rule": f"condition.{cond_type}",
                        "pass": ok,
                        "detail": f"{field}={actual} vs {val}"
                    })
            elif isinstance(condition, str):
                ctx = {
                    "price": norm_attempt.get("amount"),
                    "amount": norm_attempt.get("amount"),
                    "category": norm_attempt.get("category"),
                    "merchant": norm_attempt.get("merchant_id"),
                    **norm_attempt.get("metadata", {})
                }
                c_pass = parse_and_evaluate(condition, ctx)
                checks.append({
                    "rule": "condition.expr",
                    "pass": c_pass,
                    "detail": f"Expresión: {condition}"
                })

        # 3. Expresión DSL string (conditions_expression)
        conditions_expr = constraints.get("conditions_expression")
        if conditions_expr and isinstance(conditions_expr, str):
            ctx = {
                "price": norm_attempt.get("amount"),
                "amount": norm_attempt.get("amount"),
                "category": norm_attempt.get("category"),
                "merchant": norm_attempt.get("merchant_id"),
                **norm_attempt.get("metadata", {})
            }
            c_pass = parse_and_evaluate(conditions_expr, ctx)
            checks.append({
                "rule": "condition.expression",
                "pass": c_pass,
                "detail": f"Expresión: {conditions_expr}"
            })

        # Veredicto
        failed = [c for c in checks if not c["pass"]]
        if not failed:
            verdict = "APPROVE"
            reason = "Todas las restricciones satisfechas"
        else:
            verdict = "ESCALATE"
            failed_rules = [c["rule"] for c in failed]
            failed_names = []
            for c in failed:
                r = c["rule"]
                if r == "amount":
                    failed_names.append("Monto excede el máximo")
                elif r == "category":
                    failed_names.append("Categoría no permitida")
                elif r == "merchant":
                    failed_names.append("Comercio no permitido")
                elif r == "uses":
                    failed_names.append("Usos agotados")
                else:
                    failed_names.append(r)
            reason = (
                "Requiere aprobación humana: falló "
                + ", ".join(failed_rules)
                + " ("
                + "; ".join(failed_names)
                + ")"
            )

        return {"verdict": verdict, "checks": checks, "reason": reason}

    except Exception as exc:
        return {
            "verdict": "REJECT",
            "checks": [{
                "rule": "engine.internal_error",
                "pass": False,
                "detail": f"{type(exc).__name__}: {exc}",
            }],
            "reason": "Error interno del motor de restricciones — rechazado por seguridad",
        }


def evaluate_mandate_constraints(mandate, attempt, state) -> Tuple[bool, str, Dict[str, bool], bool]:
    """Adaptador para core/verify.py"""
    mandate_dict = mandate.model_dump() if hasattr(mandate, "model_dump") else mandate
    attempt_dict = attempt.model_dump() if hasattr(attempt, "model_dump") else attempt
    state_dict = {
        "uses_count": getattr(state, "count_this_month", 0),
        "amount_spent": getattr(state, "spent_this_month", 0.0),
    }

    result = evaluate(mandate_dict, state_dict, attempt_dict)
    authorized = (result["verdict"] == "APPROVE")
    reason = result["reason"]
    checks_dict = {c["rule"]: c["pass"] for c in result["checks"]}
    can_escalate = (result["verdict"] == "ESCALATE")

    return authorized, reason, checks_dict, can_escalate
