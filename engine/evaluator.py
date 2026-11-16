"""Engine simbólico de restricciones (paso 5.1: dinero exacto y reglas sin huecos).

evaluate(mandate, live_state, attempt) -> {"verdict", "checks", "reason"}

Dinero (P-09): todo en CENTAVOS enteros con moneda explícita.
    mandato:  constraints.max_amount_per_purchase_cents, conditions[].value_cents, currency
    intento:  amount_cents, currency, metadata.price_cents (opcional)

Veredicto:
- REJECT: el intento o el mandato no se pueden evaluar con seguridad. Monto no entero
  o ≤ 0, moneda distinta, mandato sin límite de monto, sin categorías o comercios, o
  con una condición desconocida o mal formada. Esto no se escala: no hay nada que una
  persona pueda aprobar con sentido.
- ESCALATE: el intento es válido pero incumple algún límite del mandato (monto,
  categoría, comercio, usos, precio). Decide la persona.
- APPROVE: cumple todo.

Categoría y comercio por IGUALDAD EXACTA normalizada (trim + minúsculas). Antes se
aceptaba por substring/endswith: "travel" dejaba pasar "travel_giftcards". El
comodín "*" sigue existiendo, pero es EXPLÍCITO (está escrito, y firmado, en el
mandato); una lista vacía ya no es "cualquiera".

Nunca lanza: un error interno es REJECT (fail-closed).
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Tuple

from core.money import MoneyError, format_money, is_cents, to_cents
from engine.grammar import parse_and_evaluate

WILDCARD = "*"


def _normalize_attempt(attempt: dict) -> dict:
    """Acepta el shape plano del contrato Y el anidado que envía core/
    ({"purchase": {...}}) — el engine es defensivo con cualquiera de los dos."""
    if not isinstance(attempt, dict):
        return {}
    purchase = attempt.get("purchase")
    if isinstance(purchase, dict):
        return {**attempt, **purchase}
    return attempt


def _label(value: Any) -> str:
    return str(value).strip().lower()


def _hard(rule: str, detail: str) -> dict:
    return {"rule": rule, "pass": False, "detail": detail, "hard": True}


def _check_amount(cap_cents: int, amount_cents: int) -> dict:
    ok = amount_cents <= cap_cents
    detail = (f"{format_money(amount_cents)} <= {format_money(cap_cents)}" if ok
              else f"{format_money(amount_cents)} exceeds the maximum of {format_money(cap_cents)}")
    return {"rule": "amount", "pass": ok, "detail": detail}


def _check_label(rule: str, allowed: List[Any], presented: Any, word: str) -> dict:
    """Igualdad exacta normalizada contra la lista, o el comodín explícito "*"."""
    normalized = {_label(item) for item in allowed}
    value = _label(presented) if presented is not None else ""
    ok = WILDCARD in normalized or (bool(value) and value in normalized)
    return {"rule": rule, "pass": ok, "detail": f"{presented} {word}" if ok else f"{presented} is not in {allowed}"}


def _check_uses(constraints: dict, live_state: dict) -> dict:
    """max_uses: usos de POR VIDA (live_state.uses_count). max_executions_per_month
    (línea estricta): usos del MES en curso (month_uses); si no viene el dato del mes
    se usa el total, que nunca es menor (fail-closed) (5.2)."""
    if "max_uses" in constraints:
        limit, used = constraints["max_uses"], live_state.get("uses_count", 0)
    else:
        limit = constraints.get("max_executions_per_month")
        used = live_state.get("month_uses", live_state.get("uses_count", 0))
    ok = used < limit
    return {"rule": "uses", "pass": ok, "detail": f"{used}/{limit}" if ok else f"uses exhausted ({used}/{limit})"}


def _check_monthly_budget(budget_cents: int, live_state: dict, amount_cents: int) -> dict:
    """Presupuesto del MES calendario (UTC) en curso (5.2). Sin el dato del mes se usa
    el gasto total, que nunca es menor (fail-closed)."""
    spent = live_state.get("month_spent_cents", live_state.get("amount_spent_cents", 0))
    ok = spent + amount_cents <= budget_cents
    detail = (f"{format_money(spent + amount_cents)} <= {format_money(budget_cents)} this month" if ok
              else f"{format_money(spent)} spent + {format_money(amount_cents)} exceeds the monthly budget of {format_money(budget_cents)}")
    return {"rule": "monthly_budget", "pass": ok, "detail": detail}


def _check_price_below(condition: dict, price_cents: Any) -> dict:
    limit = condition.get("value_cents")
    ok = is_cents(price_cents) and price_cents < limit
    detail = (f"{format_money(price_cents)} < {format_money(limit)}" if ok
              else f"{format_money(price_cents) if is_cents(price_cents) else price_cents} is not below {format_money(limit)}")
    return {"rule": "condition.price_below", "pass": ok, "detail": detail}


def _expression_context(attempt: dict) -> Dict[str, Any]:
    """Contexto de las expresiones DSL (legado de la línea estricta): los montos en
    UNIDADES exactas (Decimal), que es como una persona escribe "price <= 150"."""
    amount = attempt.get("amount_cents")
    price = (attempt.get("metadata") or {}).get("price_cents", amount)
    as_units = (lambda cents: Decimal(cents) / 100 if is_cents(cents) else None)
    return {
        **{key: value for key, value in (attempt.get("metadata") or {}).items() if not key.endswith("_cents")},
        "price": as_units(price),
        "amount": as_units(amount),
        "category": attempt.get("category"),
        "merchant": attempt.get("merchant_id"),
    }


def _evaluate(mandate: dict, live_state: dict, attempt: dict) -> Tuple[str, List[dict], str]:
    constraints = mandate.get("constraints") or mandate.get("scope") or {}
    if not isinstance(constraints, dict):
        return "REJECT", [_hard("input_error", "The mandate has no readable constraints.")], "Unreadable mandate"
    norm = _normalize_attempt(attempt)
    checks: List[dict] = []

    # ── Precondiciones duras (REJECT) ───────────────────────────────────────
    cap = constraints.get("max_amount_per_purchase_cents")
    if not is_cents(cap) or cap <= 0:
        checks.append(_hard("amount", "The mandate has no valid amount limit, so it authorizes no purchase."))
    amount = norm.get("amount_cents")
    if not is_cents(amount) or amount <= 0:
        checks.append(_hard("amount", f"Invalid amount ({amount!r}): it must be a whole number of cents above zero."))
    mandate_currency = constraints.get("currency")
    attempt_currency = norm.get("currency")
    if not isinstance(mandate_currency, str) or not isinstance(attempt_currency, str) \
            or mandate_currency.strip().upper() != attempt_currency.strip().upper():
        checks.append(_hard("currency", f"The purchase is in {attempt_currency}; the mandate only authorizes {mandate_currency}."))
    for key, rule in (("allowed_categories", "category"), ("allowed_merchants", "merchant")):
        allowed = constraints.get(key)
        if not isinstance(allowed, list) or not allowed:
            checks.append(_hard(rule, f"The mandate doesn't define {key}, so it authorizes no purchase."))
    conditions = constraints.get("conditions", [])
    if not isinstance(conditions, list):
        checks.append(_hard("conditions", "The mandate's conditions are not a list."))
        conditions = []
    for condition in conditions:
        if isinstance(condition, dict) and (condition.get("type") != "price_below" or not is_cents(condition.get("value_cents"))):
            checks.append(_hard(f"condition.{condition.get('type')}", "Unknown or malformed condition: it can't be evaluated."))
    if checks:
        reasons = "; ".join(check["detail"] for check in checks)
        return "REJECT", checks, f"Rejected: {reasons}"

    # ── Reglas (ESCALATE si alguna falla) ───────────────────────────────────
    checks.append(_check_amount(cap, amount))
    checks.append(_check_label("category", constraints["allowed_categories"], norm.get("category"), "allowed"))
    checks.append(_check_label("merchant", constraints["allowed_merchants"], norm.get("merchant_id"), "allowed"))
    if any(key in constraints for key in ("max_uses", "max_executions_per_month")):
        checks.append(_check_uses(constraints, live_state))
    if is_cents(constraints.get("monthly_budget_cents")):
        checks.append(_check_monthly_budget(constraints["monthly_budget_cents"], live_state, amount))

    price_cents = (norm.get("metadata") or {}).get("price_cents", amount)
    for condition in conditions:
        if isinstance(condition, dict):
            checks.append(_check_price_below(condition, price_cents))
        elif isinstance(condition, str):
            checks.append({"rule": "condition.expr", "pass": parse_and_evaluate(condition, _expression_context(norm)),
                           "detail": f"Expression: {condition}"})
    expression = constraints.get("conditions_expression")
    if isinstance(expression, str) and expression:
        checks.append({"rule": "condition.expression", "pass": parse_and_evaluate(expression, _expression_context(norm)),
                       "detail": f"Expression: {expression}"})

    failed = [check for check in checks if not check["pass"]]
    if not failed:
        return "APPROVE", checks, "All constraints satisfied"
    names = {"amount": "Amount exceeds the maximum", "category": "Category not allowed",
             "merchant": "Merchant not allowed", "uses": "Uses exhausted",
             "monthly_budget": "Monthly budget used up"}
    reason = (
        "Requires human approval — failed check: " + ", ".join(check["rule"] for check in failed)
        + " (" + "; ".join(names.get(check["rule"], check["rule"]) for check in failed) + ")"
    )
    return "ESCALATE", checks, reason


def evaluate(mandate: dict, live_state: dict, attempt: dict) -> dict:
    """Punto de entrada acordado para el Engine Simbólico. Nunca lanza."""
    try:
        if not isinstance(mandate, dict) or not isinstance(attempt, dict):
            return {"verdict": "REJECT", "checks": [{"rule": "input_error", "pass": False, "detail": "Invalid input"}],
                    "reason": "Invalid input to the evaluator"}
        verdict, checks, reason = _evaluate(mandate, live_state if isinstance(live_state, dict) else {}, attempt)
        return {"verdict": verdict, "checks": [{key: value for key, value in check.items() if key != "hard"} for check in checks],
                "reason": reason}
    except Exception as exc:
        return {
            "verdict": "REJECT",
            "checks": [{"rule": "engine.internal_error", "pass": False, "detail": f"{type(exc).__name__}: {exc}"}],
            "reason": "Internal constraint-engine error — rejected for safety",
        }


# ── Borde con la línea estricta (legado, D-01; se retira en el 7.2, P-08) ────

def _cents_or_none(value: Any) -> Any:
    try:
        return to_cents(value)
    except MoneyError:
        return None
