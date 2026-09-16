"""Registro de condiciones: una función por cada "type" de conditions[].

Agregar una condición nueva (p. ej. frequency_per_month) es solo escribir la
función y decorarla con @register("nombre") — el loop del evaluator no se toca.

Cada función recibe (condition, live_state, attempt) y devuelve un check:
    {"rule": "condition.<type>", "pass": bool, "detail": "<legible en la demo>"}
El attempt llega ya normalizado por el evaluator (campos planos: amount,
category, merchant_id, metadata).
"""
from __future__ import annotations

from typing import Any, Callable

CheckFn = Callable[[dict, dict, dict], dict]

_REGISTRY: dict[str, CheckFn] = {}


def register(cond_type: str) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        _REGISTRY[cond_type] = fn
        return fn
    return decorator


def check_condition(condition: dict, live_state: dict, attempt: dict) -> dict:
    """Despacha por condition['type']. Tipo desconocido = check fallido (fail-closed)."""
    cond_type = condition.get("type")
    fn = _REGISTRY.get(cond_type)
    if fn is None:
        return {
            "rule": f"condition.{cond_type}",
            "pass": False,
            "detail": f"tipo de condición desconocido: {cond_type!r}",
        }
    return fn(condition, live_state, attempt)


def fmt(n: Any) -> str:
    """150.0 -> '150', 149.99 -> '149.99' — detalles legibles en la demo."""
    if isinstance(n, float) and n == int(n):
        return str(int(n))
    return str(n)


@register("price_below")
def price_below(condition: dict, live_state: dict, attempt: dict) -> dict:
    limit = condition["value"]
    price = attempt.get("metadata", {}).get("price", attempt.get("amount"))
    ok = price is not None and price < limit
    detail = (
        f"{fmt(price)} < {fmt(limit)}" if ok
        else f"{fmt(price)} no es menor que {fmt(limit)}"
    )
    return {"rule": "condition.price_below", "pass": ok, "detail": detail}
