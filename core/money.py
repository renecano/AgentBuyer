"""Dinero exacto (paso 5.1, P-09): todo monto del backend es un ENTERO en la unidad
mínima (centavos) con su moneda explícita. Las conversiones viven solo en los
bordes (lo que llega de una oferta web, de un archivo de config o de un modelo
legado, y lo que se muestra a una persona), y pasan siempre por aquí.

La conversión a centavos es la MISMA de la spec firmada (mandate/mandate_message.to_cents):
exacta, sin aritmética de flotantes, y fail-closed (más de 2 decimales, negativos,
no finitos o fuera del rango seguro → error). Así un monto que el titular firmó y uno
que el engine compara usan una sola regla.
"""
from __future__ import annotations

from typing import Any

from mandate.mandate_message import MandateMessageError, to_cents as _spec_to_cents

DEFAULT_CURRENCY = "USD"


class MoneyError(ValueError):
    """Un monto no se puede representar exacto en centavos."""


def to_cents(value: Any, field: str = "amount") -> int:
    """Centavos enteros de un monto en unidades (número o texto decimal). Lanza MoneyError."""
    try:
        return _spec_to_cents(value, field)
    except MandateMessageError as error:
        raise MoneyError(str(error)) from None


def is_cents(value: Any) -> bool:
    """¿`value` es un monto en centavos válido (entero, no bool, ≥ 0)?"""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def cents_to_text(cents: int) -> str:
    """Texto decimal EXACTO del monto ("150", "150.10"): lo que acepta la spec firmada."""
    if not is_cents(cents):
        raise MoneyError(f"Not an amount in cents: {cents!r}.")
    units, remainder = divmod(cents, 100)
    return str(units) if remainder == 0 else f"{units}.{remainder:02d}"


def format_money(cents: int) -> str:
    """Para textos de detalle legibles ("150", "120.50"): mismo formato que cents_to_text."""
    return cents_to_text(cents) if is_cents(cents) else str(cents)
