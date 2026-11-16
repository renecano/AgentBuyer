"""Mensaje que firma el HUMANO al crear un mandato: especificación v1 (paso 3.2).

Gemelo de frontend/src/lib/mandateMessage.ts: ambos producen los MISMOS bytes
(canonicalización del 2.0, mandate/canonical.py). shared/mandate_signing_vectors.json
fija mensaje y firma exactos; pytest y Vitest leen ese mismo archivo.

Todavía NO está conectado: el backend no lo verifica (paso 3.3) ni el navegador lo
firma (paso 3.4).

Lo que se firma (mandate_signing_payload)
-----------------------------------------
    purpose        "agentbuyer:mandate:v1". Separación de dominio: una firma de
                   registro de llave (agentbuyer:register-key:v1) nunca vale como
                   mandato, ni al revés; la versión permite cambiar el formato.
    mandate_id     lo genera el cliente; identificador sin espacios.
    owner          email del token, trim + minúsculas.
    key_id         id de la llave registrada que firma (POST /keys).
    public_key     su pubkey Ed25519, 64 hex en minúsculas.
    agent_id       el agente al que se autoriza.
    constraints    normalizadas:
        currency                        3 letras en mayúsculas; v1 solo "USD".
        max_amount_per_purchase_cents   entero > 0 (D-11: centavos, sin flotantes).
        allowed_categories              trim + minúsculas, sin duplicados, ordenadas.
        allowed_merchants               ídem.
        max_uses                        entero ≥ 1.
        conditions                      lista cerrada de tipos conocidos, una por tipo,
                                        ordenada por tipo. v1: {"type": "price_below",
                                        "value_cents": entero > 0}.
        off_session_consent             booleano: el consentimiento a cobros sin la
                                        persona presente también es autorización.
    search_fields  lo que el agente puede buscar/comprar: objeto plano, claves
                   [a-z][a-z0-9_]*, valores texto (trim, no vacío) o enteros seguros.
    expires_at     ISO 8601 UTC con Z, precisión de segundos ("2026-12-01T00:00:00Z").
                   React manda hoy `valid_until` y el backend lo ignora; el campo
                   firmado se llama expires_at y el 3.3 lo hará cumplir. Obligatorio:
                   un mandato firmado sin vencimiento sería una autorización eterna.
    created_at     mismo formato; expires_at debe ser POSTERIOR.
    nonce          32 hex (128 bits) aleatorios del cliente, en minúsculas.

Lo que NO se firma, a propósito
-------------------------------
    payment_token  lo emite el servidor DESPUÉS de verificar la firma; en el 3.3 se
                   ata al hash del mandato firmado (no al revés).
    human.*        nombre, documento, teléfono, email de contacto: PII que no
                   autoriza nada. Firmarla la metería en cada copia del mensaje.
    monthly_budget, max_executions_per_month, conditions_expression y cualquier otra
    clave de constraints: no existen en v1. Una clave desconocida es un ERROR (no se
    ignora): nada que autorice puede viajar junto al mandato sin estar firmado.

Montos sin flotantes
--------------------
Un monto entra como NÚMERO o como TEXTO decimal y sale como centavos enteros:
- Número (int, Decimal, o float leído de JSON): su valor decimal EXACTO (un float
  vale lo que dice repr(), el mismo texto mínimo que String(n) en JS) debe ser un
  múltiplo de 0.01. 150 → 15000; 150.1 → 15010; 0.30000000000000004 → error.
- Texto: gramática estricta "(0|[1-9][0-9]*)(.[0-9]{1,2})?". "150.10" → 15010;
  "150.125", "-5", "+5", "1e2", " 5" → error.
- Negativo, no finito, bool, o > 2^53−1 centavos → error. Nunca se redondea.

Fail-closed en todo: cualquier dato fuera de la spec lanza MandateMessageError
(con `field`, el campo culpable). Nunca se "arregla" nada en silencio salvo las
normalizaciones listadas arriba, que son idénticas en los dos lenguajes. El trim
usa un conjunto de espacios EXPLÍCITO (el de String.prototype.trim de JS), no
str.strip(): así Python y TS recortan exactamente lo mismo.
"""
from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Mapping, Optional

from mandate.canonical import MAX_SAFE_INTEGER, canonicalize

MANDATE_PURPOSE = "agentbuyer:mandate:v1"
SUPPORTED_CURRENCIES = ("USD",)

# Espacios que recorta String.prototype.trim (WhiteSpace + LineTerminator de ECMAScript),
# como code points: el MISMO conjunto que TRIM_CODE_POINTS en mandateMessage.ts.
TRIM_CODE_POINTS = (
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, *range(0x2000, 0x200B),
    0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF,
)
# Prohibido dentro de un email: esos espacios y todos los controles (C0, DEL, C1).
EMAIL_FORBIDDEN_CODE_POINTS = (*TRIM_CODE_POINTS, *range(0x00, 0x20), *range(0x7F, 0xA0))


def _char_class(code_points) -> str:
    return "[" + "".join(re.escape(chr(code_point)) for code_point in sorted(set(code_points))) + "]"


_TRIM_CLASS = _char_class(TRIM_CODE_POINTS)
_TRIM = re.compile(rf"\A{_TRIM_CLASS}+|{_TRIM_CLASS}+\Z")
_EMAIL_FORBIDDEN = re.compile(_char_class(EMAIL_FORBIDDEN_CODE_POINTS))
# Las validaciones usan fullmatch: en Python `$` acepta un salto de línea final y en JS no.
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_PUBLIC_KEY = re.compile(r"[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_CURRENCY = re.compile(r"[A-Z]{3}")
_SEARCH_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}")
_AMOUNT_TEXT = re.compile(r"(0|[1-9][0-9]*)(\.[0-9]{1,2})?")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

_CONSTRAINT_KEYS = frozenset({
    "currency", "max_amount_per_purchase", "allowed_categories", "allowed_merchants",
    "max_uses", "conditions", "off_session_consent",
})
_REQUIRED_CONSTRAINT_KEYS = _CONSTRAINT_KEYS - {"conditions"}


class MandateMessageError(ValueError):
    """El dato no cumple la especificación del mandato firmado v1."""

    def __init__(self, field: str, message: str):
        super().__init__(f"{field}: {message}")
        self.field = field


# ── Normalizaciones ─────────────────────────────────────────────────────────

def _trim(text: str) -> str:
    return _TRIM.sub("", text)


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise MandateMessageError(field, "must be an identifier ([A-Za-z0-9_.:-], 1-128 chars, no spaces).")
    return value


def _owner(value: Any) -> str:
    if not isinstance(value, str):
        raise MandateMessageError("owner", "must be the session email.")
    owner = _trim(value).lower()
    local, at, domain = owner.partition("@")
    if not local or not at or not domain or "@" in domain or _EMAIL_FORBIDDEN.search(owner):
        raise MandateMessageError("owner", "must be a single email address without spaces.")
    return owner


def _hex(value: Any, pattern: re.Pattern, field: str, description: str) -> str:
    if not isinstance(value, str):
        raise MandateMessageError(field, f"must be {description}.")
    normalized = value.lower()
    if not pattern.fullmatch(normalized):
        raise MandateMessageError(field, f"must be {description}.")
    return normalized


def to_cents(value: Any, field: str) -> int:
    """Centavos enteros de un monto, sin pasar nunca por aritmética de flotantes."""
    if isinstance(value, bool):
        raise MandateMessageError(field, "must be an amount, not a boolean.")
    if isinstance(value, str):
        if not _AMOUNT_TEXT.fullmatch(value):
            raise MandateMessageError(field, "must be a decimal amount with at most 2 decimals (e.g. 150 or 150.10).")
        amount = Decimal(value)
    elif isinstance(value, int):
        amount = Decimal(value)
    elif isinstance(value, float):
        # repr() = el texto decimal mínimo que reconstruye el float (el mismo que
        # String(n) en JS): se toma ESE valor exacto, no el binario del float.
        try:
            amount = Decimal(repr(value))
        except InvalidOperation:
            raise MandateMessageError(field, "must be a finite amount.") from None
    elif isinstance(value, Decimal):
        amount = value
    else:
        raise MandateMessageError(field, "must be a number or a decimal string.")

    if not amount.is_finite():
        raise MandateMessageError(field, "must be a finite amount.")
    sign, digit_tuple, exponent = amount.as_tuple()
    digits = int("".join(map(str, digit_tuple)) or "0")
    if sign and digits != 0:
        raise MandateMessageError(field, "must not be negative.")
    scale = exponent + 2  # centavos = digits × 10^scale
    if digits == 0:
        cents = 0  # sin calcular 10^scale: "0E+999999999" no debe colgar nada
    elif scale >= 0:
        if len(str(digits)) + scale > len(str(MAX_SAFE_INTEGER)):
            raise MandateMessageError(field, "is out of the safe range.")
        cents = digits * 10 ** scale
    else:
        if len(str(digits)) <= -scale:
            raise MandateMessageError(field, "must have at most 2 decimals.")
        divisor = 10 ** -scale
        if digits % divisor:
            raise MandateMessageError(field, "must have at most 2 decimals.")
        cents = digits // divisor
    if cents > MAX_SAFE_INTEGER:
        raise MandateMessageError(field, "is out of the safe range.")
    return cents


def _positive_cents(value: Any, field: str) -> int:
    cents = to_cents(value, field)
    if cents <= 0:
        raise MandateMessageError(field, "must be greater than zero.")
    return cents


def _safe_int(value: Any, field: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= MAX_SAFE_INTEGER:
        raise MandateMessageError(field, f"must be an integer ≥ {minimum}.")
    return value


def _utf16_key(text: str) -> bytes:
    return text.encode("utf-16-be", "surrogatepass")


def _label_list(value: Any, field: str) -> List[str]:
    """trim + minúsculas, sin duplicados, ordenada (unidades UTF-16, como sort() de JS)."""
    if not isinstance(value, list) or not value:
        raise MandateMessageError(field, "must be a non-empty list.")
    labels = set()
    for item in value:
        if not isinstance(item, str) or not _trim(item):
            raise MandateMessageError(field, "must contain non-empty texts.")
        labels.add(_trim(item).lower())
    return sorted(labels, key=_utf16_key)


def _conditions(value: Any) -> List[Dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise MandateMessageError("constraints.conditions", "must be a list.")
    by_type: Dict[str, Dict[str, Any]] = {}
    for condition in value:
        if not isinstance(condition, dict) or condition.get("type") != "price_below" or set(condition) != {"type", "value"}:
            raise MandateMessageError("constraints.conditions", 'v1 only supports {"type": "price_below", "value": amount}.')
        if condition["type"] in by_type:
            raise MandateMessageError("constraints.conditions", "each condition type may appear only once.")
        by_type[condition["type"]] = {
            "type": condition["type"],
            "value_cents": _positive_cents(condition["value"], "constraints.conditions.price_below"),
        }
    return [by_type[kind] for kind in sorted(by_type, key=_utf16_key)]


def _constraints(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise MandateMessageError("constraints", "must be an object.")
    unknown = sorted(set(value) - _CONSTRAINT_KEYS)
    if unknown:
        raise MandateMessageError("constraints", f"unknown field(s) not covered by the signature: {', '.join(unknown)}.")
    missing = sorted(_REQUIRED_CONSTRAINT_KEYS - set(value))
    if missing:
        raise MandateMessageError("constraints", f"missing field(s): {', '.join(missing)}.")

    currency = value["currency"]
    if not isinstance(currency, str) or not _CURRENCY.fullmatch(_trim(currency).upper()):
        raise MandateMessageError("constraints.currency", "must be a 3-letter currency code.")
    currency = _trim(currency).upper()
    if currency not in SUPPORTED_CURRENCIES:
        raise MandateMessageError("constraints.currency", f"v1 supports only {', '.join(SUPPORTED_CURRENCIES)}.")
    if not isinstance(value["off_session_consent"], bool):
        raise MandateMessageError("constraints.off_session_consent", "must be true or false.")

    return {
        "currency": currency,
        "max_amount_per_purchase_cents": _positive_cents(value["max_amount_per_purchase"], "constraints.max_amount_per_purchase"),
        "allowed_categories": _label_list(value["allowed_categories"], "constraints.allowed_categories"),
        "allowed_merchants": _label_list(value["allowed_merchants"], "constraints.allowed_merchants"),
        "max_uses": _safe_int(value["max_uses"], "constraints.max_uses", 1),
        "conditions": _conditions(value.get("conditions")),
        "off_session_consent": value["off_session_consent"],
    }


def _search_fields(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise MandateMessageError("search_fields", "must be an object.")
    fields: Dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not _SEARCH_KEY.fullmatch(key):
            raise MandateMessageError("search_fields", f"invalid key {key!r} (expected [a-z][a-z0-9_]*).")
        if isinstance(item, str):
            if not _trim(item):
                raise MandateMessageError(f"search_fields.{key}", "must not be empty.")
            fields[key] = _trim(item)
        elif isinstance(item, int) and not isinstance(item, bool) and abs(item) <= MAX_SAFE_INTEGER:
            fields[key] = item
        else:
            raise MandateMessageError(f"search_fields.{key}", "must be a text or a safe integer (no decimals).")
    return fields


def _timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise MandateMessageError(field, 'must be ISO 8601 UTC with seconds and Z, e.g. "2026-12-01T00:00:00Z".')
    year = int(value[:4])
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise MandateMessageError(field, "is not a real date and time.") from None
    if not 2000 <= year <= 9999:
        raise MandateMessageError(field, "year must be between 2000 and 9999.")
    return value


# ── API ─────────────────────────────────────────────────────────────────────

def mandate_signing_payload(
    *,
    mandate_id: Any,
    owner_email: Any,
    key_id: Any,
    public_key: Any,
    agent_id: Any,
    constraints: Any,
    search_fields: Optional[Mapping[str, Any]] = None,
    expires_at: Any,
    created_at: Any,
    nonce: Any,
) -> Dict[str, Any]:
    """Los campos EXACTOS que firma el humano, ya normalizados (antes de canonicalizar)."""
    created = _timestamp(created_at, "created_at")
    expires = _timestamp(expires_at, "expires_at")
    if expires <= created:  # mismo formato fijo: el orden de texto es el orden temporal
        raise MandateMessageError("expires_at", "must be after created_at.")
    return {
        "purpose": MANDATE_PURPOSE,
        "mandate_id": _identifier(mandate_id, "mandate_id"),
        "owner": _owner(owner_email),
        "key_id": _identifier(key_id, "key_id"),
        "public_key": _hex(public_key, _PUBLIC_KEY, "public_key", "an Ed25519 public key (64 hex)"),
        "agent_id": _identifier(agent_id, "agent_id"),
        "constraints": _constraints(constraints),
        "search_fields": _search_fields(search_fields),
        "expires_at": expires,
        "created_at": created,
        "nonce": _hex(nonce, _NONCE, "nonce", "32 hex characters"),
    }


def mandate_signing_message(**fields: Any) -> bytes:
    """Bytes que firma el humano con Ed25519: canonicalize(mandate_signing_payload(...))."""
    return canonicalize(mandate_signing_payload(**fields))
