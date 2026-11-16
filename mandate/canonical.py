"""Canonicalización JSON compartida con el frontend (frontend/src/lib/canonical.ts).

Firmar en el navegador y verificar en el servidor exige que AMBOS lados produzcan
exactamente los mismos bytes para el mismo valor JSON. Esta es la definición de
esos bytes; los vectores en shared/canonical_vectors*.json la fijan y los dos
lados los verifican (tests/test_canonical.py y src/lib/canonical.test.ts).

Base: RFC 8785 (JSON Canonicalization Scheme, "JCS"). Reglas:

1. Claves de objeto ordenadas por unidades de código UTF-16 (como JCS y como el
   `sort()` por defecto de JS). OJO: NO es el orden de `sort_keys` de Python (que
   ordena por punto de código): difieren con caracteres fuera del BMP (emoji).
2. Sin espacios: separadores "," y ":".
3. Texto en UTF-8 crudo, SIN escapar lo no-ASCII ("Córdoba" viaja como "Córdoba").
   Solo se escapan `"`, `\\` y los controles U+0000..U+001F (\\b \\f \\n \\r \\t
   cortos; el resto como \\u00xx en minúscula). Es exactamente JSON.stringify.
   No se normaliza Unicode (NFC/NFD): se firman los puntos de código tal cual.
4. Números con el formato de ECMAScript Number→String (el de JSON.stringify, que
   es el que exige JCS): 150.0 → "150", -0 → "0", 0.1 → "0.1", 1e-7 → "1e-7".
   Desviación deliberada de JCS: solo se aceptan números finitos con valor
   absoluto ≤ 2^53−1 (Number.MAX_SAFE_INTEGER). Más allá, JS pierde precisión al
   PARSEAR (9007199254740993 llega como ...992), así que ningún formato puede
   garantizar bytes iguales: se rechaza en ambos lados en vez de firmar algo
   distinto de lo que el humano vio.
5. Fail-closed: lo que no tiene representación canónica idéntica en ambos lados
   (NaN/Infinity, enteros fuera de rango, surrogates UTF-16 huérfanos, claves no
   texto, tipos no-JSON) lanza CanonicalizationError. Nunca se "arregla" en silencio.

Todavía NO está conectado a ninguna firma: mandate/sign.py y audit/log.py siguen
usando su canonical_json. El paso 3 conectará ESTE módulo a la firma de mandatos
(no al hash del ledger, que admite valores que aquí se rechazan).
"""
import math
from decimal import Decimal
from typing import Any, List

MAX_SAFE_INTEGER = 2**53 - 1

_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class CanonicalizationError(ValueError):
    """El valor no tiene una forma canónica idéntica en JS y Python."""


def canonicalize(value: Any) -> bytes:
    """Bytes UTF-8 canónicos de `value` (lo que se firma)."""
    return canonicalize_text(value).encode("utf-8")


def canonicalize_text(value: Any) -> str:
    """Texto canónico de `value` (mismo contenido que canonicalize, sin codificar)."""
    out: List[str] = []
    _write(value, out)
    return "".join(out)


def _write(value: Any, out: List[str]) -> None:
    # bool antes que int: en Python, True es un int.
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"Entero fuera del rango seguro (±2^53−1): {value}.")
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_number(value))
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, list):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _write(item, out)
        out.append("]")
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(f"Las claves deben ser texto, no {type(key).__name__}.")
        out.append("{")
        for index, key in enumerate(sorted(value, key=_utf16_sort_key)):
            if index:
                out.append(",")
            out.append(_string(key))
            out.append(":")
            _write(value[key], out)
        out.append("}")
    else:
        raise CanonicalizationError(f"Tipo no JSON: {type(value).__name__}.")


def _utf16_sort_key(key: str) -> bytes:
    # UTF-16 big-endian compara byte a byte igual que por unidades de código UTF-16.
    _ensure_well_formed(key)
    return key.encode("utf-16-be")


def _ensure_well_formed(text: str) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise CanonicalizationError("Texto con un surrogate UTF-16 huérfano: no es Unicode válido.") from None


def _string(text: str) -> str:
    _ensure_well_formed(text)
    parts = ['"']
    for char in text:
        escaped = _SHORT_ESCAPES.get(char)
        if escaped is not None:
            parts.append(escaped)
        elif ord(char) < 0x20:
            parts.append(f"\\u{ord(char):04x}")
        else:
            parts.append(char)
    parts.append('"')
    return "".join(parts)


def _number(value: float) -> str:
    """ECMAScript Number::toString para floats (el formato de JSON.stringify)."""
    if not math.isfinite(value):
        raise CanonicalizationError(f"Número no finito: {value!r}.")
    if abs(value) > MAX_SAFE_INTEGER:
        raise CanonicalizationError(f"Número fuera del rango seguro (±2^53−1): {value!r}.")
    if value == 0:
        return "0"  # incluye -0.0
    if value.is_integer():
        return str(int(value))

    # repr() da los dígitos MÍNIMOS que reconstruyen el float (igual criterio que JS);
    # solo cambia el formato, que se rearma según las reglas de ECMAScript.
    sign, digit_tuple, exponent = Decimal(repr(value)).as_tuple()
    digits = "".join(map(str, digit_tuple)).rstrip("0")
    exponent += len("".join(map(str, digit_tuple))) - len(digits)
    k = len(digits)
    n = exponent + k  # valor = 0.d1d2…dk × 10^n
    prefix = "-" if sign else ""

    if k <= n <= 21:
        return prefix + digits + "0" * (n - k)
    if 0 < n <= 21:
        return prefix + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return prefix + "0." + "0" * (-n) + digits
    e = n - 1
    mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{prefix}{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
