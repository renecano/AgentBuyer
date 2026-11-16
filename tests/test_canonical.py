"""Canonicalización compartida JS/Python (mandate/canonical.py).

Lee los MISMOS archivos que frontend/src/lib/canonical.test.ts:
- shared/canonical_vectors.json: vectores escritos a mano (bytes exactos esperados).
- shared/canonical_vectors_fuzz.json: corpus aleatorio; aquí se exige que el archivo
  sea exactamente lo que produce hoy la implementación Python (y TS debe coincidir).
Si alguien cambia la canonicalización de un lado, el test de ESE lado falla.
"""
import json
import math
import pathlib
from decimal import Decimal

import pytest

from mandate.canonical import MAX_SAFE_INTEGER, CanonicalizationError, canonicalize, canonicalize_text
from tests import canonical_fuzz

SHARED = pathlib.Path(__file__).resolve().parent.parent / "shared"
VECTORS = json.loads((SHARED / "canonical_vectors.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=[v["name"] for v in VECTORS["vectors"]])
def test_shared_vector_produces_the_exact_expected_bytes(vector):
    value = json.loads(vector["input_json"])  # el mismo camino que un payload recibido

    assert canonicalize_text(value) == vector["canonical"]
    assert canonicalize(value).hex() == vector["canonical_utf8_hex"]


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=[v["name"] for v in VECTORS["vectors"]])
def test_vector_file_is_self_consistent(vector):
    """El hex es la verdad byte a byte: protege contra un editor que normalice el
    texto del archivo (p. ej. NFD → NFC) sin que nadie lo note."""
    assert vector["canonical"].encode("utf-8").hex() == vector["canonical_utf8_hex"]


@pytest.mark.parametrize("vector", VECTORS["invalid"], ids=[v["name"] for v in VECTORS["invalid"]])
def test_shared_invalid_vector_is_rejected(vector):
    with pytest.raises(CanonicalizationError):
        canonicalize(json.loads(vector["input_json"]))


def test_fuzz_corpus_matches_the_current_python_implementation():
    """El archivo es exactamente lo que genera hoy mandate/canonical.py con la semilla
    fija. Si cambia la canonicalización Python, esto falla; si se regenera el
    archivo para "arreglarlo", falla el test de TS. Regenerar: python -m tests.canonical_fuzz"""
    on_disk = canonical_fuzz.PATH.read_text(encoding="utf-8")
    assert on_disk == canonical_fuzz.render(canonical_fuzz.generate())


# ── Casos que solo existen en Python (no representables como texto JSON) ────

@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf], ids=["nan", "inf", "-inf"])
def test_non_finite_floats_are_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonicalize({"amount": value})


@pytest.mark.parametrize(
    "value",
    [(1, 2), {1, 2}, Decimal("1.5"), b"bytes", object()],
    ids=["tuple", "set", "decimal", "bytes", "object"],
)
def test_non_json_types_are_rejected_not_coerced(value):
    """json.dumps convertiría la tupla en lista en silencio; aquí es un error."""
    with pytest.raises(CanonicalizationError):
        canonicalize([value])


def test_non_string_keys_are_rejected_not_coerced():
    """json.dumps convertiría la clave 1 en "1" en silencio; aquí es un error."""
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "x"})


def test_booleans_are_not_numbers():
    assert canonicalize_text([True, False, 1, 0]) == "[true,false,1,0]"


def test_safe_integer_boundaries():
    assert canonicalize_text([MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER]) == "[9007199254740991,-9007199254740991]"
    for unsafe in (MAX_SAFE_INTEGER + 1, -(MAX_SAFE_INTEGER + 1), float(2**60)):
        with pytest.raises(CanonicalizationError):
            canonicalize(unsafe)


def test_differs_from_the_legacy_signature_canonical_json_on_purpose():
    """Documenta por qué hace falta: mandate/sign.canonical_json (aún en uso por las
    firmas del servidor y el ledger) escapa no-ASCII y escribe 150.0 como "150.0";
    JS no. El paso 3 conecta ESTE módulo a la firma de mandatos."""
    from mandate.sign import canonical_json as legacy

    payload = {"amount": 150.0, "city": "Córdoba"}
    assert legacy(payload) == b'{"amount":150.0,"city":"C\\u00f3rdoba"}'
    assert canonicalize(payload) == '{"amount":150,"city":"Córdoba"}'.encode("utf-8")
