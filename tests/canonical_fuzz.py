"""Genera shared/canonical_vectors_fuzz.json: casos aleatorios (semilla fija) para
comparar la canonicalización Python con la de TypeScript byte a byte.

Los vectores escritos a mano (shared/canonical_vectors.json) anclan la implementación
a las reglas; este corpus cubre combinaciones que nadie escribiría a mano (acentos,
emoji, controles, claves raras, floats de todo tipo, anidamiento). El esperado lo
produce mandate/canonical.py y el test de Vitest exige que TS dé los mismos bytes.

- El input_json se escribe con json.dumps en formatos variados (ensure_ascii sí/no,
  con o sin espacios, 150.0 como float…), y el esperado se calcula sobre el JSON
  RE-PARSEADO: exactamente el camino real (el payload viaja como JSON).
- tests/test_canonical.py regenera el corpus en memoria y lo compara con el archivo:
  un cambio en la canonicalización Python rompe ese test, y regenerar el archivo
  para "arreglarlo" rompe el de TS. Para regenerar a propósito:

      python -m tests.canonical_fuzz
"""
import json
import pathlib
import random

from mandate.canonical import MAX_SAFE_INTEGER, canonicalize

SEED = 20260918
CASES = 250
PATH = pathlib.Path(__file__).resolve().parent.parent / "shared" / "canonical_vectors_fuzz.json"

_ALPHABET = (
    "abcxyzABC019 _-./"          # ASCII común (incluye '/', que no se escapa)
    "áéíóúñÑüÜçÇ€"              # acentos y símbolos del BMP
    "日本"                       # CJK
    "😀🚀"                      # fuera del BMP (pares de surrogates en UTF-16)
    "ﬁ"                         # U+FB01: ordena distinto por código vs UTF-16
    "́ "               # acento combinante, separador de línea
    "\"\\\n\t\r\b\f\x00\x1f\x7f"  # lo que sí se escapa (y DEL, que no)
)


# Solo se usa rng.random(): es lo ÚNICO de `random` cuya secuencia Python garantiza
# igual entre versiones para la misma semilla (randint/choice/uniform pueden cambiar
# de algoritmo). Así el corpus es idéntico en el CI (3.13) y en local (3.14).
def _below(rng: random.Random, n: int) -> int:
    return int(rng.random() * n)


def _between(rng: random.Random, low: int, high: int) -> int:
    return low + _below(rng, high - low + 1)


def _uniform(rng: random.Random, low: float, high: float) -> float:
    return low + (high - low) * rng.random()


def _pick(rng: random.Random, options):
    return options[_below(rng, len(options))]


def _text(rng: random.Random, max_len: int = 8) -> str:
    return "".join(_pick(rng, _ALPHABET) for _ in range(_between(rng, 0, max_len)))


def _number(rng: random.Random):
    kind = _below(rng, 8)
    if kind == 0:
        return _between(rng, -1000, 1000)
    if kind == 1:
        return _between(rng, -MAX_SAFE_INTEGER, MAX_SAFE_INTEGER)
    if kind == 2:
        return float(_between(rng, -10**6, 10**6))           # entero como float: 150.0
    if kind == 3:
        return round(_uniform(rng, 0, 10_000), 2)            # montos: 149.99
    if kind == 4:
        return _uniform(rng, -1e15, 1e15)                    # 17 dígitos significativos
    if kind == 5:
        return _uniform(rng, -1e-5, 1e-5)                    # pequeños: notación exponencial
    if kind == 6:
        return _pick(rng, [0.0, -0.0, 0.1, 0.5, 1e-7, 5e-324, 2.5e-10])
    return _uniform(rng, -1, 1) * 10 ** _between(rng, -8, 12)


def _value(rng: random.Random, depth: int = 0):
    roll = _below(rng, 10 if depth < 3 else 6)
    if roll == 0:
        return None
    if roll == 1:
        return rng.random() < 0.5
    if roll in (2, 3):
        return _number(rng)
    if roll in (4, 5):
        return _text(rng)
    if roll in (6, 7):
        return [_value(rng, depth + 1) for _ in range(_between(rng, 0, 4))]
    return {_text(rng, 6): _value(rng, depth + 1) for _ in range(_between(rng, 0, 5))}


def generate() -> dict:
    rng = random.Random(SEED)
    cases = []
    for _ in range(CASES):
        value = {_text(rng, 6): _value(rng, 1) for _ in range(_between(rng, 1, 6))}
        source = json.dumps(
            value,
            ensure_ascii=rng.random() < 0.5,
            separators=_pick(rng, [(",", ":"), (", ", ": ")]),
        )
        cases.append({
            "input_json": source,
            "canonical_utf8_hex": canonicalize(json.loads(source)).hex(),
        })
    return {
        "description": "Corpus aleatorio (semilla fija) generado por tests/canonical_fuzz.py. NO editar a mano.",
        "seed": SEED,
        "cases": cases,
    }


def render(document: dict) -> str:
    return json.dumps(document, ensure_ascii=True, indent=1) + "\n"


if __name__ == "__main__":
    PATH.write_text(render(generate()), encoding="utf-8", newline="\n")
    print(f"Escrito {PATH} ({CASES} casos, semilla {SEED}).")
