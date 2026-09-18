/**
 * Canonicalización compartida con el backend: lee los MISMOS archivos de vectores
 * que tests/test_canonical.py. Si alguien cambia la canonicalización de un lado,
 * el test de ese lado falla contra los bytes fijados en shared/.
 */
import { describe, expect, it } from "vitest";
import shared from "../../../shared/canonical_vectors.json";
import fuzz from "../../../shared/canonical_vectors_fuzz.json";
import { CanonicalizationError, canonicalBytes, canonicalize } from "./canonical";

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

describe("vectores escritos a mano (shared/canonical_vectors.json)", () => {
  it.each(shared.vectors.map((vector) => [vector.name, vector] as const))(
    "%s: bytes exactos",
    (_name, vector) => {
      const value: unknown = JSON.parse(vector.input_json); // el mismo camino que un payload
      expect(canonicalize(value)).toBe(vector.canonical);
      expect(toHex(canonicalBytes(value))).toBe(vector.canonical_utf8_hex);
    },
  );

  it.each(shared.invalid.map((vector) => [vector.name, vector] as const))(
    "%s: se rechaza (fail-closed)",
    (_name, vector) => {
      expect(() => canonicalize(JSON.parse(vector.input_json))).toThrow(CanonicalizationError);
    },
  );
});

describe("corpus aleatorio generado por Python (shared/canonical_vectors_fuzz.json)", () => {
  it("TS produce EXACTAMENTE los mismos bytes que Python en todos los casos", () => {
    expect(fuzz.cases.length).toBeGreaterThanOrEqual(200);
    const mismatches = fuzz.cases
      .map((testCase, index) => ({ index, input: testCase.input_json, expected: testCase.canonical_utf8_hex,
        got: toHex(canonicalBytes(JSON.parse(testCase.input_json))) }))
      .filter((result) => result.got !== result.expected);
    expect(mismatches).toEqual([]);
  });
});

describe("casos que solo existen en JS", () => {
  it.each([
    ["NaN", NaN],
    ["Infinity", Infinity],
    ["-Infinity", -Infinity],
    ["undefined en objeto", { a: undefined }],
    ["undefined en lista", [undefined]],
    ["BigInt", BigInt(1)],
    ["Date", new Date(0)],
    ["Map", new Map()],
    ["función", () => 1],
    ["Symbol", Symbol("x")],
    ["instancia de clase", new (class Point { x = 1; })()],
  ] as const)("%s se rechaza en vez de coercionarse", (_name, value) => {
    expect(() => canonicalize(value)).toThrow(CanonicalizationError);
  });

  it("-0 se escribe 0 (JSON.stringify ya lo hace; se fija igual)", () => {
    expect(canonicalize([-0, 0])).toBe("[0,0]");
  });

  it("un objeto sin prototipo es un objeto plano válido", () => {
    const bare = Object.assign(Object.create(null) as Record<string, unknown>, { b: 1, a: 2 });
    expect(canonicalize(bare)).toBe('{"a":2,"b":1}');
  });

  it("las claves con forma de entero se ordenan como texto, no en el orden de Object.keys", () => {
    // Object.keys daría ["1","2","10"]; la regla es orden de texto UTF-16.
    expect(canonicalize({ 10: "x", 2: "y", 1: "z" })).toBe('{"1":"z","10":"x","2":"y"}');
  });
});
