/**
 * Canonicalización JSON compartida con el backend (mandate/canonical.py).
 *
 * Firmar aquí y verificar en el servidor exige que ambos lados produzcan los
 * MISMOS bytes. Las reglas (RFC 8785 / JCS, con una desviación documentada) están
 * en mandate/canonical.py; los vectores de shared/canonical_vectors*.json las fijan
 * y los dos lados los verifican (canonical.test.ts y tests/test_canonical.py).
 *
 * Resumen:
 * - Claves ordenadas por unidades de código UTF-16 (el `sort()` por defecto de JS).
 * - Sin espacios. Texto en UTF-8 crudo: solo se escapan `"`, `\` y U+0000..U+001F.
 * - Números: el formato de JSON.stringify (ECMAScript Number→String).
 * - Fail-closed: NaN/Infinity, |n| > 2^53−1, surrogates huérfanos, `undefined`,
 *   BigInt, funciones y objetos no planos (Date, Map…) lanzan CanonicalizationError.
 */

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

// Un surrogate alto sin bajo detrás, o uno bajo sin alto delante.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function writeString(text: string): string {
  if (LONE_SURROGATE.test(text)) {
    throw new CanonicalizationError("Texto con un surrogate UTF-16 huérfano: no es Unicode válido.");
  }
  // JSON.stringify escapa exactamente `"`, `\` y los controles (\b \f \n \r \t, resto \u00xx).
  return JSON.stringify(text);
}

function writeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new CanonicalizationError(`Número no finito: ${value}.`);
  }
  if (Math.abs(value) > Number.MAX_SAFE_INTEGER) {
    throw new CanonicalizationError(`Número fuera del rango seguro (±2^53−1): ${value}.`);
  }
  return JSON.stringify(value); // -0 → "0", 150.0 → "150", 1e-7 → "1e-7"
}

function isPlainObject(value: object): value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function write(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return writeNumber(value);
    case "string":
      return writeString(value);
    case "object":
      break;
    default:
      throw new CanonicalizationError(`Tipo no JSON: ${typeof value}.`);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => write(item)).join(",")}]`;
  }
  if (!isPlainObject(value)) {
    throw new CanonicalizationError(`Objeto no plano (${Object.prototype.toString.call(value)}): no es JSON.`);
  }
  // sort() sin comparador ordena por unidades de código UTF-16: la regla de JCS.
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${writeString(key)}:${write(value[key])}`).join(",")}}`;
}

/** Texto canónico de `value`. */
export function canonicalize(value: unknown): string {
  return write(value);
}

/** Bytes UTF-8 canónicos de `value`: lo que se firma. */
export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
