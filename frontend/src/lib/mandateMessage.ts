/**
 * Mensaje que firma el HUMANO al crear un mandato: especificación v1 (paso 3.2).
 *
 * Gemelo de mandate/mandate_message.py: ambos producen los MISMOS bytes con la
 * canonicalización del 2.0 (lib/canonical.ts). La lista de campos firmados, los
 * que quedan fuera a propósito (payment_token, PII de contacto) y las reglas de
 * montos están documentados en el docstring del módulo Python; aquí se repiten
 * solo las reglas que afectan a cómo se escribe el código.
 *
 * shared/mandate_signing_vectors.json fija mensaje y firma exactos; este archivo y
 * el de Python se prueban contra ese MISMO archivo.
 *
 * Todavía NO está conectado: el wizard lo usará en el paso 3.4.
 *
 * Reglas de simetría con Python:
 * - El orden de validación es el mismo, así el `field` del error coincide.
 * - El trim usa un conjunto EXPLÍCITO de code points (el de String.prototype.trim),
 *   compartido con Python, no `.trim()`: así ambos recortan exactamente lo mismo.
 * - Montos: un número vale su texto decimal mínimo (String(n), igual que repr() en
 *   Python) y se escala a centavos con BigInt, sin aritmética de flotantes. Un texto
 *   sigue la gramática estricta "(0|[1-9][0-9]*)(.[0-9]{1,2})?".
 */
import { canonicalBytes } from "./canonical";

export const MANDATE_PURPOSE = "agentbuyer:mandate:v1";
export const SUPPORTED_CURRENCIES: readonly string[] = ["USD"];

const MAX_SAFE_CENTS = BigInt(Number.MAX_SAFE_INTEGER);

function range(from: number, toExclusive: number): number[] {
  return Array.from({ length: toExclusive - from }, (_, index) => from + index);
}

/** Espacios de String.prototype.trim. MISMO conjunto que TRIM_CODE_POINTS en Python. */
export const TRIM_CODE_POINTS: readonly number[] = [
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, ...range(0x2000, 0x200b),
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff,
];
/** Prohibido dentro de un email: esos espacios y todos los controles (C0, DEL, C1). */
const EMAIL_FORBIDDEN_CODE_POINTS: readonly number[] = [...TRIM_CODE_POINTS, ...range(0x00, 0x20), ...range(0x7f, 0xa0)];

function charClass(codePoints: readonly number[]): string {
  // Ninguno de estos code points es especial dentro de una clase de RegExp.
  return `[${[...new Set(codePoints)].sort((a, b) => a - b).map((point) => String.fromCodePoint(point)).join("")}]`;
}

const TRIM_CLASS = charClass(TRIM_CODE_POINTS);
const TRIM = new RegExp(`^${TRIM_CLASS}+|${TRIM_CLASS}+$`, "g");
const EMAIL_FORBIDDEN = new RegExp(charClass(EMAIL_FORBIDDEN_CODE_POINTS));
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const PUBLIC_KEY = /^[0-9a-f]{64}$/;
const NONCE = /^[0-9a-f]{32}$/;
const CURRENCY = /^[A-Z]{3}$/;
const SEARCH_KEY = /^[a-z][a-z0-9_]{0,63}$/;
const AMOUNT_TEXT = /^(0|[1-9][0-9]*)(\.[0-9]{1,2})?$/;
const TIMESTAMP = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/;
// Lo que produce String(n) para un número finito.
const NUMBER_TEXT = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:e([+-][0-9]+))?$/;

const CONSTRAINT_KEYS = [
  "currency", "max_amount_per_purchase", "allowed_categories", "allowed_merchants",
  "max_uses", "conditions", "off_session_consent",
] as const;
const REQUIRED_CONSTRAINT_KEYS = CONSTRAINT_KEYS.filter((key) => key !== "conditions");
const INPUT_KEYS = [
  "mandate_id", "owner_email", "key_id", "public_key", "agent_id",
  "constraints", "search_fields", "expires_at", "created_at", "nonce",
] as const;

// ── Tipos ───────────────────────────────────────────────────────────────────

/** Un monto: número (su valor decimal exacto) o texto decimal estricto. */
export type AmountInput = number | string;

export type MandateConstraintsInput = {
  currency: string;
  max_amount_per_purchase: AmountInput;
  allowed_categories: string[];
  allowed_merchants: string[];
  max_uses: number;
  conditions?: { type: "price_below"; value: AmountInput }[] | null;
  off_session_consent: boolean;
};

/** Entrada en snake_case: la misma forma que los vectores compartidos y que Python. */
export type MandateMessageInput = {
  mandate_id: string;
  owner_email: string;
  key_id: string;
  public_key: string;
  agent_id: string;
  constraints: MandateConstraintsInput;
  search_fields?: Record<string, string | number> | null;
  expires_at: string;
  created_at: string;
  nonce: string;
};

export type SignedMandateConstraints = {
  currency: string;
  max_amount_per_purchase_cents: number;
  allowed_categories: string[];
  allowed_merchants: string[];
  max_uses: number;
  conditions: { type: "price_below"; value_cents: number }[];
  off_session_consent: boolean;
};

export type MandateSigningPayload = {
  purpose: typeof MANDATE_PURPOSE;
  mandate_id: string;
  owner: string;
  key_id: string;
  public_key: string;
  agent_id: string;
  constraints: SignedMandateConstraints;
  search_fields: Record<string, string | number>;
  expires_at: string;
  created_at: string;
  nonce: string;
};

/** El dato no cumple la especificación del mandato firmado v1. */
export class MandateMessageError extends Error {
  readonly field: string;

  constructor(field: string, message: string) {
    super(`${field}: ${message}`);
    this.name = "MandateMessageError";
    this.field = field;
  }
}

// ── Normalizaciones ─────────────────────────────────────────────────────────

function trim(text: string): string {
  return text.replace(TRIM, "");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function identifier(value: unknown, field: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new MandateMessageError(field, "must be an identifier ([A-Za-z0-9_.:-], 1-128 chars, no spaces).");
  }
  return value;
}

function owner(value: unknown): string {
  if (typeof value !== "string") throw new MandateMessageError("owner", "must be the session email.");
  const normalized = trim(value).toLowerCase();
  const at = normalized.indexOf("@");
  const local = at < 0 ? "" : normalized.slice(0, at);
  const domain = at < 0 ? "" : normalized.slice(at + 1);
  if (!local || !domain || domain.includes("@") || EMAIL_FORBIDDEN.test(normalized)) {
    throw new MandateMessageError("owner", "must be a single email address without spaces.");
  }
  return normalized;
}

function hex(value: unknown, pattern: RegExp, field: string, description: string): string {
  if (typeof value !== "string" || !pattern.test(value.toLowerCase())) {
    throw new MandateMessageError(field, `must be ${description}.`);
  }
  return value.toLowerCase();
}

/** Centavos enteros de un monto, sin pasar nunca por aritmética de flotantes. */
export function toCents(value: unknown, field: string): number {
  let negative = false;
  let digits: string;
  let exponent: number; // valor = digits × 10^exponent

  if (typeof value === "string") {
    const match = AMOUNT_TEXT.exec(value);
    if (!match) throw new MandateMessageError(field, "must be a decimal amount with at most 2 decimals (e.g. 150 or 150.10).");
    const fraction = match[2] ? match[2].slice(1) : "";
    digits = match[1] + fraction;
    exponent = -fraction.length;
  } else if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new MandateMessageError(field, "must be a finite amount.");
    // String(n): el texto decimal mínimo que reconstruye el número (como repr() en Python).
    const match = NUMBER_TEXT.exec(String(value));
    if (!match) throw new MandateMessageError(field, "must be a finite amount.");
    negative = match[1] === "-";
    const fraction = match[3] ?? "";
    digits = match[2] + fraction;
    exponent = Number(match[4] ?? "0") - fraction.length;
  } else {
    throw new MandateMessageError(field, typeof value === "boolean" ? "must be an amount, not a boolean." : "must be a number or a decimal string.");
  }

  const magnitude = BigInt(digits);
  if (negative && magnitude !== 0n) throw new MandateMessageError(field, "must not be negative.");
  if (magnitude === 0n) return 0;
  const significant = magnitude.toString().length;
  const scale = exponent + 2; // centavos = digits × 10^scale
  let cents: bigint;
  if (scale >= 0) {
    if (significant + scale > MAX_SAFE_CENTS.toString().length) throw new MandateMessageError(field, "is out of the safe range.");
    cents = magnitude * 10n ** BigInt(scale);
  } else {
    if (significant <= -scale) throw new MandateMessageError(field, "must have at most 2 decimals.");
    const divisor = 10n ** BigInt(-scale);
    if (magnitude % divisor !== 0n) throw new MandateMessageError(field, "must have at most 2 decimals.");
    cents = magnitude / divisor;
  }
  if (cents > MAX_SAFE_CENTS) throw new MandateMessageError(field, "is out of the safe range.");
  return Number(cents);
}

function positiveCents(value: unknown, field: string): number {
  const cents = toCents(value, field);
  if (cents <= 0) throw new MandateMessageError(field, "must be greater than zero.");
  return cents;
}

function safeInt(value: unknown, field: string, minimum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    throw new MandateMessageError(field, `must be an integer ≥ ${minimum}.`);
  }
  return value;
}

/** trim + minúsculas, sin duplicados, ordenada (sort() por defecto = unidades UTF-16). */
function labelList(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length === 0) throw new MandateMessageError(field, "must be a non-empty list.");
  const labels = new Set<string>();
  for (const item of value) {
    if (typeof item !== "string" || !trim(item)) throw new MandateMessageError(field, "must contain non-empty texts.");
    labels.add(trim(item).toLowerCase());
  }
  return [...labels].sort();
}

function conditions(value: unknown): SignedMandateConstraints["conditions"] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new MandateMessageError("constraints.conditions", "must be a list.");
  const byType = new Map<string, { type: "price_below"; value_cents: number }>();
  for (const condition of value) {
    if (!isPlainObject(condition) || condition.type !== "price_below" || Object.keys(condition).sort().join(",") !== "type,value") {
      throw new MandateMessageError("constraints.conditions", 'v1 only supports {"type": "price_below", "value": amount}.');
    }
    if (byType.has(condition.type)) throw new MandateMessageError("constraints.conditions", "each condition type may appear only once.");
    byType.set(condition.type, {
      type: condition.type,
      value_cents: positiveCents(condition.value, "constraints.conditions.price_below"),
    });
  }
  return [...byType.keys()].sort().map((type) => byType.get(type)!);
}

function constraints(value: unknown): SignedMandateConstraints {
  if (!isPlainObject(value)) throw new MandateMessageError("constraints", "must be an object.");
  const unknown = Object.keys(value).filter((key) => !(CONSTRAINT_KEYS as readonly string[]).includes(key)).sort();
  if (unknown.length) throw new MandateMessageError("constraints", `unknown field(s) not covered by the signature: ${unknown.join(", ")}.`);
  const missing = REQUIRED_CONSTRAINT_KEYS.filter((key) => !(key in value)).sort();
  if (missing.length) throw new MandateMessageError("constraints", `missing field(s): ${missing.join(", ")}.`);

  const rawCurrency = value.currency;
  if (typeof rawCurrency !== "string" || !CURRENCY.test(trim(rawCurrency).toUpperCase())) {
    throw new MandateMessageError("constraints.currency", "must be a 3-letter currency code.");
  }
  const currency = trim(rawCurrency).toUpperCase();
  if (!SUPPORTED_CURRENCIES.includes(currency)) {
    throw new MandateMessageError("constraints.currency", `v1 supports only ${SUPPORTED_CURRENCIES.join(", ")}.`);
  }
  if (typeof value.off_session_consent !== "boolean") {
    throw new MandateMessageError("constraints.off_session_consent", "must be true or false.");
  }

  return {
    currency,
    max_amount_per_purchase_cents: positiveCents(value.max_amount_per_purchase, "constraints.max_amount_per_purchase"),
    allowed_categories: labelList(value.allowed_categories, "constraints.allowed_categories"),
    allowed_merchants: labelList(value.allowed_merchants, "constraints.allowed_merchants"),
    max_uses: safeInt(value.max_uses, "constraints.max_uses", 1),
    conditions: conditions(value.conditions),
    off_session_consent: value.off_session_consent,
  };
}

function searchFields(value: unknown): Record<string, string | number> {
  if (value === undefined || value === null) return {};
  if (!isPlainObject(value)) throw new MandateMessageError("search_fields", "must be an object.");
  const fields: Record<string, string | number> = {};
  for (const [key, item] of Object.entries(value)) {
    if (!SEARCH_KEY.test(key)) throw new MandateMessageError("search_fields", `invalid key '${key}' (expected [a-z][a-z0-9_]*).`);
    if (typeof item === "string") {
      if (!trim(item)) throw new MandateMessageError(`search_fields.${key}`, "must not be empty.");
      fields[key] = trim(item);
    } else if (typeof item === "number" && Number.isSafeInteger(item)) {
      fields[key] = item;
    } else {
      throw new MandateMessageError(`search_fields.${key}`, "must be a text or a safe integer (no decimals).");
    }
  }
  return fields;
}

function daysInMonth(year: number, month: number): number {
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  return [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
}

function timestamp(value: unknown, field: string): string {
  const match = typeof value === "string" ? TIMESTAMP.exec(value) : null;
  if (!match) throw new MandateMessageError(field, 'must be ISO 8601 UTC with seconds and Z, e.g. "2026-12-01T00:00:00Z".');
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59) {
    throw new MandateMessageError(field, "is not a real date and time.");
  }
  if (year < 2000 || year > 9999) throw new MandateMessageError(field, "year must be between 2000 and 9999.");
  return value as string;
}

// ── API ─────────────────────────────────────────────────────────────────────

/** Los campos EXACTOS que firma el humano, ya normalizados (antes de canonicalizar). */
export function mandateSigningPayload(input: MandateMessageInput): MandateSigningPayload {
  if (!isPlainObject(input)) throw new MandateMessageError("input", "must be an object.");
  const unexpected = Object.keys(input).filter((key) => !(INPUT_KEYS as readonly string[]).includes(key));
  if (unexpected.length) throw new MandateMessageError("input", `unknown field(s): ${unexpected.sort().join(", ")}.`);

  const createdAt = timestamp(input.created_at, "created_at");
  const expiresAt = timestamp(input.expires_at, "expires_at");
  // Mismo formato fijo: el orden de texto es el orden temporal.
  if (expiresAt <= createdAt) throw new MandateMessageError("expires_at", "must be after created_at.");
  return {
    purpose: MANDATE_PURPOSE,
    mandate_id: identifier(input.mandate_id, "mandate_id"),
    owner: owner(input.owner_email),
    key_id: identifier(input.key_id, "key_id"),
    public_key: hex(input.public_key, PUBLIC_KEY, "public_key", "an Ed25519 public key (64 hex)"),
    agent_id: identifier(input.agent_id, "agent_id"),
    constraints: constraints(input.constraints),
    search_fields: searchFields(input.search_fields),
    expires_at: expiresAt,
    created_at: createdAt,
    nonce: hex(input.nonce, NONCE, "nonce", "32 hex characters"),
  };
}

/** Bytes que firma el humano con Ed25519: canonicalBytes(mandateSigningPayload(...)). */
export function mandateSigningMessage(input: MandateMessageInput): Uint8Array<ArrayBuffer> {
  return canonicalBytes(mandateSigningPayload(input));
}

/** Nonce del mandato: 16 bytes aleatorios de WebCrypto en hex (32 caracteres). */
export function newMandateNonce(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Fecha en el formato firmado: ISO 8601 UTC con Z y precisión de segundos (trunca los ms). */
export function toSignedTimestamp(date: Date): string {
  if (Number.isNaN(date.getTime())) throw new MandateMessageError("timestamp", "is not a valid date.");
  return timestamp(date.toISOString().replace(/\.[0-9]{3}Z$/, "Z"), "timestamp");
}
