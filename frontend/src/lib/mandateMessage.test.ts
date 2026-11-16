/**
 * Mensaje firmado del mandato v1 (paso 3.2) contra shared/mandate_signing_vectors.json:
 * el MISMO archivo que verifica tests/test_mandate_message.py. Si un lado cambia un
 * byte, su test falla contra los bytes fijados.
 *
 * La llave del RFC 8032 se importa solo aquí, como llave de prueba.
 */
import { describe, expect, it } from "vitest";
import registration from "../../../shared/key_registration_vectors.json";
import shared from "../../../shared/mandate_signing_vectors.json";
import { canonicalBytes, canonicalize } from "./canonical";
import { REGISTER_KEY_PURPOSE, registrationPayload } from "./enrollment";
import {
  MANDATE_PURPOSE,
  MandateMessageError,
  TRIM_CODE_POINTS,
  mandateSigningMessage,
  mandateSigningPayload,
  newMandateNonce,
  toCents,
  toSignedTimestamp,
  type MandateMessageInput,
} from "./mandateMessage";
import { signCanonical } from "./signing";

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const fromHex = (hex: string) => new Uint8Array(hex.match(/../g)!.map((pair) => parseInt(pair, 16)));
const clone = <T,>(value: T): T => structuredClone(value);
const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";

async function rfcPrivateKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", fromHex(PKCS8_ED25519_PREFIX + shared.rfc8032_test1.secret_key_hex), { name: "Ed25519" }, false, ["sign"]);
}

async function verifies(message: Uint8Array<ArrayBuffer>, signatureHex: string): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey("raw", fromHex(shared.rfc8032_test1.public_key_hex), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, publicKey, fromHex(signatureHex), message);
}

const BASE_INPUT = shared.vectors[0].inputs as unknown as MandateMessageInput;

it("el purpose es el de la spec y distinto del registro de llave", () => {
  expect(MANDATE_PURPOSE).toBe(shared.purpose);
  expect(MANDATE_PURPOSE).not.toBe(REGISTER_KEY_PURPOSE);
});

describe("vectores: bytes y firma exactos (los mismos que verifica Python)", () => {
  it.each(shared.vectors.map((vector) => [vector.name, vector] as const))("%s", async (_name, vector) => {
    const message = mandateSigningMessage(clone(vector.inputs) as unknown as MandateMessageInput);

    expect(new TextDecoder().decode(message)).toBe(vector.expected_message);
    expect(toHex(message)).toBe(vector.expected_message_utf8_hex);

    const payload = mandateSigningPayload(clone(vector.inputs) as unknown as MandateMessageInput);
    const signature = await signCanonical(await rfcPrivateKey(), payload);
    expect(signature).toBe(vector.expected_signature_hex);
    expect(await verifies(message, signature)).toBe(true);
  });

  it("la entrada no se modifica", () => {
    const input = clone(shared.vectors[3].inputs) as unknown as MandateMessageInput;
    const before = clone(input);
    mandateSigningPayload(input);
    expect(input).toEqual(before);
  });
});

describe("inválidos: fallan en el mismo campo que en Python", () => {
  it.each(shared.invalid.map((entry) => [entry.name, entry] as const))("%s", (_name, entry) => {
    let failure: unknown = null;
    try {
      mandateSigningMessage(clone(entry.inputs) as unknown as MandateMessageInput);
    } catch (caught) {
      failure = caught;
    }
    expect(failure).toBeInstanceOf(MandateMessageError);
    expect((failure as MandateMessageError).field).toBe(entry.error_field);
  });

  it("rechaza campos de entrada que la spec no conoce", () => {
    const input = { ...clone(BASE_INPUT), purpose: REGISTER_KEY_PURPOSE } as unknown as MandateMessageInput;
    expect(() => mandateSigningPayload(input)).toThrow(MandateMessageError);
  });
});

describe("centavos sin flotantes (amount_cases compartidos)", () => {
  it.each(shared.amount_cases.map((entry, index) => [index, JSON.stringify(entry.input), entry] as const))("#%i %s", (_index, _label, entry) => {
    if ("error" in entry && entry.error) expect(() => toCents(entry.input, "amount")).toThrow(MandateMessageError);
    else expect(toCents(entry.input, "amount")).toBe((entry as { cents: number }).cents);
  });

  it("0.1 + 0.2 calculado en JS no son 2 decimales exactos", () => {
    expect(() => toCents(0.1 + 0.2, "amount")).toThrow("at most 2 decimals");
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, -0.01, 2 ** 60, 5e-324])("rechaza %s", (value) => {
    expect(() => toCents(value, "amount")).toThrow(MandateMessageError);
  });
});

// ── Cambiar cualquier campo firmado invalida la firma ───────────────────────

type Payload = Record<string, unknown>;

function setPath(target: Payload, path: string, value: unknown) {
  const parts = path.split(".");
  const leaf = parts.pop()!;
  let node = target;
  for (const part of parts) node = node[part] as Payload;
  node[leaf] = value;
}

function leafPaths(value: Payload, prefix = ""): string[] {
  return Object.entries(value).flatMap(([key, item]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    return path === "constraints" ? leafPaths(item as Payload, path) : [path];
  });
}

const TAMPERS: Record<string, unknown> = {
  purpose: REGISTER_KEY_PURPOSE,
  mandate_id: "mnd_marta_mbx3k3",
  owner: "mallory@example.com",
  key_id: "key_ffeeddccbbaa99887766554433221100",
  public_key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  agent_id: "agt_mallory",
  "constraints.currency": "EUR",
  "constraints.max_amount_per_purchase_cents": 15001,
  "constraints.allowed_categories": ["travel.flights", "travel.hotels"],
  "constraints.allowed_merchants": ["mch_otro"],
  "constraints.max_uses": 4,
  "constraints.conditions": [{ type: "price_below", value_cents: 14001 }],
  "constraints.off_session_consent": false,
  search_fields: { origin: "MEX", destination: "BOG", departure_date: "2026-12-05" },
  expires_at: "2027-11-30T23:59:59Z",
  created_at: "2026-11-16T10:00:01Z",
  nonce: "ffeeddccbbaa99887766554433221100",
};

describe("cambiar cualquier campo firmado invalida la firma", () => {
  it("hay un cambio por cada campo firmado", () => {
    expect(leafPaths(mandateSigningPayload(clone(BASE_INPUT)) as unknown as Payload).sort()).toEqual(Object.keys(TAMPERS).sort());
  });

  it.each(Object.keys(TAMPERS).sort())("%s", async (path) => {
    const payload = mandateSigningPayload(clone(BASE_INPUT)) as unknown as Payload;
    const signature = await signCanonical(await rfcPrivateKey(), payload);
    expect(await verifies(canonicalBytes(payload), signature)).toBe(true);

    const tampered = clone(payload);
    setPath(tampered, path, TAMPERS[path]);
    expect(canonicalize(tampered)).not.toBe(canonicalize(payload));
    expect(await verifies(canonicalBytes(tampered), signature)).toBe(false);
  });
});

// ── Separación de dominio con register-key:v1 ───────────────────────────────

describe("separación de dominio con agentbuyer:register-key:v1", () => {
  const regVector = registration.vectors[0];

  it("una firma de registro no verifica como mandato", async () => {
    expect(await verifies(new TextEncoder().encode(regVector.expected_message), regVector.expected_signature_hex)).toBe(true);
    const input = { ...clone(BASE_INPUT), owner_email: regVector.inputs.owner_email };
    expect(await verifies(mandateSigningMessage(input), regVector.expected_signature_hex)).toBe(false);
  });

  it("una firma de mandato no verifica como registro", async () => {
    const asRegistration = canonicalBytes(registrationPayload({
      challengeId: `chl_${BASE_INPUT.nonce}`,
      nonce: BASE_INPUT.nonce,
      ownerEmail: BASE_INPUT.owner_email,
      publicKey: BASE_INPUT.public_key,
    }));
    expect(await verifies(asRegistration, shared.vectors[0].expected_signature_hex)).toBe(false);
  });

  it("el purpose firmado es el que separa los dominios", async () => {
    const payload = mandateSigningPayload(clone(BASE_INPUT));
    const signature = await signCanonical(await rfcPrivateKey(), payload);
    expect(await verifies(canonicalBytes({ ...payload, purpose: REGISTER_KEY_PURPOSE }), signature)).toBe(false);
  });
});

// ── Utilidades para el 3.4 ──────────────────────────────────────────────────

describe("utilidades", () => {
  it("newMandateNonce: 32 hex distintos cada vez y aceptados por la spec", () => {
    const nonces = new Set(Array.from({ length: 50 }, () => newMandateNonce()));
    expect(nonces.size).toBe(50);
    for (const nonce of nonces) {
      expect(nonce).toMatch(/^[0-9a-f]{32}$/);
      expect(mandateSigningPayload({ ...clone(BASE_INPUT), nonce }).nonce).toBe(nonce);
    }
  });

  it("toSignedTimestamp: UTC con Z, segundos, trunca los milisegundos", () => {
    expect(toSignedTimestamp(new Date(Date.UTC(2026, 10, 30, 23, 59, 59, 999)))).toBe("2026-11-30T23:59:59Z");
    expect(() => toSignedTimestamp(new Date(Number.NaN))).toThrow(MandateMessageError);
    expect(() => toSignedTimestamp(new Date(Date.UTC(1999, 0, 1)))).toThrow(MandateMessageError);
  });

  it("el trim recorta exactamente el conjunto compartido con Python", () => {
    expect(TRIM_CODE_POINTS.map((point) => `U+${point.toString(16).toUpperCase().padStart(4, "0")}`)).toEqual(shared.trim_code_points);
    const spaces = TRIM_CODE_POINTS.map((point) => String.fromCodePoint(point)).join("");
    const input = clone(BASE_INPUT);
    input.search_fields = { destination: `${spaces}COR${spaces}` };
    expect(mandateSigningPayload(input).search_fields).toEqual({ destination: "COR" });
    // U+001C y U+0085 (que str.strip() de Python sí recortaría) NO se recortan: se firman tal cual.
    for (const kept of [0x1c, 0x85]) {
      input.search_fields = { destination: `${String.fromCodePoint(kept)}COR` };
      expect(mandateSigningPayload(input).search_fields.destination).toBe(`${String.fromCodePoint(kept)}COR`);
    }
  });
});
