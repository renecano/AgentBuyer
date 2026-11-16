/**
 * El wizard firma el mandato (paso 3.4): bytes de la spec, firma verificable, vigencia
 * al final del día local (D-19) y manejo de 403/409/422. Hermético: IndexedDB en
 * memoria, WebCrypto nativo y fetch simulado.
 */
import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setTokenGetter } from "./api";
import { canonicalBytes } from "./canonical";
import { getOrCreateLocalKey, markLocalKeyRegistered, type LocalKeyRecord } from "./keystore";
import { mandateSigningMessage } from "./mandateMessage";
import {
  DeviceKeyNotReadyError,
  MandateFieldError,
  SigningKeyRejectedError,
  createSignedMandate,
  describeExpiry,
  endOfLocalDay,
  signMandateDraft,
  type MandateDraft,
  type SignedMandateBody,
} from "./signedMandate";

const OWNER = "marta@example.com";
const NOW = new Date(Date.UTC(2026, 10, 16, 15, 30, 0));
const NONCE = "00112233445566778899aabbccddeeff";

function draft(changes: Partial<MandateDraft["constraints"]> = {}, validUntil = "2026-11-30"): MandateDraft {
  return {
    mandateId: "mnd_marta_abc123",
    human: { id: "hum_marta", display_name: "Marta", email: OWNER },
    agent: { id: "agt_saturday", display_name: "Saturday" },
    constraints: {
      currency: "USD",
      max_amount_per_purchase: "150",
      allowed_categories: ["travel.flights"],
      allowed_merchants: ["mch_vuelaya"],
      max_uses: 3,
      conditions: [{ type: "price_below", value: "140" }],
      off_session_consent: true,
      ...changes,
    },
    searchFields: { origin: "BUE", destination: "COR", departure_date: "2026-12-05" },
    validUntil,
  };
}

const fromHex = (hex: string) => new Uint8Array(hex.match(/../g)!.map((pair) => parseInt(pair, 16)));

async function verifies(publicKeyHex: string, message: Uint8Array<ArrayBuffer>, signatureHex: string): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey("raw", fromHex(publicKeyHex), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, publicKey, fromHex(signatureHex), message);
}

/** Reconstruye, desde el CUERPO enviado, el mensaje que el servidor verificará (3.3). */
function serverMessage(body: SignedMandateBody, publicKeyHex: string) {
  return mandateSigningMessage({
    mandate_id: body.mandate_id, owner_email: OWNER, key_id: body.key_id, public_key: publicKeyHex,
    agent_id: body.agent.id, constraints: body.constraints, search_fields: body.search_fields,
    expires_at: body.expires_at, created_at: body.created_at, nonce: body.nonce,
  });
}

let key: LocalKeyRecord & { keyId: string };
let releaseToken: () => void;

beforeEach(async () => {
  vi.stubGlobal("indexedDB", new IDBFactory());
  const local = await getOrCreateLocalKey(OWNER);
  key = (await markLocalKeyRegistered(OWNER, local.publicKeyHex, "key_00112233445566778899aabbccddeeff")) as typeof key;
  releaseToken = setTokenGetter(() => "header.payload.signature");
});

afterEach(() => {
  releaseToken();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("el payload firmado", () => {
  it("reproduce byte a byte mandate_signing_message y la firma verifica con la pubkey", async () => {
    const { body, payload } = await signMandateDraft(draft(), OWNER, key, NOW, NONCE, "UTC");

    const rebuilt = serverMessage(body, key.publicKeyHex);
    expect(rebuilt).toEqual(canonicalBytes(payload));
    expect(await verifies(key.publicKeyHex, rebuilt, body.signature)).toBe(true);
    expect(payload.constraints).toMatchObject({ max_amount_per_purchase_cents: 15000, conditions: [{ type: "price_below", value_cents: 14000 }] });
  });

  it("solo lleva los campos del formato firmado (nada fuera de la spec)", async () => {
    const { body } = await signMandateDraft(draft(), OWNER, key, NOW, NONCE, "UTC");
    expect(Object.keys(body).sort()).toEqual([
      "agent", "constraints", "created_at", "expires_at", "human", "key_id", "mandate_id", "nonce", "search_fields", "signature",
    ]);
    expect(body).toMatchObject({ created_at: "2026-11-16T15:30:00Z", nonce: NONCE, key_id: key.keyId });
  });

  it("los montos viajan como el texto que tecleó la persona (sin float)", async () => {
    const { body, payload } = await signMandateDraft(draft({ max_amount_per_purchase: "89.99" }), OWNER, key, NOW, NONCE, "UTC");
    expect(body.constraints.max_amount_per_purchase).toBe("89.99");
    expect(payload.constraints.max_amount_per_purchase_cents).toBe(8999);
  });

  it("editar un límite después de firmar produce una firma NUEVA (nunca se reutiliza)", async () => {
    const first = await signMandateDraft(draft(), OWNER, key, NOW, NONCE, "UTC");
    const edited = await signMandateDraft(draft({ max_amount_per_purchase: "160" }), OWNER, key, NOW, NONCE, "UTC");

    expect(edited.body.signature).not.toBe(first.body.signature);
    const editedMessage = serverMessage(edited.body, key.publicKeyHex);
    expect(await verifies(key.publicKeyHex, editedMessage, edited.body.signature)).toBe(true);
    expect(await verifies(key.publicKeyHex, editedMessage, first.body.signature)).toBe(false);
  });

  it("un monto fuera de la spec es un error del formulario ANTES de firmar o enviar", async () => {
    const failure = await signMandateDraft(draft({ max_amount_per_purchase: "150.125" }), OWNER, key, NOW, NONCE, "UTC").catch((caught: unknown) => caught);
    expect(failure).toBeInstanceOf(MandateFieldError);
    expect((failure as MandateFieldError).field).toBe("constraints.max_amount_per_purchase");
  });
});

describe("vigencia: final del día elegido en la zona LOCAL (D-19)", () => {
  it.each([
    ["America/Mexico_City", "2026-11-30", "2026-12-01T05:59:59.000Z"], // UTC−6
    ["Asia/Tokyo", "2026-11-30", "2026-11-30T14:59:59.000Z"],          // UTC+9
    ["UTC", "2026-11-30", "2026-11-30T23:59:59.000Z"],
    ["America/New_York", "2026-07-01", "2026-07-02T03:59:59.000Z"],    // horario de verano (UTC−4)
    ["America/New_York", "2026-12-01", "2026-12-02T04:59:59.000Z"],    // horario estándar (UTC−5)
    // El día anterior a que termine el horario de verano (5 abr, 03:00 AEDT = 16:00Z del 4):
    // el offset en las 23:59:59Z ya es +10, pero el final del día local aún es +11.
    ["Australia/Sydney", "2026-04-04", "2026-04-04T12:59:59.000Z"],
  ])("%s, %s → %s", (timeZone, day, expected) => {
    expect(endOfLocalDay(day, timeZone).toISOString()).toBe(expected);
  });

  it("el expires_at firmado usa la zona del navegador (dos zonas distintas, dos instantes)", async () => {
    const mexico = await signMandateDraft(draft(), OWNER, key, NOW, NONCE, "America/Mexico_City");
    const tokyo = await signMandateDraft(draft(), OWNER, key, NOW, NONCE, "Asia/Tokyo");
    expect(mexico.body.expires_at).toBe("2026-12-01T05:59:59Z");
    expect(tokyo.body.expires_at).toBe("2026-11-30T14:59:59Z");
  });

  it("la confirmación muestra fecha, hora y zona", () => {
    const text = describeExpiry("2026-12-01T05:59:59Z", "America/Mexico_City");
    expect(text).toContain("Nov 30, 2026");
    expect(text).toContain("11:59:59");
    expect(text).toContain("(America/Mexico_City)");
  });

  it.each([
    ["fecha pasada", "2026-11-01"],
    ["el mismo instante de creación o antes", "2026-11-15"],
    ["fecha inexistente", "2026-02-30"],
    ["sin fecha", ""],
  ])("%s → error del formulario", async (_name, validUntil) => {
    const failure = await signMandateDraft(draft({}, validUntil), OWNER, key, NOW, NONCE, "UTC").catch((caught: unknown) => caught);
    expect(failure).toBeInstanceOf(MandateFieldError);
    expect((failure as MandateFieldError).field).toBe("expires_at");
  });
});

describe("createSignedMandate (POST /mandates)", () => {
  function respond(...responses: Array<{ status: number; body: unknown }>) {
    const calls: SignedMandateBody[] = [];
    const queue = [...responses];
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
      calls.push(JSON.parse(init.body as string));
      const next = queue.shift()!;
      return new Response(JSON.stringify(next.body), { status: next.status, headers: { "Content-Type": "application/json" } });
    }));
    return calls;
  }

  it("sin llave registrada no autoriza ni llama al servidor", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory()); // otro navegador: sin llave
    const calls = respond({ status: 201, body: {} });
    await expect(createSignedMandate(draft(), OWNER)).rejects.toBeInstanceOf(DeviceKeyNotReadyError);
    expect(calls).toHaveLength(0);
  });

  it("una llave local SIN registrar tampoco autoriza", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    await getOrCreateLocalKey(OWNER);
    const calls = respond({ status: 201, body: {} });
    await expect(createSignedMandate(draft(), OWNER)).rejects.toBeInstanceOf(DeviceKeyNotReadyError);
    expect(calls).toHaveLength(0);
  });

  it("201 devuelve el registro del servidor", async () => {
    respond({ status: 201, body: { mandate: { mandate_id: "mnd_marta_abc123" }, live_state: {} } });
    const record = await createSignedMandate<{ mandate: { mandate_id: string } }>(draft(), OWNER, { now: () => NOW, timeZone: "UTC" });
    expect(record.mandate.mandate_id).toBe("mnd_marta_abc123");
  });

  it("409 (nonce ya usado) reintenta UNA vez con nonce y firma nuevos", async () => {
    const calls = respond({ status: 409, body: { detail: "replay" } }, { status: 201, body: { mandate: {} } });
    const nonces = ["a".repeat(32), "b".repeat(32)];
    await createSignedMandate(draft(), OWNER, { now: () => NOW, newNonce: () => nonces.shift()!, timeZone: "UTC" });

    expect(calls).toHaveLength(2);
    expect(calls.map((call) => call.nonce)).toEqual(["a".repeat(32), "b".repeat(32)]);
    expect(calls[1].signature).not.toBe(calls[0].signature);
    expect(await verifies(key.publicKeyHex, serverMessage(calls[1], key.publicKeyHex), calls[1].signature)).toBe(true);
  });

  it("un segundo 409 ya no reintenta: error", async () => {
    const calls = respond({ status: 409, body: { detail: "replay" } }, { status: 409, body: { detail: "replay" } }, { status: 201, body: {} });
    await expect(createSignedMandate(draft(), OWNER, { now: () => NOW, timeZone: "UTC" })).rejects.toMatchObject({ status: 409 });
    expect(calls).toHaveLength(2);
  });

  it("403 → SigningKeyRejectedError (la UI recarga el estado de la llave)", async () => {
    const calls = respond({ status: 403, body: { detail: "The signing key is not valid for this account." } });
    await expect(createSignedMandate(draft(), OWNER, { now: () => NOW, timeZone: "UTC" })).rejects.toBeInstanceOf(SigningKeyRejectedError);
    expect(calls).toHaveLength(1);
  });

  it("422 → MandateFieldError con el campo que dio el servidor", async () => {
    respond({ status: 422, body: { detail: "constraints.currency: v1 supports only USD." } });
    const failure = await createSignedMandate(draft(), OWNER, { now: () => NOW, timeZone: "UTC" }).catch((caught: unknown) => caught);
    expect(failure).toBeInstanceOf(MandateFieldError);
    expect((failure as MandateFieldError).field).toBe("constraints.currency");
  });
});
