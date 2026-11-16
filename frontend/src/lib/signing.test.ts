/**
 * signCanonical contra shared/key_registration_vectors.json: los MISMOS vectores
 * que verifica el backend (tests/test_key_registration*.py). Ed25519 es
 * determinista, así que la firma esperada es exacta: si el navegador firmara un
 * solo byte distinto, la firma cambiaría por completo.
 *
 * La llave del RFC 8032 §7.1 TEST 1 se importa AQUÍ y solo aquí, como llave de
 * prueba. La app nunca importa privadas: las genera no extraíbles (keystore.ts).
 */
import { describe, expect, it } from "vitest";
import vectors from "../../../shared/key_registration_vectors.json";
import { CanonicalizationError, canonicalBytes, canonicalize } from "./canonical";
import { REGISTER_KEY_PURPOSE, registrationPayload } from "./enrollment";
import { signCanonical } from "./signing";

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const fromHex = (hex: string) => new Uint8Array(hex.match(/../g)!.map((pair) => parseInt(pair, 16)));

// PKCS#8 de una semilla Ed25519 de 32 bytes: prefijo DER fijo (RFC 8410) + semilla.
const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";

async function importRfc8032TestKey(): Promise<CryptoKey> {
  const pkcs8 = fromHex(PKCS8_ED25519_PREFIX + vectors.rfc8032_test1.secret_key_hex);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
}

async function verifyRfc8032(signatureHex: string, message: Uint8Array<ArrayBuffer>): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey("raw", fromHex(vectors.rfc8032_test1.public_key_hex), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, publicKey, fromHex(signatureHex), message);
}

describe("signCanonical reproduce shared/key_registration_vectors.json byte a byte", () => {
  it("el purpose del cliente es el de la spec", () => {
    expect(REGISTER_KEY_PURPOSE).toBe(vectors.purpose);
  });

  it.each(vectors.vectors.map((vector) => [vector.name, vector] as const))("%s: mismo mensaje y misma firma", async (_name, vector) => {
    const payload = registrationPayload({
      challengeId: vector.inputs.challenge_id,
      nonce: vector.inputs.nonce,
      ownerEmail: vector.inputs.owner_email,
      publicKey: vector.inputs.public_key,
    });

    // Mensaje: texto canónico y bytes UTF-8 exactos.
    expect(canonicalize(payload)).toBe(vector.expected_message);
    expect(toHex(canonicalBytes(payload))).toBe(vector.expected_message_utf8_hex);

    // Firma: exacta (Ed25519 determinista) y verificable con la pública del RFC.
    const signature = await signCanonical(await importRfc8032TestKey(), payload);
    expect(signature).toBe(vector.expected_signature_hex);
    expect(await verifyRfc8032(signature, canonicalBytes(payload))).toBe(true);
  });

  it("firma los bytes canónicos, no el orden de inserción del objeto", async () => {
    const key = await importRfc8032TestKey();
    const vector = vectors.vectors[0];
    const payload = registrationPayload({
      challengeId: vector.inputs.challenge_id,
      nonce: vector.inputs.nonce,
      ownerEmail: vector.inputs.owner_email,
      publicKey: vector.inputs.public_key,
    });
    const reordered = Object.fromEntries(Object.entries(payload).reverse());
    expect(await signCanonical(key, reordered)).toBe(vector.expected_signature_hex);
  });
});

describe("signCanonical es fail-closed", () => {
  it("un valor no canonicalizable lanza y no firma nada", async () => {
    const key = await importRfc8032TestKey();
    await expect(signCanonical(key, { amount: Number.NaN })).rejects.toBeInstanceOf(CanonicalizationError);
    await expect(signCanonical(key, { at: new Date(0) })).rejects.toBeInstanceOf(CanonicalizationError);
  });

  it("solo firma con una privada Ed25519 (no con una pública)", async () => {
    const publicKey = await crypto.subtle.importKey("raw", fromHex(vectors.rfc8032_test1.public_key_hex), { name: "Ed25519" }, true, ["verify"]);
    await expect(signCanonical(publicKey, { a: 1 })).rejects.toThrow("Ed25519 private key");
  });
});

describe("registrationPayload sigue la spec (core/key_challenges.registration_payload)", () => {
  const base = { challengeId: "chl_1", nonce: "00", ownerEmail: " Marta@Example.COM ", publicKey: vectors.rfc8032_test1.public_key_hex.toUpperCase() };

  it("normaliza owner y pubkey y tiene exactamente los 5 campos", () => {
    expect(registrationPayload(base)).toEqual({
      purpose: "agentbuyer:register-key:v1",
      challenge_id: "chl_1",
      nonce: "00",
      owner: "marta@example.com",
      public_key: vectors.rfc8032_test1.public_key_hex,
    });
  });

  it.each([
    ["challenge vacío", { ...base, challengeId: "" }],
    ["nonce vacío", { ...base, nonce: "" }],
    ["pubkey corta", { ...base, publicKey: "abcd" }],
    ["pubkey no hex", { ...base, publicKey: "z".repeat(64) }],
    ["owner vacío", { ...base, ownerEmail: "   " }],
  ])("%s → lanza (no se firma un mensaje que el servidor rechazaría)", (_name, input) => {
    expect(() => registrationPayload(input)).toThrow();
  });
});
