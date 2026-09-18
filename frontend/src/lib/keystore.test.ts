import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  UNSUPPORTED_BROWSER_MESSAGE,
  UnsupportedBrowserError,
  deleteLocalKey,
  detectEd25519Support,
  exportPublicKeyHex,
  generateKeyPair,
  getLocalKey,
  getOrCreateLocalKey,
  requestPersistentStorage,
  signBytes,
} from "./keystore";

const MARTA = "marta@example.com";
const OTHER = "otra.persona@example.com";

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(hex.match(/../g)!.map((pair) => parseInt(pair, 16)));
}

async function verifyWithPublicHex(publicKeyHex: string, signatureHex: string, data: Uint8Array<ArrayBuffer>): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey("raw", hexToBytes(publicKeyHex), { name: "Ed25519" }, true, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, publicKey, hexToBytes(signatureHex), data);
}

beforeEach(() => {
  // Una base IndexedDB vacía por test: ningún test depende de otro.
  vi.stubGlobal("indexedDB", new IDBFactory());
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ── 2.1 Detección de soporte ────────────────────────────────────────────────

describe("detección de soporte Ed25519 (sin respaldo)", () => {
  it("este entorno lo soporta", async () => {
    expect(await detectEd25519Support()).toEqual({ supported: true });
  });

  it("si generateKey no conoce Ed25519, el motivo es no-ed25519", async () => {
    vi.spyOn(crypto.subtle, "generateKey").mockRejectedValue(new DOMException("Unrecognized name.", "NotSupportedError"));
    const support = await detectEd25519Support();
    expect(support).toMatchObject({ supported: false, reason: "no-ed25519" });
  });

  it("sin crypto.subtle (contexto inseguro), el motivo es no-webcrypto", async () => {
    vi.stubGlobal("crypto", {});
    expect(await detectEd25519Support()).toMatchObject({ supported: false, reason: "no-webcrypto" });
  });

  it("sin IndexedDB, el motivo es no-indexeddb", async () => {
    vi.stubGlobal("indexedDB", undefined);
    expect(await detectEd25519Support()).toMatchObject({ supported: false, reason: "no-indexeddb" });
  });

  it.each([
    ["getOrCreateLocalKey", () => getOrCreateLocalKey(MARTA)],
    ["getLocalKey", () => getLocalKey(MARTA)],
    ["deleteLocalKey", () => deleteLocalKey(MARTA)],
    ["generateKeyPair", () => generateKeyPair()],
  ] as const)("%s falla con un error claro ANTES de tocar el keystore", async (_name, use) => {
    vi.spyOn(crypto.subtle, "generateKey").mockRejectedValue(new DOMException("Unrecognized name.", "NotSupportedError"));
    const openSpy = vi.spyOn(indexedDB, "open");

    const failure = await use().catch((caught: unknown) => caught);

    expect(failure).toBeInstanceOf(UnsupportedBrowserError);
    expect((failure as UnsupportedBrowserError).message).toBe(UNSUPPORTED_BROWSER_MESSAGE);
    expect((failure as UnsupportedBrowserError).reason).toBe("no-ed25519");
    expect(openSpy).not.toHaveBeenCalled(); // la detección corre antes que cualquier uso
  });
});

// ── 2.2 Llave no extraíble ──────────────────────────────────────────────────

describe("generateKeyPair", () => {
  it("la privada es NO extraíble", async () => {
    const pair = await generateKeyPair();
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.privateKey.algorithm.name).toBe("Ed25519");
  });

  it.each(["pkcs8", "jwk"] as const)("exportKey('%s') de la privada se rechaza", async (format) => {
    const pair = await generateKeyPair();
    await expect(crypto.subtle.exportKey(format, pair.privateKey)).rejects.toThrow();
  });

  it("exportPublicKeyHex solo acepta la pública (la privada nunca se exporta)", async () => {
    const pair = await generateKeyPair();
    expect(await exportPublicKeyHex(pair.publicKey)).toMatch(/^[0-9a-f]{64}$/);
    await expect(exportPublicKeyHex(pair.privateKey)).rejects.toThrow("Only public keys");
  });
});

// ── Keystore en IndexedDB ───────────────────────────────────────────────────

describe("getOrCreateLocalKey / getLocalKey", () => {
  it("la primera vez crea; la segunda recupera LA MISMA llave", async () => {
    const created = await getOrCreateLocalKey(MARTA);
    const again = await getOrCreateLocalKey(MARTA);

    expect(again.publicKeyHex).toBe(created.publicKeyHex);
    expect(again.createdAt).toBe(created.createdAt);
  });

  it("el registro guardado tiene la forma acordada y la privada como CryptoKey (sin serializar)", async () => {
    const record = await getOrCreateLocalKey(MARTA);

    expect(Object.keys(record).sort()).toEqual(["createdAt", "email", "keyId", "privateKey", "publicKeyHex", "registered"]);
    expect(record).toMatchObject({ email: MARTA, keyId: null, registered: false });
    expect(record.privateKey).toBeInstanceOf(CryptoKey);
    expect(record.privateKey.extractable).toBe(false);
    expect(record.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
  });

  it("persiste entre sesiones: otra 'página' (módulo recargado) recupera la misma llave, aún no extraíble", async () => {
    const created = await getOrCreateLocalKey(MARTA);

    vi.resetModules(); // como recargar la página: módulo nuevo, misma base IndexedDB
    const freshPage = await import("./keystore");
    const restored = await freshPage.getLocalKey(MARTA);

    expect(restored?.publicKeyHex).toBe(created.publicKeyHex);
    expect(restored?.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", restored!.privateKey)).rejects.toThrow();
    // Y sigue firmando: la llave recuperada es utilizable, no solo un registro.
    const data = new TextEncoder().encode("after reload");
    expect(await verifyWithPublicHex(created.publicKeyHex, await freshPage.signBytes(restored!.privateKey, data), data)).toBe(true);
  });

  it("varios emails en el mismo navegador no se pisan", async () => {
    const marta = await getOrCreateLocalKey(MARTA);
    const other = await getOrCreateLocalKey(OTHER);

    expect(other.publicKeyHex).not.toBe(marta.publicKeyHex);
    expect((await getLocalKey(MARTA))?.publicKeyHex).toBe(marta.publicKeyHex);
    expect((await getLocalKey(OTHER))?.publicKeyHex).toBe(other.publicKeyHex);
  });

  it("el email se normaliza como en el backend (trim + minúsculas)", async () => {
    const created = await getOrCreateLocalKey("  Marta@Example.COM ");

    expect(created.email).toBe(MARTA);
    expect((await getLocalKey(MARTA))?.publicKeyHex).toBe(created.publicKeyHex);
  });

  it("un email vacío es un error, no una llave", async () => {
    await expect(getOrCreateLocalKey("   ")).rejects.toThrow("email is required");
  });

  it("llamadas simultáneas para el mismo email devuelven UNA sola llave (sin carrera)", async () => {
    const results = await Promise.all(Array.from({ length: 5 }, () => getOrCreateLocalKey(MARTA)));
    const stored = await getLocalKey(MARTA);

    expect(new Set(results.map((record) => record.publicKeyHex))).toEqual(new Set([stored!.publicKeyHex]));
  });

  it("getLocalKey no crea nada: null si no hay llave", async () => {
    expect(await getLocalKey(MARTA)).toBeNull();
    expect(await getLocalKey(MARTA)).toBeNull();
  });
});

describe("deleteLocalKey", () => {
  it("borra la llave; después getLocalKey devuelve null", async () => {
    await getOrCreateLocalKey(MARTA);

    expect(await deleteLocalKey(MARTA)).toBe(true);
    expect(await getLocalKey(MARTA)).toBeNull();
    expect(await deleteLocalKey(MARTA)).toBe(false); // ya no había
  });

  it("solo borra la del email indicado", async () => {
    await getOrCreateLocalKey(MARTA);
    const other = await getOrCreateLocalKey(OTHER);

    await deleteLocalKey(MARTA);
    expect((await getLocalKey(OTHER))?.publicKeyHex).toBe(other.publicKeyHex);
  });

  it("después de borrar, getOrCreateLocalKey genera una llave NUEVA", async () => {
    const first = await getOrCreateLocalKey(MARTA);
    await deleteLocalKey(MARTA);
    const second = await getOrCreateLocalKey(MARTA);

    expect(second.publicKeyHex).not.toBe(first.publicKeyHex);
  });
});

// ── Firma ───────────────────────────────────────────────────────────────────

describe("signBytes", () => {
  it("firma y verifica contra la pública; alterar un byte rompe la verificación", async () => {
    const record = await getOrCreateLocalKey(MARTA);
    const data = new TextEncoder().encode('{"amount":150,"city":"Córdoba"}');

    const signature = await signBytes(record.privateKey, data);

    expect(signature).toMatch(/^[0-9a-f]{128}$/);
    expect(await verifyWithPublicHex(record.publicKeyHex, signature, data)).toBe(true);
    const tampered = data.slice();
    tampered[5] ^= 0x01;
    expect(await verifyWithPublicHex(record.publicKeyHex, signature, tampered)).toBe(false);
  });

  it("la firma no verifica con la llave de otro email", async () => {
    const marta = await getOrCreateLocalKey(MARTA);
    const other = await getOrCreateLocalKey(OTHER);
    const data = new TextEncoder().encode("hola");

    expect(await verifyWithPublicHex(other.publicKeyHex, await signBytes(marta.privateKey, data), data)).toBe(false);
  });

  it("se niega a firmar con una llave pública", async () => {
    const pair = await generateKeyPair();
    await expect(signBytes(pair.publicKey, new Uint8Array([1]))).rejects.toThrow("private key");
  });
});

// ── Almacenamiento persistente ──────────────────────────────────────────────

describe("navigator.storage.persist", () => {
  function stubStorage(storage: object | undefined) {
    vi.stubGlobal("navigator", { storage });
  }

  it("sin la API: 'unavailable', y la llave se crea igual", async () => {
    stubStorage(undefined);
    expect(await requestPersistentStorage()).toBe("unavailable");
    expect((await getOrCreateLocalKey(MARTA)).publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
  });

  it("si la persona lo niega: 'denied', y la llave se crea igual", async () => {
    const persist = vi.fn(async () => false);
    stubStorage({ persist, persisted: vi.fn(async () => false) });

    const record = await getOrCreateLocalKey(MARTA);

    expect(record.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(persist).toHaveBeenCalledTimes(1);
    expect(await requestPersistentStorage()).toBe("denied");
  });

  it("si la API lanza: 'denied', sin romper nada", async () => {
    stubStorage({ persist: vi.fn(async () => { throw new Error("boom"); }), persisted: vi.fn(async () => false) });
    expect(await requestPersistentStorage()).toBe("denied");
    expect((await getOrCreateLocalKey(MARTA)).publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
  });

  it("si ya es persistente: 'granted' sin volver a pedirlo", async () => {
    const persist = vi.fn(async () => true);
    stubStorage({ persist, persisted: vi.fn(async () => true) });

    expect(await requestPersistentStorage()).toBe("granted");
    expect(persist).not.toHaveBeenCalled();
  });

  it("se pide al CREAR la llave, no cada vez que se recupera", async () => {
    const persist = vi.fn(async () => true);
    stubStorage({ persist, persisted: vi.fn(async () => false) });

    await getOrCreateLocalKey(MARTA);
    await getOrCreateLocalKey(MARTA);
    await getLocalKey(MARTA);

    expect(persist).toHaveBeenCalledTimes(1);
  });
});
