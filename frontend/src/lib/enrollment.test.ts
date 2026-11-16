/**
 * Enrolamiento de la llave del navegador (paso 3.1) contra un backend falso que
 * reproduce api/keys.py y VERIFICA la prueba de posesión (src/test/fakeKeyServer.ts).
 * Hermético: fetch simulado, IndexedDB en memoria, WebCrypto nativo de Node.
 */
import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeKeyServer, RESEND_COOLDOWN_SECONDS, randomPublicKeyHex } from "../test/fakeKeyServer";
import { setTokenGetter, setUnauthorizedHandler } from "./api";
import {
  EnrollmentProtocolError,
  MAX_ACTIVE_KEYS_PER_OWNER,
  ProofRejectedError,
  StepUpRateLimitedError,
  WrongStepUpCodeError,
  beginEnrollment,
  completeEnrollment,
  deriveKeyStatus,
  loadKeyState,
  revokeServerKey,
  startStepUp,
  type KeyStatus,
  type ServerKey,
} from "./enrollment";
import { UNSUPPORTED_BROWSER_MESSAGE, UnsupportedBrowserError, getLocalKey, getOrCreateLocalKey } from "./keystore";

const MARTA = "marta@example.com";

let server: FakeKeyServer;
let onUnauthorized: ReturnType<typeof vi.fn>;
let releaseToken: () => void;
let releaseUnauthorized: () => void;

beforeEach(() => {
  vi.stubGlobal("indexedDB", new IDBFactory());
  server = new FakeKeyServer(MARTA);
  vi.stubGlobal("fetch", vi.fn(server.fetch));
  // Sesión iniciada (como la deja AuthProvider): las peticiones llevan token y un
  // 401 de una petición autenticada cerraría la sesión.
  releaseToken = setTokenGetter(() => "header.payload.signature");
  onUnauthorized = vi.fn();
  releaseUnauthorized = setUnauthorizedHandler(onUnauthorized);
});

afterEach(() => {
  releaseToken();
  releaseUnauthorized();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

/** begin + complete con el código que llegó por correo (code_demo en dev). */
async function enrollOnce() {
  const start = await beginEnrollment(MARTA);
  expect(start.kind).toBe("code_sent");
  return completeEnrollment(MARTA, server.currentCode());
}

// ── Flujo feliz ─────────────────────────────────────────────────────────────

describe("flujo feliz", () => {
  it("registra la llave local con prueba de posesión y persiste keyId/registered", async () => {
    const start = await beginEnrollment(MARTA);
    expect(start).toMatchObject({ kind: "code_sent", stepUp: { codeDemo: server.currentCode(), sentVia: "dev" } });
    if (start.kind !== "code_sent") throw new Error("unreachable");

    const result = await completeEnrollment(MARTA, start.stepUp.codeDemo!);

    expect(result.kind).toBe("registered");
    if (result.kind !== "registered") throw new Error("unreachable");
    // El servidor (que verificó la firma) tiene exactamente esa llave.
    expect(server.activeKeys().map((key) => key.public_key)).toEqual([start.publicKeyHex]);
    expect(result.serverKey).toMatchObject({ keyId: server.activeKeys()[0].key_id, publicKey: start.publicKeyHex });

    // IndexedDB guarda keyId + registered, y la privada sigue no extraíble.
    const stored = await getLocalKey(MARTA);
    expect(stored).toMatchObject({ publicKeyHex: start.publicKeyHex, keyId: result.serverKey.keyId, registered: true });
    expect(stored!.privateKey.extractable).toBe(false);

    expect((await loadKeyState(MARTA)).status).toBe("registered");
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("todas las llamadas van autenticadas y el body de POST /keys no trae owner (lo pone el token)", async () => {
    await enrollOnce();
    expect(server.calls.every((call) => call.authorization === "Bearer header.payload.signature")).toBe(true);
    const [post] = server.callsTo("POST", "/keys");
    expect(Object.keys(post.body!).sort()).toEqual(["challenge_id", "public_key", "signature"]);
  });

  it("si la respuesta del servidor trae OTRA pubkey, no se marca nada como registrado", async () => {
    await beginEnrollment(MARTA);
    const other = await randomPublicKeyHex();
    server.override = (method, path) => method === "POST" && path === "/keys"
      ? new Response(JSON.stringify({ key_id: "key_x", public_key: other, alg: "ed25519", created_at: "now" }), { status: 201 })
      : null;

    await expect(completeEnrollment(MARTA, server.currentCode())).rejects.toBeInstanceOf(EnrollmentProtocolError);
    expect(await getLocalKey(MARTA)).toMatchObject({ registered: false, keyId: null });
  });

  it("si el challenge pide otro purpose, no se firma ni se envía nada (fail-closed)", async () => {
    await beginEnrollment(MARTA);
    server.override = (method, path) => method === "POST" && path === "/keys/challenge"
      ? new Response(JSON.stringify({ challenge_id: "chl_1", nonce: "00", expires_in: 120, purpose: "agentbuyer:register-key:v2" }), { status: 201 })
      : null;

    await expect(completeEnrollment(MARTA, server.currentCode())).rejects.toBeInstanceOf(EnrollmentProtocolError);
    expect(server.callsTo("POST", "/keys")).toHaveLength(0);
  });
});

// ── Step-up: 403 y 429 ──────────────────────────────────────────────────────

describe("step-up y challenge", () => {
  it("403 en el challenge (código incorrecto) permite reintentar y NO cierra la sesión", async () => {
    await beginEnrollment(MARTA);

    await expect(completeEnrollment(MARTA, "000000")).rejects.toBeInstanceOf(WrongStepUpCodeError);
    expect(onUnauthorized).not.toHaveBeenCalled();
    expect(server.callsTo("POST", "/keys")).toHaveLength(0);

    // El mismo código correcto sigue sirviendo: reintento sin pedir otro.
    const result = await completeEnrollment(MARTA, server.currentCode());
    expect(result.kind).toBe("registered");
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("429 al pedir el código expone el cooldown (Retry-After)", async () => {
    server.stepUpRetryAfter = 42;
    const failure = await beginEnrollment(MARTA).catch((caught: unknown) => caught);

    expect(failure).toBeInstanceOf(StepUpRateLimitedError);
    expect(failure).toMatchObject({ retryAfterSeconds: 42, needsNewCode: false });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("429 en el challenge (intentos agotados) pide un código nuevo, sin cerrar la sesión", async () => {
    await beginEnrollment(MARTA);
    for (let attempt = 1; attempt < 5; attempt += 1) {
      await expect(completeEnrollment(MARTA, "000000")).rejects.toBeInstanceOf(WrongStepUpCodeError);
    }
    const failure = await completeEnrollment(MARTA, "000000").catch((caught: unknown) => caught);

    expect(failure).toBeInstanceOf(StepUpRateLimitedError);
    // El código quedó invalidado; desde el 3.3 el backend dice con Retry-After cuándo
    // se puede pedir otro (antes no lo mandaba y esto era null).
    expect(failure).toMatchObject({ needsNewCode: true, retryAfterSeconds: RESEND_COOLDOWN_SECONDS });
    expect(onUnauthorized).not.toHaveBeenCalled();

    // Camino de salida: pedir un código nuevo y terminar.
    await beginEnrollment(MARTA);
    expect((await completeEnrollment(MARTA, server.currentCode())).kind).toBe("registered");
  });

  it("403 en POST /keys (challenge vencido) → ProofRejectedError; con un código nuevo se completa", async () => {
    await beginEnrollment(MARTA);
    const code = server.currentCode();
    server.override = (method, path) => {
      if (method === "POST" && path === "/keys") server.expireChallenges();
      return null;
    };

    await expect(completeEnrollment(MARTA, code)).rejects.toBeInstanceOf(ProofRejectedError);
    expect(onUnauthorized).not.toHaveBeenCalled();
    expect(await getLocalKey(MARTA)).toMatchObject({ registered: false });

    server.override = null;
    expect((await enrollOnce()).kind).toBe("registered");
  });

  it("422 en POST /keys es un bug del cliente: error claro, nada marcado", async () => {
    await beginEnrollment(MARTA);
    server.override = (method, path) => method === "POST" && path === "/keys"
      ? new Response(JSON.stringify({ detail: "The Ed25519 public key must have 64 hex characters." }), { status: 422 })
      : null;

    const failure = await completeEnrollment(MARTA, server.currentCode()).catch((caught: unknown) => caught);
    expect(failure).toBeInstanceOf(EnrollmentProtocolError);
    expect((failure as Error).message).toMatch(/problem in the app/);
    expect(await getLocalKey(MARTA)).toMatchObject({ registered: false });
  });
});

// ── 409 ─────────────────────────────────────────────────────────────────────

describe("409: tope de llaves y llave revocada", () => {
  it("409 por tope: lista, revoca una y reintenta con la MISMA llave local", async () => {
    for (let i = 0; i < MAX_ACTIVE_KEYS_PER_OWNER - 1; i += 1) server.seedKey(await randomPublicKeyHex());
    const start = await beginEnrollment(MARTA); // 9 activas: el preflight deja pasar
    if (start.kind !== "code_sent") throw new Error(`expected code_sent, got ${start.kind}`);
    server.seedKey(await randomPublicKeyHex()); // otro dispositivo ocupa el último cupo entretanto

    const conflict = await completeEnrollment(MARTA, server.currentCode());
    expect(conflict.kind).toBe("limit_reached");
    if (conflict.kind !== "limit_reached") throw new Error("unreachable");
    expect(conflict.keys).toHaveLength(MAX_ACTIVE_KEYS_PER_OWNER);

    server.mandatesSignedWith.set(conflict.keys[0].keyId, 2);
    expect(await revokeServerKey(conflict.keys[0].keyId)).toBe(2); // 3.5: lo que queda sin efecto
    expect(server.activeKeys()).toHaveLength(MAX_ACTIVE_KEYS_PER_OWNER - 1);

    const retry = await enrollOnce();
    expect(retry.kind).toBe("registered");
    if (retry.kind !== "registered") throw new Error("unreachable");
    expect(retry.record.publicKeyHex).toBe(start.publicKeyHex); // el tope no quema la llave
    expect(server.activeKeys()).toHaveLength(MAX_ACTIVE_KEYS_PER_OWNER);
  });

  it("con el tope ya lleno, beginEnrollment lo dice ANTES de mandar un correo", async () => {
    for (let i = 0; i < MAX_ACTIVE_KEYS_PER_OWNER; i += 1) server.seedKey(await randomPublicKeyHex());

    const start = await beginEnrollment(MARTA);

    expect(start.kind).toBe("limit_reached");
    expect(server.callsTo("POST", "/keys/step-up/start")).toHaveLength(0);
  });

  it("409 por llave revocada: genera una llave NUEVA y la enrola", async () => {
    const original = await getOrCreateLocalKey(MARTA);
    server.seedKey(original.publicKeyHex, true); // esa pubkey ya fue revocada en el servidor

    const conflict = await enrollOnce();
    expect(conflict.kind).toBe("key_replaced");
    if (conflict.kind !== "key_replaced") throw new Error("unreachable");
    expect(conflict.record.publicKeyHex).not.toBe(original.publicKeyHex);
    expect((await getLocalKey(MARTA))!.publicKeyHex).toBe(conflict.record.publicKeyHex);

    const retry = await enrollOnce();
    expect(retry.kind).toBe("registered");
    if (retry.kind !== "registered") throw new Error("unreachable");
    expect(retry.record.publicKeyHex).toBe(conflict.record.publicKeyHex);
    expect(server.activeKeys().map((key) => key.public_key)).toEqual([conflict.record.publicKeyHex]);
  });

  it("missing_on_server (revocada después de registrarla): beginEnrollment regenera y re-enrola", async () => {
    const first = await enrollOnce();
    if (first.kind !== "registered") throw new Error("unreachable");
    server.revokeDirectly(first.record.publicKeyHex);
    expect((await loadKeyState(MARTA)).status).toBe("missing_on_server");

    const again = await enrollOnce();
    expect(again.kind).toBe("registered");
    if (again.kind !== "registered") throw new Error("unreachable");
    expect(again.record.publicKeyHex).not.toBe(first.record.publicKeyHex);
    expect((await loadKeyState(MARTA)).status).toBe("registered");
  });
});

it("una respuesta de revocación sin mandates_affected es un error de protocolo (fail-closed)", async () => {
  const key = server.seedKey(await randomPublicKeyHex());
  server.override = (method) => method === "DELETE"
    ? new Response(JSON.stringify({ key_id: key.key_id, revoked_at: "now" }), { status: 200 })
    : null;
  await expect(revokeServerKey(key.key_id)).rejects.toBeInstanceOf(EnrollmentProtocolError);
});

// ── Sin soporte ─────────────────────────────────────────────────────────────

describe("navegador sin soporte", () => {
  beforeEach(() => {
    vi.spyOn(crypto.subtle, "generateKey").mockRejectedValue(new DOMException("Unrecognized name.", "NotSupportedError"));
  });

  it.each([
    ["beginEnrollment", () => beginEnrollment(MARTA)],
    ["completeEnrollment", () => completeEnrollment(MARTA, "123456")],
  ] as const)("%s lanza UnsupportedBrowserError sin abrir IndexedDB ni llamar al servidor", async (_name, use) => {
    const openSpy = vi.spyOn(indexedDB, "open");

    const failure = await use().catch((caught: unknown) => caught);

    expect(failure).toBeInstanceOf(UnsupportedBrowserError);
    expect((failure as Error).message).toBe(UNSUPPORTED_BROWSER_MESSAGE);
    expect(openSpy).not.toHaveBeenCalled();
    expect(server.calls).toHaveLength(0); // ni se manda correo ni se gasta un código
  });

  it("loadKeyState devuelve 'unsupported' sin abrir IndexedDB", async () => {
    const openSpy = vi.spyOn(indexedDB, "open");
    const state = await loadKeyState(MARTA);
    expect(state.status).toBe("unsupported");
    expect(openSpy).not.toHaveBeenCalled();
    expect(server.calls).toHaveLength(0);
  });
});

// ── Re-enrolar ──────────────────────────────────────────────────────────────

describe("re-enrolar una llave ya registrada no crea otra", () => {
  it("beginEnrollment con la llave registrada no manda correo ni genera llave", async () => {
    const first = await enrollOnce();
    if (first.kind !== "registered") throw new Error("unreachable");

    const again = await beginEnrollment(MARTA);

    expect(again.kind).toBe("already_registered");
    expect(server.callsTo("POST", "/keys/step-up/start")).toHaveLength(1);
    expect((await getLocalKey(MARTA))!.publicKeyHex).toBe(first.record.publicKeyHex);
    expect(server.activeKeys()).toHaveLength(1);
  });

  it("completar otra vez con la misma llave devuelve el mismo keyId (idempotente)", async () => {
    const first = await enrollOnce();
    if (first.kind !== "registered") throw new Error("unreachable");

    await startStepUp(); // un código nuevo, pedido a mano (la UI no lo ofrece si ya está registrada)
    const second = await completeEnrollment(MARTA, server.currentCode());

    expect(second.kind).toBe("registered");
    if (second.kind !== "registered") throw new Error("unreachable");
    expect(second.record.keyId).toBe(first.record.keyId);
    expect(second.record.publicKeyHex).toBe(first.record.publicKeyHex);
    expect(server.keys).toHaveLength(1);
  });

  it("recargar la página (módulos nuevos, misma IndexedDB) mantiene la misma llave registrada", async () => {
    const first = await enrollOnce();
    if (first.kind !== "registered") throw new Error("unreachable");

    vi.resetModules();
    const freshApi = await import("./api");
    const freshEnrollment = await import("./enrollment");
    const release = freshApi.setTokenGetter(() => "header.payload.signature");
    try {
      const state = await freshEnrollment.loadKeyState(MARTA);
      expect(state.status).toBe("registered");
      expect(state.local).toMatchObject({ keyId: first.record.keyId, publicKeyHex: first.record.publicKeyHex });
      expect((await freshEnrollment.beginEnrollment(MARTA)).kind).toBe("already_registered");
    } finally {
      release();
    }
  });

  it("loadKeyState reconcilia una llave que el servidor ya tiene pero que no se anotó localmente", async () => {
    const local = await getOrCreateLocalKey(MARTA);
    const listed = server.seedKey(local.publicKeyHex); // el 201 llegó, pero la pestaña se cerró antes de guardar

    const state = await loadKeyState(MARTA);

    expect(state.status).toBe("registered");
    expect(await getLocalKey(MARTA)).toMatchObject({ keyId: listed.key_id, registered: true });
    expect(server.activeKeys()).toHaveLength(1);
  });
});

// ── Estado (función pura) ───────────────────────────────────────────────────

describe("deriveKeyStatus cubre los 5 estados", () => {
  const PUB = "a".repeat(64);
  const listed: ServerKey = { keyId: "key_1", publicKey: PUB, alg: "ed25519", createdAt: "2026-11-16T00:00:00Z" };

  it.each<[string, Parameters<typeof deriveKeyStatus>[0], KeyStatus]>([
    ["sin soporte", { supported: false, local: null, serverKeys: [listed] }, "unsupported"],
    ["sin soporte aunque haya llave", { supported: false, local: { publicKeyHex: PUB, keyId: "key_1", registered: true }, serverKeys: [listed] }, "unsupported"],
    ["sin llave local", { supported: true, local: null, serverKeys: [] }, "none"],
    ["sin llave local, con llaves de otros dispositivos", { supported: true, local: null, serverKeys: [listed] }, "none"],
    ["llave local sin registrar", { supported: true, local: { publicKeyHex: PUB, keyId: null, registered: false }, serverKeys: [] }, "local_unregistered"],
    ["registrada y listada", { supported: true, local: { publicKeyHex: PUB, keyId: "key_1", registered: true }, serverKeys: [listed] }, "registered"],
    ["registrada pero el servidor ya no la lista", { supported: true, local: { publicKeyHex: PUB, keyId: "key_1", registered: true }, serverKeys: [] }, "missing_on_server"],
    ["mismo keyId pero otra pubkey", { supported: true, local: { publicKeyHex: "b".repeat(64), keyId: "key_1", registered: true }, serverKeys: [listed] }, "missing_on_server"],
    ["misma pubkey pero otro keyId", { supported: true, local: { publicKeyHex: PUB, keyId: "key_2", registered: true }, serverKeys: [listed] }, "missing_on_server"],
  ])("%s → %s", (_name, input, expected) => {
    expect(deriveKeyStatus(input)).toBe(expected);
  });
});
