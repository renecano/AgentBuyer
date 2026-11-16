/**
 * Enrolamiento de la llave Ed25519 del navegador (paso 3.1).
 *
 * Flujo (contrato del backend: api/keys.py y core/key_challenges.py):
 *
 *   beginEnrollment(email)
 *     1. estado actual: keystore local + GET /keys (loadKeyState)
 *     2. ya registrada → no hace nada (no manda correo, no crea otra llave)
 *        el servidor ya no la lista → genera una nueva (replaceLocalKey)
 *        sin llave → la genera (getOrCreateLocalKey)
 *     3. tope de llaves activas ya lleno → limit_reached ANTES de mandar un correo inútil
 *     4. POST /keys/step-up/start → OTP al email DEL TOKEN (en dev llega code_demo)
 *
 *   completeEnrollment(email, code)        ← la persona tecleó el código
 *     5. POST /keys/challenge {code}        403 = código incorrecto (se puede reintentar;
 *                                           la sesión sigue), 429 = cooldown
 *     6. firma registrationPayload(...) con signCanonical (bytes de la spec, byte a byte)
 *     7. POST /keys {public_key, challenge_id, signature}
 *          201 → guarda keyId + registered=true en IndexedDB
 *          403 → la prueba no valió (challenge vencido/usado) → pedir un código nuevo
 *          409 → GET /keys decide: tope lleno → limit_reached (revocar una y empezar de
 *                nuevo); si no, la llave ya no puede registrarse (revocada) → se genera
 *                otra (key_replaced) y hay que empezar de nuevo
 *          422 → bug del cliente (EnrollmentProtocolError)
 *
 * Los 409 NO se distinguen por el texto del `detail` (va a cambiar de idioma, P-12):
 * se distinguen por el estado que devuelve GET /keys.
 *
 * Cada challenge sirve para UN intento de registro (el servidor lo quema antes de
 * mirar la firma), así que cualquier reintento tras 403/409 en POST /keys exige un
 * código de step-up nuevo. Es el contrato del servidor, no una limitación de aquí.
 *
 * Fuera de alcance (paso 3.4): la llave todavía NO firma mandatos ni toca /verify.
 */
import { ApiError, request } from "./api";
import {
  UnsupportedBrowserError,
  detectEd25519Support,
  getLocalKey,
  getOrCreateLocalKey,
  markLocalKeyRegistered,
  normalizeEmail,
  replaceLocalKey,
  type KeySupport,
  type LocalKeyRecord,
} from "./keystore";
import { signCanonical } from "./signing";

/** Separación de dominio del mensaje de registro (core/key_challenges.REGISTER_KEY_PURPOSE). */
export const REGISTER_KEY_PURPOSE = "agentbuyer:register-key:v1";
/** Tope de llaves activas por cuenta (core/owner_keys.MAX_ACTIVE_KEYS_PER_OWNER). */
export const MAX_ACTIVE_KEYS_PER_OWNER = 10;

const PUBLIC_KEY_HEX = /^[0-9a-f]{64}$/;

// ── Tipos ───────────────────────────────────────────────────────────────────

/** Una llave ACTIVA tal como la lista el servidor (GET /keys). */
export type ServerKey = {
  keyId: string;
  publicKey: string;
  alg: string;
  createdAt: string;
};

export type KeyStatus =
  /** El navegador no puede guardar una llave Ed25519 no extraíble. */
  | "unsupported"
  /** Este navegador no tiene llave para esta cuenta. */
  | "none"
  /** Hay llave local pero todavía no está registrada en el servidor. */
  | "local_unregistered"
  /** La llave local está registrada y el servidor la lista como activa. */
  | "registered"
  /** La llave local figuraba registrada pero el servidor ya no la lista activa
   * (revocada, o el servidor perdió su estado) → regenerar y re-enrolar. */
  | "missing_on_server";

export type KeyState = {
  status: KeyStatus;
  support: KeySupport;
  local: LocalKeyRecord | null;
  /** Llaves activas de la cuenta según el servidor (vacío si no hay soporte). */
  serverKeys: ServerKey[];
};

export type StepUpStart = {
  /** Email enmascarado para mostrar ("***rta@example.com"). */
  emailHint: string;
  expiresInSeconds: number;
  /** "smtp" si se envió por correo, "dev" si el backend está en AUTH_DEV_MODE. */
  sentVia: string;
  /** El código en claro: SOLO llega con AUTH_DEV_MODE=true en el backend. */
  codeDemo: string | null;
};

export type KeyChallenge = {
  challengeId: string;
  nonce: string;
  expiresInSeconds: number;
};

export type RegistrationPayload = {
  purpose: typeof REGISTER_KEY_PURPOSE;
  challenge_id: string;
  nonce: string;
  owner: string;
  public_key: string;
};

export type EnrollmentStart =
  | { kind: "already_registered"; state: KeyState }
  | { kind: "limit_reached"; keys: ServerKey[] }
  | { kind: "code_sent"; stepUp: StepUpStart; publicKeyHex: string };

export type EnrollmentCompletion =
  | { kind: "registered"; record: LocalKeyRecord; serverKey: ServerKey }
  /** Tope de llaves activas: revocar una (revokeServerKey) y volver a beginEnrollment. */
  | { kind: "limit_reached"; keys: ServerKey[] }
  /** La llave anterior ya no puede registrarse (revocada): se generó otra; volver a beginEnrollment. */
  | { kind: "key_replaced"; record: LocalKeyRecord };

// ── Errores (cada uno dice qué tiene que hacer la persona) ──────────────────

/** 429: demasiados códigos pedidos o demasiados intentos fallidos. */
export class StepUpRateLimitedError extends Error {
  /** Segundos de espera (Retry-After), si el servidor los dio. */
  readonly retryAfterSeconds: number | null;
  /** true si el código actual quedó inválido y hay que pedir otro. */
  readonly needsNewCode: boolean;

  constructor(message: string, retryAfterSeconds: number | null, needsNewCode: boolean) {
    super(message);
    this.name = "StepUpRateLimitedError";
    this.retryAfterSeconds = retryAfterSeconds;
    this.needsNewCode = needsNewCode;
  }
}

/** 403 en el challenge: código incorrecto o vencido. La sesión sigue; se puede reintentar. */
export class WrongStepUpCodeError extends Error {
  constructor(message = "That confirmation code isn't valid. Check it and try again, or request a new one.") {
    super(message);
    this.name = "WrongStepUpCodeError";
  }
}

/** 403 en POST /keys: la prueba de posesión no valió (challenge vencido/usado). Pedir un código nuevo. */
export class ProofRejectedError extends Error {
  constructor(message = "The registration couldn't be confirmed (the confirmation expired). Request a new code and try again.") {
    super(message);
    this.name = "ProofRejectedError";
  }
}

/** El cliente y el servidor no hablan el mismo protocolo (422 o respuesta inesperada): es un bug, no algo que la persona hizo mal. */
export class EnrollmentProtocolError extends Error {
  constructor(detail: string) {
    super(`Couldn't register this device because of a problem in the app (${detail}). This isn't something you did; please report it.`);
    this.name = "EnrollmentProtocolError";
  }
}

// ── Estado (función pura) ───────────────────────────────────────────────────

export type KeyStatusInput = {
  supported: boolean;
  local: Pick<LocalKeyRecord, "publicKeyHex" | "keyId" | "registered"> | null;
  serverKeys: readonly ServerKey[];
};

/**
 * Estado de la llave de este navegador para esta cuenta. Pura: no lee nada.
 * "registered" exige que el servidor liste como activa EXACTAMENTE esa llave
 * (mismo keyId y misma pubkey); cualquier otra cosa no cuenta como registrada.
 */
export function deriveKeyStatus({ supported, local, serverKeys }: KeyStatusInput): KeyStatus {
  if (!supported) return "unsupported";
  if (local === null) return "none";
  if (!local.registered) return "local_unregistered";
  const listed = serverKeys.some((key) => key.keyId === local.keyId && key.publicKey === local.publicKeyHex);
  return listed ? "registered" : "missing_on_server";
}

// ── Mensaje de registro (spec) ──────────────────────────────────────────────

/**
 * Los campos EXACTOS que se firman (core/key_challenges.registration_payload):
 * owner normalizado (trim + minúsculas) y pubkey en hex minúsculas. Fail-closed:
 * datos que el servidor rechazaría lanzan aquí, en vez de firmar otra cosa.
 */
export function registrationPayload(input: {
  challengeId: string;
  nonce: string;
  ownerEmail: string;
  publicKey: string;
}): RegistrationPayload {
  if (typeof input.challengeId !== "string" || !input.challengeId) throw new EnrollmentProtocolError("missing challenge id");
  if (typeof input.nonce !== "string" || !input.nonce) throw new EnrollmentProtocolError("missing challenge nonce");
  const publicKey = input.publicKey.trim().toLowerCase();
  if (!PUBLIC_KEY_HEX.test(publicKey)) throw new EnrollmentProtocolError("malformed public key");
  return {
    purpose: REGISTER_KEY_PURPOSE,
    challenge_id: input.challengeId,
    nonce: input.nonce,
    owner: normalizeEmail(input.ownerEmail),
    public_key: publicKey,
  };
}

// ── Llamadas al backend ─────────────────────────────────────────────────────

function parseServerKey(raw: unknown): ServerKey {
  const key = raw as Record<string, unknown> | null;
  if (
    !key || typeof key !== "object"
    || typeof key.key_id !== "string" || !key.key_id
    || typeof key.public_key !== "string" || !PUBLIC_KEY_HEX.test(key.public_key)
    || typeof key.alg !== "string"
    || typeof key.created_at !== "string"
  ) {
    throw new EnrollmentProtocolError("unexpected key format from the server");
  }
  return { keyId: key.key_id, publicKey: key.public_key, alg: key.alg, createdAt: key.created_at };
}

/** Llaves ACTIVAS de la cuenta (GET /keys). */
export async function listServerKeys(): Promise<ServerKey[]> {
  const body = await request<{ keys?: unknown }>("/keys");
  if (!Array.isArray(body?.keys)) throw new EnrollmentProtocolError("unexpected key list from the server");
  return body.keys.map(parseServerKey);
}

/** POST /keys/step-up/start: OTP de confirmación al email del token. */
export async function startStepUp(): Promise<StepUpStart> {
  let body: Record<string, unknown>;
  try {
    body = await request<Record<string, unknown>>("/keys/step-up/start", { method: "POST" });
  } catch (caught) {
    if (caught instanceof ApiError && caught.status === 429) {
      throw new StepUpRateLimitedError("Too many confirmation code requests.", caught.retryAfterSeconds, false);
    }
    throw caught;
  }
  return {
    emailHint: typeof body.email_hint === "string" ? body.email_hint : "",
    expiresInSeconds: typeof body.expires_in_seconds === "number" ? body.expires_in_seconds : 0,
    sentVia: typeof body.sent_via === "string" ? body.sent_via : "",
    codeDemo: typeof body.code_demo === "string" && body.code_demo ? body.code_demo : null,
  };
}

/** POST /keys/challenge {code}: canjea el OTP de step-up por un challenge de un solo uso. */
export async function requestKeyChallenge(code: string): Promise<KeyChallenge> {
  let body: Record<string, unknown>;
  try {
    body = await request<Record<string, unknown>>("/keys/challenge", {
      method: "POST",
      body: JSON.stringify({ code: code.trim() }),
    });
  } catch (caught) {
    if (caught instanceof ApiError && caught.status === 403) throw new WrongStepUpCodeError();
    if (caught instanceof ApiError && caught.status === 429) {
      throw new StepUpRateLimitedError("Too many failed attempts. Request a new confirmation code.", caught.retryAfterSeconds, true);
    }
    throw caught;
  }
  // Fail-closed: si el servidor pide firmar otro formato, no se firma nada.
  if (body.purpose !== REGISTER_KEY_PURPOSE) throw new EnrollmentProtocolError("the server asked for a different registration format");
  if (typeof body.challenge_id !== "string" || !body.challenge_id || typeof body.nonce !== "string" || !body.nonce) {
    throw new EnrollmentProtocolError("unexpected challenge from the server");
  }
  return {
    challengeId: body.challenge_id,
    nonce: body.nonce,
    expiresInSeconds: typeof body.expires_in === "number" ? body.expires_in : 0,
  };
}

/** DELETE /keys/{key_id}: revoca una llave propia (libera cupo; no vuelve a registrarse). */
export async function revokeServerKey(keyId: string): Promise<void> {
  if (!keyId) throw new EnrollmentProtocolError("missing key id");
  await request<unknown>(`/keys/${encodeURIComponent(keyId)}`, { method: "DELETE" });
}

// ── Orquestación ────────────────────────────────────────────────────────────

/**
 * Estado actual de la llave. Sin soporte devuelve "unsupported" sin abrir IndexedDB
 * ni llamar al servidor.
 *
 * Reconcilia un único caso: la llave local no figura como registrada pero el
 * servidor SÍ la lista como activa de esta cuenta (p. ej. se cerró la pestaña entre
 * el 201 y el guardado local). Se anota el keyId del servidor; es nuestra pubkey y
 * nuestra cuenta, así que no se registra nada nuevo.
 */
export async function loadKeyState(email: string): Promise<KeyState> {
  const owner = normalizeEmail(email);
  const support = await detectEd25519Support();
  if (!support.supported) return { status: "unsupported", support, local: null, serverKeys: [] };

  let local = await getLocalKey(owner);
  const serverKeys = await listServerKeys();
  if (local && !local.registered) {
    const listed = serverKeys.find((key) => key.publicKey === local!.publicKeyHex);
    if (listed) local = await markLocalKeyRegistered(owner, local.publicKeyHex, listed.keyId);
  }
  const status = deriveKeyStatus({ supported: true, local, serverKeys });
  return { status, support, local, serverKeys };
}

/** Pasos 1–4: prepara la llave local y pide el código de step-up. */
export async function beginEnrollment(email: string): Promise<EnrollmentStart> {
  const owner = normalizeEmail(email);
  const state = await loadKeyState(owner);
  if (!state.support.supported) throw new UnsupportedBrowserError(state.support.reason, state.support.detail);
  if (state.status === "registered") return { kind: "already_registered", state };

  const local = state.status === "missing_on_server" && state.local
    ? await replaceLocalKey(owner, state.local.publicKeyHex)
    : await getOrCreateLocalKey(owner);

  const listed = state.serverKeys.some((key) => key.publicKey === local.publicKeyHex);
  if (!listed && state.serverKeys.length >= MAX_ACTIVE_KEYS_PER_OWNER) {
    return { kind: "limit_reached", keys: state.serverKeys };
  }

  const stepUp = await startStepUp();
  return { kind: "code_sent", stepUp, publicKeyHex: local.publicKeyHex };
}

/** Pasos 5–7: canjea el código, prueba posesión de la llave local y la registra. */
export async function completeEnrollment(email: string, code: string): Promise<EnrollmentCompletion> {
  const owner = normalizeEmail(email);
  // La llave primero: sin soporte falla aquí (UnsupportedBrowserError) sin gastar el código.
  const local = await getOrCreateLocalKey(owner);
  const challenge = await requestKeyChallenge(code);

  const payload = registrationPayload({
    challengeId: challenge.challengeId,
    nonce: challenge.nonce,
    ownerEmail: owner,
    publicKey: local.publicKeyHex,
  });
  const signature = await signCanonical(local.privateKey, payload);

  let created: ServerKey;
  try {
    created = parseServerKey(await request<unknown>("/keys", {
      method: "POST",
      body: JSON.stringify({ public_key: payload.public_key, challenge_id: payload.challenge_id, signature }),
    }));
  } catch (caught) {
    if (!(caught instanceof ApiError)) throw caught;
    if (caught.status === 403) throw new ProofRejectedError();
    if (caught.status === 422) throw new EnrollmentProtocolError(caught.detail ?? "the server rejected the request format");
    if (caught.status === 409) return resolveConflict(owner, local);
    throw caught;
  }

  // El servidor debe devolver LA llave que se firmó; si no, no se anota nada.
  if (created.publicKey !== local.publicKeyHex) throw new EnrollmentProtocolError("the server registered a different key");
  const record = await markLocalKeyRegistered(owner, local.publicKeyHex, created.keyId);
  return { kind: "registered", record, serverKey: created };
}

/**
 * 409 con una prueba de posesión VÁLIDA: la llave no se puede registrar. Desde el
 * 2.4 nadie puede registrar nuestra pubkey sin nuestra privada, así que las causas
 * reales son dos y GET /keys las distingue sin leer el texto del error:
 *   - el tope de llaves activas está lleno → limit_reached;
 *   - la llave fue revocada (no se reactiva nunca) → se genera otra.
 */
async function resolveConflict(owner: string, local: LocalKeyRecord): Promise<EnrollmentCompletion> {
  const keys = await listServerKeys();
  if (keys.some((key) => key.publicKey === local.publicKeyHex)) {
    // El registro es idempotente: con la llave activa el servidor responde 201, no 409.
    throw new EnrollmentProtocolError("the server reported a conflict for a key it lists as active");
  }
  if (keys.length >= MAX_ACTIVE_KEYS_PER_OWNER) return { kind: "limit_reached", keys };
  const record = await replaceLocalKey(owner, local.publicKeyHex);
  return { kind: "key_replaced", record };
}
