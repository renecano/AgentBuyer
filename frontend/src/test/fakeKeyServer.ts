/**
 * Backend falso de /keys para los tests de enrolamiento: reproduce el contrato de
 * api/keys.py + core/key_challenges.py + core/owner_keys.py, en memoria y sin red.
 *
 * Lo importante es que VERIFICA de verdad la prueba de posesión: reconstruye el
 * mensaje canónico con el owner del "token" y el nonce que él emitió, y comprueba
 * la firma Ed25519 con la pubkey presentada. Un cliente que firmara otros bytes no
 * registra nada aquí, igual que en el backend real.
 *
 * Orden de POST /keys, como el real: pubkey mal formada → 422 (no consume) →
 * consumir challenge (desconocido/usado/ajeno → 403) → firma (mala → 403) →
 * registrar (otra cuenta / revocada / tope → 409; misma llave activa → idempotente).
 * El 429 de /keys/challenge (intentos agotados) trae Retry-After con lo que falta para
 * poder pedir otro código (3.3), como el real; aquí, el cooldown entero de reenvío.
 */
import { canonicalize } from "../lib/canonical";

export const FAKE_API_BASE = "http://127.0.0.1:8000";
const MAX_ACTIVE_KEYS = 10;
const MAX_OTP_ATTEMPTS = 5;
/** Cooldown de reenvío del OTP de step-up (core/email_otp: resend_cooldown_seconds). */
export const RESEND_COOLDOWN_SECONDS = 60;

export type FakeKey = {
  key_id: string;
  owner: string;
  public_key: string;
  alg: "ed25519";
  created_at: string;
  revoked_at: string | null;
};

export type FakeCall = { method: string; path: string; body: Record<string, unknown> | null; authorization: string | null };

type Challenge = { owner: string; nonce: string; used: boolean };

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(hex.match(/../g)!.map((pair) => parseInt(pair, 16)));
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

let counter = 0;
const nextId = (prefix: string) => `${prefix}_${(++counter).toString(16).padStart(32, "0")}`;

export class FakeKeyServer {
  readonly owner: string;
  readonly keys: FakeKey[] = [];
  readonly calls: FakeCall[] = [];
  /** Dev mode del backend: devuelve code_demo en step-up/start. */
  devMode = true;
  /** Si no es null, step-up/start responde 429 con este Retry-After. */
  stepUpRetryAfter: number | null = null;
  /** Interceptor para forzar una respuesta concreta en un endpoint (p. ej. un 422). */
  override: ((method: string, path: string) => Response | null) | null = null;

  private pendingCode: string | null = null;
  private failedAttempts = 0;
  private readonly challenges = new Map<string, Challenge>();
  private codeSeq = 0;

  constructor(owner: string) {
    this.owner = owner;
  }

  /** Para `vi.stubGlobal("fetch", server.fetch)`. */
  readonly fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (url.origin !== FAKE_API_BASE) throw new TypeError(`Unexpected origin in a hermetic test: ${url.origin}`);
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" && init.body ? (JSON.parse(init.body) as Record<string, unknown>) : null;
    this.calls.push({ method, path: url.pathname, body, authorization: headers.get("Authorization") });

    const forced = this.override?.(method, url.pathname);
    if (forced) return forced;
    if (!headers.get("Authorization")?.startsWith("Bearer ")) return json(401, { detail: "Not authenticated." });

    if (method === "GET" && url.pathname === "/keys") return this.listKeys();
    if (method === "POST" && url.pathname === "/keys/step-up/start") return this.startStepUp();
    if (method === "POST" && url.pathname === "/keys/challenge") return this.issueChallenge(body);
    if (method === "POST" && url.pathname === "/keys") return this.registerKey(body);
    const revoke = /^\/keys\/([^/]+)$/.exec(url.pathname);
    if (method === "DELETE" && revoke) return this.revoke(decodeURIComponent(revoke[1]));
    return json(404, { detail: "Not Found" });
  };

  // ── Helpers para preparar escenarios ──────────────────────────────────────

  /** Alta directa (p. ej. "otro dispositivo de la misma cuenta"). */
  seedKey(publicKey: string, revoked = false): FakeKey {
    const key: FakeKey = {
      key_id: nextId("key"),
      owner: this.owner,
      public_key: publicKey,
      alg: "ed25519",
      created_at: new Date().toISOString(),
      revoked_at: revoked ? new Date().toISOString() : null,
    };
    this.keys.push(key);
    return key;
  }

  activeKeys(): FakeKey[] {
    return this.keys.filter((key) => key.owner === this.owner && key.revoked_at === null);
  }

  revokeDirectly(publicKey: string): void {
    const key = this.keys.find((candidate) => candidate.public_key === publicKey);
    if (!key) throw new Error("No such key in the fake server.");
    key.revoked_at = new Date().toISOString();
  }

  /** Vence todos los challenges emitidos (como si pasaran los 120 s). */
  expireChallenges(): void {
    this.challenges.clear();
  }

  callsTo(method: string, path: string): FakeCall[] {
    return this.calls.filter((call) => call.method === method && call.path === path);
  }

  // ── Endpoints ─────────────────────────────────────────────────────────────

  private publicView(key: FakeKey) {
    return { key_id: key.key_id, public_key: key.public_key, alg: key.alg, created_at: key.created_at };
  }

  private listKeys(): Response {
    return json(200, { keys: this.activeKeys().map((key) => this.publicView(key)) });
  }

  private startStepUp(): Response {
    if (this.stepUpRetryAfter !== null) {
      return json(429, { detail: "Too many confirmation code requests. Try again later." }, { "Retry-After": String(this.stepUpRetryAfter) });
    }
    this.pendingCode = String(100000 + (++this.codeSeq));
    this.failedAttempts = 0;
    const body: Record<string, unknown> = { ok: true, email_hint: "***rta@example.com", sent_via: "dev", expires_in_seconds: 300 };
    if (this.devMode) body.code_demo = this.pendingCode;
    return json(200, body);
  }

  /** El código vigente (lo que la persona leería en su correo). */
  currentCode(): string {
    if (!this.pendingCode) throw new Error("No step-up code was issued.");
    return this.pendingCode;
  }

  private issueChallenge(body: Record<string, unknown> | null): Response {
    // Como EmailOtpService.verify: al agotar los intentos el código se BORRA (429);
    // después ya no hay código y cualquier intento es 403.
    if (this.pendingCode === null || body?.code !== this.pendingCode) {
      if (this.pendingCode !== null) {
        this.failedAttempts += 1;
        if (this.failedAttempts >= MAX_OTP_ATTEMPTS) {
          this.pendingCode = null;
          return json(429, { detail: "Too many failed attempts. Request a new confirmation code." }, { "Retry-After": String(RESEND_COOLDOWN_SECONDS) });
        }
      }
      return json(403, { detail: "A fresh confirmation code is required to register a key." });
    }
    this.pendingCode = null; // uso único
    const challengeId = nextId("chl");
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
    this.challenges.set(challengeId, { owner: this.owner, nonce, used: false });
    return json(201, { challenge_id: challengeId, nonce, expires_in: 120, purpose: "agentbuyer:register-key:v1" });
  }

  private async registerKey(body: Record<string, unknown> | null): Promise<Response> {
    const publicKey = typeof body?.public_key === "string" ? body.public_key.trim().toLowerCase() : "";
    if (!/^[0-9a-f]{64}$/.test(publicKey) || typeof body?.challenge_id !== "string" || typeof body?.signature !== "string") {
      return json(422, { detail: "La llave pública Ed25519 debe tener 64 caracteres hex." });
    }
    const challenge = this.challenges.get(body.challenge_id);
    if (!challenge || challenge.owner !== this.owner) return json(403, { detail: "Unknown challenge. Request a new one." });
    if (challenge.used) return json(403, { detail: "The challenge was already used. Request a new one." });
    challenge.used = true; // se quema antes de mirar la firma

    const message = canonicalize({
      purpose: "agentbuyer:register-key:v1",
      challenge_id: body.challenge_id,
      nonce: challenge.nonce,
      owner: this.owner,
      public_key: publicKey,
    });
    let valid = false;
    try {
      const verifier = await crypto.subtle.importKey("raw", hexToBytes(publicKey), { name: "Ed25519" }, false, ["verify"]);
      valid = /^[0-9a-f]{128}$/.test(body.signature)
        && await crypto.subtle.verify({ name: "Ed25519" }, verifier, hexToBytes(body.signature), new TextEncoder().encode(message));
    } catch {
      valid = false;
    }
    if (!valid) return json(403, { detail: "The signature does not prove possession of this key. Request a new challenge." });

    const holder = this.keys.find((key) => key.public_key === publicKey);
    if (holder) {
      if (holder.owner !== this.owner) return json(409, { detail: "Esa llave pública ya está registrada por otra cuenta." });
      if (holder.revoked_at !== null) return json(409, { detail: "Esa llave fue revocada y no puede volver a registrarse." });
      return json(201, this.publicView(holder)); // idempotente
    }
    if (this.activeKeys().length >= MAX_ACTIVE_KEYS) return json(409, { detail: "Máximo 10 llaves activas por cuenta." });
    return json(201, this.publicView(this.seedKey(publicKey)));
  }

  private revoke(keyId: string): Response {
    const key = this.keys.find((candidate) => candidate.key_id === keyId);
    if (!key || key.revoked_at !== null) return json(404, { detail: "Key not found." });
    if (key.owner !== this.owner) return json(403, { detail: "This key belongs to another account." });
    key.revoked_at = new Date().toISOString();
    return json(200, { key_id: keyId, revoked_at: key.revoked_at });
  }
}

/** Una pubkey Ed25519 válida y nueva (para simular otros dispositivos). */
export async function randomPublicKeyHex(): Promise<string> {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return Array.from(raw, (b) => b.toString(16).padStart(2, "0")).join("");
}
