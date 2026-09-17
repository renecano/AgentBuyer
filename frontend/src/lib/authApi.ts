/**
 * Login por OTP de email contra el backend (api/auth.py).
 *
 * verifyEmailLogin DEVUELVE el access token y falla si el backend no lo entrega;
 * startEmailLogin expone el cooldown del 429 (Retry-After, expuesto por CORS).
 */
import { ApiError, request } from "./api";

export type AuthRole = "user" | "admin";

export type EmailLoginStart = {
  /** Email enmascarado para mostrar ("***rta@example.com"). */
  emailHint: string;
  /** Validez del código en segundos. */
  codeExpiresInSeconds: number;
  /** "smtp" si se envió por correo, "dev" si el backend está en AUTH_DEV_MODE. */
  sentVia: string;
  /** El código en claro: SOLO llega con AUTH_DEV_MODE=true en el backend. */
  codeDemo: string | null;
};

export type AccessToken = {
  accessToken: string;
  tokenType: "bearer";
  /** Vida del token en segundos. */
  expiresIn: number;
  /** Email verificado (sujeto del token). */
  email: string;
  /** Rol leído del token, solo para la UI: la autorización real la decide el backend. */
  role: AuthRole;
};

/** Se pidieron demasiados códigos (429): hay que esperar `retryAfterSeconds`. */
export class LoginRateLimitedError extends Error {
  readonly retryAfterSeconds: number | null;

  constructor(message: string, retryAfterSeconds: number | null) {
    super(message);
    this.name = "LoginRateLimitedError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** El backend respondió 2xx pero sin un token utilizable. */
export class InvalidTokenResponseError extends Error {
  constructor(message = "The server did not return a valid access token.") {
    super(message);
    this.name = "InvalidTokenResponseError";
  }
}

type StartResponse = {
  email_hint?: unknown;
  expires_in_seconds?: unknown;
  sent_via?: unknown;
  code_demo?: unknown;
};

type CheckResponse = {
  email?: unknown;
  access_token?: unknown;
  token_type?: unknown;
  expires_in?: unknown;
};

function postJson<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: "POST", body: JSON.stringify(body), skipAuth: true });
}

/** Pide un código de verificación para `email` (POST /auth/email/start). */
export async function startEmailLogin(email: string): Promise<EmailLoginStart> {
  try {
    const response = await postJson<StartResponse>("/auth/email/start", { email: email.trim() });
    return {
      emailHint: typeof response.email_hint === "string" ? response.email_hint : "",
      codeExpiresInSeconds: typeof response.expires_in_seconds === "number" ? response.expires_in_seconds : 0,
      sentVia: typeof response.sent_via === "string" ? response.sent_via : "",
      codeDemo: typeof response.code_demo === "string" && response.code_demo ? response.code_demo : null,
    };
  } catch (caught) {
    if (caught instanceof ApiError && caught.status === 429) {
      throw new LoginRateLimitedError(caught.message, caught.retryAfterSeconds);
    }
    throw caught;
  }
}

/** Lee el rol del payload del JWT SIN verificarlo (no hay secreto en el cliente): solo para la UI. */
function roleFromToken(token: string): AuthRole {
  try {
    const payload = token.split(".")[1];
    if (!payload) return "user";
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(payload.length / 4) * 4, "=");
    const claims = JSON.parse(atob(base64)) as { role?: unknown };
    return claims.role === "admin" ? "admin" : "user";
  } catch {
    return "user";
  }
}

/**
 * Verifica el código (POST /auth/email/check) y devuelve el access token.
 * Lanza ApiError si el código es incorrecto/expirado (401) o se agotaron los
 * intentos (429), e InvalidTokenResponseError si la respuesta no trae un token válido.
 */
export async function verifyEmailLogin(email: string, code: string): Promise<AccessToken> {
  const response = await postJson<CheckResponse>("/auth/email/check", { email: email.trim(), code: code.trim() });

  const { access_token: accessToken, token_type: tokenType, expires_in: expiresIn } = response;
  if (typeof accessToken !== "string" || accessToken.split(".").length !== 3) {
    throw new InvalidTokenResponseError();
  }
  if (typeof tokenType !== "string" || tokenType.toLowerCase() !== "bearer") {
    throw new InvalidTokenResponseError("The server returned an unsupported token type.");
  }
  if (typeof expiresIn !== "number" || !Number.isFinite(expiresIn) || expiresIn <= 0) {
    throw new InvalidTokenResponseError("The server returned an invalid token lifetime.");
  }

  return {
    accessToken,
    tokenType: "bearer",
    expiresIn,
    email: typeof response.email === "string" ? response.email : email.trim().toLowerCase(),
    role: roleFromToken(accessToken),
  };
}
