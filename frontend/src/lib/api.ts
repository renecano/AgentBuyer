/**
 * Cliente HTTP único del frontend.
 *
 * - API_BASE configurable con VITE_API_BASE (default http://127.0.0.1:8000).
 * - request / requestWithTimeout: mismo comportamiento que los helpers que vivían
 *   en App.tsx (Content-Type JSON, `detail` del backend traducido a error legible,
 *   abort por timeout o señal externa → null).
 * - Token: si el getter registrado (setTokenGetter) devuelve un token, se envía
 *   `Authorization: Bearer <token>`. Por defecto no hay getter → no se envía nada.
 * - 401: si se registró un handler (setUnauthorizedHandler) y la petición llevaba
 *   token, se le avisa. Todavía no hay handler registrado.
 */
import { translateBackendText } from "./presentation";

const DEFAULT_API_BASE = "http://127.0.0.1:8000";

export const API_BASE = (import.meta.env.VITE_API_BASE?.trim() || DEFAULT_API_BASE).replace(/\/+$/, "");

/** Error de una respuesta HTTP no-2xx del backend. */
export class ApiError extends Error {
  readonly status: number;
  /** `detail` crudo del backend (sin traducir), si vino como texto. */
  readonly detail: string | null;
  /** Segundos del header Retry-After (p. ej. en un 429), si vino. */
  readonly retryAfterSeconds: number | null;

  constructor(status: number, message: string, detail: string | null, retryAfterSeconds: number | null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

type TokenGetter = () => string | null;
type UnauthorizedHandler = (error: ApiError) => void;

let tokenGetter: TokenGetter = () => null;
let unauthorizedHandler: UnauthorizedHandler | null = null;

/** Registra de dónde sale el token de acceso. Devuelve una función para desregistrarlo. */
export function setTokenGetter(getter: TokenGetter): () => void {
  tokenGetter = getter;
  return () => {
    if (tokenGetter === getter) tokenGetter = () => null;
  };
}

/** Registra qué hacer ante un 401 de una petición autenticada (p. ej. volver al login). */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): () => void {
  unauthorizedHandler = handler;
  return () => {
    if (unauthorizedHandler === handler) unauthorizedHandler = null;
  };
}

function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds);
  const date = Date.parse(value);
  return Number.isNaN(date) ? null : Math.max(0, Math.ceil((date - Date.now()) / 1000));
}

export type RequestOptions = RequestInit & {
  /** No adjuntar el token (p. ej. endpoints de login: un 401 ahí es "código incorrecto", no sesión caída). */
  skipAuth?: boolean;
};

export async function request<T>(path: string, options?: RequestOptions): Promise<T> {
  const { skipAuth = false, ...init } = options ?? {};
  const headers = new Headers(init.headers);
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const token = skipAuth ? null : tokenGetter();
  if (token && !headers.has("Authorization")) headers.set("Authorization", `Bearer ${token}`);

  const response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!response.ok) {
    // El backend explica sus 404/409/422 en `detail`; se traduce en la capa de
    // presentación (clave para los errores de la revisión humana).
    let message = `The system responded ${response.status}.`;
    let detail: string | null = null;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string" && body.detail) {
        detail = body.detail;
        message = translateBackendText(body.detail);
      }
    } catch { /* cuerpo no-JSON: se conserva el mensaje genérico */ }

    const error = new ApiError(response.status, message, detail, parseRetryAfter(response.headers.get("Retry-After")));
    if (response.status === 401 && token && unauthorizedHandler) unauthorizedHandler(error);
    throw error;
  }
  return response.json() as Promise<T>;
}

/** Como request, pero aborta a los `timeoutMs` o cuando se aborta `externalSignal`; en ese caso devuelve null. */
export async function requestWithTimeout<T>(
  path: string,
  options: RequestOptions,
  timeoutMs: number,
  externalSignal?: AbortSignal,
): Promise<T | null> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  externalSignal?.addEventListener("abort", abort, { once: true });
  const timeout = window.setTimeout(abort, timeoutMs);
  try {
    return await request<T>(path, { ...options, signal: controller.signal });
  } catch (caught) {
    if (controller.signal.aborted) return null;
    throw caught;
  } finally {
    window.clearTimeout(timeout);
    externalSignal?.removeEventListener("abort", abort);
  }
}
