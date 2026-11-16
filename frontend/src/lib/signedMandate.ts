/**
 * El humano firma su mandato con la llave del dispositivo (paso 3.4).
 *
 * El wizard arma un borrador con lo que la persona eligió; aquí se convierte en el
 * mensaje de la spec v1 (lib/mandateMessage.ts), se firma con la llave Ed25519 NO
 * extraíble del keystore (signCanonical) y se envía a POST /mandates en el formato
 * firmado que el backend verifica desde el 3.3.
 *
 * - La firma se calcula en el momento de autorizar, cada vez: nunca se reutiliza. Si
 *   la persona cambia un límite, la próxima firma es otra.
 * - Montos: el texto que la persona tecleó ("150", "89.99") viaja tal cual; la spec lo
 *   convierte a centavos sin pasar por float, en los dos lados.
 * - Vigencia (D-19): la fecha elegida vence al FINAL de ese día en la zona horaria
 *   local del navegador (23:59:59), convertida a UTC con Z.
 * - Errores: 403 → la llave ya no vale (recargar su estado); 409 → nonce nuevo y UN
 *   reintento; 422 → error del formulario con el campo.
 */
import { ApiError, request } from "./api";
import { getLocalKey, normalizeEmail, type LocalKeyRecord } from "./keystore";
import {
  MandateMessageError,
  mandateSigningPayload,
  newMandateNonce,
  toSignedTimestamp,
  type MandateConstraintsInput,
  type MandateMessageInput,
  type MandateSigningPayload,
} from "./mandateMessage";
import { signCanonical } from "./signing";

/** Lo que la persona eligió en el wizard (antes de firmar). */
export type MandateDraft = {
  mandateId: string;
  /** Contacto (PII): viaja con el mandato pero NO se firma (no autoriza nada). */
  human: Record<string, string>;
  agent: { id: string; display_name?: string };
  constraints: MandateConstraintsInput;
  searchFields: Record<string, string | number> | null;
  /** Fecha elegida "válido hasta" (YYYY-MM-DD, en la zona local). */
  validUntil: string;
};

/** Cuerpo de POST /mandates en formato firmado (3.2/3.3). Nada fuera de la spec. */
export type SignedMandateBody = {
  mandate_id: string;
  human: Record<string, string>;
  agent: { id: string; display_name?: string };
  constraints: MandateConstraintsInput;
  search_fields: Record<string, string | number>;
  expires_at: string;
  created_at: string;
  nonce: string;
  key_id: string;
  signature: string;
};

export type SignedMandate = { body: SignedMandateBody; payload: MandateSigningPayload };

/** Este navegador no tiene una llave registrada para la cuenta: hay que enrolar el dispositivo. */
export class DeviceKeyNotReadyError extends Error {
  constructor(message = "Register this device before authorizing: your permission is signed with its key.") {
    super(message);
    this.name = "DeviceKeyNotReadyError";
  }
}

/** 403: el servidor no aceptó la llave o la firma (revocada, de otra cuenta…). */
export class SigningKeyRejectedError extends Error {
  constructor(message = "The server didn't accept this device's key. Check the device card and register it again if needed.") {
    super(message);
    this.name = "SigningKeyRejectedError";
  }
}

/** Un campo del formulario no cumple la spec (validación local o 422 del servidor). */
export class MandateFieldError extends Error {
  readonly field: string;

  constructor(field: string, message: string) {
    super(message);
    this.name = "MandateFieldError";
    this.field = field;
  }
}

// ── Vigencia (D-19) ─────────────────────────────────────────────────────────

/** Zona horaria IANA del navegador (p. ej. "America/Mexico_City"). */
export function localTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone;
}

/** Desfase (ms) de `timeZone` respecto de UTC en el instante dado: local − UTC. */
function zoneOffsetMs(instant: number, timeZone: string): number {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).formatToParts(new Date(instant));
  const value = (type: Intl.DateTimeFormatPartTypes) => Number(parts.find((part) => part.type === type)?.value);
  const wallAsUtc = Date.UTC(value("year"), value("month") - 1, value("day"), value("hour"), value("minute"), value("second"));
  return wallAsUtc - Math.floor(instant / 1000) * 1000;
}

/** Fecha local (YYYY-MM-DD) del instante en `timeZone`. */
function localDateKey(instant: Date, timeZone: string): string {
  const parts = new Intl.DateTimeFormat("en-CA", { timeZone, year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(instant);
  const value = (type: Intl.DateTimeFormatPartTypes) => parts.find((part) => part.type === type)?.value;
  return `${value("year")}-${value("month")}-${value("day")}`;
}

/**
 * Instante UTC del final (23:59:59) del día `dateKey` en `timeZone` (por defecto, la
 * zona del navegador). Dos pasadas: la segunda corrige un cambio de horario de verano.
 */
export function endOfLocalDay(dateKey: string, timeZone: string = localTimeZone()): Date {
  const match = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/.exec(dateKey);
  if (!match) throw new MandateFieldError("expires_at", "Choose until when the permission is valid.");
  const [year, month, day] = match.slice(1).map(Number);
  const wall = Date.UTC(year, month - 1, day, 23, 59, 59);
  let instant = wall - zoneOffsetMs(wall, timeZone);
  instant = wall - zoneOffsetMs(instant, timeZone);
  const result = new Date(instant);
  if (Number.isNaN(result.getTime()) || localDateKey(result, timeZone) !== dateKey) {
    throw new MandateFieldError("expires_at", "That date doesn't exist. Choose another one.");
  }
  return result;
}

/** "Nov 30, 2026, 11:59:59 PM CST (America/Mexico_City)": fecha, hora y zona, para la persona. */
export function describeExpiry(expiresAt: string | Date, timeZone: string = localTimeZone()): string {
  const date = typeof expiresAt === "string" ? new Date(expiresAt) : expiresAt;
  const text = new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "long", timeZone }).format(date);
  return `${text} (${timeZone})`;
}

// ── Firma ───────────────────────────────────────────────────────────────────

/** Llave local registrada de `email`, o DeviceKeyNotReadyError. */
export async function registeredDeviceKey(email: string): Promise<LocalKeyRecord & { keyId: string }> {
  const key = await getLocalKey(email);
  if (!key || !key.registered || !key.keyId) throw new DeviceKeyNotReadyError();
  return key as LocalKeyRecord & { keyId: string };
}

/**
 * Firma el borrador con la llave del dispositivo. Pura salvo por la firma: `now` y
 * `nonce` se inyectan (tests deterministas). Los errores de la spec salen como
 * MandateFieldError ANTES de enviar nada.
 */
export async function signMandateDraft(
  draft: MandateDraft,
  ownerEmail: string,
  key: Pick<LocalKeyRecord, "privateKey" | "publicKeyHex"> & { keyId: string },
  now: Date,
  nonce: string,
  timeZone: string = localTimeZone(),
): Promise<SignedMandate> {
  const createdAt = toSignedTimestamp(now);
  const expiresAt = toSignedTimestamp(endOfLocalDay(draft.validUntil, timeZone));
  if (expiresAt <= createdAt) {
    throw new MandateFieldError("expires_at", "The permission must be valid until a future date.");
  }
  const input: MandateMessageInput = {
    mandate_id: draft.mandateId,
    owner_email: normalizeEmail(ownerEmail),
    key_id: key.keyId,
    public_key: key.publicKeyHex,
    agent_id: draft.agent.id,
    constraints: draft.constraints,
    search_fields: draft.searchFields,
    expires_at: expiresAt,
    created_at: createdAt,
    nonce,
  };
  let payload: MandateSigningPayload;
  try {
    payload = mandateSigningPayload(input);
  } catch (caught) {
    if (caught instanceof MandateMessageError) throw new MandateFieldError(caught.field, caught.message);
    throw caught;
  }
  const signature = await signCanonical(key.privateKey, payload);
  return {
    payload,
    body: {
      mandate_id: payload.mandate_id,
      human: draft.human,
      agent: draft.agent,
      constraints: draft.constraints,
      search_fields: payload.search_fields,
      expires_at: expiresAt,
      created_at: createdAt,
      nonce,
      key_id: key.keyId,
      signature,
    },
  };
}

type CreateOptions = {
  now?: () => Date;
  newNonce?: () => string;
  timeZone?: string;
};

/** "constraints.max_amount_per_purchase: must be…" → campo. */
function fieldOf(detail: string | null): string {
  const match = detail ? /^([a-z_][a-z0-9_.]*):/i.exec(detail) : null;
  return match ? match[1] : "mandate";
}

/**
 * Firma y crea el mandato. Devuelve el registro {mandate, live_state} del servidor.
 * 409 (nonce ya usado o carrera): UN reintento con nonce y created_at nuevos (y por
 * lo tanto una firma nueva). 403 → SigningKeyRejectedError. 422 → MandateFieldError.
 */
export async function createSignedMandate<T = unknown>(draft: MandateDraft, ownerEmail: string, options: CreateOptions = {}): Promise<T> {
  const now = options.now ?? (() => new Date());
  const newNonce = options.newNonce ?? newMandateNonce;
  const key = await registeredDeviceKey(ownerEmail);

  for (let attempt = 0; ; attempt += 1) {
    const { body } = await signMandateDraft(draft, ownerEmail, key, now(), newNonce(), options.timeZone);
    try {
      return await request<T>("/mandates", { method: "POST", body: JSON.stringify(body) });
    } catch (caught) {
      if (!(caught instanceof ApiError)) throw caught;
      if (caught.status === 409 && attempt === 0) continue;
      if (caught.status === 403) throw new SigningKeyRejectedError();
      if (caught.status === 422) throw new MandateFieldError(fieldOf(caught.detail), caught.detail ?? caught.message);
      throw caught;
    }
  }
}
