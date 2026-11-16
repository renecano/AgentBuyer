/**
 * Tarjeta "Register this device": enrola la llave Ed25519 no extraíble de este
 * navegador en la cuenta de la sesión (lib/enrollment.ts, paso 3.1).
 *
 * Desde el 3.4 es requisito para autorizar: el wizard firma cada permiso con esta
 * llave. La tarjeta informa su estado al wizard (onStatusChange) y el wizard puede
 * pedirle que lo vuelva a leer (refreshSignal), p. ej. tras un 403 o tras enrolar
 * en la demo. Se monta con key={email}: si cambia la cuenta, empieza de cero.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../lib/api";
import {
  EnrollmentProtocolError,
  MAX_ACTIVE_KEYS_PER_OWNER,
  ProofRejectedError,
  StepUpRateLimitedError,
  WrongStepUpCodeError,
  beginEnrollment,
  completeEnrollment,
  listServerKeys,
  loadKeyState,
  revokeServerKey,
  type EnrollmentStart,
  type KeyStatus,
  type ServerKey,
} from "../lib/enrollment";
import { LocalKeyChangedError, UNSUPPORTED_BROWSER_MESSAGE, UnsupportedBrowserError } from "../lib/keystore";

type View =
  | { name: "loading" }
  | { name: "load_failed" }
  | { name: "unsupported" }
  | { name: "ready"; status: Exclude<KeyStatus, "unsupported" | "registered"> }
  | { name: "awaiting_code"; emailHint: string; codeDemo: string | null; needsNewCode: boolean }
  | { name: "limit"; keys: ServerKey[] }
  | { name: "registered"; keyId: string; publicKeyHex: string };

type Busy = "loading" | "sending" | "confirming" | { revoking: string } | null;

const READY_COPY: Record<Exclude<KeyStatus, "unsupported" | "registered">, string> = {
  none: "Create a signing key on this device and link it to your account.",
  local_unregistered: "This device has a signing key that isn't linked to your account yet.",
  missing_on_server: "Your account no longer lists this device's key (it may have been revoked). Register again to create a new one.",
};

function shortHex(hex: string) {
  return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}

function formatDate(timestamp: string) {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime())
    ? timestamp
    : new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

/** Mensaje para la persona. Los errores propios ya traen el texto; el resto se resume. */
function messageFor(caught: unknown): string {
  if (caught instanceof UnsupportedBrowserError) return caught.message;
  if (
    caught instanceof WrongStepUpCodeError
    || caught instanceof ProofRejectedError
    || caught instanceof EnrollmentProtocolError
    || caught instanceof LocalKeyChangedError
    || caught instanceof StepUpRateLimitedError
  ) return caught.message;
  if (caught instanceof ApiError) return caught.message;
  return "No connection to the system. Check your connection and try again.";
}

/** Lo que el wizard necesita saber: ¿se puede firmar ya con este dispositivo? */
export type DeviceKeyStatus =
  | { status: "loading" }
  | { status: "registered"; keyId: string }
  | { status: Exclude<KeyStatus, "registered"> | "unavailable" };

type DeviceKeyCardProps = {
  email: string;
  onStatusChange?: (status: DeviceKeyStatus) => void;
  /** Cambiarlo hace que la tarjeta vuelva a leer el estado de la llave. */
  refreshSignal?: number;
};

function statusOf(view: View): DeviceKeyStatus {
  switch (view.name) {
    case "registered": return { status: "registered", keyId: view.keyId };
    case "ready": return { status: view.status };
    case "unsupported": return { status: "unsupported" };
    case "loading": return { status: "loading" };
    default: return { status: "unavailable" };
  }
}

export default function DeviceKeyCard({ email, onStatusChange, refreshSignal = 0 }: DeviceKeyCardProps) {
  const [view, setView] = useState<View>({ name: "loading" });
  const [busy, setBusy] = useState<Busy>("loading");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [cooldownSeconds, setCooldownSeconds] = useState(0);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);

  useEffect(() => {
    if (cooldownSeconds <= 0) return undefined;
    const timer = window.setTimeout(() => setCooldownSeconds((seconds) => Math.max(0, seconds - 1)), 1000);
    return () => window.clearTimeout(timer);
  }, [cooldownSeconds]);

  const refresh = useCallback(async () => {
    setBusy("loading");
    try {
      const state = await loadKeyState(email);
      if (!alive.current) return;
      if (state.status === "unsupported") setView({ name: "unsupported" });
      else if (state.status === "registered" && state.local?.keyId) setView({ name: "registered", keyId: state.local.keyId, publicKeyHex: state.local.publicKeyHex });
      else if (state.status !== "registered") setView({ name: "ready", status: state.status });
    } catch (caught) {
      if (!alive.current) return;
      setView({ name: "load_failed" });
      setError(messageFor(caught));
    } finally {
      if (alive.current) setBusy(null);
    }
  }, [email]);

  useEffect(() => { void refresh(); }, [refresh, refreshSignal]);

  // El wizard solo autoriza con status "registered"; cualquier otra vista lo bloquea.
  const reported = statusOf(view);
  const reportedKey = reported.status === "registered" ? `registered:${reported.keyId}` : reported.status;
  useEffect(() => {
    onStatusChange?.(reported);
    // reportedKey resume `reported` (objeto nuevo en cada render): se avisa solo si cambia.
  }, [reportedKey, onStatusChange]);

  function applyStart(start: EnrollmentStart) {
    if (start.kind === "code_sent") {
      setView({ name: "awaiting_code", emailHint: start.stepUp.emailHint, codeDemo: start.stepUp.codeDemo, needsNewCode: false });
    } else if (start.kind === "limit_reached") {
      setView({ name: "limit", keys: start.keys });
    } else if (start.state.local?.keyId) {
      setView({ name: "registered", keyId: start.state.local.keyId, publicKeyHex: start.state.local.publicKeyHex });
    }
  }

  async function sendCode() {
    setBusy("sending");
    setError(null);
    setCode("");
    try {
      const start = await beginEnrollment(email);
      if (alive.current) applyStart(start);
    } catch (caught) {
      if (!alive.current) return;
      if (caught instanceof UnsupportedBrowserError) setView({ name: "unsupported" });
      if (caught instanceof StepUpRateLimitedError && caught.retryAfterSeconds) setCooldownSeconds(caught.retryAfterSeconds);
      setError(messageFor(caught));
    } finally {
      if (alive.current) setBusy(null);
    }
  }

  async function confirmCode() {
    if (view.name !== "awaiting_code") return;
    setBusy("confirming");
    setError(null);
    setNotice(null);
    try {
      const result = await completeEnrollment(email, code);
      if (!alive.current) return;
      setCode("");
      if (result.kind === "registered") {
        setView({ name: "registered", keyId: result.record.keyId!, publicKeyHex: result.record.publicKeyHex });
        setNotice("This device is now registered.");
      } else if (result.kind === "limit_reached") {
        setView({ name: "limit", keys: result.keys });
      } else {
        // La llave anterior fue revocada y no puede volver: ya hay una nueva; se
        // pide otro código para registrarla (cada código sirve para un solo intento).
        setNotice("This device's previous key was revoked, so we created a new one. Enter the new code we just sent to finish.");
        setBusy("sending");
        applyStart(await beginEnrollment(email));
      }
    } catch (caught) {
      if (!alive.current) return;
      if (caught instanceof StepUpRateLimitedError || caught instanceof ProofRejectedError) {
        // El código o el challenge ya no sirven: hay que pedir uno nuevo.
        setView({ ...view, needsNewCode: true, codeDemo: null });
        setCode("");
        if (caught instanceof StepUpRateLimitedError && caught.retryAfterSeconds) setCooldownSeconds(caught.retryAfterSeconds);
      }
      if (caught instanceof UnsupportedBrowserError) setView({ name: "unsupported" });
      if (caught instanceof LocalKeyChangedError) void refresh();
      setError(messageFor(caught));
    } finally {
      if (alive.current) setBusy(null);
    }
  }

  async function revoke(keyId: string) {
    setBusy({ revoking: keyId });
    setError(null);
    try {
      await revokeServerKey(keyId);
      const keys = await listServerKeys();
      if (alive.current) setView({ name: "limit", keys });
    } catch (caught) {
      if (alive.current) setError(messageFor(caught));
    } finally {
      if (alive.current) setBusy(null);
    }
  }

  const working = busy !== null;
  const status = view.name === "registered" ? "complete" : view.name === "awaiting_code" || working ? "processing" : "pending";
  const chip = view.name === "registered" ? "REGISTERED" : view.name === "unsupported" ? "UNAVAILABLE" : working || view.name === "awaiting_code" ? "IN PROGRESS" : "REQUIRED";

  return (
    <section className={`verify-item is-${status}`} aria-labelledby="device-key-title">
      <header className="verify-item-heading">
        <span className="verify-item-number" aria-hidden="true">{view.name === "registered" ? "✓" : "🔑"}</span>
        <div className="verify-item-title">
          <b id="device-key-title">Register this device</b>
          <small>
            {view.name === "registered" ? `Registered key ${shortHex(view.publicKeyHex)}`
              : view.name === "awaiting_code" ? `Confirmation code sent to ${view.emailHint || email}`
              : view.name === "ready" ? READY_COPY[view.status]
              : view.name === "limit" ? `Your account already has ${MAX_ACTIVE_KEYS_PER_OWNER} registered devices`
              : view.name === "unsupported" ? "This browser can't hold a secure signing key"
              : view.name === "load_failed" ? "Couldn't check this device's key"
              : "Checking this device…"}
          </small>
        </div>
        <em className={`verify-chip is-${status}`}>{chip}</em>
      </header>

      <div className="verify-item-body" aria-live="polite">
        {view.name === "unsupported" && <p className="verify-hint verify-hint-warn" role="alert">{UNSUPPORTED_BROWSER_MESSAGE}</p>}

        {view.name === "ready" && <>
          <p className="verify-hint">
            The private key is created in this browser and can't be exported, not even by this app. Registering it needs a fresh code sent to your email. Every permission you authorize is signed with this key, so you need it to continue.
          </p>
          <button className="verify-action" type="button" onClick={() => void sendCode()} disabled={working || cooldownSeconds > 0}>
            {busy === "sending" ? "Sending…" : cooldownSeconds > 0 ? `Try again in ${cooldownSeconds}s` : "Register this device"}
          </button>
        </>}

        {view.name === "awaiting_code" && <>
          {!view.needsNewCode && <div className="otp-code-controls">
            <input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" placeholder="6-digit code" aria-label="Device confirmation code" disabled={working} />
            <button className="verify-action verify-action-confirm" type="button" onClick={() => void confirmCode()} disabled={working || code.length !== 6}>
              {busy === "confirming" ? "Registering…" : "Confirm and register"}
            </button>
          </div>}
          {view.codeDemo && !view.needsNewCode && (
            <p className="verify-hint verify-hint-tip">
              Development mode (AUTH_DEV_MODE): your code is <b>{view.codeDemo}</b>.{" "}
              <button className="verify-edit" type="button" onClick={() => setCode(view.codeDemo!)}>Use it</button>
            </p>
          )}
          <button className="verify-action" type="button" onClick={() => void sendCode()} disabled={working || cooldownSeconds > 0}>
            {busy === "sending" ? "Sending…" : cooldownSeconds > 0 ? `Try again in ${cooldownSeconds}s` : "Send a new code"}
          </button>
        </>}

        {view.name === "limit" && <>
          <p className="verify-hint verify-hint-warn">
            {view.keys.length >= MAX_ACTIVE_KEYS_PER_OWNER
              ? "Revoke a device you no longer use to register this one. A revoked key can't be registered again."
              : "There's room for this device now. Continue to register it with a new code."}
          </p>
          <ul className="device-key-list">
            {view.keys.map((key) => (
              <li key={key.keyId}>
                <span><b>{shortHex(key.publicKey)}</b><small>Added {formatDate(key.createdAt)}</small></span>
                <button className="verify-edit" type="button" onClick={() => void revoke(key.keyId)} disabled={working}>
                  {typeof busy === "object" && busy?.revoking === key.keyId ? "Revoking…" : "Revoke"}
                </button>
              </li>
            ))}
          </ul>
          {view.keys.length < MAX_ACTIVE_KEYS_PER_OWNER && (
            <button className="verify-action" type="button" onClick={() => void sendCode()} disabled={working || cooldownSeconds > 0}>
              {busy === "sending" ? "Sending…" : cooldownSeconds > 0 ? `Try again in ${cooldownSeconds}s` : "Continue registration"}
            </button>
          )}
        </>}

        {view.name === "registered" && (
          <p className="verify-hint">Key ID {view.keyId}. It stays on this browser and can't be exported. Every permission you authorize here is signed with it.</p>
        )}

        {view.name === "load_failed" && (
          <button className="verify-action" type="button" onClick={() => { setError(null); void refresh(); }} disabled={working}>Try again</button>
        )}

        {cooldownSeconds > 0 && <p className="verify-hint verify-hint-warn">Too many code requests. You can request a new code in {cooldownSeconds}s.</p>}
        {notice && <p className="verify-hint verify-hint-tip" role="status">{notice}</p>}
        {error && <p className="verify-hint verify-hint-warn" role="alert">{error}</p>}
      </div>
    </section>
  );
}
