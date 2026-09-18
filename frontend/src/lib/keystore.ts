/**
 * Keystore local de la llave de firma del humano (Ed25519, WebCrypto nativo).
 *
 * - UNA sola vía: Ed25519 nativo de WebCrypto. Si el navegador no lo soporta, se
 *   lanza UnsupportedBrowserError con un mensaje para la persona. Sin librería de
 *   respaldo: una llave de librería sería extraíble (robable por un XSS) y el
 *   servidor no podría distinguir qué protección tiene cada llave.
 * - La privada se genera con extractable=false: sirve para firmar, pero sus bytes
 *   no se pueden leer desde JS (ni por un XSS). Se guarda en IndexedDB como
 *   CryptoKey (structured clone), sin serializar, y sigue no-extraíble al volver.
 * - Un registro por email (normalizado como el backend): varios usuarios pueden
 *   compartir navegador sin pisarse.
 *
 * Todavía NO está conectado a la app: ni se registra la llave en el servidor
 * (sub-pasos 2.3-2.5) ni se firman mandatos (2.6 / paso 3).
 */

export const KEYSTORE_DB = "agentbuyer-keys";
export const KEYSTORE_STORE = "signing-keys";
const KEYSTORE_VERSION = 1;
const ED25519 = "Ed25519";

export const UNSUPPORTED_BROWSER_MESSAGE =
  "Your browser doesn't support the security keys this app needs. Please update to a recent version of Chrome, Firefox, or Safari.";

export type UnsupportedReason = "no-webcrypto" | "no-ed25519" | "no-indexeddb";

export type KeySupport =
  | { supported: true }
  | { supported: false; reason: UnsupportedReason; detail: string };

/** El navegador no puede guardar llaves de firma seguras. `message` es para mostrar tal cual. */
export class UnsupportedBrowserError extends Error {
  readonly reason: UnsupportedReason;
  /** Diagnóstico técnico (para logs/soporte), no para la persona. */
  readonly detail: string;

  constructor(reason: UnsupportedReason, detail: string) {
    super(UNSUPPORTED_BROWSER_MESSAGE);
    this.name = "UnsupportedBrowserError";
    this.reason = reason;
    this.detail = detail;
  }
}

export type LocalKeyRecord = {
  /** Email normalizado (trim + minúsculas, igual que el backend). */
  email: string;
  /** Privada Ed25519, extractable=false. Se guarda como CryptoKey, nunca como bytes. */
  privateKey: CryptoKey;
  /** Pública en crudo (32 bytes) como hex de 64 caracteres. */
  publicKeyHex: string;
  /** Asignado por el servidor al registrar la llave (sub-paso 2.4). */
  keyId: string | null;
  registered: boolean;
  createdAt: string;
};

export type PersistResult = "granted" | "denied" | "unavailable";

// ── Utilidades ──────────────────────────────────────────────────────────────

export function bytesToHex(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Array.from(view, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Mismo criterio que el backend (core/owner_keys.normalize_owner_email). */
export function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (!normalized) throw new Error("An email is required to use the keystore.");
  return normalized;
}

// ── 2.1 Detección de soporte ────────────────────────────────────────────────

/**
 * ¿Puede este navegador generar, guardar y usar una llave Ed25519 no extraíble?
 * Lo comprueba haciéndolo (generar + firmar + verificar), no leyendo el user agent.
 */
export async function detectEd25519Support(): Promise<KeySupport> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    return { supported: false, reason: "no-webcrypto", detail: "crypto.subtle is unavailable (insecure context or very old browser)." };
  }
  if (!globalThis.indexedDB) {
    return { supported: false, reason: "no-indexeddb", detail: "indexedDB is unavailable." };
  }
  try {
    const probe = await subtle.generateKey({ name: ED25519 }, false, ["sign", "verify"]);
    const data = new Uint8Array([1, 2, 3]);
    const signature = await subtle.sign({ name: ED25519 }, probe.privateKey, data);
    if (!(await subtle.verify({ name: ED25519 }, probe.publicKey, signature, data))) {
      return { supported: false, reason: "no-ed25519", detail: "Ed25519 sign/verify round-trip failed." };
    }
  } catch (caught) {
    const detail = caught instanceof Error ? `${caught.name}: ${caught.message}` : String(caught);
    return { supported: false, reason: "no-ed25519", detail };
  }
  return { supported: true };
}

/** Corre la detección y lanza UnsupportedBrowserError si no hay soporte. */
export async function assertEd25519Supported(): Promise<void> {
  const support = await detectEd25519Support();
  if (!support.supported) throw new UnsupportedBrowserError(support.reason, support.detail);
}

// ── 2.2 Llaves ──────────────────────────────────────────────────────────────

/** Genera un par Ed25519 con la privada NO extraíble. */
export async function generateKeyPair(): Promise<CryptoKeyPair> {
  await assertEd25519Supported();
  const pair = await crypto.subtle.generateKey({ name: ED25519 }, false, ["sign", "verify"]);
  // Garantía explícita: si algún día esto cambiara (o un navegador lo ignorara),
  // preferimos fallar a guardar una privada exportable.
  if (pair.privateKey.extractable !== false) {
    throw new Error("Refusing to use an extractable private key.");
  }
  return pair;
}

/** Pública en hex (raw, 32 bytes). Solo acepta llaves públicas: la privada nunca se exporta. */
export async function exportPublicKeyHex(publicKey: CryptoKey): Promise<string> {
  if (publicKey.type !== "public") {
    throw new Error("Only public keys can be exported.");
  }
  return bytesToHex(await crypto.subtle.exportKey("raw", publicKey));
}

/** Firma `bytes` con la privada Ed25519 y devuelve la firma (64 bytes) en hex. */
// Uint8Array<ArrayBuffer> (no SharedArrayBuffer): lo único que WebCrypto acepta.
export async function signBytes(privateKey: CryptoKey, bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  if (privateKey.type !== "private" || privateKey.algorithm.name !== ED25519 || !privateKey.usages.includes("sign")) {
    throw new Error("signBytes needs an Ed25519 private key with the 'sign' usage.");
  }
  return bytesToHex(await crypto.subtle.sign({ name: ED25519 }, privateKey, bytes));
}

// ── Persistencia en IndexedDB ───────────────────────────────────────────────

function promisify<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error ?? new Error("Keystore transaction aborted."));
  });
}

function openKeystore(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(KEYSTORE_DB, KEYSTORE_VERSION);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(KEYSTORE_STORE, { keyPath: "email" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("The keystore is blocked by another open tab."));
  });
}

/** Abre, usa y SIEMPRE cierra la conexión (no dejar conexiones colgadas que bloqueen upgrades). */
async function withKeystore<T>(use: (db: IDBDatabase) => Promise<T>): Promise<T> {
  const db = await openKeystore();
  try {
    return await use(db);
  } finally {
    db.close();
  }
}

/**
 * Pide al navegador almacenamiento persistente (reduce que expulse la llave por
 * falta de espacio). Si lo niega o no existe la API, se sigue igual: la llave
 * funciona, solo con menos garantías de durar.
 */
export async function requestPersistentStorage(): Promise<PersistResult> {
  const storage = globalThis.navigator?.storage;
  if (!storage?.persist) return "unavailable";
  try {
    if (await storage.persisted?.()) return "granted";
    return (await storage.persist()) ? "granted" : "denied";
  } catch {
    return "denied";
  }
}

function readRecord(normalizedEmail: string): Promise<LocalKeyRecord | null> {
  return withKeystore(async (db) => {
    const record = await promisify(db.transaction(KEYSTORE_STORE, "readonly").objectStore(KEYSTORE_STORE).get(normalizedEmail));
    return (record as LocalKeyRecord | undefined) ?? null;
  });
}

/** Llave local de `email`, o null si este navegador no tiene ninguna. No crea nada. */
export async function getLocalKey(email: string): Promise<LocalKeyRecord | null> {
  const key = normalizeEmail(email);
  await assertEd25519Supported();
  return readRecord(key);
}

/**
 * Llave local de `email`: la recupera si existe; si no, genera una y la guarda.
 *
 * Atómico: la comprobación y el alta van en UNA transacción readwrite (IndexedDB las
 * serializa, incluso entre pestañas). Si dos llamadas compiten, ambas devuelven la
 * MISMA llave guardada; la generada de más se descarta sin haberse usado.
 */
export async function getOrCreateLocalKey(email: string): Promise<LocalKeyRecord> {
  const key = normalizeEmail(email);
  await assertEd25519Supported();

  const existing = await readRecord(key);
  if (existing) return existing;

  // La generación es asíncrona y no es de IndexedDB: se hace ANTES de abrir la
  // transacción (una transacción se cierra sola si espera promesas ajenas).
  // generateKeyPair repite la detección: es barata y la mantiene en su API pública.
  const pair = await generateKeyPair();
  const candidate: LocalKeyRecord = {
    email: key,
    privateKey: pair.privateKey,
    publicKeyHex: await exportPublicKeyHex(pair.publicKey),
    keyId: null,
    registered: false,
    createdAt: new Date().toISOString(),
  };

  const stored = await withKeystore(async (db) => {
    const transaction = db.transaction(KEYSTORE_STORE, "readwrite");
    const store = transaction.objectStore(KEYSTORE_STORE);
    const done = transactionDone(transaction);
    let winner = candidate;
    const request = store.get(key);
    request.onsuccess = () => {
      if (request.result) winner = request.result as LocalKeyRecord;  // alguien la creó mientras tanto
      else store.add(candidate);
    };
    await done;
    return winner;
  });

  if (stored === candidate) await requestPersistentStorage();
  return stored;
}

/** Borra la llave local de `email` ("usar otro email" / reset). true si había una. */
export async function deleteLocalKey(email: string): Promise<boolean> {
  const key = normalizeEmail(email);
  await assertEd25519Supported();
  return withKeystore(async (db) => {
    const transaction = db.transaction(KEYSTORE_STORE, "readwrite");
    const store = transaction.objectStore(KEYSTORE_STORE);
    const done = transactionDone(transaction);
    let existed = false;
    const lookup = store.getKey(key);
    lookup.onsuccess = () => {
      existed = lookup.result !== undefined;
      if (existed) store.delete(key);
    };
    await done;
    return existed;
  });
}
