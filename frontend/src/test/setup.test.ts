/**
 * Humo del entorno de tests, preparado para el almacén de llaves (sub-paso 2.2):
 * fake-indexeddb debe guardar y devolver un CryptoKey Ed25519 NO extraíble como lo
 * hace el navegador (structured clone), sin volverlo exportable.
 */
import { expect, it } from "vitest";

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

it("IndexedDB (fake-indexeddb) guarda y recupera un CryptoKey Ed25519 no extraíble", async () => {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;

  const open = indexedDB.open("setup-smoke", 1);
  open.onupgradeneeded = () => open.result.createObjectStore("keys", { keyPath: "email" });
  const db = await request(open);
  await request(db.transaction("keys", "readwrite").objectStore("keys").put({ email: "a@example.com", privateKey: pair.privateKey }));
  const stored = (await request(db.transaction("keys").objectStore("keys").get("a@example.com"))) as { privateKey: CryptoKey };
  db.close();

  expect(stored.privateKey).toBeInstanceOf(CryptoKey);
  expect(stored.privateKey.extractable).toBe(false);
  await expect(crypto.subtle.exportKey("pkcs8", stored.privateKey)).rejects.toThrow();

  const data = new TextEncoder().encode("hola");
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, stored.privateKey, data);
  expect(await crypto.subtle.verify({ name: "Ed25519" }, pair.publicKey, signature, data)).toBe(true);
});
