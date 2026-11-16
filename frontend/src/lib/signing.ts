/**
 * Firma canónica: los bytes que firma el navegador son EXACTAMENTE los que el
 * backend reconstruye y verifica.
 *
 * signCanonical = canonicalize (lib/canonical.ts, la misma regla que
 * mandate/canonical.py) → UTF-8 → Ed25519 con la privada no extraíble del
 * keystore (signBytes). No hay otro camino: ni JSON.stringify, ni otro algoritmo.
 * shared/key_registration_vectors.json fija mensaje y firma byte a byte
 * (signing.test.ts lo comprueba con la llave de prueba del RFC 8032).
 */
import { canonicalBytes } from "./canonical";
import { signBytes } from "./keystore";

/** Firma Ed25519 (hex, 128 caracteres) de la forma canónica de `value`. */
export async function signCanonical(privateKey: CryptoKey, value: unknown): Promise<string> {
  // canonicalBytes lanza CanonicalizationError ante cualquier valor no firmable:
  // nunca se firma una aproximación del valor.
  return signBytes(privateKey, canonicalBytes(value));
}
