"""Registro de llaves públicas por DUEÑO (owner_email): paso 1 de la firma del humano.

Cada dueño puede tener VARIAS llaves (un dispositivo = una llave), cada una:
    {key_id, public_key (Ed25519, 64 hex), alg="ed25519", created_at, revoked_at}

Qué es y qué NO es todavía:
- Es el directorio "esta llave pública pertenece a esta persona". El dueño sale
  SIEMPRE del token (api/keys.py), igual que el dueño de un mandato.
- NO participa aún en la verificación de firmas de mandatos (/verify): eso es el
  paso 3. Hoy registrar una llave no cambia ningún veredicto.
- NO prueba posesión de la llave privada: cualquiera puede registrar una pubkey
  que no controla (no le sirve para firmar, pero sí para "reclamarla"). La
  unicidad global de abajo mitiga el reclamo de llaves ajenas ya registradas; la
  prueba de posesión (firmar un desafío) queda pendiente para cuando exista la
  firma en el cliente.

En memoria, como el resto del estado: se pierde al reiniciar el proceso.
"""
import threading
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

ALG_ED25519 = "ed25519"
ED25519_PUBLIC_KEY_HEX_LENGTH = 64  # 32 bytes
# Tope de llaves ACTIVAS por dueño: cada una es memoria del servidor y la crea
# un usuario autenticado; sin tope, un solo usuario podría llenarla.
MAX_ACTIVE_KEYS_PER_OWNER = 10

# owner_email (normalizado) → lista de registros de llave, en orden de alta.
OWNER_KEYS: Dict[str, List[dict]] = {}
_lock = threading.RLock()


class InvalidPublicKey(ValueError):
    """La llave pública no es una Ed25519 bien formada."""


class KeyConflict(ValueError):
    """La llave no se puede registrar (ya es de otro dueño, está revocada, o hay tope)."""


def normalize_owner_email(owner_email: str) -> str:
    """Misma normalización que MANDATE_OWNERS y owner_email_for (minúsculas, sin
    espacios alrededor): así una llave ata con el dueño del mandato y con el
    subject del token. Un email vacío es un error, nunca un dueño."""
    if not isinstance(owner_email, str) or not owner_email.strip():
        raise ValueError("owner_email es obligatorio.")
    return owner_email.strip().lower()


def validate_public_key(public_key: object) -> str:
    """Devuelve la pubkey Ed25519 canónica (hex en minúsculas) o lanza InvalidPublicKey.

    Exige exactamente 64 caracteres hex que carguen como llave pública Ed25519."""
    if not isinstance(public_key, str):
        raise InvalidPublicKey("La llave pública debe ser un texto hex.")
    candidate = public_key.strip().lower()
    if len(candidate) != ED25519_PUBLIC_KEY_HEX_LENGTH:
        raise InvalidPublicKey(
            f"La llave pública Ed25519 debe tener {ED25519_PUBLIC_KEY_HEX_LENGTH} caracteres hex."
        )
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(candidate))
    except ValueError:
        raise InvalidPublicKey("La llave pública no es una llave Ed25519 hex válida.") from None
    return candidate


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _find_holder(public_key: str) -> Optional[tuple[str, dict]]:
    for owner, records in OWNER_KEYS.items():
        for record in records:
            if record["public_key"] == public_key:
                return owner, record
    return None


def register_key(owner_email: str, public_key: str) -> str:
    """Registra `public_key` para `owner_email` y devuelve su key_id.

    - Idempotente: la misma llave ya activa para el mismo dueño devuelve su key_id.
    - Una llave REVOCADA no se reactiva (pudo revocarse por compromiso): KeyConflict.
    - Una llave ya registrada por OTRO dueño: KeyConflict (una pubkey = una persona).
    - Más de MAX_ACTIVE_KEYS_PER_OWNER activas: KeyConflict.
    """
    owner = normalize_owner_email(owner_email)
    key = validate_public_key(public_key)
    with _lock:
        holder = _find_holder(key)
        if holder is not None:
            holder_owner, record = holder
            if holder_owner != owner:
                raise KeyConflict("Esa llave pública ya está registrada por otra cuenta.")
            if record["revoked_at"] is not None:
                raise KeyConflict("Esa llave fue revocada y no puede volver a registrarse.")
            return record["key_id"]

        records = OWNER_KEYS.setdefault(owner, [])
        if sum(record["revoked_at"] is None for record in records) >= MAX_ACTIVE_KEYS_PER_OWNER:
            raise KeyConflict(f"Máximo {MAX_ACTIVE_KEYS_PER_OWNER} llaves activas por cuenta.")
        key_id = f"key_{uuid.uuid4().hex}"
        records.append({
            "key_id": key_id,
            "public_key": key,
            "alg": ALG_ED25519,
            "created_at": _now(),
            "revoked_at": None,
        })
        return key_id


def list_active_key_records(owner_email: str) -> List[dict]:
    """Registros (copias) de las llaves activas del dueño, en orden de alta."""
    owner = normalize_owner_email(owner_email)
    with _lock:
        return [deepcopy(record) for record in OWNER_KEYS.get(owner, []) if record["revoked_at"] is None]


def get_active_keys(owner_email: str) -> List[str]:
    """Pubkeys activas del dueño (vacío si no tiene ninguna)."""
    return [record["public_key"] for record in list_active_key_records(owner_email)]


def revoke_key(owner_email: str, key_id: str) -> bool:
    """Marca revoked_at en la llave `key_id` DEL DUEÑO. True si quedó revocada ahora;
    False si no existe para ese dueño o ya estaba revocada (no toca llaves ajenas)."""
    owner = normalize_owner_email(owner_email)
    with _lock:
        for record in OWNER_KEYS.get(owner, []):
            if record["key_id"] == key_id:
                if record["revoked_at"] is not None:
                    return False
                record["revoked_at"] = _now()
                return True
    return False


def is_key_active(owner_email: str, public_key: object) -> bool:
    """¿`public_key` es una llave ACTIVA de `owner_email`? Fail-closed: una pubkey
    malformada, un email vacío o una llave revocada → False."""
    try:
        key = validate_public_key(public_key)
        return key in get_active_keys(owner_email)
    except ValueError:  # InvalidPublicKey o email inválido
        return False


def clear() -> None:
    """Olvida todas las llaves (tests / reinicio de demo)."""
    with _lock:
        OWNER_KEYS.clear()
