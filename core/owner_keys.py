"""Registro de llaves públicas por DUEÑO (owner_email): las llaves con las que cada
titular firma sus mandatos en su dispositivo.

Cada dueño puede tener VARIAS llaves (un dispositivo = una llave), cada una:
    {key_id, public_key (Ed25519, 64 hex), alg="ed25519", created_at, revoked_at}

- El dueño sale SIEMPRE del token (api/keys.py), igual que el dueño de un mandato.
- Registrar exige prueba de posesión: step-up OTP + challenge firmado (Fase 2,
  core/key_challenges.py). Esta capa recibe la llave ya probada.
- /verify y la creación de mandatos firmados consultan aquí si la llave sigue
  activa (Fase 3, P-01 a): revocarla deja sin efecto lo firmado con ella.

Persistente desde el 6.2 (tabla owner_keys, core/db_schema.py). Las invariantes
viven EN LA BASE, no solo en el código: una pubkey = una persona (UNIQUE global),
key_id único, alg fijo. El tope de llaves activas por dueño se decide dentro de una
transacción BEGIN IMMEDIATE (SQLite no tiene CHECK agregados).
"""
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import and_, delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError

from core.db import read_tx, write_tx
from core.db_schema import owner_keys as KEYS

ALG_ED25519 = "ed25519"
ED25519_PUBLIC_KEY_HEX_LENGTH = 64  # 32 bytes
# Tope de llaves ACTIVAS por dueño: cada una es espacio del servidor y la crea un
# usuario autenticado; sin tope, un solo usuario podría llenarlo.
MAX_ACTIVE_KEYS_PER_OWNER = 10

_COLUMNS = (KEYS.c.key_id, KEYS.c.public_key, KEYS.c.alg, KEYS.c.created_at, KEYS.c.revoked_at)


class InvalidPublicKey(ValueError):
    """La llave pública no es una Ed25519 bien formada."""


class KeyConflict(ValueError):
    """La llave no se puede registrar (ya es de otro dueño, está revocada, o hay tope)."""


def normalize_owner_email(owner_email: str) -> str:
    """Misma normalización que MANDATE_OWNERS y owner_email_for (minúsculas, sin
    espacios alrededor): así una llave ata con el dueño del mandato y con el
    subject del token. Un email vacío es un error, nunca un dueño."""
    if not isinstance(owner_email, str) or not owner_email.strip():
        raise ValueError("owner_email is required.")
    return owner_email.strip().lower()


def validate_public_key(public_key: object) -> str:
    """Devuelve la pubkey Ed25519 canónica (hex en minúsculas) o lanza InvalidPublicKey.

    Exige exactamente 64 caracteres hex que carguen como llave pública Ed25519."""
    if not isinstance(public_key, str):
        raise InvalidPublicKey("The public key must be hex text.")
    candidate = public_key.strip().lower()
    if len(candidate) != ED25519_PUBLIC_KEY_HEX_LENGTH:
        raise InvalidPublicKey(
            f"The Ed25519 public key must have {ED25519_PUBLIC_KEY_HEX_LENGTH} hex characters."
        )
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(candidate))
    except ValueError:
        raise InvalidPublicKey("The public key is not a valid hex Ed25519 key.") from None
    return candidate


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record(row) -> dict:
    return {"key_id": row.key_id, "public_key": row.public_key, "alg": row.alg,
            "created_at": row.created_at, "revoked_at": row.revoked_at}


def register_key(owner_email: str, public_key: str) -> str:
    """Registra `public_key` para `owner_email` y devuelve su key_id.

    - Idempotente: la misma llave ya activa para el mismo dueño devuelve su key_id.
    - Una llave REVOCADA no se reactiva (pudo revocarse por compromiso): KeyConflict.
    - Una llave ya registrada por OTRO dueño: KeyConflict (una pubkey = una persona).
    - Más de MAX_ACTIVE_KEYS_PER_OWNER activas: KeyConflict.
    """
    owner = normalize_owner_email(owner_email)
    key = validate_public_key(public_key)
    try:
        with write_tx() as connection:
            holder = connection.execute(select(KEYS.c.owner_email, *_COLUMNS).where(KEYS.c.public_key == key)).first()
            if holder is not None:
                if holder.owner_email != owner:
                    raise KeyConflict("That public key is already registered by another account.")
                if holder.revoked_at is not None:
                    raise KeyConflict("That key was revoked and cannot be registered again.")
                return holder.key_id

            active = connection.execute(
                select(func.count()).select_from(KEYS).where(and_(KEYS.c.owner_email == owner, KEYS.c.revoked_at.is_(None)))
            ).scalar_one()
            if active >= MAX_ACTIVE_KEYS_PER_OWNER:
                raise KeyConflict(f"At most {MAX_ACTIVE_KEYS_PER_OWNER} active keys per account.")
            key_id = f"key_{uuid.uuid4().hex}"
            connection.execute(insert(KEYS).values(
                key_id=key_id, owner_email=owner, public_key=key, alg=ALG_ED25519, created_at=_now(), revoked_at=None,
            ))
            return key_id
    except IntegrityError:
        # La base rechazó lo que el código no detectó (p. ej. otra escritura concurrente
        # fuera de esta transacción): mismo resultado, fail-closed.
        raise KeyConflict("That public key is already registered.") from None


def list_active_key_records(owner_email: str) -> List[dict]:
    """Registros de las llaves activas del dueño, en orden de alta."""
    owner = normalize_owner_email(owner_email)
    with read_tx() as connection:
        rows = connection.execute(
            select(*_COLUMNS).where(and_(KEYS.c.owner_email == owner, KEYS.c.revoked_at.is_(None))).order_by(KEYS.c.id)
        ).all()
    return [_record(row) for row in rows]


def get_active_keys(owner_email: str) -> List[str]:
    """Pubkeys activas del dueño (vacío si no tiene ninguna)."""
    return [record["public_key"] for record in list_active_key_records(owner_email)]


def find_key(key_id: str) -> Optional[tuple[str, dict]]:
    """(owner_email, registro) de `key_id`, activa o revocada; None si no existe."""
    if not isinstance(key_id, str):
        return None
    with read_tx() as connection:
        row = connection.execute(select(KEYS.c.owner_email, *_COLUMNS).where(KEYS.c.key_id == key_id)).first()
    return (row.owner_email, _record(row)) if row is not None else None


def revoke_key(owner_email: str, key_id: str) -> bool:
    """Marca revoked_at en la llave `key_id` DEL DUEÑO. True si quedó revocada ahora;
    False si no existe para ese dueño o ya estaba revocada (no toca llaves ajenas)."""
    owner = normalize_owner_email(owner_email)
    with write_tx() as connection:
        result = connection.execute(
            update(KEYS)
            .where(and_(KEYS.c.owner_email == owner, KEYS.c.key_id == key_id, KEYS.c.revoked_at.is_(None)))
            .values(revoked_at=_now())
        )
        return result.rowcount == 1


def is_key_active(owner_email: str, public_key: object) -> bool:
    """¿`public_key` es una llave ACTIVA de `owner_email`? Fail-closed: una pubkey
    malformada, un email vacío o una llave revocada → False."""
    try:
        key = validate_public_key(public_key)
        return key in get_active_keys(owner_email)
    except ValueError:  # InvalidPublicKey o email inválido
        return False


def clear() -> None:
    """Olvida todas las llaves. SOLO tests y la utilidad de reinicio de desarrollo: una
    llave que firmó un mandato no se puede borrar (clave foránea de mandate_signers)."""
    with write_tx() as connection:
        connection.execute(delete(KEYS))
