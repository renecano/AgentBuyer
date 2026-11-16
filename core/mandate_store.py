import hashlib
import threading
from copy import deepcopy
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union, Any

from shared.schemas import Mandate, MandateStatus

# Estado global autoritativo en memoria (Zero-Caching).
# Cada registro es {"mandate": {...}, "live_state": {status, uses_count, amount_spent, revoked_at}}.
# live_state es la ÚNICA fuente de verdad del estado vivo (status y contadores) para
# ambas líneas de verificación y para lo que expone GET /mandates/{id}.
MANDATES: Dict[str, dict] = {}

# Dueño de cada mandato (email verificado de quien lo creó), por mandate_id.
# Vive APARTE de MANDATES a propósito: get_mandate() devuelve el registro
# {mandate, live_state} tal cual a GET /mandates/{id}, y el dueño es un dato
# INTERNO de autorización que no debe filtrarse a React ni venir del cliente.
# None = mandato sin dueño conocido (creado sin token).
MANDATE_OWNERS: Dict[str, Optional[str]] = {}

# Quién firmó cada mandato, por mandate_id (paso 3.3). Aparte, como MANDATE_OWNERS:
# es un dato interno de verificación que no se filtra a ninguna respuesta.
#   {"kind": "human" | "system_seal",
#    "key_id": str | None, "public_key": str | None,
#    "message_hash": sha256 hex de los bytes firmados | None, "signed_at": ISO 8601}
# human       = el titular firmó con SU llave registrada (core/signed_mandates). Es el
#               único camino para los mandatos de usuarios (3.5).
# system_seal = el servidor selló el mandato SEMILLA al arrancar (no es una firma del
#               titular). Ningún endpoint lo crea; desaparece con el seed (7.2, P-11).
MANDATE_SIGNERS: Dict[str, dict] = {}


def _utcnow() -> datetime:
    """Reloj del almacén (expiración). Los tests lo sustituyen: sin esperas reales."""
    return datetime.now(timezone.utc)


def _normalize_owner(owner_email: Optional[str]) -> Optional[str]:
    if owner_email is None:
        return None
    normalized = owner_email.strip().lower()
    return normalized or None


def mandate_exists(mandate_id: str) -> bool:
    """¿Existe el mandato? Sin copiarlo: para decidir 404 antes de evaluar propiedad."""
    with mandate_store._lock:
        return mandate_id in MANDATES


def get_mandate_signer(mandate_id: str) -> Optional[dict]:
    """Registro del firmante del mandato (copia), o None si no hay."""
    with mandate_store._lock:
        signer = MANDATE_SIGNERS.get(mandate_id)
        return deepcopy(signer) if signer is not None else None


def _sealed_signer(public_key: Optional[str], sealed_bytes: Optional[bytes], kind: str) -> dict:
    return {
        "kind": kind,
        "key_id": None,
        "public_key": public_key,
        "message_hash": hashlib.sha256(sealed_bytes).hexdigest() if sealed_bytes is not None else None,
        "signed_at": _utcnow().isoformat(),
    }


def mandate_ids_owned_by(owner_email: Optional[str]) -> set:
    """Ids de los mandatos cuyo dueño es `owner_email` (vacío si no hay dueño)."""
    owner = _normalize_owner(owner_email)
    if owner is None:
        return set()
    with mandate_store._lock:
        return {mandate_id for mandate_id, holder in MANDATE_OWNERS.items() if holder == owner}


def get_mandate_owner(mandate_id: str) -> Optional[str]:
    """Email del dueño del mandato, o None si no tiene dueño registrado (o no existe)."""
    with mandate_store._lock:
        return MANDATE_OWNERS.get(mandate_id)


def _apply_live_expiry(record: dict) -> None:
    """Regla de expiración única para todos los lectores (clase y funciones): un
    mandato activo cuyo expires_at ya pasó queda "expired" en live_state.

    Una fecha ilegible se ignora aquí, igual que antes; core/verify la rechaza por
    su cuenta (fail-closed).
    """
    live_state = record["live_state"]
    expires_at = record["mandate"].get("expires_at")
    if live_state["status"] != "active" or not isinstance(expires_at, str) or not expires_at:
        return
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if _utcnow() > expiry:
        live_state["status"] = "expired"
        if "status" in record["mandate"]:
            record["mandate"]["status"] = "EXPIRED"


class MandateStore:
    """
    Authoritative, thread-safe in-memory store for Mandates.
    CRITICAL RULE: NO CACHING. All status checks query this live registry directly.
    """

    def __init__(self):
        # RLock: list_mandates() llama a get_mandate() con el lock ya tomado
        self._lock = threading.RLock()

    def save_mandate(self, mandate: Union[Mandate, dict], owner_email: Optional[str] = None) -> Mandate:
        with self._lock:
            if isinstance(mandate, dict):
                m_obj = Mandate(**mandate)
            else:
                m_obj = mandate.model_copy(deep=True)

            mandate_id = m_obj.mandate_id
            MANDATES[mandate_id] = {
                "mandate": m_obj.model_dump(),
                "live_state": {
                    "status": m_obj.status.value.lower(),
                    "uses_count": 0,
                    "amount_spent_cents": 0,
                    "revoked_at": m_obj.revoked_at,
                },
            }
            MANDATE_OWNERS[mandate_id] = _normalize_owner(owner_email)
            # mandate/issue.py firma con llaves que guarda el SERVIDOR (_key_registry):
            # es un sello de sistema, no una firma del titular.
            MANDATE_SIGNERS[mandate_id] = _sealed_signer(m_obj.human_pubkey or None, None, "system_seal")
            try:
                from audit.log import audit_ledger
                audit_ledger.append_entry(
                    event_type="MANDATE_CREATED",
                    actor_type="HUMAN",
                    actor_id=m_obj.human_id,
                    mandate_id=mandate_id,
                    details={"scope": m_obj.scope.model_dump() if m_obj.scope else {}},
                )
            except Exception:
                pass
            return m_obj


    def get_mandate(self, mandate_id: str) -> Optional[Mandate]:
        with self._lock:
            record = MANDATES.get(mandate_id)
            if not record:
                return None
            _apply_live_expiry(record)
            live_state = record["live_state"]
            # status y revoked_at salen de live_state (única fuente de verdad), no
            # del dict del mandato, que puede quedar desactualizado.
            return Mandate(**{
                **record["mandate"],
                "status": live_state["status"].upper(),
                "revoked_at": live_state.get("revoked_at"),
            })

    def list_mandates(self, human_id: Optional[str] = None) -> List[Mandate]:
        with self._lock:
            mandates = []
            for m_id in list(MANDATES.keys()):
                m = self.get_mandate(m_id)
                if m and (human_id is None or m.human_id == human_id):
                    mandates.append(m)
            return mandates

    def revoke_mandate(self, mandate_id: str, reason: str = "Revoked by cardholder") -> bool:
        """Live Revocation Kill Switch."""
        with self._lock:
            record = MANDATES.get(mandate_id)
            if not record:
                return False
            record["live_state"]["status"] = "revoked"
            now_iso = datetime.now(timezone.utc).isoformat()
            record["live_state"]["revoked_at"] = now_iso
            if "status" in record["mandate"]:
                record["mandate"]["status"] = "REVOKED"
            if "revoked_at" in record["mandate"]:
                record["mandate"]["revoked_at"] = now_iso
            if "revocation_reason" in record["mandate"]:
                record["mandate"]["revocation_reason"] = reason
            return True

    def pause_mandate(self, mandate_id: str) -> bool:
        with self._lock:
            record = MANDATES.get(mandate_id)
            if not record:
                return False
            record["live_state"]["status"] = "paused"
            record["mandate"]["status"] = "PAUSED"
            return True

    def resume_mandate(self, mandate_id: str) -> bool:
        with self._lock:
            record = MANDATES.get(mandate_id)
            if not record:
                return False
            record["live_state"]["status"] = "active"
            record["mandate"]["status"] = "ACTIVE"
            return True

    def get_live_status(self, mandate_id: str) -> Tuple[Optional[MandateStatus], Optional[str]]:
        m = self.get_mandate(mandate_id)
        if not m:
            return None, "Mandate not found"
        return m.status, m.revocation_reason

    def clear(self) -> None:
        with self._lock:
            MANDATES.clear()
            MANDATE_OWNERS.clear()
            MANDATE_SIGNERS.clear()
            from core.signed_mandates import used_nonces
            used_nonces.clear()


# Global singleton instance
mandate_store = MandateStore()


# Funciones funcionales para frontend y routers
def seal_seed_mandate(mandate: dict, owner_email: Optional[str] = None) -> dict:
    """Sella el mandato SEMILLA al arrancar (api/main.load_seed_mandates): el único
    mandato que el servidor firma con una llave suya (kind=system_seal, D-12). No lo
    llama ningún endpoint: los usuarios crean mandatos firmados por ellos (3.5).

    El payment_token lo emite el servidor atado a los bytes sellados (también aquí):
    uno que venga en el seed se descarta. Una firma que venga en el seed es un error,
    no un "sello del cliente": ese camino legado ya no existe."""
    from core.signed_mandates import issue_payment_token
    from mandate.sign import canonical_json, generate_keypair, sign_payload

    mandate_id = mandate.get("mandate_id")
    if not mandate_id:
        raise ValueError("El mandate_id es obligatorio")
    if "signature" in mandate or "human_signature" in mandate:
        raise ValueError("El seed no puede traer firma: el servidor lo sella al cargarlo.")

    m_copy = deepcopy(mandate)
    if isinstance(m_copy.get("constraints"), dict):
        # El seed es un archivo de config en UNIDADES: su borde a centavos es aquí (5.1).
        m_copy["constraints"] = _seed_constraints_to_cents(m_copy["constraints"])
    sealed = m_copy.get("constraints", m_copy.get("scope", {}))
    sealed_bytes = canonical_json(sealed)
    h_priv, h_pub = generate_keypair()
    m_copy["human_pubkey"] = h_pub
    m_copy["signature"] = sign_payload(h_priv, sealed)
    signer = _sealed_signer(h_pub, sealed_bytes, "system_seal")
    m_copy["payment_token"] = issue_payment_token(mandate_id, signer["message_hash"])

    with mandate_store._lock:
        if mandate_id in MANDATES:
            raise ValueError("El mandate_id ya existe")
        MANDATES[mandate_id] = {
            "mandate": m_copy,
            "live_state": {"status": "active", "uses_count": 0, "amount_spent_cents": 0, "revoked_at": None},
        }
        MANDATE_OWNERS[mandate_id] = _normalize_owner(owner_email)
        MANDATE_SIGNERS[mandate_id] = signer
        return get_mandate(mandate_id)


def _seed_constraints_to_cents(constraints: dict) -> dict:
    """Constraints del seed (unidades) → la forma del engine (centavos enteros).
    max_amount_per_tx era un duplicado de max_amount_per_purchase: se descarta."""
    from core.money import to_cents

    converted = {key: value for key, value in constraints.items()
                 if key not in ("max_amount_per_purchase", "max_amount_per_tx", "monthly_budget", "conditions")}
    cap = constraints.get("max_amount_per_purchase", constraints.get("max_amount_per_tx"))
    if cap is not None:
        converted["max_amount_per_purchase_cents"] = to_cents(cap, "max_amount_per_purchase")
    if constraints.get("monthly_budget") is not None:
        converted["monthly_budget_cents"] = to_cents(constraints["monthly_budget"], "monthly_budget")
    converted["conditions"] = [
        {"type": condition["type"], "value_cents": to_cents(condition["value"], f"conditions.{condition['type']}")}
        if isinstance(condition, dict) and "value" in condition else condition
        for condition in constraints.get("conditions", [])
    ]
    return converted


def count_mandates_signed_with(owner_email: str, key_id: str) -> int:
    """Mandatos del dueño firmados con `key_id` que todavía podrían autorizar compras
    (activos o pausados): los que quedan sin efecto si esa llave se revoca (P-01 a)."""
    owner = _normalize_owner(owner_email)
    with mandate_store._lock:
        return sum(
            1
            for mandate_id, signer in MANDATE_SIGNERS.items()
            if signer.get("kind") == "human"
            and signer.get("key_id") == key_id
            and MANDATE_OWNERS.get(mandate_id) == owner
            and MANDATES.get(mandate_id, {}).get("live_state", {}).get("status") in ("active", "paused")
        )


def create_human_signed_mandate(mandate: dict, signer: dict, owner_email: str, nonce: str, created_at: datetime) -> dict:
    """Guarda un mandato YA verificado por core/signed_mandates (kind=human).

    Atómico bajo el lock del almacén: el anti-replay del nonce y la unicidad del
    mandate_id se deciden juntos, sin ventana entre comprobar y guardar.
    Lanza ValueError (→ 409) si el mandate_id existe o el nonce ya se usó."""
    from core.signed_mandates import used_nonces, _utcnow as signed_clock

    mandate_id = mandate["mandate_id"]
    owner = _normalize_owner(owner_email)
    with mandate_store._lock:
        if mandate_id in MANDATES:
            raise ValueError("El mandate_id ya existe")
        if not used_nonces.claim(owner, nonce, created_at, signed_clock()):
            raise ValueError("Este nonce ya se usó para crear otro mandato (replay).")
        MANDATES[mandate_id] = {
            "mandate": deepcopy(mandate),
            "live_state": {"status": "active", "uses_count": 0, "amount_spent_cents": 0, "revoked_at": None},
        }
        MANDATE_OWNERS[mandate_id] = owner
        MANDATE_SIGNERS[mandate_id] = deepcopy(signer)
        return get_mandate(mandate_id)


def get_mandate(mandate_id: str) -> dict | None:
    with mandate_store._lock:
        record = MANDATES.get(mandate_id)
        if record is None:
            return None
        _apply_live_expiry(record)
        return deepcopy(record)


def revoke_mandate(mandate_id: str) -> dict | None:
    record = MANDATES.get(mandate_id)
    if record is None:
        return None
    live_state = record["live_state"]
    if live_state["status"] != "revoked":
        live_state["status"] = "revoked"
        live_state["revoked_at"] = datetime.now(timezone.utc).isoformat()
    return get_mandate(mandate_id)


def reset_mandate(mandate_id: str) -> dict | None:
    """Restaura el estado vivo inicial de un mandato para reiniciar una demo."""
    record = MANDATES.get(mandate_id)
    if record is None:
        return None

    record["live_state"] = {
        "status": "active",
        "uses_count": 0,
        "amount_spent_cents": 0,
        "revoked_at": None,
    }
    return get_mandate(mandate_id)


def apply_approved_purchase(mandate_id: str, amount_cents: int) -> dict | None:
    """ÚNICO punto que consume un uso y suma gasto, sea cual sea la línea que
    aprobó la compra (api/verify, api/escalations o core/verify).

    5.1 (P-09): el gasto es un entero de centavos. Un monto que no lo sea (float,
    negativo, cero, bool) es un error del llamador: se rechaza, no se redondea."""
    from core.money import is_cents

    if not is_cents(amount_cents) or amount_cents <= 0:
        raise ValueError(f"apply_approved_purchase exige centavos enteros > 0 (recibido {amount_cents!r}).")
    with mandate_store._lock:
        record = MANDATES.get(mandate_id)
        if record is None:
            return None
        live_state = record["live_state"]
        live_state["uses_count"] += 1
        live_state["amount_spent_cents"] += amount_cents
        return get_mandate(mandate_id)
