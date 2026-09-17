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


def _normalize_owner(owner_email: Optional[str]) -> Optional[str]:
    if owner_email is None:
        return None
    normalized = owner_email.strip().lower()
    return normalized or None


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
    if datetime.now(timezone.utc) > expiry:
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
                    "amount_spent": 0.0,
                    "revoked_at": m_obj.revoked_at,
                },
            }
            MANDATE_OWNERS[mandate_id] = _normalize_owner(owner_email)
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


# Global singleton instance
mandate_store = MandateStore()


# Funciones funcionales para frontend y routers
def create_mandate(mandate: dict, owner_email: Optional[str] = None) -> dict:
    """Crea el mandato (flujo React/API). `owner_email` lo decide el SERVIDOR
    (token autenticado o seed); nunca se lee del cuerpo `mandate`."""
    import uuid
    from mandate.sign import generate_keypair, sign_payload

    mandate_id = mandate.get("mandate_id")
    if not mandate_id:
        raise ValueError("El mandate_id es obligatorio")
    if mandate_id in MANDATES:
        raise ValueError("El mandate_id ya existe")

    m_copy = deepcopy(mandate)
    
    # 🛡️ Garantía DLP: Asignar Scoped Virtual Token si no existe
    if "payment_token" not in m_copy:
        m_copy["payment_token"] = {
            "token_id": f"vtok_{uuid.uuid4().hex[:12]}",
            "token_type": "SCOPED_VIRTUAL_TOKEN",
            "masked_card": "•••• 4242",
            "bank_issuer": "Galicia AI Payments",
            "bound_mandate_id": mandate_id,
        }

    # 🔐 Sello Criptográfico: Asignar firma y claves si no existen
    if "signature" not in m_copy and "human_signature" not in m_copy:
        h_priv, h_pub = generate_keypair()
        m_copy["human_pubkey"] = h_pub
        m_copy["signature"] = sign_payload(h_priv, m_copy.get("constraints", m_copy.get("scope", {})))

    MANDATES[mandate_id] = {
        "mandate": m_copy,
        "live_state": {
            "status": "active",
            "uses_count": 0,
            "amount_spent": 0,
            "revoked_at": None,
        },
    }
    MANDATE_OWNERS[mandate_id] = _normalize_owner(owner_email)
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
        "amount_spent": 0,
        "revoked_at": None,
    }
    return get_mandate(mandate_id)


def apply_approved_purchase(mandate_id: str, amount: int | float) -> dict | None:
    """ÚNICO punto que consume un uso y suma gasto, sea cual sea la línea que
    aprobó la compra (api/verify, api/escalations o core/verify)."""
    with mandate_store._lock:
        record = MANDATES.get(mandate_id)
        if record is None:
            return None
        live_state = record["live_state"]
        live_state["uses_count"] += 1
        live_state["amount_spent"] += amount
        return get_mandate(mandate_id)
