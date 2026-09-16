import threading
from copy import deepcopy
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union, Any

from shared.schemas import Mandate, MandateStatus

# Estado global autoritativo en memoria (Zero-Caching)
MANDATES: Dict[str, dict] = {}
VERIFICATION_EVENTS: List[dict] = []


class MandateStore:
    """
    Authoritative, thread-safe in-memory store for Mandates.
    CRITICAL RULE: NO CACHING. All status checks query this live registry directly.
    """

    def __init__(self):
        # RLock: list_mandates() llama a get_mandate() con el lock ya tomado
        self._lock = threading.RLock()

    def save_mandate(self, mandate: Union[Mandate, dict]) -> Mandate:
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
            m_dict = record["mandate"]
            # Los mandatos del flujo API guardan status en minúsculas ("active");
            # el enum MandateStatus exige mayúsculas.
            status_raw = m_dict.get("status")
            if isinstance(status_raw, str):
                m_dict = {**m_dict, "status": status_raw.upper()}
            m_obj = Mandate(**m_dict)
            
            # Chequeo en vivo de expiración
            if m_obj.status == MandateStatus.ACTIVE and m_obj.expires_at:
                now = datetime.now(timezone.utc)
                try:
                    exp = datetime.fromisoformat(m_obj.expires_at.replace("Z", "+00:00"))
                    if now > exp:
                        m_obj.status = MandateStatus.EXPIRED
                        record["live_state"]["status"] = "expired"
                        record["mandate"]["status"] = "EXPIRED"
                except Exception:
                    pass

            if record["live_state"]["status"] == "revoked":
                m_obj.status = MandateStatus.REVOKED
                m_obj.revoked_at = record["live_state"].get("revoked_at")

            return m_obj

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
            VERIFICATION_EVENTS.clear()


# Global singleton instance
mandate_store = MandateStore()


# Funciones funcionales para frontend y routers
def create_mandate(mandate: dict) -> dict:
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
    return get_mandate(mandate_id)


def get_mandate(mandate_id: str) -> dict | None:
    record = MANDATES.get(mandate_id)
    return deepcopy(record) if record is not None else None


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
    record = MANDATES.get(mandate_id)
    if record is None:
        return None
    record["live_state"]["uses_count"] += 1
    record["live_state"]["amount_spent"] += amount
    return get_mandate(mandate_id)


def record_verification_event(
    mandate_id: str, attempt_id: str, verdict: str, timestamp: str
) -> None:
    VERIFICATION_EVENTS.append(
        {
            "mandate_id": mandate_id,
            "attempt_id": attempt_id,
            "verdict": verdict,
            "timestamp": timestamp,
        }
    )
