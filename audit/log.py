import hashlib
import json
import threading
from copy import deepcopy
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Union
from uuid import uuid4

from shared.schemas import AuditLogEntry, EventType, ActorType
from mandate.sign import canonical_json

_EVENT_TYPES = {
    "mandate_created",
    "verification",
    "revocation",
    "purchase_completed",
    "agent_run",
    "human_override_approved",
    "human_override_declined",
    "hitl_approved",
    "settlement_completed",
}


class CryptographicAuditLedger:
    """
    Append-only SHA-256 hash-chained cryptographic ledger.
    Every event is cryptographically linked to the previous entry, providing tamper-evident proof
    for cardholders, merchants, and chargeback auditors.
    """

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self):
        self._entries: List[AuditLogEntry] = []
        self._lock = threading.Lock()

    def _compute_hash(
        self,
        index: int,
        prev_hash: str,
        timestamp: str,
        event_type: str,
        actor_type: str,
        actor_id: str,
        mandate_id: Optional[str],
        attempt_id: Optional[str],
        details: Dict[str, Any],
    ) -> str:
        payload = {
            "index": index,
            "prev_hash": prev_hash,
            "timestamp": timestamp,
            "event_type": event_type,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "mandate_id": mandate_id,
            "attempt_id": attempt_id,
            "details": details,
        }
        return hashlib.sha256(canonical_json(payload)).hexdigest()

    def append_entry(
        self,
        event_type: Union[EventType, str],
        actor_type: Union[ActorType, str],
        actor_id: str,
        details: Dict[str, Any],
        mandate_id: Optional[str] = None,
        attempt_id: Optional[str] = None,
        signature: Optional[str] = None,
    ) -> AuditLogEntry:
        with self._lock:
            index = len(self._entries)
            prev_hash = self.GENESIS_HASH if index == 0 else self._entries[-1].hash
            timestamp = datetime.now(timezone.utc).isoformat()

            e_type_str = event_type.value if hasattr(event_type, "value") else str(event_type)
            a_type_str = actor_type.value if hasattr(actor_type, "value") else str(actor_type)

            curr_hash = self._compute_hash(
                index=index,
                prev_hash=prev_hash,
                timestamp=timestamp,
                event_type=e_type_str,
                actor_type=a_type_str,
                actor_id=actor_id,
                mandate_id=mandate_id,
                attempt_id=attempt_id,
                details=details,
            )

            entry = AuditLogEntry(
                entry_id=f"evt_{uuid4().hex[:10]}",
                index=index,
                prev_hash=prev_hash,
                timestamp=timestamp,
                event_type=e_type_str,
                actor_type=a_type_str,
                actor_id=actor_id,
                mandate_id=mandate_id,
                attempt_id=attempt_id,
                details=details,
                hash=curr_hash,
                signature=signature,
            )
            self._entries.append(entry)
            return entry

    def verify_chain_integrity(self) -> Tuple[bool, str]:
        with self._lock:
            if not self._entries:
                return True, "Audit log is empty (valid)."

            expected_prev = self.GENESIS_HASH
            for i, entry in enumerate(self._entries):
                if entry.index != i:
                    return False, f"Broken sequence at index {i}: found index {entry.index}"
                if entry.prev_hash != expected_prev:
                    return False, f"Broken link at index {i}: prev_hash {entry.prev_hash} != {expected_prev}"

                calculated_hash = self._compute_hash(
                    index=entry.index,
                    prev_hash=entry.prev_hash,
                    timestamp=entry.timestamp,
                    event_type=entry.event_type.value if hasattr(entry.event_type, "value") else str(entry.event_type),
                    actor_type=entry.actor_type.value if hasattr(entry.actor_type, "value") else str(entry.actor_type),
                    actor_id=entry.actor_id,
                    mandate_id=entry.mandate_id,
                    attempt_id=entry.attempt_id,
                    details=entry.details,
                )
                if calculated_hash != entry.hash:
                    return False, f"Tampered entry at index {i}: calculated hash {calculated_hash} != stored {entry.hash}"

                expected_prev = entry.hash

            return True, "Chain integrity 100% verified (Zero tampering detected)."

    def get_all_entries(self) -> List[AuditLogEntry]:
        with self._lock:
            return [e.model_copy(deep=True) for e in self._entries]

    def get_trail_for(self, role: str = "auditor", mandate_id: Optional[str] = None, attempt_id: Optional[str] = None) -> List[AuditLogEntry]:
        with self._lock:
            entries = self._entries
            if mandate_id:
                entries = [e for e in entries if e.mandate_id == mandate_id]
            if attempt_id:
                entries = [e for e in entries if e.attempt_id == attempt_id]
            return [e.model_copy(deep=True) for e in entries]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()



# Global singleton audit ledger
audit_ledger = CryptographicAuditLedger()

# Actor con el que append_entry escribe en el ledger. Identifica los eventos del
# "trail" (los que ve la UI) frente a los que la línea estricta escribe directo
# en el ledger (core/verify, core/dispute, mandate_store.save_mandate).
TRAIL_ACTOR_TYPE = "GATEWAY"
TRAIL_ACTOR_ID = "system_gateway"


def _is_trail_entry(entry: AuditLogEntry) -> bool:
    return (
        entry.actor_type == TRAIL_ACTOR_TYPE
        and entry.actor_id == TRAIL_ACTOR_ID
        and isinstance(entry.details, dict)
        and {"type", "mandate_id", "summary"} <= entry.details.keys()
    )


def _trail_entries(mandate_id: str | None = None, attempt_id: str | None = None) -> list[AuditLogEntry]:
    """Entradas del trail en orden de escritura (index ascendente)."""
    entries = [
        entry for entry in audit_ledger.get_trail_for(mandate_id=mandate_id, attempt_id=attempt_id)
        if _is_trail_entry(entry)
    ]
    return sorted(entries, key=lambda entry: entry.index)


def get_trail_events(mandate_id: str | None = None, attempt_id: str | None = None) -> list[dict]:
    """Eventos completos del trail (todos los campos que se escribieron), en orden
    de escritura. Uso interno del backend (escalaciones, disputas)."""
    return [
        {**deepcopy(entry.details), "event_id": entry.entry_id, "timestamp": entry.timestamp}
        for entry in _trail_entries(mandate_id, attempt_id)
    ]


def append_entry(event: dict) -> dict:
    """Agrega un evento del trail al ledger con cadena hash (única fuente de escritura).

    Devuelve el evento completo con el event_id y timestamp de su bloque.
    """
    event_type = event.get("type")
    if event_type not in _EVENT_TYPES and event_type not in [e.value for e in EventType]:
        raise ValueError(f"Tipo de evento de auditoría inválido: {event_type!r}")
    if "mandate_id" not in event or "summary" not in event:
        raise ValueError("Todo evento requiere mandate_id y summary.")

    entry = audit_ledger.append_entry(
        event_type=event_type,
        actor_type=TRAIL_ACTOR_TYPE,
        actor_id=TRAIL_ACTOR_ID,
        mandate_id=event.get("mandate_id"),
        attempt_id=event.get("attempt_id"),
        # Copia profunda: si el llamador muta su dict después, el bloque no cambia.
        details=deepcopy(event),
    )
    return {**deepcopy(entry.details), "event_id": entry.entry_id, "timestamp": entry.timestamp}


def to_frontend_event(entry: AuditLogEntry) -> dict:
    """ADAPTADOR ledger → evento que consume React (AuditView.tsx / AccountView.tsx).

    Entrada (ledger):  {entry_id, index, prev_hash, hash, timestamp, event_type,
                        actor_type, actor_id, mandate_id, attempt_id, details{...}}
    Salida (React):    {event_id, timestamp, type, mandate_id, summary,
                        attempt_id?, verdict?}

    - event_id / timestamp: los del bloque del ledger (el evento no tiene otros).
    - type: el tipo tal como lo escribió append_entry ("verification",
      "agent_run", ... y también "DISPUTE_FILED"/"DISPUTE_RESOLVED" en
      mayúsculas): se copia literal, NUNCA se normaliza, porque
      presentation.ts los etiqueta por su valor exacto.
    - attempt_id / verdict: opcionales. Aparecen solo si el evento original los
      traía y con su valor literal (verdict puede ser null, p. ej. DISPUTE_RESOLVED).
    Solo recibe entradas del trail (ver _is_trail_entry).
    """
    details = entry.details
    event = {
        "event_id": entry.entry_id,
        "timestamp": entry.timestamp,
        "type": details["type"],
        "mandate_id": details["mandate_id"],
        "summary": details["summary"],
    }
    for optional_field in ("attempt_id", "verdict"):
        if optional_field in details:
            event[optional_field] = deepcopy(details[optional_field])
    return event


def get_trail_for(role: str = "auditor", mandate_id: str | None = None, attempt_id: str | None = None) -> list[dict]:
    """Vista del trail para la UI: eventos del ledger adaptados a la forma de React,
    del más nuevo al más viejo, con la visibilidad del rol solicitado.

    `attempt_id` se acepta por compatibilidad de firma pero, igual que antes de
    migrar al ledger, no filtra.
    """
    if role in {"human", "merchant"}:
        if not mandate_id:
            return []
        entries = _trail_entries(mandate_id=mandate_id)
    else:
        entries = _trail_entries()

    return [to_frontend_event(entry) for entry in reversed(entries)]


def reset_trail() -> dict:
    """Reinicia explícitamente la sesión de auditoría en memoria para una demo nueva.

    Durante una sesión el trail sigue siendo append-only. Este corte sólo se
    invoca al iniciar/reiniciar una demo y también reinicia la cadena hash.
    """
    removed = len(_trail_entries())
    audit_ledger.clear()
    return {"cleared": removed, "status": "reset"}
