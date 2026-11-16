"""Ledger de auditoría con cadena hash SHA-256: append-only, persistente (6.3).

Cada entrada se encadena con la anterior (prev_hash) y su hash cubre el JSON canónico
de todos sus campos. Desde el 6.3 vive en la base (tabla audit_ledger) y la base
misma impide UPDATE/DELETE y exige que cada INSERT extienda la cabeza (ledger_head):
ver migrations/versions/0002. La API verifica la cadena COMPLETA al arrancar y, si
está rota, no arranca (api/main.py; diagnóstico sin API: scripts/verify_ledger.py).

`details` se guarda como el JSON exacto del que se calculó el hash, y el hash se
calcula sobre ESE JSON ya leído de vuelta: re-verificar desde la base da los mismos
bytes que al escribir.
"""
import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import uuid4

from sqlalchemy import func, insert, select

from core.db import read_tx, write_tx_or
from core.db_schema import audit_ledger as LEDGER
from core.db_schema import ledger_head as HEAD
from mandate.sign import canonical_json
from shared.schemas import ActorType, AuditLogEntry, EventType

class LedgerIntegrityError(RuntimeError):
    """La cadena del ledger no verifica: la API no debe arrancar sobre esa evidencia."""


_EVENT_TYPES = {
    "mandate_created",
    "verification",
    # 4.2: verificación de un escenario de demostración (nunca es una compra).
    "scenario_verification",
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
        *,
        connection=None,
    ) -> AuditLogEntry:
        """Agrega una entrada al final de la cadena. Con `connection`, dentro de la
        transacción del llamador (p. ej. decisión humana + compra + evento: todo o nada)."""
        e_type_str = event_type.value if hasattr(event_type, "value") else str(event_type)
        a_type_str = actor_type.value if hasattr(actor_type, "value") else str(actor_type)
        details_text = json.dumps(details, ensure_ascii=False)
        stored_details = json.loads(details_text)
        with write_tx_or(connection) as conn:
            head = conn.execute(select(HEAD.c.last_idx, HEAD.c.last_hash).where(HEAD.c.id == 1)).one()
            index = head.last_idx + 1
            prev_hash = head.last_hash
            timestamp = datetime.now(timezone.utc).isoformat()
            curr_hash = self._compute_hash(
                index=index, prev_hash=prev_hash, timestamp=timestamp, event_type=e_type_str,
                actor_type=a_type_str, actor_id=actor_id, mandate_id=mandate_id, attempt_id=attempt_id,
                details=stored_details,
            )
            entry_id = f"evt_{uuid4().hex[:10]}"
            conn.execute(insert(LEDGER).values(
                idx=index, entry_id=entry_id, prev_hash=prev_hash, hash=curr_hash, timestamp=timestamp,
                event_type=e_type_str, actor_type=a_type_str, actor_id=actor_id, mandate_id=mandate_id,
                attempt_id=attempt_id, details=details_text, signature=signature,
            ))
        return AuditLogEntry(
            entry_id=entry_id, index=index, prev_hash=prev_hash, timestamp=timestamp, event_type=e_type_str,
            actor_type=a_type_str, actor_id=actor_id, mandate_id=mandate_id, attempt_id=attempt_id,
            details=stored_details, hash=curr_hash, signature=signature,
        )

    @staticmethod
    def _entry(row) -> AuditLogEntry:
        return AuditLogEntry(
            entry_id=row.entry_id, index=row.idx, prev_hash=row.prev_hash, timestamp=row.timestamp,
            event_type=row.event_type, actor_type=row.actor_type, actor_id=row.actor_id, mandate_id=row.mandate_id,
            attempt_id=row.attempt_id, details=json.loads(row.details), hash=row.hash, signature=row.signature,
        )

    def verify_chain_integrity(self) -> Tuple[bool, str]:
        """Re-verifica TODA la cadena desde la base, y que termine exactamente en la
        cabeza registrada (H4: borrar las últimas filas deja una cadena "válida" que
        ya no llega a la cabeza)."""
        with read_tx() as conn:
            head = conn.execute(select(HEAD.c.last_idx, HEAD.c.last_hash).where(HEAD.c.id == 1)).one_or_none()
            rows = conn.execute(select(LEDGER).order_by(LEDGER.c.idx)).all()
        if head is None:
            return False, "Ledger head is missing."

        expected_prev = self.GENESIS_HASH
        for i, row in enumerate(rows):
            entry = self._entry(row)
            if entry.index != i:
                return False, f"Broken sequence at index {i}: found index {entry.index}"
            if entry.prev_hash != expected_prev:
                return False, f"Broken link at index {i}: prev_hash {entry.prev_hash} != {expected_prev}"
            calculated_hash = self._compute_hash(
                index=entry.index, prev_hash=entry.prev_hash, timestamp=entry.timestamp,
                event_type=entry.event_type, actor_type=entry.actor_type, actor_id=entry.actor_id,
                mandate_id=entry.mandate_id, attempt_id=entry.attempt_id, details=entry.details,
            )
            if calculated_hash != entry.hash:
                return False, f"Tampered entry at index {i}: calculated hash {calculated_hash} != stored {entry.hash}"
            expected_prev = entry.hash

        if head.last_idx != len(rows) - 1 or head.last_hash != expected_prev:
            return False, (f"Ledger does not end at its recorded head: head is index {head.last_idx}, "
                           f"the chain ends at index {len(rows) - 1}. Entries were removed or the head was altered.")
        if not rows:
            return True, "Audit log is empty (valid)."
        return True, "Chain integrity 100% verified (Zero tampering detected)."

    def count(self) -> int:
        with read_tx() as conn:
            return conn.execute(select(func.count()).select_from(LEDGER)).scalar_one()

    def get_all_entries(self) -> List[AuditLogEntry]:
        return self.get_trail_for()

    def get_trail_for(self, role: str = "auditor", mandate_id: Optional[str] = None, attempt_id: Optional[str] = None) -> List[AuditLogEntry]:
        query = select(LEDGER).order_by(LEDGER.c.idx)
        if mandate_id:
            query = query.where(LEDGER.c.mandate_id == mandate_id)
        if attempt_id:
            query = query.where(LEDGER.c.attempt_id == attempt_id)
        with read_tx() as conn:
            return [self._entry(row) for row in conn.execute(query)]


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


def append_entry(event: dict, *, connection=None) -> dict:
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
        connection=connection,
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

    `mandate_id` y `attempt_id` filtran (antes del 4.1 `attempt_id` se ignoraba y
    devolvía el trail entero). Un humano o comercio sin mandate_id no ve nada.
    """
    if role in {"human", "merchant"} and not mandate_id:
        return []
    entries = _trail_entries(mandate_id=mandate_id, attempt_id=attempt_id)

    return [to_frontend_event(entry) for entry in reversed(entries)]
