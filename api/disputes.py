"""Resolución de disputas sobre el modelo de datos que usa el flujo React/API.

La responsabilidad se resuelve sobre los MISMOS datos que ve la app: el registro
vivo del mandato + el trail auditable. (7.2: el árbitro de la línea estricta,
core/dispute.py, se retiró con ella.)

Reglas de responsabilidad:
  - Sin mandato en el registro        -> COMERCIO responsable + reembolso
  - Compra tras la revocación         -> COMERCIO responsable + reembolso
  - Sin APROBACIÓN en el trail (no verificada, rechazada o escalada sin aprobar)
                                      -> COMERCIO responsable + reembolso
  - Compra válida, verificada y aprobada    -> TITULAR responsable, sin reembolso
El veredicto se apoya en la evidencia del trail append-only (tamper-evident).

4.1: abrir una disputa exige ser dueño del mandato (o admin), el intento debe ser
de ESE mandato (no se puede disputar un cargo ajeno bajo un mandato propio) y la
evidencia son solo los eventos de ese mandato (antes: el trail de todos). Listar
disputas muestra a cada uno las suyas; un admin, todas (misma regla que P-04).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import insert, select

from api.security import Principal, assert_can_access_mandate, is_admin, owner_email_for, require_principal
from audit.log import append_entry, get_trail_events
from core.db import read_tx, write_tx
from core.db_schema import disputes as DISPUTES
from core.mandate_store import get_mandate, mandate_ids_owned_by

router = APIRouter()

# 6.3: las disputas resueltas se guardan en la base (tabla disputes) con el JSON exacto
# que se devolvió; antes vivían en un dict y se perdían al reiniciar.


class FileDisputeBody(BaseModel):
    attempt_id: str
    mandate_id: str
    claimant_id: str = "hum_cardholder"
    reason: str = "El titular niega haber autorizado este cargo."


def _resolve(attempt_id: str, mandate_id: str, evidence: list[dict]) -> dict:
    """Devuelve (verdict, liable_party, refund, explanation) sobre datos dict."""
    record = get_mandate(mandate_id)
    if record is None:
        return {
            "verdict": "MERCHANT_LIABLE_NO_MANDATE", "liable_party": "MERCHANT", "refund_issued": True,
            "explanation": "El comercio procesó un pago contra un mandato que no existe en el registro. El titular queda protegido.",
        }

    live = record["live_state"]
    approvals = [
        e for e in evidence
        if e.get("attempt_id") == attempt_id
        and (e.get("verdict") == "APPROVE" or e.get("type") in ("purchase_completed", "human_override_approved"))
    ]

    # Compra ocurrida después de una revocación.
    revoked_at = live.get("revoked_at")
    if revoked_at and approvals:
        try:
            rev_t = datetime.fromisoformat(revoked_at)
            tx_t = datetime.fromisoformat(approvals[0]["timestamp"])
            if tx_t > rev_t:
                return {
                    "verdict": "MERCHANT_LIABLE_POST_REVOCATION", "liable_party": "MERCHANT", "refund_issued": True,
                    "explanation": f"El comercio aceptó la compra ({approvals[0]['timestamp']}) DESPUÉS de que el mandato fue revocado ({revoked_at}). El titular queda protegido.",
                }
        except (ValueError, KeyError):
            pass

    # No hay APROBACIÓN registrada para este intento. 7.2: antes bastaba un evento de
    # verificación, así que un intento RECHAZADO (o escalado y nunca aprobado) se
    # resolvía como "compra verificada y aprobada" a cargo del titular.
    if not approvals:
        return {
            "verdict": "MERCHANT_LIABLE_UNVERIFIED", "liable_party": "MERCHANT", "refund_issued": True,
            "explanation": "No existe una aprobación registrada para esta compra en el trail auditable (no se verificó, o se rechazó, o quedó escalada sin aprobar). El titular queda protegido.",
        }

    # Compra válida, verificada y aprobada dentro del mandato.
    return {
        "verdict": "HUMAN_LIABLE_VALID_MANDATE", "liable_party": "HUMAN", "refund_issued": False,
        "explanation": "La evidencia criptográfica del registro confirma que la compra fue verificada y aprobada dentro de un mandato activo y firmado por el titular. La disputa se desestima.",
    }


@router.post("/disputes/file")
def file_dispute(body: FileDisputeBody, principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    assert_can_access_mandate(principal, body.mandate_id)
    # El intento debe pertenecer a ESTE mandato: si el trail lo registra bajo otro,
    # disputarlo aquí sería reclamar (y cobrar el reembolso de) un cargo ajeno.
    foreign = {event.get("mandate_id") for event in get_trail_events()
               if event.get("attempt_id") == body.attempt_id and event.get("mandate_id") != body.mandate_id}
    if foreign:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This purchase attempt does not belong to this mandate.")

    dispute_id = f"dsp_{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()

    append_entry({
        "type": "DISPUTE_FILED", "mandate_id": body.mandate_id, "attempt_id": body.attempt_id,
        "summary": f"Disputa {dispute_id} abierta por el titular: {body.reason}",
    })

    # Evidencia: SOLO los eventos de este mandato (antes: el trail entero, con
    # eventos de otras personas), del más nuevo al más viejo, del ledger con cadena hash.
    evidence = [event for event in reversed(get_trail_events()) if event.get("mandate_id") == body.mandate_id]
    resolution = _resolve(body.attempt_id, body.mandate_id, evidence)

    claim = {
        "dispute_id": dispute_id, "attempt_id": body.attempt_id, "mandate_id": body.mandate_id,
        "claimant_id": body.claimant_id, "reason": body.reason, "created_at": now,
        "status": "RESOLVED", "audit_evidence": evidence, **resolution,
    }
    # La disputa resuelta y su evento en el ledger: una sola transacción.
    with write_tx() as connection:
        connection.execute(insert(DISPUTES).values(
            dispute_id=dispute_id, mandate_id=body.mandate_id, attempt_id=body.attempt_id,
            created_at=now, claim=json.dumps(claim, ensure_ascii=False),
        ))
        append_entry({
            "type": "DISPUTE_RESOLVED", "mandate_id": body.mandate_id, "attempt_id": body.attempt_id,
            "verdict": None,
            "summary": (
                f"Disputa {dispute_id} resuelta: {resolution['liable_party']} responsable"
                + (" — reembolso emitido al titular." if resolution["refund_issued"] else " — cargo válido, sin reembolso.")
            ),
        }, connection=connection)
    return claim


@router.get("/disputes")
def list_disputes(principal: Principal = Depends(require_principal)) -> list[dict]:
    """Las disputas de los mandatos del usuario; un admin ve todas."""
    with read_tx() as connection:
        rows = connection.execute(select(DISPUTES.c.mandate_id, DISPUTES.c.claim).order_by(DISPUTES.c.created_at)).all()
    if is_admin(principal):
        return [json.loads(row.claim) for row in rows]
    owned = mandate_ids_owned_by(owner_email_for(principal))
    return [json.loads(row.claim) for row in rows if row.mandate_id in owned]
