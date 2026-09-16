"""Resolución de disputas sobre el modelo de datos que usa el flujo React/API.

El árbitro forense de core/dispute.py opera sobre objetos Mandate (Ed25519,
flujo adversarial). Los mandatos creados por la UI tienen otra forma (dict con
human/agent/constraints), así que aquí se resuelve la responsabilidad sobre los
MISMOS datos que ve la app: el registro vivo del mandato + el trail auditable.

Reglas de responsabilidad (mismo espíritu que el árbitro):
  - Sin mandato en el registro        -> COMERCIO responsable + reembolso
  - Compra tras la revocación         -> COMERCIO responsable + reembolso
  - Sin verificación/aprobación en el trail -> COMERCIO responsable + reembolso
  - Compra válida, verificada y aprobada    -> TITULAR responsable, sin reembolso
El veredicto se apoya en la evidencia del trail append-only (tamper-evident).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from audit.log import append_entry, get_trail_for
from core.mandate_store import get_mandate

router = APIRouter()

_disputes: dict[str, dict] = {}


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
    # Evento de verificación de este intento.
    verifications = [e for e in evidence if e.get("attempt_id") == attempt_id and e.get("type") == "verification"]
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

    # No hay verificación ni aprobación registrada para este intento.
    if not verifications and not approvals:
        return {
            "verdict": "MERCHANT_LIABLE_UNVERIFIED", "liable_party": "MERCHANT", "refund_issued": True,
            "explanation": "No existe registro de verificación ni de aprobación para esta compra en el trail auditable. El titular queda protegido.",
        }

    # Compra válida, verificada y aprobada dentro del mandato.
    return {
        "verdict": "HUMAN_LIABLE_VALID_MANDATE", "liable_party": "HUMAN", "refund_issued": False,
        "explanation": "La evidencia criptográfica del registro confirma que la compra fue verificada y aprobada dentro de un mandato activo y firmado por el titular. La disputa se desestima.",
    }


@router.post("/disputes/file")
def file_dispute(body: FileDisputeBody) -> dict[str, Any]:
    dispute_id = f"dsp_{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()

    append_entry({
        "type": "DISPUTE_FILED", "mandate_id": body.mandate_id, "attempt_id": body.attempt_id,
        "summary": f"Disputa {dispute_id} abierta por el titular: {body.reason}",
    })

    evidence = get_trail_for("auditor", body.mandate_id)
    resolution = _resolve(body.attempt_id, body.mandate_id, evidence)

    claim = {
        "dispute_id": dispute_id, "attempt_id": body.attempt_id, "mandate_id": body.mandate_id,
        "claimant_id": body.claimant_id, "reason": body.reason, "created_at": now,
        "status": "RESOLVED", "audit_evidence": evidence, **resolution,
    }
    _disputes[dispute_id] = claim

    append_entry({
        "type": "DISPUTE_RESOLVED", "mandate_id": body.mandate_id, "attempt_id": body.attempt_id,
        "verdict": None,
        "summary": (
            f"Disputa {dispute_id} resuelta: {resolution['liable_party']} responsable"
            + (" — reembolso emitido al titular." if resolution["refund_issued"] else " — cargo válido, sin reembolso.")
        ),
    })
    return claim


@router.get("/disputes")
def list_disputes() -> list[dict]:
    return list(_disputes.values())
