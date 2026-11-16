"""Revisión humana de compras escaladas — el eslabón que faltaba del flujo.

Una compra ESCALATE quedó evaluada y detenida; aquí una persona la aprueba o
rechaza. NO se re-corre el engine: se registra la decisión humana sobre esa
evaluación existente. Lo único que sí se re-verifica es el estado vivo del
mandato — una persona jamás puede aprobar sobre un mandato revocado/expirado.
"""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError

from api.security import Principal, require_mandate_access
from audit.log import append_entry, get_trail_events
from core.db import write_tx
from core.db_schema import escalation_decisions as ESCALATION_DECISIONS
from core.mandate_store import apply_approved_purchase, get_mandate, get_mandate_signer
from core.money import is_cents
from core.signed_mandates import KIND_HUMAN, verify_signing_key_active


router = APIRouter()

_OVERRIDE_TYPES = {"human_override_approved", "human_override_declined"}


def _latest_verification(attempt_id: str) -> dict | None:
    """Última verificación registrada para el intento (el ledger es append-only)."""
    for event in reversed(get_trail_events(attempt_id=attempt_id)):
        if event.get("type") == "verification":
            return event
    return None


def _existing_override(attempt_id: str) -> dict | None:
    for event in get_trail_events(attempt_id=attempt_id):
        if event.get("type") in _OVERRIDE_TYPES:
            return event
    return None


@router.post("/mandates/{mandate_id}/approve_escalation")
def approve_escalation(
    mandate_id: str,
    request: dict[str, Any],
    principal: Principal = Depends(require_mandate_access),
):
    """Registra la decisión humana (approve/decline) sobre un intento escalado."""
    attempt_id = request.get("purchase_attempt_id")
    decision = request.get("decision")
    if not isinstance(attempt_id, str) or not attempt_id.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="purchase_attempt_id is required and must be a non-empty text.",
        )
    if decision not in ("approve", "decline"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail='decision must be "approve" or "decline".',
        )

    verification = _latest_verification(attempt_id)
    if verification is None or verification.get("mandate_id") != mandate_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="There is no recorded verification for that attempt on this mandate.",
        )
    if verification.get("verdict") != "ESCALATE":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Only escalated attempts allow human review; this one was {verification.get('verdict')}.",
        )
    if _existing_override(attempt_id) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This attempt was already reviewed by a person.",
        )

    # Re-chequeo del estado vivo, fresco, igual que en /verify: si el mandato
    # fue revocado o expiró después de la escalación, la revisión no procede.
    record = get_mandate(mandate_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mandate not found.")
    live_status = record["live_state"]["status"]
    if live_status != "active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"The mandate is {live_status}: a human review cannot "
                "approve purchases on a mandate that is no longer valid."
            ),
        )

    # P-01 (a): si la llave que firmó el mandato fue revocada, lo firmado ya no
    # autoriza nada; tampoco una aprobación humana sobre él (4.1).
    signer = get_mandate_signer(mandate_id)
    if signer is not None and signer.get("kind") == KIND_HUMAN and not verify_signing_key_active(signer)[0]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The key that signed the mandate was revoked: a human review cannot approve purchases on it.",
        )

    escalation_reason = {
        "failed_rules": verification.get("failed_rules", []),
        "summary": verification.get("summary", ""),
    }

    amount_cents = verification.get("amount_cents")
    if decision == "approve" and (not is_cents(amount_cents) or amount_cents <= 0):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The escalation did not record a verifiable amount; it cannot be approved.",
        )
    verdict = "APPROVE" if decision == "approve" else "REJECT"
    human_readable = ("Purchase approved by human review after escalation." if decision == "approve"
                      else "Purchase declined by human review after escalation.")
    outcome = "APPROVED" if decision == "approve" else "DECLINED"
    decided_at = datetime.now(timezone.utc).isoformat()

    # 6.3 (H2): la decisión, la compra y su evento del ledger son UNA transacción, y la
    # decisión tiene al intento como clave primaria. Antes "¿ya hay decisión?" y "aplicar
    # la compra" eran pasos separados: dos aprobaciones simultáneas cobraban dos veces.
    try:
        with write_tx() as connection:
            connection.execute(insert(ESCALATION_DECISIONS).values(
                attempt_id=attempt_id, mandate_id=mandate_id, decision=decision,
                decided_by=principal.subject, decided_at=decided_at,
            ))
            if decision == "approve":
                # Exactamente el mismo efecto que un APPROVE del flujo normal.
                apply_approved_purchase(mandate_id, amount_cents, connection=connection)
            append_entry(
                {
                    "type": "human_override_approved" if decision == "approve" else "human_override_declined",
                    "mandate_id": mandate_id,
                    "attempt_id": attempt_id,
                    "verdict": verdict,
                    "escalation_reason": escalation_reason,
                    "summary": (
                        "Escalated for "
                        + (", ".join(escalation_reason["failed_rules"]) or "unrecorded rules")
                        + f" — reviewed and {outcome} by a person."
                    ),
                },
                connection=connection,
            )
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This attempt was already reviewed by a person.",
        ) from None

    # Misma forma que la respuesta de /verify para que el front la renderice igual.
    return {
        "attempt_id": attempt_id,
        "mandate_id": mandate_id,
        "verdict": verdict,
        "checks": [
            {
                "rule": "human_review",
                "pass": decision == "approve",
                "detail": (
                    "Approved by a person." if decision == "approve"
                    else "Declined by a person."
                ),
            },
            {"rule": "status", "pass": True, "detail": "Mandate active at the time of review."},
        ],
        "human_readable": human_readable,
        "decided_at": decided_at,
    }
