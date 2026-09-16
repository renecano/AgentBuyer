"""Revisión humana de compras escaladas — el eslabón que faltaba del flujo.

Una compra ESCALATE quedó evaluada y detenida; aquí una persona la aprueba o
rechaza. NO se re-corre el engine: se registra la decisión humana sobre esa
evaluación existente. Lo único que sí se re-verifica es el estado vivo del
mandato — una persona jamás puede aprobar sobre un mandato revocado/expirado.
"""

from datetime import datetime, timezone
from numbers import Real
from typing import Any

from fastapi import APIRouter, HTTPException, status

from audit.log import AUDIT_TRAIL, append_entry
from core.mandate_store import apply_approved_purchase, get_mandate


router = APIRouter()

_OVERRIDE_TYPES = {"human_override_approved", "human_override_declined"}


def _latest_verification(attempt_id: str) -> dict | None:
    """Última verificación registrada para el intento (el trail es append-only)."""
    for event in reversed(AUDIT_TRAIL):
        if event.get("type") == "verification" and event.get("attempt_id") == attempt_id:
            return event
    return None


def _existing_override(attempt_id: str) -> dict | None:
    for event in AUDIT_TRAIL:
        if event.get("type") in _OVERRIDE_TYPES and event.get("attempt_id") == attempt_id:
            return event
    return None


@router.post("/mandates/{mandate_id}/approve_escalation")
def approve_escalation(mandate_id: str, request: dict[str, Any]):
    """Registra la decisión humana (approve/decline) sobre un intento escalado."""
    attempt_id = request.get("purchase_attempt_id")
    decision = request.get("decision")
    if not isinstance(attempt_id, str) or not attempt_id.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="purchase_attempt_id es obligatorio y debe ser un texto no vacío.",
        )
    if decision not in ("approve", "decline"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail='decision debe ser "approve" o "decline".',
        )

    verification = _latest_verification(attempt_id)
    if verification is None or verification.get("mandate_id") != mandate_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No existe una verificación registrada para ese intento en este mandato.",
        )
    if verification.get("verdict") != "ESCALATE":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Solo los intentos escalados admiten revisión humana; este quedó {verification.get('verdict')}.",
        )
    if _existing_override(attempt_id) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Este intento ya fue revisado por una persona.",
        )

    # Re-chequeo del estado vivo, fresco, igual que en /verify: si el mandato
    # fue revocado o expiró después de la escalación, la revisión no procede.
    record = get_mandate(mandate_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mandato no encontrado.")
    live_status = record["live_state"]["status"]
    if live_status != "active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"El mandato está {live_status}: una revisión humana no puede "
                "aprobar compras sobre un mandato que ya no es válido."
            ),
        )

    escalation_reason = {
        "failed_rules": verification.get("failed_rules", []),
        "summary": verification.get("summary", ""),
    }

    if decision == "approve":
        amount = verification.get("amount")
        if not isinstance(amount, Real) or isinstance(amount, bool):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="La escalación no registró un monto verificable; no se puede aprobar.",
            )
        # Exactamente el mismo efecto que un APPROVE del flujo normal.
        apply_approved_purchase(mandate_id, amount)
        verdict = "APPROVE"
        human_readable = "Compra aprobada por revisión humana tras la escalación."
        append_entry(
            {
                "type": "human_override_approved",
                "mandate_id": mandate_id,
                "attempt_id": attempt_id,
                "verdict": verdict,
                "escalation_reason": escalation_reason,
                "summary": (
                    "Escalada por "
                    + (", ".join(escalation_reason["failed_rules"]) or "reglas no registradas")
                    + " — revisada y APROBADA por una persona."
                ),
            }
        )
    else:
        verdict = "REJECT"
        human_readable = "Compra rechazada por revisión humana tras la escalación."
        append_entry(
            {
                "type": "human_override_declined",
                "mandate_id": mandate_id,
                "attempt_id": attempt_id,
                "verdict": verdict,
                "escalation_reason": escalation_reason,
                "summary": (
                    "Escalada por "
                    + (", ".join(escalation_reason["failed_rules"]) or "reglas no registradas")
                    + " — revisada y RECHAZADA por una persona."
                ),
            }
        )

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
                    "Aprobada por una persona." if decision == "approve"
                    else "Rechazada por una persona."
                ),
            },
            {"rule": "status", "pass": True, "detail": "Mandato activo al momento de la revisión."},
        ],
        "human_readable": human_readable,
        "decided_at": datetime.now(timezone.utc).isoformat(),
    }
