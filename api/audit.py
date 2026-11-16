"""Vistas de solo lectura para el trail de auditoría append-only.

4.1: GET /audit exige sesión y muestra a cada usuario SOLO los eventos de sus
mandatos; un admin ve todo (P-04).

6.3: POST /audit/reset ya no existe (P-05: sale del producto). El ledger vive en la
base y la base misma impide borrarlo. "Empezar de cero" en desarrollo es borrar el
archivo de la base de desarrollo con la API detenida (.env.example).
"""

from fastapi import APIRouter, Depends

from api.security import Principal, is_admin, owner_email_for, require_mandate_access, require_principal
from audit.log import get_trail_for
from core.mandate_store import mandate_ids_owned_by


router = APIRouter()


@router.get("/audit")
def get_audit_trail(principal: Principal = Depends(require_principal)):
    """Trail para la vista de auditoría: el del usuario (sus mandatos) o, para un
    admin, el completo (P-04)."""
    events = get_trail_for("auditor")
    if is_admin(principal):
        return events
    owned = mandate_ids_owned_by(owner_email_for(principal))
    return [event for event in events if event.get("mandate_id") in owned]


@router.get("/audit/{mandate_id}")
def get_mandate_audit_trail(mandate_id: str, principal: Principal = Depends(require_mandate_access)):
    """Devuelve los eventos visibles para el humano dueño de un mandato.

    Exige ser su dueño (o admin): el trail cuenta qué compró y por cuánto."""
    return get_trail_for("human", mandate_id)
