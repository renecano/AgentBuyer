"""Vistas de solo lectura para el trail de auditoría append-only.

4.1: GET /audit exige sesión y muestra a cada usuario SOLO los eventos de sus
mandatos; un admin ve todo (P-04). POST /audit/reset salió del producto (P-05):
borrar el ledger "append-only" solo existe como utilidad de desarrollo, con
AUTH_DEV_MODE=true Y rol admin; fuera de ese modo la ruta responde 404.
"""

from fastapi import APIRouter, Depends, HTTPException, status

from api.security import Principal, is_admin, owner_email_for, require_admin, require_mandate_access, require_principal
from audit.log import get_trail_for, reset_trail
from core.auth_config import auth_dev_mode_enabled
from core.mandate_store import mandate_ids_owned_by


router = APIRouter()


@router.post("/audit/reset")
def reset_audit_trail(principal: Principal = Depends(require_admin)):
    """Utilidad de DESARROLLO (P-05): reinicia el ledger. No es parte del producto."""
    if not auth_dev_mode_enabled():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return reset_trail()


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
