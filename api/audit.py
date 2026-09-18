"""Vistas de solo lectura para el trail de auditoría append-only."""

from fastapi import APIRouter, Depends

from api.security import Principal, require_mandate_access
from audit.log import get_trail_for, reset_trail


router = APIRouter()


@router.post("/audit/reset")
def reset_audit_trail():
    """Abre una sesión de auditoría limpia para una nueva demo."""
    return reset_trail()


@router.get("/audit")
def get_audit_trail():
    """Devuelve el trail completo para la vista de auditoría."""
    return get_trail_for("auditor")


@router.get("/audit/{mandate_id}")
def get_mandate_audit_trail(mandate_id: str, principal: Principal = Depends(require_mandate_access)):
    """Devuelve los eventos visibles para el humano dueño de un mandato.

    Exige ser su dueño (o admin): el trail cuenta qué compró y por cuánto."""
    return get_trail_for("human", mandate_id)
