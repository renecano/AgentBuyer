"""Llaves públicas del dueño autenticado: registrar (POST /keys) y listar (GET /keys).

El dueño es SIEMPRE el subject del token (owner_email_for), nunca el cuerpo: un
campo owner/owner_email en el body se ignora, igual que al crear un mandato.
Aditivo: registrar una llave todavía no cambia la verificación de mandatos.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from api.security import Principal, owner_email_for, require_principal
from core.owner_keys import (
    InvalidPublicKey,
    KeyConflict,
    list_active_key_records,
    register_key,
)

router = APIRouter()

# Lo único que se expone de una llave: nada privado (el servidor no tiene nada
# privado del dueño) y sin el email, que ya es el del propio token.
_PUBLIC_FIELDS = ("key_id", "public_key", "alg", "created_at")


class RegisterKeyRequest(BaseModel):
    # Campos extra (p. ej. owner_email) se IGNORAN: Pydantic los descarta por defecto.
    public_key: str


def _owner(principal: Principal) -> str:
    owner = owner_email_for(principal)
    if owner is None:  # require_principal solo deja pasar user/admin; defensa en profundidad
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only a person can own keys.")
    return owner


def _public_view(record: dict) -> dict:
    return {field: record[field] for field in _PUBLIC_FIELDS}


@router.post("/keys", status_code=status.HTTP_201_CREATED)
def register_public_key(payload: RegisterKeyRequest, principal: Principal = Depends(require_principal)):
    """Registra una llave pública Ed25519 (64 hex) bajo el email del token."""
    owner = _owner(principal)
    try:
        key_id = register_key(owner, payload.public_key)
    except InvalidPublicKey as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)) from None
    except KeyConflict as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from None
    record = next(record for record in list_active_key_records(owner) if record["key_id"] == key_id)
    return _public_view(record)


@router.get("/keys")
def list_public_keys(principal: Principal = Depends(require_principal)):
    """Llaves ACTIVAS del dueño del token (las revocadas no aparecen)."""
    return {"keys": [_public_view(record) for record in list_active_key_records(_owner(principal))]}
