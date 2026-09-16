"""API para ejecutar una corrida completa del agente comprador."""

from typing import Any

from fastapi import APIRouter, HTTPException, status

from core.agent_loop import run_agent


router = APIRouter()


@router.post("/agent/run")
def run_buyer_agent(request: dict[str, Any]):
    """Hace que el agente descubra vuelos, decida y presente una compra."""
    mandate_id = request.get("mandate_id")
    if not isinstance(mandate_id, str) or not mandate_id.strip():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="El campo mandate_id es obligatorio y debe ser un texto no vacío.")
    # Opcional: con search_fields el agente descubre ofertas reales en la web
    # ({origin, destination, departure_date, ...}); sin él usa el catálogo demo.
    search_fields = request.get("search_fields")
    if search_fields is not None and not isinstance(search_fields, dict):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="search_fields debe ser un objeto.")
    return run_agent(mandate_id, search_fields)
