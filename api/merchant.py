"""API del comercio: catálogo mock VuelaYa + búsqueda real en la web."""

from typing import Any

from fastapi import APIRouter, HTTPException, status

from core.merchant import get_flights
from core.merchant_search import CATEGORY_SPECS, search_merchant_offers


router = APIRouter()


@router.get("/merchant/flights")
def list_flights():
    """Devuelve el catálogo actual de vuelos inventados de VuelaYa."""
    return get_flights()


@router.post("/merchant/search")
def search_offers(request: dict[str, Any]):
    """Busca ofertas REALES vía web search (Despegar, Expedia, Kayak, ...).

    Body: {"category": "flights", "fields": {"origin": ..., ...}, "max_results": 3}
    Devuelve una lista de ofertas (posiblemente vacía si la búsqueda falla) —
    el caller decide el fallback al catálogo mock.
    """
    category = request.get("category")
    fields = request.get("fields")
    if not isinstance(category, str) or category not in CATEGORY_SPECS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"category debe ser una de {sorted(CATEGORY_SPECS)}.",
        )
    if not isinstance(fields, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="fields debe ser un objeto con los campos de búsqueda.",
        )
    max_results = request.get("max_results", 3)
    if not isinstance(max_results, int) or not 1 <= max_results <= 5:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="max_results debe ser un entero entre 1 y 5.",
        )
    return search_merchant_offers(category, fields, max_results)
