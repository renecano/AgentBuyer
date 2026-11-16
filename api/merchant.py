"""API del comercio: catálogo mock VuelaYa + búsqueda real en la web."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from api.security import Principal, require_principal
from core.merchant_search import CATEGORY_SPECS, search_merchant_offers


router = APIRouter()


# 7.2 (P-08): GET /merchant/flights (catálogo de vuelos inventados de VuelaYa) se
# retiró con core/merchant.py. Las ofertas son las de la búsqueda real.


@router.post("/merchant/search")
def search_offers(request: dict[str, Any], principal: Principal = Depends(require_principal)):
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
            detail=f"category must be one of {sorted(CATEGORY_SPECS)}.",
        )
    if not isinstance(fields, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="fields must be an object with the search fields.",
        )
    max_results = request.get("max_results", 3)
    if not isinstance(max_results, int) or not 1 <= max_results <= 5:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="max_results must be an integer between 1 and 5.",
        )
    return search_merchant_offers(category, fields, max_results)
