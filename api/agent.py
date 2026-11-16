"""API para ejecutar una corrida completa del agente comprador.

Desde el 4.1 exige sesión y ser dueño del mandato (o admin), y consume la cuota
por usuario (core/quotas.py): cada corrida busca ofertas reales en la web.

4.2: acepta `scenario` ("trap_offer" | "after_revocation") para la demo, solo para
el dueño del mandato. Un escenario usa una oferta sintética, no busca en la web (no
gasta cuota) y nunca compra (core/agent_loop.py).
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from api.security import Principal, assert_can_access_mandate, require_principal
from core.agent_loop import SCENARIOS, ScenarioNotApplicable, SignedSearchFieldsMismatch, run_agent
from core.quotas import PerSubjectQuota, QuotaExceeded


router = APIRouter()

# Instancia del proceso; los tests la sustituyen por otra con reloj controlado.
agent_run_quota = PerSubjectQuota.agent_runs_from_env()


@router.post("/agent/run")
def run_buyer_agent(request: dict[str, Any], principal: Principal = Depends(require_principal)):
    """Hace que el agente descubra vuelos, decida y presente una compra.

    Orden: sesión (401) → cuerpo (422) → dueño del mandato (404/403) → cuota (429 con
    Retry-After). Un no-dueño o un cuerpo inválido no gastan cuota de nadie."""
    mandate_id = request.get("mandate_id")
    if not isinstance(mandate_id, str) or not mandate_id.strip():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="El campo mandate_id es obligatorio y debe ser un texto no vacío.")
    # Opcional: con search_fields el agente descubre ofertas reales en la web
    # ({origin, destination, departure_date, ...}); sin él usa los del mandato. En un
    # mandato firmado por el titular solo puede usar los firmados (3.3).
    search_fields = request.get("search_fields")
    if search_fields is not None and not isinstance(search_fields, dict):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="search_fields debe ser un objeto.")
    scenario = request.get("scenario")
    if scenario is not None and scenario not in SCENARIOS:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"scenario must be one of: {', '.join(SCENARIOS)}.")
    assert_can_access_mandate(principal, mandate_id)

    if scenario is not None:
        # Escenario de demostración: sin búsqueda web (no gasta cuota) y sin compra.
        try:
            return run_agent(mandate_id, search_fields, scenario=scenario)
        except ScenarioNotApplicable as error:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from None
        except SignedSearchFieldsMismatch as error:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)) from None

    try:
        agent_run_quota.consume(principal.subject)
    except QuotaExceeded as exceeded:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="You've reached the limit of agent runs for now. Try again later.",
            headers={"Retry-After": str(exceeded.retry_after_seconds)},
        ) from None
    try:
        return run_agent(mandate_id, search_fields)
    except SignedSearchFieldsMismatch as error:
        # Mandato firmado por el titular: buscar otra cosa no se ignora, se rechaza.
        # No llegó a buscar: el uso de la cuota se devuelve.
        agent_run_quota.refund(principal.subject)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)) from None
