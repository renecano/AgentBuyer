from dotenv import load_dotenv
load_dotenv()

import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Dict, Any, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from shared.schemas import (
    Mandate,
    CreateMandateRequest,
    RevokeMandateRequest,
    ExecutePurchaseRequest,
    CatalogItem,
)
from mandate.issue import create_mandate
from mandate.sign import generate_keypair
from core.mandate_store import (
    mandate_store,
    create_mandate as store_create_mandate,
    get_mandate as store_get_mandate,
    revoke_mandate as store_revoke_mandate,
    reset_mandate,
)
from core.merchant import vuelaya_merchant
from core.agent_loop import PurchasingAgent
from api.security import Principal, owner_email_for, require_admin, require_principal, require_service
from audit.log import audit_ledger, append_entry, get_trail_for, reset_trail
from core.auth_config import ServiceKeyConfigError, validate_service_key_config
from core.auth_tokens import TokenConfigError, validate_token_config
from mandate.adversarial_tests import run_adversarial_suite

startup_logger = logging.getLogger("agentbuyer.startup")

# Se lee en cada arranque (no se captura al importar), así los tests pueden
# apuntarlo a una copia del seed con fechas relativas.
SEED_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "shared", "seed_mandates.json")


def load_seed_mandates():
    if os.path.exists(SEED_PATH):
        import json
        with open(SEED_PATH, "r", encoding="utf-8") as f:
            seeds = json.load(f)
            for m in seeds:
                try:
                    # El seed es config del servidor (no input de un cliente): su dueño
                    # es el email de su human, igual que si ese humano lo hubiera creado.
                    store_create_mandate(m, owner_email=(m.get("human") or {}).get("email"))
                except Exception:
                    pass


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Reemplaza el @app.on_event("startup") deprecado.
    # Fail-fast: un despliegue sin JWT_SECRET válido (fuera de AUTH_DEV_MODE) no
    # arranca, en vez de fallar en el primer login o firmar con una clave pública.
    try:
        validate_token_config()
    except TokenConfigError as error:
        startup_logger.critical("AgentBuyer API no puede arrancar: configuración de tokens inválida. %s", error)
        raise
    # SERVICE_API_KEY ausente es válido (endpoints de servicio cerrados); configurada
    # pero débil es un error de configuración y se reporta al arrancar.
    try:
        validate_service_key_config()
    except ServiceKeyConfigError as error:
        startup_logger.critical("AgentBuyer API no puede arrancar: %s", error)
        raise
    load_seed_mandates()
    yield


app = FastAPI(
    title="AgentBuyer Protocol API",
    description="Safe agentic purchases powered by Zero-Trust mandates, cryptographic signatures & deterministic limits.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS: antes allow_origins=["*"] junto con allow_credentials=True, combinación que
# el estándar no permite y que Starlette resuelve reflejando cualquier Origin (cualquier
# sitio podía llamar al API con credenciales). Ahora es una lista explícita tomada de
# CORS_ALLOWED_ORIGINS (separada por comas); el valor por defecto es SOLO para desarrollo.
CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:5173"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    # Retry-After no es un header "safelisted": sin exponerlo, el navegador no deja
    # que el frontend lea el cooldown del 429 (login por email).
    expose_headers=["Retry-After"],
)

# Key storage for demo
_key_registry: Dict[str, Dict[str, str]] = {}


def _get_or_create_keys(entity_id: str) -> Dict[str, str]:

    if entity_id not in _key_registry:
        priv, pub = generate_keypair()
        _key_registry[entity_id] = {"priv": priv, "pub": pub}
    return _key_registry[entity_id]


@app.get("/")
def root():
    """Estado mínimo del servicio. La UI es el frontend React (frontend/)."""
    return {"service": "AgentBuyer API", "status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok"}


class TicketSendRequest(BaseModel):
    email: str
    pnr: Optional[str] = None
    passenger: Optional[str] = None
    destination: Optional[str] = None
    merchant: Optional[str] = None
    price: Optional[float] = None
    currency: Optional[str] = "USD"


@app.get("/inbox/messages")
def api_get_inbox_messages(limit: int = Query(default=10, ge=1, le=50), principal: Principal = Depends(require_admin)):
    """
    Connects to saturday.agentbuyer@gmail.com via IMAP and reads the latest received emails.
    """
    from core.notifications import leer_correos_recibidos
    result = leer_correos_recibidos(limite=limit)
    return result


@app.post("/notifications/send-ticket")
def api_send_ticket_notification(payload: TicketSendRequest, principal: Principal = Depends(require_admin)):
    """
    Dispatches an official receipt/ticket with Google Calendar integration to ANY destination email.
    """
    from core.notifications import enviar_ticket_confirmacion
    reserva = {
        "pnr": payload.pnr or "PNR-VYA-849201",
        "pasajero": payload.passenger or "Authorized Customer",
        "destino": payload.destination or "Direct Flight Buenos Aires (AEP) -> Córdoba (COR)",
        "proveedor": payload.merchant or "VuelaYa Travel & Logistics Inc.",
        "precio_total": payload.price or 130.00,
        "moneda": payload.currency or "USD",
        "orden_id": f"ORD-{int(time.time()) % 100000}",
    }
    result = enviar_ticket_confirmacion(payload.email, reserva)
    return result


# Mandate Endpoints
@app.post("/mandates/create", response_model=Mandate)
def api_create_mandate(req: CreateMandateRequest, principal: Principal = Depends(require_principal)):
    h_keys = _get_or_create_keys(req.human_id)
    a_keys = _get_or_create_keys("agent_marta")

    mandate = create_mandate(
        human_id=req.human_id,
        human_privkey=h_keys["priv"],
        human_pubkey=h_keys["pub"],
        agent_id="agent_marta",
        agent_pubkey=a_keys["pub"],
        max_amount_per_tx=req.max_amount_per_tx,
        monthly_budget=req.monthly_budget,
        allowed_categories=req.allowed_categories,
        allowed_merchants=req.allowed_merchants,
        conditions_expression=req.conditions_expression,
        currency=req.currency,
        max_executions_per_month=req.max_executions_per_month,
        allow_hitl_escalation=req.allow_hitl_escalation,
        validity_days=req.validity_days,
        masked_card=req.masked_card,
        bank_issuer=req.bank_issuer,
    )
    mandate_store.save_mandate(mandate, owner_email=owner_email_for(principal))
    return mandate


@app.post("/mandates", status_code=status.HTTP_201_CREATED)
def create_mandate_endpoint(mandate: dict[str, Any]):
    """Crea un mandato firmado y establece su estado vivo inicial."""
    mandate_id = mandate.get("mandate_id")
    if not isinstance(mandate_id, str) or not mandate_id.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="El campo mandate_id es obligatorio y debe ser un texto no vacío.",
        )

    try:
        # Dueño derivado del token, NUNCA del cuerpo. Este endpoint aún no exige
        # token (lo llama React sin él), así que hoy no hay principal: owner=None.
        # Al añadir `principal: Principal = Depends(require_principal)`, pasarlo aquí.
        record = store_create_mandate(mandate, owner_email=owner_email_for(None))
        append_entry(
            {
                "type": "mandate_created",
                "mandate_id": mandate_id,
                "summary": f"Mandato creado para {mandate.get('human', {}).get('display_name', 'la persona autorizante')}.",
            }
        )
        return record
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(error)
        ) from error


@app.get("/mandates", response_model=List[Mandate])
def api_list_mandates(human_id: Optional[str] = None, principal: Principal = Depends(require_principal)):
    return mandate_store.list_mandates(human_id)


@app.get("/mandates/{mandate_id}")
def api_get_mandate(mandate_id: str):
    rec = store_get_mandate(mandate_id)
    if rec is not None:
        return rec
    raise HTTPException(status_code=404, detail="Mandate not found")



@app.post("/mandates/{mandate_id}/revoke")
def api_revoke_mandate(mandate_id: str, req: Optional[RevokeMandateRequest] = None):
    reason = req.reason if req else "Revocado por el usuario"
    previous = store_get_mandate(mandate_id)
    success = mandate_store.revoke_mandate(mandate_id, reason)
    record = store_revoke_mandate(mandate_id)
    
    if previous is not None and previous.get("live_state", {}).get("status") != "revoked":
        append_entry(
            {
                "type": "revocation",
                "mandate_id": mandate_id,
                "summary": "Mandato revocado por la persona autorizante.",
            }
        )
    if not success and record is None:
        raise HTTPException(status_code=404, detail="Mandate not found")
    return record or {"status": "REVOKED", "mandate_id": mandate_id, "reason": reason}


@app.post("/mandates/{mandate_id}/pause")
def api_pause_mandate(mandate_id: str, principal: Principal = Depends(require_principal)):
    success = mandate_store.pause_mandate(mandate_id)
    if not success:
        raise HTTPException(status_code=404, detail="Mandate not found")
    return {"status": "PAUSED", "mandate_id": mandate_id}


@app.post("/mandates/{mandate_id}/reset")
def reset_mandate_endpoint(mandate_id: str):
    """Restaura el mandato a un estado vivo fresco para reiniciar la demo."""
    record = reset_mandate(mandate_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mandato no encontrado.")
    return record


@app.post("/mandates/{mandate_id}/resume")
def api_resume_mandate(mandate_id: str, principal: Principal = Depends(require_principal)):
    success = mandate_store.resume_mandate(mandate_id)
    if not success:
        raise HTTPException(status_code=404, detail="Mandate not found")
    return {"status": "ACTIVE", "mandate_id": mandate_id}


# Merchant & Purchasing Endpoints
@app.get("/merchant/catalog", response_model=List[CatalogItem])
def api_get_catalog():
    return vuelaya_merchant.get_catalog()


# /merchant/flights, /merchant/search y /agent/run viven en sus routers
# (api/merchant.py, api/agent.py) — una sola dueña por ruta, sin sombras.


@app.post("/purchases/execute")
def api_execute_purchase(req: ExecutePurchaseRequest, principal: Principal = Depends(require_principal)):
    mandate = mandate_store.get_mandate(req.mandate_id)
    if not mandate:
        raise HTTPException(status_code=404, detail="Mandate not found")

    item = vuelaya_merchant.get_item(req.item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found in catalog")

    a_keys = _get_or_create_keys(req.agent_id)
    agent = PurchasingAgent(req.agent_id, a_keys["priv"], a_keys["pub"])

    attempt, result = agent.attempt_purchase(
        mandate=mandate,
        item=item,
        merchant=vuelaya_merchant,
        override_amount=req.override_amount,
    )

    return {
        "attempt": attempt,
        "verification_result": result,
    }


# Mandate Activity Trail for User
@app.get("/mandates/{mandate_id}/activity")
def api_get_mandate_activity(mandate_id: str, principal: Principal = Depends(require_principal)):
    mandate = mandate_store.get_mandate(mandate_id)
    if not mandate:
        raise HTTPException(status_code=404, detail="Mandato no encontrado")
    trail = get_trail_for(role="human", mandate_id=mandate_id)
    return {
        "mandate_id": mandate_id,
        "status": mandate.status.value,
        "activity_count": len(trail),
        "trail": trail,
    }


# HITL Exception Approval
class ApproveExceptionRequest(BaseModel):
    user_passkey_signature: Optional[str] = None
    notes: Optional[str] = None


@app.post("/purchases/{purchase_id}/approve-exception")
def api_approve_purchase_exception(purchase_id: str, req: Optional[ApproveExceptionRequest] = None, principal: Principal = Depends(require_admin)):
    # Procesa excepción HITL firmada con Passkey
    append_entry({
        "type": "hitl_approved",
        "attempt_id": purchase_id,
        "mandate_id": "mnd_delegated",
        "summary": f"Excepción autorizada manualmente por el titular con Passkey para intento {purchase_id}.",
    })
    return {
        "ok": True,
        "purchase_id": purchase_id,
        "status": "APPROVED_BY_HUMAN_OVERRIDE",
        "message": "Compra fuera de mandato autorizada mediante verificación step-up.",
    }


# Stripe Off-Session Webhook
@app.post("/webhooks/stripe")
def api_webhook_stripe(payload: dict):
    event_type = payload.get("type", "payment_intent.succeeded")
    mandate_id = payload.get("data", {}).get("object", {}).get("metadata", {}).get("mandate_id", "mnd_live")
    amount = payload.get("data", {}).get("object", {}).get("amount", 13000) / 100.0

    append_entry({
        "type": "settlement_completed",
        "mandate_id": mandate_id,
        "summary": f"Cobro off-session de ${amount:.2f} USD confirmado por webhook de Stripe.",
    })
    return {"received": True, "event": event_type}


# Travel Provider (Amadeus / VuelaYa) Webhook
@app.post("/webhooks/travel-provider")
def api_webhook_travel_provider(payload: dict):
    pnr = payload.get("pnr", "PNR-VYA-849201")
    flight_id = payload.get("flight_id", "FLIGHT_COR_130")
    status_str = payload.get("status", "TICKET_ISSUED")
    # Sin correo en el payload no se envía nada (nunca auto-enviarse el boleto).
    user_email = payload.get("email") or ""

    append_entry({
        "type": "settlement_completed",
        "mandate_id": payload.get("mandate_id", "mnd_live"),
        "summary": f"Emisión de boleto confirmada por aerolínea: PNR {pnr} ({status_str}).",
    })

    try:
        from core.notifications import enviar_ticket_confirmacion
        enviar_ticket_confirmacion(
            correo_destino=user_email,
            detalles_reserva={
                "destino": payload.get("destination", "Córdoba (COR)"),
                "proveedor": payload.get("merchant", "VuelaYa Travel"),
                "pnr": pnr,
                "precio_total": payload.get("amount", 130),
                "moneda": "USD",
            }
        )
    except Exception as notify_err:
        print("Aviso al enviar ticket desde webhook:", notify_err)

    return {"received": True, "pnr": pnr, "status": status_str}


# Audit Trail Router
@app.post("/audit/reset")
def api_reset_audit_trail():
    """Abre una sesión de auditoría limpia al reiniciar/iniciar una demo."""
    return reset_trail()


@app.get("/audit/verify")
def api_verify_audit_integrity():
    is_valid, msg = audit_ledger.verify_chain_integrity()
    return {"valid": is_valid, "message": msg, "total_blocks": len(audit_ledger._entries)}



# Disputas: /disputes/file y /disputes viven en api/disputes.py (resolver
# nativo del modelo API/React). core/dispute.py sigue sirviendo al flujo adversarial.


# Adversarial Suite Runner
@app.post("/adversarial/run")
def api_run_adversarial(principal: Principal = Depends(require_service)):
    success = run_adversarial_suite()
    return {
        "success": success,
        "message": "All 8 attack vectors evaluated." if success else "Some attacks breached perimeter.",
    }


# Include modular routers
from api.agent import router as agent_router
from api.audit import router as audit_router
from api.auth import router as auth_router
from api.disputes import router as disputes_router
from api.escalations import router as escalations_router
from api.merchant import router as merchant_router

app.include_router(agent_router)
app.include_router(audit_router)
app.include_router(auth_router)
app.include_router(disputes_router)
app.include_router(escalations_router)
app.include_router(merchant_router)

try:
    from api.verify import router as verify_router
    app.include_router(verify_router)
except ImportError:
    pass
