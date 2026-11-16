from dotenv import load_dotenv
load_dotenv()

from datetime import datetime, timezone
import logging
import os
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware

from shared.schemas import (
    Mandate,
    RevokeMandateRequest,
    ExecutePurchaseRequest,
    CatalogItem,
)
from core.db import DatabaseConfigError, get_engine, validate_database_config
from core.mandate_store import (
    mandate_store,
    seal_seed_mandate,
    create_human_signed_mandate,
    get_mandate as store_get_mandate,
    revoke_mandate as store_revoke_mandate,
    reset_mandate,
)
from core.merchant import vuelaya_merchant
from core.agent_loop import PurchasingAgent
from api.security import (
    Principal,
    owner_email_for,
    require_human_principal,
    require_mandate_access,
    require_principal,
)
from audit.log import LedgerIntegrityError, audit_ledger, append_entry, get_trail_for
from core.auth_config import ServiceKeyConfigError, validate_service_key_config
from core.auth_tokens import TokenConfigError, validate_token_config
from core.agent_keys import get_or_create_agent_keys
from core.signed_mandates import (
    SignedMandateError,
    build_signed_mandate,
    missing_signature_detail,
    parse_signed_body,
)

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
                    # No trae firma: al crearlo, el servidor lo SELLA con una llave
                    # Ed25519 real (sello de sistema/legado, verificable en /verify).
                    # Un placeholder de texto ya no pasaría: la verificación es fail-closed.
                    seal_seed_mandate(m, owner_email=(m.get("human") or {}).get("email"))
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
    # 6.2: la base es obligatoria fuera de desarrollo y se migra a la última versión
    # ANTES de servir (un esquema viejo no debe recibir tráfico).
    try:
        validate_database_config()
        get_engine()
    except DatabaseConfigError as error:
        startup_logger.critical("AgentBuyer API no puede arrancar: %s", error)
        raise
    # 6.3: la evidencia se verifica COMPLETA antes de servir. Con la cadena rota la API
    # no arranca (no hay modo solo lectura: docs/design/persistence.md §6). Para
    # investigar sin la API: python -m scripts.verify_ledger
    chain_ok, chain_detail = audit_ledger.verify_chain_integrity()
    if not chain_ok:
        startup_logger.critical("AgentBuyer API no puede arrancar: el ledger de auditoría no verifica. %s", chain_detail)
        raise LedgerIntegrityError(chain_detail)
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

# Llaves del AGENTE: viven en core/agent_keys.py (servidor, P-02); las de las
# personas nunca están en el servidor (cada titular firma en su dispositivo).
_get_or_create_agent_keys = get_or_create_agent_keys


@app.get("/")
def root():
    """Estado mínimo del servicio. La UI es el frontend React (frontend/)."""
    return {"service": "AgentBuyer API", "status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok"}


# 7.1 (P-07): GET /inbox/messages (leía el Gmail del proyecto por IMAP) y
# POST /notifications/send-ticket (mandaba un "recibo" con datos inventados a cualquier
# dirección) se retiraron. El recibo es un servicio interno que dispara la compra
# (core/notifications.send_purchase_receipt).


# Mandate Endpoints
# (POST /mandates/create se retiró en el 3.5, P-02: firmaba con llaves "humanas" que
# guardaba el servidor. Hoy el único alta es POST /mandates, firmado por el titular.)
@app.post("/mandates", status_code=status.HTTP_201_CREATED)
async def create_mandate_endpoint(
    request: Request,
    principal: Principal = Depends(require_human_principal),
):
    """Crea un mandato FIRMADO por su titular y establece su estado vivo inicial.

    Desde el 3.5 es el único camino: el cuerpo trae el formato del 3.2 (key_id + nonce
    + created_at + signature) firmado con la llave registrada del dispositivo, y se
    verifica antes de guardar (kind=human). El servidor ya no firma por nadie:
    sin firma → 422; firma o llave que no valen → 403 (core/signed_mandates.py).

    Exige token de persona (user/admin): quien lo crea queda como su dueño, y el
    dueño sale del token, nunca del cuerpo."""
    raw = await request.body()
    try:
        # Los montos como Decimal: lo firmado no puede pasar por float.
        body = parse_signed_body(raw)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="The body must be valid JSON.") from None
    missing = missing_signature_detail(body)
    if missing is not None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=missing)

    owner_email = owner_email_for(principal)
    try:
        mandate, signer, nonce = build_signed_mandate(body, owner_email)
    except SignedMandateError as error:
        raise HTTPException(status_code=error.status_code, detail=error.detail) from None
    try:
        record = create_human_signed_mandate(
            mandate, signer, owner_email, nonce,
            created_at=datetime.strptime(mandate["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
        )
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    append_entry(
        {
            "type": "mandate_created",
            "mandate_id": mandate["mandate_id"],
            "summary": f"Mandato firmado por el titular creado para {mandate.get('human', {}).get('display_name', 'la persona autorizante')}.",
        }
    )
    return record


@app.get("/mandates", response_model=List[Mandate])
def api_list_mandates(human_id: Optional[str] = None, principal: Principal = Depends(require_principal)):
    return mandate_store.list_mandates(human_id)


@app.get("/mandates/{mandate_id}")
def api_get_mandate(mandate_id: str, principal: Principal = Depends(require_mandate_access)):
    rec = store_get_mandate(mandate_id)
    if rec is not None:
        return rec
    raise HTTPException(status_code=404, detail="Mandate not found")



@app.post("/mandates/{mandate_id}/revoke")
def api_revoke_mandate(
    mandate_id: str,
    req: Optional[RevokeMandateRequest] = None,
    principal: Principal = Depends(require_mandate_access),
):
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
def api_pause_mandate(mandate_id: str, principal: Principal = Depends(require_mandate_access)):
    success = mandate_store.pause_mandate(mandate_id)
    if not success:
        raise HTTPException(status_code=404, detail="Mandate not found")
    return {"status": "PAUSED", "mandate_id": mandate_id}


@app.post("/mandates/{mandate_id}/reset")
def reset_mandate_endpoint(mandate_id: str, principal: Principal = Depends(require_mandate_access)):
    """Restaura el mandato a un estado vivo fresco para reiniciar la demo."""
    record = reset_mandate(mandate_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mandato no encontrado.")
    return record


@app.post("/mandates/{mandate_id}/resume")
def api_resume_mandate(mandate_id: str, principal: Principal = Depends(require_mandate_access)):
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

    a_keys = _get_or_create_agent_keys(req.agent_id)
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
def api_get_mandate_activity(mandate_id: str, principal: Principal = Depends(require_mandate_access)):
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


# 7.1 (P-06): se retiraron POST /purchases/{id}/approve-exception (escribía una
# "aprobación con Passkey" en el ledger sin verificar nada), POST /webhooks/stripe y
# POST /webhooks/travel-provider. Los webhooks NO tenían autenticación: cualquiera podía
# escribir eventos settlement_completed en el ledger, y el de viajes enviaba correos a la
# dirección que le pasaran. Los pagos reales (Stripe con verificación de firma y secretos
# por entorno) son el siguiente paso documentado, no algo que la demo simule.


# Audit Trail Router (POST /audit/reset vive SOLO en api/audit.py desde el 4.1: era
# una ruta registrada dos veces, y ahora es una utilidad de desarrollo, P-05.)


@app.get("/audit/verify")
def api_verify_audit_integrity():
    is_valid, msg = audit_ledger.verify_chain_integrity()
    return {"valid": is_valid, "message": msg, "total_blocks": audit_ledger.count()}



# Disputas: /disputes/file y /disputes viven en api/disputes.py (resolver
# nativo del modelo API/React). core/dispute.py sigue sirviendo al flujo adversarial.


# (POST /adversarial/run se retiró en el 3.5: creaba mandatos sellados por el servidor
# en el registro VIVO. Los ataques a la firma son ahora regresión permanente en CI:
# tests/test_mandate_signature_attacks.py.)


# Include modular routers
from api.agent import router as agent_router
from api.audit import router as audit_router
from api.auth import router as auth_router
from api.disputes import router as disputes_router
from api.escalations import router as escalations_router
from api.keys import router as keys_router
from api.merchant import router as merchant_router

app.include_router(agent_router)
app.include_router(audit_router)
app.include_router(auth_router)
app.include_router(disputes_router)
app.include_router(escalations_router)
app.include_router(keys_router)
app.include_router(merchant_router)

try:
    from api.verify import router as verify_router
    app.include_router(verify_router)
except ImportError:
    pass
