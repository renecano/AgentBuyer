import os
import json
import hmac
import hashlib
import base64
import time
import urllib.request
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

from shared.schemas import (
    Mandate,
    PurchaseAttempt,
    VerificationResult,
    VerificationStatus,
    HITLApprovalRequest,
    EventType,
    ActorType,
)
from mandate.sign import verify_signature
from core.mandate_store import mandate_store, get_mandate, apply_approved_purchase, record_verification_event
from engine.evaluator import evaluate_mandate_constraints
from engine.state import state_manager
from audit.log import audit_ledger

# Carga OPENAI_API_KEY desde el entorno o archivo .env local
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
if not OPENAI_API_KEY:
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("OPENAI_API_KEY="):
                    OPENAI_API_KEY = line.strip().split("=", 1)[1].strip('"\'')
                    os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY
                    break


def encode_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def consultar_llm_auditor(intento_desc: str, categoria_permitida: str = "flight") -> dict:
    """LLM Auditor: Actúa como Semantic Firewall consumiendo créditos de OpenAI con GPT-4o."""
    api_key = os.environ.get("OPENAI_API_KEY", OPENAI_API_KEY)
    if not api_key:
        return {"riesgo": "alto", "es_fraude": True, "motivo": "API Key de OpenAI no configurada en el entorno."}
        
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    
    prompt = (
        f"Actúa como un auditor forense de seguridad financiera. Analiza si la descripción del cobro "
        f"'{intento_desc}' intenta evadir la categoría permitida '{categoria_permitida}' o contiene cobros ocultos o tarjetas de regalo/activos líquidos. "
        f"Responde estrictamente en JSON con esta estructura: "
        f"{{\"riesgo\": \"bajo\" o \"alto\", \"es_fraude\": true o false, \"motivo\": \"explicación breve\"}}"
    )
    
    data = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
        "response_format": {"type": "json_object"}
    }
    
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            res = json.loads(response.read().decode('utf-8'))
            return json.loads(res['choices'][0]['message']['content'])
    except Exception as e:
        # Fallback de seguridad si hay error de red
        lower = intento_desc.lower()
        if any(w in lower for w in ["gift card", "tarjeta de regalo", "amazon", "crypto", "bitcoin", "por fuera", "48 horas"]):
            return {"riesgo": "alto", "es_fraude": True, "motivo": f"Detección de evasión o activo líquido: {intento_desc}"}
        return {"riesgo": "alto", "es_fraude": True, "motivo": f"Fallo en auditoría LLM ({str(e)}). Principio Fail-Closed."}


def evaluar_intento_compra(token_jwt: str, secret_key: bytes, base_datos_revocacion: dict, intento_compra: dict) -> dict:
    """Pasarela Zero-Trust de doble capa: Criptografía + Motor Determinista + LLM Auditor."""
    try:
        # Fase 1: Integridad Criptográfica (Tamper-proofing)
        partes = token_jwt.split('.')
        if len(partes) != 3:
            return {"status": 403, "mensaje": "Estructura de token inválida."}
        header, payload, firma = partes
        
        firma_esperada = encode_b64url(hmac.new(secret_key, f"{header}.{payload}".encode('utf-8'), hashlib.sha256).digest())
        if not hmac.compare_digest(firma, firma_esperada):
            return {"status": 403, "mensaje": "Firma criptográfica inválida. Manipulación detectada."}
            
        # Corregir padding de base64 si es necesario
        padded = payload + '=' * (-len(payload) % 4)
        datos = json.loads(base64.urlsafe_b64decode(padded.encode('utf-8')).decode('utf-8'))
        
        # Fase 2: Expiración del Mandato
        if datos.get("exp", 0) < time.time():
            return {"status": 403, "mensaje": "El mandato temporal ha expirado."}
            
        # Fase 3: Kill Switch (Consulta en Vivo en BD)
        mandate_id = datos.get("mandate_id")
        if base_datos_revocacion.get(mandate_id) == "REVOKED":
            return {"status": 403, "mensaje": "Kill Switch activado: Mandato revocado por el usuario."}
            
        # Fase 4: Límites Duros (Motor Determinista)
        if intento_compra["monto"] > datos.get("amount", 0):
            return {"status": 403, "mensaje": f"Límite excedido: ${intento_compra['monto']} > ${datos.get('amount')} autorizado."}
            
        # Fase 5: Auditoría Semántica (LLM Auditor con GPT-4o)
        auditoria = consultar_llm_auditor(intento_compra["descripcion"], "flight")
        if auditoria.get("es_fraude") or auditoria.get("riesgo") == "alto":
            return {"status": 403, "mensaje": f"Bloqueado por LLM Auditor: {auditoria.get('motivo')}"}
            
        return {"status": 200, "mensaje": "✅ 200 APROBADO: Verificación Zero-Trust superada con éxito. Listo para pasarela PCI."}
        
    except Exception as e:
        return {"status": 500, "mensaje": f"Error interno en pasarela: {str(e)}"}


# =========================================================================
# Verificación en 6 Etapas (Compatibilidad total con API del equipo y suites)
# =========================================================================
_escalation_inbox: Dict[str, HITLApprovalRequest] = {}


def get_pending_escalations(mandate_id: Optional[str] = None) -> List[HITLApprovalRequest]:
    if mandate_id:
        return [req for req in _escalation_inbox.values() if req.mandate_id == mandate_id and req.status == "PENDING"]
    return [req for req in _escalation_inbox.values() if req.status == "PENDING"]


def resolve_escalation(
    escalation_id: str,
    approved: bool,
    human_privkey: str,
    human_pubkey: str,
    note: str = "",
) -> Optional[VerificationResult]:
    if escalation_id not in _escalation_inbox:
        return None

    esc_req = _escalation_inbox[escalation_id]
    if esc_req.status != "PENDING":
        return None

    now_iso = datetime.now(timezone.utc).isoformat()
    esc_req.resolved_at = now_iso
    esc_req.resolution_note = note
    esc_req.status = "APPROVED" if approved else "REJECTED"

    mandate = mandate_store.get_mandate(esc_req.mandate_id)
    if not mandate:
        return None

    if approved:
        import uuid
        settlement_id = f"stl_{uuid.uuid4().hex[:10]}"
        dispute_token = f"dsp_{uuid.uuid4().hex[:12]}"
        
        state_manager.record_usage(
            mandate_id=mandate.mandate_id,
            amount=esc_req.attempt.amount,
            nonce=esc_req.attempt.nonce,
        )

        return VerificationResult(
            attempt_id=esc_req.attempt.attempt_id,
            status=VerificationStatus.APPROVED,
            authorized=True,
            reason=f"Approved by cardholder (HITL note: {note})",
            checks={"hitl_approval": True},
            settlement_id=settlement_id,
            dispute_token=dispute_token,
            escalation_id=escalation_id,
            timestamp=now_iso,
        )
    else:
        return VerificationResult(
            attempt_id=esc_req.attempt.attempt_id,
            status=VerificationStatus.REJECTED,
            authorized=False,
            reason=f"Rejected by cardholder during HITL escalation: {note}",
            checks={"hitl_approval": False},
            escalation_id=escalation_id,
            timestamp=now_iso,
        )


def verify_purchase(attempt: PurchaseAttempt) -> VerificationResult:
    now_iso = datetime.now(timezone.utc).isoformat()
    checks: Dict[str, bool] = {}

    # 1. Look up mandate in live store
    mandate = mandate_store.get_mandate(attempt.mandate_id)
    if not mandate:
        return VerificationResult(
            attempt_id=attempt.attempt_id,
            status=VerificationStatus.REJECTED,
            authorized=False,
            reason="Mandate not found in live registry.",
            checks={"mandate_exists": False},
            timestamp=now_iso,
        )
    checks["mandate_exists"] = True

    # 2. Check Live Status (Kill Switch)
    if mandate.status.value == "REVOKED":
        return VerificationResult(
            attempt_id=attempt.attempt_id,
            status=VerificationStatus.REJECTED,
            authorized=False,
            reason=f"Mandate is REVOKED. Revocation timestamp: {mandate.revoked_at}. Reason: {mandate.revocation_reason}",
            checks={"status_active": False},
            timestamp=now_iso,
        )
    checks["status_active"] = True

    # 3. Verify Human Signature (Ed25519)
    unsigned_mandate_payload = {
        "mandate_id": mandate.mandate_id,
        "human_id": mandate.human_id,
        "human_pubkey": mandate.human_pubkey,
        "agent_id": mandate.agent_id,
        "agent_pubkey": mandate.agent_pubkey,
        "scope": mandate.scope.model_dump(),
        "payment_token": mandate.payment_token.model_dump(),
        "created_at": mandate.created_at,
        "expires_at": mandate.expires_at,
        "status": "ACTIVE",
    }
    # ZERO-TRUST: verificación Ed25519 estricta contra el payload EXACTO firmado
    # por create_mandate. Sin fallbacks por longitud ni por payload alternativo —
    # una firma ausente, malformada o que no coincide falla cerrado (401/403).
    human_sig_valid = verify_signature(
        mandate.human_pubkey,
        unsigned_mandate_payload,
        mandate.human_signature,
    )

    checks["human_signature_valid"] = human_sig_valid
    if not human_sig_valid:
        return VerificationResult(
            attempt_id=attempt.attempt_id,
            status=VerificationStatus.REJECTED,
            authorized=False,
            reason="403 Forbidden: Human digital signature on mandate is INVALID or forged. Cryptographic verification failed.",
            checks=checks,
            timestamp=now_iso,
        )

    # 4. Verify Agent Signature
    unsigned_attempt_payload = {
        "attempt_id": attempt.attempt_id,
        "mandate_id": attempt.mandate_id,
        "agent_id": attempt.agent_id,
        "merchant_id": attempt.merchant_id,
        "category": attempt.category,
        "amount": attempt.amount,
        "currency": attempt.currency,
        "timestamp": attempt.timestamp,
        "nonce": attempt.nonce,
        "item_description": getattr(attempt, "item_description", getattr(attempt, "item_title", "")),
        "metadata": attempt.metadata,
    }
    # ZERO-TRUST: verificación Ed25519 estricta de la firma del agente sobre el
    # payload EXACTO del intento. Cualquier manipulación in-flight (monto, categoría,
    # identidad) rompe la firma. Sin bypass por longitud — falla cerrado.
    sig = attempt.agent_signature or attempt.signature
    agent_sig_valid = False
    if sig:
        try:
            agent_sig_valid = verify_signature(
                mandate.agent_pubkey,
                unsigned_attempt_payload,
                sig,
            )
        except Exception:
            agent_sig_valid = False

    checks["agent_signature_valid"] = agent_sig_valid
    if not agent_sig_valid:
        return VerificationResult(
            attempt_id=attempt.attempt_id,
            status=VerificationStatus.REJECTED,
            authorized=False,
            reason="403 Forbidden: Agent signature is INVALID, forged, tampered, or signed by an unauthorized (impersonating) entity.",
            checks=checks,
            timestamp=now_iso,
        )

    # 5. Nonce Replay Check
    nonce_valid = state_manager.validate_nonce(attempt.nonce)
    checks["nonce_fresh"] = nonce_valid
    if not nonce_valid:
        return VerificationResult(
            attempt_id=attempt.attempt_id,
            status=VerificationStatus.REJECTED,
            authorized=False,
            reason=f"REPLAY ATTACK DETECTED: Nonce '{attempt.nonce}' was already used in a previous purchase.",
            checks=checks,
            timestamp=now_iso,
        )

    # 6. Evaluate Constraints
    rolling_state = state_manager.get_or_create_state(mandate.mandate_id)
    authorized, reason, constraint_checks, can_escalate = evaluate_mandate_constraints(
        mandate=mandate,
        attempt=attempt,
        state=rolling_state,
    )
    checks.update(constraint_checks)

    if not authorized:
        if can_escalate and mandate.scope.allow_hitl_escalation:
            import uuid
            escalation_id = f"esc_{uuid.uuid4().hex[:10]}"
            hitl_req = HITLApprovalRequest(
                escalation_id=escalation_id,
                attempt_id=attempt.attempt_id,
                mandate_id=mandate.mandate_id,
                attempt=attempt,
                reason=reason,
                requested_amount=attempt.amount,
                mandate_limit=mandate.scope.max_amount_per_tx,
                created_at=now_iso,
            )
            _escalation_inbox[escalation_id] = hitl_req
            return VerificationResult(
                attempt_id=attempt.attempt_id,
                status=VerificationStatus.ESCALATED_HITL,
                authorized=False,
                reason=f"Out of bounds: {reason}. Escalated to cardholder for approval.",
                checks=checks,
                escalation_id=escalation_id,
                timestamp=now_iso,
            )
        else:
            return VerificationResult(
                attempt_id=attempt.attempt_id,
                status=VerificationStatus.REJECTED,
                authorized=False,
                reason=f"Constraint violation: {reason}",
                checks=checks,
                timestamp=now_iso,
            )

    # Approved
    import uuid
    settlement_id = f"stl_{uuid.uuid4().hex[:10]}"
    dispute_token = f"dsp_{uuid.uuid4().hex[:12]}"
    state_manager.record_usage(
        mandate_id=mandate.mandate_id,
        amount=attempt.amount,
        nonce=attempt.nonce,
    )

    try:
        from audit.log import audit_ledger
        audit_ledger.append_entry(
            event_type="SETTLEMENT_COMPLETED",
            actor_type="BANK",
            actor_id="galicia_bank",
            mandate_id=mandate.mandate_id,
            attempt_id=attempt.attempt_id,
            details={"amount": attempt.amount, "settlement_id": settlement_id, "dispute_token": dispute_token},
        )
    except Exception:
        pass

    return VerificationResult(
        attempt_id=attempt.attempt_id,
        status=VerificationStatus.APPROVED,
        authorized=True,
        reason="All cryptographic, identity, state, and policy constraints satisfied.",
        checks=checks,
        settlement_id=settlement_id,
        dispute_token=dispute_token,
        timestamp=now_iso,
    )



class VerificationGateway:
    def verify_and_authorize(
        self,
        attempt: PurchaseAttempt,
        mandate: Optional[Mandate] = None,
        merchant_pubkey: Optional[str] = None,
    ) -> VerificationResult:
        return verify_purchase(attempt)


gateway = VerificationGateway()

