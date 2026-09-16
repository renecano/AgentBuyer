import os
import json
import hmac
import hashlib
import base64
import time
import urllib.request
import uuid
from copy import deepcopy
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

from shared.schemas import (
    Mandate,
    MandateStatus,
    PurchaseAttempt,
    VerificationResult,
    VerificationStatus,
    HITLApprovalRequest,
    EventType,
    ActorType,
)
from mandate.sign import verify_signature
from core.mandate_store import mandate_store, get_mandate, apply_approved_purchase, record_verification_event
from core.semantic_firewall import auditoria_cognitiva_firewall
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

# Quién firma los eventos de decisión en el ledger con cadena hash.
_GATEWAY_ACTOR_TYPE = "GATEWAY"
_GATEWAY_ACTOR_ID = "verification_gateway"

_DECISION_EVENTS = {
    VerificationStatus.APPROVED: EventType.VERIFICATION_SUCCESS,
    VerificationStatus.REJECTED: EventType.VERIFICATION_FAILED,
    VerificationStatus.ESCALATED_HITL: EventType.HITL_ESCALATED,
}

_FIREWALL_VERDICTS = {"APPROVE", "REJECT", "ESCALATE"}


def _check(rule: str, passed: bool, detail: str) -> Dict[str, Any]:
    """Un check con la misma forma que /verify: {rule, pass, detail}."""
    return {"rule": rule, "pass": bool(passed), "detail": detail}


def _decide(
    attempt: PurchaseAttempt,
    mandate_id: str,
    status: VerificationStatus,
    reason: str,
    checks: List[Dict[str, Any]],
    now_iso: str,
    event_type: Optional[EventType] = None,
    **fields: Any,
) -> VerificationResult:
    """Construye la decisión y la registra en el ledger ANTES de devolverla.

    Toda decisión (aprobación, rechazo o escalación) deja evidencia. Si el ledger
    falla, la excepción se propaga: nunca se devuelve una decisión sin registrar.
    """
    result = VerificationResult(
        attempt_id=attempt.attempt_id,
        status=status,
        authorized=status == VerificationStatus.APPROVED,
        reason=reason,
        checks=checks,
        timestamp=now_iso,
        **fields,
    )
    audit_ledger.append_entry(
        event_type=event_type or _DECISION_EVENTS[status],
        actor_type=_GATEWAY_ACTOR_TYPE,
        actor_id=_GATEWAY_ACTOR_ID,
        mandate_id=mandate_id,
        attempt_id=attempt.attempt_id,
        details={
            "status": result.status.value,
            "authorized": result.authorized,
            "reason": result.reason,
            "checks": deepcopy(result.checks),
            "amount": attempt.amount,
            "currency": attempt.currency,
            "agent_id": attempt.agent_id,
            "merchant_id": attempt.merchant_id,
            "escalation_id": result.escalation_id,
            "settlement_id": result.settlement_id,
        },
    )
    return result


def _record_settlement(mandate_id: str, attempt: PurchaseAttempt, amount: float, settlement_id: str, dispute_token: str) -> None:
    audit_ledger.append_entry(
        event_type=EventType.SETTLEMENT_COMPLETED,
        actor_type=ActorType.BANK,
        actor_id="galicia_bank",
        mandate_id=mandate_id,
        attempt_id=attempt.attempt_id,
        details={"amount": amount, "settlement_id": settlement_id, "dispute_token": dispute_token},
    )


def _expiry_check(expires_at: Optional[str]) -> Dict[str, Any]:
    """Relee expires_at aunque el store ya marque EXPIRED: el store ignora fechas
    ilegibles, aquí una fecha ilegible falla cerrado."""
    if not expires_at:
        return _check("not_expired", True, "Mandate has no expiration date.")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return _check("not_expired", False, f"Unreadable expires_at {expires_at!r}; rejected (fail-closed).")
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) >= expiry:
        return _check("not_expired", False, f"Mandate expired at {expires_at}.")
    return _check("not_expired", True, f"Valid until {expires_at}.")


def _run_semantic_firewall(mandate: Mandate, attempt: PurchaseAttempt) -> Tuple[str, str]:
    """Devuelve (veredicto, detalle). Una excepción o un veredicto fuera de
    APPROVE/REJECT/ESCALATE se reporta como "ERROR" (el llamador lo rechaza)."""
    scope = mandate.scope
    constraints = {
        "max_amount_per_purchase": scope.max_amount_per_tx,
        "allowed_categories": scope.allowed_categories,
        "conditions_expression": scope.conditions_expression,
    }
    try:
        audit = auditoria_cognitiva_firewall(
            mandato_constraints=constraints,
            # Solo campos cubiertos por la firma del agente: item_title no está
            # firmado y podría alterarse en tránsito para manipular al auditor.
            item_titulo=attempt.item_description,
            item_descripcion=attempt.item_description,
            precio_declarado=float(attempt.amount),
            categoria=attempt.category,
            metadata=attempt.metadata,
        )
    except Exception as exc:
        return "ERROR", f"Semantic firewall failed ({type(exc).__name__}: {exc}); rejected (fail-closed)."

    verdict = audit.get("veredicto") if isinstance(audit, dict) else None
    if verdict not in _FIREWALL_VERDICTS:
        return "ERROR", f"Semantic firewall returned an unusable verdict ({verdict!r}); rejected (fail-closed)."
    detail = str(audit.get("resumen_para_humano") or f"Semantic firewall verdict: {verdict}.")
    return verdict, detail


def _escalate(
    attempt: PurchaseAttempt,
    mandate: Mandate,
    reason: str,
    checks: List[Dict[str, Any]],
    now_iso: str,
) -> VerificationResult:
    escalation_id = f"esc_{uuid.uuid4().hex[:10]}"
    _escalation_inbox[escalation_id] = HITLApprovalRequest(
        escalation_id=escalation_id,
        attempt_id=attempt.attempt_id,
        mandate_id=mandate.mandate_id,
        attempt=attempt,
        reason=reason,
        requested_amount=attempt.amount,
        mandate_limit=mandate.scope.max_amount_per_tx,
        created_at=now_iso,
    )
    return _decide(
        attempt, mandate.mandate_id, VerificationStatus.ESCALATED_HITL,
        f"{reason}. Escalated to cardholder for approval.", checks, now_iso,
        escalation_id=escalation_id,
    )


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

    attempt = esc_req.attempt
    checks = [_check("hitl_approval", approved, note or ("Approved by cardholder." if approved else "Rejected by cardholder."))]

    if approved:
        settlement_id = f"stl_{uuid.uuid4().hex[:10]}"
        dispute_token = f"dsp_{uuid.uuid4().hex[:12]}"

        state_manager.record_usage(
            mandate_id=mandate.mandate_id,
            amount=attempt.amount,
            nonce=attempt.nonce,
        )
        result = _decide(
            attempt, mandate.mandate_id, VerificationStatus.APPROVED,
            f"Approved by cardholder (HITL note: {note})", checks, now_iso,
            event_type=EventType.HITL_APPROVED,
            settlement_id=settlement_id, dispute_token=dispute_token, escalation_id=escalation_id,
        )
        _record_settlement(mandate.mandate_id, attempt, attempt.amount, settlement_id, dispute_token)
        return result

    return _decide(
        attempt, mandate.mandate_id, VerificationStatus.REJECTED,
        f"Rejected by cardholder during HITL escalation: {note}", checks, now_iso,
        event_type=EventType.HITL_REJECTED,
        escalation_id=escalation_id,
    )


def verify_purchase(attempt: PurchaseAttempt) -> VerificationResult:
    now_iso = datetime.now(timezone.utc).isoformat()
    checks: List[Dict[str, Any]] = []

    def reject(mandate_id: str, reason: str) -> VerificationResult:
        return _decide(attempt, mandate_id, VerificationStatus.REJECTED, reason, checks, now_iso)

    # 1. Look up mandate in live store
    mandate = mandate_store.get_mandate(attempt.mandate_id)
    if not mandate:
        checks.append(_check("mandate_exists", False, "Mandate not found in live registry."))
        return reject(attempt.mandate_id, "Mandate not found in live registry.")
    checks.append(_check("mandate_exists", True, "Mandate found in live registry."))

    # 2. Live status (kill switch): solo ACTIVE puede comprar. REVOKED, PAUSED,
    # EXPIRED o cualquier estado que se agregue en el futuro se rechaza (fail-closed).
    if mandate.status != MandateStatus.ACTIVE:
        checks.append(_check("status_active", False, f"Mandate status is {mandate.status.value}."))
        if mandate.status == MandateStatus.REVOKED:
            reason = f"Mandate is REVOKED. Revocation timestamp: {mandate.revoked_at}. Reason: {mandate.revocation_reason}"
        else:
            reason = f"Mandate is {mandate.status.value}. Only ACTIVE mandates can authorize purchases."
        return reject(mandate.mandate_id, reason)
    checks.append(_check("status_active", True, "Mandate status is ACTIVE."))

    # 3. Expiration (expires_at)
    expiry = _expiry_check(mandate.expires_at)
    checks.append(expiry)
    if not expiry["pass"]:
        return reject(mandate.mandate_id, f"Mandate is EXPIRED: {expiry['detail']}")

    # 4. Verify Human Signature (Ed25519)
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

    checks.append(_check(
        "human_signature_valid", human_sig_valid,
        "Ed25519 cardholder signature verified." if human_sig_valid else "Ed25519 cardholder signature is invalid or forged.",
    ))
    if not human_sig_valid:
        return reject(mandate.mandate_id, "403 Forbidden: Human digital signature on mandate is INVALID or forged. Cryptographic verification failed.")

    # 5. Verify Agent Signature
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

    checks.append(_check(
        "agent_signature_valid", agent_sig_valid,
        "Ed25519 agent signature verified." if agent_sig_valid else "Agent signature is missing, invalid, tampered, or from an unauthorized key.",
    ))
    if not agent_sig_valid:
        return reject(mandate.mandate_id, "403 Forbidden: Agent signature is INVALID, forged, tampered, or signed by an unauthorized (impersonating) entity.")

    # 6. Nonce Replay Check
    nonce_valid = state_manager.validate_nonce(attempt.nonce)
    checks.append(_check(
        "nonce_fresh", nonce_valid,
        "Nonce not seen before." if nonce_valid else "Nonce was already used (replay).",
    ))
    if not nonce_valid:
        return reject(mandate.mandate_id, f"REPLAY ATTACK DETECTED: Nonce '{attempt.nonce}' was already used in a previous purchase.")

    # 7. Evaluate Constraints
    rolling_state = state_manager.get_or_create_state(mandate.mandate_id)
    authorized, reason, constraint_checks, can_escalate = evaluate_mandate_constraints(
        mandate=mandate,
        attempt=attempt,
        state=rolling_state,
    )
    checks.extend(constraint_checks)

    if not authorized:
        if can_escalate and mandate.scope.allow_hitl_escalation:
            return _escalate(attempt, mandate, f"Out of bounds: {reason}", checks, now_iso)
        return reject(mandate.mandate_id, f"Constraint violation: {reason}")

    # 8. Semantic Firewall. Solo APPROVE deja pasar: ESCALATE va a revisión humana
    # (o se rechaza si el mandato no la permite) y REJECT/falla se rechaza (fail-closed).
    firewall_verdict, firewall_detail = _run_semantic_firewall(mandate, attempt)
    checks.append(_check("semantic_firewall", firewall_verdict == "APPROVE", firewall_detail))
    if firewall_verdict == "ESCALATE":
        if mandate.scope.allow_hitl_escalation:
            return _escalate(attempt, mandate, f"Semantic firewall flagged the purchase: {firewall_detail}", checks, now_iso)
        return reject(mandate.mandate_id, f"Semantic firewall flagged the purchase and HITL escalation is disabled: {firewall_detail}")
    if firewall_verdict != "APPROVE":
        return reject(mandate.mandate_id, f"Semantic firewall veto: {firewall_detail}")

    # Approved: se consume el presupuesto y luego se registra la decisión y la liquidación.
    settlement_id = f"stl_{uuid.uuid4().hex[:10]}"
    dispute_token = f"dsp_{uuid.uuid4().hex[:12]}"
    state_manager.record_usage(
        mandate_id=mandate.mandate_id,
        amount=attempt.amount,
        nonce=attempt.nonce,
    )
    result = _decide(
        attempt, mandate.mandate_id, VerificationStatus.APPROVED,
        "All cryptographic, identity, state, policy, and semantic firewall checks satisfied.",
        checks, now_iso,
        settlement_id=settlement_id, dispute_token=dispute_token,
    )
    _record_settlement(mandate.mandate_id, attempt, attempt.amount, settlement_id, dispute_token)
    return result


class VerificationGateway:
    def verify_and_authorize(
        self,
        attempt: PurchaseAttempt,
        mandate: Optional[Mandate] = None,
        merchant_pubkey: Optional[str] = None,
    ) -> VerificationResult:
        return verify_purchase(attempt)


gateway = VerificationGateway()

