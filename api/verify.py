"""Endpoint que orquesta la verificación segura de un intento de compra.
Integra Criptografía Asimétrica (Ed25519/JWT), DLP (Scoped Virtual Tokens) y Auditoría Cognitiva.
"""

from datetime import datetime, timezone
from numbers import Real
from typing import Any

from fastapi import APIRouter, HTTPException, status

from audit.log import append_entry
from core.mandate_store import (
    apply_approved_purchase,
    get_mandate,
)
from engine.evaluator import evaluate
from mandate.sign import verify_signature
from core.semantic_firewall import auditoria_cognitiva_firewall

router = APIRouter()


def _timestamp() -> str:
    """Genera timestamps explícitamente en UTC para respuestas y auditoría."""
    return datetime.now(timezone.utc).isoformat()


def _finish(
    mandate_id: str,
    attempt_id: str,
    verdict: str,
    checks: list[dict],
    human_readable: str,
    amount: int | float | None = None,
) -> dict:
    """Registra toda decisión antes de devolverla al comercio."""
    decided_at = _timestamp()
    append_entry(
        {
            "type": "verification",
            "mandate_id": mandate_id,
            "attempt_id": attempt_id,
            "verdict": verdict,
            "summary": human_readable,
            # Datos para la revisión humana de escalaciones (api/escalations.py):
            "amount": amount,
            "failed_rules": [c["rule"] for c in checks if not c.get("pass")],
        }
    )
    return {
        "attempt_id": attempt_id,
        "mandate_id": mandate_id,
        "verdict": verdict,
        "checks": checks,
        "human_readable": human_readable,
        "decided_at": decided_at,
    }


@router.post("/verify")
def verify_purchase(attempt_purchase: dict[str, Any]):
    """
    Verifica seguridad criptográfica, DLP y delega restricciones al Engine Simbólico + Semantic Firewall.
    """
    if "purchase" in attempt_purchase and not isinstance(attempt_purchase["purchase"], dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="purchase debe ser un objeto.",
        )

    attempt_id = str(attempt_purchase.get("attempt_id", ""))
    mandate_id = str(attempt_purchase.get("mandate_id", ""))

    # 1. Consulta el registro en vivo; ZERO CACHING.
    record = get_mandate(mandate_id)
    if record is None:
        return _finish(
            mandate_id,
            attempt_id,
            "REJECT",
            [{"rule": "mandate_exists", "pass": False, "detail": "Mandato no encontrado."}],
            "Compra rechazada: el mandato no existe.",
        )

    mandate = record["mandate"]
    live_state = record["live_state"]
    security_checks: list[dict] = []

    # 2a. Firma del mandato (Ed25519), FAIL-CLOSED. El check pasa SOLO si hay una
    # firma que verifica de verdad contra la llave pública guardada en el mandato.
    # Sin firma, sin llave con la que verificarla, firma malformada o que no
    # coincide: REJECT. No hay ninguna rama que apruebe sin verificar (antes una
    # firma sin pubkey, o de menos de 64 caracteres, pasaba como "estructurada").
    signature = mandate.get("signature") or mandate.get("human_signature")
    pubkey = mandate.get("human_pubkey") or mandate.get("pubkey")

    if not isinstance(signature, str) or not signature.strip():
        signature_check = {"rule": "signature", "pass": False, "detail": "Firma ausente o vacía."}
    elif verify_signature(pubkey, mandate.get("scope", mandate.get("constraints", {})), signature):
        signature_check = {"rule": "signature", "pass": True, "detail": "Firma digital Ed25519 válida."}
    else:
        # Incluye la firma sin llave pública: lo que no se puede verificar no es válido.
        signature_check = {"rule": "signature", "pass": False, "detail": "Firma digital inválida."}

    security_checks.append(signature_check)
    if not signature_check["pass"]:
        return _finish(
            mandate_id,
            attempt_id,
            "REJECT",
            security_checks,
            "Compra rechazada: la firma del mandato no es válida.",
        )

    # 2b. El agente que presenta el intento debe ser el autorizado en el mandato
    expected_agent_id = mandate.get("agent", {}).get("id") or mandate.get("agent_id")
    presented_agent_id = attempt_purchase.get("presented_by_agent") or attempt_purchase.get("agent_id")
    if expected_agent_id and presented_agent_id and presented_agent_id != expected_agent_id:
        security_checks.append(
            {
                "rule": "agent_identity",
                "pass": False,
                "detail": "El agente que presenta el intento no está autorizado.",
            }
        )
        return _finish(
            mandate_id,
            attempt_id,
            "REJECT",
            security_checks,
            "Compra rechazada: el agente no coincide con el mandato.",
        )
    security_checks.append(
        {"rule": "agent_identity", "pass": True, "detail": "Agente autorizado."}
    )

    # 2c. Kill Switch en Vivo (Lectura fresca en memoria)
    if live_state["status"] == "revoked":
        security_checks.append(
            {"rule": "status", "pass": False, "detail": "mandato revocado"}
        )
        return _finish(
            mandate_id,
            attempt_id,
            "REJECT",
            security_checks,
            "Compra rechazada: el mandato está revocado.",
        )
    if live_state["status"] == "expired":
        security_checks.append(
            {"rule": "status", "pass": False, "detail": "mandato expirado"}
        )
        return _finish(
            mandate_id,
            attempt_id,
            "REJECT",
            security_checks,
            "Compra rechazada: el mandato está expirado.",
        )
    security_checks.append({"rule": "status", "pass": True, "detail": "Mandato activo."})

    # 3. Evaluación en el Engine Simbólico
    engine_attempt = attempt_purchase.get("purchase", attempt_purchase)
    if not isinstance(engine_attempt, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="purchase debe ser un objeto.",
        )
    engine_result = evaluate(mandate, live_state, engine_attempt)
    verdict = engine_result["verdict"]
    checks = security_checks + engine_result["checks"]

    # 4. Auditoría Cognitiva (Detección de Costos Ocultos y Trampas de Letra Chica)
    purchase = attempt_purchase.get("purchase", attempt_purchase)
    item_desc = str(purchase.get("description", purchase.get("item_title", "")))
    amount = purchase.get("amount", 0.0)
    
    if verdict == "APPROVE" and item_desc:
        constraints = mandate.get("constraints") or mandate.get("scope", {})
        if any(w in item_desc.lower() for w in ["por fuera", "upgrade automático", "48 horas", "gift card", "crypto"]):
            audit_res = auditoria_cognitiva_firewall(
                mandato_constraints=constraints,
                item_titulo=item_desc,
                item_descripcion=item_desc,
                precio_declarado=float(amount) if isinstance(amount, Real) else 0.0,
                categoria=str(purchase.get("category", "travel")),
                metadata=purchase.get("metadata", {}),
            )
            if audit_res.get("veredicto") == "REJECT":
                checks.append({
                    "rule": "semantic_firewall",
                    "pass": False,
                    "detail": audit_res.get("resumen_para_humano", "Hidden fine-print risk detected.")
                })
                return _finish(
                    mandate_id,
                    attempt_id,
                    "REJECT",
                    checks,
                    f"Purchase vetoed by Semantic Firewall: {audit_res.get('resumen_para_humano', 'Hidden fine-print risk detected.')}"
                )

    amount = engine_attempt.get("amount")
    if not isinstance(amount, Real) or isinstance(amount, bool):
        amount = None

    # 5. La actualización se aplica sobre el estado vivo, únicamente al aprobar.
    if verdict == "APPROVE":
        if amount is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="purchase.amount debe ser un número.",
            )
        apply_approved_purchase(mandate_id, amount)
        human_readable = "Compra aprobada por el mandato."
    else:
        human_readable = "La compra requiere aprobación humana."

    # 4 y 6. El veredicto final es el del engine y combina todos los checks.
    return _finish(mandate_id, attempt_id, verdict, checks, human_readable, amount=amount)
