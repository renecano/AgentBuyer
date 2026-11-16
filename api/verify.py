"""Verificación de un intento de compra (comercio/agente).

4.2 (P-03): POST /verify es la verificación del COMERCIO o del AGENTE, no de una
persona: exige credencial `service`. React ya no la llama; el agente de la
plataforma verifica por dentro (verify_attempt) y la demo usa /agent/run con un
escenario explícito. Cada intento trae un nonce único (anti-replay); si declara la
firma del agente, se verifica con la llave del agente que lo presenta; y la moneda
del intento debe ser la del mandato.
"""

import functools
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from api.security import Principal, require_service
from core.agent_keys import AGENT_SIGNATURE_FIELD, verify_attempt_signature
from core.money import is_cents

from audit.log import append_entry
from core.mandate_store import (
    apply_approved_purchase,
    get_mandate,
    get_mandate_owner,
    get_mandate_signer,
)
from core.signed_mandates import (
    KIND_HUMAN,
    KIND_SYSTEM_SEAL,
    verify_payment_token_binding,
    verify_signed_mandate,
    verify_signing_key_active,
)
from engine.evaluator import evaluate
from mandate.sign import verify_signature
from core.semantic_firewall import auditoria_cognitiva_firewall

router = APIRouter()


def _timestamp() -> str:
    """Genera timestamps explícitamente en UTC para respuestas y auditoría."""
    return datetime.now(timezone.utc).isoformat()


# ── Anti-replay de intentos (4.2) ───────────────────────────────────────────

NONCE_TTL_SECONDS = 24 * 60 * 60
NONCE_MIN_LENGTH, NONCE_MAX_LENGTH = 16, 128


class AttemptNonceGuard:
    """Nonces de intento ya vistos. Un nonce sirve UNA vez (aunque el intento se
    rechace): un intento capturado no se puede volver a presentar. En memoria; los
    vencidos se purgan (la persistencia durable llega en el 6.3)."""

    def __init__(self, ttl_seconds: int = NONCE_TTL_SECONDS, clock: Callable[[], float] = time.time):
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def claim(self, nonce: str) -> bool:
        with self._lock:
            now = self._clock()
            for stale in [key for key, seen_at in self._seen.items() if now - seen_at >= self.ttl_seconds]:
                del self._seen[stale]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


attempt_nonces = AttemptNonceGuard()


def _finish(
    mandate_id: str,
    attempt_id: str,
    verdict: str,
    checks: list[dict],
    human_readable: str,
    amount_cents: int | None = None,
    scenario: Optional[str] = None,
) -> dict:
    """Registra toda decisión antes de devolverla al comercio.

    Un escenario de demostración (4.2) se registra como "scenario_verification": no
    es una compra, así que ni las escalaciones ni las disputas lo toman por una."""
    decided_at = _timestamp()
    append_entry(
        {
            "type": "scenario_verification" if scenario else "verification",
            "mandate_id": mandate_id,
            "attempt_id": attempt_id,
            "verdict": verdict,
            "summary": human_readable,
            # Datos para la revisión humana de escalaciones (api/escalations.py):
            "amount_cents": amount_cents,
            "failed_rules": [c["rule"] for c in checks if not c.get("pass")],
            **({"scenario": scenario} if scenario else {}),
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
def verify_purchase(attempt_purchase: dict[str, Any], principal: Principal = Depends(require_service)):
    """Verificación del comercio/agente (P-03): solo con credencial `service`."""
    return verify_attempt(attempt_purchase)


def verify_attempt(attempt_purchase: dict[str, Any], *, scenario: Optional[str] = None) -> dict:
    """
    Verifica seguridad criptográfica, DLP y delega restricciones al Engine Simbólico + Semantic Firewall.

    `scenario` (demo de /agent/run, 4.2): se verifica igual que una compra real, pero
    NUNCA compra: no consume usos ni gasto, y queda registrado como escenario.
    """
    finish = functools.partial(_finish, scenario=scenario)
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
        return finish(
            mandate_id,
            attempt_id,
            "REJECT",
            [{"rule": "mandate_exists", "pass": False, "detail": "Mandato no encontrado."}],
            "Compra rechazada: el mandato no existe.",
        )

    mandate = record["mandate"]
    live_state = record["live_state"]
    security_checks: list[dict] = []
    signer = get_mandate_signer(mandate_id)
    kind = signer["kind"] if signer else None

    # 2a. Firma del mandato (Ed25519), FAIL-CLOSED. El check pasa SOLO si hay una
    # firma que verifica de verdad contra la llave pública guardada en el mandato.
    # Sin firma, sin llave con la que verificarla, firma malformada o que no
    # coincide: REJECT. No hay ninguna rama que apruebe sin verificar (antes una
    # firma sin pubkey, o de menos de 64 caracteres, pasaba como "estructurada").
    signature = mandate.get("signature") or mandate.get("human_signature")
    pubkey = mandate.get("human_pubkey") or mandate.get("pubkey")

    if kind == KIND_HUMAN:
        # Firma del TITULAR (3.3): se reconstruye el mensaje desde lo guardado y se
        # verifica con su llave registrada, que debe seguir siendo suya.
        human_ok, human_detail = verify_signed_mandate(mandate, get_mandate_owner(mandate_id), signer)
        signature_check = {"rule": "signature", "pass": human_ok, "detail": human_detail}
    elif kind != KIND_SYSTEM_SEAL:
        # 3.5: sin firmante registrado (ni titular ni sello del seed) no hay mandato válido.
        signature_check = {"rule": "signature", "pass": False, "detail": "El mandato no tiene una firma registrada."}
    elif not isinstance(signature, str) or not signature.strip():
        signature_check = {"rule": "signature", "pass": False, "detail": "Firma ausente o vacía."}
    elif verify_signature(pubkey, mandate.get("scope", mandate.get("constraints", {})), signature):
        # El detail dice QUÉ verificó: un sello del servidor no es una firma del titular.
        signature_check = {"rule": "signature", "pass": True,
                           "detail": "Sello de sistema Ed25519 válido (llave del servidor; no es una firma del titular)."}
    else:
        # Incluye la firma sin llave pública: lo que no se puede verificar no es válido.
        signature_check = {"rule": "signature", "pass": False, "detail": "Firma digital inválida."}

    security_checks.append(signature_check)
    if not signature_check["pass"]:
        return finish(
            mandate_id,
            attempt_id,
            "REJECT",
            security_checks,
            "Compra rechazada: la firma del mandato no es válida.",
        )

    # 2a'. P-01 (a): revocar la llave que firmó deja sin efecto el mandato.
    if kind == KIND_HUMAN:
        key_ok, key_detail = verify_signing_key_active(signer)
        security_checks.append({"rule": "signing_key_active", "pass": key_ok, "detail": key_detail})
        if not key_ok:
            return finish(
                mandate_id,
                attempt_id,
                "REJECT",
                security_checks,
                "Compra rechazada: la llave que firmó el mandato fue revocada.",
            )

    # 2a''. El payment_token lo emitió el servidor atado a ESTOS bytes firmados (o
    # sellados, para el seed); uno de otro mandato, o aportado por un cliente, no sirve.
    binding_ok, binding_detail = verify_payment_token_binding(mandate, signer)
    security_checks.append({"rule": "payment_token_binding", "pass": binding_ok, "detail": binding_detail})
    if not binding_ok:
        return finish(
            mandate_id,
            attempt_id,
            "REJECT",
            security_checks,
            "Compra rechazada: el token de pago no corresponde a este mandato.",
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
        return finish(
            mandate_id,
            attempt_id,
            "REJECT",
            security_checks,
            "Compra rechazada: el agente no coincide con el mandato.",
        )
    security_checks.append(
        {"rule": "agent_identity", "pass": True, "detail": "Agente autorizado."}
    )

    # 2b'. Si el intento declara la firma del agente, debe ser del agente que lo
    # presenta y sobre ESTE intento (4.2). Declarada y falsa → REJECT.
    if AGENT_SIGNATURE_FIELD in attempt_purchase:
        signed_ok = verify_attempt_signature(presented_agent_id or expected_agent_id, attempt_purchase)
        security_checks.append({
            "rule": "agent_signature",
            "pass": signed_ok,
            "detail": "Firma del agente válida sobre este intento." if signed_ok
            else "La firma del agente no corresponde a este intento o a este agente.",
        })
        if not signed_ok:
            return finish(
                mandate_id,
                attempt_id,
                "REJECT",
                security_checks,
                "Compra rechazada: la firma del agente no es válida.",
            )

    # 2b''. Anti-replay (4.2): cada intento trae un nonce único; un intento ya
    # presentado (aprobado o no) no se acepta otra vez.
    nonce = attempt_purchase.get("nonce")
    nonce_ok = isinstance(nonce, str) and NONCE_MIN_LENGTH <= len(nonce) <= NONCE_MAX_LENGTH and attempt_nonces.claim(nonce)
    security_checks.append({
        "rule": "nonce_fresh",
        "pass": nonce_ok,
        "detail": "Intento nuevo (nonce no visto)." if nonce_ok
        else "Intento sin nonce válido, o ya presentado antes (replay).",
    })
    if not nonce_ok:
        return finish(
            mandate_id,
            attempt_id,
            "REJECT",
            security_checks,
            "Compra rechazada: el intento ya fue presentado o no trae un nonce válido.",
        )

    # 2c. Kill Switch en Vivo (Lectura fresca en memoria). Solo un mandato ACTIVO
    # compra (5.1: antes un mandato PAUSADO pasaba este check y aprobaba).
    status_detail = {"revoked": "mandato revocado", "expired": "mandato expirado", "paused": "mandato pausado"}
    if live_state["status"] != "active":
        detail = status_detail.get(live_state["status"], f"mandato {live_state['status']}")
        security_checks.append({"rule": "status", "pass": False, "detail": detail})
        return finish(
            mandate_id,
            attempt_id,
            "REJECT",
            security_checks,
            f"Compra rechazada: el {detail.replace('mandato ', 'mandato está ')}.",
        )
    security_checks.append({"rule": "status", "pass": True, "detail": "Mandato activo."})

    # 2d. Moneda (4.2: en TODO mandato; en los del titular va firmada, D-15): otra
    # moneda, o ninguna, es REJECT. Un mandato sin moneda no autoriza nada.
    purchase_view = attempt_purchase.get("purchase", attempt_purchase)
    constraints_view = mandate.get("constraints") or mandate.get("scope") or {}
    signed_currency = constraints_view.get("currency") if isinstance(constraints_view, dict) else None
    presented_currency = purchase_view.get("currency") if isinstance(purchase_view, dict) else None
    currency_ok = (
        isinstance(signed_currency, str) and isinstance(presented_currency, str)
        and presented_currency.strip().upper() == signed_currency.strip().upper()
    )
    security_checks.append({
        "rule": "currency",
        "pass": currency_ok,
        "detail": f"{presented_currency} = {signed_currency}" if currency_ok
        else f"La compra es en {presented_currency}; el mandato autoriza solo {signed_currency}.",
    })
    if not currency_ok:
        return finish(
            mandate_id,
            attempt_id,
            "REJECT",
            security_checks,
            "Compra rechazada: la moneda no es la autorizada en el mandato.",
        )

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

    # 3b. Consentimiento firmado a comprar sin la persona presente (D-16). Sin él,
    # NINGUNA compra se aprueba sola: toda compra escala a aprobación humana.
    if kind == KIND_HUMAN:
        consent = (mandate.get("constraints") or {}).get("off_session_consent") is True
        checks.append({
            "rule": "off_session_consent",
            "pass": consent,
            "detail": "El titular autorizó compras sin estar presente." if consent
            else "El titular no autorizó compras sin estar presente: cada compra requiere su aprobación.",
        })
        if not consent and verdict == "APPROVE":
            verdict = "ESCALATE"

    # 4. Auditoría Cognitiva (Detección de Costos Ocultos y Trampas de Letra Chica)
    purchase = attempt_purchase.get("purchase", attempt_purchase)
    item_desc = str(purchase.get("description", purchase.get("item_title", "")))
    amount_cents = purchase.get("amount_cents")

    if verdict == "APPROVE" and item_desc:
        constraints = mandate.get("constraints") or mandate.get("scope", {})
        if any(w in item_desc.lower() for w in ["por fuera", "upgrade automático", "48 horas", "gift card", "crypto"]):
            # Borde con el firewall/LLM: el prompt habla en UNIDADES (texto para una
            # persona o un modelo); la decisión del engine ya se tomó en centavos.
            units_view = {**constraints, "max_amount_per_purchase": constraints.get("max_amount_per_purchase_cents", 0) / 100}
            audit_res = auditoria_cognitiva_firewall(
                mandato_constraints=units_view,
                item_titulo=item_desc,
                item_descripcion=item_desc,
                precio_declarado=amount_cents / 100 if is_cents(amount_cents) else 0.0,
                categoria=str(purchase.get("category", "travel")),
                metadata=purchase.get("metadata", {}),
            )
            if audit_res.get("veredicto") == "REJECT":
                checks.append({
                    "rule": "semantic_firewall",
                    "pass": False,
                    "detail": audit_res.get("resumen_para_humano", "Hidden fine-print risk detected.")
                })
                return finish(
                    mandate_id,
                    attempt_id,
                    "REJECT",
                    checks,
                    f"Purchase vetoed by Semantic Firewall: {audit_res.get('resumen_para_humano', 'Hidden fine-print risk detected.')}"
                )

    amount_cents = engine_attempt.get("amount_cents")
    if not is_cents(amount_cents):
        amount_cents = None

    # 5. La actualización se aplica sobre el estado vivo, únicamente al aprobar. El
    # engine ya rechazó (REJECT) cualquier monto que no sea centavos enteros > 0.
    if verdict == "APPROVE":
        if scenario:
            # Un escenario de demostración nunca compra (4.2).
            human_readable = "Escenario de demostración: el mandato lo aprobaría, pero no se realizó ninguna compra."
        else:
            apply_approved_purchase(mandate_id, amount_cents)
            human_readable = "Compra aprobada por el mandato."
    else:
        human_readable = "La compra requiere aprobación humana."

    # 4 y 6. El veredicto final es el del engine y combina todos los checks.
    return finish(mandate_id, attempt_id, verdict, checks, human_readable, amount_cents=amount_cents)
