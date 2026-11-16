"""Verificación de un intento de compra (comercio/agente).

4.2 (P-03): POST /verify es la verificación del COMERCIO o del AGENTE, no de una
persona: exige credencial `service`. React ya no la llama; el agente de la
plataforma verifica por dentro (verify_attempt) y la demo usa /agent/run con un
escenario explícito. Cada intento trae un nonce único (anti-replay); si declara la
firma del agente, se verifica con la llave del agente que lo presenta; y la moneda
del intento debe ser la del mandato.
"""

import functools
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, insert, select

from api.security import Principal, require_service
from core.agent_keys import AGENT_SIGNATURE_FIELD, verify_attempt_signature
from core.db import write_tx
from core.db_schema import attempt_nonces as ATTEMPT_NONCES
from core.merchant_identity import merchant_id_from_url
from core.money import is_cents

from audit.log import append_entry
from core.mandate_store import (
    get_mandate,
    period_usage,
    reserve_purchase,
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


# ── Anti-replay de intentos (4.2; durable desde el 6.3) ─────────────────────
# H1 (docs/design/persistence.md): antes el nonce se olvidaba a las 24 h y en cada
# reinicio, y el intento no llevaba fecha: un intento capturado volvía a servir.
# Ahora el intento trae `created_at` (lo firma el agente junto con todo el intento),
# /verify rechaza intentos viejos o del futuro, y el nonce se guarda en la base hasta
# que el intento ya se rechazaría por viejo. Olvidarlo después es seguro.
MAX_ATTEMPT_AGE = timedelta(minutes=10)
ATTEMPT_CLOCK_SKEW = timedelta(minutes=2)
NONCE_MIN_LENGTH, NONCE_MAX_LENGTH = 16, 128
ATTEMPT_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _utcnow() -> datetime:
    """Reloj de /verify (frescura de intentos). Los tests lo sustituyen."""
    return datetime.now(timezone.utc)


def attempt_timestamp(moment: datetime) -> str:
    """created_at de un intento: UTC con resolución de segundos y sufijo Z."""
    return moment.astimezone(timezone.utc).strftime(ATTEMPT_TIMESTAMP_FORMAT)


_ATTEMPT_TIMESTAMP_SHAPE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def _parse_attempt_time(value: Any) -> Optional[datetime]:
    """Solo el formato canónico exacto (strptime solo no basta: acepta "t"/"z" en
    minúscula). El agente firma ese texto tal cual."""
    if not isinstance(value, str) or not _ATTEMPT_TIMESTAMP_SHAPE.fullmatch(value):
        return None
    try:
        return datetime.strptime(value, ATTEMPT_TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def claim_attempt_nonce(nonce: str, mandate_id: Optional[str], created_at: datetime, now: datetime) -> bool:
    """Reserva el nonce (True) o detecta un replay (False). Un nonce sirve UNA vez,
    aunque el intento se rechace después. Purga los vencidos en la misma transacción."""
    with write_tx() as connection:
        connection.execute(delete(ATTEMPT_NONCES).where(ATTEMPT_NONCES.c.expires_at < _stamp(now)))
        if connection.execute(select(ATTEMPT_NONCES.c.nonce).where(ATTEMPT_NONCES.c.nonce == nonce)).first() is not None:
            return False
        connection.execute(insert(ATTEMPT_NONCES).values(
            nonce=nonce, mandate_id=mandate_id, seen_at=_stamp(now),
            expires_at=_stamp(created_at + MAX_ATTEMPT_AGE + ATTEMPT_CLOCK_SKEW),
        ))
        return True


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

    # 2b-bis. Identidad del comercio (5.3): si el intento trae la URL de la oferta, el
    # comercio presentado debe ser el de ESE dominio. Un comercio que solo "afirma"
    # el LLM (o una página) no pasa por uno autorizado.
    offer_view = attempt_purchase.get("purchase", attempt_purchase)
    offer_url = (offer_view.get("metadata") or {}).get("url") if isinstance(offer_view, dict) else None
    if offer_url is not None:
        derived = merchant_id_from_url(offer_url)
        presented = str(offer_view.get("merchant_id", "")).strip().lower()
        identity_ok = derived is not None and derived == presented
        security_checks.append({
            "rule": "merchant_identity",
            "pass": identity_ok,
            "detail": f"{presented} coincide con el dominio de la oferta." if identity_ok
            else f"El comercio presentado ({presented}) no es el del dominio de la oferta ({derived}).",
        })
        if not identity_ok:
            return finish(mandate_id, attempt_id, "REJECT", security_checks,
                          "Compra rechazada: el comercio no coincide con la fuente de la oferta.")

    # 2b''. Frescura (6.3, H1): el intento declara cuándo se creó. Uno viejo o "del
    # futuro" se rechaza ANTES de reservar su nonce.
    now = _utcnow()
    created_at = _parse_attempt_time(attempt_purchase.get("created_at"))
    fresh = created_at is not None and now - MAX_ATTEMPT_AGE <= created_at <= now + ATTEMPT_CLOCK_SKEW
    security_checks.append({
        "rule": "attempt_fresh",
        "pass": fresh,
        "detail": "Intento reciente." if fresh
        else "El intento no trae una fecha válida o es demasiado viejo (más de 10 minutos) o del futuro.",
    })
    if not fresh:
        return finish(mandate_id, attempt_id, "REJECT", security_checks,
                      "Compra rechazada: el intento no es reciente.")

    # 2b'''. Anti-replay (4.2; durable desde el 6.3): cada intento trae un nonce único;
    # un intento ya presentado (aprobado o no) no se acepta otra vez, ni tras reiniciar.
    nonce = attempt_purchase.get("nonce")
    nonce_ok = (isinstance(nonce, str) and NONCE_MIN_LENGTH <= len(nonce) <= NONCE_MAX_LENGTH
                and claim_attempt_nonce(nonce, mandate_id, created_at, now))
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
    # El engine ve también el uso del MES en curso (5.2: presupuesto mensual).
    month = period_usage(mandate_id)
    live_view = {**live_state, "month_uses": month["uses"], "month_spent_cents": month["spent_cents"]}
    engine_result = evaluate(mandate, live_view, engine_attempt)
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

    # 4. Firewall semántico (5.3): revisa la letra chica de TODA compra que el engine
    # aprobaría (antes solo si el texto traía ciertas palabras en español, así que la
    # misma trampa en inglés pasaba). Solo puede BAJAR el veredicto: el LLM nunca
    # aprueba lo que el código rechazó. ESCALATE escala; REJECT rechaza.
    purchase = attempt_purchase.get("purchase", attempt_purchase)
    item_desc = str(purchase.get("description", purchase.get("item_title", "")))
    if verdict == "APPROVE":
        audit_res = auditoria_cognitiva_firewall(
            mandate_constraints=mandate.get("constraints") or {},
            title=item_desc,
            description=item_desc,
            price_cents=engine_attempt.get("amount_cents"),
            category=str(purchase.get("category", "")),
            metadata=purchase.get("metadata", {}),
        )
        firewall_verdict = audit_res.get("veredicto")
        summary = audit_res.get("resumen_para_humano") or "Semantic firewall review."
        checks.append({"rule": "semantic_firewall", "pass": firewall_verdict == "APPROVE", "detail": summary})
        if firewall_verdict == "REJECT":
            return finish(mandate_id, attempt_id, "REJECT", checks, f"Purchase vetoed by Semantic Firewall: {summary}")
        if firewall_verdict != "APPROVE":  # ESCALATE, o cualquier cosa inesperada: decide la persona
            verdict = "ESCALATE"

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
            # 5.2: verificar y consumir en UNA operación atómica sobre el estado vivo.
            # Si otra compra simultánea se llevó el último uso o el presupuesto, esta
            # no se aprueba: se re-evalúa con el estado fresco (normalmente ESCALATE).
            constraints_now = mandate.get("constraints") or {}
            lost_rule = reserve_purchase(mandate_id, amount_cents, constraints_now)
            if lost_rule is None:
                human_readable = "Compra aprobada por el mandato."
            else:
                fresh = get_mandate(mandate_id) or record
                month = period_usage(mandate_id)
                fresh_view = {**fresh["live_state"], "month_uses": month["uses"], "month_spent_cents": month["spent_cents"]}
                engine_result = evaluate(fresh["mandate"], fresh_view, engine_attempt)
                verdict = engine_result["verdict"] if engine_result["verdict"] != "APPROVE" else "REJECT"
                checks = security_checks + engine_result["checks"] + [{
                    "rule": "atomic_reservation", "pass": False,
                    "detail": f"Otra compra simultánea consumió el límite ({lost_rule}) antes que esta.",
                }]
                human_readable = "La compra requiere aprobación humana." if verdict == "ESCALATE" else "Compra rechazada: el mandato ya no admite esta compra."
                return finish(mandate_id, attempt_id, verdict, checks, human_readable, amount_cents=amount_cents)
    else:
        human_readable = "La compra requiere aprobación humana."

    # 4 y 6. El veredicto final es el del engine y combina todos los checks.
    return finish(mandate_id, attempt_id, verdict, checks, human_readable, amount_cents=amount_cents)
