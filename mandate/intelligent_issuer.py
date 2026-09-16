import os
import json
import time
import uuid
import urllib.request
import urllib.error
from typing import Dict, Any, Tuple, Optional

from shared.schemas import Mandate, MandateScope, MandateStatus, PaymentToken
from mandate.sign import generate_keypair, sign_payload

# Lee OPENAI_API_KEY del entorno
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")


def interpretar_directiva_con_ia(directiva_humana: str, presupuesto_referencia: float = 500.0) -> Dict[str, Any]:
    """
    Agente Emisor de IA: Analiza la directiva en lenguaje natural del humano,
    comprende matices, restricciones implícitas y deduce los límites óptimos.
    """
    api_key = os.getenv("OPENAI_API_KEY", "")

    system_prompt = """Eres un Agente Emisor de Mandatos Financieros Inteligentes de alta precisión.
Tu trabajo es traducir la directiva en lenguaje natural de un humano a un contrato de compra estructurado, prudente y seguro para un agente autónomo de compras.

Debes deducir:
- max_amount_per_purchase: Monto máximo seguro por transacción individual.
- monthly_budget: Presupuesto total mensual considerando buffers de seguridad.
- allowed_categories: Lista de categorías permitidas (ej: ["travel.flights", "travel.hospitality"]).
- conditions_expression: Expresión lógica de restricciones (ej: "price <= 150 AND destination == 'COR'").
- intent_summary: Resumen claro de la intención para el humano.
- chain_of_thought: Tu razonamiento paso a paso explicando cómo interpretaste las prioridades y restricciones implícitas del usuario.

Devuelve ÚNICAMENTE un JSON con esta estructura exacta."""

    user_prompt = f"""Directiva del Humano:
\"\"\"{directiva_humana}\"\"\"

Presupuesto de referencia o disponible: ${presupuesto_referencia:.2f}

Genera el contrato semántico formal."""

    if not api_key:
        # Modo heurístico inteligente offline si no hay API key configurada
        lower = directiva_humana.lower()
        destino = "COR" if any(c in lower for c in ["cordoba", "córdoba", "cor"]) else "ANY"
        
        # Detección de montos
        import re
        montos = [float(m) for m in re.findall(r"\$?\s?(\d+(?:\.\d+)?)", directiva_humana)]
        max_tx = montos[0] if montos else 150.0
        
        # Si menciona cena/presupuesto restante
        if "cenar" in lower or "presupuesto" in lower or "juicio" in lower:
            max_tx = min(max_tx, 150.0)
            budget = 400.0
            cot = "El usuario pidió vuelo pero enfatizó no quedarse sin dinero para cenar. He fijado un techo de $150 por vuelo y reservado un buffer de presupuesto de $400."
        else:
            budget = max_tx * 2.5
            cot = f"Interpretación directa: Compra orientada a viajes con tope de ${max_tx:.2f} por transacción."

        return {
            "max_amount_per_purchase": max_tx,
            "monthly_budget": budget,
            "allowed_categories": ["travel.flights", "travel"],
            "allowed_merchants": ["mch_vuelaya", "*"],
            "conditions_expression": f"price <= {max_tx} AND destination == '{destino}'" if destino != "ANY" else f"price <= {max_tx}",
            "intent_summary": f"Vuelo con destino {destino} con tope de ${max_tx:.2f} y protección de presupuesto.",
            "chain_of_thought": cot
        }

    # Llamada a OpenAI API
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1
    }

    try:
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            parsed = json.loads(data["choices"][0]["message"]["content"])
            return parsed
    except Exception as e:
        # Fallback conservador seguro
        return {
            "max_amount_per_purchase": 150.0,
            "monthly_budget": presupuesto_referencia,
            "allowed_categories": ["travel.flights", "travel"],
            "allowed_merchants": ["*"],
            "conditions_expression": "price <= 150",
            "intent_summary": directiva_humana[:80],
            "chain_of_thought": f"Generado vía fallback seguro (Error API: {str(e)})."
        }


def emitir_mandato_inteligente(
    directiva_humana: str,
    human_id: str = "marta_traveler",
    agent_id: str = "agent_marta",
    presupuesto_referencia: float = 500.0,
    human_privkey: Optional[str] = None,
    human_pubkey: Optional[str] = None,
    agent_pubkey: Optional[str] = None,
) -> Tuple[Mandate, Dict[str, Any]]:
    """
    PIEZA 2 COMPLETA:
    1. Agente Emisor de IA razona y estructura la directiva en lenguaje natural.
    2. Motor Criptográfico sella el contrato con Ed25519 / HMAC.
    3. Motor DLP emite Scoped Virtual Payment Token (cero tarjetas crudas).
    """
    # 1. Razonamiento de IA
    estructura_ia = interpretar_directiva_con_ia(directiva_humana, presupuesto_referencia)

    # 2. Claves criptográficas
    if not human_privkey or not human_pubkey:
        h_priv, h_pub = generate_keypair()
    else:
        h_priv, h_pub = human_privkey, human_pubkey

    if not agent_pubkey:
        _, a_pub = generate_keypair()
    else:
        a_pub = agent_pubkey

    mandate_id = f"mnd_{uuid.uuid4().hex[:10]}"
    now = time.time()
    expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 30 * 86400))
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    scope = MandateScope(
        max_amount_per_tx=float(estructura_ia.get("max_amount_per_purchase", 150.0)),
        monthly_budget=float(estructura_ia.get("monthly_budget", presupuesto_referencia)),
        allowed_categories=estructura_ia.get("allowed_categories", ["travel.flights"]),
        allowed_merchants=estructura_ia.get("allowed_merchants", ["*"]),
        conditions_expression=estructura_ia.get("conditions_expression"),
        currency="USD",
        max_executions_per_month=5,
        allow_hitl_escalation=True,
    )

    # 3. DLP: Scoped Virtual Token
    payment_token = PaymentToken(
        token_id=f"vtok_{uuid.uuid4().hex[:12]}",
        token_type="SCOPED_VIRTUAL_TOKEN",
        masked_card="•••• 4242",
        bank_issuer="Galicia AI Payments",
        expires_at=expires_at,
        bound_mandate_id=mandate_id,
    )

    unsigned_dict = {
        "mandate_id": mandate_id,
        "human_id": human_id,
        "human_pubkey": h_pub,
        "agent_id": agent_id,
        "agent_pubkey": a_pub,
        "scope": scope.model_dump(),
        "payment_token": payment_token.model_dump(),
        "created_at": created_at,
        "expires_at": expires_at,
        "status": MandateStatus.ACTIVE.value,
        "intent_summary": estructura_ia.get("intent_summary"),
    }

    # 4. Sello Criptográfico
    signature = sign_payload(h_priv, unsigned_dict)

    mandate = Mandate(
        mandate_id=mandate_id,
        human_id=human_id,
        human_pubkey=h_pub,
        agent_id=agent_id,
        agent_pubkey=a_pub,
        scope=scope,
        payment_token=payment_token,
        created_at=created_at,
        expires_at=expires_at,
        status=MandateStatus.ACTIVE,
        human_signature=signature,
    )

    return mandate, estructura_ia
