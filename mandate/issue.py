import time
import uuid
from typing import List, Optional, Union
from shared.schemas import Mandate, MandateScope, MandateStatus, PaymentToken
from mandate.sign import sign_payload


def emitir_mandato(user_id: str, flight_offer_id: str, amount: float, currency: str, secret_key: bytes):
    """Genera un token temporal y de un solo uso vinculado estrictamente a la intención del usuario."""
    mandate_id = f"mandate_{uuid.uuid4().hex[:8]}"
    purchase_id = f"purchase_{uuid.uuid4().hex[:8]}"
    
    payload = {
        "mandate_id": mandate_id,
        "user_id": user_id,
        "purchase_id": purchase_id,
        "flight_offer_id": flight_offer_id,
        "amount": amount,
        "currency": currency,
        "single_use": True,
        "status": "active",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300  # Expira en 5 minutos (privilegios temporales estrictos)
    }
    
    signed_token = sign_payload(payload, secret_key)
    return signed_token, mandate_id


def create_mandate(
    human_id: str,
    human_privkey: str,
    human_pubkey: str,
    agent_id: str,
    agent_pubkey: str,
    max_amount_per_tx: float,
    monthly_budget: float = 500.0,
    allowed_categories: Optional[List[str]] = None,
    allowed_merchants: Optional[List[str]] = None,
    conditions_expression: Optional[str] = None,
    currency: str = "USD",
    max_executions_per_month: int = 5,
    allow_hitl_escalation: bool = True,
    validity_days: int = 30,
    masked_card: str = "•••• 4242",
    bank_issuer: str = "Galicia AI Payments",
) -> Mandate:
    """
    Creates and cryptographically signs a purchasing mandate.
    Generates a Scoped Virtual Payment Token guaranteeing zero raw credit card exposure.
    """
    if allowed_categories is None:
        allowed_categories = ["travel.flights", "travel"]
    if allowed_merchants is None:
        allowed_merchants = ["*"]

    mandate_id = f"mnd_{uuid.uuid4().hex[:10]}"
    now = time.time()
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + validity_days * 86400))

    scope = MandateScope(
        max_amount_per_tx=max_amount_per_tx,
        monthly_budget=monthly_budget,
        allowed_categories=allowed_categories,
        allowed_merchants=allowed_merchants,
        conditions_expression=conditions_expression,
        currency=currency,
        max_executions_per_month=max_executions_per_month,
        allow_hitl_escalation=allow_hitl_escalation,
    )

    payment_token = PaymentToken(
        token_id=f"vtok_{uuid.uuid4().hex[:12]}",
        token_type="SCOPED_VIRTUAL_TOKEN",
        masked_card=masked_card,
        bank_issuer=bank_issuer,
        expires_at=expires_at,
        bound_mandate_id=mandate_id,
    )

    unsigned_payload = {
        "mandate_id": mandate_id,
        "human_id": human_id,
        "human_pubkey": human_pubkey,
        "agent_id": agent_id,
        "agent_pubkey": agent_pubkey,
        "scope": scope.model_dump(),
        "payment_token": payment_token.model_dump(),
        "created_at": created_at,
        "expires_at": expires_at,
        "status": MandateStatus.ACTIVE.value,
    }

    signature = sign_payload(unsigned_payload, human_privkey)

    return Mandate(
        mandate_id=mandate_id,
        human_id=human_id,
        human_pubkey=human_pubkey,
        agent_id=agent_id,
        agent_pubkey=agent_pubkey,
        scope=scope,
        payment_token=payment_token,
        created_at=created_at,
        expires_at=expires_at,
        status=MandateStatus.ACTIVE,
        human_signature=signature,
    )
