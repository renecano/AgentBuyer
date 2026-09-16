from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class MandateStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    PAUSED = "PAUSED"


class VerificationStatus(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    ESCALATED_HITL = "ESCALATED_HITL"


class ActorType(str, Enum):
    HUMAN = "HUMAN"
    AGENT = "AGENT"
    MERCHANT = "MERCHANT"
    AUDITOR = "AUDITOR"
    BANK = "BANK"
    REGISTRY = "REGISTRY"


class EventType(str, Enum):
    MANDATE_CREATED = "MANDATE_CREATED"
    MANDATE_REVOKED = "MANDATE_REVOKED"
    MANDATE_PAUSED = "MANDATE_PAUSED"
    MANDATE_RESUMED = "MANDATE_RESUMED"
    PURCHASE_ATTEMPTED = "PURCHASE_ATTEMPTED"
    VERIFICATION_SUCCESS = "VERIFICATION_SUCCESS"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    HITL_ESCALATED = "HITL_ESCALATED"
    HITL_APPROVED = "HITL_APPROVED"
    HITL_REJECTED = "HITL_REJECTED"
    SETTLEMENT_COMPLETED = "SETTLEMENT_COMPLETED"
    DISPUTE_FILED = "DISPUTE_FILED"
    DISPUTE_RESOLVED = "DISPUTE_RESOLVED"
    ADVERSARIAL_BLOCKED = "ADVERSARIAL_BLOCKED"


class MandateScope(BaseModel):
    max_amount_per_tx: float = Field(..., description="Maximum amount allowed for a single purchase")
    monthly_budget: float = Field(default=1000.0, description="Total rolling spend limit per month")
    allowed_categories: List[str] = Field(default_factory=lambda: ["travel", "flights"], description="Permitted category tags")
    allowed_merchants: List[str] = Field(default_factory=lambda: ["*"], description="Permitted merchant IDs or wildcard")
    conditions_expression: Optional[str] = Field(
        default=None, 
        description="DSL condition string, e.g. price <= 150 AND destination == 'COR'"
    )
    currency: str = Field(default="USD", description="Currency code")
    max_executions_per_month: int = Field(default=5, description="Max purchases within billing period")
    allow_hitl_escalation: bool = Field(
        default=True, 
        description="Whether to escalate slightly exceeding purchases to human instead of hard reject"
    )


class PaymentToken(BaseModel):
    token_id: str
    token_type: str = "SCOPED_VIRTUAL_TOKEN"
    masked_card: str = "•••• 4242"
    bank_issuer: str = "Galicia AI Payments"
    expires_at: str = "2026-12-31T00:00:00Z"
    bound_mandate_id: Optional[str] = None


class Mandate(BaseModel):
    mandate_id: str
    human_id: str = "hum_marta"
    human_pubkey: str = ""
    agent_id: str = "agt_saturday"
    agent_pubkey: str = ""
    scope: Optional[MandateScope] = None
    constraints: Optional[Dict[str, Any]] = None
    human: Optional[Dict[str, Any]] = None
    agent: Optional[Dict[str, Any]] = None
    payment_token: Optional[PaymentToken] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None
    status: MandateStatus = MandateStatus.ACTIVE
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None
    human_signature: str = ""
    signature: str = ""



class PurchaseAttempt(BaseModel):
    attempt_id: str
    mandate_id: str
    agent_id: str
    merchant_id: str
    item_id: str = "item_01"
    item_title: str = "Item"
    item_description: str = ""
    category: str
    amount: float
    currency: str = "USD"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str
    nonce: str
    signature: str = ""
    agent_signature: str = ""



class VerificationResult(BaseModel):
    attempt_id: str
    status: VerificationStatus
    authorized: bool
    reason: str
    checks: Dict[str, bool] = Field(default_factory=dict)
    dispute_token: Optional[str] = None
    settlement_id: Optional[str] = None
    settlement_token: Optional[str] = None
    escalation_id: Optional[str] = None
    timestamp: str



class HITLApprovalRequest(BaseModel):
    escalation_id: str
    attempt_id: str
    mandate_id: str
    attempt: PurchaseAttempt
    reason: str
    requested_amount: float
    mandate_limit: float
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED
    created_at: str
    resolved_at: Optional[str] = None
    resolution_note: Optional[str] = None
    human_decision_signature: Optional[str] = None


class AuditLogEntry(BaseModel):
    entry_id: str
    index: int
    prev_hash: str
    hash: str
    timestamp: str
    event_type: str
    actor_type: str
    actor_id: str
    mandate_id: Optional[str] = None
    attempt_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    signature: Optional[str] = None


class DisputeClaim(BaseModel):
    dispute_id: str
    attempt_id: str
    mandate_id: str
    claimant_id: str
    reason: str
    created_at: str
    status: str = "FILED"  # FILED, UNDER_REVIEW, RESOLVED
    verdict: Optional[str] = None
    liable_party: Optional[str] = None  # HUMAN, AGENT, MERCHANT, FRAUDSTER
    refund_issued: bool = False
    audit_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    explanation: Optional[str] = None


class CatalogItem(BaseModel):
    item_id: str
    title: str = "Item"
    description: str = ""
    category: str
    price: float
    currency: str = "USD"
    merchant_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    available: bool = True



class CreateMandateRequest(BaseModel):
    human_id: str
    max_amount_per_tx: float
    monthly_budget: float = 1000.0
    allowed_categories: List[str] = Field(default_factory=lambda: ["travel", "flights"])
    allowed_merchants: List[str] = Field(default_factory=lambda: ["*"])
    conditions_expression: Optional[str] = None
    currency: str = "USD"
    max_executions_per_month: int = 5
    allow_hitl_escalation: bool = True
    validity_days: int = 30
    masked_card: str = "•••• 4242"
    bank_issuer: str = "Galicia AI Payments"


class RevokeMandateRequest(BaseModel):
    reason: str = "Revoked by cardholder"


class ExecutePurchaseRequest(BaseModel):
    mandate_id: str
    agent_id: str
    item_id: str
    override_amount: Optional[float] = None


class ResolveEscalationRequest(BaseModel):
    approved: bool
    note: Optional[str] = None


class FileDisputeRequest(BaseModel):
    attempt_id: str
    mandate_id: str
    claimant_id: str
    reason: str

