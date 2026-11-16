"""Modelos compartidos del ledger de auditoría.

7.2 (P-08): los modelos de la línea estricta (Mandate, MandateScope, PaymentToken,
PurchaseAttempt, VerificationResult, HITLApprovalRequest, DisputeClaim, CatalogItem
y sus requests) se retiraron con ella. Los mandatos del producto son el documento
firmado por su titular (mandate/mandate_message.py) y el registro {mandate,
live_state} de core/mandate_store.py.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ActorType(str, Enum):
    HUMAN = "HUMAN"
    AGENT = "AGENT"
    MERCHANT = "MERCHANT"
    AUDITOR = "AUDITOR"
    BANK = "BANK"
    REGISTRY = "REGISTRY"


class EventType(str, Enum):
    """Tipos de evento en MAYÚSCULAS que el trail sigue escribiendo (api/disputes.py).
    Los demás tipos del trail están en audit/log._EVENT_TYPES."""
    DISPUTE_FILED = "DISPUTE_FILED"
    DISPUTE_RESOLVED = "DISPUTE_RESOLVED"


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
