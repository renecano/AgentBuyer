import pytest
from datetime import datetime, timedelta, timezone

from shared.schemas import MandateStatus, VerificationStatus
from mandate.sign import generate_keypair
from mandate.issue import create_mandate
from core.mandate_store import mandate_store
from core.agent_loop import PurchasingAgent
from core.merchant import vuelaya_merchant
from core.verify import get_pending_escalations, resolve_escalation
from core.dispute import dispute_arbiter
from audit.log import audit_ledger


@pytest.fixture(autouse=True)
def cleanup():
    mandate_store.clear()
    audit_ledger.clear()
    yield
    mandate_store.clear()
    audit_ledger.clear()


def test_e2e_successful_purchase():
    # 1. Human creates mandate: flights to Cordoba <= $150
    h_priv, h_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()

    mandate = create_mandate(
        human_id="marta_01",
        human_privkey=h_priv,
        human_pubkey=h_pub,
        agent_id="agent_marta",
        agent_pubkey=a_pub,
        max_amount_per_tx=150.0,
        conditions_expression="price <= 150 AND destination == 'COR'",
    )
    mandate_store.save_mandate(mandate)

    # 2. Agent scans catalog and finds Flight COR at $130
    agent = PurchasingAgent("agent_marta", a_priv, a_pub)
    flight_130 = vuelaya_merchant.get_item("FLIGHT_COR_130")

    # 3. Agent executes purchase
    attempt, result = agent.attempt_purchase(mandate, flight_130)

    # 4. Assert verification approved and settled
    assert result.authorized is True
    assert result.status == VerificationStatus.APPROVED
    assert result.settlement_id is not None
    assert result.dispute_token is not None

    # 5. Assert audit trail recorded
    entries = audit_ledger.get_all_entries()
    assert len(entries) >= 2
    is_valid, _ = audit_ledger.verify_chain_integrity()
    assert is_valid is True


def test_out_of_mandate_hitl_approval():
    h_priv, h_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()

    mandate = create_mandate(
        human_id="marta_01",
        human_privkey=h_priv,
        human_pubkey=h_pub,
        agent_id="agent_marta",
        agent_pubkey=a_pub,
        max_amount_per_tx=150.0,
        allow_hitl_escalation=True,
    )
    mandate_store.save_mandate(mandate)

    agent = PurchasingAgent("agent_marta", a_priv, a_pub)
    flight_300 = vuelaya_merchant.get_item("FLIGHT_COR_300")

    # Purchase attempt on $300 flight (exceeds $150 limit)
    attempt, result = agent.attempt_purchase(mandate, flight_300)

    assert result.status == VerificationStatus.ESCALATED_HITL
    assert result.authorized is False
    assert result.escalation_id is not None

    # Check pending escalation inbox
    pending = get_pending_escalations(mandate.mandate_id)
    assert len(pending) == 1
    assert pending[0].escalation_id == result.escalation_id

    # Human Marta reviews and approves the escalation
    resolution = resolve_escalation(
        escalation_id=result.escalation_id,
        approved=True,
        human_privkey=h_priv,
        human_pubkey=h_pub,
        note="Approved by Marta: Last minute urgent flight needed",
    )

    assert resolution.authorized is True
    assert resolution.status == VerificationStatus.APPROVED
    assert resolution.settlement_id is not None


def test_out_of_mandate_hitl_rejection():
    h_priv, h_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()

    mandate = create_mandate(
        human_id="marta_01",
        human_privkey=h_priv,
        human_pubkey=h_pub,
        agent_id="agent_marta",
        agent_pubkey=a_pub,
        max_amount_per_tx=150.0,
        allow_hitl_escalation=True,
    )
    mandate_store.save_mandate(mandate)

    agent = PurchasingAgent("agent_marta", a_priv, a_pub)
    flight_300 = vuelaya_merchant.get_item("FLIGHT_COR_300")

    attempt, result = agent.attempt_purchase(mandate, flight_300)
    assert result.status == VerificationStatus.ESCALATED_HITL

    # Marta denies
    resolution = resolve_escalation(
        escalation_id=result.escalation_id,
        approved=False,
        human_privkey=h_priv,
        human_pubkey=h_pub,
        note="Too expensive, wait for promo",
    )

    assert resolution.authorized is False
    assert resolution.status == VerificationStatus.REJECTED


def test_trial_by_fire_live_revocation():
    h_priv, h_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()

    mandate = create_mandate(
        human_id="marta_01",
        human_privkey=h_priv,
        human_pubkey=h_pub,
        agent_id="agent_marta",
        agent_pubkey=a_pub,
        max_amount_per_tx=150.0,
    )
    mandate_store.save_mandate(mandate)

    agent = PurchasingAgent("agent_marta", a_priv, a_pub)
    flight_130 = vuelaya_merchant.get_item("FLIGHT_COR_130")

    # Purchase 1 succeeds
    _, res1 = agent.attempt_purchase(mandate, flight_130)
    assert res1.authorized is True

    # Trial by fire: Marta revokes mandate live
    revoked = mandate_store.revoke_mandate(mandate.mandate_id, reason="Trial by fire jury test")
    assert revoked is True

    # Purchase 2 fails immediately at merchant verification
    _, res2 = agent.attempt_purchase(mandate, flight_130)
    assert res2.authorized is False
    assert res2.status == VerificationStatus.REJECTED
    assert "REVOKED" in res2.reason


def test_dispute_resolution_human_liable():
    h_priv, h_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()

    mandate = create_mandate(
        human_id="marta_01",
        human_privkey=h_priv,
        human_pubkey=h_pub,
        agent_id="agent_marta",
        agent_pubkey=a_pub,
        max_amount_per_tx=150.0,
    )
    mandate_store.save_mandate(mandate)

    agent = PurchasingAgent("agent_marta", a_priv, a_pub)
    flight_130 = vuelaya_merchant.get_item("FLIGHT_COR_130")

    attempt, res = agent.attempt_purchase(mandate, flight_130)
    assert res.authorized is True

    # Human claims dispute: "I didn't authorize this"
    claim = dispute_arbiter.file_dispute(
        attempt_id=attempt.attempt_id,
        mandate_id=mandate.mandate_id,
        claimant_id=mandate.human_id,
        reason="I did not authorize this charge",
    )

    assert claim.status == "RESOLVED"
    assert claim.verdict == "HUMAN_LIABLE_VALID_MANDATE"
    assert claim.liable_party == "HUMAN"
    assert claim.refund_issued is False


def test_audit_hash_chain_integrity_and_tamper_detection():
    audit_ledger.append_entry("TEST_EVENT_1", "HUMAN", "user_1", {"msg": "hello"})
    audit_ledger.append_entry("TEST_EVENT_2", "AGENT", "agent_1", {"msg": "world"})

    is_valid, msg = audit_ledger.verify_chain_integrity()
    assert is_valid is True

    # Tamper test
    audit_ledger._entries[0].details["msg"] = "tampered_data"
    is_valid_after_tamper, error_msg = audit_ledger.verify_chain_integrity()
    assert is_valid_after_tamper is False
    assert "Tampered entry" in error_msg
