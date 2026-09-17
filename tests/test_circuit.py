import pytest
from datetime import datetime, timedelta, timezone

from shared.schemas import MandateStatus, VerificationStatus
from mandate.sign import generate_keypair
from mandate.issue import create_mandate
from core import verify as core_verify
from core.mandate_store import MANDATES, get_mandate, mandate_store
from core.agent_loop import PurchasingAgent
from core.merchant import vuelaya_merchant
from core.verify import get_pending_escalations, resolve_escalation
from core.dispute import dispute_arbiter
from audit.log import audit_ledger


@pytest.fixture(autouse=True)
def cleanup(monkeypatch):
    # El Semantic Firewall usa su heurística offline sin OPENAI_API_KEY: tests herméticos.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    mandate_store.clear()
    audit_ledger.clear()
    yield
    mandate_store.clear()
    audit_ledger.clear()


def new_mandate(**overrides):
    """Mandato estricto firmado (Ed25519) y guardado, con su agente listo para comprar."""
    h_priv, h_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    params = dict(
        human_id="marta_01",
        human_privkey=h_priv,
        human_pubkey=h_pub,
        agent_id="agent_marta",
        agent_pubkey=a_pub,
        max_amount_per_tx=150.0,
    )
    params.update(overrides)
    mandate = create_mandate(**params)
    mandate_store.save_mandate(mandate)
    return mandate, PurchasingAgent("agent_marta", a_priv, a_pub)


def checks_by_rule(result):
    return {check["rule"]: check for check in result.checks}


def ledger_event_types(attempt_id):
    return [entry.event_type for entry in audit_ledger.get_trail_for(attempt_id=attempt_id)]


def assert_checks_shape(result):
    assert isinstance(result.checks, list) and result.checks
    for check in result.checks:
        assert set(check) == {"rule", "pass", "detail"}
        assert isinstance(check["rule"], str)
        assert isinstance(check["pass"], bool)
        assert isinstance(check["detail"], str)


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

    # 4b. Checks como lista {rule, pass, detail}, todos en verde, incluido el firewall
    assert_checks_shape(result)
    assert all(check["pass"] for check in result.checks)
    assert {"mandate_exists", "status_active", "not_expired", "human_signature_valid",
            "agent_signature_valid", "nonce_fresh", "semantic_firewall"} <= set(checks_by_rule(result))

    # 5. Assert audit trail recorded
    entries = audit_ledger.get_all_entries()
    assert len(entries) >= 2
    assert ledger_event_types(attempt.attempt_id) == ["VERIFICATION_SUCCESS", "SETTLEMENT_COMPLETED"]
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
    assert_checks_shape(resolution)
    assert checks_by_rule(resolution)["hitl_approval"]["pass"] is True

    # Escalación y aprobación humana quedan ambas en el ledger
    assert ledger_event_types(attempt.attempt_id) == ["HITL_ESCALATED", "HITL_APPROVED", "SETTLEMENT_COMPLETED"]


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
    assert_checks_shape(resolution)
    assert checks_by_rule(resolution)["hitl_approval"]["pass"] is False
    assert ledger_event_types(attempt.attempt_id) == ["HITL_ESCALATED", "HITL_REJECTED"]


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
    attempt2, res2 = agent.attempt_purchase(mandate, flight_130)
    assert res2.authorized is False
    assert res2.status == VerificationStatus.REJECTED
    assert "REVOKED" in res2.reason
    assert_checks_shape(res2)
    assert checks_by_rule(res2)["status_active"]["pass"] is False
    # El rechazo también queda registrado en el ledger
    assert ledger_event_types(attempt2.attempt_id) == ["VERIFICATION_FAILED"]


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


# ── Estado vivo: solo ACTIVE compra (fail-closed) ───────────────────────────

def test_paused_mandate_is_rejected():
    mandate, agent = new_mandate()
    assert mandate_store.pause_mandate(mandate.mandate_id) is True

    attempt, result = agent.attempt_purchase(mandate, vuelaya_merchant.get_item("FLIGHT_COR_130"))

    assert result.authorized is False
    assert result.status == VerificationStatus.REJECTED
    assert "PAUSED" in result.reason
    assert checks_by_rule(result)["status_active"]["pass"] is False
    assert get_mandate(mandate.mandate_id)["live_state"]["uses_count"] == 0
    assert ledger_event_types(attempt.attempt_id) == ["VERIFICATION_FAILED"]


def test_expired_mandate_is_rejected():
    mandate, agent = new_mandate(validity_days=-1)  # expires_at ya en el pasado

    attempt, result = agent.attempt_purchase(mandate, vuelaya_merchant.get_item("FLIGHT_COR_130"))

    assert result.authorized is False
    assert result.status == VerificationStatus.REJECTED
    assert "EXPIRED" in result.reason
    assert checks_by_rule(result)["status_active"]["pass"] is False
    assert ledger_event_types(attempt.attempt_id) == ["VERIFICATION_FAILED"]


def test_unreadable_expires_at_fails_closed():
    """El store ignora una fecha ilegible y deja el mandato ACTIVE; la verificación no."""
    mandate, agent = new_mandate()
    MANDATES[mandate.mandate_id]["mandate"]["expires_at"] = "not-a-date"

    attempt, result = agent.attempt_purchase(mandate, vuelaya_merchant.get_item("FLIGHT_COR_130"))

    by_rule = checks_by_rule(result)
    assert result.authorized is False
    assert result.status == VerificationStatus.REJECTED
    assert by_rule["status_active"]["pass"] is True
    assert by_rule["not_expired"]["pass"] is False
    assert "human_signature_valid" not in by_rule  # se corta antes de la firma


# ── Ledger: toda decisión queda registrada ──────────────────────────────────

def test_every_decision_is_recorded_in_ledger():
    mandate, agent = new_mandate()

    approved_attempt, approved = agent.attempt_purchase(mandate, vuelaya_merchant.get_item("FLIGHT_COR_130"))
    escalated_attempt, escalated = agent.attempt_purchase(mandate, vuelaya_merchant.get_item("FLIGHT_COR_300"))
    replay_result = vuelaya_merchant.process_purchase(approved_attempt)

    assert approved.status == VerificationStatus.APPROVED
    assert escalated.status == VerificationStatus.ESCALATED_HITL
    assert replay_result.status == VerificationStatus.REJECTED

    assert ledger_event_types(escalated_attempt.attempt_id) == ["HITL_ESCALATED"]
    assert ledger_event_types(approved_attempt.attempt_id) == [
        "VERIFICATION_SUCCESS", "SETTLEMENT_COMPLETED", "VERIFICATION_FAILED",  # el replay también
    ]

    decision = next(
        entry for entry in audit_ledger.get_trail_for(attempt_id=escalated_attempt.attempt_id)
        if entry.event_type == "HITL_ESCALATED"
    )
    assert decision.details["status"] == "ESCALATED_HITL"
    assert decision.details["escalation_id"] == escalated.escalation_id
    assert decision.details["checks"] == escalated.checks

    is_valid, _ = audit_ledger.verify_chain_integrity()
    assert is_valid is True


def test_unknown_mandate_rejection_is_recorded():
    _, agent = new_mandate()
    ghost, _ = new_mandate()
    mandate_store.clear()  # el mandato ya no existe en el registro vivo

    attempt, result = agent.attempt_purchase(ghost, vuelaya_merchant.get_item("FLIGHT_COR_130"))

    assert result.status == VerificationStatus.REJECTED
    assert checks_by_rule(result)["mandate_exists"]["pass"] is False
    assert ledger_event_types(attempt.attempt_id) == ["VERIFICATION_FAILED"]


# ── Semantic Firewall en la línea estricta ──────────────────────────────────

def _firewall(verdict):
    def fake(**kwargs):
        return {"veredicto": verdict, "resumen_para_humano": f"firewall said {verdict}"}
    return fake


def _firewall_raises(**kwargs):
    raise RuntimeError("model unavailable")


@pytest.mark.parametrize(
    "firewall, allow_hitl, expected_status",
    [
        (_firewall("REJECT"), True, VerificationStatus.REJECTED),
        (_firewall("ESCALATE"), True, VerificationStatus.ESCALATED_HITL),
        (_firewall("ESCALATE"), False, VerificationStatus.REJECTED),
        (_firewall_raises, True, VerificationStatus.REJECTED),
        (_firewall("MAYBE"), True, VerificationStatus.REJECTED),
        (lambda **kwargs: None, True, VerificationStatus.REJECTED),
    ],
    ids=["reject", "escalate-hitl", "escalate-no-hitl", "exception", "unknown-verdict", "malformed-response"],
)
def test_semantic_firewall_never_approves_unless_it_says_approve(monkeypatch, firewall, allow_hitl, expected_status):
    monkeypatch.setattr(core_verify, "auditoria_cognitiva_firewall", firewall)
    mandate, agent = new_mandate(allow_hitl_escalation=allow_hitl)

    attempt, result = agent.attempt_purchase(mandate, vuelaya_merchant.get_item("FLIGHT_COR_130"))

    assert result.authorized is False
    assert result.status == expected_status
    assert result.settlement_id is None
    assert checks_by_rule(result)["semantic_firewall"]["pass"] is False
    # Las reglas del mandato sí pasaron: lo único que frena es el firewall.
    assert all(check["pass"] for check in result.checks if check["rule"] != "semantic_firewall")
    assert get_mandate(mandate.mandate_id)["live_state"]["uses_count"] == 0
    assert "SETTLEMENT_COMPLETED" not in ledger_event_types(attempt.attempt_id)


def test_semantic_firewall_receives_mandate_limit_from_scope(monkeypatch):
    seen = {}

    def spy(**kwargs):
        seen.update(kwargs)
        return {"veredicto": "APPROVE", "resumen_para_humano": "ok"}

    monkeypatch.setattr(core_verify, "auditoria_cognitiva_firewall", spy)
    mandate, agent = new_mandate(max_amount_per_tx=200.0, allowed_categories=["travel.flights"])

    _, result = agent.attempt_purchase(mandate, vuelaya_merchant.get_item("FLIGHT_MDZ_180"))

    assert result.status == VerificationStatus.APPROVED
    assert seen["mandato_constraints"]["max_amount_per_purchase"] == 200.0
    assert seen["precio_declarado"] == 180.0


# ── Disputas: un "verification" rechazado no prueba autorización ────────────

@pytest.mark.parametrize(
    "logged_verdict, expected_verdict",
    [
        ("REJECT", "MERCHANT_LIABLE_UNVERIFIED"),
        ("ESCALATE", "MERCHANT_LIABLE_UNVERIFIED"),
        ("APPROVE", "HUMAN_LIABLE_VALID_MANDATE"),
    ],
)
def test_dispute_only_counts_approved_verification_events(logged_verdict, expected_verdict):
    mandate, _ = new_mandate()
    audit_ledger.append_entry(
        event_type="verification",
        actor_type="GATEWAY",
        actor_id="system_gateway",
        mandate_id=mandate.mandate_id,
        attempt_id="att_api_flow",
        details={"type": "verification", "verdict": logged_verdict, "summary": "API flow decision"},
    )

    claim = dispute_arbiter.file_dispute(
        attempt_id="att_api_flow",
        mandate_id=mandate.mandate_id,
        claimant_id=mandate.human_id,
    )

    assert claim.verdict == expected_verdict
