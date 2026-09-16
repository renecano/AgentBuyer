import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from shared.schemas import MandateStatus, VerificationStatus, CatalogItem
from mandate.sign import generate_keypair, sign_payload
from mandate.issue import create_mandate
from core.mandate_store import mandate_store
from core.agent_loop import PurchasingAgent
from core.merchant import vuelaya_merchant
from core.verify import verify_purchase
from engine.state import state_manager


def run_adversarial_suite() -> bool:
    print("=" * 70)
    print("[SEC-SUITE] RUNNING AGENTBUYER ADVERSARIAL ATTACK TEST SUITE (8 VECTORS)")
    print("=" * 70)

    # Setup keys
    human_priv, human_pub = generate_keypair()
    agent_priv, agent_pub = generate_keypair()
    rogue_priv, rogue_pub = generate_keypair()

    all_passed = True

    # -------------------------------------------------------------
    # ATTACK 1: REPLAY ATTACK (Resending previously approved attempt)
    # -------------------------------------------------------------
    print("\n[ATTACK 1] Simulating Replay Attack (Re-submitting used nonce)...")
    m1 = create_mandate(
        human_id="marta_replay_test",
        human_privkey=human_priv,
        human_pubkey=human_pub,
        agent_id="agent_marta",
        agent_pubkey=agent_pub,
        max_amount_per_tx=150.0,
    )
    mandate_store.save_mandate(m1)
    agent = PurchasingAgent("agent_marta", agent_priv, agent_pub)
    item = vuelaya_merchant.get_item("FLIGHT_COR_130")

    # First attempt: should succeed
    att1, res1 = agent.attempt_purchase(m1, item)
    assert res1.authorized is True, "Legitimate attempt 1 failed"

    # Replay attempt: exact same nonce and signature
    replay_res = vuelaya_merchant.process_purchase(att1)
    # Propiedad de seguridad: fraude NO autorizado, bloqueado por el guard correcto (nonce).
    if not replay_res.authorized and replay_res.checks.get("nonce_fresh") is False:
        print("  [BLOCKED] Replay attack intercepted via nonce verification.")
    else:
        print(f"  [FAILED] Replay attack succeeded! Result: {replay_res}")
        all_passed = False

    # -------------------------------------------------------------
    # ATTACK 2: PAYLOAD TAMPERING (Altering price after signing)
    # -------------------------------------------------------------
    print("\n[ATTACK 2] Simulating In-Flight Payload Tampering (Signature Mismatch)...")
    att2 = agent.create_signed_attempt(m1, item, vuelaya_merchant.MERCHANT_ID)
    # Tamper with amount in transit: signed $130, modified to $300
    att2.amount = 300.0
    tamper_res = vuelaya_merchant.process_purchase(att2)
    # El monto alterado tras firmar rompe la firma Ed25519 del agente (integridad criptográfica).
    if not tamper_res.authorized and tamper_res.checks.get("agent_signature_valid") is False:
        print("  [BLOCKED] Tampered amount detected via agent cryptographic signature check.")
    else:
        print(f"  [FAILED] Tampered payload accepted! Result: {tamper_res}")
        all_passed = False

    # -------------------------------------------------------------
    # ATTACK 3: FORBIDDEN CATEGORY EVASION
    # -------------------------------------------------------------
    print("\n[ATTACK 3] Simulating Category Constraint Violation (Buying Rolex under Flight mandate)...")
    luxury_item = vuelaya_merchant.get_item("LUXURY_WATCH_999")
    att3, res3 = agent.attempt_purchase(m1, luxury_item)
    # No autorizado (rechazado o escalado a HITL) por violación de categoría.
    if not res3.authorized and res3.checks.get("category") is False:
        print("  [BLOCKED] Category mismatch caught by fail-closed evaluator.")
    else:
        print(f"  [FAILED] Forbidden category accepted! Result: {res3}")
        all_passed = False

    # -------------------------------------------------------------
    # ATTACK 4: LIVE REVOCATION (The Trial by Fire)
    # -------------------------------------------------------------
    print("\n[ATTACK 4] Simulating Live Revocation (The Trial by Fire)...")
    m4 = create_mandate(
        human_id="marta_revocation_test",
        human_privkey=human_priv,
        human_pubkey=human_pub,
        agent_id="agent_marta",
        agent_pubkey=agent_pub,
        max_amount_per_tx=150.0,
    )
    mandate_store.save_mandate(m4)
    # Marta revokes live
    mandate_store.revoke_mandate(m4.mandate_id, reason="Cardholder noticed suspicious activity")
    
    # Agent attempts to buy right after
    att4, res4 = agent.attempt_purchase(m4, item)
    if not res4.authorized and "REVOKED" in res4.reason:
        print("  [BLOCKED] Live revocation immediately terminated purchasing ability.")
    else:
        print(f"  [FAILED] Revoked mandate purchase succeeded! Result: {res4}")
        all_passed = False

    # -------------------------------------------------------------
    # ATTACK 5: AGENT IMPERSONATION (Rogue agent using legitimate mandate)
    # -------------------------------------------------------------
    print("\n[ATTACK 5] Simulating Agent Impersonation Attack...")
    rogue_agent = PurchasingAgent("rogue_agent_99", rogue_priv, rogue_pub)
    att5, res5 = rogue_agent.attempt_purchase(m1, item, tampered_agent_id="rogue_agent_99")
    # La firma del agente rogue no valida contra la clave pública autorizada del mandato.
    if not res5.authorized and res5.checks.get("agent_signature_valid") is False:
        print("  [BLOCKED] Unregistered agent identity rejected.")
    else:
        print(f"  [FAILED] Impersonated agent accepted! Result: {res5}")
        all_passed = False

    # -------------------------------------------------------------
    # ATTACK 6: FORGED HUMAN MANDATE SIGNATURE
    # -------------------------------------------------------------
    print("\n[ATTACK 6] Simulating Forged Mandate Signature Attack...")
    forged_mandate = create_mandate(
        human_id="victim_human",
        human_privkey=rogue_priv,  # Signed with attacker's private key
        human_pubkey=human_pub,    # But claims victim's public key
        agent_id="agent_marta",
        agent_pubkey=agent_pub,
        max_amount_per_tx=500.0,
    )
    # The signature will not match victim's human_pubkey
    mandate_store.save_mandate(forged_mandate)
    att6, res6 = agent.attempt_purchase(forged_mandate, item)
    # Firmado con la clave del atacante pero declarando la pubkey de la víctima: Ed25519 falla.
    if not res6.authorized and res6.checks.get("human_signature_valid") is False:
        print("  [BLOCKED] Forged human mandate signature detected and rejected.")
    else:
        print(f"  [FAILED] Forged mandate signature accepted! Result: {res6}")
        all_passed = False

    # -------------------------------------------------------------
    # ATTACK 7: FREQUENCY & BUDGET EXHAUSTION
    # -------------------------------------------------------------
    print("\n[ATTACK 7] Simulating Frequency & Budget Limit Exhaustion...")
    m7 = create_mandate(
        human_id="marta_budget_test",
        human_privkey=human_priv,
        human_pubkey=human_pub,
        agent_id="agent_marta",
        agent_pubkey=agent_pub,
        max_amount_per_tx=150.0,
        monthly_budget=200.0,
        max_executions_per_month=1,
    )
    mandate_store.save_mandate(m7)
    # Purchase 1 ($130) -> Should pass
    att7_1, res7_1 = agent.attempt_purchase(m7, item)
    assert res7_1.authorized is True, "Purchase 1 should succeed"
    # Purchase 2 ($130) -> Total $260 > $200 AND count 2 > 1 -> Should fail
    att7_2, res7_2 = agent.attempt_purchase(m7, item)
    # Contador de usos/presupuesto agotado: no autorizado (segunda compra bloqueada).
    if not res7_2.authorized and res7_2.checks.get("uses") is False:
        print("  [BLOCKED] Budget and execution counter limits strictly enforced.")
    else:
        print(f"  [FAILED] Budget exhaustion not prevented! Result: {res7_2}")
        all_passed = False

    # -------------------------------------------------------------
    # ATTACK 8: AST INJECTION / MALICIOUS CODE EXECUTION ATTEMPT
    # -------------------------------------------------------------
    print("\n[ATTACK 8] Simulating AST Sandbox Escape & Prompt Injection Attack...")
    m8 = create_mandate(
        human_id="marta_ast_test",
        human_privkey=human_priv,
        human_pubkey=human_pub,
        agent_id="agent_marta",
        agent_pubkey=agent_pub,
        max_amount_per_tx=150.0,
        conditions_expression="__import__('os').system('calc') == 0",
    )
    mandate_store.save_mandate(m8)
    att8, res8 = agent.attempt_purchase(m8, item)
    if not res8.authorized:
        print("  [BLOCKED] Malicious AST code construct safely rejected (fail-closed sandbox).")
    else:
        print(f"  [FAILED] Malicious code expression allowed! Result: {res8}")
        all_passed = False

    print("\n" + "=" * 70)
    if all_passed:
        print("[SUCCESS] ALL 8 ADVERSARIAL ATTACKS SUCCESSFULLY BLOCKED WITH ZERO BREACHES!")
    else:
        print("[WARNING] SOME ADVERSARIAL ATTACK TESTS FAILED.")
    print("=" * 70)

    return all_passed


if __name__ == "__main__":
    success = run_adversarial_suite()
    sys.exit(0 if success else 1)
