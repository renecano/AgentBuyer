"""Integración end-to-end: /verify con el engine REAL ya cableado.

Cubre lo que los tests unitarios del engine no pueden ver:
  - el orden seguridad-primero (firma, agente, status) antes del engine
  - que uses_count/amount_spent se actualizan SOLO al aprobar
  - que revocar corta la siguiente compra (trial by fire)
  - que el seed de la demo carga al startup

El store es memoria a nivel de módulo, así que cada test limpia el estado
y crea su propio mandato — ningún test depende de otro.
"""
import pytest
from fastapi.testclient import TestClient
from tests.conftest import verify_as_service

from audit.log import get_trail_events, reset_trail
from api.main import app
from core import mandate_store, owner_keys
from mandate.sign import generate_keypair, sign_payload

# 4.2 (P-03): /verify es la verificación del comercio/agente: credencial `service`.
pytestmark = pytest.mark.usefixtures("service_key")

ENGINE_RULES = {"amount", "category", "merchant", "uses", "condition.price_below"}
# 3.3/3.5 (cambio deliberado): un mandato firmado por el titular suma, en este orden,
# la vigencia de su llave (P-01 a), el binding del payment_token y la moneda firmada.
# 4.2 (P-03): y antes del estado, el nonce único del intento (anti-replay). Este intento
# no declara firma del agente; si la declarara, "agent_signature" iría tras agent_identity.
SECURITY_ORDER = ["signature", "signing_key_active", "payment_token_binding", "agent_identity", "nonce_fresh", "status", "currency"]
SECURITY_RULES = set(SECURITY_ORDER)
# Y después del engine, el consentimiento a comprar sin la persona presente (D-16).
CONSENT_RULE = "off_session_consent"


@pytest.fixture()
def client(auth_headers):
    # El context manager dispara el startup (que carga el seed); limpiamos
    # después para que cada test empiece con memoria vacía y estado propio.
    # Autenticado como usuario real: crear mandatos exige token (POST /mandates).
    with TestClient(app, headers=auth_headers) as test_client:
        mandate_store.mandate_store.clear()
        owner_keys.clear()
        reset_trail()
        yield test_client
    mandate_store.mandate_store.clear()
    owner_keys.clear()
    reset_trail()


def make_mandate(mandate_id: str = "mnd_test_001", **overrides) -> dict:
    mandate = {
        "mandate_id": mandate_id,
        "human": {"id": "hum_test", "name": "Test Human"},
        "agent": {"id": "agt_test"},
        "constraints": {
            "max_amount_per_purchase": 150.00,
            "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"],
            "max_uses": 3,
            "conditions": [{"type": "price_below", "value": 150.00}],
        },
        # 3.5: lo firma el titular (helper signed_poster, como el navegador).
    }
    mandate.update(overrides)
    return mandate


def make_attempt(
    mandate_id: str = "mnd_test_001",
    agent_id: str = "agt_test",
    amount_cents: int = 13000,
    category: str = "travel.flights",
    merchant_id: str = "mch_vuelaya",
    attempt_id: str = "att_test_001",
) -> dict:
    return {
        "attempt_id": attempt_id,
        "mandate_id": mandate_id,
        "presented_by_agent": agent_id,
        "purchase": {
            "merchant_id": merchant_id,
            "category": category,
            "amount_cents": amount_cents,
            "currency": "USD",
            "metadata": {"price_cents": amount_cents},
        },
    }


def create_mandate(poster, mandate: dict) -> None:
    """Crea el mandato FIRMADO por el titular (tests/conftest.py: SignedMandatePoster)."""
    poster.create(mandate)


def rules_of(result: dict) -> list[str]:
    return [check["rule"] for check in result["checks"]]


# ── Camino feliz ─────────────────────────────────────────────────────────────

def test_approve_runs_security_then_engine_and_updates_state(client, signed_poster):
    create_mandate(signed_poster, make_mandate())
    response = verify_as_service(client, make_attempt())
    result = response.json()

    assert response.status_code == 200
    assert result["verdict"] == "APPROVE"
    # Seguridad primero, engine después — y todas las reglas presentes.
    rules = rules_of(result)
    assert rules[:len(SECURITY_ORDER)] == SECURITY_ORDER
    assert set(rules[len(SECURITY_ORDER):-2]) == ENGINE_RULES
    # 5.3: tras el consentimiento, el firewall semántico revisa TODA compra aprobable.
    assert rules[-2:] == [CONSENT_RULE, "semantic_firewall"]

    # El estado vivo se actualizó tras aprobar.
    live_state = client.get("/mandates/mnd_test_001").json()["live_state"]
    assert live_state["uses_count"] == 1
    assert live_state["amount_spent_cents"] == 13000


def test_uses_exhaust_after_three_approvals(client, signed_poster):
    create_mandate(signed_poster, make_mandate())
    for n in range(3):
        result = verify_as_service(client, make_attempt(attempt_id=f"att_{n}")
        ).json()
        assert result["verdict"] == "APPROVE", result

    fourth = verify_as_service(client, make_attempt(attempt_id="att_3")).json()
    assert fourth["verdict"] == "ESCALATE"
    failed = {c["rule"] for c in fourth["checks"] if not c["pass"]}
    assert failed == {"uses"}
    # El intento escalado no consumió un uso.
    assert client.get("/mandates/mnd_test_001").json()["live_state"]["uses_count"] == 3


def test_escalate_does_not_touch_live_state(client, signed_poster):
    create_mandate(signed_poster, make_mandate())
    result = verify_as_service(client, make_attempt(amount_cents=30000)).json()

    assert result["verdict"] == "ESCALATE"
    live_state = client.get("/mandates/mnd_test_001").json()["live_state"]
    assert live_state["uses_count"] == 0
    assert live_state["amount_spent_cents"] == 0


# ── Seguridad primero: el engine ni se entera ────────────────────────────────

def test_revoked_mandate_rejects_before_engine(client, signed_poster):
    """El trial by fire: revocar y la SIGUIENTE compra muere en status."""
    create_mandate(signed_poster, make_mandate())
    assert verify_as_service(client, make_attempt()).json()["verdict"] == "APPROVE"

    assert client.post("/mandates/mnd_test_001/revoke").status_code == 200

    result = verify_as_service(client, make_attempt(attempt_id="att_post_revoke")).json()
    assert result["verdict"] == "REJECT"
    rules = rules_of(result)
    assert "status" in rules
    # Ninguna regla del engine fue evaluada: se corta antes.
    assert not ENGINE_RULES.intersection(rules)


def test_wrong_agent_rejects(client, signed_poster):
    create_mandate(signed_poster, make_mandate())
    result = verify_as_service(client, make_attempt(agent_id="agt_impostor")
    ).json()
    assert result["verdict"] == "REJECT"
    failed = {c["rule"] for c in result["checks"] if not c["pass"]}
    assert failed == {"agent_identity"}
    assert not ENGINE_RULES.intersection(rules_of(result))


def test_mandate_without_cardholder_signature_is_not_created(client):
    """3.5 (cambio deliberado): antes un mandato con signature="" se creaba y /verify lo
    rechazaba. Ahora ni se crea: sin firma del titular, POST /mandates da 422."""
    response = client.post("/mandates", json=make_mandate(signature=""))
    assert response.status_code == 422
    assert "cardholder signature is required" in response.json()["detail"]
    assert "mnd_test_001" not in mandate_store.MANDATES


def test_unknown_mandate_rejects(client):
    result = verify_as_service(client, make_attempt(mandate_id="mnd_no_existe")
    ).json()
    assert result["verdict"] == "REJECT"
    assert rules_of(result) == ["mandate_exists"]


# ── Contratos del endpoint ───────────────────────────────────────────────────

def test_non_dict_purchase_is_422_before_engine(client, signed_poster):
    create_mandate(signed_poster, make_mandate())
    attempt = make_attempt()
    attempt["purchase"] = "no-soy-un-dict"
    response = verify_as_service(client, attempt)
    assert response.status_code == 422


def test_engine_escalation_reports_engine_checks_alongside_security(client, signed_poster):
    """En un ESCALATE la respuesta combina los checks de seguridad (pass)
    con los del engine — el trail completo para el humano que decide."""
    create_mandate(signed_poster, make_mandate())
    result = verify_as_service(client, make_attempt(category="hotel")).json()

    assert result["verdict"] == "ESCALATE"
    by_rule = {c["rule"]: c["pass"] for c in result["checks"]}
    for rule in SECURITY_RULES:
        assert by_rule[rule] is True
    assert by_rule["category"] is False


def test_verification_events_are_recorded(client, signed_poster):
    create_mandate(signed_poster, make_mandate())
    verify_as_service(client, make_attempt())
    verify_as_service(client, make_attempt(amount_cents=30000, attempt_id="att_2"))

    verdicts = [event["verdict"] for event in get_trail_events() if event["type"] == "verification"]
    assert verdicts == ["APPROVE", "ESCALATE"]


# ── Seed de la demo ──────────────────────────────────────────────────────────

def test_seed_mandate_loads_on_startup(active_seed, seed_owner_headers):
    """El startup carga el seed — Marta existe sin POST previo.

    active_seed (tests/conftest.py) le da una expiración relativa a "ahora": el
    test no caduca con la fecha absoluta de shared/seed_mandates.json."""
    mandate_store.MANDATES.clear()
    with TestClient(app, headers=seed_owner_headers) as fresh_client:
        response = fresh_client.get("/mandates/mnd_marta_001")
        assert response.status_code == 200
        record = response.json()
        assert record["live_state"]["status"] == "active"
        assert record["mandate"]["constraints"]["max_uses"] == 3
        assert record["mandate"]["expires_at"] == active_seed["expires_at"]
    mandate_store.MANDATES.clear()
    reset_trail()


# ── Mandato firmado por el titular (payload del wizard desde el 3.4) ────────

def test_cardholder_signed_mandate_passes_real_ed25519_verification(client, signed_poster):
    """3.5: el servidor ya no firma por el usuario. El titular firma con la llave de su
    dispositivo; /verify reconstruye el mensaje y lo verifica, y alterar las
    constraints guardadas rompe la verificación."""
    create_mandate(signed_poster, make_mandate(mandate_id="mnd_signed"))

    approved = verify_as_service(client, make_attempt(mandate_id="mnd_signed", attempt_id="att_signed_1")).json()
    signature_check = next(check for check in approved["checks"] if check["rule"] == "signature")
    assert approved["verdict"] == "APPROVE"
    assert signature_check == {"rule": "signature", "pass": True,
                               "detail": "Firma humana Ed25519 válida (llave registrada del titular)."}

    mandate_store.MANDATES["mnd_signed"]["mandate"]["constraints"]["max_amount_per_purchase_cents"] = 9999900
    tampered = verify_as_service(client, make_attempt(mandate_id="mnd_signed", attempt_id="att_signed_2")).json()
    assert tampered["verdict"] == "REJECT"
    assert next(check for check in tampered["checks"] if check["rule"] == "signature")["pass"] is False


# ── Firmas legadas: ya no crean mandatos (3.5) ──────────────────────────────
#
# Antes /verify daba pass=True a una firma sin llave pública, o de menos de 64
# caracteres ("Firma presente y estructurada."). Después (2.x-3.4) esas firmas se
# rechazaban en /verify. Desde el 3.5 ni siquiera crean el mandato: el único alta es
# la firma del titular con su llave registrada. Estos casos lo congelan.

def client_signed(mandate_id: str, signing_priv: str, declared_pub) -> dict:
    """Mandato firmado por el CLIENTE con una llave propia NO registrada (camino legado)."""
    mandate = make_mandate(mandate_id=mandate_id)
    mandate["human_pubkey"] = declared_pub
    mandate["signature"] = sign_payload(signing_priv, mandate["constraints"])
    return mandate


def legacy_cases():
    priv, pub = generate_keypair()
    other_priv, _ = generate_keypair()
    return {
        "one-char": make_mandate(mandate_id="mnd_l1", signature="x"),
        "placeholder": make_mandate(mandate_id="mnd_l2", signature="firma-de-prueba"),
        "128-hex-garbage": make_mandate(mandate_id="mnd_l3", signature="ab" * 64),
        "garbage-with-real-pubkey": make_mandate(mandate_id="mnd_l4", human_pubkey=pub, signature="ab" * 64),
        "own-unregistered-key": client_signed("mnd_l5", priv, pub),
        "pubkey-of-another-key": client_signed("mnd_l6", other_priv, pub),
        "malformed-pubkey": client_signed("mnd_l7", priv, "zz" * 32),
        "non-string-signature": make_mandate(mandate_id="mnd_l8", human_pubkey=pub, signature={"sig": "x"}),
    }


@pytest.mark.parametrize("case", sorted(legacy_cases()))
def test_legacy_client_signature_no_longer_creates_a_mandate(client, case):
    """Incluida una firma Ed25519 REAL con la llave propia del cliente: sin llave
    registrada del titular no prueba quién firmó, así que no autoriza nada."""
    mandate = legacy_cases()[case]
    response = client.post("/mandates", json=mandate)
    assert response.status_code == 422
    assert mandate["mandate_id"] not in mandate_store.MANDATES


def test_no_signature_check_ever_passes_without_verifying(client, signed_poster):
    """Ninguna respuesta de /verify vuelve a decir 'presente y estructurada/verificada'
    (los textos de las ramas que aprobaban sin verificar), ni con una firma alterada."""
    create_mandate(signed_poster, make_mandate(mandate_id="mnd_text"))
    for index, signature in enumerate(["x", "ab" * 64]):
        mandate_store.MANDATES["mnd_text"]["mandate"]["signature"] = signature
        result = verify_as_service(client, make_attempt(mandate_id="mnd_text", attempt_id=f"att_text_{index}")).json()
        check = next(item for item in result["checks"] if item["rule"] == "signature")
        assert result["verdict"] == "REJECT" and check["pass"] is False
        assert check["detail"] not in {"Firma presente y estructurada.", "Firma presente y verificada."}
