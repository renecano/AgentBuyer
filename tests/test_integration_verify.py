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

from audit.log import get_trail_events, reset_trail
from api.main import app
from core import mandate_store
from mandate.sign import generate_keypair, sign_payload

ENGINE_RULES = {"amount", "category", "merchant", "uses", "condition.price_below"}
SECURITY_RULES = {"signature", "agent_identity", "status"}


@pytest.fixture()
def client(auth_headers):
    # El context manager dispara el startup (que carga el seed); limpiamos
    # después para que cada test empiece con memoria vacía y estado propio.
    # Autenticado como usuario real: crear mandatos exige token (POST /mandates).
    with TestClient(app, headers=auth_headers) as test_client:
        mandate_store.MANDATES.clear()
        reset_trail()
        yield test_client
    mandate_store.MANDATES.clear()
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
        # Sin "signature": el servidor sella el mandato con Ed25519 REAL al crearlo
        # (antes: "firma-de-prueba", que solo pasaba por el fail-open de /verify).
    }
    mandate.update(overrides)
    return mandate


def make_attempt(
    mandate_id: str = "mnd_test_001",
    agent_id: str = "agt_test",
    amount: float = 130.0,
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
            "amount": amount,
            "currency": "USD",
            "metadata": {"price": amount},
        },
    }


def create_mandate(client: TestClient, mandate: dict) -> None:
    response = client.post("/mandates", json=mandate)
    assert response.status_code == 201, response.text


def rules_of(result: dict) -> list[str]:
    return [check["rule"] for check in result["checks"]]


# ── Camino feliz ─────────────────────────────────────────────────────────────

def test_approve_runs_security_then_engine_and_updates_state(client):
    create_mandate(client, make_mandate())
    response = client.post("/verify", json=make_attempt())
    result = response.json()

    assert response.status_code == 200
    assert result["verdict"] == "APPROVE"
    # Seguridad primero, engine después — y todas las reglas presentes.
    rules = rules_of(result)
    assert rules[:3] == ["signature", "agent_identity", "status"]
    assert set(rules[3:]) == ENGINE_RULES

    # El estado vivo se actualizó tras aprobar.
    live_state = client.get("/mandates/mnd_test_001").json()["live_state"]
    assert live_state["uses_count"] == 1
    assert live_state["amount_spent"] == 130.0


def test_uses_exhaust_after_three_approvals(client):
    create_mandate(client, make_mandate())
    for n in range(3):
        result = client.post(
            "/verify", json=make_attempt(attempt_id=f"att_{n}")
        ).json()
        assert result["verdict"] == "APPROVE", result

    fourth = client.post("/verify", json=make_attempt(attempt_id="att_3")).json()
    assert fourth["verdict"] == "ESCALATE"
    failed = {c["rule"] for c in fourth["checks"] if not c["pass"]}
    assert failed == {"uses"}
    # El intento escalado no consumió un uso.
    assert client.get("/mandates/mnd_test_001").json()["live_state"]["uses_count"] == 3


def test_escalate_does_not_touch_live_state(client):
    create_mandate(client, make_mandate())
    result = client.post("/verify", json=make_attempt(amount=300.0)).json()

    assert result["verdict"] == "ESCALATE"
    live_state = client.get("/mandates/mnd_test_001").json()["live_state"]
    assert live_state["uses_count"] == 0
    assert live_state["amount_spent"] == 0


# ── Seguridad primero: el engine ni se entera ────────────────────────────────

def test_revoked_mandate_rejects_before_engine(client):
    """El trial by fire: revocar y la SIGUIENTE compra muere en status."""
    create_mandate(client, make_mandate())
    assert client.post("/verify", json=make_attempt()).json()["verdict"] == "APPROVE"

    assert client.post("/mandates/mnd_test_001/revoke").status_code == 200

    result = client.post("/verify", json=make_attempt(attempt_id="att_post_revoke")).json()
    assert result["verdict"] == "REJECT"
    rules = rules_of(result)
    assert "status" in rules
    # Ninguna regla del engine fue evaluada: se corta antes.
    assert not ENGINE_RULES.intersection(rules)


def test_wrong_agent_rejects(client):
    create_mandate(client, make_mandate())
    result = client.post(
        "/verify", json=make_attempt(agent_id="agt_impostor")
    ).json()
    assert result["verdict"] == "REJECT"
    failed = {c["rule"] for c in result["checks"] if not c["pass"]}
    assert failed == {"agent_identity"}
    assert not ENGINE_RULES.intersection(rules_of(result))


def test_missing_signature_rejects(client):
    create_mandate(client, make_mandate(signature=""))
    result = client.post("/verify", json=make_attempt()).json()
    assert result["verdict"] == "REJECT"
    failed = {c["rule"] for c in result["checks"] if not c["pass"]}
    assert failed == {"signature"}


def test_unknown_mandate_rejects(client):
    result = client.post(
        "/verify", json=make_attempt(mandate_id="mnd_no_existe")
    ).json()
    assert result["verdict"] == "REJECT"
    assert rules_of(result) == ["mandate_exists"]


# ── Contratos del endpoint ───────────────────────────────────────────────────

def test_non_dict_purchase_is_422_before_engine(client):
    create_mandate(client, make_mandate())
    attempt = make_attempt()
    attempt["purchase"] = "no-soy-un-dict"
    response = client.post("/verify", json=attempt)
    assert response.status_code == 422


def test_engine_escalation_reports_engine_checks_alongside_security(client):
    """En un ESCALATE la respuesta combina los checks de seguridad (pass)
    con los del engine — el trail completo para el humano que decide."""
    create_mandate(client, make_mandate())
    result = client.post("/verify", json=make_attempt(category="hotel")).json()

    assert result["verdict"] == "ESCALATE"
    by_rule = {c["rule"]: c["pass"] for c in result["checks"]}
    for rule in SECURITY_RULES:
        assert by_rule[rule] is True
    assert by_rule["category"] is False


def test_verification_events_are_recorded(client):
    create_mandate(client, make_mandate())
    client.post("/verify", json=make_attempt())
    client.post("/verify", json=make_attempt(amount=300.0, attempt_id="att_2"))

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


# ── Mandato firmado por el servidor (payload del wizard con login OTP) ──────

def test_server_signed_mandate_passes_real_ed25519_verification(client):
    """El wizard ya no envía firma: el servidor firma con Ed25519 al crear.
    Ese mandato debe pasar la verificación criptográfica REAL de /verify, y
    alterar las constraints firmadas debe romperla."""
    mandate = make_mandate(mandate_id="mnd_server_signed")
    assert "signature" not in mandate  # el servidor firma
    create_mandate(client, mandate)

    approved = client.post("/verify", json=make_attempt(mandate_id="mnd_server_signed", attempt_id="att_signed_1")).json()
    signature_check = next(check for check in approved["checks"] if check["rule"] == "signature")
    assert approved["verdict"] == "APPROVE"
    assert signature_check == {"rule": "signature", "pass": True, "detail": "Firma digital Ed25519 válida."}

    mandate_store.MANDATES["mnd_server_signed"]["mandate"]["constraints"]["max_amount_per_purchase"] = 99999
    tampered = client.post("/verify", json=make_attempt(mandate_id="mnd_server_signed", attempt_id="att_signed_2")).json()
    assert tampered["verdict"] == "REJECT"
    assert next(check for check in tampered["checks"] if check["rule"] == "signature")["pass"] is False


# ── Firma FAIL-CLOSED: el check pasa SOLO con Ed25519 verificada de verdad ──
#
# Antes /verify daba pass=True a una firma sin llave pública, o de menos de 64
# caracteres ("Firma presente y estructurada."), y la rama except también
# aprobaba. Estos casos congelan que eso ya no ocurre.

def signature_result(client, mandate: dict) -> tuple[str, dict]:
    create_mandate(client, mandate)
    result = client.post("/verify", json=make_attempt(mandate_id=mandate["mandate_id"])).json()
    return result["verdict"], next(check for check in result["checks"] if check["rule"] == "signature")


def client_signed(mandate_id: str, signing_priv: str, declared_pub: str) -> dict:
    """Mandato firmado por el CLIENTE: su pubkey y su firma Ed25519 sobre constraints."""
    mandate = make_mandate(mandate_id=mandate_id)
    mandate["human_pubkey"] = declared_pub
    mandate["signature"] = sign_payload(signing_priv, mandate["constraints"])
    return mandate


@pytest.mark.parametrize(
    "signature",
    ["x", "firma-de-prueba", "test-signature-placeholder", "ab" * 64],
    ids=["one-char", "placeholder", "seed-placeholder", "128-hex-garbage"],
)
def test_signature_without_public_key_is_rejected(client, signature):
    """Sin llave con la que verificar, ninguna firma pasa: ni corta ni con forma de Ed25519."""
    verdict, check = signature_result(client, make_mandate(mandate_id="mnd_nopub", signature=signature))

    assert verdict == "REJECT"
    assert check == {"rule": "signature", "pass": False, "detail": "Firma digital inválida."}


def test_garbage_signature_with_a_real_public_key_is_rejected(client):
    _, pub = generate_keypair()
    mandate = make_mandate(mandate_id="mnd_garbage", human_pubkey=pub, signature="ab" * 64)

    verdict, check = signature_result(client, mandate)
    assert verdict == "REJECT" and check["pass"] is False


def test_client_signature_with_its_own_key_is_approved(client):
    """Una firma Ed25519 real hecha por el cliente, con su propia llave, verifica."""
    priv, pub = generate_keypair()
    verdict, check = signature_result(client, client_signed("mnd_client_ok", priv, pub))

    assert verdict == "APPROVE"
    assert check == {"rule": "signature", "pass": True, "detail": "Firma digital Ed25519 válida."}


def test_public_key_of_one_key_and_signature_of_another_is_rejected(client):
    _, pub = generate_keypair()
    other_priv, _ = generate_keypair()
    verdict, check = signature_result(client, client_signed("mnd_mismatch", other_priv, pub))

    assert verdict == "REJECT" and check["pass"] is False


@pytest.mark.parametrize("bad_pubkey", ["zz" * 32, "ab" * 10, 12345], ids=["non-hex", "short", "not-a-string"])
def test_malformed_public_key_fails_closed(client, bad_pubkey):
    """Una llave pública que ni siquiera se puede cargar no es 'firma presente': es REJECT."""
    priv, _ = generate_keypair()
    verdict, check = signature_result(client, client_signed("mnd_badpub", priv, bad_pubkey))

    assert verdict == "REJECT" and check["pass"] is False


def test_non_string_signature_is_rejected(client):
    _, pub = generate_keypair()
    verdict, check = signature_result(
        client, make_mandate(mandate_id="mnd_sig_obj", human_pubkey=pub, signature={"sig": "x"})
    )
    assert verdict == "REJECT" and check["pass"] is False


def test_no_signature_check_ever_passes_without_verifying(client):
    """Ninguna respuesta de /verify vuelve a decir 'presente y estructurada/verificada'
    (los textos de las ramas que aprobaban sin verificar)."""
    for index, signature in enumerate(["x", "ab" * 64]):
        _, check = signature_result(client, make_mandate(mandate_id=f"mnd_text_{index}", signature=signature))
        assert check["detail"] not in {"Firma presente y estructurada.", "Firma presente y verificada."}

