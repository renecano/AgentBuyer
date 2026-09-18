"""Registro de llave con PRUEBA DE POSESIÓN (sub-paso 2.4) y revocación.

POST /keys exige {public_key, challenge_id, signature}: la firma Ed25519, hecha con
la privada de ESA pubkey, sobre registration_message(challenge, owner del token,
pubkey). El challenge exige un OTP fresco (2.3). Todo por HTTP, con tokens reales y
la verificación de producción; el helper key_registrar (conftest) hace el flujo."""
import pytest
from fastapi.testclient import TestClient

from api.main import app
from audit.log import reset_trail
from core import mandate_store, owner_keys
from core.owner_keys import MAX_ACTIVE_KEYS_PER_OWNER, get_active_keys, is_key_active, register_key
from tests.conftest import TEST_USER_EMAIL, KeyRegistrar

VICTIM = "victim@example.com"
ATTACKER = "attacker@example.com"


@pytest.fixture(autouse=True)
def clean_registry():
    owner_keys.clear()
    yield
    owner_keys.clear()


@pytest.fixture()
def client():
    mandate_store.mandate_store.clear()
    reset_trail()
    with TestClient(app) as test_client:
        yield test_client
    mandate_store.mandate_store.clear()
    reset_trail()


def post_key(registrar: KeyRegistrar, headers, public_key: str, challenge_id: str, signature: str):
    return registrar.client.post(
        "/keys", json={"public_key": public_key, "challenge_id": challenge_id, "signature": signature}, headers=headers,
    )


# ── Camino feliz ────────────────────────────────────────────────────────────

def test_valid_proof_registers_the_key(key_registrar):
    response, _, key = key_registrar.register(TEST_USER_EMAIL)

    assert response.status_code == 201
    assert response.json()["public_key"] == key
    assert get_active_keys(TEST_USER_EMAIL) == [key]


def test_blind_registration_of_the_step_1_kind_is_no_longer_possible(client, auth_headers):
    """Lo que el paso 1 aceptaba (solo la pubkey) ahora es un cuerpo incompleto."""
    key = KeyRegistrar.public_hex(KeyRegistrar.new_private_key())
    response = client.post("/keys", json={"public_key": key}, headers=auth_headers)

    assert response.status_code == 422
    assert owner_keys.OWNER_KEYS == {}


# ── Challenge ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("missing", ["challenge_id", "signature"])
def test_missing_proof_fields_are_rejected(key_registrar, auth_headers, missing):
    private_key = key_registrar.new_private_key()
    key = key_registrar.public_hex(private_key)
    challenge = key_registrar.challenge(auth_headers)
    body = {"public_key": key, "challenge_id": challenge["challenge_id"],
            "signature": key_registrar.sign(private_key, challenge, TEST_USER_EMAIL, key)}
    del body[missing]

    assert key_registrar.client.post("/keys", json=body, headers=auth_headers).status_code == 422
    assert get_active_keys(TEST_USER_EMAIL) == []


def test_unknown_challenge_is_rejected(key_registrar, auth_headers):
    private_key = key_registrar.new_private_key()
    key = key_registrar.public_hex(private_key)
    fake = {"challenge_id": "chl_" + "0" * 32, "nonce": "00" * 32}

    response = post_key(key_registrar, auth_headers, key, fake["challenge_id"],
                        key_registrar.sign(private_key, fake, TEST_USER_EMAIL, key))

    assert response.status_code == 403
    assert get_active_keys(TEST_USER_EMAIL) == []


def test_challenge_of_another_account_is_rejected_and_not_burned(key_registrar):
    """B presenta el challenge de A (aunque firme correctamente para sí): 403. Y el
    challenge de A sigue sirviendo a A: B no puede sabotear su registro."""
    headers_a, headers_b = key_registrar.bearer(VICTIM), key_registrar.bearer(ATTACKER)
    challenge_a = key_registrar.challenge(headers_a)
    attacker_key = key_registrar.new_private_key()
    attacker_pub = key_registrar.public_hex(attacker_key)

    stolen = post_key(key_registrar, headers_b, attacker_pub, challenge_a["challenge_id"],
                      key_registrar.sign(attacker_key, challenge_a, ATTACKER, attacker_pub))
    assert stolen.status_code == 403
    assert "Unknown challenge" in stolen.json()["detail"]  # no revela que existe

    victim_key = key_registrar.new_private_key()
    victim_pub = key_registrar.public_hex(victim_key)
    own = post_key(key_registrar, headers_a, victim_pub, challenge_a["challenge_id"],
                   key_registrar.sign(victim_key, challenge_a, VICTIM, victim_pub))
    assert own.status_code == 201
    assert get_active_keys(ATTACKER) == [] and get_active_keys(VICTIM) == [victim_pub]


def test_expired_challenge_is_rejected(key_registrar, auth_headers):
    private_key = key_registrar.new_private_key()
    key = key_registrar.public_hex(private_key)
    challenge = key_registrar.challenge(auth_headers)
    key_registrar.challenge_clock.advance(key_registrar.challenge_service.ttl_seconds)

    response = post_key(key_registrar, auth_headers, key, challenge["challenge_id"],
                        key_registrar.sign(private_key, challenge, TEST_USER_EMAIL, key))

    assert response.status_code == 403
    assert "expired" in response.json()["detail"]
    assert get_active_keys(TEST_USER_EMAIL) == []


def test_a_used_challenge_cannot_be_replayed(key_registrar, auth_headers):
    """Reenviar la MISMA petición válida (un replay capturado) no vuelve a pasar."""
    private_key = key_registrar.new_private_key()
    key = key_registrar.public_hex(private_key)
    challenge = key_registrar.challenge(auth_headers)
    signature = key_registrar.sign(private_key, challenge, TEST_USER_EMAIL, key)

    assert post_key(key_registrar, auth_headers, key, challenge["challenge_id"], signature).status_code == 201
    replay = post_key(key_registrar, auth_headers, key, challenge["challenge_id"], signature)
    assert replay.status_code == 403
    assert "already used" in replay.json()["detail"]


def test_a_failed_signature_burns_the_challenge(key_registrar, auth_headers):
    """UN intento de firma por challenge: después de una firma mala, ni la buena pasa.
    Así un challenge no sirve para probar firmas a ciegas."""
    private_key = key_registrar.new_private_key()
    key = key_registrar.public_hex(private_key)
    challenge = key_registrar.challenge(auth_headers)

    assert post_key(key_registrar, auth_headers, key, challenge["challenge_id"], "ab" * 64).status_code == 403
    good = key_registrar.sign(private_key, challenge, TEST_USER_EMAIL, key)
    assert post_key(key_registrar, auth_headers, key, challenge["challenge_id"], good).status_code == 403
    assert get_active_keys(TEST_USER_EMAIL) == []


# ── Firma ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "signature",
    ["ab" * 64, "00" * 64, "zz" * 64, "ab" * 10, ""],
    ids=["basura", "ceros", "no-hex", "corta", "vacia"],
)
def test_invalid_signature_is_rejected_and_nothing_is_registered(key_registrar, auth_headers, signature):
    key = key_registrar.public_hex(key_registrar.new_private_key())
    challenge = key_registrar.challenge(auth_headers)

    response = post_key(key_registrar, auth_headers, key, challenge["challenge_id"], signature)

    assert response.status_code == 403
    assert get_active_keys(TEST_USER_EMAIL) == []


def test_signature_made_with_another_private_key_is_rejected(key_registrar, auth_headers):
    key = key_registrar.public_hex(key_registrar.new_private_key())
    other_private = key_registrar.new_private_key()
    challenge = key_registrar.challenge(auth_headers)

    response = post_key(key_registrar, auth_headers, key, challenge["challenge_id"],
                        key_registrar.sign(other_private, challenge, TEST_USER_EMAIL, key))

    assert response.status_code == 403
    assert get_active_keys(TEST_USER_EMAIL) == []


def test_the_signed_public_key_must_be_the_registered_one(key_registrar, auth_headers):
    """La pubkey va dentro del mensaje Y es la que verifica: firmar para la llave A
    (con A) y presentar la llave B no registra ninguna."""
    private_a, private_b = key_registrar.new_private_key(), key_registrar.new_private_key()
    pub_a, pub_b = key_registrar.public_hex(private_a), key_registrar.public_hex(private_b)

    challenge = key_registrar.challenge(auth_headers)
    signed_for_a = key_registrar.sign(private_a, challenge, TEST_USER_EMAIL, pub_a)
    assert post_key(key_registrar, auth_headers, pub_b, challenge["challenge_id"], signed_for_a).status_code == 403

    # Y al revés: un mensaje que nombra a B, firmado con la privada de A.
    challenge = key_registrar.challenge(auth_headers)
    names_b_signed_by_a = key_registrar.sign(private_a, challenge, TEST_USER_EMAIL, pub_b)
    assert post_key(key_registrar, auth_headers, pub_b, challenge["challenge_id"], names_b_signed_by_a).status_code == 403

    assert get_active_keys(TEST_USER_EMAIL) == []


def test_signature_for_another_owner_is_rejected(key_registrar, auth_headers):
    """El owner del mensaje es el del TOKEN: una firma hecha para otro email no vale."""
    private_key = key_registrar.new_private_key()
    key = key_registrar.public_hex(private_key)
    challenge = key_registrar.challenge(auth_headers)

    response = post_key(key_registrar, auth_headers, key, challenge["challenge_id"],
                        key_registrar.sign(private_key, challenge, "someone.else@example.com", key))

    assert response.status_code == 403


def test_a_signature_over_a_different_purpose_is_rejected(key_registrar, auth_headers):
    """Separación de dominio: una firma de OTRO propósito sobre los mismos campos no
    registra llaves (el paso 3 tendrá el suyo, agentbuyer:mandate:v1)."""
    from mandate.canonical import canonicalize

    private_key = key_registrar.new_private_key()
    key = key_registrar.public_hex(private_key)
    challenge = key_registrar.challenge(auth_headers)
    foreign = canonicalize({"purpose": "agentbuyer:mandate:v1", "challenge_id": challenge["challenge_id"],
                            "nonce": challenge["nonce"], "owner": TEST_USER_EMAIL, "public_key": key})

    response = post_key(key_registrar, auth_headers, key, challenge["challenge_id"], private_key.sign(foreign).hex())

    assert response.status_code == 403


# ── SQUATTING CERRADO ───────────────────────────────────────────────────────

def test_squatting_is_closed_without_the_private_key(key_registrar):
    """EL objetivo del sub-paso. La víctima tiene una llave (su privada no sale de su
    navegador) y su pubkey es pública. El atacante tiene SU PROPIA sesión y pasa SU
    PROPIO step-up (challenge legítimo), pero no tiene la privada de la víctima:

    - no puede registrar la pubkey de la víctima con ninguna firma que pueda producir;
    - y como no la registró, la víctima NO queda bloqueada por el 409 de unicidad."""
    victim_private = key_registrar.new_private_key()
    victim_pub = key_registrar.public_hex(victim_private)
    attacker_headers = key_registrar.bearer(ATTACKER)
    attacker_private = key_registrar.new_private_key()

    attempts = {
        "firma al azar": lambda ch: "ab" * 64,
        "firma con SU llave de un mensaje que nombra la pubkey de la víctima":
            lambda ch: key_registrar.sign(attacker_private, ch, ATTACKER, victim_pub),
        "firma de la víctima capturada para otro challenge":
            lambda ch: key_registrar.sign(victim_private, {"challenge_id": "chl_" + "9" * 32, "nonce": "11" * 32},
                                          ATTACKER, victim_pub),
    }
    for label, forge in attempts.items():
        challenge = key_registrar.challenge(attacker_headers)
        response = post_key(key_registrar, attacker_headers, victim_pub, challenge["challenge_id"], forge(challenge))
        assert response.status_code == 403, label

    # Tampoco con una llave PROPIA ya registrada: poseer ALGUNA llave de la cuenta no
    # prueba poseer ESTA. (Si el servidor aceptara cualquier llave del dueño, un
    # atacante con su llave legítima podría registrar pubkeys ajenas.)
    registered, attacker_registered_private, _ = key_registrar.register(ATTACKER, attacker_private)
    assert registered.status_code == 201
    challenge = key_registrar.challenge(attacker_headers)
    signed_with_own_registered_key = key_registrar.sign(attacker_registered_private, challenge, ATTACKER, victim_pub)
    assert post_key(key_registrar, attacker_headers, victim_pub, challenge["challenge_id"],
                    signed_with_own_registered_key).status_code == 403

    assert not is_key_active(ATTACKER, victim_pub)
    # Nadie quedó como dueño de la pubkey de la víctima (ni activa ni revocada).
    assert all(record["public_key"] != victim_pub
               for records in owner_keys.OWNER_KEYS.values() for record in records)

    # La víctima registra SU llave sin problema: el atacante no la bloqueó.
    response, _, _ = key_registrar.register(VICTIM, victim_private)
    assert response.status_code == 201
    assert get_active_keys(VICTIM) == [victim_pub]
    assert victim_pub not in get_active_keys(ATTACKER)


# ── DELETE /keys/{key_id} ───────────────────────────────────────────────────

def test_delete_without_token_is_401(client):
    assert client.delete("/keys/key_x").status_code == 401


def test_owner_revokes_own_key(key_registrar, auth_headers):
    response, _, key = key_registrar.register(TEST_USER_EMAIL)
    key_id = response.json()["key_id"]

    deleted = key_registrar.client.delete(f"/keys/{key_id}", headers=auth_headers)

    assert deleted.status_code == 200
    assert deleted.json()["key_id"] == key_id and deleted.json()["revoked_at"]
    assert get_active_keys(TEST_USER_EMAIL) == []
    assert key_registrar.client.get("/keys", headers=auth_headers).json() == {"keys": []}


def test_cannot_revoke_someone_elses_key(key_registrar, auth_headers):
    response, _, victim_key = key_registrar.register(VICTIM)

    denied = key_registrar.client.delete(f"/keys/{response.json()['key_id']}", headers=auth_headers)

    assert denied.status_code == 403
    assert is_key_active(VICTIM, victim_key)


def test_revoking_a_nonexistent_or_already_revoked_key_is_404(key_registrar, auth_headers):
    assert key_registrar.client.delete("/keys/key_does_not_exist", headers=auth_headers).status_code == 404

    response, _, _ = key_registrar.register(TEST_USER_EMAIL)
    key_id = response.json()["key_id"]
    assert key_registrar.client.delete(f"/keys/{key_id}", headers=auth_headers).status_code == 200
    assert key_registrar.client.delete(f"/keys/{key_id}", headers=auth_headers).status_code == 404


def test_revoking_frees_a_slot_under_the_cap(key_registrar, auth_headers):
    """El caso del spike: quien borra los datos del navegador genera otra llave; sin
    revocar las huérfanas, llegaría al tope y no podría registrar la nueva."""
    orphan_ids = [register_key(TEST_USER_EMAIL, key_registrar.public_hex(key_registrar.new_private_key()))
                  for _ in range(MAX_ACTIVE_KEYS_PER_OWNER)]

    at_cap, private_key, key = key_registrar.register(TEST_USER_EMAIL)
    assert at_cap.status_code == 409  # la prueba valía, pero no hay cupo

    assert key_registrar.client.delete(f"/keys/{orphan_ids[0]}", headers=auth_headers).status_code == 200
    freed, _, _ = key_registrar.register(TEST_USER_EMAIL, private_key)
    assert freed.status_code == 201
    assert key in get_active_keys(TEST_USER_EMAIL)


def test_a_revoked_key_cannot_come_back_even_with_a_valid_proof(key_registrar, auth_headers):
    response, private_key, _ = key_registrar.register(TEST_USER_EMAIL)
    key_registrar.client.delete(f"/keys/{response.json()['key_id']}", headers=auth_headers)

    again, _, _ = key_registrar.register(TEST_USER_EMAIL, private_key)

    assert again.status_code == 409
    assert get_active_keys(TEST_USER_EMAIL) == []
