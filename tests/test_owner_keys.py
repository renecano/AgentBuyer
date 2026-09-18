"""Registro de llaves públicas por dueño (core/owner_keys.py + api/keys.py).

Paso 1 de la firma del humano (registrar exige prueba de posesión desde el 2.4,
ver tests/test_key_registration.py): el registro existe y es consultable, pero
/verify todavía NO lo usa (eso es el paso 3). Los tests de "aditivo" al final lo congelan
a propósito: cuando el paso 3 invierta la verificación, deben cambiar ahí.
"""
import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.security import Principal, owner_email_for
from audit.log import reset_trail
from core import mandate_store, owner_keys
from core.auth_tokens import create_access_token
from core.owner_keys import (
    MAX_ACTIVE_KEYS_PER_OWNER,
    KeyConflict,
    get_active_keys,
    is_key_active,
    normalize_owner_email,
    register_key,
    revoke_key,
)
from mandate.sign import generate_keypair, sign_payload
from tests.conftest import TEST_ADMIN_EMAIL, TEST_USER_EMAIL

OTHER_EMAIL = "someone.else@example.com"


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


def pubkey() -> str:
    return generate_keypair()[1]


def bearer(email: str) -> dict:
    return {"Authorization": f"Bearer {create_access_token(email)}"}


# ── POST /keys: autenticado, el dueño sale del token ────────────────────────
# Desde el sub-paso 2.4 registrar exige PRUEBA DE POSESIÓN: estos tests pasan por el
# flujo real (step-up OTP → challenge → firma) con el helper key_registrar (conftest).

def test_register_key_without_token_is_401(client):
    response = client.post("/keys", json={"public_key": pubkey(), "challenge_id": "chl_x", "signature": "00" * 64})

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert owner_keys.OWNER_KEYS == {}


def test_register_key_with_token_records_it_under_the_token_email(key_registrar):
    response, _, key = key_registrar.register(TEST_USER_EMAIL)

    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"key_id", "public_key", "alg", "created_at"}
    assert body["key_id"].startswith("key_") and body["public_key"] == key and body["alg"] == "ed25519"
    assert get_active_keys(TEST_USER_EMAIL) == [key]


def test_body_cannot_choose_the_owner(key_registrar):
    """Mismo principio que los mandatos: la identidad sale del token, no del cuerpo."""
    response, _, key = key_registrar.register(
        TEST_USER_EMAIL, extra={"owner_email": "attacker@example.com", "owner": "attacker@example.com"},
    )

    assert response.status_code == 201
    assert get_active_keys(TEST_USER_EMAIL) == [key]
    assert get_active_keys("attacker@example.com") == []


@pytest.mark.parametrize(
    "bad_key",
    ["", "ab" * 10, "zz" * 32, "ab" * 33, "ab" * 31 + "g1", 12345, None],
    ids=["empty", "short", "64-non-hex", "too-long", "one-non-hex-char", "number", "null"],
)
def test_malformed_public_key_is_rejected(key_registrar, auth_headers, bad_key):
    """Con un challenge VÁLIDO y el resto del cuerpo completo: el 422 lo causa la
    pubkey, no la falta de campos. Y un formato roto no gasta el challenge."""
    challenge = key_registrar.challenge(auth_headers)
    response = key_registrar.client.post(
        "/keys", json={"public_key": bad_key, "challenge_id": challenge["challenge_id"], "signature": "00" * 64},
        headers=auth_headers,
    )

    assert response.status_code == 422
    assert get_active_keys(TEST_USER_EMAIL) == []
    key_registrar.challenge_service.consume(challenge["challenge_id"], TEST_USER_EMAIL)  # sigue sin usar


def test_missing_public_key_field_is_422(client, auth_headers):
    body = {"challenge_id": "chl_x", "signature": "00" * 64}
    assert client.post("/keys", json=body, headers=auth_headers).status_code == 422


def test_admin_is_a_person_and_can_register_keys(key_registrar, admin_headers):
    response, _, key = key_registrar.register(TEST_ADMIN_EMAIL, headers=admin_headers)
    assert response.status_code == 201
    assert get_active_keys(TEST_ADMIN_EMAIL) == [key]


def test_service_key_cannot_register_keys(client, service_headers):
    """Una máquina no es dueña de llaves de humano: sin JWT de persona → 401."""
    body = {"public_key": pubkey(), "challenge_id": "chl_x", "signature": "00" * 64}
    response = client.post("/keys", json=body, headers=service_headers)
    assert response.status_code == 401
    assert owner_keys.OWNER_KEYS == {}


def test_same_key_twice_for_the_same_owner_is_idempotent(key_registrar):
    first, private_key, key = key_registrar.register(TEST_USER_EMAIL)
    second, _, _ = key_registrar.register(TEST_USER_EMAIL, private_key, public_key_hex=key.upper())

    assert first.status_code == second.status_code == 201
    assert first.json()["key_id"] == second.json()["key_id"]
    assert get_active_keys(TEST_USER_EMAIL) == [key]  # hex canónico en minúsculas


def test_a_key_already_registered_by_another_account_is_409(key_registrar):
    """Aun CON prueba de posesión válida (esta cuenta tiene la privada), una pubkey
    pertenece a una sola cuenta."""
    first, private_key, key = key_registrar.register(OTHER_EMAIL)
    assert first.status_code == 201

    response, _, _ = key_registrar.register(TEST_USER_EMAIL, private_key)
    assert response.status_code == 409
    assert get_active_keys(TEST_USER_EMAIL) == []


def test_token_email_is_normalized_like_mandate_owners(key_registrar):
    """La llave debe atar con MANDATE_OWNERS y con owner_email_for: misma normalización."""
    messy = "  Mixed.Case@Example.COM  "
    response, _, key = key_registrar.register(messy)
    assert response.status_code == 201

    assert "mixed.case@example.com" in owner_keys.OWNER_KEYS
    assert normalize_owner_email(messy) == owner_email_for(Principal(subject=messy, role="user"))
    assert is_key_active(messy, key)


# ── GET /keys ───────────────────────────────────────────────────────────────

def test_list_keys_without_token_is_401(client):
    assert client.get("/keys").status_code == 401


def test_list_keys_shows_only_my_active_keys_and_nothing_private(client, auth_headers):
    mine_kept, mine_revoked = pubkey(), pubkey()
    register_key(TEST_USER_EMAIL, mine_kept)
    revoke_key(TEST_USER_EMAIL, register_key(TEST_USER_EMAIL, mine_revoked))
    register_key(OTHER_EMAIL, pubkey())

    response = client.get("/keys", headers=auth_headers)

    assert response.status_code == 200
    keys = response.json()["keys"]
    assert [key["public_key"] for key in keys] == [mine_kept]
    assert set(keys[0]) == {"key_id", "public_key", "alg", "created_at"}  # sin revoked_at ni owner


def test_list_keys_is_empty_for_an_account_without_keys(client, auth_headers):
    assert client.get("/keys", headers=auth_headers).json() == {"keys": []}


# ── Helpers del registro ────────────────────────────────────────────────────

def test_several_keys_per_owner_coexist_in_registration_order():
    first, second = pubkey(), pubkey()
    first_id = register_key(TEST_USER_EMAIL, first)
    second_id = register_key(TEST_USER_EMAIL, second)

    assert first_id != second_id
    assert get_active_keys(TEST_USER_EMAIL) == [first, second]
    assert is_key_active(TEST_USER_EMAIL, first) and is_key_active(TEST_USER_EMAIL, second)


def test_revoke_sets_revoked_at_and_excludes_the_key():
    kept, revoked = pubkey(), pubkey()
    register_key(TEST_USER_EMAIL, kept)
    revoked_id = register_key(TEST_USER_EMAIL, revoked)

    assert revoke_key(TEST_USER_EMAIL, revoked_id) is True

    record = next(r for r in owner_keys.OWNER_KEYS[TEST_USER_EMAIL] if r["key_id"] == revoked_id)
    assert record["revoked_at"] is not None  # el registro se conserva, marcado
    assert get_active_keys(TEST_USER_EMAIL) == [kept]
    assert is_key_active(TEST_USER_EMAIL, revoked) is False
    assert revoke_key(TEST_USER_EMAIL, revoked_id) is False  # ya estaba revocada


def test_a_revoked_key_cannot_be_registered_again():
    """Una llave se revoca, p. ej., por compromiso: no se reactiva por la puerta de atrás."""
    key = pubkey()
    revoke_key(TEST_USER_EMAIL, register_key(TEST_USER_EMAIL, key))

    with pytest.raises(KeyConflict):
        register_key(TEST_USER_EMAIL, key)


def test_an_owner_cannot_revoke_someone_elses_key():
    victim_key = pubkey()
    victim_id = register_key(OTHER_EMAIL, victim_key)

    assert revoke_key(TEST_USER_EMAIL, victim_id) is False
    assert is_key_active(OTHER_EMAIL, victim_key) is True


def test_get_active_keys_of_an_email_without_keys_is_empty():
    assert get_active_keys("nobody@example.com") == []


@pytest.mark.parametrize("bad", [None, "", "zz" * 32, 42], ids=["none", "empty", "non-hex", "int"])
def test_is_key_active_fails_closed_on_malformed_input(bad):
    register_key(TEST_USER_EMAIL, pubkey())
    assert is_key_active(TEST_USER_EMAIL, bad) is False


def test_empty_owner_email_is_an_error_not_an_owner():
    with pytest.raises(ValueError):
        register_key("   ", pubkey())


def test_active_keys_per_owner_are_capped():
    for _ in range(MAX_ACTIVE_KEYS_PER_OWNER):
        register_key(TEST_USER_EMAIL, pubkey())
    with pytest.raises(KeyConflict):
        register_key(TEST_USER_EMAIL, pubkey())

    # Revocar libera cupo.
    revoke_key(TEST_USER_EMAIL, owner_keys.OWNER_KEYS[TEST_USER_EMAIL][0]["key_id"])
    register_key(TEST_USER_EMAIL, pubkey())


# ── Decisión del seed y carácter ADITIVO (el paso 3 cambiará esto) ──────────

def test_seed_sealing_key_is_not_registered_as_a_human_key(client, active_seed, seed_owner_headers):
    """El seed es "sistema/legado": lo sella el servidor con una llave efímera que
    nadie conserva. Registrarla como llave del humano afirmaría algo falso."""
    seed_owner = active_seed["human"]["email"]

    assert get_active_keys(seed_owner) == []
    sealed = client.get("/mandates/mnd_marta_001", headers=seed_owner_headers).json()["mandate"]
    assert is_key_active(seed_owner, sealed["human_pubkey"]) is False


def test_verify_does_not_consult_the_registry_yet(client, auth_headers):
    """ADITIVO: una firma de cliente con una llave NO registrada sigue aprobando en
    /verify, y registrar llaves no cambia ningún veredicto. El paso 3 invierte esto."""
    priv, pub = generate_keypair()
    constraints = {
        "max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
        "allowed_merchants": ["mch_vuelaya"], "max_uses": 3,
        "conditions": [{"type": "price_below", "value": 150}],
    }
    mandate = {
        "mandate_id": "mnd_unregistered_key", "human": {"id": "hum_k", "display_name": "K"},
        "agent": {"id": "agt_saturday"}, "constraints": constraints,
        "human_pubkey": pub, "signature": sign_payload(priv, constraints),
    }
    assert client.post("/mandates", json=mandate, headers=auth_headers).status_code == 201
    assert get_active_keys(TEST_USER_EMAIL) == []

    verdict = client.post("/verify", json={
        "attempt_id": "att_k", "mandate_id": "mnd_unregistered_key", "presented_by_agent": "agt_saturday",
        "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount": 100.0,
                     "currency": "USD", "metadata": {"price": 100.0}},
    }, headers=auth_headers).json()["verdict"]
    assert verdict == "APPROVE"
