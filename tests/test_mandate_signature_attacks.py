"""Sondeo de regresión PERMANENTE (3.5): ataques a la firma humana del mandato.

Cada caso intenta que exista, o que autorice una compra, un mandato que su titular
no firmó con su llave registrada y activa. Todos deben fallar: al crear (403/409/422)
o en /verify (REJECT). Todo por HTTP, con tokens reales, llaves registradas por el
flujo real de prueba de posesión y la verificación de producción.

Víctima: Marta. Atacante: Mallory, con cuenta y llave propias (lo peor realista: un
usuario legítimo del sistema intentando actuar por otro).
"""
import copy

import pytest
from fastapi.testclient import TestClient

from api.main import app
from audit.log import reset_trail
from core import mandate_store, owner_keys
from core.key_challenges import registration_message
from core.mandate_store import MANDATES
from mandate.sign import generate_keypair, sign_payload
from tests.conftest import KeyRegistrar, MandateSigner, verify_as_service

# 4.2 (P-03): /verify es la verificación del comercio/agente: credencial `service`.
pytestmark = pytest.mark.usefixtures("service_key")

MARTA = "marta.victim@example.com"
MALLORY = "mallory.attacker@example.com"


@pytest.fixture()
def client():
    mandate_store.mandate_store.clear()
    owner_keys.clear()
    reset_trail()
    with TestClient(app) as test_client:
        yield test_client
    mandate_store.mandate_store.clear()
    owner_keys.clear()
    reset_trail()


@pytest.fixture()
def marta(client, key_registrar) -> MandateSigner:
    signer = MandateSigner(client, key_registrar, MARTA)
    signer.register()
    return signer


@pytest.fixture()
def mallory(client, key_registrar) -> MandateSigner:
    signer = MandateSigner(client, key_registrar, MALLORY)
    signer.register()
    return signer


def purchase(mandate_id: str, attempt_id: str = "att_attack") -> dict:
    return {
        "attempt_id": attempt_id, "mandate_id": mandate_id, "presented_by_agent": "agt_saturday",
        "purchase": {"merchant_id": "mch_vuelaya", "category": "travel.flights", "amount": 100.0,
                     "currency": "USD", "metadata": {"price": 100.0}},
    }


def verdict(client, mandate_id: str, attempt_id: str = "att_attack") -> str:
    return verify_as_service(client, purchase(mandate_id, attempt_id)).json()["verdict"]


def assert_not_created(response, mandate_id: str, status: int):
    assert response.status_code == status, response.text
    assert mandate_id not in MANDATES


# ── Sin firma del titular ───────────────────────────────────────────────────

def test_sin_firma(client, marta):
    body = marta.body()
    for field in ("signature", "key_id", "nonce", "created_at"):
        partial = {key: value for key, value in body.items() if key != field}
        assert_not_created(marta.post(partial), body["mandate_id"], 422)


def test_sello_del_servidor_para_un_usuario(client, marta):
    """El payload sin firma de antes del 3.4: el servidor ya no sella por el usuario."""
    body = marta.body()
    legacy = {key: body[key] for key in ("mandate_id", "human", "agent", "constraints", "search_fields")}
    assert_not_created(marta.post(legacy), body["mandate_id"], 422)


def test_firma_propia_con_llave_no_registrada(client, marta):
    priv, pub = generate_keypair()
    body = marta.body()
    legacy = {key: body[key] for key in ("mandate_id", "human", "agent", "constraints")}
    legacy.update(human_pubkey=pub, signature=sign_payload(priv, legacy["constraints"]))
    assert_not_created(marta.post(legacy), body["mandate_id"], 422)


@pytest.mark.parametrize("garbage", ["00" * 64, "ab" * 64, "x", "", "zz" * 64])
def test_firma_basura(client, marta, garbage):
    body = marta.body()
    body["signature"] = garbage
    assert_not_created(marta.post(body), body["mandate_id"], 403)


# ── Firmas y llaves de otra persona ─────────────────────────────────────────

def test_firma_de_otro_dueno(client, marta, mallory):
    """Mallory firma un mandato con SU llave y Marta lo presenta: la llave no es de Marta."""
    body = mallory.body()
    assert_not_created(marta.post(body), body["mandate_id"], 403)


def test_mandato_firmado_por_marta_presentado_con_el_token_de_mallory(client, marta, mallory):
    """Replay a otra cuenta: el owner sale del token, y la llave no es de Mallory."""
    body = marta.body()
    assert_not_created(mallory.post(body), body["mandate_id"], 403)


def test_llave_de_otro_dueno_con_key_id_propio(client, marta, mallory):
    """Mallory firma con SU privada pero declara el key_id de Marta: no verifica."""
    forged = MandateSigner(marta.client, marta.registrar, MARTA, private_key=mallory.private_key)
    forged.key_id = marta.key_id
    body = forged.body()
    assert_not_created(marta.post(body), body["mandate_id"], 403)


def test_public_key_de_mallory_en_el_cuerpo(client, marta, mallory):
    body = marta.body()
    body["public_key"] = mallory.public_key
    assert_not_created(marta.post(body), body["mandate_id"], 403)


# ── Revocación ──────────────────────────────────────────────────────────────

def test_llave_revocada_antes_de_crear(client, marta):
    assert marta.client.delete(f"/keys/{marta.key_id}", headers=marta.headers).status_code == 200
    body = marta.body()
    assert_not_created(marta.post(body), body["mandate_id"], 403)


def test_llave_revocada_despues_de_crear(client, marta):
    body = marta.create()
    assert verdict(client, body["mandate_id"], "att_before") == "APPROVE"
    assert marta.client.delete(f"/keys/{marta.key_id}", headers=marta.headers).status_code == 200
    assert verdict(client, body["mandate_id"], "att_after") == "REJECT"


# ── Separación de dominio y replay ──────────────────────────────────────────

def test_firma_de_register_key_presentada_como_mandato(client, marta):
    """Una firma auténtica de Marta, pero sobre el mensaje de REGISTRO de llave."""
    body = marta.body()
    registration = registration_message(f"chl_{body['nonce']}", body["nonce"], MARTA, marta.public_key)
    body["signature"] = marta.private_key.sign(registration).hex()
    assert_not_created(marta.post(body), body["mandate_id"], 403)


def test_replay_de_una_creacion(client, marta):
    body = marta.create()
    assert marta.post(body).status_code == 409  # el mismo cuerpo otra vez
    renamed = marta.body(nonce=body["nonce"])  # mismo nonce en otro mandato
    assert_not_created(marta.post(renamed), renamed["mandate_id"], 409)


# ── Lo guardado después de firmar ───────────────────────────────────────────

@pytest.mark.parametrize("path, value", [
    ("constraints.max_amount_per_purchase", 99999),
    ("constraints.allowed_merchants", ["mch_mallory"]),
    ("constraints.off_session_consent", True),
    ("search_fields.destination", "MIA"),
    ("expires_at", "2099-01-01T00:00:00Z"),
    ("agent.id", "agt_mallory"),
])
def test_campo_alterado_despues_de_firmar(client, marta, path, value):
    body = marta.create(constraints__off_session_consent=False)
    target = MANDATES[body["mandate_id"]]["mandate"]
    *parents, leaf = path.split(".")
    for parent in parents:
        target = target[parent]
    target[leaf] = value
    assert verdict(client, body["mandate_id"]) == "REJECT"


def test_campo_alterado_antes_de_enviar(client, marta):
    body = marta.body()
    body["constraints"]["max_amount_per_purchase"] = "99999"
    assert_not_created(marta.post(body), body["mandate_id"], 403)


# ── payment_token ───────────────────────────────────────────────────────────

def test_payment_token_de_otro_mandato(client, marta):
    victim = marta.create()
    other = marta.create()
    MANDATES[victim["mandate_id"]]["mandate"]["payment_token"] = copy.deepcopy(
        MANDATES[other["mandate_id"]]["mandate"]["payment_token"])
    assert verdict(client, victim["mandate_id"]) == "REJECT"


def test_payment_token_enviado_por_el_cliente(client, marta):
    body = marta.body()
    body["payment_token"] = {"token_id": "vtok_cliente", "bound_mandate_id": body["mandate_id"]}
    assert_not_created(marta.post(body), body["mandate_id"], 422)


def test_las_rutas_que_firmaban_por_el_usuario_no_existen(client, marta):
    assert client.post("/mandates/create", json={"human_id": "hum_x", "max_amount_per_tx": 150},
                       headers=marta.headers).status_code in (404, 405)


def test_el_camino_legitimo_sigue_funcionando(client, marta):
    """Contraprueba: todo lo anterior falla por la razón correcta, no porque nada funcione."""
    body = marta.create()
    assert verdict(client, body["mandate_id"]) == "APPROVE"
