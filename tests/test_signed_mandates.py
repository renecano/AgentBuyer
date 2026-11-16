"""Mandatos firmados por el HUMANO (paso 3.3): alta verificada, /verify y agente atado.

Todo por HTTP con tokens reales. La llave se registra por el flujo REAL de prueba de
posesión (key_registrar, conftest) y el mandato se firma como lo hará el navegador
en el 3.4 (SignedMandateClient): mensaje del 3.2 (mandate/mandate_message.py) con la
llave registrada. Los relojes del alta y de la expiración se fijan (sin esperas).

Además, cada vector de shared/mandate_signing_vectors.json se envía TAL CUAL (mismos
bytes, misma firma del RFC 8032): el servidor acepta exactamente lo que el frontend
ya reproduce byte a byte (mandateMessage.test.ts).
"""
import copy
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

import core.agent_loop as agent_loop
import core.mandate_store as store_module
import core.signed_mandates as signed_module
from api.main import app
from audit.log import reset_trail
from core import mandate_store, owner_keys
from core.auth_tokens import create_access_token
from core.mandate_store import MANDATE_OWNERS, MANDATES, get_mandate_signer
from core.verify import verify_purchase as strict_verify_purchase
from mandate.mandate_message import mandate_signing_message
from shared.schemas import PurchaseAttempt
from tests.conftest import TEST_USER_EMAIL, KeyRegistrar, MandateSigner, verify_as_service

# 4.2 (P-03): /verify es la verificación del comercio/agente: credencial `service`.
pytestmark = pytest.mark.usefixtures("service_key")

VECTORS = json.loads((Path(__file__).resolve().parent.parent / "shared" / "mandate_signing_vectors.json").read_text(encoding="utf-8"))
RFC = VECTORS["rfc8032_test1"]
RFC_PRIVATE = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(RFC["secret_key_hex"]))
BASE_INPUTS = VECTORS["vectors"][0]["inputs"]
OTHER_OWNER = "otra.persona@example.com"
NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


def stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def bearer(email: str) -> dict:
    return {"Authorization": f"Bearer {create_access_token(email)}"}


class Clock:
    def __init__(self, now: datetime):
        self.now = now

    def advance(self, **delta) -> None:
        self.now += timedelta(**delta)


@pytest.fixture()
def clock(monkeypatch) -> Clock:
    """Reloj del alta firmada (ventana de created_at) y de la expiración del almacén."""
    fixed = Clock(NOW)
    monkeypatch.setattr(signed_module, "_utcnow", lambda: fixed.now)
    monkeypatch.setattr(store_module, "_utcnow", lambda: fixed.now)
    return fixed


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


class SignedMandateClient(MandateSigner):
    """El helper de conftest con la base del vector caso_base del 3.2 y el reloj fijo."""

    def __init__(self, client, registrar: KeyRegistrar, clock: Clock, email: str = TEST_USER_EMAIL, private_key=None):
        super().__init__(client, registrar, email, private_key=private_key, now=lambda: clock.now,
                         base_inputs=BASE_INPUTS,
                         human={"id": "hum_marta", "display_name": "Marta", "email": email, "phone": "+00 000 000 0000"})
        self.clock = clock

    def body(self, **changes) -> dict:
        # La vigencia del vector (2026-11-30) salvo que el test la cambie.
        return super().body(**{"expires_at": BASE_INPUTS["expires_at"], **changes})


@pytest.fixture()
def signer(client, key_registrar, clock) -> SignedMandateClient:
    """Usuario de la suite con una llave ya registrada (flujo real)."""
    signed = SignedMandateClient(client, key_registrar, clock)
    signed.register()
    return signed


def attempt(mandate_id: str, attempt_id: str = "att_1", **purchase) -> dict:
    return {
        "attempt_id": attempt_id,
        "mandate_id": mandate_id,
        "presented_by_agent": "agt_saturday",
        "purchase": {
            "merchant_id": "mch_vuelaya", "category": "travel.flights", "amount": 100.0, "currency": "USD",
            "metadata": {"price": 100.0}, **purchase,
        },
    }


def verify(client, mandate_id: str, **purchase) -> dict:
    return verify_as_service(client, attempt(mandate_id, **purchase)).json()


def check(result: dict, rule: str) -> dict:
    return next(item for item in result["checks"] if item["rule"] == rule)


# ── Vectores del 3.2, tal cual ──────────────────────────────────────────────

@pytest.mark.parametrize("name", [vector["name"] for vector in VECTORS["vectors"]])
def test_el_servidor_acepta_cada_vector_del_3_2_byte_a_byte(name, client, key_registrar, clock, monkeypatch):
    vector = next(item for item in VECTORS["vectors"] if item["name"] == name)
    inputs = vector["inputs"]
    owner = inputs["owner_email"].strip().lower()
    created = datetime.strptime(inputs["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    clock.now = created + timedelta(seconds=30)
    # La llave del RFC registrada por el flujo real, con el key_id del vector.
    vector_signer = SignedMandateClient(client, key_registrar, clock, email=owner, private_key=RFC_PRIVATE)
    vector_signer.register(monkeypatch, key_id_hex=inputs["key_id"].removeprefix("key_"))
    assert vector_signer.key_id == inputs["key_id"]

    body = {
        "mandate_id": inputs["mandate_id"], "agent": {"id": inputs["agent_id"]},
        "constraints": inputs["constraints"], "expires_at": inputs["expires_at"],
        "created_at": inputs["created_at"], "nonce": inputs["nonce"], "key_id": inputs["key_id"],
        "public_key": inputs["public_key"], "signature": vector["expected_signature_hex"],
        **({"search_fields": inputs["search_fields"]} if "search_fields" in inputs else {}),
    }
    response = client.post("/mandates", content=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                           headers={**bearer(inputs["owner_email"]), "Content-Type": "application/json"})

    assert response.status_code == 201, response.text
    signer_record = get_mandate_signer(inputs["mandate_id"])
    assert signer_record["kind"] == "human"
    assert signer_record["message_hash"] == hashlib.sha256(vector["expected_message"].encode("utf-8")).hexdigest()
    # Lo guardado es lo FIRMADO (normalizado), no el cuerpo crudo.
    signed = json.loads(vector["expected_message"])
    stored = response.json()["mandate"]
    assert stored["constraints"]["allowed_merchants"] == signed["constraints"]["allowed_merchants"]
    assert stored["search_fields"] == signed["search_fields"]


# ── Alta ────────────────────────────────────────────────────────────────────

def test_firma_valida_crea_kind_human_y_aprueba(signer, client):
    body = signer.create()
    mandate_id = body["mandate_id"]

    record = get_mandate_signer(mandate_id)
    assert record["kind"] == "human"
    assert record["key_id"] == signer.key_id and record["public_key"] == signer.public_key
    assert record["signed_at"] == body["created_at"]

    result = verify(client, mandate_id)
    assert result["verdict"] == "APPROVE"
    assert check(result, "signature") == {
        "rule": "signature", "pass": True, "detail": "Firma humana Ed25519 válida (llave registrada del titular).",
    }
    assert check(result, "payment_token_binding")["pass"] is True
    assert check(result, "off_session_consent")["pass"] is True


def test_el_registro_del_firmante_no_se_filtra(signer, client):
    """MANDATE_SIGNERS es interno: ni sus campos ni la public_key (que solo vive ahí)
    aparecen en las respuestas. El hash SÍ aparece, a propósito, como binding del
    payment_token (bound_message_hash): es lo que ata el token a lo firmado."""
    body = signer.body()
    created = json.dumps(signer.post(body).json())
    fetched = json.dumps(client.get(f"/mandates/{body['mandate_id']}", headers=signer.headers).json())
    for response in (created, fetched):
        assert signer.public_key not in response
        for field in ('"kind"', '"signed_at"', '"message_hash"'):
            assert field not in response


def test_el_payment_token_lo_emite_el_servidor_atado_a_los_bytes_firmados(signer):
    body = signer.body()
    body["payment_token"] = {"token_id": "vtok_del_cliente"}
    assert signer.post(body).status_code == 422  # el cliente no aporta el token

    body = signer.create()
    token = MANDATES[body["mandate_id"]]["mandate"]["payment_token"]
    assert token["bound_mandate_id"] == body["mandate_id"]
    assert token["bound_message_hash"] == get_mandate_signer(body["mandate_id"])["message_hash"]


def test_el_owner_sale_del_token_no_del_cuerpo(signer, client):
    # Firmado para el usuario de la suite pero enviado con el token de OTRA cuenta:
    # su llave no es de esa cuenta → 403, y nada se crea.
    body = signer.body()
    response = signer.post(body, headers=bearer(OTHER_OWNER))
    assert response.status_code == 403
    assert body["mandate_id"] not in MANDATES


def test_key_id_de_otro_dueno_inexistente_o_revocado_dan_el_mismo_403(signer, client, key_registrar, clock):
    other = SignedMandateClient(client, key_registrar, clock, email=OTHER_OWNER)
    other.register()

    foreign = signer.body()
    foreign["key_id"] = other.key_id
    missing = signer.body()
    missing["key_id"] = "key_" + "0" * 32
    responses = [signer.post(foreign), signer.post(missing)]

    revoked_body = signer.body()
    assert client.delete(f"/keys/{signer.key_id}", headers=signer.headers).status_code == 200
    responses.append(signer.post(revoked_body))

    assert [response.status_code for response in responses] == [403, 403, 403]
    assert len({response.json()["detail"] for response in responses}) == 1  # no revela cuál


def test_firma_de_otra_llave_del_mismo_dueno_con_este_key_id_da_403(signer, client, key_registrar, clock):
    second = SignedMandateClient(client, key_registrar, clock, email=signer.email)
    second.register()
    body = second.body()
    body["key_id"] = signer.key_id  # firmó la segunda llave, pero dice ser la primera
    response = signer.post(body)
    assert response.status_code == 403
    assert body["mandate_id"] not in MANDATES


def test_public_key_distinta_en_el_cuerpo_da_403(signer, key_registrar):
    body = signer.body()
    body["public_key"] = key_registrar.public_hex(key_registrar.new_private_key())
    assert signer.post(body).status_code == 403

    body = signer.body()
    body["public_key"] = signer.public_key.upper()  # la misma, en otra grafía: vale
    assert signer.post(body).status_code == 201


def test_firma_alterada_o_campo_cambiado_antes_de_enviar_da_403(signer):
    body = signer.body()
    body["constraints"]["max_amount_per_purchase"] = 9999
    assert signer.post(body).status_code == 403

    body = signer.body()
    body["signature"] = "00" * 64
    assert signer.post(body).status_code == 403


@pytest.mark.parametrize("change, expected", [
    ({"key_id": None}, 422),
    ({"valid_until": "2026-12-01"}, 422),
    ({"scope": {"max_amount_per_tx": 1}}, 422),
    ({"human_pubkey": "ab" * 32}, 422),
    ({"agent": {"id": "agt_saturday", "extra": 1}}, 422),
    ({"signature": 123}, 422),
])
def test_cuerpo_malformado_da_422(signer, change, expected):
    body = signer.body()
    for key, value in change.items():
        if value is None:
            del body[key]
        else:
            body[key] = value
    response = signer.post(body)
    assert response.status_code == expected, response.text
    assert body["mandate_id"] not in MANDATES


@pytest.mark.parametrize("name", [
    entry["name"] for entry in VECTORS["invalid"] if entry["error_field"] not in ("owner", "public_key")
])
def test_los_invalidos_del_3_2_dan_422(name, signer):
    entry = next(item for item in VECTORS["invalid"] if item["name"] == name)
    inputs = entry["inputs"]
    body = {
        "mandate_id": inputs["mandate_id"], "agent": {"id": inputs["agent_id"]},
        "constraints": inputs["constraints"], "search_fields": inputs["search_fields"],
        "expires_at": inputs["expires_at"], "created_at": inputs["created_at"],
        "nonce": inputs["nonce"], "key_id": signer.key_id, "signature": "00" * 64,
    }
    response = signer.client.post("/mandates", content=json.dumps(body).encode("utf-8"),
                                  headers={**signer.headers, "Content-Type": "application/json"})
    assert response.status_code == 422, (name, response.text)
    assert response.json()["detail"].startswith(entry["error_field"])


def test_montos_se_leen_como_decimal_no_como_float(signer):
    # 0.1 + 0.2 escrito en JSON: como float sería 0.30000000000000004 → la spec lo
    # rechaza en ambos casos; "150.10" como Decimal se acepta exacto (15010 centavos).
    body = signer.body(constraints__max_amount_per_purchase=150.10)
    raw = json.dumps(body).replace('"max_amount_per_purchase": 150.1', '"max_amount_per_purchase": 150.10')
    response = signer.client.post("/mandates", content=raw.encode("utf-8"),
                                  headers={**signer.headers, "Content-Type": "application/json"})
    assert response.status_code == 201, response.text
    assert response.json()["mandate"]["constraints"]["max_amount_per_purchase"] == 150.1


# ── Ventana de created_at y anti-replay ─────────────────────────────────────

@pytest.mark.parametrize("offset, expected", [
    (timedelta(minutes=-11), 422),   # firmado hace más de 10 min
    (timedelta(minutes=3), 422),     # más de 2 min en el futuro
    (timedelta(minutes=1), 201),     # reloj del cliente algo adelantado: se tolera
    (timedelta(minutes=-9), 201),
])
def test_ventana_de_created_at(signer, clock, offset, expected):
    signed_at = clock.now + offset
    body = signer.body(created_at=stamp(signed_at))
    assert signer.post(body).status_code == expected


def test_nonce_repetido_da_409_por_dueno(signer, client, key_registrar, clock):
    first = signer.create()
    replay = signer.body(nonce=first["nonce"])
    response = signer.post(replay)
    assert response.status_code == 409
    assert replay["mandate_id"] not in MANDATES

    # Otro dueño puede usar el mismo nonce: el anti-replay es por dueño.
    other = SignedMandateClient(client, key_registrar, clock, email=OTHER_OWNER)
    other.register()
    assert other.post(other.body(nonce=first["nonce"])).status_code == 201


def test_el_mismo_cuerpo_reenviado_no_crea_otro_mandato(signer):
    body = signer.create()
    assert signer.post(body).status_code == 409


def test_los_nonces_viejos_se_olvidan_pero_su_mandato_seria_rechazado_por_viejo(signer, clock):
    first = signer.create()
    clock.advance(minutes=13)
    # El nonce ya se olvidó (memoria acotada), pero reusar el created_at viejo no
    # sirve: la ventana lo rechaza antes.
    replay = signer.body(nonce=first["nonce"], created_at=first["created_at"])
    assert signer.post(replay).status_code == 422


# ── Sin firma del titular no hay mandato (3.5) ─────────────────────────────

def unsigned_payload(mandate_id: str) -> dict:
    return {
        "mandate_id": mandate_id,
        "human": {"id": "hum_marta", "display_name": "Marta"},
        "agent": {"id": "agt_saturday", "display_name": "Saturday"},
        "constraints": {
            "max_amount_per_purchase": 150, "currency": "USD", "allowed_categories": ["travel.flights"],
            "allowed_merchants": ["mch_vuelaya"], "max_uses": 3,
            "conditions": [{"type": "price_below", "value": 140}], "off_session_consent": True,
        },
        "valid_until": "2026-11-30",
    }


def test_sin_firma_del_titular_el_mandato_no_se_crea(client, auth_headers):
    """3.5 (cambio deliberado): el payload de antes del 3.4 ya no se sella: 422."""
    response = client.post("/mandates", json=unsigned_payload("mnd_unsigned"), headers=auth_headers)
    assert response.status_code == 422
    assert "cardholder signature is required" in response.json()["detail"]
    assert "mnd_unsigned" not in MANDATES and get_mandate_signer("mnd_unsigned") is None


def test_firma_propia_del_cliente_ya_no_crea_el_mandato(client, auth_headers):
    """3.5: una firma Ed25519 real con una llave propia NO registrada (el antiguo
    legacy_client) no prueba quién firmó: 422, ni se crea."""
    from mandate.sign import generate_keypair, sign_payload
    priv, pub = generate_keypair()
    payload = unsigned_payload("mnd_legacy")
    payload.update(human_pubkey=pub, signature=sign_payload(priv, payload["constraints"]))
    assert client.post("/mandates", json=payload, headers=auth_headers).status_code == 422
    assert "mnd_legacy" not in MANDATES


def test_el_seed_es_el_unico_sello_y_su_token_lo_emite_el_servidor(client, active_seed):
    """El sello de sistema solo existe para el seed cargado al arrancar (D-12), y su
    payment_token ya no es el del archivo: lo emite el servidor atado a lo sellado."""
    with TestClient(app):
        signer = get_mandate_signer(active_seed["mandate_id"])
        token = MANDATES[active_seed["mandate_id"]]["mandate"]["payment_token"]
    assert signer["kind"] == "system_seal"
    assert token["bound_message_hash"] == signer["message_hash"]
    assert token["token_id"] != active_seed["payment_token"]["token_id"]


# ── /verify sobre lo guardado ───────────────────────────────────────────────

TAMPERS = {
    "max_amount": lambda m: m["constraints"].__setitem__("max_amount_per_purchase", 9999),
    "price_below": lambda m: m["constraints"]["conditions"][0].__setitem__("value", 9999),
    "merchants": lambda m: m["constraints"]["allowed_merchants"].append("mch_otro"),
    "categories": lambda m: m["constraints"]["allowed_categories"].append("travel.hotels"),
    "max_uses": lambda m: m["constraints"].__setitem__("max_uses", 99),
    "currency": lambda m: m["constraints"].__setitem__("currency", "EUR"),
    "consent": lambda m: m["constraints"].__setitem__("off_session_consent", False),
    "search_fields": lambda m: m["search_fields"].__setitem__("destination", "BOG"),
    "expires_at": lambda m: m.__setitem__("expires_at", "2030-01-01T00:00:00Z"),
    "created_at": lambda m: m.__setitem__("created_at", "2026-11-20T11:59:00Z"),
    "nonce": lambda m: m.__setitem__("nonce", "f" * 32),
    "agent": lambda m: m["agent"].__setitem__("id", "agt_mallory"),
    "key_id": lambda m: m.__setitem__("key_id", "key_" + "1" * 32),
    "signature": lambda m: m.__setitem__("signature", "00" * 64),
    "extra_constraint": lambda m: m["constraints"].__setitem__("monthly_budget", 99999),
}


@pytest.mark.parametrize("field", sorted(TAMPERS))
def test_campo_alterado_tras_firmar_da_reject(signer, client, field):
    body = signer.create()
    TAMPERS[field](MANDATES[body["mandate_id"]]["mandate"])

    result = verify(client, body["mandate_id"])
    assert result["verdict"] == "REJECT"
    assert check(result, "signature")["pass"] is False


def test_cambiar_el_dueno_tras_firmar_da_reject(signer, client):
    body = signer.create()
    MANDATE_OWNERS[body["mandate_id"]] = OTHER_OWNER
    assert verify(client, body["mandate_id"])["verdict"] == "REJECT"


def test_si_la_llave_deja_de_pertenecer_al_dueno_da_reject(signer, client):
    body = signer.create()
    owner_keys.clear()  # el registro ya no tiene esa llave para ese dueño
    result = verify(client, body["mandate_id"])
    assert result["verdict"] == "REJECT"
    assert check(result, "signature")["detail"] == "Firma humana inválida: la llave ya no pertenece al titular."


def test_si_la_llave_pasa_a_otra_cuenta_da_reject(signer, client):
    """La pertenencia es la ÚNICA defensa aquí: la llave sigue existiendo con la misma
    pubkey (la firma verifica), pero el registro ya no la tiene a nombre del dueño."""
    body = signer.create()
    record = owner_keys.OWNER_KEYS.pop(signer.email)
    owner_keys.OWNER_KEYS[OTHER_OWNER] = record

    result = verify(client, body["mandate_id"])
    assert result["verdict"] == "REJECT"
    assert check(result, "signature")["detail"] == "Firma humana inválida: la llave ya no pertenece al titular."


def test_cambiar_lo_guardado_por_otra_version_firmada_da_reject(signer, client):
    """El message_hash del alta es la ÚNICA defensa aquí: el titular firmó dos versiones
    del mismo mandate_id; la segunda se rechazó (409), pero su firma es auténtica. Si
    alguien sustituye lo guardado por esa versión, la firma verifica y el hash no."""
    accepted = signer.create()
    rival = signer.body(mandate_id=accepted["mandate_id"], constraints__max_amount_per_purchase=5000)
    assert signer.post(rival).status_code == 409

    stored = MANDATES[accepted["mandate_id"]]["mandate"]
    stored["constraints"]["max_amount_per_purchase"] = 5000
    stored.update(nonce=rival["nonce"], created_at=rival["created_at"], signature=rival["signature"])

    result = verify(client, accepted["mandate_id"])
    assert result["verdict"] == "REJECT"
    assert check(result, "signature")["detail"] == "Firma humana inválida: el mandato cambió después de firmarse."


def test_llave_revocada_despues_de_crear_deja_sin_efecto_el_mandato(signer, client):
    """P-01 (a), 3.5 (inversión deliberada del test del 3.3, que aprobaba): revocar la
    llave deja sin efecto lo firmado con ella, sin mutar el estado del mandato. DELETE
    /keys informa cuántos mandatos vigentes quedan sin efecto."""
    first = signer.create()
    second = signer.create()
    assert verify(client, first["mandate_id"])["verdict"] == "APPROVE"

    revoked = signer.client.delete(f"/keys/{signer.key_id}", headers=signer.headers)
    assert revoked.status_code == 200
    assert revoked.json()["mandates_affected"] == 2

    result = verify_as_service(client, attempt(first["mandate_id"], attempt_id="att_2")).json()
    assert result["verdict"] == "REJECT"
    assert check(result, "signing_key_active")["pass"] is False
    assert check(result, "signature")["pass"] is True  # la firma era auténtica: lo que cambió es la llave
    assert MANDATES[second["mandate_id"]]["live_state"]["status"] == "active"  # sin mutar el estado


def test_revocar_cuenta_solo_mandatos_vigentes_de_esa_llave(signer, client, key_registrar, clock):
    other_device = SignedMandateClient(client, key_registrar, clock, email=signer.email)
    other_device.register()
    kept = other_device.create()
    revoked_first = signer.create()
    signer.create()
    assert client.post(f"/mandates/{revoked_first['mandate_id']}/revoke", headers=signer.headers).status_code == 200

    response = signer.client.delete(f"/keys/{signer.key_id}", headers=signer.headers)
    assert response.json()["mandates_affected"] == 1  # el revocado y el del otro dispositivo no cuentan
    assert verify(client, kept["mandate_id"])["verdict"] == "APPROVE"


def test_expires_at_vencido_da_reject(signer, client, clock):
    body = signer.create(expires_at=stamp(clock.now + timedelta(hours=1)))
    assert verify(client, body["mandate_id"])["verdict"] == "APPROVE"
    clock.advance(hours=1, seconds=1)
    result = verify_as_service(client, attempt(body["mandate_id"], attempt_id="att_2")).json()
    assert result["verdict"] == "REJECT"
    assert check(result, "status")["detail"] == "mandato expirado"


def test_payment_token_de_otro_mandato_da_reject(signer, client):
    first = signer.create()
    second = signer.create()
    stolen = copy.deepcopy(MANDATES[second["mandate_id"]]["mandate"]["payment_token"])
    MANDATES[first["mandate_id"]]["mandate"]["payment_token"] = stolen

    result = verify(client, first["mandate_id"])
    assert result["verdict"] == "REJECT"
    assert check(result, "signature")["pass"] is True  # la firma sigue bien: el token es lo que falla
    assert check(result, "payment_token_binding")["pass"] is False


def test_payment_token_reemitido_sin_binding_da_reject(signer, client):
    body = signer.create()
    del MANDATES[body["mandate_id"]]["mandate"]["payment_token"]["bound_message_hash"]
    assert verify(client, body["mandate_id"])["verdict"] == "REJECT"


@pytest.mark.parametrize("currency, verdict", [("EUR", "REJECT"), (None, "REJECT"), ("usd", "APPROVE")])
def test_moneda_distinta_da_reject(signer, client, currency, verdict):
    body = signer.create()
    purchase = {"currency": currency} if currency is not None else {}
    payload = attempt(body["mandate_id"], **purchase)
    if currency is None:
        del payload["purchase"]["currency"]
    result = verify_as_service(client, payload).json()
    assert result["verdict"] == verdict
    assert check(result, "currency")["pass"] is (verdict == "APPROVE")


def test_sin_consentimiento_off_session_toda_compra_escala(signer, client):
    body = signer.create(constraints__off_session_consent=False)
    result = verify(client, body["mandate_id"])  # dentro de todos los límites
    assert result["verdict"] == "ESCALATE"
    assert check(result, "off_session_consent")["pass"] is False
    assert MANDATES[body["mandate_id"]]["live_state"]["uses_count"] == 0  # no se compró solo


def test_con_consentimiento_el_flujo_es_el_normal(signer, client):
    body = signer.create()
    assert verify(client, body["mandate_id"])["verdict"] == "APPROVE"
    over = verify_as_service(client, attempt(body["mandate_id"], attempt_id="att_2", amount=500.0,
                                               metadata={"price": 500.0})).json()
    assert over["verdict"] == "ESCALATE"  # fuera de límites: escala como siempre


# ── Línea estricta (core/verify) ────────────────────────────────────────────

def strict_attempt(mandate_id: str, currency: str = "USD") -> PurchaseAttempt:
    return PurchaseAttempt(
        attempt_id="att_strict", mandate_id=mandate_id, agent_id="agt_saturday", merchant_id="mch_vuelaya",
        category="travel.flights", amount=100.0, currency=currency, timestamp=stamp(NOW),
        nonce=secrets.token_hex(16), signature="", agent_signature="",
    )


def test_linea_estricta_verifica_la_firma_humana(signer):
    body = signer.create()
    valid = strict_verify_purchase(strict_attempt(body["mandate_id"]))
    human = next(item for item in valid.checks if item["rule"] == "human_signature_valid")
    assert human["pass"] is True and "Firma humana Ed25519 válida" in human["detail"]
    assert next(item for item in valid.checks if item["rule"] == "payment_token_binding")["pass"] is True
    # Sin firma de agente válida no hay compra (igual que cualquier mandato de esta línea).
    assert valid.authorized is False
    assert next(item for item in valid.checks if item["rule"] == "agent_signature_valid")["pass"] is False

    MANDATES[body["mandate_id"]]["mandate"]["constraints"]["max_amount_per_purchase"] = 9999
    tampered = strict_verify_purchase(strict_attempt(body["mandate_id"]))
    assert tampered.authorized is False
    assert next(item for item in tampered.checks if item["rule"] == "human_signature_valid")["pass"] is False


def test_linea_estricta_rechaza_token_ajeno_y_otra_moneda(signer):
    first = signer.create()
    second = signer.create()
    MANDATES[first["mandate_id"]]["mandate"]["payment_token"] = copy.deepcopy(MANDATES[second["mandate_id"]]["mandate"]["payment_token"])
    stolen = strict_verify_purchase(strict_attempt(first["mandate_id"]))
    assert next(item for item in stolen.checks if item["rule"] == "payment_token_binding")["pass"] is False

    eur = strict_verify_purchase(strict_attempt(second["mandate_id"], currency="EUR"))
    assert next(item for item in eur.checks if item["rule"] == "currency")["pass"] is False
    assert eur.authorized is False


# ── El agente queda atado a lo firmado ──────────────────────────────────────

@pytest.fixture()
def searches(monkeypatch) -> list:
    """Búsqueda web simulada (R15): registra con qué search_fields buscó el agente."""
    calls: list = []
    monkeypatch.setattr(agent_loop, "search_merchant_offers", lambda category, fields: calls.append(fields) or [])
    return calls


def test_agent_run_con_search_fields_distintos_da_422(signer, client, searches):
    body = signer.create()
    response = client.post("/agent/run", json={"mandate_id": body["mandate_id"],
                                               "search_fields": {"origin": "MEX", "destination": "BOG", "departure_date": "2026-12-05"}},
                           headers=signer.headers)
    assert response.status_code == 422
    assert searches == []  # ni siquiera buscó


def test_agent_run_usa_lo_firmado(signer, client, searches):
    body = signer.create()
    signed_fields = MANDATES[body["mandate_id"]]["mandate"]["search_fields"]

    assert client.post("/agent/run", json={"mandate_id": body["mandate_id"]}, headers=signer.headers).status_code == 200
    # Los mismos campos con otra grafía (espacios) son los mismos tras normalizar.
    same = {key: f" {value} " for key, value in signed_fields.items()}
    assert client.post("/agent/run", json={"mandate_id": body["mandate_id"], "search_fields": same}, headers=signer.headers).status_code == 200
    assert searches == [signed_fields, signed_fields]


# ── Pendiente del 3.1: Retry-After en el 429 de /keys/challenge ─────────────

def test_challenge_bloqueado_manda_retry_after(client, key_registrar):
    headers = bearer(TEST_USER_EMAIL)
    assert client.post("/keys/step-up/start", headers=headers).status_code == 200
    key_registrar.otp_clock.advance(20)
    statuses = [client.post("/keys/challenge", json={"code": "000000"}, headers=headers) for _ in range(key_registrar.otp_service.max_attempts)]

    locked = statuses[-1]
    assert [response.status_code for response in statuses] == [403] * (key_registrar.otp_service.max_attempts - 1) + [429]
    expected = key_registrar.otp_service.resend_cooldown_seconds - 20
    assert locked.headers["Retry-After"] == str(expected)
    # Y es exactamente cuándo se puede pedir otro código.
    key_registrar.otp_clock.advance(expected - 1)
    assert client.post("/keys/step-up/start", headers=headers).status_code == 429
    key_registrar.otp_clock.advance(1)
    assert client.post("/keys/step-up/start", headers=headers).status_code == 200


def test_retry_after_del_challenge_se_expone_por_cors(client, key_registrar, monkeypatch):
    headers = {**bearer(TEST_USER_EMAIL), "Origin": "http://localhost:5173"}
    client.post("/keys/step-up/start", headers=headers)
    for _ in range(key_registrar.otp_service.max_attempts):
        locked = client.post("/keys/challenge", json={"code": "000000"}, headers=headers)
    assert locked.status_code == 429
    assert "retry-after" in locked.headers.get("access-control-expose-headers", "").lower()


# ── 3.5: huecos que señaló la prueba de mutación ────────────────────────────

def test_linea_estricta_rechaza_mandato_con_llave_revocada(signer):
    """P-01 (a) también en core/verify: revocar la llave deja sin efecto el mandato."""
    body = signer.create()
    assert signer.client.delete(f"/keys/{signer.key_id}", headers=signer.headers).status_code == 200

    result = strict_verify_purchase(strict_attempt(body["mandate_id"]))
    assert result.authorized is False
    assert next(item for item in result.checks if item["rule"] == "signing_key_active")["pass"] is False
    # Corta AHÍ, por la revocación: no sigue evaluando (ni token, ni moneda, ni agente).
    assert "revocada" in result.reason
    assert [item["rule"] for item in result.checks][-1] == "signing_key_active"


def test_mandato_sin_firmante_registrado_se_rechaza_aunque_su_firma_legada_verifique(client):
    """Un mandato que llegue al registro sin firmante (ni titular ni sello del seed) se
    rechaza: aunque traiga una firma Ed25519 legada que SÍ verificaría con su propia
    llave (el antiguo legacy_client), esa firma no prueba quién la hizo."""
    from mandate.sign import generate_keypair, sign_payload
    priv, pub = generate_keypair()
    constraints = {"max_amount_per_purchase": 150, "allowed_categories": ["travel.flights"],
                   "allowed_merchants": ["mch_vuelaya"], "max_uses": 3}
    MANDATES["mnd_no_signer"] = {
        "mandate": {"mandate_id": "mnd_no_signer", "agent": {"id": "agt_saturday"}, "constraints": constraints,
                    "human_pubkey": pub, "signature": sign_payload(priv, constraints)},
        "live_state": {"status": "active", "uses_count": 0, "amount_spent": 0, "revoked_at": None},
    }
    result = verify(client, "mnd_no_signer")
    assert result["verdict"] == "REJECT"
    assert check(result, "signature") == {"rule": "signature", "pass": False, "detail": "El mandato no tiene una firma registrada."}


def test_el_seed_no_puede_traer_firma_propia(client):
    from core.mandate_store import seal_seed_mandate
    seed = {"mandate_id": "mnd_seed_signed", "constraints": {"max_amount_per_purchase": 150},
            "human_pubkey": "ab" * 32, "signature": "cd" * 64}
    with pytest.raises(ValueError, match="no puede traer firma"):
        seal_seed_mandate(seed)
    assert "mnd_seed_signed" not in MANDATES
