"""Mensaje firmado del mandato v1 (paso 3.2) contra shared/mandate_signing_vectors.json.

El MISMO archivo lo verifica frontend/src/lib/mandateMessage.test.ts: si un lado
cambia un byte, su test falla contra los bytes fijados.

Los vectores se leen de dos formas: con parse_float=Decimal (lo que hará el backend
en el 3.3, sin flotantes) y con floats normales (json por defecto). Ambas deben dar
los mismos centavos y los mismos bytes.
"""
import copy
import json
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.key_challenges import REGISTER_KEY_PURPOSE, registration_message
from mandate.canonical import canonicalize
from mandate.mandate_message import (
    MANDATE_PURPOSE,
    TRIM_CODE_POINTS,
    MandateMessageError,
    mandate_signing_message,
    mandate_signing_payload,
    to_cents,
)
from mandate.sign import verify_ed25519_bytes

VECTORS_PATH = Path(__file__).resolve().parent.parent / "shared" / "mandate_signing_vectors.json"
REGISTRATION_VECTORS_PATH = VECTORS_PATH.with_name("key_registration_vectors.json")


def _load(parse_float):
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"), parse_float=parse_float)


SHARED = _load(Decimal)
SHARED_FLOATS = _load(float)
RFC = SHARED["rfc8032_test1"]
PUBLIC = RFC["public_key_hex"]
PRIVATE = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(RFC["secret_key_hex"]))
PARSERS = [pytest.param(SHARED, id="decimal"), pytest.param(SHARED_FLOATS, id="float")]


def _by_name(document, section):
    return {entry["name"]: entry for entry in document[section]}


def test_purpose_es_el_de_la_spec_y_distinto_del_registro():
    assert MANDATE_PURPOSE == SHARED["purpose"] == "agentbuyer:mandate:v1"
    assert MANDATE_PURPOSE != REGISTER_KEY_PURPOSE


# ── Bytes y firma exactos ───────────────────────────────────────────────────

@pytest.mark.parametrize("document", PARSERS)
@pytest.mark.parametrize("name", [vector["name"] for vector in SHARED["vectors"]])
def test_vector_bytes_y_firma_exactos(document, name):
    vector = _by_name(document, "vectors")[name]
    message = mandate_signing_message(**copy.deepcopy(vector["inputs"]))

    assert message.decode("utf-8") == vector["expected_message"]
    assert message.hex() == vector["expected_message_utf8_hex"]
    signature = PRIVATE.sign(message).hex()
    assert signature == vector["expected_signature_hex"]  # Ed25519 es determinista
    assert verify_ed25519_bytes(PUBLIC, message, signature)


def test_el_payload_es_exactamente_el_mensaje_canonico():
    vector = SHARED["vectors"][0]
    payload = mandate_signing_payload(**copy.deepcopy(vector["inputs"]))
    assert canonicalize(payload).decode("utf-8") == vector["expected_message"]
    assert sorted(payload) == [
        "agent_id", "constraints", "created_at", "expires_at", "key_id", "mandate_id",
        "nonce", "owner", "public_key", "purpose", "search_fields",
    ]


def test_la_entrada_no_se_modifica():
    inputs = copy.deepcopy(SHARED["vectors"][3]["inputs"])
    before = copy.deepcopy(inputs)
    mandate_signing_payload(**inputs)
    assert inputs == before


# ── Inválidos ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("document", PARSERS)
@pytest.mark.parametrize("name", [entry["name"] for entry in SHARED["invalid"]])
def test_invalido_falla_en_el_campo_esperado(document, name):
    entry = _by_name(document, "invalid")[name]
    with pytest.raises(MandateMessageError) as caught:
        mandate_signing_message(**copy.deepcopy(entry["inputs"]))
    assert caught.value.field == entry["error_field"]


def test_trim_usa_el_conjunto_compartido():
    assert [f"U+{point:04X}" for point in TRIM_CODE_POINTS] == SHARED["trim_code_points"]
    spaces = "".join(chr(point) for point in TRIM_CODE_POINTS)
    inputs = copy.deepcopy(SHARED["vectors"][0]["inputs"])
    inputs["search_fields"] = {"destination": f"{spaces}COR{spaces}"}
    assert mandate_signing_payload(**inputs)["search_fields"] == {"destination": "COR"}
    # str.strip() recortaría U+001C y U+0085; la spec (y JS) no: se firman tal cual.
    for kept in (0x1C, 0x85):
        inputs["search_fields"] = {"destination": f"{chr(kept)}COR"}
        assert mandate_signing_payload(**inputs)["search_fields"]["destination"] == f"{chr(kept)}COR"


# ── Centavos sin flotantes ──────────────────────────────────────────────────

@pytest.mark.parametrize("document", PARSERS)
@pytest.mark.parametrize("index", range(len(SHARED["amount_cases"])))
def test_amount_cases_compartidos(document, index):
    case = document["amount_cases"][index]
    if case.get("error"):
        with pytest.raises(MandateMessageError):
            to_cents(case["input"], "amount")
    else:
        assert to_cents(case["input"], "amount") == case["cents"]


@pytest.mark.parametrize("value, cents", [
    (150, 15000), (150.1, 15010), (Decimal("150.10"), 15010), ("150.10", 15010),
    (Decimal("1E+2"), 10000), (Decimal("0E+999999999"), 0),
])
def test_to_cents_exactos(value, cents):
    assert to_cents(value, "amount") == cents


@pytest.mark.parametrize("value", [
    0.1 + 0.2, Decimal("0.30000000000000004"), Decimal("NaN"), Decimal("Infinity"),
    float("nan"), float("inf"), Decimal("-0.01"), Decimal("1E-999999999"), 2**60, "150\n", "١٥٠",
])
def test_to_cents_rechaza(value):
    with pytest.raises(MandateMessageError):
        to_cents(value, "amount")


# ── Cambiar cualquier campo firmado invalida la firma ───────────────────────

def _base():
    inputs = copy.deepcopy(SHARED["vectors"][0]["inputs"])
    payload = mandate_signing_payload(**inputs)
    return payload, PRIVATE.sign(canonicalize(payload)).hex()


def _set(payload, path, value):
    target = payload
    *parents, leaf = path.split(".")
    for parent in parents:
        target = target[parent]
    target[leaf] = value


# Un cambio mínimo por campo firmado (ruta en el payload → nuevo valor).
TAMPERS = {
    "purpose": REGISTER_KEY_PURPOSE,
    "mandate_id": "mnd_marta_mbx3k3",
    "owner": "mallory@example.com",
    "key_id": "key_ffeeddccbbaa99887766554433221100",
    "public_key": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "agent_id": "agt_mallory",
    "constraints.currency": "EUR",
    "constraints.max_amount_per_purchase_cents": 15001,
    "constraints.allowed_categories": ["travel.flights", "travel.hotels"],
    "constraints.allowed_merchants": ["mch_otro"],
    "constraints.max_uses": 4,
    "constraints.conditions": [{"type": "price_below", "value_cents": 14001}],
    "constraints.off_session_consent": False,
    "search_fields": {"origin": "MEX", "destination": "BOG", "departure_date": "2026-12-05"},
    "expires_at": "2027-11-30T23:59:59Z",
    "created_at": "2026-11-16T10:00:01Z",
    "nonce": "ffeeddccbbaa99887766554433221100",
}


def _leaf_paths(value, prefix=""):
    if isinstance(value, dict) and prefix in ("", "constraints"):
        for key, item in value.items():
            yield from _leaf_paths(item, f"{prefix}.{key}" if prefix else key)
    else:
        yield prefix


def test_hay_un_cambio_por_cada_campo_firmado():
    payload, _ = _base()
    assert sorted(_leaf_paths(payload)) == sorted(TAMPERS)


@pytest.mark.parametrize("path", sorted(TAMPERS))
def test_cambiar_un_campo_firmado_invalida_la_firma(path):
    payload, signature = _base()
    assert verify_ed25519_bytes(PUBLIC, canonicalize(payload), signature)

    tampered = copy.deepcopy(payload)
    _set(tampered, path, TAMPERS[path])
    assert tampered != payload
    assert not verify_ed25519_bytes(PUBLIC, canonicalize(tampered), signature)


# Y desde la ENTRADA: cada dato que manda el cliente llega al mensaje (nada se descarta).
INPUT_TAMPERS = {
    "mandate_id": "mnd_otro",
    "owner_email": "otra@example.com",
    "key_id": "key_otro",
    "public_key": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "agent_id": "agt_otro",
    "constraints.max_amount_per_purchase": "150.01",
    "constraints.allowed_categories": ["travel.hotels"],
    "constraints.allowed_merchants": ["mch_otro"],
    "constraints.max_uses": 2,
    "constraints.conditions": [{"type": "price_below", "value": "139.99"}],
    "constraints.off_session_consent": False,
    "search_fields": {"origin": "MEX"},
    "expires_at": "2026-12-01T00:00:00Z",
    "created_at": "2026-11-16T09:59:59Z",
    "nonce": "0" * 32,
}


@pytest.mark.parametrize("path", sorted(INPUT_TAMPERS))
def test_cada_entrada_cambia_el_mensaje(path):
    inputs = copy.deepcopy(SHARED["vectors"][0]["inputs"])
    base = mandate_signing_message(**copy.deepcopy(inputs))
    _set(inputs, path, INPUT_TAMPERS[path])
    assert mandate_signing_message(**inputs) != base


# ── Separación de dominio con register-key:v1 ───────────────────────────────

def test_una_firma_de_registro_no_verifica_como_mandato():
    registration = json.loads(REGISTRATION_VECTORS_PATH.read_text(encoding="utf-8"))
    reg_vector = registration["vectors"][0]
    reg_message = reg_vector["expected_message"].encode("utf-8")
    assert verify_ed25519_bytes(PUBLIC, reg_message, reg_vector["expected_signature_hex"])  # misma llave RFC

    mandate_message = mandate_signing_message(**copy.deepcopy(SHARED["vectors"][0]["inputs"]))
    assert not verify_ed25519_bytes(PUBLIC, mandate_message, reg_vector["expected_signature_hex"])
    # Ni siquiera un mandato con los mismos valores que el registro (pubkey, owner).
    inputs = copy.deepcopy(SHARED["vectors"][0]["inputs"])
    inputs["owner_email"] = reg_vector["inputs"]["owner_email"]
    assert not verify_ed25519_bytes(PUBLIC, mandate_signing_message(**inputs), reg_vector["expected_signature_hex"])


def test_una_firma_de_mandato_no_verifica_como_registro():
    vector = SHARED["vectors"][0]
    mandate_signature = vector["expected_signature_hex"]
    inputs = vector["inputs"]
    as_registration = registration_message(
        challenge_id=f"chl_{inputs['nonce']}", nonce=inputs["nonce"],
        owner_email=inputs["owner_email"], public_key=inputs["public_key"],
    )
    assert not verify_ed25519_bytes(PUBLIC, as_registration, mandate_signature)


def test_el_purpose_firmado_es_el_que_separa_los_dominios():
    payload, signature = _base()
    relabeled = {**payload, "purpose": REGISTER_KEY_PURPOSE}
    assert not verify_ed25519_bytes(PUBLIC, canonicalize(relabeled), signature)
    # Y el builder no permite elegir el purpose: no es una entrada.
    with pytest.raises(TypeError):
        mandate_signing_payload(**SHARED["vectors"][0]["inputs"], purpose=REGISTER_KEY_PURPOSE)
