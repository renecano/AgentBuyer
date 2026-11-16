"""Flujo real de punta a punta, compartido por scripts/bootstrap_demo.py y run_demo.py.

Habla con la API como lo haría el navegador: login por OTP, registro de una llave
Ed25519 con prueba de posesión (step-up OTP + challenge firmado), mandato firmado por
esa llave (spec v1, mandate/mandate_message.py) y verificación como comercio.
Solo funciona con AUTH_DEV_MODE=true: los códigos OTP vienen en la respuesta
(`code_demo`), porque no hay un correo que leer. No hay atajos del lado del servidor.

Dos transportes con la misma interfaz `request(method, path, json=None, headers=None)`
→ (status, body):
- HttpTransport: una API corriendo (urllib, sin dependencias extra).
- InProcessTransport: la app en el mismo proceso (fastapi.testclient; requiere
  requirements-dev.txt). La usa run_demo.py para no depender de un servidor.
"""
from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.key_challenges import registration_message
from mandate.mandate_message import mandate_signing_message


class DemoFlowError(RuntimeError):
    """Un paso del flujo no respondió lo esperado (el mensaje dice cuál y qué vino)."""


class HttpTransport:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, path: str, json_body: Any = None, headers: Optional[dict] = None):
        data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
        request = urllib.request.Request(self.base_url + path, data=data, method=method,
                                         headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                return error.code, json.loads(raw) if raw else None
            except ValueError:
                return error.code, raw.decode("utf-8", "replace")


class InProcessTransport:
    def __init__(self, test_client):
        self.client = test_client

    def request(self, method: str, path: str, json_body: Any = None, headers: Optional[dict] = None):
        response = self.client.request(method, path, json=json_body, headers=headers or {})
        try:
            body = response.json()
        except ValueError:
            body = response.text
        return response.status_code, body


def _expect(step: str, status: int, body: Any, *expected: int) -> Any:
    if status not in expected:
        raise DemoFlowError(f"{step}: HTTP {status} (expected {', '.join(map(str, expected))}): {body}")
    return body


def utc_stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Person:
    email: str
    token: str
    private_key: ed25519.Ed25519PrivateKey
    public_key: str
    key_id: str

    @property
    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}


def login(api, email: str) -> str:
    started = _expect("Login (send code)", *api.request("POST", "/auth/email/start", {"email": email}), 200)
    code = (started or {}).get("code_demo")
    if not code:
        raise DemoFlowError("The API is not in AUTH_DEV_MODE=true: the code is not in the response. "
                            "This flow is for development only.")
    checked = _expect("Login (verify code)", *api.request("POST", "/auth/email/check", {"email": email, "code": code}), 200)
    return checked["access_token"]


def enroll(api, email: str) -> Person:
    """Login + registro de una llave nueva con prueba de posesión (como el navegador)."""
    token = login(api, email)
    headers = {"Authorization": f"Bearer {token}"}
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    step_up = _expect("Step-up (confirmation code)", *api.request("POST", "/keys/step-up/start", None, headers), 200)
    challenge = _expect("Challenge", *api.request("POST", "/keys/challenge", {"code": step_up["code_demo"]}, headers), 201)
    signature = private_key.sign(registration_message(challenge["challenge_id"], challenge["nonce"], email, public_key)).hex()
    registered = _expect("Register the key", *api.request(
        "POST", "/keys", {"public_key": public_key, "challenge_id": challenge["challenge_id"], "signature": signature}, headers), 201)
    return Person(email=email.strip().lower(), token=token, private_key=private_key, public_key=public_key,
                  key_id=registered["key_id"])


DEFAULT_CONSTRAINTS = {
    "max_amount_per_purchase": "150",
    "currency": "USD",
    "allowed_categories": ["travel.flights"],
    "allowed_merchants": ["mch_vuelaya"],
    "max_uses": 3,
    "conditions": [{"type": "price_below", "value": "150"}],
    "off_session_consent": True,
}
DEFAULT_SEARCH = {"origin": "BUE", "destination": "COR", "departure_date": "2026-12-05"}


def sign_mandate(api, person: Person, *, mandate_id: Optional[str] = None, constraints: Optional[dict] = None,
                 search_fields: Optional[dict] = None, valid_days: int = 30) -> dict:
    """Firma con la llave de `person` (spec v1) y crea el mandato. Devuelve el registro."""
    created = datetime.now(timezone.utc)
    inputs = {
        "mandate_id": mandate_id or f"mnd_demo_{secrets.token_hex(4)}",
        "agent_id": "agt_saturday",
        "constraints": constraints or DEFAULT_CONSTRAINTS,
        "search_fields": search_fields or DEFAULT_SEARCH,
        "created_at": utc_stamp(created),
        "expires_at": utc_stamp((created + timedelta(days=valid_days)).replace(hour=23, minute=59, second=59)),
        "nonce": secrets.token_hex(16),
        "key_id": person.key_id,
    }
    message = mandate_signing_message(**{**inputs, "owner_email": person.email, "public_key": person.public_key})
    body = {
        "mandate_id": inputs["mandate_id"],
        "human": {"id": "hum_demo", "display_name": person.email.split("@")[0]},
        "agent": {"id": inputs["agent_id"], "display_name": "Saturday"},
        "constraints": inputs["constraints"], "search_fields": inputs["search_fields"],
        "expires_at": inputs["expires_at"], "created_at": inputs["created_at"], "nonce": inputs["nonce"],
        "key_id": inputs["key_id"], "signature": person.private_key.sign(message).hex(),
    }
    return _expect("Create the signed mandate", *api.request("POST", "/mandates", body, person.headers), 201)


def merchant_verifies(api, service_key: str, mandate_id: str, amount_cents: int,
                      merchant_id: str = "mch_vuelaya", description: str = "Flight BUE-COR") -> dict:
    """El comercio presenta un intento a POST /verify con su credencial de servicio."""
    attempt = {
        "attempt_id": f"att_demo_{secrets.token_hex(4)}", "mandate_id": mandate_id, "presented_by_agent": "agt_saturday",
        "nonce": secrets.token_hex(16), "created_at": utc_stamp(datetime.now(timezone.utc)),
        "purchase": {"merchant_id": merchant_id, "category": "travel.flights", "amount_cents": amount_cents,
                     "currency": "USD", "description": description, "metadata": {"price_cents": amount_cents}},
    }
    return _expect("Merchant verification", *api.request("POST", "/verify", attempt, {"X-Service-Key": service_key}), 200)
