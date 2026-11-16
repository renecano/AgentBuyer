"""Fixtures compartidos de la suite."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import api.main as api_main
from core.auth_tokens import ROLE_ADMIN, create_access_token

# Holgura de la expiración relativa del seed. Solo tiene que cubrir la duración de
# un test; un año evita cualquier borde de reloj.
SEED_VALIDITY = timedelta(days=365)

# Clave SOLO para la suite (>= 32 bytes). No es la clave de desarrollo del código.
TEST_JWT_SECRET = "pytest-only-jwt-secret-not-used-anywhere-else-0123456789"


@pytest.fixture(autouse=True)
def auth_config(monkeypatch):
    """Configuración de auth que la app EXIGE para arrancar (core/auth_tokens.
    validate_token_config): JWT_SECRET válido y modo desarrollo apagado, como en
    producción. Aísla la suite del .env y del entorno de quien la corre; los tests
    que prueban otras combinaciones las sobrescriben con monkeypatch."""
    monkeypatch.setenv("JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.delenv("AUTH_DEV_MODE", raising=False)
    monkeypatch.delenv("JWT_TTL_SECONDS", raising=False)
    # Sin admins ni keys de servicio salvo que el test las configure (fail-closed).
    monkeypatch.delenv("ADMIN_EMAILS", raising=False)
    monkeypatch.delenv("SERVICE_API_KEY", raising=False)


# Identidad del usuario de la suite en los tokens de auth_headers.
TEST_USER_EMAIL = "pytest.user@example.com"


@pytest.fixture()
def auth_headers(auth_config) -> dict[str, str]:
    """Header `Authorization: Bearer <JWT>` de un usuario válido, para llamar a
    endpoints protegidos con require_principal (api/security.py).

    El token es real: lo firma create_access_token con el mismo JWT_SECRET con el
    que arranca la app (auth_config), y la dependencia lo valida por el camino
    normal (firma, emisor, expiración, rol). No se desactiva ni se simula la auth.
    Es el mismo token que /auth/email/check emite tras verificar el OTP (ver
    test_token_from_real_email_login_opens_protected_endpoint).
    """
    return {"Authorization": f"Bearer {create_access_token(TEST_USER_EMAIL)}"}


@pytest.fixture()
def active_seed(monkeypatch, tmp_path) -> dict:
    """Carga el mandato semilla con una expiración RELATIVA al momento del test.

    shared/seed_mandates.json trae un expires_at absoluto que en algún momento
    queda en el pasado. Los tests que necesitan el seed ACTIVO no deben depender
    de la fecha del sistema, así que se usa una copia idéntica del seed real con
    expires_at = ahora + 1 año, y el lifespan de la app la carga por el camino
    normal (load_seed_mandates leyendo SEED_PATH).

    No toca la regla de expiración: un mandato realmente vencido se sigue
    rechazando (ver test_expired_seed_is_still_rejected). Si SEED_PATH deja de
    existir, monkeypatch falla con AttributeError en vez de ignorarse en silencio.
    Devuelve el seed tal como se cargó.
    """
    seeds = json.loads(Path(api_main.SEED_PATH).read_text(encoding="utf-8"))
    expires_at = (datetime.now(timezone.utc) + SEED_VALIDITY).strftime("%Y-%m-%dT%H:%M:%SZ")
    for seed in seeds:
        seed["expires_at"] = expires_at

    relative_seed = tmp_path / "seed_mandates.json"
    relative_seed.write_text(json.dumps(seeds, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(api_main, "SEED_PATH", str(relative_seed))
    return seeds[0]


@pytest.fixture()
def seed_owner_headers(active_seed) -> dict[str, str]:
    """Bearer del DUEÑO del mandato semilla, para los endpoints que exigen
    propiedad (api/security.py: require_mandate_access).

    El email NO se escribe a mano: sale del propio seed (human.email), que es de
    donde el arranque saca el dueño. Si el seed cambia de dueño, el token lo sigue
    y los tests no empiezan a mentir en silencio."""
    return {"Authorization": f"Bearer {create_access_token(active_seed['human']['email'])}"}


# Identidad admin y key de servicio de la suite.
TEST_ADMIN_EMAIL = "pytest.admin@example.com"
TEST_SERVICE_KEY = "pytest-only-service-key-0123456789-abcdefghijklmnop"


@pytest.fixture()
def admin_headers(auth_config, monkeypatch) -> dict[str, str]:
    """Bearer de un ADMIN real: el email está en ADMIN_EMAILS (como exige
    require_admin) y el token lleva role="admin", igual que el que emite
    /auth/email/check para ese email."""
    monkeypatch.setenv("ADMIN_EMAILS", TEST_ADMIN_EMAIL)
    return {"Authorization": f"Bearer {create_access_token(TEST_ADMIN_EMAIL, role=ROLE_ADMIN)}"}


@pytest.fixture()
def service_headers(auth_config, monkeypatch) -> dict[str, str]:
    """Header X-Service-Key con una key configurada en SERVICE_API_KEY, validada
    por require_service por el camino normal (comparación en tiempo constante)."""
    monkeypatch.setenv("SERVICE_API_KEY", TEST_SERVICE_KEY)
    return {"X-Service-Key": TEST_SERVICE_KEY}


# ── Registro de llaves con PRUEBA DE POSESIÓN (flujo real completo) ──────────

class FakeClock:
    """Reloj controlable para servicios con TTL (OTP, challenges)."""

    def __init__(self, start: float = 1_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class KeyRegistrar:
    """Hace el flujo REAL de registro de una llave por HTTP, sin atajos:

        POST /keys/step-up/start → (código del correo) → POST /keys/challenge
        → firmar registration_message con la privada → POST /keys

    Usa servicios de step-up y challenge con reloj propio (sin esperas reales) y un
    buzón falso en lugar de SMTP. Nada se desactiva: la verificación del servidor
    es la de producción."""

    def __init__(self, client, monkeypatch):
        import api.keys as keys_api
        from core.email_otp import EmailOtpService
        from core.key_challenges import KeyChallengeService

        self.client = client
        self.otp_clock = FakeClock()
        self.challenge_clock = FakeClock()
        self.outbox: list[dict] = []
        self.otp_service = EmailOtpService(clock=self.otp_clock)
        self.challenge_service = KeyChallengeService(clock=self.challenge_clock)
        monkeypatch.setattr(keys_api, "step_up_otp_service", self.otp_service)
        monkeypatch.setattr(keys_api, "challenge_service", self.challenge_service)
        monkeypatch.setattr(
            keys_api, "send_step_up_email",
            lambda email, code, ttl: self.outbox.append({"email": email, "code": code}) or True,
        )

    @staticmethod
    def bearer(email: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {create_access_token(email)}"}

    @staticmethod
    def new_private_key():
        from cryptography.hazmat.primitives.asymmetric import ed25519
        return ed25519.Ed25519PrivateKey.generate()

    @staticmethod
    def public_hex(private_key) -> str:
        from cryptography.hazmat.primitives import serialization
        return private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def challenge(self, headers: dict[str, str]) -> dict:
        """Step-up OTP + challenge para el dueño de `headers`."""
        started = self.client.post("/keys/step-up/start", headers=headers)
        assert started.status_code == 200, started.text
        code = self.outbox[-1]["code"]
        issued = self.client.post("/keys/challenge", json={"code": code}, headers=headers)
        assert issued.status_code == 201, issued.text
        # Ya canjeado: deja pasar el cooldown y la ventana del rate limit del OTP para
        # el próximo registro (el reloj de los challenges es otro y no se mueve).
        self.otp_clock.advance(self.otp_service.send_window_seconds)
        return issued.json()

    @staticmethod
    def sign(private_key, challenge: dict, owner_email: str, public_key_hex: str) -> str:
        from core.key_challenges import registration_message
        message = registration_message(challenge["challenge_id"], challenge["nonce"], owner_email, public_key_hex)
        return private_key.sign(message).hex()

    def register(self, email: str, private_key=None, *, headers=None, public_key_hex=None, extra=None):
        """Registro completo con prueba válida. Devuelve (respuesta, privada, pubkey_hex)."""
        headers = headers or self.bearer(email)
        private_key = private_key or self.new_private_key()
        public_key_hex = public_key_hex or self.public_hex(private_key)
        challenge = self.challenge(headers)
        body = {
            "public_key": public_key_hex,
            "challenge_id": challenge["challenge_id"],
            "signature": self.sign(private_key, challenge, email, public_key_hex),
            **(extra or {}),
        }
        return self.client.post("/keys", json=body, headers=headers), private_key, public_key_hex


@pytest.fixture()
def key_registrar(client, monkeypatch) -> KeyRegistrar:
    """Registrador de llaves por el flujo real (usa el fixture `client` del módulo)."""
    return KeyRegistrar(client, monkeypatch)


# ── Mandatos firmados por el titular (como el navegador desde el 3.4) ────────

def utc_stamp(moment: datetime) -> str:
    """ISO 8601 UTC con Z y precisión de segundos (formato firmado del 3.2)."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Lo que envía MandateCreator.tsx desde el 3.4 (submitMandate → lib/signedMandate):
# los montos son el TEXTO que tecleó la persona; la spec los pasa a centavos.
REACT_MANDATE_INPUTS = {
    "agent_id": "agt_saturday",
    "constraints": {
        "max_amount_per_purchase": "150",
        "currency": "USD",
        "allowed_categories": ["travel.flights"],
        "allowed_merchants": ["mch_vuelaya"],
        "max_uses": 3,
        "conditions": [{"type": "price_below", "value": "150"}],
        "off_session_consent": True,
    },
    "search_fields": {"origin": "BUE", "destination": "COR", "departure_date": "2026-12-05"},
}
REACT_HUMAN_CONTACT = {
    "id": "hum_test_user_contract",
    "display_name": "Test User",
    "id_document": "XXXXXX",
    "phone": "+520000000000",
}


class MandateSigner:
    """Firma mandatos como el navegador (lib/signedMandate.ts, paso 3.4): el mensaje
    del 3.2 (mandate/mandate_message.py) con una llave registrada por el flujo REAL
    de prueba de posesión. Sin atajos: el servidor verifica como en producción.

    `now` es el reloj del cliente (created_at); `base_inputs` la forma del mandato
    (por defecto, la del wizard)."""

    _counter = 0

    def __init__(self, client, registrar: "KeyRegistrar", email: str, *, private_key=None, now=None,
                 base_inputs: dict | None = None, human: dict | None = None):
        self.client = client
        self.registrar = registrar
        self.email = email
        self.headers = KeyRegistrar.bearer(email)
        self.private_key = private_key or registrar.new_private_key()
        self.public_key = registrar.public_hex(self.private_key)
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.base_inputs = base_inputs or REACT_MANDATE_INPUTS
        self.human = human or {**REACT_HUMAN_CONTACT, "email": email}
        self.key_id: str | None = None

    def register(self, monkeypatch=None, key_id_hex: str | None = None) -> str:
        """Registro REAL con prueba de posesión. key_id_hex fija el id (para vectores)."""
        from core import owner_keys

        if key_id_hex is not None:
            class FixedUuid:
                hex = key_id_hex
            with monkeypatch.context() as patch:
                patch.setattr(owner_keys.uuid, "uuid4", lambda: FixedUuid())
                response, _, _ = self.registrar.register(self.email, self.private_key, headers=self.headers)
        else:
            response, _, _ = self.registrar.register(self.email, self.private_key, headers=self.headers)
        assert response.status_code == 201, response.text
        self.key_id = response.json()["key_id"]
        return self.key_id

    def body(self, **changes) -> dict:
        """Cuerpo firmado (formato 3.2/3.3). `changes` usa rutas con "__"
        (constraints__max_uses=2) y se aplica ANTES de firmar."""
        import copy
        import secrets

        from mandate.mandate_message import mandate_signing_message

        MandateSigner._counter += 1
        created = self.now()
        inputs = copy.deepcopy(self.base_inputs)
        inputs.update({
            "mandate_id": f"mnd_signed_{MandateSigner._counter}",
            "created_at": utc_stamp(created),
            "expires_at": utc_stamp((created + timedelta(days=30)).replace(hour=23, minute=59, second=59)),
            "nonce": secrets.token_hex(16),
            "key_id": self.key_id,
        })
        inputs.pop("owner_email", None)
        inputs.pop("public_key", None)
        for path, value in changes.items():
            target = inputs
            *parents, leaf = path.split("__")
            for parent in parents:
                target = target[parent]
            target[leaf] = value
        message = mandate_signing_message(**{**inputs, "owner_email": self.email, "public_key": self.public_key})
        return {
            "mandate_id": inputs["mandate_id"],
            "human": dict(self.human),
            "agent": {"id": inputs["agent_id"], "display_name": "Saturday"},
            "constraints": inputs["constraints"],
            "search_fields": inputs["search_fields"],
            "expires_at": inputs["expires_at"],
            "created_at": inputs["created_at"],
            "nonce": inputs["nonce"],
            "key_id": inputs["key_id"],
            "signature": self.private_key.sign(message).hex(),
        }

    def post(self, body: dict, headers: dict | None = None):
        return self.client.post("/mandates", json=body, headers=headers or self.headers)

    def create(self, **changes) -> dict:
        body = self.body(**changes)
        response = self.post(body)
        assert response.status_code == 201, response.text
        return body


class SignedMandatePoster:
    """Desde el 3.5 todo mandato de usuario va firmado por su titular. Este helper toma
    el MISMO dict con forma de React que arma cada test ({mandate_id, human, agent,
    constraints, search_fields?, expires_at?}), lo firma como el navegador con una
    llave registrada por el flujo real (una por email, registrada la primera vez) y lo
    postea. La intención del test no cambia; solo cómo nace el mandato.

    Las constraints se firman tal cual (la spec v1 las valida); si faltan `currency` u
    `off_session_consent` se usan los valores que envía el wizard (USD, True)."""

    def __init__(self, client, registrar: KeyRegistrar, default_email: str = TEST_USER_EMAIL, now=None):
        self.client = client
        self.registrar = registrar
        self.default_email = default_email
        self.now = now
        self._signers: dict[str, MandateSigner] = {}

    def signer_for(self, email: str) -> MandateSigner:
        normalized = email.strip().lower()
        if normalized not in self._signers:
            signer = MandateSigner(self.client, self.registrar, normalized, now=self.now)
            signer.register()
            self._signers[normalized] = signer
        return self._signers[normalized]

    def body(self, mandate: dict, email: str | None = None) -> dict:
        import copy

        signer = self.signer_for(email or self.default_email)
        constraints = copy.deepcopy(mandate.get("constraints") or {})
        constraints.setdefault("currency", "USD")
        constraints.setdefault("off_session_consent", True)
        changes = {
            "mandate_id": mandate["mandate_id"],
            "agent_id": (mandate.get("agent") or {}).get("id", "agt_saturday"),
            "constraints": constraints,
            "search_fields": copy.deepcopy(mandate.get("search_fields") or {}),
        }
        if "expires_at" in mandate:
            changes["expires_at"] = mandate["expires_at"]
        signed = signer.body(**changes)
        if "human" in mandate:
            signed["human"] = copy.deepcopy(mandate["human"])
        if "agent" in mandate:
            signed["agent"] = {key: value for key, value in mandate["agent"].items() if key in ("id", "display_name")}
        return signed

    def post(self, mandate: dict, email: str | None = None, headers: dict | None = None):
        signer = self.signer_for(email or self.default_email)
        return self.client.post("/mandates", json=self.body(mandate, email), headers=headers or signer.headers)

    def create(self, mandate: dict, email: str | None = None) -> dict:
        response = self.post(mandate, email)
        assert response.status_code == 201, response.text
        return response.json()


@pytest.fixture()
def signed_poster(client, key_registrar):
    """Crea mandatos firmados por el titular (flujo real) desde dicts con forma de React.
    Cada test corre sobre su propia base (conftest.py de la raíz, 6.2): las llaves de un
    test no se suman al tope de 10 por cuenta del siguiente."""
    yield SignedMandatePoster(client, key_registrar)


# ── /verify es la verificación del comercio/agente (4.2, P-03) ───────────────

@pytest.fixture()
def service_key(monkeypatch):
    """Configura SERVICE_API_KEY para los módulos que verifican como el comercio/agente
    (se activa con `pytestmark = pytest.mark.usefixtures("service_key")`)."""
    monkeypatch.setenv("SERVICE_API_KEY", TEST_SERVICE_KEY)


def verify_as_service(client, attempt: dict, nonce: str | None = None):
    """POST /verify COMO SERVICIO (X-Service-Key), con un nonce único por intento si el
    test no fija uno: así verifica el comercio o el agente desde el 4.2."""
    import secrets

    body = dict(attempt)
    body.setdefault("nonce", nonce or secrets.token_hex(16))
    return client.post("/verify", json=body, headers={"X-Service-Key": TEST_SERVICE_KEY})
