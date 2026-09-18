"""Challenges para la PRUEBA DE POSESIÓN al registrar una llave (sub-pasos 2.3/2.4).

Flujo completo (el 2.4 añade el último paso a POST /keys):

    1. POST /keys/step-up/start   (sesión)            → OTP de step-up al email DEL TOKEN
    2. POST /keys/challenge {code} (sesión + OTP)      → {challenge_id, nonce, expires_in}
    3. el cliente firma registration_message(...) con su privada (no extraíble)
    4. POST /keys {public_key, challenge_id, signature} → consume() + verificar firma → registrar

El challenge ES la prueba del step-up: solo existe si alguien presentó, con esa
misma sesión, un OTP fresco del email del dueño. Un token robado sin acceso al
correo no puede obtener challenges, y sin challenge (2.4) no se registra ninguna
llave. Por eso el challenge es corto (120 s), de un solo uso y atado a su dueño.

Memoria: cada challenge cuesta un OTP válido (con rate limit por email), así que
no hace falta un tope propio; los vencidos se purgan al emitir.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict

from core.owner_keys import normalize_owner_email, validate_public_key
from mandate.canonical import canonicalize
from mandate.sign import verify_ed25519_bytes

CHALLENGE_TTL_SECONDS = 120
NONCE_BYTES = 32  # 256 bits

# Separación de dominio: una firma de registro nunca puede pasar por la firma de
# un mandato (que tendrá su propio purpose en el paso 3), ni al revés. La versión
# permite cambiar el formato en el futuro sin ambigüedad sobre qué se firmó.
REGISTER_KEY_PURPOSE = "agentbuyer:register-key:v1"


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    owner_email: str
    nonce: str          # hex, NONCE_BYTES bytes
    expires_at: float   # epoch en segundos


class ChallengeRejection(str, Enum):
    UNKNOWN = "unknown"          # nunca emitido (o ya purgado tras vencer)
    EXPIRED = "expired"
    USED = "used"
    WRONG_OWNER = "wrong_owner"


class ChallengeRejected(Exception):
    def __init__(self, reason: ChallengeRejection):
        super().__init__(f"Challenge rejected: {reason.value}.")
        self.reason = reason


@dataclass
class _Entry:
    challenge: Challenge
    used: bool = False


class KeyChallengeService:
    def __init__(self, ttl_seconds: int = CHALLENGE_TTL_SECONDS, clock: Callable[[], float] = time.time):
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._entries: Dict[str, _Entry] = {}
        self._lock = threading.Lock()

    def issue(self, owner_email: str) -> Challenge:
        """Emite un challenge para `owner_email`. Quien llama ya exigió el step-up OTP."""
        owner = normalize_owner_email(owner_email)
        with self._lock:
            now = self._clock()
            self._purge_expired(now)
            challenge = Challenge(
                challenge_id=f"chl_{secrets.token_hex(16)}",
                owner_email=owner,
                nonce=secrets.token_hex(NONCE_BYTES),
                expires_at=now + self.ttl_seconds,
            )
            self._entries[challenge.challenge_id] = _Entry(challenge)
            return challenge

    def consume(self, challenge_id: str, owner_email: str) -> Challenge:
        """Toma el challenge para su dueño, UNA sola vez. Lanza ChallengeRejected si
        no existe, venció, ya se usó o es de otra cuenta.

        Se marca usado ANTES de que el llamador verifique la firma (2.4): un intento
        con firma mala también lo quema, así no sirve para probar firmas a ciegas.
        Presentarlo desde OTRA cuenta no lo quema (esa cuenta no puede usarlo, y así
        tampoco puede sabotear el registro legítimo del dueño)."""
        owner = normalize_owner_email(owner_email)
        with self._lock:
            entry = self._entries.get(challenge_id)
            if entry is None:
                raise ChallengeRejected(ChallengeRejection.UNKNOWN)
            if entry.challenge.owner_email != owner:
                raise ChallengeRejected(ChallengeRejection.WRONG_OWNER)
            if entry.used:
                raise ChallengeRejected(ChallengeRejection.USED)
            if self._clock() >= entry.challenge.expires_at:
                del self._entries[challenge_id]
                raise ChallengeRejected(ChallengeRejection.EXPIRED)
            entry.used = True
            return entry.challenge

    def _purge_expired(self, now: float) -> None:
        for challenge_id in [cid for cid, e in self._entries.items() if now >= e.challenge.expires_at]:
            del self._entries[challenge_id]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


def registration_payload(challenge_id: str, nonce: str, owner_email: str, public_key: str) -> dict:
    """Los campos EXACTOS que se firman para registrar una llave (antes de canonicalizar).

    - owner: normalizado (trim + minúsculas), igual que el subject del token.
    - public_key: hex Ed25519 canónico en minúsculas (se valida; mal formada → error).
    - challenge_id / nonce: tal cual los devolvió POST /keys/challenge.
    """
    if not isinstance(challenge_id, str) or not challenge_id:
        raise ValueError("challenge_id es obligatorio.")
    if not isinstance(nonce, str) or not nonce:
        raise ValueError("nonce es obligatorio.")
    return {
        "purpose": REGISTER_KEY_PURPOSE,
        "challenge_id": challenge_id,
        "nonce": nonce,
        "owner": normalize_owner_email(owner_email),
        "public_key": validate_public_key(public_key),
    }


def registration_message(challenge_id: str, nonce: str, owner_email: str, public_key: str) -> bytes:
    """Bytes que el cliente firma con Ed25519: la canonicalización compartida (2.0,
    mandate/canonical.py) de registration_payload(). El frontend debe reproducirlos
    byte por byte; shared/key_registration_vectors.json fija ejemplos exactos."""
    return canonicalize(registration_payload(challenge_id, nonce, owner_email, public_key))


class InvalidProofSignature(Exception):
    """La firma no prueba posesión de la privada de ESA pubkey para ESTE challenge."""


def verify_proof_of_possession(
    service: KeyChallengeService,
    owner_email: str,
    public_key: str,
    challenge_id: str,
    signature_hex: str,
) -> str:
    """Prueba de posesión de un registro de llave (sub-paso 2.4). Devuelve la pubkey
    canónica (hex en minúsculas) si la prueba es válida; si no, lanza.

    Orden, y por qué:
    1. validate_public_key → InvalidPublicKey. Un formato roto es un error del cliente,
       no un intento de firma: NO consume el challenge (se puede reintentar).
    2. service.consume(challenge_id, owner) → ChallengeRejected. Deja el challenge
       USADO antes de mirar la firma: cada challenge admite UN solo intento de firma,
       así que no sirve para probar firmas a ciegas.
    3. Reconstruye registration_message con el owner DEL TOKEN, la pubkey PRESENTADA y
       el challenge_id/nonce DEL SERVIDOR (el cliente no aporta nonce: no puede elegir
       qué se firma), y verifica la firma Ed25519 sobre esos bytes exactos contra esa
       misma pubkey → InvalidProofSignature.

    Como la pubkey va DENTRO del mensaje y además es la llave que verifica, la firma
    prueba posesión de la privada de exactamente la pubkey que se va a registrar.
    """
    owner = normalize_owner_email(owner_email)
    key = validate_public_key(public_key)
    challenge = service.consume(challenge_id, owner)
    message = registration_message(challenge.challenge_id, challenge.nonce, owner, key)
    if not verify_ed25519_bytes(key, message, signature_hex):
        raise InvalidProofSignature("The signature does not prove possession of this key for this challenge.")
    return key
