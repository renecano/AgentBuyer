"""Política del código de verificación por email (OTP): emisión, TTL, uso único,
límite de intentos y rate limit por destino.

No envía correos ni conoce HTTP: api/auth.py orquesta el envío y las respuestas.
El código nunca se guarda en claro (solo un HMAC con una clave aleatoria del
proceso) y ningún mensaje de esta capa lo incluye.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

CODE_DIGITS = 6


class OtpCheck(str, Enum):
    VALID = "valid"
    INVALID = "invalid"      # código incorrecto, quedan intentos
    EXPIRED = "expired"
    LOCKED = "locked"        # se agotaron los intentos: el código quedó invalidado
    NO_CODE = "no_code"      # no hay código pendiente para ese email


class OtpRateLimited(Exception):
    """Se pidieron demasiados códigos para el mismo email."""

    def __init__(self, retry_after_seconds: int):
        super().__init__("Too many verification code requests for this email.")
        self.retry_after_seconds = retry_after_seconds


@dataclass
class _PendingCode:
    digest: bytes
    expires_at: float
    failed_attempts: int = 0


def _env_positive_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} debe ser un entero positivo (recibido {raw!r}).") from None
    if value <= 0:
        raise ValueError(f"{name} debe ser un entero positivo (recibido {raw!r}).")
    return value


class EmailOtpService:
    def __init__(
        self,
        ttl_seconds: int = 600,
        max_attempts: int = 5,
        resend_cooldown_seconds: int = 60,
        max_sends_per_window: int = 5,
        send_window_seconds: int = 3600,
        clock: Callable[[], float] = time.time,
    ):
        self.ttl_seconds = ttl_seconds
        self.max_attempts = max_attempts
        self.resend_cooldown_seconds = resend_cooldown_seconds
        self.max_sends_per_window = max_sends_per_window
        self.send_window_seconds = send_window_seconds
        self._clock = clock
        self._key = secrets.token_bytes(32)
        self._codes: dict[str, _PendingCode] = {}
        self._sends: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls) -> "EmailOtpService":
        return cls(
            ttl_seconds=_env_positive_int("AUTH_OTP_TTL_SECONDS", 600),
            max_attempts=_env_positive_int("AUTH_OTP_MAX_ATTEMPTS", 5),
            resend_cooldown_seconds=_env_positive_int("AUTH_OTP_RESEND_COOLDOWN_SECONDS", 60),
            max_sends_per_window=_env_positive_int("AUTH_OTP_MAX_SENDS_PER_HOUR", 5),
            send_window_seconds=3600,
        )

    def _digest(self, email: str, code: str) -> bytes:
        return hmac.new(self._key, f"{email}:{code}".encode("utf-8"), hashlib.sha256).digest()

    def issue(self, email: str) -> str:
        """Emite un código nuevo para `email` (reemplaza al anterior y reinicia los
        intentos). Lanza OtpRateLimited si se supera el cooldown o el máximo por
        ventana; el pedido cuenta para el límite aunque luego falle el envío."""
        with self._lock:
            now = self._clock()
            history = [sent_at for sent_at in self._sends.get(email, []) if now - sent_at < self.send_window_seconds]
            if history and now - history[-1] < self.resend_cooldown_seconds:
                raise OtpRateLimited(math.ceil(self.resend_cooldown_seconds - (now - history[-1])))
            if len(history) >= self.max_sends_per_window:
                raise OtpRateLimited(math.ceil(self.send_window_seconds - (now - history[0])))

            history.append(now)
            self._sends[email] = history
            code = f"{secrets.randbelow(10 ** CODE_DIGITS):0{CODE_DIGITS}d}"
            self._codes[email] = _PendingCode(digest=self._digest(email, code), expires_at=now + self.ttl_seconds)
            return code

    def invalidate(self, email: str) -> None:
        with self._lock:
            self._codes.pop(email, None)

    def verify(self, email: str, code: str) -> OtpCheck:
        """Uso único: un código válido se borra al verificarse. Uno expirado o que
        agota los intentos también se borra."""
        with self._lock:
            pending = self._codes.get(email)
            if pending is None:
                return OtpCheck.NO_CODE
            if self._clock() >= pending.expires_at:
                del self._codes[email]
                return OtpCheck.EXPIRED
            if hmac.compare_digest(pending.digest, self._digest(email, code.strip())):
                del self._codes[email]
                return OtpCheck.VALID
            pending.failed_attempts += 1
            if pending.failed_attempts >= self.max_attempts:
                del self._codes[email]
                return OtpCheck.LOCKED
            return OtpCheck.INVALID
