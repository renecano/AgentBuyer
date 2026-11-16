"""Cuotas por usuario (paso 4.1): cada corrida del agente consume búsqueda web real
(OpenAI), así que un usuario autenticado no puede dispararla sin límite.

Ventana deslizante por sujeto (email normalizado del token), en memoria como el resto
del estado efímero (OTP, challenges): se pierde al reiniciar. El punto donde se
conectaría Redis es esta clase (consume/refund son las dos únicas operaciones).

Configuración (P-16: por defecto 20 corridas por usuario cada 24 h):
    AGENT_RUN_QUOTA_PER_USER         corridas permitidas por ventana   (default 20)
    AGENT_RUN_QUOTA_WINDOW_SECONDS   largo de la ventana en segundos   (default 86400)
El tope GLOBAL diario de gasto llega con el despliegue (9.1, P-16).
"""
from __future__ import annotations

import math
import threading
import time
from typing import Callable, Dict, List

from core.email_otp import env_positive_int

DEFAULT_AGENT_RUNS_PER_USER = 20
DEFAULT_AGENT_RUN_WINDOW_SECONDS = 24 * 60 * 60


class QuotaExceeded(Exception):
    """El sujeto agotó su cuota; `retry_after_seconds` es cuándo vuelve a tener una."""

    def __init__(self, retry_after_seconds: int):
        super().__init__(f"Quota exceeded. Retry in {retry_after_seconds}s.")
        self.retry_after_seconds = retry_after_seconds


class PerSubjectQuota:
    def __init__(self, limit: int, window_seconds: int, clock: Callable[[], float] = time.time):
        if limit <= 0 or window_seconds <= 0:
            raise ValueError("La cuota y su ventana deben ser positivas.")
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._uses: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    @classmethod
    def agent_runs_from_env(cls) -> "PerSubjectQuota":
        return cls(
            limit=env_positive_int("AGENT_RUN_QUOTA_PER_USER", DEFAULT_AGENT_RUNS_PER_USER),
            window_seconds=env_positive_int("AGENT_RUN_QUOTA_WINDOW_SECONDS", DEFAULT_AGENT_RUN_WINDOW_SECONDS),
        )

    def consume(self, subject: str) -> None:
        """Toma un uso de la cuota de `subject` o lanza QuotaExceeded (sin tomarlo)."""
        key = subject.strip().lower()
        with self._lock:
            now = self._clock()
            recent = [used_at for used_at in self._uses.get(key, []) if now - used_at < self.window_seconds]
            if len(recent) >= self.limit:
                self._uses[key] = recent
                raise QuotaExceeded(max(1, math.ceil(self.window_seconds - (now - recent[0]))))
            recent.append(now)
            self._uses[key] = recent

    def refund(self, subject: str) -> None:
        """Devuelve el último uso (la corrida no llegó a buscar: p. ej. un 422 previo)."""
        key = subject.strip().lower()
        with self._lock:
            if self._uses.get(key):
                self._uses[key].pop()

    def clear(self) -> None:
        with self._lock:
            self._uses.clear()
