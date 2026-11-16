"""Cuotas por usuario (paso 4.1): cada corrida del agente consume búsqueda web real
(OpenAI), así que un usuario autenticado no puede dispararla sin límite.

Ventana deslizante por sujeto (email normalizado del token). Desde el 6.3 se guarda en
la base (tabla quota_usage): es un control de COSTO (P-16), no un rate limit
anti-abuso, y en memoria cada despliegue regalaba corridas. La decisión "contar e
insertar" es una transacción BEGIN IMMEDIATE: dos corridas simultáneas no pasan el tope.

Configuración (P-16: por defecto 20 corridas por usuario cada 24 h):
    AGENT_RUN_QUOTA_PER_USER         corridas permitidas por ventana   (default 20)
    AGENT_RUN_QUOTA_WINDOW_SECONDS   largo de la ventana en segundos   (default 86400)
El tope GLOBAL diario de gasto llega con el despliegue (9.1, P-16): esta tabla es la
contabilidad sobre la que se apoyará.
"""
from __future__ import annotations

import math
import time
from typing import Callable

from sqlalchemy import and_, delete, func, insert, select

from core.db import write_tx
from core.db_schema import quota_usage as USAGE
from core.email_otp import env_positive_int

DEFAULT_AGENT_RUNS_PER_USER = 20
DEFAULT_AGENT_RUN_WINDOW_SECONDS = 24 * 60 * 60


class QuotaExceeded(Exception):
    """El sujeto agotó su cuota; `retry_after_seconds` es cuándo vuelve a tener una."""

    def __init__(self, retry_after_seconds: int):
        super().__init__(f"Quota exceeded. Retry in {retry_after_seconds}s.")
        self.retry_after_seconds = retry_after_seconds


class PerSubjectQuota:
    def __init__(self, limit: int, window_seconds: int, clock: Callable[[], float] = time.time, bucket: str = "agent_run"):
        if limit <= 0 or window_seconds <= 0:
            raise ValueError("The quota and its window must be positive.")
        self.limit = limit
        self.window_seconds = window_seconds
        self.bucket = bucket
        self._clock = clock

    @classmethod
    def agent_runs_from_env(cls) -> "PerSubjectQuota":
        return cls(
            limit=env_positive_int("AGENT_RUN_QUOTA_PER_USER", DEFAULT_AGENT_RUNS_PER_USER),
            window_seconds=env_positive_int("AGENT_RUN_QUOTA_WINDOW_SECONDS", DEFAULT_AGENT_RUN_WINDOW_SECONDS),
        )

    def _mine(self, key: str):
        return and_(USAGE.c.bucket == self.bucket, USAGE.c.subject == key)

    def consume(self, subject: str) -> None:
        """Toma un uso de la cuota de `subject` o lanza QuotaExceeded (sin tomarlo)."""
        key = subject.strip().lower()
        with write_tx() as connection:
            now = self._clock()
            # Los usos fuera de la ventana ya no cuentan: se olvidan.
            connection.execute(delete(USAGE).where(and_(self._mine(key), USAGE.c.used_at <= now - self.window_seconds)))
            used, oldest = connection.execute(
                select(func.count(), func.min(USAGE.c.used_at)).where(self._mine(key))
            ).one()
            if used >= self.limit:
                raise QuotaExceeded(max(1, math.ceil(self.window_seconds - (now - oldest))))
            connection.execute(insert(USAGE).values(bucket=self.bucket, subject=key, used_at=now))

    def refund(self, subject: str) -> None:
        """Devuelve el último uso (la corrida no llegó a buscar: p. ej. un 422 previo)."""
        key = subject.strip().lower()
        with write_tx() as connection:
            last = connection.execute(select(func.max(USAGE.c.id)).where(self._mine(key))).scalar_one()
            if last is not None:
                connection.execute(delete(USAGE).where(USAGE.c.id == last))

    def clear(self) -> None:
        with write_tx() as connection:
            connection.execute(delete(USAGE).where(USAGE.c.bucket == self.bucket))
