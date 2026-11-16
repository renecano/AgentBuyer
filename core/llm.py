"""Cliente LLM ÚNICO del backend (paso 5.3, P-15).

Antes había cuatro clientes con cuatro modelos distintos ("gpt-5.6", "gpt-4o",
"gpt-4o-mini", "gpt-4.1-mini"), dos APIs y parseo manual de .env. Ahora todo pasa
por aquí:

- Modelo por entorno (OPENAI_MODEL). Default VERIFICADO al implementar (16 nov 2026,
  https://developers.openai.com/api/docs/models/gpt-6-luna): `gpt-6-luna` soporta la
  Responses API, Structured Outputs y la herramienta web_search, y es el más barato
  de la línea actual. Hallazgo de la verificación: el default anterior de la
  búsqueda web, "gpt-5.6", NO es un ID válido (la búsqueda real habría fallado
  siempre, y el agente habría dicho "no encontré ofertas"); gpt-4o, gpt-4o-mini y
  gpt-4.1-mini están deprecados.
- Timeout por request (LLM_TIMEOUT_SECONDS, 20 s) y reintentos acotados
  (LLM_MAX_RETRIES, 1), a cargo del SDK.
- Fail-closed: cualquier problema (sin clave, timeout, error HTTP, respuesta mal
  formada) es un LLMError con un `kind`. NUNCA un veredicto: decidir qué significa
  un fallo es del llamador (que nunca aprueba por él).
- Sin secretos en logs: se registra el `kind` y el código HTTP, jamás la clave, los
  headers ni el cuerpo de la respuesta de error.

Costura de tests (R15): set_llm_client(fake) sustituye el cliente; ningún test llama
a la red.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional, Protocol

from core.email_otp import env_positive_int

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gpt-6-luna"
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_MAX_RETRIES = 1
# Presupuesto por request (P-15): tope de tokens de salida. Las respuestas estructuradas
# son de unos cientos de tokens y la búsqueda devuelve una lista JSON corta; una respuesta
# que choca con el tope llega incompleta y se trata como inusable (fail-closed).
DEFAULT_MAX_OUTPUT_TOKENS = 2000


def _env_non_negative_int(name: str, default: int) -> int:
    """Entero ≥ 0 del entorno (0 reintentos es válido). Mal formado → ValueError (no se adivina)."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} debe ser un entero ≥ 0 (recibido {raw!r}).") from None
    if value < 0:
        raise ValueError(f"{name} debe ser un entero ≥ 0 (recibido {raw!r}).")
    return value


class LLMError(Exception):
    """Fallo del LLM. `kind`: unavailable | timeout | upstream | malformed."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class LLMConfig:
    model: str
    timeout_seconds: int
    max_retries: int
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS

    @classmethod
    def from_env(cls) -> "LLMConfig":
        model = (os.getenv("OPENAI_MODEL") or "").strip() or DEFAULT_MODEL
        return cls(
            model=model,
            timeout_seconds=env_positive_int("LLM_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS),
            max_retries=_env_non_negative_int("LLM_MAX_RETRIES", DEFAULT_MAX_RETRIES),
            max_output_tokens=env_positive_int("LLM_MAX_OUTPUT_TOKENS", DEFAULT_MAX_OUTPUT_TOKENS),
        )


class LLMClient(Protocol):
    def structured(self, *, system: str, user: str, schema_name: str, schema: dict) -> dict: ...

    def web_search(self, prompt: str) -> str: ...


class OpenAIResponsesClient:
    """Implementación sobre la Responses API del SDK oficial (openai==3.14.1, fijado)."""

    def __init__(self, api_key: str, config: LLMConfig):
        from openai import OpenAI

        self._config = config
        self._client = OpenAI(api_key=api_key, timeout=config.timeout_seconds, max_retries=config.max_retries)

    def _call(self, operation: str, **kwargs: Any) -> Any:
        import openai

        try:
            response = self._client.responses.create(
                model=self._config.model, max_output_tokens=self._config.max_output_tokens, **kwargs)
        except openai.APITimeoutError:
            logger.warning("llm %s: timeout (model=%s)", operation, self._config.model)
            raise LLMError("timeout", "The AI service did not answer in time.") from None
        except openai.APIStatusError as error:
            logger.warning("llm %s: HTTP %s (model=%s)", operation, error.status_code, self._config.model)
            raise LLMError("upstream", f"The AI service returned HTTP {error.status_code}.") from None
        except openai.APIError as error:
            logger.warning("llm %s: %s (model=%s)", operation, type(error).__name__, self._config.model)
            raise LLMError("upstream", "The AI service could not be reached.") from None
        if getattr(response, "status", None) == "incomplete":
            # Cortada por el presupuesto de tokens (u otra causa): no se usa a medias.
            logger.warning("llm %s: incomplete answer (model=%s)", operation, self._config.model)
            raise LLMError("malformed", "The AI service returned an incomplete answer.")
        return response

    def structured(self, *, system: str, user: str, schema_name: str, schema: dict) -> dict:
        response = self._call(
            "structured",
            instructions=system,
            input=user,
            text={"format": {"type": "json_schema", "name": schema_name, "schema": schema, "strict": True}},
        )
        try:
            parsed = json.loads(response.output_text)
        except (TypeError, ValueError, AttributeError):
            raise LLMError("malformed", "The AI service returned an unreadable answer.") from None
        if not isinstance(parsed, dict):
            raise LLMError("malformed", "The AI service returned an answer with the wrong shape.")
        return parsed

    def web_search(self, prompt: str) -> str:
        # tool_choice "required": sin él el modelo puede contestar sin buscar (docs de web_search).
        response = self._call("web_search", tools=[{"type": "web_search"}], tool_choice="required", input=prompt)
        text = getattr(response, "output_text", None)
        if not isinstance(text, str):
            raise LLMError("malformed", "The AI service returned no text.")
        return text


_override: Optional[LLMClient] = None


def set_llm_client(client: Optional[LLMClient]) -> None:
    """Costura de tests: sustituye el cliente (None vuelve al real)."""
    global _override
    _override = client


def get_llm() -> LLMClient:
    """El cliente configurado. Sin OPENAI_API_KEY → LLMError("unavailable")."""
    if _override is not None:
        return _override
    api_key = (os.getenv("OPENAI_API_KEY") or "").strip()
    if not api_key:
        raise LLMError("unavailable", "The AI service is not configured.")
    return OpenAIResponsesClient(api_key, LLMConfig.from_env())


def llm_configured() -> bool:
    return _override is not None or bool((os.getenv("OPENAI_API_KEY") or "").strip())
