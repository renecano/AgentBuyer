# IA en AgentBuyer: qué decide el modelo y qué decide el código

> Base de la sección "IA responsable" del README (Fase 12). Escrito en el paso 5.3; cada afirmación enlaza al código y al test que la respaldan.

## La regla de oro

**El LLM nunca puede aprobar lo que el código determinista rechazó.** Al firewall semántico solo se le pregunta por compras que el engine ya aprobó. Puede **bajar** el veredicto (a ESCALATE o REJECT), nunca subirlo.

- Código: `api/verify.py` (paso 4, "Firewall semántico"). La línea estricta (`core/verify.py`) se retiró en el 7.2.
- Test: `tests/test_llm_layer.py::test_the_llm_cannot_approve_what_the_engine_did_not`. El engine escala una compra sobre el tope, un LLM simulado dice "APPROVE", y el veredicto sigue en ESCALATE: al LLM ni siquiera se le pregunta.

## Quién decide qué

| Decisión | Quién | Dónde |
|---|---|---|
| ¿El titular firmó **este** mandato con **su** llave registrada y activa? | Código (Ed25519, determinista) | `core/signed_mandates.py` |
| ¿Monto, moneda, categoría, comercio, usos, `price_below`, presupuesto mensual? | Código (enteros de centavos, igualdad exacta) | `engine/evaluator.py` |
| ¿El intento es nuevo (anti-replay) y lo firmó el agente que lo presenta? | Código | `api/verify.py`, `core/agent_keys.py` |
| ¿El comercio es el que dice ser? | Código: el dominio de la URL de la oferta, **no** el nombre que afirma el LLM | `core/merchant_identity.py` |
| ¿Qué ofertas existen en la web? | LLM con búsqueda web; el código valida cada oferta (forma, precio exacto en centavos, URL verificable) | `core/merchant_search.py`, `core/agent_loop.py` |
| ¿La letra chica esconde una trampa (cargos aparte, equivalentes de efectivo, condiciones abusivas)? | LLM si está configurado; si no, una heurística determinista. Solo puede bajar el veredicto | `core/semantic_firewall.py` |

## Cuando el LLM falla: fail-closed

Todo pasa por un único cliente: `core/llm.py`.

- **Modelo:** configurable con `OPENAI_MODEL`. El default es `gpt-6-luna`, verificado el 16 nov 2026 en la documentación oficial.
- **Timeout y reintentos:** acotados (`LLM_TIMEOUT_SECONDS`, `LLM_MAX_RETRIES`).
- **Presupuesto por request:** tope de tokens de salida (`LLM_MAX_OUTPUT_TOKENS`, default 2000). Una respuesta cortada por el tope llega incompleta y se descarta: no se usa JSON a medias. Test: `test_an_answer_cut_by_the_token_budget_is_not_used`.
- **Sin claves en los logs:** se registra el tipo de fallo y el código HTTP; nunca la clave ni el cuerpo del error.

| Falla | Efecto | Test |
|---|---|---|
| Sin `OPENAI_API_KEY` | Búsqueda: "sin ofertas" (no se inventan). Firewall: heurística determinista | `test_without_api_key_the_llm_is_unavailable_not_guessed` |
| Timeout, error HTTP, sin conexión | `LLMError`. Firewall → ESCALATE (decide la persona). Búsqueda → sin ofertas | `test_sdk_failures_become_llm_errors_without_leaking_secrets`, `test_firewall_llm_failures_never_approve`, `test_web_search_goes_through_the_single_client_and_fails_closed` |
| Respuesta mal formada o veredicto desconocido | ESCALATE; nunca APPROVE | `test_malformed_structured_answer_is_an_error`, `test_firewall_llm_failures_never_approve` |

El texto de una oferta se trata como **dato no confiable**. El prompt del sistema le indica al modelo que ignore cualquier instrucción que venga dentro de ese texto. Aun así, un intento de inyección que lograra que el modelo dijera "APPROVE" no podría aprobar nada que el engine no hubiera aprobado ya.

## Qué datos salen hacia el proveedor del LLM

- **Búsqueda web:** los `search_fields` del mandato (origen, destino, fechas) y el nombre de la categoría. Nunca la identidad de la persona.
- **Firewall:** el tope por compra, la moneda, las categorías autorizadas, y el título, la descripción, el precio y la metadata de la oferta.
- **Nunca salen** el email, el documento, el teléfono, las llaves ni las firmas.

## Límites conocidos

- **La heurística sin LLM es deliberadamente simple.** Detecta:
  - equivalentes de efectivo (gift cards, vouchers, cripto);
  - cargos fuera del precio, extrayendo el monto de una mención de dinero real;
  - retenciones o escalas de 48 h o más.

  No entiende contexto; ante cargos de monto desconocido o condiciones raras, escala. Esto lo prueban `test_heuristic_reads_english_and_spanish_and_says_what_it_found` y `test_heuristic_no_longer_flags_charges_because_of_a_10_or_20`.
- **La identidad del comercio por dominio no usa la Public Suffix List completa.** Cubre `www.` y los sufijos de segundo nivel comunes (`com.ar`, `co.uk`…). Un dominio exótico puede derivar mal; el efecto es fail-closed, porque el comercio no coincide con `allowed_merchants` y la compra escala o se rechaza.
- **El modelo por defecto se verificó en una fecha concreta.** Si se retira, la búsqueda falla cerrado: no hay ofertas, y no se inventan.
