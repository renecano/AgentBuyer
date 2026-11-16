# Fase 5 — Motor de decisión

Esta fase rehízo el corazón de la decisión: el dinero pasa a ser exacto, las reglas ya no tienen huecos que dejen pasar compras, el consumo es atómico y la capa de IA es honesta. Antes los montos eran flotantes y la categoría se comparaba por substring. Además, un mandato sin límite aprobaba todo, dos compras simultáneas podían superar `max_uses` y el firewall solo se activaba con palabras clave en español. Había cuatro clientes LLM, y uno de ellos con un modelo que no existe.

Rama `fase-5-motor`: commits `fc9f9ec` (5.1), `bf5c80d` (5.2) y `b03efe5` (5.3). Tests al cierre: **925 pytest + 240 Vitest**, CI verde. Decisiones aplicadas: P-09 y P-15, según las resoluciones vigentes de `docs/PLAN.md`.

## Garantías nuevas y el test que prueba cada una

| Garantía | Test |
|---|---|
| Todo el dinero es entero de centavos con moneda explícita: mandato, intento, estado vivo, ledger y ofertas. La conversión es exacta y solo en los bordes | `tests/test_money_and_rules.py::test_spend_accumulates_exactly_in_cents`, `::test_signed_mandate_is_stored_in_cents`, `core/tests/test_merchant_search.py::test_offer_price_that_is_not_exact_cents_is_dropped` |
| Un monto inválido (≤ 0, no entero, bool) o una moneda distinta se rechazan, no escalan | `engine/tests/test_evaluator.py::test_invalid_amount_is_rejected_not_escalated`, `::test_currency_mismatch_is_rejected` |
| Un mandato sin límite de monto, categorías o comercios no autoriza nada | `::test_mandate_without_amount_limit_is_rejected`, `::test_mandate_without_categories_or_merchants_is_rejected` |
| Categoría y comercio por igualdad exacta normalizada: `travel` ≠ `travel_giftcards`; `*` solo si está escrito | `::test_category_is_exact_normalized_equality`, `::test_merchant_is_exact_normalized_equality` |
| Gramática: un campo ausente no cumple `!=`; hay topes contra la repetición gigante, la profundidad y el largo | `::test_missing_field_does_not_satisfy_not_equal`, `::test_sequence_repetition_is_bounded`, `::test_deep_or_long_expressions_fail_closed` |
| Solo un mandato activo compra: un mandato **pausado** aprobaba en la línea de React | `tests/test_money_and_rules.py::test_paused_mandate_is_rejected_on_the_react_line`, `::test_non_active_mandate_is_rejected_on_the_strict_line` |
| El agente no intenta lo que no cabe, y usa la misma regla que el engine | `::test_agent_does_not_attempt_when_no_offer_fits`, `::test_agent_uses_the_same_price_rule_as_the_engine` |
| Verificar y consumir es atómico: 50 compras simultáneas contra `max_uses=3` → exactamente 3 | `tests/test_atomic_budget.py::test_fifty_concurrent_purchases_against_max_uses_3_approve_exactly_3`, `::test_concurrent_purchases_never_exceed_the_monthly_budget` |
| Presupuesto mensual por mes calendario UTC, que se reinicia solo | `::test_monthly_budget_is_applied_and_resets_with_the_calendar_month`, `::test_month_boundary_is_utc` |
| Un solo cliente LLM con un modelo verificado; fail-closed y sin claves en los logs | `tests/test_llm_layer.py::test_sdk_failures_become_llm_errors_without_leaking_secrets`, `::test_config_defaults_to_the_verified_model_and_is_overridable` |
| El LLM nunca aprueba lo que el engine no aprobó; si el firewall dice ESCALATE, escala; un fallo nunca aprueba | `::test_the_llm_cannot_approve_what_the_engine_did_not`, `::test_firewall_escalate_escalates_on_the_react_line`, `::test_firewall_llm_failures_never_approve` |
| La heurística sin LLM no inventa cargos y dice lo que encontró; el juez usa palabras completas, no substrings | `::test_heuristic_no_longer_flags_charges_because_of_a_10_or_20`, `::test_heuristic_reads_english_and_spanish_and_says_what_it_found`, `::test_judge_uses_word_boundaries_not_substrings` |
| El comercio es el del dominio de la oferta, no el que afirma el LLM | `::test_merchant_claimed_by_the_llm_different_from_the_domain_is_rejected`, `::test_agent_uses_the_domain_merchant_not_the_claimed_name` |

Prueba de mutación: se detectaron las 15 mutaciones del 5.1, las 6 del 5.2 (incluida quitar el lock) y las 11 del 5.3. Dos tests pasaban por la razón equivocada y se afinaron.

## Hallazgos que vale la pena conocer

- **El modelo de la búsqueda web real (`gpt-5.6`) no es un ID válido de OpenAI.** Se verificó en la documentación oficial el 16 nov 2026. En producción, toda búsqueda habría fallado y el agente habría dicho siempre "no encontré ofertas". El default nuevo, `gpt-6-luna`, está verificado: soporta Responses, Structured Outputs y `web_search`. Además, `gpt-4o`, `gpt-4o-mini` y `gpt-4.1-mini` están deprecados.
- **Un mandato pausado aprobaba compras** en la línea de React: el check de estado solo miraba revocado y vencido.
- **La "trampa" del acto 4 de la demo**, cuando todavía llamaba a `/verify` antes del 4.2, se aprobaba: el firewall solo se activaba con palabras en español.

## Cambios de contrato (a propósito)

- **Dinero en centavos en todo el contrato de React:**
  - `constraints.max_amount_per_purchase_cents`
  - `conditions[].value_cents`
  - `live_state.amount_spent_cents`
  - `flights_seen[].price_cents`
  - `attempt.purchase.amount_cents` y `metadata.price_cents`

  React convierte a dólares solo al mostrar, y ya no redondea $139.99 a $140.
- **`/verify`:**
  - Un mandato pausado, o un intento con un monto inválido, se rechaza.
  - Si la oferta trae URL, el comercio debe coincidir con su dominio (`merchant_identity`).
  - El firewall revisa toda compra aprobable; ESCALATE escala.
  - Si la reserva atómica se pierde por una compra simultánea, el intento se re-evalúa con el estado fresco.
- **`/agent/run`:** si ninguna oferta cabe en el mandato, responde `no_fit: true` sin intento de compra. La escalación por el agente es la del comercio fuera del mandato.
- **Engine:** REJECT, en vez de ESCALATE o APPROVE, para los defectos duros descritos arriba.

## Límites conocidos

- **La spec firmada v1 no lleva `monthly_budget` (D-17).** El presupuesto mensual se aplica donde está declarado: el seed y la línea estricta. En un mandato firmado, el gasto total ya lo acota `max_uses × tope por compra`.
- **La identidad por dominio no usa la Public Suffix List completa.** Un dominio exótico falla cerrado: escala o se rechaza.
- **La heurística sin LLM es deliberadamente simple** y escala ante la duda.
- **`mandate/intelligent_issuer.py` conserva su propio cliente LLM.** Es legado y se retira en el 7.2 (P-08).

## Verificación en navegador (Chromium headless, modo autónomo)

- **Flujo completo:** login → registrar el dispositivo → firmar → compra aprobada → revocar → compra rechazada → Audit válido.
- **Demo de 5 actos:**

  | Acto | Resultado |
  |---|---|
  | 2 y 3 | APPROVE |
  | 4 | REJECT, con un resumen que describe la trampa real (gift card + cargo aparte + retención de 48 h) |
  | 5 | REJECT por revocación |

Sin errores de consola.
