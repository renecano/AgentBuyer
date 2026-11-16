# Fase 4 — Cerrar las rutas que seguían abiertas

Antes de esta fase, cinco rutas que usa React respondían a cualquiera, sin sesión: `POST /agent/run`, `POST /verify`, `GET /audit`, `POST /audit/reset` (registrada dos veces) y `POST /disputes/file`. Ahora todas exigen una credencial, y cada persona ve y opera **solo lo suyo**. `/verify` pasó a ser la verificación del comercio o del agente, con anti-replay y firma del agente. La demo dejó de llamarla desde el navegador.

Rama `fase-4-rutas`, commits `3466a2c` (4.1) y `9712c55` (4.2). Tests al cierre: **823 pytest + 240 Vitest**, CI verde. Decisiones aplicadas: P-03, P-04 y P-05, según las resoluciones vigentes de `docs/PLAN.md`.

## Garantías nuevas y el test que prueba cada una

| Garantía | Test |
|---|---|
| `/agent/run` exige sesión y ser dueño del mandato (o admin) | `tests/test_route_access.py::test_agent_run_matrix` |
| Cuota por usuario en `/agent/run` (P-16: 20 cada 24 h, configurable): 429 con `Retry-After`; un 422 previo a buscar no gasta cuota | `::test_agent_run_quota_429_with_retry_after`, `::test_agent_run_rejected_before_searching_does_not_spend_quota` |
| `GET /audit`: cada usuario ve sus mandatos y el admin ve todo (P-04) | `::test_audit_matrix_user_sees_only_own_and_admin_sees_all` |
| Una disputa exige ser dueño, y su evidencia no incluye eventos de otras personas | `::test_dispute_matrix`, `::test_dispute_evidence_has_no_foreign_events` |
| No se puede disputar un cargo ajeno bajo un mandato propio (antes salía "comercio responsable + reembolso") | `::test_cannot_dispute_someone_elses_attempt_under_your_own_mandate` |
| `GET /disputes` muestra lo propio | `::test_list_disputes_shows_only_own` |
| `/audit/reset` salió del producto: solo con `AUTH_DEV_MODE=true` y admin, y ya no está duplicada (P-05) | `::test_audit_reset_is_out_of_the_product`, `::test_audit_reset_is_registered_once` |
| Una escalación no se aprueba sobre un mandato revocado, pausado, vencido o firmado con una llave revocada | `::test_cannot_approve_escalation_on_revoked_or_paused_mandate`, `::test_cannot_approve_escalation_on_expired_mandate`, `::test_cannot_approve_escalation_when_the_signing_key_was_revoked`, `::test_strict_line_escalation_on_revoked_mandate_is_rejected` |
| `/verify` solo acepta la credencial `service` (P-03) | `tests/test_service_verify.py::test_verify_requires_a_service_credential` |
| Anti-replay: cada intento trae un nonce de un solo uso | `::test_replayed_nonce_is_rejected`, `::test_attempt_without_a_valid_nonce_is_rejected`, `::test_a_rejected_attempt_also_burns_its_nonce` |
| Si el intento declara la firma del agente, se verifica (y el agente firma sus intentos) | `::test_bad_agent_signature_is_rejected`, `::test_agent_runs_sign_their_attempts` |
| La moneda del intento debe ser la del mandato, en todo mandato | `::test_currency_must_match_on_every_mandate` |
| Los escenarios de la demo nunca compran y no se pueden disputar como compras | `::test_trap_offer_is_caught_and_never_buys`, `::test_a_scenario_that_would_approve_still_buys_nothing`, `::test_scenario_events_cannot_be_disputed_as_purchases` |
| Ninguna ruta que llama React queda sin seguridad | `tests/test_internal_endpoints_auth.py::test_each_internal_endpoint_declares_the_right_security_scheme` |

Prueba de mutación: 13 garantías rotas a propósito en el 4.1 y 10 en el 4.2. Todas se detectaron.

## Cambios de contrato (a propósito)

- **`POST /agent/run`, `GET /audit` y `POST /disputes/file`** exigen el token de la sesión. React ya lo enviaba en todas sus llamadas (`lib/api.ts`). El contrato de React lo congela en `tests/test_frontend_contract.py::test_react_routes_require_the_session_token`.
- **`POST /agent/run`:**
  - Puede responder 403 (no es el dueño) o 429 (cuota agotada, con `Retry-After`).
  - Acepta `scenario`: `"trap_offer"` o `"after_revocation"`. Un escenario desconocido da 422; uno que no aplica al estado del mandato da 409.
- **`POST /verify`:**
  - Solo la credencial `service`. React ya no la llama.
  - Exige `nonce`.
  - Checks nuevos: `nonce_fresh`, `agent_signature` (cuando se declara) y `currency` en todo mandato.
- **`POST /audit/reset`:** fuera del producto. Fuera de `AUTH_DEV_MODE` responde 404; dentro, solo admin. React ya no la llama: "empezar limpio" resetea solo el estado vivo del mandato, con un endpoint del dueño.
- **Ledger:** tipo de evento nuevo `scenario_verification`.

## Migraciones de comportamiento

- **El ledger ya no se borra al empezar una demo** (era "append-only" solo de nombre). El historial se conserva.
- **La vista Audit muestra a un usuario sus propios permisos**, con el título "Your permissions' record". Un admin ve el registro completo.
- **Actos 4 y 5 de la demo:** ahora son escenarios **explícitos** del servidor, con una oferta sintética rotulada como tal. Antes, el acto 4 **aprobaba** la "trampa": el firewall solo se activaba con palabras clave en español.

## Límites conocidos

- **`GET /audit/verify` sigue siendo anónimo** y expone el número de bloques del ledger.
- **El resumen del firewall sin LLM es un texto fijo.** Menciona un "upgrade" y una retención de 48 h aunque la trampa detectada sea otra. Lo corrige el 5.3, que reescribe esa heurística.
- **La cuota, los nonces de intento y las llaves del agente viven en memoria.** Se pierden al reiniciar; se persisten en la Fase 6.
- **El tope global diario de gasto en OpenAI llega con el despliegue** (9.1, P-16).

## Verificación en navegador (Chromium headless, modo autónomo)

- **Flujo completo:** login → registrar el dispositivo → firmar → compra aprobada → revocar → compra rechazada → Audit con solo los eventos propios y la cadena válida.
- **Demo de 5 actos con login:**

  | Acto | Resultado |
  |---|---|
  | 1 | Mandato firmado |
  | 2 y 3 | APPROVE |
  | 4 | REJECT por el firewall semántico |
  | 5 | REJECT por revocación |

  El navegador hizo cero llamadas a `/verify`.
