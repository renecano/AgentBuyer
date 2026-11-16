# Fase 6 — Persistencia

Antes de esta fase, **todo** el estado vivía en diccionarios del proceso. Un reinicio borraba mandatos, llaves registradas, el ledger "a prueba de manipulación" y los nonces anti-replay. Ahora el estado que importa vive en SQLite (SQLAlchemy 2 Core + Alembic, P-10). Las invariantes las hace cumplir **la base**, no solo el código: el ledger es append-only en la propia base, y la API verifica la cadena completa antes de arrancar.

Rama `fase-6-persistencia`:

| Commit | Paso |
|---|---|
| `4e053bd` | Complemento P-15: presupuesto de tokens por request, que faltaba en el 5.3 |
| `7db1331` | 6.1 diseño, `docs/design/persistence.md` |
| `07072c6` | 6.2 |
| `8a3f833` | 6.3 |

Tests al cierre: **980 pytest + 240 Vitest**, CI verde.

## Garantías nuevas y el test que prueba cada una

| Garantía | Test |
|---|---|
| Mandatos, llaves, firmantes, uso mensual y nonces de creación sobreviven a un reinicio, y lo guardado sigue verificando | `tests/test_persistence.py::test_mandates_keys_and_usage_survive_a_restart`, `::test_creation_nonce_still_blocks_a_replay_after_restart`, `::test_revoked_key_stays_revoked_after_restart` |
| Una pubkey = una persona, ahora en la base: un `UNIQUE` global que se cumple aunque alguien se salte el código. También hay `CHECK` de estado, contadores, `alg` y dueño normalizado, y FK del firmante a su llave | `::test_database_rejects_the_same_public_key_for_two_owners_even_bypassing_the_code`, `::test_database_rejects_malformed_keys`, `::test_database_rejects_invalid_mandate_rows`, `::test_database_rejects_a_human_signer_without_key_and_a_key_that_does_not_exist` |
| Una llave que firmó un mandato no se puede borrar del registro | `tests/test_signed_mandates.py::test_una_llave_que_firmo_un_mandato_no_se_puede_borrar_del_registro` |
| Las transacciones `BEGIN IMMEDIATE` reemplazan a los locks: **cada** intento simultáneo recibe una respuesta limpia y ninguno pasa el tope | `tests/test_atomic_budget.py::test_fifty_concurrent_purchases_against_max_uses_3_approve_exactly_3`, `tests/test_persistence.py::test_concurrent_key_registration_respects_the_active_key_cap` |
| Las migraciones construyen exactamente el esquema del código, bajan y suben limpias, y la app migra sola al arrancar | `::test_migrations_build_the_schema_the_code_expects`, `::test_migrations_downgrade_and_upgrade_cleanly`, `::test_the_api_migrates_an_empty_database_on_startup` |
| Sin `DATABASE_URL`, la API no arranca fuera de desarrollo | `::test_without_database_url_the_api_refuses_to_start_outside_dev_mode` |
| El ledger es append-only **en la base**: sin UPDATE ni DELETE desde la app, un INSERT solo si extiende la cabeza, y la cabeza no retrocede | `tests/test_ledger_persistence.py::test_the_app_cannot_update_or_delete_ledger_rows`, `::test_an_insert_that_does_not_extend_the_head_is_refused`, `::test_the_head_only_moves_forward_and_cannot_be_deleted` |
| Si se altera una fila o se borran las últimas (H4), la API no arranca y dice por qué; la CLI diagnostica sin la API | `::test_a_tampered_row_stops_the_api_from_starting`, `::test_removing_the_last_entries_stops_the_api_from_starting`, `::test_the_cli_verifies_without_starting_the_api` |
| Un intento capturado no sirve otra vez, ni pasadas 24 h ni tras un reinicio (H1) | `::test_a_replay_after_a_restart_is_rejected`, `::test_attempt_age_window`, `::test_a_captured_attempt_is_dead_once_its_nonce_could_be_forgotten`, `::test_created_at_is_covered_by_the_agent_signature` |
| Dos revisiones humanas del mismo intento compran una sola vez (H2) | `::test_two_approvals_that_both_passed_the_precheck_buy_once`, `::test_a_decision_survives_a_restart` |
| Las disputas y la cuota del agente sobreviven al reinicio | `::test_disputes_survive_a_restart`, `::test_the_agent_quota_survives_a_restart` |

**Prueba de mutación:**

| Paso | Mutaciones | Resultado |
|---|---|---|
| 6.2 | 12 | Todas detectadas. Quitar `BEGIN IMMEDIATE` sobrevivía al principio: SQLite igual impedía el gasto doble, pero **fallando** la transacción concurrente. Los tests pasaron a exigir que cada intento reciba respuesta |
| 6.3 | 14 | Todas detectadas. Dos sobrevivieron al principio y revelaron tests débiles, que se corrigieron |

Los dos tests débiles del 6.3:

- **El de doble aprobación con hilos no generaba una carrera real**, porque `TestClient` serializa las peticiones. Se reemplazó por uno determinista.
- **El de formato de fecha usaba una fecha vieja**, así que se rechazaba por antigüedad y no por formato. Al corregirlo apareció un bug real: `strptime` aceptaba `t`/`z` en minúscula. Se cerró con un regex estricto.

## Hallazgos del mapeo (6.1) y qué pasó con cada uno

- **H1 — replay de un intento capturado** (tras 24 h o tras cualquier reinicio): **cerrado** en el 6.3.
- **H2 — doble decisión humana sin atomicidad**: **cerrado** en el 6.3.
- **H3 — `POST /mandates/{id}/reset` borra contadores firmados con solo una sesión**: **pendiente de decisión (P-17)**. Recomendación: retirarlo, y que el acto 1 de la demo firme un mandato nuevo. Mientras tanto se persiste con el mismo comportamiento de antes.
- **H4 — truncar el final del ledger no se detectaba**: **cerrado** en el 6.3, con la cabeza y los triggers.
- **H5 — docstring obsoleto en `core/owner_keys.py`**: corregido.

## Cambios de contrato (a propósito)

- **`POST /verify`:**
  - El intento debe traer `created_at` (`YYYY-MM-DDTHH:MM:SSZ`, UTC) de hace 10 minutos como máximo, con hasta 2 de margen hacia el futuro.
  - Hay un check nuevo, `attempt_fresh`, que va antes de `nonce_fresh`: un intento viejo no gasta su nonce.
  - El agente del servidor agrega y firma ese campo; React no construye intentos.
- **`POST /audit/reset`:** ya no existe, ni en desarrollo (P-05). "Empezar de cero" en desarrollo es borrar `var/agentbuyer.db` con la API detenida.
- **Configuración:** `DATABASE_URL` es obligatoria fuera de desarrollo. La API migra sola al arrancar.
- **Revisión humana:** una segunda revisión del mismo intento responde 409 también ante una carrera, no solo de forma secuencial.
- **UI:** el check `nonce_fresh` se muestra como "Not a replay", y `attempt_fresh` como "Recent attempt".

## Límites conocidos

- **El dueño del disco puede reescribir la evidencia.** Quien tenga escritura sobre el archivo puede quitar los triggers y reescribir la cadena entera junto con la cabeza. La evidencia es a prueba de manipulación *por la aplicación*. Para cerrar ese hueco hacen falta anclas externas, que van al modelo de amenazas (12.1).
- **Las llaves del agente** cambian en cada reinicio hasta el 9.1, porque requieren un secreto de producción (P-13). El efecto está acotado: un intento firmado antes del reinicio deja de verificar, y como mucho tenía 10 minutos de vida.
- **OTP, challenges y rate limits siguen en memoria** (P-10). Con varios workers hace falta Redis; el punto de enganche está en `api/auth.py` y `api/keys.py`. El despliegue del 9.1 debe correr un solo worker o traer Redis.
- **La línea estricta legada** (`core/verify.py`, `engine/state.py`) sigue con nonces en memoria. Se retira en el 7.2 (P-08).
- **Costo en tiempo:** la suite pasó de ~18 s a ~40 s por usar una base por test.

## Verificación en navegador (Chromium headless, modo autónomo)

1. **Reinicio real del backend** (se mata el proceso y se levanta otro sobre el mismo archivo):
   - la misma llave del dispositivo figura registrada;
   - se firma sin volver a registrar;
   - el mandato anterior conserva `uses_count: 1` y vuelve a comprar (pasa a 2);
   - la historia de Audit y `/audit/verify` sobreviven con los mismos bloques.
2. **Archivo de la base alterado:** el backend real no arranca (código de salida 3, con el motivo en el log) y `scripts.verify_ledger` marca el mismo eslabón.
3. **Flujo completo y demo de 5 actos:** OK y sin errores de consola. Los scripts de verificación esperaban un tiempo fijo y ahora esperan al veredicto, porque el panel revela un check más.
