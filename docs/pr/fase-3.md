# Fase 3 — La firma del humano

Antes de esta fase el servidor firmaba los mandatos **por** el usuario, con llaves que guardaba él mismo e indexaba por un `human_id` que mandaba el cliente. Una firma así no prueba que la persona autorizó nada. Ahora cada titular firma su mandato **en su propio dispositivo**, con una llave Ed25519 no extraíble que registró probando que la posee. El servidor verifica esa firma al crear el mandato y otra vez en cada compra. Ya no firma por nadie.

Rama `fase-3-firma-cliente`, 10 commits, de `6eeee99` a `9d51047`. Tests al cierre: **783 pytest + 240 Vitest**, CI verde. El contrato de React (`tests/test_frontend_contract.py`, 15 tests) cambió a propósito en un solo punto, el alta firmada (ver más abajo).

## Qué incluye

| Paso | Commit | Qué hace |
|---|---|---|
| 2.0 | `6eeee99` | Canonicalización JSON compartida JS/Python (RFC 8785 con desviaciones documentadas), con vectores, fuzz y mutación |
| 2.1–2.2 | `a99bd80` | Keystore Ed25519 **no extraíble** en IndexedDB (WebCrypto nativo, sin respaldo de librería) |
| 2.3 | `508fed3` | `POST /keys/step-up/start` + `POST /keys/challenge`: step-up con OTP fresco; el challenge es la prueba |
| 2.4 | `095d1cf` | `POST /keys` exige prueba de posesión; `DELETE /keys/{key_id}` |
| 3.1 | `eca397f` | El navegador enrola su llave (step-up, challenge, firma del mensaje de registro) |
| 3.2 | `065f1bf` | Spec del mensaje firmado del mandato v1: montos en centavos, vectores compartidos |
| 3.3 | `da4c784` | El backend acepta y verifica mandatos firmados (doble vía, aditivo) |
| — | `46e2f38` | Plan en modo autónomo y resoluciones vigentes |
| 3.4 | `58734f0` | El wizard firma el mandato con la llave del dispositivo |
| 3.5 | `9d51047` | Se exige la firma humana; el servidor deja de firmar por el usuario |

## Garantías nuevas y el test que prueba cada una

| Garantía | Test |
|---|---|
| Los bytes que se firman son idénticos en JS y Python | `tests/test_canonical.py::test_shared_vector_produces_the_exact_expected_bytes`, `frontend/src/lib/canonical.test.ts` (mismos `shared/canonical_vectors*.json`) |
| La llave privada del navegador no se puede exportar, ni siquiera desde la app | `frontend/src/lib/keystore.test.ts` ("exportKey de la privada se rechaza") |
| Registrar una llave exige un OTP fresco del correo del dueño (step-up) | `tests/test_key_challenges.py::test_step_up_start_without_token_is_401` y siguientes |
| Registrar una llave exige probar que se tiene su privada: el squatting quedó cerrado | `tests/test_key_registration.py::test_blind_registration_of_the_step_1_kind_is_no_longer_possible`, `::test_signature_made_with_another_private_key_is_rejected` |
| El navegador firma exactamente los bytes de la spec (registro y mandato) | `frontend/src/lib/signing.test.ts`, `frontend/src/lib/mandateMessage.test.ts` (vectores del RFC 8032, byte a byte) |
| Cambiar cualquier campo firmado invalida la firma, y una firma de registro nunca vale como mandato | `tests/test_mandate_message.py::test_cambiar_un_campo_firmado_invalida_la_firma`, `::test_una_firma_de_registro_no_verifica_como_mandato` |
| Los montos firmados son centavos enteros, sin flotantes (0.1 + 0.2 se rechaza) | `tests/test_mandate_message.py::test_amount_cases_compartidos`, `frontend/src/lib/mandateMessage.test.ts` |
| El servidor acepta exactamente lo que firma el frontend | `tests/test_signed_mandates.py::test_el_servidor_acepta_cada_vector_del_3_2_byte_a_byte` |
| Sin firma del titular no se crea ningún mandato; el servidor no sella para usuarios | `tests/test_mandate_signature_attacks.py::test_sin_firma`, `::test_sello_del_servidor_para_un_usuario` |
| Una firma o llave de otra persona no sirve, y no revela si el `key_id` existe | `tests/test_mandate_signature_attacks.py::test_firma_de_otro_dueno`, `::test_llave_de_otro_dueno_con_key_id_propio`, `tests/test_signed_mandates.py::test_key_id_de_otro_dueno_inexistente_o_revocado_dan_el_mismo_403` |
| Anti-replay de la creación (nonce por dueño, ventana de `created_at`) | `tests/test_mandate_signature_attacks.py::test_replay_de_una_creacion`, `tests/test_signed_mandates.py::test_ventana_de_created_at` |
| Alterar lo guardado después de firmar hace que `/verify` rechace | `tests/test_mandate_signature_attacks.py::test_campo_alterado_despues_de_firmar` (6 campos), `tests/test_signed_mandates.py::test_cambiar_lo_guardado_por_otra_version_firmada_da_reject` |
| La llave debe seguir siendo del titular y estar activa: revocarla deja sin efecto lo que firmó (P-01 a) | `tests/test_signed_mandates.py::test_llave_revocada_despues_de_crear_deja_sin_efecto_el_mandato`, `::test_si_la_llave_pasa_a_otra_cuenta_da_reject`, `::test_linea_estricta_rechaza_mandato_con_llave_revocada` |
| El `payment_token` lo emite el servidor y queda atado a los bytes firmados | `tests/test_mandate_signature_attacks.py::test_payment_token_de_otro_mandato`, `::test_payment_token_enviado_por_el_cliente` |
| Moneda firmada (D-15): un intento en otra moneda se rechaza | `tests/test_signed_mandates.py::test_moneda_distinta_da_reject` |
| `off_session_consent=false` hace que toda compra escale a aprobación humana (D-16) | `tests/test_signed_mandates.py::test_sin_consentimiento_off_session_toda_compra_escala` |
| El agente solo puede buscar lo que el titular firmó | `tests/test_signed_mandates.py::test_agent_run_con_search_fields_distintos_da_422` |
| La vigencia vence al final del día elegido en la zona local del navegador (D-19) | `frontend/src/lib/signedMandate.test.ts` (México, Tokio, UTC, Nueva York con y sin horario de verano, Sídney) |
| Sin un dispositivo registrado, el wizard no autoriza; cambiar un límite produce una firma nueva | `frontend/src/lib/signedMandate.test.ts` ("sin llave registrada…", "editar un límite…") |

Cada paso pasó prueba de mutación (R5): se rompió cada garantía a propósito y algún test falló. Cuatro mutaciones sobrevivieron al principio, y cada una dejó un test nuevo:

- el orden UTF-16 de las listas;
- la pertenencia de la llave en `/verify`;
- el `message_hash`;
- la segunda pasada de horario de verano.

## Cambios de contrato (a propósito)

- **`POST /mandates`** exige el formato firmado del 3.2: `key_id`, `nonce`, `created_at`, `signature`, `expires_at` y los campos de la spec.
  - Sin firma: **422**.
  - Firma o llave que no valen: **403**.
  - Replay o `mandate_id` repetido: **409**.
  - No admite campos fuera de la spec. `valid_until`, `scope`, `payment_token`, `human_pubkey` u `owner` dan 422; antes se guardaban sin efecto.
- **`POST /mandates/create` retirado** (P-02). Firmaba con llaves "humanas" que guardaba el servidor.
- **`POST /adversarial/run` retirado.** Creaba mandatos sellados por el servidor en el registro vivo. Su cobertura pasó a `tests/test_mandate_signature_attacks.py`, que corre en CI.
- **`POST /keys`** exige prueba de posesión: `{public_key, challenge_id, signature}`.
- **Endpoints nuevos:** `POST /keys/step-up/start`, `POST /keys/challenge`, `DELETE /keys/{key_id}`. Este último responde `mandates_affected`.
- **`POST /keys/challenge`:** el 429 trae `Retry-After`.
- **`POST /verify`:**
  - Checks nuevos: `signing_key_active`, `payment_token_binding`, `currency` y `off_session_consent`.
  - El `detail` del check `signature` dice si fue una firma del titular o el sello del seed.
  - Un mandato sin firmante registrado se rechaza.
- **`POST /agent/run`:** en un mandato firmado, `search_fields` distintos de los firmados dan 422.
- **Contrato de React:** el alta congela el payload firmado. Los montos van como texto decimal y el mandato queda firmado por su titular.

## Migraciones de comportamiento que conviene conocer

- **Los usuarios necesitan registrar el dispositivo para autorizar.** El paso 1 del wizard lo pide, y la demo guiada lo hace sola con `AUTH_DEV_MODE=true`.
- **Recargar la página cierra la sesión (D-05), pero la llave del dispositivo se conserva:** la misma llave sigue registrada. Otro email en el mismo navegador tiene su propia llave.
- **Revocar un dispositivo deja sin efecto lo firmado con él.** La tarjeta del dispositivo dice cuántos permisos quedan sin efecto, y el titular los re-firma con un dispositivo registrado.
- **El sello de sistema solo existe para el mandato semilla** (D-12). Desaparece con el seed en el 7.2 (P-11).
- **La línea estricta (`core/verify.py`, `/purchases/execute`) verifica la firma humana, pero no puede aprobar mandatos con forma de React.** Esos mandatos no traen llave de agente. Es así desde D-01, y esa línea se retira en el 7.2 (P-08).

## Límites conocidos (honestos)

- **La sesión y el correo siguen siendo la raíz de confianza.** Quien controla el correo del titular puede pasar el step-up y registrar un dispositivo nuevo.
- **Un XSS puede usar la llave mientras dure.** La llave no es extraíble, así que un script inyectado no puede copiarla, pero sí pedirle al navegador que firme mientras la página está abierta.
- **El servidor no puede probar que la llave es no extraíble.** Sin attestation, confía en que el cliente usó WebCrypto con `extractable=false`. El siguiente paso documentado es WebAuthn con attestation (D-06).
- **Las minúsculas dependen de la versión de Unicode de cada motor.** Un desajuste falla cerrado: la firma no verifica y se rechaza.
- **Todo el estado sigue en memoria:** mandatos, llaves y nonces se pierden al reiniciar. Se persiste en la Fase 6.

## Verificación en navegador (Chromium headless, modo autónomo)

Recorrido completo: login → registrar el dispositivo → firmar un mandato → la compra se aprueba con "cardholder signature" → revocar el mandato → la compra se rechaza → `GET /audit/verify` con la cadena válida. Lo que vio la verificación queda en la bitácora de `docs/PLAN.md` (sección 18).
