# Persistencia: inventario del estado y diseño del esquema (paso 6.1)

> Paso de solo lectura: este documento no cambia código. Decisión aplicada: **P-10**. La base es SQLite con SQLAlchemy 2 y Alembic. OTP, challenges y rate limits se quedan en memoria, con un punto de enganche para Redis.
>
> Escrito el 16 nov 2026 sobre `main` en `0f85984`. Cada afirmación sobre el código cita el archivo donde se puede comprobar.

## 0. Estado de la implementación

| Paso | Estado |
|---|---|
| 6.2 | **Hecho.** `core/db.py`, `core/db_schema.py`, `migrations/` (`0001_mandates_and_keys`). Llaves del titular, mandatos, dueños, firmantes, periodos y nonces de creación son persistentes. H5 corregido. Tests: `tests/test_persistence.py`, más los de concurrencia del 5.2, que ahora exigen que cada intento simultáneo reciba una respuesta |
| 6.3 | Pendiente: ledger, cabeza y triggers (H4), nonces de intento con `created_at` firmado (H1), `escalation_decisions` (H2), disputas, cuota y llaves públicas del agente |

## 1. Por qué

Hoy **todo** el estado vive en diccionarios del proceso. Un reinicio borra mandatos, llaves registradas, el ledger "a prueba de manipulación" y los nonces anti-replay. Que el ledger sea a prueba de manipulación no sirve de mucho si desaparece con cada despliegue. Que el anti-replay funcione tampoco, si se reinicia cada vez que arranca el proceso.

## 2. Inventario

**Persistir** quiere decir que el dato sobrevive a un reinicio. **Efímero** quiere decir que perderlo no concede nada a nadie: a lo sumo obliga a pedir otro código.

### 2.1 Se persiste

| Estado | Dónde vive hoy | Forma | Quién escribe / quién lee | Invariantes que hoy garantiza el código | Paso |
|---|---|---|---|---|---|
| Mandatos | `MANDATES`, `core/mandate_store.py` | `{mandate: {...documento...}, live_state: {status, uses_count, amount_spent_cents, revoked_at}}` | Escriben: `create_human_signed_mandate`, `seal_seed_mandate`, `revoke/pause/resume/reset`, `reserve_purchase`, `apply_approved_purchase`. Leen: `/verify`, `/agent/run`, `GET /mandates`, React | `mandate_id` único. `status` ∈ {active, paused, revoked, expired}. Contadores ≥ 0. Expiración derivada al leer (`_apply_live_expiry`), no guardada. Lo firmado se guarda tal cual (bytes verificables otra vez) | 6.2 |
| Dueño del mandato | `MANDATE_OWNERS` | `mandate_id → owner_email` normalizado, o `None` | Lo escribe la creación. Lo leen `require_mandate_access`, `mandate_ids_owned_by` y `/audit` | Un dueño por mandato, nunca enviado por el cliente. Es interno: no sale en respuestas | 6.2 |
| Firmante | `MANDATE_SIGNERS` | `{kind, key_id, public_key, message_hash, signed_at}` | Lo escribe la creación. Lo leen `/verify` (`signing_key_active`, binding del token) y la revocación de llaves | `kind` ∈ {human, system_seal}. Un `human` siempre tiene `key_id`. Es interno | 6.2 |
| Uso del mes | `MANDATE_PERIODS` | `mandate_id → {month, uses, spent_cents}` | Lo escriben `reserve_purchase` y `apply_approved_purchase`. Lo leen el engine (presupuesto mensual) | Se reinicia al cambiar el mes UTC. Se actualiza en la misma operación atómica que `live_state` | 6.2 |
| Llaves del titular | `OWNER_KEYS`, `core/owner_keys.py` | `owner → [{key_id, public_key, alg, created_at, revoked_at}]` | Escriben: `POST /keys` (tras la prueba de posesión) y `DELETE /keys/{id}`. Leen: firma de mandatos y `/verify` | **Una pubkey = una persona, global.** Una llave revocada no se reactiva. Hay un máximo de 10 activas por dueño. `key_id` único | 6.2 |
| Nonces de creación | `used_nonces`, `core/signed_mandates.py` | `(owner, nonce) → created_at` | Lo escribe `POST /mandates` (claim, y release si falla). Se purga por ventana | Un nonce por dueño sirve una vez. Se olvida solo cuando el `created_at` firmado ya está fuera de la ventana (10 min + 2 min de margen), porque entonces la firma se rechaza por vieja | 6.2 (va con el mandato, en la misma transacción) |
| Ledger | `audit_ledger._entries`, `audit/log.py` | Cadena SHA-256: `index, prev_hash, hash, timestamp, event_type, actor_*, mandate_id, attempt_id, details, signature` | Lo escriben todos los veredictos, la creación, la revocación, las decisiones humanas y las corridas. Lo leen `/audit`, `/audit/verify`, escalaciones y disputas | Índices sin huecos. `prev_hash` encadena. `hash` = SHA-256 del JSON canónico. Solo se agrega (salvo `/audit/reset` de desarrollo) | 6.3 |
| Nonces de intento | `attempt_nonces`, `api/verify.py` | `nonce → visto_en` (TTL 24 h) | Lo escribe `/verify` | Un nonce sirve **una** vez, aunque el intento se rechace | 6.3 |
| Escalaciones de React | Se **derivan** del ledger (`api/escalations.py`) | Eventos `human_override_*` | Lo escribe `POST /mandates/{id}/approve_escalation` | Una decisión por intento. Hoy esto se comprueba leyendo el ledger, **sin atomicidad** (hallazgo H2) | 6.3 |
| Disputas | `_disputes`, `api/disputes.py` | `dispute_id → {attempt_id, mandate_id, claimant, reason, evidence, …}` | Lo escribe `/disputes/file`. Lo leen `GET /disputes` (filtrado por dueño) | Solo el dueño puede disputar. La evidencia es solo de ese mandato | 6.3 |
| Cuota de corridas del agente | `agent_run_quota`, `api/agent.py` + `core/quotas.py` | `subject → [instantes]` en ventana móvil | Lo escriben `/agent/run` (consume y refund) | ≤ N corridas por ventana y por usuario (P-16) | 6.3 (ver §5.4) |

### 2.2 Efímero (P-10): queda en memoria, con enganche a Redis

| Estado | Dónde | Por qué perderlo es seguro |
|---|---|---|
| OTP de login | `api/auth.otp_service` (`core/email_otp.py`: `_codes`, `_sends`) | TTL de 10 min. Perderlo solo obliga a pedir otro código; nunca concede acceso |
| OTP de step-up | `api/keys.step_up_otp_service` | Igual que el de login |
| Challenges de registro de llave | `api/keys.challenge_service` (`core/key_challenges.py`) | TTL de 120 s y un solo uso. Perderlo invalida el challenge, que es el resultado seguro |
| Rate limits de OTP (envíos por hora, cooldown) | `_sends` en `EmailOtpService` | Un reinicio los pone en cero. Un atacante no puede provocar reinicios, y el SMTP tiene su propio límite. Es un riesgo aceptado y documentado |

**Punto de enganche.** Los tres servicios ya están detrás de una interfaz pequeña: `EmailOtpService.issue/verify/invalidate/seconds_until_next_issue` y `KeyChallengeService.issue/consume`. El paso a Redis es una implementación alternativa de esa interfaz, inyectada al construir `otp_service`, `step_up_otp_service` y `challenge_service`. En el 6.3 se documenta la línea exacta.

**Con varios procesos esto deja de ser opcional.** Un OTP emitido por un worker no lo ve otro. Mientras la app corra en un solo proceso, la memoria es correcta. El despliegue del 9.1 debe correr un solo worker o traer Redis; queda anotado como requisito de ese paso.

### 2.3 No se persiste: es legado y se retira en el 7.2 (P-08)

| Estado | Dónde | Destino |
|---|---|---|
| Nonces y estado de la línea estricta | `engine/state.state_manager` | Se retira con `core/verify.py` |
| Bandeja HITL de la línea estricta | `core/verify._escalation_inbox` | Se retira |
| Árbitro de disputas legado | `core/dispute.dispute_arbiter` (segundo almacén de disputas, solo lo usan el legado y sus tests) | Se retira |
| Órdenes del comercio simulado | `core/merchant.vuelaya_merchant.settled_orders` | Se retira con el comercio de demo |
| Historial del agente de consola | `core/agent_loop.py: purchase_history` | Se retira |

Persistir cualquiera de estos sería migrar dos veces código que se va a borrar.

### 2.4 Llaves del agente: caso aparte

`core/agent_keys._registry` guarda la **llave privada** del agente, generada al arrancar. Hoy cambia en cada reinicio. Hay dos razones para no ponerla en la base:

- Sería un secreto guardado junto a los datos.
- Con la pubkey basta: verificar intentos pasados no necesita la privada.

**Propuesta:**

- En producción, `AGENT_SIGNING_KEY` (semilla Ed25519 de 32 bytes, en hex) viene del gestor de secretos. Es parte de los secretos de P-13: se prepara en el 9.1 y no se crea aquí.
- En desarrollo se genera al arrancar, como hoy.
- La base guarda solo `agent_public_keys(agent_id, public_key, valid_from, valid_to)`, para auditar intentos viejos.
- Sin `AGENT_SIGNING_KEY` fuera de `AUTH_DEV_MODE`, la API no arranca. Es la misma regla que `JWT_SECRET`.

## 3. Hallazgos del mapeo

Son problemas reales que se encontraron al leer el código para este diseño. Se resuelven en el paso indicado, salvo H3, que requiere una decisión.

- **H1 — Replay de un intento capturado (alto; se resuelve en el 6.3).** Un intento no lleva una fecha firmada (`core/agent_keys.attempt_signing_bytes` firma el intento tal cual, y no hay campo de tiempo) y su nonce se olvida a las 24 h (`api/verify.NONCE_TTL_SECONDS`). Un intento firmado y capturado puede volver a presentarse:
  - pasadas 24 h;
  - o hoy, tras **cualquier reinicio**.

  Si el mandato tiene usos, se aprueba otra vez.

  **Diseño:** el intento lleva un `created_at` cubierto por la firma del agente. `/verify` rechaza intentos con más de `MAX_ATTEMPT_AGE` (10 min) o del futuro (más de 2 min de margen). El nonce persiste con `expires_at = created_at + MAX_ATTEMPT_AGE + margen`. Así es seguro olvidarlo: pasado ese momento, el intento ya se rechaza por viejo. Es el mismo argumento que hoy usa el nonce de creación de mandatos.

  **Cambio de contrato:** `created_at` pasa a ser obligatorio en el intento. El agente del servidor lo agrega, y React no construye intentos (4.2).
- **H2 — Doble decisión humana sobre un intento escalado (medio; 6.3).** `approve_escalation` primero busca en el ledger si ya hay una decisión y después aplica la compra. Esas dos operaciones no son atómicas: dos aprobaciones simultáneas pueden cobrar dos veces. **Diseño:** la tabla `escalation_decisions` tiene `attempt_id` como clave primaria, y la decisión, la compra y el evento del ledger van en una sola transacción. La segunda decisión choca con la clave y responde 409.
- **H3 — `POST /mandates/{id}/reset` borra los contadores con solo una sesión (alto; necesita una decisión, ver §7).** Pone `uses_count` y `amount_spent_cents` en cero (`core/mandate_store.reset_mandate`) y no deja ningún evento en el ledger. El `max_uses` lo firmó la **llave del dispositivo**, pero para resetearlo basta un **token de sesión**: una sesión robada puede renovar indefinidamente un mandato que, según lo firmado, ya se agotó. P-05 lo mencionaba como el reset de la demo, así que el plan lo da por existente.
- **H4 — Truncar el ledger no se detecta (medio; 6.3).** `verify_chain_integrity` valida los eslabones, pero si se borran las **últimas** filas, la cadena que queda sigue siendo válida. **Diseño:**
  - triggers de SQLite que abortan cualquier `UPDATE`/`DELETE` en `audit_ledger`;
  - una fila `ledger_head(id=1, last_index, last_hash)` que se actualiza en la misma transacción que cada append;
  - la verificación al arrancar exige que la cadena termine exactamente en esa cabeza.

  **Límite honesto:** quien tenga acceso de escritura al archivo puede quitar los triggers y reescribir la cadena entera junto con la cabeza. La evidencia es a prueba de manipulación *por la aplicación*, no contra el dueño del disco. Para cerrar ese hueco hacen falta anclas externas, por ejemplo publicar la cabeza firmada periódicamente; queda como siguiente paso en el modelo de amenazas (12.1).
- **H5 — Docstring obsoleto.** `core/owner_keys.py` todavía dice que el registro "no prueba posesión" y que "no participa en /verify". Las dos cosas dejaron de ser ciertas en las Fases 2 y 3. Se corrige en el 6.2, al reescribir ese módulo.

## 4. Esquema propuesto

Se implementa con SQLAlchemy 2 **Core**, no con el ORM:

- las consultas quedan explícitas y se pueden revisar;
- el código actual trabaja con diccionarios, y Core devuelve filas que se convierten directamente;
- las transacciones se ven donde hoy hay locks.

Las migraciones son de Alembic. Los montos son `INTEGER` en centavos. Las fechas son texto ISO 8601 UTC, el mismo formato que hoy se firma y se encadena. Así nada se re-serializa distinto.

| Tabla | Columnas | Restricciones e índices |
|---|---|---|
| `owner_keys` | `key_id` PK, `owner_email`, `public_key`, `alg`, `created_at`, `revoked_at` NULL | **`UNIQUE(public_key)`** (una pubkey = una persona, ahora en la base). `CHECK(alg='ed25519')`. `CHECK(owner_email = lower(trim(owner_email)))`. Índice `(owner_email, revoked_at)`. El tope de 10 activas se comprueba en la misma transacción `BEGIN IMMEDIATE` que el insert (SQLite no tiene un `CHECK` agregado) |
| `mandates` | `mandate_id` PK, `owner_email` NULL, `document` TEXT (JSON exacto de lo guardado), `status`, `uses_count`, `amount_spent_cents`, `revoked_at` NULL, `created_at` | `CHECK(status IN ('active','paused','revoked','expired'))`. `CHECK(uses_count >= 0 AND amount_spent_cents >= 0)`. Índice `owner_email` |
| `mandate_signers` | `mandate_id` PK y FK, `kind`, `key_id` NULL y FK a `owner_keys`, `public_key`, `message_hash`, `signed_at` | `CHECK(kind IN ('human','system_seal'))`. `CHECK(kind <> 'human' OR key_id IS NOT NULL)`. Índice `key_id` (para contar los mandatos afectados al revocar una llave) |
| `mandate_periods` | `(mandate_id, month)` PK, `uses`, `spent_cents` | Una fila por mes, no una que se sobrescribe: queda el historial mensual. `CHECK(month GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]')` |
| `mandate_creation_nonces` | `(owner_email, nonce)` PK, `created_at`, `expires_at` | La PK es el anti-replay. Las filas vencidas se purgan |
| `attempt_nonces` | `nonce` PK, `mandate_id`, `seen_at`, `expires_at` | La PK es el anti-replay (H1). Las filas vencidas se purgan |
| `audit_ledger` | `idx` INTEGER PK (= `index`), `entry_id` UNIQUE, `prev_hash`, `hash` UNIQUE, `timestamp`, `event_type`, `actor_type`, `actor_id`, `mandate_id`, `attempt_id`, `details` TEXT (JSON canónico, el mismo que se hashea), `signature` | Triggers `BEFORE UPDATE` y `BEFORE DELETE` → `RAISE(ABORT)`. Índices `mandate_id` y `attempt_id` |
| `ledger_head` | `id` PK `CHECK(id=1)`, `last_idx`, `last_hash` | Se actualiza en la misma transacción que el append (H4) |
| `escalation_decisions` | `attempt_id` PK, `mandate_id`, `decision`, `decided_by`, `decided_at` | `CHECK(decision IN ('approve','decline'))`. La PK cierra H2 |
| `disputes` | `dispute_id` PK, `attempt_id`, `mandate_id`, `claimant_email`, `reason`, `status`, `evidence` TEXT, `created_at` | Índices `mandate_id` y `attempt_id` |
| `agent_run_usage` | `id` PK, `subject`, `used_at` | Índice `(subject, used_at)`. Un refund borra la fila de esa corrida: no es evidencia, es un contador |
| `agent_public_keys` | `(agent_id, public_key)` PK, `valid_from`, `valid_to` NULL | §2.4 |

**Lo que se queda fuera de la base:**

- **El estado `expired`.** Se sigue derivando al leer, como hoy, y no se escribe por un reloj. Así una base restaurada de un backup no "des-expira" nada.
- **Los JSON de `mandates.document` y `audit_ledger.details`.** Se guardan como texto exacto, no en columnas desnormalizadas. La firma y el hash cubren esos bytes, y re-serializarlos podría cambiar la verificación.

## 5. Capa de repositorios

### 5.1 Forma

- `core/db.py`:
  - `get_engine()` desde `DATABASE_URL`;
  - pragmas por conexión: `foreign_keys=ON`, `journal_mode=WAL`, `busy_timeout=5000`;
  - un helper `write_tx()` que abre `BEGIN IMMEDIATE`. Toma el lock de escritura al empezar, que es el equivalente al `with mandate_store._lock:` actual.
- `core/repositories/`: un módulo por agregado (`mandates.py`, `owner_keys.py`, `nonces.py`, `ledger.py`, `escalations.py`, `disputes.py`, `quotas.py`). Cada uno contiene funciones que reciben la conexión.
- **Las funciones públicas de hoy mantienen su firma.** Por ejemplo `core.mandate_store.get_mandate`, `reserve_purchase`, `create_human_signed_mandate` y `owner_keys.register_key` pasan a delegar en el repositorio. Las rutas no cambian, y ese es el criterio de "aditivo" de este paso.

### 5.2 Configuración

- `DATABASE_URL` por entorno.
- Default en desarrollo: `sqlite:///./var/agentbuyer.db`, con `var/` en `.gitignore`. Ningún archivo de base entra al repo.
- Producción: un disco persistente (P-13, 9.1).
- Fuera de `AUTH_DEV_MODE`, la app **exige** `DATABASE_URL`. Es fail-closed: evita que un despliegue escriba en un archivo efímero dentro del contenedor creyendo que persiste.

### 5.3 Tests

- **Una base temporal por test** (`tmp_path`). Para no correr Alembic más de 900 veces, una fixture de sesión migra una vez una plantilla y cada test copia el archivo.
- **Un test de migraciones.** Hace `upgrade head` desde cero, compara el esquema con lo que espera el código y prueba `downgrade` y `upgrade` otra vez.
- **Los tests que hoy tocan los diccionarios cambian su forma, no su fuerza (R4).** Son 28 escrituras directas en `MANDATES` en 12 archivos, más `OWNER_KEYS` en 3 y `_disputes` en 1. Pasan a usar helpers de fixture que escriben por el repositorio. Cada test conserva lo que prueba, y los cambios se listan en el resumen del paso.
- **Se mantienen tal cual** los tests de concurrencia del 5.2 (50 compras contra `max_uses=3`) y el seam `_reservation_pause()`. La atomicidad ahora la da `BEGIN IMMEDIATE`, y esos tests son la prueba de que sigue siendo cierta.

### 5.4 La cuota del agente se persiste (decisión de diseño, dentro de P-10)

P-10 deja en memoria "OTP, challenges y rate limits". La cuota de `/agent/run` no es un rate limit anti-abuso: es un **control de costo** (P-16), porque cada corrida gasta en OpenAI. Si queda en memoria, cada despliegue regala corridas. Además, el tope global diario del 9.1 necesita contabilidad que sobreviva a reinicios. El costo es una tabla y un índice. Si René prefiere dejarla en memoria, basta con no hacer ese sub-paso.

## 6. Orden de migración y riesgo

| Paso | Qué | Riesgo | Cómo se controla |
|---|---|---|---|
| 6.2 a | Dependencias fijadas (SQLAlchemy 2, Alembic), `core/db.py`, Alembic con la migración base, `var/` en `.gitignore`, fixture de base por test | Bajo | Suite completa sin cambios de comportamiento |
| 6.2 b | `owner_keys` → repositorio. `UNIQUE(public_key)` en la base | Medio: la unicidad global pasa del código a la base | Los tests de reclamo de llave ajena y de reactivación de una revocada siguen; test nuevo de que el `UNIQUE` lo hace cumplir la base aunque se salte el código |
| 6.2 c | Mandatos, dueños, firmantes, periodos y nonces de creación → repositorio. `create_human_signed_mandate` y `reserve_purchase` en `BEGIN IMMEDIATE` | **Alto:** la atomicidad del 5.2 cambia de mecanismo | Los tests de 50 hilos del 5.2 deben seguir pasando; mutación quitando `BEGIN IMMEDIATE` |
| 6.2 d | Test de reinicio: crear, registrar llave, comprar → nueva app sobre el mismo archivo → todo sigue y verifica | Bajo | — |
| 6.3 a | Ledger + cabeza + triggers; verificación al arrancar | **Alto:** es la evidencia | Tests: alterar una fila → no arranca; borrar la última → no arranca (H4); `UPDATE` desde la app → error |
| 6.3 b | Nonces de intento durables con `created_at` firmado (H1), `escalation_decisions` (H2), disputas, cuota | Medio: cambia el contrato del intento | Tests: replay tras reinicio → REJECT; intento viejo o del futuro → REJECT; dos aprobaciones simultáneas → una sola compra |

**Arranque con la cadena rota: la app no arranca.** Lo explica en el log con el índice del primer eslabón roto. No se elige un modo de solo lectura por tres razones:

- un sistema cuya evidencia está comprometida no debe seguir tomando decisiones que se encadenan a una historia rota;
- un modo de solo lectura duplica las rutas de código, con superficie nueva justo en el caso de incidente;
- para investigar ya existe la lectura directa del archivo, y el 6.3 agrega un comando de diagnóstico (`python -m scripts.verify_ledger`) que no levanta la API.

**`POST /audit/reset` desaparece en el 6.3.** Un ledger append-only en la base no admite `DELETE` desde la app. "Empezar limpio" en desarrollo pasa a ser borrar el archivo de la base de desarrollo, y se documenta así. Esto cumple P-05: el reset sale del producto.

**El seed (hasta el 7.2):** `seal_seed_mandate` pasa a ser idempotente. Inserta solo si el mandato no existe, para que reiniciar no duplique ni resetee el seed.

## 7. Decisión pendiente para René

- **P-17 — `POST /mandates/{id}/reset` (H3).** Recomendado: **retirarlo**. Reiniciar un mandato agotado es, en la práctica, autorizar más compras. Eso debe pasar por la firma del dispositivo, es decir, crear un mandato nuevo firmado, no por una sesión.

  **Hoy React lo usa en dos lugares** (`frontend/src/App.tsx`): en el acto 1 de la demo guiada, para "empezar limpio", y en el botón "reset mission". Retirarlo implica que el acto 1 cree y firme un mandato nuevo. El dispositivo ya está registrado en ese punto de la demo, así que firmar no pide nada más a la persona. Es un cambio de frontend y backend del tamaño de un sub-paso.

  Alternativa: dejarlo solo con `AUTH_DEV_MODE=true`, registrando un evento en el ledger. La demo en vivo (9.1) corre sin modo desarrollo, así que ahí el acto 1 fallaría igual.

  Hasta que René decida, el 6.2 lo persiste con el mismo comportamiento de hoy, sin cambiar la semántica. El hallazgo queda en la lista de pendientes. No bloquea la Fase 6.
