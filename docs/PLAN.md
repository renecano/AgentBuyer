# AgentBuyer — Plan maestro hasta v1.0

> Documento de trabajo. Lo diseñó Claude (chat) con René; cada paso es **un prompt** que René pega en Claude Code.
> Estado tomado del repo el **16 nov 2026**. Si algo de aquí no coincide con el repo real, manda el repo: Claude Code se detiene y lo reporta (regla R2).

---

## 0. Cómo se usa este plan

Cada paso sigue el mismo ciclo:

1. **Decisiones primero.** Si el paso dice `⛔ requiere P-xx`, René decide esa pregunta (sección 4) antes de pegar el prompt y escribe la respuesta en el prompt donde dice `DECISIÓN:`.
2. **René pega el prompt** en Claude Code. Todos los prompts empiezan pidiendo leer este archivo, así que las reglas de la sección 2 aplican siempre aunque el prompt no las repita.
3. **Claude Code trabaja y hace commit** (nunca push).
4. **René verifica** lo que diga la casilla "Verificación de René" (normalmente el navegador) y hace `git push`.
5. **René pega el reporte en el chat**; Claude lo revisa antes de soltar el siguiente paso. Si el reporte trae una decisión nueva o una desviación, se resuelve ahí.

Un paso no se considera hecho hasta que cumple su **Definición de terminado** y el CI está verde.

### 0b. Modo autónomo (vigente desde el 16 nov 2026, paso 3.4 en adelante)

René pidió que Claude Code ejecute el plan completo por su cuenta: hacer los chequeos que antes hacía René, hacer push y seguir con el siguiente paso. Mientras este modo esté vigente, **sustituye** el ciclo de arriba:

1. **Ejecuta los pasos en el orden de la sección 5**, empezando por el primero que no aparezca como hecho en la bitácora (sección 18).
2. **Decisiones:** donde un prompt diga `DECISIÓN: <...>`, usa la resolución de la sección 4 ("Resoluciones vigentes"). Si una situación no la cubre ninguna decisión ni regla, **alto** (ver 0c).
3. **Verificación del navegador:** la casilla "Verificación de René" la ejecuta Claude Code con un navegador real sin interfaz (Playwright + Chromium; instálalo si falta). Levanta backend (`AUTH_DEV_MODE=true`, base temporal) y frontend, recorre los pasos de la casilla y reporta qué hizo y qué vio. Estos guiones de verificación viven fuera del repo (scratchpad) hasta la Fase 11, que formaliza la suite E2E en CI. Lo que exige a una persona (abrir un correo real, el teléfono) se marca como "no verificable sin René".
4. **Commit y push:** al terminar cada paso, con suite y build en verde, commit y `git push` de la rama. Después confirma el estado del CI de ese commit en GitHub (API pública `https://api.github.com/repos/renecano/AgentBuyer/actions/runs?branch=<rama>` o `gh` si existe). CI rojo → arréglalo antes de seguir; si no puedes reproducir el fallo, replica el CI en un entorno limpio (venv Python 3.13 + `pip install -r requirements-dev.txt` + `npm ci`).
5. **Cierre de fase:** replica el CI en entorno limpio, `git merge --no-ff` de la rama a `main` con un mensaje que resuma la fase, push de `main`, confirma CI verde en `main`, y borra la rama local y remota. La siguiente fase sale de `main` actualizado con la rama que indica el plan.
6. **Bitácora:** al terminar cada paso añade una entrada a la sección 18 (fecha, paso, commit, conteos de tests, verificación del navegador, decisiones propias, pendientes) dentro del mismo commit. Es lo que permite retomar en otra sesión.
7. **Reporte a René:** al final de cada fase, y siempre que te detengas, deja un resumen en el formato R10.

### 0c. Condiciones de ALTO (te detienes y esperas a René)

- Hace falta una cuenta, credencial, pago o acción fuera del repo: crear servicios de despliegue, dominios, SMTP real, llaves de OpenAI con gasto, secretos de producción (P-13, P-16 en la parte de cuentas).
- Licencia del código coescrito (P-14): no apliques licencia hasta que René confirme con el equipo original.
- El CI sigue rojo después de dos intentos de arreglo razonados.
- Una decisión de producto que el plan no cubre, o que contradice una D-xx.
- La auditoría de cierre (13.1) encuentra algo crítico o alto abierto.
- Cualquier acción irreversible fuera de lo descrito.

**Prohibido siempre:** `git push --force`, reescribir historia publicada, borrar `main`, cambiar configuración del repo en GitHub, commitear secretos o `.env`.

---

## 1. Dónde estamos

> Actualizado en modo autónomo (16 nov 2026). El detalle paso a paso está en la bitácora (sección 18).

| | |
|---|---|
| Rama activa | `fase-6-persistencia` (desde `main` en `0f85984`) |
| `main` | `0f85984` — merge de la Fase 5 (PR #3), CI verde |
| Tests | 952 pytest + 240 Vitest |

**Hecho:**

- **Fase 1 — Cimiento** y **Fase 2 — Autenticación y autorización** (ver historial de `main`).
- **Fase 3 — Firma del humano** (merge `06df819`, resumen en `docs/pr/fase-3.md`): el titular firma cada mandato en su dispositivo con una llave Ed25519 no extraíble registrada con prueba de posesión; el servidor ya no firma por nadie; revocar una llave deja sin efecto lo firmado (P-01 a); `POST /mandates/create` y `POST /adversarial/run` retirados.
- **Fase 4:** 4.1 — `/agent/run`, `GET /audit`, `/disputes/file`, `GET /disputes` exigen sesión y propiedad (P-04); cuota por usuario en `/agent/run`; `/audit/reset` solo como utilidad de desarrollo (P-05). 4.2 — `/verify` solo para servicios (P-03) con anti-replay, firma del agente y moneda; la demo usa escenarios de `/agent/run` que nunca compran.
- **Fase 5 — Motor de decisión** (merge `0f85984`, resumen en `docs/pr/fase-5.md`): dinero en centavos enteros con moneda; reglas del engine sin huecos (REJECT ante defectos duros, igualdad exacta, gramática fail-closed); verificar y consumir es atómico; presupuesto mensual; un solo cliente LLM con modelo verificado, presupuesto por request y fail-closed; comercio por dominio de la oferta.

**Lo que sigue abierto, comprobado en el repo:**

- `GET /audit/verify` es anónimo (expone el número de bloques del ledger).
- Webhooks sin verificación de firma; `print` en lugar de logging; `mandate/intelligent_issuer.py` conserva su propio cliente LLM (legado, 7.2); el texto del agente dice "real search" aunque la búsqueda esté simulada en demos (7.3).
- Ledger, nonces de intento, escalaciones, disputas y cuota siguen en memoria (6.3); mandatos y llaves ya son persistentes (6.2). Hallazgos H1 (replay de intentos tras 24 h o reinicio) y H2 (doble decisión humana) se cierran en el 6.3.
- Línea estricta (`core/verify.py`, `/purchases/execute`, `mandate/issue.py`, `mandate/adversarial_tests.py`) sin alta por endpoint desde el 3.5: legado a retirar en el 7.2 (P-08).
- README y `docs/` describen el proyecto del hackathon; no hay `LICENSE` (Fase 12, P-14).

---

## 2. Reglas transversales (aplican a TODOS los prompts)

- **R1 — Alcance.** Solo lo que pide el paso. Si encuentras algo roto fuera de alcance, repórtalo; no lo arregles.
- **R2 — Estado real primero.** Antes de tocar nada confirma rama, árbol limpio y los supuestos del prompt (archivos, rutas, números de línea). Si algo difiere, **detente y reporta** antes de improvisar.
- **R3 — Fail-closed.** Ante duda, error, dato faltante o excepción: rechazar. Nunca una degradación silenciosa a otro algoritmo, otro camino o un valor por defecto permisivo.
- **R4 — Nunca debilitar un test para que pase.** Un test solo cambia si el contrato cambia a propósito; en ese caso explica qué cambió y por qué. Si un test pasaba "por la razón equivocada" (verde sin ejercer nada), arréglalo y repórtalo.
- **R5 — Prueba de mutación.** Por cada garantía nueva, rómpela a propósito y confirma que al menos un test falla. Reporta qué rompiste y qué lo detectó. Restaura el código después.
- **R6 — Contrato de React.** `tests/test_frontend_contract.py` en verde, salvo cambio de contrato deliberado y declarado en el prompt.
- **R7 — Suite completa al final.** Backend `python -m pytest -q`; frontend `npm run build` y `npm test` (en `frontend/`). Reporta conteos antes y después.
- **R8 — Dependencias.** Solo las necesarias; Python fijado con `==` en `requirements*.txt`; npm con `package-lock.json` commiteado. Justifica cada dependencia nueva. Instalar lo que el proyecto necesita está permitido.
- **R9 — Commit y push.** Al terminar, un commit con el mensaje que da el prompt. En modo autónomo (0b) también `git push` de la rama y comprobación del CI; fuera de ese modo, sin push.
- **R10 — Formato del reporte.** (1) qué cambió, por archivo; (2) conteos de tests antes/después; (3) decisiones que tomaste por tu cuenta y por qué; (4) lo que NO pudiste verificar; (5) pendientes que descubriste; (6) qué debe verificar René en el navegador.
- **R11 — Pruebas pesadas al final.** Playwright, benchmarks y cargas largas solo en las Fases 10–11.
- **R12 — Honestidad del producto.** Nada en la UI, correos, logs o docs puede prometer una garantía que el código no da. Lo falso se va.
- **R13 — Secretos y PII.** Nunca en código, logs, asuntos de correo ni respuestas. Fixtures con datos obviamente ficticios y dominios reservados (`example.com`).
- **R14 — Texto.** Archivos en UTF-8 (el CI tiene guardia anti-mojibake). Textos visibles al usuario y mensajes de la API en inglés (ver P-12).
- **R15 — Tests herméticos.** Ningún test llama a red ni a OpenAI; relojes inyectables en lugar de esperas reales.

---

## 3. Decisiones ya tomadas (registro)

| ID | Decisión | Por qué |
|---|---|---|
| D-01 | Consolidar en un pipeline confiable sin migrar React entero a la línea estricta | Pasos 7–13 del mapeo rompían el frontend completo; la seguridad no exige unificar los dos contratos |
| D-02 | Email como único mecanismo de login; SMS/Twilio fuera | Una sola historia de autenticación, sin código muerto |
| D-03 | JWT propio (PyJWT, HS256) en lugar de Auth0 | Proyecto de portafolio: demostrar el mecanismo; en producción real se usaría un proveedor (documentar en ADR) |
| D-04 | Tres identidades: `user` (OTP), `admin` (OTP + `ADMIN_EMAILS`, revalidado en cada request), `service` (API key estática ≥16 bytes) | Least privilege; humano vs máquina |
| D-05 | Sesión solo en memoria; recargar = volver al login | Evita exponer el token a XSS vía storage |
| D-06 | Firma del humano: camino (a), llave de software Ed25519 en el navegador | Concepto completo de no-repudio, alcanzable y honesto; WebAuthn queda como siguiente paso documentado |
| D-07 | Solo Ed25519 nativo de WebCrypto, sin respaldo a `@noble` | Todas las llaves no extraíbles por construcción; sin degradación silenciosa |
| D-08 | Registrar llave exige OTP fresco (step-up) | Un token robado solo no basta para enrolar un firmante |
| D-09 | Vitest en el frontend | El frontend no tenía red de tests |
| D-10 | Canonicalización JCS (RFC 8785) con rango de enteros seguros | Bytes idénticos JS/Python, verificados con vectores y fuzz |
| D-11 | Montos firmados en **centavos enteros** | Elimina flotantes del payload firmado (práctica de Stripe/PayPal) |
| D-12 | El seed se trata como "sello de sistema/legado", nunca como llave humana | Registrarlo afirmaría algo falso y ocultaría la distinción sello vs firma |
| D-13 | No-dueño recibe 403 (no 404) | No añade filtración nueva; documentado en código |
| D-14 | Sacar el seed del proyecto al final | Hoy sostiene tests; se reemplaza a propósito (P-11) |
| D-15 | La moneda va **firmada** en el mandato; la v1 solo acepta `USD` | Centavos sin moneda son ambiguos; ampliar monedas exige definir sus decimales (no todas tienen 2) |
| D-16 | `off_session_consent` va firmado **y se aplica**: en `false`, toda compra de un mandato firmado escala a aprobación humana | Es autorización para cobrar sin la persona presente; firmarlo sin aplicarlo sería teatro |
| D-17 | Una clave desconocida en `constraints` se **rechaza** (422), no se ignora | Nada que autorice puede viajar junto al mandato sin estar firmado (`monthly_budget`, `conditions_expression`… no existen en v1) |
| D-18 | `expires_at` es obligatorio y posterior a `created_at` (ISO 8601 UTC con `Z`, segundos) | Un mandato firmado sin vencimiento sería una autorización eterna |
| D-19 | La vigencia elegida como fecha vence al **final de ese día en la zona horaria local del navegador**, convertida a UTC; la confirmación muestra fecha, hora y zona | Es lo que una persona entiende por "válido hasta el 30" |
| D-20 | Modo autónomo: Claude Code verifica, hace push, mergea fases y sigue el plan (sección 0b) | Pedido de René, 16 nov 2026 |

### Límites conocidos (se documentan, no se esconden)

- **Minúsculas y Unicode.** La firma normaliza a minúsculas (`owner`, categorías, comercios) con `str.lower()` en Python y `toLowerCase()` en JS. Coinciden en lo probado (acentos, ß, emoji), pero dependen de la versión de Unicode de cada motor: un carácter raro podría bajar distinto. El efecto es **fail-closed**: los bytes no coinciden, la firma no verifica y el mandato se rechaza; nunca se aprueba algo distinto de lo firmado.

---

## 4. Decisiones pendientes (René decide antes del paso que las requiere)

Cada una trae la recomendación de Claude. Responde en el chat o escribe la respuesta en el prompt (`DECISIÓN: ...`).

### Resoluciones vigentes (16 nov 2026)

René adoptó las recomendaciones al pedir que el plan se ejecute completo. Puede cambiar cualquiera editando esta tabla; Claude Code usa lo que diga aquí.

| P | Resolución |
|---|---|
| P-01 | (a) Revocar la llave deja sin efecto los mandatos firmados con ella (`signing_key_active`); se re-firma con la llave nueva |
| P-02 | Retirar `POST /mandates/create` y las llaves humanas del servidor; las llaves del agente se quedan, documentado |
| P-03 | `/verify` exige credencial `service`; los actos 4 y 5 de la demo pasan por `/agent/run` con escenario |
| P-04 | `GET /audit`: cada usuario ve lo suyo; `admin` ve todo |
| P-05 | `POST /audit/reset` sale del producto; utilidad solo con `AUTH_DEV_MODE=true` + `admin`; sin ruta duplicada |
| P-06 | Retirar webhooks y `approve-exception`; documentar pagos reales como siguiente paso |
| P-07 | Retirar el inbox; recibos como servicio interno disparado por la compra |
| P-08 | Retirar `aegis_core.py` e `intelligent_issuer.py`; `run_demo.py` reescrito como recorrido real |
| P-09 | Todo el dinero del backend en enteros de unidad mínima + moneda |
| P-10 | SQLite con SQLAlchemy 2 + Alembic; OTP/challenges/rate limits en memoria con punto de enganche a Redis |
| P-11 | Opción B: fixtures firmadas en tests + `scripts/bootstrap_demo.py` solo en dev; fuera el seed y `system_seal` |
| P-12 | UI, API y README en inglés (README con resumen en español); comentarios existentes sin reescritura masiva |
| P-13 | **Pendiente de René** (cuentas y costos). Claude Code prepara todo lo que no requiera cuentas y se detiene |
| P-14 | **Pendiente de René** (confirmar con Ana Paola Oviedo y dglvanp). Hasta entonces: sección de créditos sí, licencia no |
| P-15 | Un solo cliente LLM configurable; modelo verificado al implementar; fail-closed |
| P-16 | Cuota configurable por usuario (por defecto 20 corridas/día) y tope global diario configurable; al agotarse, error claro. El límite de gasto en la cuenta de OpenAI lo configura René |
| P-17 | **Pendiente de René** (surgió en el 6.1, hallazgo H3 de `docs/design/persistence.md`). Recomendado: retirar `POST /mandates/{id}/reset`; el acto 1 de la demo crea y firma un mandato nuevo. Hasta decidir, se persiste sin cambiar su comportamiento |

**P-01 — ¿Qué pasa con un mandato si se revoca la llave que lo firmó?** *(antes de 3.5)*
- (a) **Recomendado:** el mandato deja de verificar (`/verify` → REJECT con check `signing_key_active`), sin mutar su estado. El humano re-firma con su llave nueva. Coherente con el kill switch: revocar una llave comprometida corta todo lo firmado con ella.
- (b) El mandato sigue válido porque la firma era válida al crearse (se guarda `signed_at`). Más cómodo, pero una llave robada sigue autorizando compras.

**P-02 — `POST /mandates/create` y las llaves humanas en el servidor.** *(antes de 3.5)*
- **Recomendado:** retirar la ruta (React no la usa) y las llaves humanas de `_key_registry`. Las llaves del **agente** se quedan en el servidor porque el agente es un servicio de la plataforma; se documenta así.

**P-03 — ¿Quién llama a `POST /verify`?** *(antes de 4.2)*
- **Recomendado:** es la verificación del comercio/agente → exige credencial `service`. Los actos 4 y 5 de la demo de React dejan de llamarla directo y pasan por `/agent/run` con un escenario explícito (oferta trampa / mandato revocado).

**P-04 — `GET /audit`.** *(antes de 4.1)*
- **Recomendado:** cada usuario ve solo eventos de sus mandatos; `admin` ve todo.

**P-05 — `POST /audit/reset` (borra el ledger "append-only").** *(antes de 4.1)*
- **Recomendado:** sale del producto. Si la demo necesita "empezar limpio", que sea un reset por mandato del dueño (ya existe `/mandates/{id}/reset`) y, como mucho, una utilidad solo con `AUTH_DEV_MODE=true` + `admin`. Se elimina la ruta duplicada.

**P-06 — Webhooks de Stripe y del proveedor de viajes, y `approve-exception`.** *(antes de 7.1)*
- **Recomendado:** retirarlos. Hoy simulan cobros off-session sin Stripe real ni verificación de firma: es teatro. Se documentan como siguiente paso.
- Alternativa: integrarlos de verdad con Stripe en modo test (firma `Stripe-Signature`, secretos por entorno). Es más alcance; solo si quieres que el pago sea real.

**P-07 — `GET /inbox/messages` (lee el Gmail del proyecto) y `POST /notifications/send-ticket`.** *(antes de 7.1)*
- **Recomendado:** retirar el inbox; el envío de recibos queda como servicio interno disparado por la compra, no como endpoint.

**P-08 — `aegis_core.py`, `mandate/intelligent_issuer.py`, `run_demo.py`.** *(antes de 7.2)*
- **Recomendado:** retirar `aegis_core.py` e `intelligent_issuer.py` (tercer modelo de mandato, fuera del flujo); rehacer `run_demo.py` como script de punta a punta del flujo real (login dev → enrolar → firmar → comprar → revocar → auditar).

**P-09 — Dinero en todo el backend.** *(antes de 5.1)*
- **Recomendado:** migrar el modelo completo a enteros en la unidad mínima (`*_cents`) con moneda explícita. El engine compara exacto; se acaban los flotantes. React convierte en el borde.

**P-10 — Persistencia.** *(antes de 6.1)*
- **Recomendado:** SQLite con SQLAlchemy 2 (Core o ORM) + Alembic para migraciones. Real, sin infraestructura extra, y con migraciones versionadas. OTP, challenges y contadores de rate limit se quedan en memoria (efímeros, documentado con el punto de enganche para Redis).

**P-11 — El seed.** *(antes de 7.2)*
- **Recomendado (Opción B):** los tests crean sus mandatos con fixtures firmadas por una llave de prueba; para la demo local, `scripts/bootstrap_demo.py` solo con `AUTH_DEV_MODE=true`. El archivo `shared/seed_mandates.json` y el "sello de sistema" desaparecen.

**P-12 — Idioma.** *(antes de 7.3)*
- **Recomendado:** UI, mensajes de API y README en inglés (audiencia técnica global), README con un resumen en español; `presentation.ts` deja de traducir con regex porque el backend ya responderá en inglés. Los comentarios de código existentes no se reescriben en masa.

**P-13 — Despliegue en vivo.** *(antes de 9.1)*
- **Recomendado:** backend en un host con disco persistente para SQLite (Fly.io o Render con disco; confirmar precios ese día), frontend estático (Cloudflare Pages o Vercel), correo con un proveedor transaccional (Resend o Gmail con App Password). Con dominio propio si lo quieres bajo `renecano.com`.

**P-14 — Licencia y atribución.** *(antes de 12.1)*
- El código nace del hackathon con Ana Paola Oviedo y dglvanp. **Recomendado:** licencia MIT, pero **confírmalo con ellos** antes de aplicarla a código que coescribieron, y deja en el README una sección de origen y créditos explícita.

**P-15 — Modelos LLM.** *(antes de 5.3)*
- **Recomendado:** un único cliente LLM configurable por entorno, con modelo verificado que exista al momento (hoy hay un default `gpt-5.6` sin confirmar), timeout, fail-closed y presupuesto por request.

**P-16 — Costo de OpenAI en la demo en vivo.** *(antes de 9.1)*
- **Recomendado:** búsqueda real con cuota por usuario/día y tope de gasto global; al agotarse, error claro (no un resultado simulado presentado como real).

---

## 5. Hoja de ruta

| Fase | Paso | Objetivo | Capa | Requiere |
|---|---|---|---|---|
| 3 | 3.1 | Enrolar la llave del navegador | Frontend | — |
| 3 | 3.2 | Spec del mensaje firmado del mandato v1 + vectores | Ambos (aditivo) | — |
| 3 | 3.3 | Backend acepta mandatos firmados por el humano (doble vía) | Backend (aditivo) | — |
| 3 | 3.4 | El wizard firma el mandato con la llave del dispositivo | Frontend | — |
| 3 | 3.5 | Exigir la firma humana; retirar la firma del servidor | Backend | P-01, P-02 |
| 3 | 3.6 | PR, merge a `main`, borrar rama | Git/CI | — |
| 4 | 4.1 | Cerrar `/agent/run`, `GET /audit`, `/disputes/file`, `/audit/reset` | Backend + front | P-04, P-05 |
| 4 | 4.2 | `/verify` como verificación de servicio; demo por `/agent/run` | Ambos | P-03 |
| 5 | 5.1 | Dinero en centavos + reglas del engine + gramática | Backend | P-09 |
| 5 | 5.2 | Atomicidad de `max_uses` y presupuesto mensual | Backend | — |
| 5 | 5.3 | Un cliente LLM; firewall, juez y agente sin trucos | Backend | P-15 |
| 6 | 6.1 | Mapeo y diseño del esquema (solo lectura) | Backend | P-10 |
| 6 | 6.2 | Repositorios + migraciones; mandatos, dueños y llaves persistentes | Backend | — |
| 6 | 6.3 | Ledger persistente con verificación al arrancar; nonces anti-replay | Backend | — |
| 7 | 7.1 | Retirar el teatro restante (webhooks, inbox, recibo) | Ambos | P-06, P-07 |
| 7 | 7.2 | Sin seed; demo scripts reales; legado fuera | Ambos | P-08, P-11 |
| 7 | 7.3 | Logging, idioma, rutas y limpieza final de código | Ambos | P-12 |
| 8 | 8.1 | Dependencias y CI modernos (Vite, Node, matriz Python) | Infra | — |
| 8 | 8.2 | Calidad estática y seguridad de la cadena de suministro | Infra | — |
| 9 | 9.1 | Despliegue en vivo | Infra | P-13, P-16 |
| 10 | 10.1 | Evidencia medida (`docs/RESULTS.md`) | Ambos | — |
| 11 | 11.1 | E2E con Playwright (local y humo en vivo) | Frontend | — |
| 12 | 12.1 | README nivel Helada, ADRs, modelo de amenazas, licencia | Docs | P-14 |
| 13 | 13.1 | Auditoría de cierre y release `v1.0.0` | Todo | — |

Orden pensado por dependencias: la firma (3) va antes de cerrar rutas (4) porque cambia el contrato de creación; el engine (5) antes de persistir (6) para no migrar dos veces el modelo de dinero; la persistencia antes del despliegue (9); la evidencia, el E2E y la documentación al final porque describen el sistema terminado.

---

## 6. Fase 3 — La firma del humano

### 3.1 — Enrolamiento de la llave en el navegador

**Objetivo:** el navegador genera su llave no extraíble, pasa el step-up, firma el mensaje canónico de registro y queda enrolado. Todavía no firma mandatos.

**Definición de terminado:** la firma del navegador reproduce byte a byte `shared/key_registration_vectors.json`; el flujo completo funciona en el navegador; 409 por tope tiene camino de recuperación.

**Verificación de René:** con `AUTH_DEV_MODE=true`, iniciar sesión → "Register this device" → ver el `code_demo` del step-up → ingresarlo → la tarjeta muestra la llave registrada. Recargar e iniciar sesión otra vez: la misma llave sigue registrada (no se crea otra).

```
Lee docs/PLAN.md (secciones 1 y 2) y aplica todas las reglas. Rama fase-3-firma-cliente.
Paso 3.1: que el NAVEGADOR enrole su llave Ed25519. Solo frontend. NO conectes la llave a la
creación de mandatos ni a /verify (eso es 3.4). La app debe seguir creando mandatos igual
que hoy.

1. FIRMA CANÓNICA (frontend/src/lib/signing.ts):
   - signCanonical(privateKey, value): canonicaliza con la implementación TS del 2.0
     (lib/canonical.ts) y firma los bytes con signBytes del keystore. Devuelve hex.
   - Debe reproducir BYTE A BYTE shared/key_registration_vectors.json: mismo mensaje y
     misma firma hex para ambos vectores (normalización y acento). Como el vector usa la
     llave del RFC 8032, impórtala en el test como llave de prueba (importKey de pkcs8 o
     jwk SOLO en el test); la app nunca importa privadas.

2. ENROLAMIENTO (frontend/src/lib/enrollment.ts), usando AuthProvider/api del 2E:
   a. getOrCreateLocalKey(email) → pubkey hex.
   b. POST /keys/step-up/start → OTP al email del token; en dev maneja code_demo.
   c. El usuario ingresa el código.
   d. POST /keys/challenge {code}. 403 = código incorrecto: permite reintentar y NO cierres
      sesión. 429 = cooldown con Retry-After.
   e. Construye el registration_message EXACTO de la spec (purpose, challenge_id, nonce,
      owner = email de la sesión normalizado, public_key) y fírmalo con signCanonical.
   f. POST /keys {public_key, challenge_id, signature} → 201. Guarda keyId y
      registered=true en IndexedDB.
   g. 409 por tope de 10: lista con GET /keys y permite revocar una con DELETE
      /keys/{key_id}, luego reintenta. 409 por llave revocada: genera una nueva y enrola.
      422: bug del cliente, error claro.

3. ESTADO DE LA LLAVE (función pura, testeable) a partir de keystore + GET /keys:
   unsupported | none | local_unregistered | registered | missing_on_server
   (missing_on_server = la tienes local pero el servidor ya no la lista activa → regenerar
   y re-enrolar).

4. UI: en el wizard, tras iniciar sesión, una tarjeta "Register this device" con el estado,
   el campo del código de step-up, cooldown, errores y el resultado. Navegador sin soporte:
   mensaje claro de UnsupportedBrowserError, sin degradar. NO bloquees todavía la creación
   de mandatos.

TESTS (Vitest + fake-indexeddb + fetch simulado):
- signCanonical reproduce los dos vectores byte a byte (mensaje y firma).
- Flujo feliz: registra y persiste keyId/registered.
- 403 en challenge permite reintentar sin cerrar sesión; 429 expone cooldown.
- 409 por tope recorre revocar + reintentar; 409 por revocada regenera.
- Sin soporte: lanza el error claro sin abrir IndexedDB.
- Re-enrolar una llave ya registrada no crea otra.
- La función de estado cubre los 5 estados.

Al terminar: npm run build y npm test en verde; backend sin cambios (confírmalo con pytest).
Commit: "feat(frontend): enrolamiento de llave Ed25519 (step-up + challenge + PoP)".
```

---

### 3.2 — Especificación del mandato firmado v1 (aditivo)

**Objetivo:** fijar *qué bytes exactos* firma el humano, idénticos en Python y TS, antes de que nadie los use.

**Definición de terminado:** archivo de vectores compartido leído por pytest y Vitest; cambiar cualquier campo invalida la firma; separación de dominio frente a `register-key`.

```
Lee docs/PLAN.md (secciones 1 a 3) y aplica todas las reglas. Rama fase-3-firma-cliente.
Paso 3.2: especificación del mensaje que firma el humano al crear un mandato. Aditivo: no
conectes nada todavía (eso es 3.3 y 3.4).

1. Implementa mandate_signing_message(...) en Python (mandate/mandate_message.py) y su
   equivalente en TS (frontend/src/lib/mandateMessage.ts). Ambas producen los mismos bytes
   usando la canonicalización del 2.0.

2. Campos firmados (justifica en el reporte si propones cambiar alguno):
   - purpose: "agentbuyer:mandate:v1"
   - mandate_id (lo genera el cliente)
   - owner: email del token, trim + minúsculas
   - key_id y public_key de la llave que firma
   - agent_id
   - constraints normalizadas: montos en CENTAVOS ENTEROS (D-11), categorías y comercios
     normalizados (trim + minúsculas, ordenados, sin duplicados), max_uses, condiciones
   - search_fields (lo que el agente puede buscar/comprar)
   - expires_at: ISO 8601 UTC con Z y precisión de segundos. Hoy React manda valid_until y
     el backend lo ignora: el campo firmado se llama expires_at y en 3.3 el backend lo hará
     cumplir.
   - created_at (ISO 8601 UTC, segundos) y nonce (32 hex aleatorios del cliente)
   Fuera de la firma, a propósito: payment_token (lo emite el servidor después; en 3.3 se
   ata al hash del mandato firmado) y datos de contacto/documento (PII que no autoriza
   nada). Documenta esta lista en el docstring.

3. Conversión a centavos SIN flotantes: desde la representación decimal del número (Decimal
   en Python, string en TS). Más de 2 decimales, negativo, no finito o fuera del rango
   seguro → error (fail-closed). 150 → 15000; 150.1 → 15010; 0.1+0.2 calculado → error si
   no es exactamente 2 decimales.

4. Vectores en shared/mandate_signing_vectors.json, con la llave del RFC 8032 para fijar
   también la firma: caso base, montos con decimales, acentos en search_fields, listas
   desordenadas con duplicados, email con mayúsculas/espacios. Más inválidos: 3 decimales,
   monto negativo, fecha sin zona.

TESTS (pytest y Vitest leen el MISMO archivo):
- Ambos lenguajes producen los bytes y la firma exacta de cada vector.
- Cambiar cada campo firmado invalida la firma (un test por campo).
- Una firma de register-key:v1 no verifica como mandate:v1 y viceversa.
- Los inválidos fallan en ambos lados.
Mutación: rompe la conversión a centavos y el ordenamiento de listas; confirma detección.

Commit: "feat: especificacion del mandato firmado v1 (centavos, vectores compartidos)".
```

---

### 3.3 — El backend acepta mandatos firmados por el humano (doble vía, aditivo)

**Objetivo:** el backend entiende y verifica la firma humana *sin* romper lo que hoy envía React. Primero el proveedor acepta lo nuevo; luego el consumidor lo manda; al final se exige.

**Definición de terminado:** un mandato firmado según 3.2 se crea y aprueba en `/verify`; los mandatos sin firma siguen sellados por el servidor pero quedan **marcados** como sello; el contrato de React no cambia.

```
Lee docs/PLAN.md (secciones 1 a 3) y aplica todas las reglas. Rama fase-3-firma-cliente.
Paso 3.3: POST /mandates acepta mandatos firmados por el humano. ADITIVO: un payload sin
firma sigue funcionando como hoy. Los 15 tests de contrato no cambian.

1. Si el cuerpo trae {signature, key_id, created_at, nonce} (formato 3.2):
   - El owner sale del token (nunca del cuerpo). La llave se busca en OWNER_KEYS por
     (owner, key_id) y debe estar ACTIVA; la public_key la pone el servidor desde el
     registro, no el cliente.
   - Reconstruye mandate_signing_message desde el cuerpo y verifica con
     verify_ed25519_bytes. Falla → 403; cuerpo malformado → 422; key_id ajeno o inexistente
     → 403 (sin revelar si existe).
   - created_at no puede estar en el futuro (tolerancia 2 min) ni ser más viejo que 10 min;
     el nonce es único por dueño (anti-replay de creación).
   - expires_at se GUARDA y se hace cumplir (hoy valid_until se ignora).
2. Si NO trae firma: comportamiento actual (el servidor sella), pero registra el tipo.
3. Guarda aparte, como MANDATE_OWNERS, un registro MANDATE_SIGNERS por mandate_id:
   {kind: "human" | "system_seal", key_id, public_key, message_hash, signed_at}. No se
   filtra a la respuesta pública.
4. /verify (las dos líneas): para kind=human reconstruye el mensaje del mandato guardado y
   verifica contra la public_key registrada; además comprueba que la llave siga
   perteneciendo al dueño. El check de firma informa en "detail" si fue firma humana o sello
   de sistema.
5. payment_token: el servidor lo emite DESPUÉS y lo ata al sha256 de los bytes firmados
   (message_hash). /verify rechaza un token cuyo binding no coincide.

TESTS: crear con firma válida → 201 y kind=human; firma de otra llave del mismo dueño ≠
key_id → 403; llave de otro dueño → 403; llave revocada → 403; campo alterado tras firmar
→ /verify REJECT; created_at viejo o futuro → 422/403; nonce repetido → 409; sin firma →
igual que hoy con kind=system_seal; expires_at vencido → REJECT; payment_token de otro
mandato → REJECT. Helper de test que firma como lo hará el cliente (reutiliza los vectores).
Mutación: quita la comprobación de pertenencia de la llave, del binding del token y del
anti-replay; confirma detección.

Commit: "feat: backend verifica mandatos firmados por el humano (doble via, aditivo)".
```

---

### 3.4 — El wizard firma el mandato

**Objetivo:** React firma cada mandato con la llave del dispositivo. Enrolar pasa a ser requisito para autorizar.

**Verificación (René o Claude Code en modo autónomo):** iniciar sesión → registrar el dispositivo → crear un mandato → aparece "Signed on this device" → en Mission Control una compra muestra el check de firma como **firma del titular** (ya no "system seal"). Cerrar sesión y entrar con otro email en el mismo navegador → pide registrar otra llave. La vigencia se muestra con fecha, hora y zona.

```
Lee docs/PLAN.md (secciones 0b, 1 a 4) y aplica todas las reglas. Rama fase-3-firma-cliente.
Paso 3.4: el wizard firma el mandato con la llave del dispositivo usando la spec del 3.2
(lib/mandateMessage.ts) y lo envía en el formato firmado que el backend acepta desde el 3.3.

1. Requisito para autorizar: sesión activa Y llave en estado "registered" (DeviceKeyCard del
   3.1). En none, local_unregistered o missing_on_server el wizard guía a enrolar antes de
   avanzar; el botón de autorizar explica qué falta. La tarjeta deja de decir que la llave
   "todavía no firma tus permisos".
2. submitMandate construye el payload firmado:
   - montos en el formato de la spec (centavos en el mensaje; el humano los ve y escribe en
     su formato normal), currency "USD", off_session_consent como lo eligió la persona,
     search_fields, agent_id, mandate_id generado por el cliente;
   - created_at y nonce con toSignedTimestamp y newMandateNonce;
   - expires_at según D-19: final del día elegido (23:59:59) en la zona LOCAL del navegador,
     convertido a UTC con Z; la confirmación muestra fecha, hora y zona. Fecha pasada o no
     posterior a created_at → error del formulario.
   - firma con signCanonical sobre mandate_signing_message y envía {campos de la spec,
     signature, key_id, created_at, nonce}. Nada fuera de la spec.
   - Errores: 403 de firma/llave → mensaje claro y recargar el estado de la llave; 409 de
     nonce → regenerar y reintentar una vez; 422 → error del formulario con el campo.
3. Cambiar un límite después de firmar obliga a firmar de nuevo (la firma se calcula al
   autorizar, nunca se reutiliza).
4. Mission Control y la confirmación muestran la verdad: "Signed on this device" con el
   key_id corto; el check de firma de /verify se presenta como firma del titular. Nada de
   promesas de hardware o biometría (R12).
5. Demo automática: con AUTH_DEV_MODE=true enrola (code_demo del step-up) y firma sola; sin
   modo dev espera los códigos.
6. Contrato de React (cambio deliberado, R4): tests/test_frontend_contract.py congela el
   payload FIRMADO del wizard (generado con el helper que firma como el cliente) y que crea
   un mandato kind=human. Explica la diferencia con el contrato anterior.

TESTS (Vitest): el payload reproduce byte a byte mandate_signing_message y la firma verifica;
sin llave registrada no se autoriza; editar un límite tras firmar genera firma nueva;
expires_at = final del día local en UTC (al menos dos zonas simuladas); 409 de nonce reintenta
una vez; 403 recarga el estado de la llave. Mutación: JSON.stringify, reutilizar firma tras
editar, expires_at a medianoche UTC.

Commit: "feat(frontend): el humano firma su mandato con la llave del dispositivo".
```

---

### 3.5 — Exigir la firma humana (P-01, P-02 resueltas en la sección 4)

**Objetivo:** el servidor deja de firmar por los usuarios. No-repudio a nivel de dispositivo de verdad.

**Definición de terminado:** ningún mandato creado por un usuario existe sin firma humana; el sello de sistema solo existe para el seed (hasta 7.2); sondeo de ataques congelado como regresión.

```
Lee docs/PLAN.md (secciones 0b, 1 a 4) y aplica todas las reglas. Rama fase-3-firma-cliente.
Paso 3.5: exigir la firma humana. Cambia el contrato de POST /mandates a propósito.
Decisiones: P-01 y P-02 según "Resoluciones vigentes".

1. POST /mandates sin firma humana válida → 422 (falta) / 403 (no verifica). El servidor ya no
   firma mandatos de usuarios. kind=system_seal solo para el seed cargado al arrancar; ningún
   endpoint puede crearlo. Se retira kind=legacy_client (firma con llave no registrada) y el
   camino legado que aceptaba un payment_token enviado por el cliente: el token siempre lo
   emite el servidor y queda atado a message_hash (también para el seed).
2. P-01 (a): /verify agrega el check signing_key_active y rechaza mandatos firmados con una
   llave revocada; cambia a propósito el test que hoy fija lo contrario. DELETE /keys
   responde cuántos mandatos quedan sin efecto.
3. P-02: retira POST /mandates/create y las llaves humanas de _key_registry. Las llaves del
   agente se quedan del lado del servidor; documenta por qué en el código. Ajusta el
   guardián de OpenAPI.
4. Sondeo de regresión permanente (tests/test_mandate_signature_attacks.py): sin firma;
   firma basura; firma de otro dueño; llave de otro dueño con key_id propio; llave revocada
   antes y después de crear; mensaje de register-key presentado como mandato; replay de una
   creación; campo alterado después de firmar; payment_token de otro mandato o enviado por
   el cliente. Todos rechazados.
5. Tests que creaban mandatos sin firma: pásalos al helper que firma como el cliente. Solo los
   que prueban el seed pueden usar el sello.

Mutación: permitir el sello para usuarios, reactivar la ruta retirada, ignorar la revocación.
Commit: "seguridad: exigir firma humana en mandatos; el servidor deja de firmar por el usuario".
```

---

### 3.6 — Cierre de la Fase 3

**Verificación de René (completa, en el navegador):** login → enrolar → firmar mandato → compra aprobada → revocar → compra rechazada → auditoría con cadena válida (`GET /audit/verify`).

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-3-firma-cliente.
Paso 3.6: prepara el cierre de la Fase 3, sin cambiar código de producto.
1. Corre la suite completa y el build; reporta conteos.
2. Revisa el diff completo de la rama contra main y reporta: archivos tocados, endpoints que
   cambiaron de contrato, migraciones de comportamiento que René debe conocer.
3. Escribe el cuerpo del Pull Request en docs/pr/fase-3.md (resumen, garantías nuevas con
   el test que prueba cada una, cambios de contrato, límites conocidos: la sesión sigue
   siendo la raíz de confianza; un XSS puede USAR la llave mientras dure; WebAuthn como
   siguiente paso).
Commit: "docs: resumen de la Fase 3 para el PR".
```

Luego, el cierre de fase de la sección 0b (en modo autónomo lo hace Claude Code): CI replicado en limpio, merge `--no-ff` a `main` usando `docs/pr/fase-3.md` como mensaje, push, CI verde en `main`, rama borrada.

---

## 7. Fase 4 — Cerrar las rutas que siguen abiertas

Trabajo en una rama nueva: `git checkout main && git pull && git checkout -b fase-4-rutas`.

### 4.1 — `/agent/run`, `GET /audit`, `/disputes/file`, `/audit/reset` `⛔ requiere P-04, P-05`

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-4-rutas.
Paso 4.1: autenticar y autorizar las rutas de React que siguen abiertas, excepto /verify.
DECISIÓN P-04: <...>   DECISIÓN P-05: <...>

1. POST /agent/run: exige token y require_mandate_access sobre el mandato. Añade cuota por
   usuario (ej. N corridas/hora, configurable) porque consume OpenAI; al agotarse 429 con
   Retry-After.
2. GET /audit: según P-04 (dueño ve lo suyo; admin todo). Arregla get_trail_for, que ignora
   attempt_id.
3. POST /disputes/file: exige ser dueño del mandato del intento. Arregla la evidencia: solo
   eventos de ese mandato (hoy incluye todos).
4. POST /audit/reset: según P-05. Elimina el registro duplicado (api/main.py y api/audit.py).
5. resolve_escalation / approve_escalation: rechaza (409) si el mandato está revocado,
   pausado o vencido antes de aprobar.
6. Frontend: deja de llamar lo que se retire y ajusta la demo. Contrato de React cambiado a
   propósito: actualiza los tests de contrato para autenticar y documenta.
7. Guardián de OpenAPI: REACT_ROUTES sin seguridad debe quedar vacío salvo /verify.

TESTS: matriz 401/403/200 por ruta; evidencia de disputa sin eventos ajenos; escalación
sobre mandato revocado → 409; cuota de /agent/run → 429. Mutación en cada uno.
Commit: "seguridad: autenticar agent/run, audit y disputes; fuera audit/reset del producto".
```

### 4.2 — `/verify` como verificación de servicio `⛔ requiere P-03`

**Verificación de René:** la demo de 5 actos completa funciona con login, incluidos el acto trampa y el acto de revocación.

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-4-rutas.
Paso 4.2: POST /verify pasa a ser la verificación del comercio/agente.
DECISIÓN P-03: <...>
1. /verify exige credencial service (require_service). Exige nonce único por intento
   (anti-replay) y firma del agente sobre el intento cuando el intento la declara.
2. Los actos 4 y 5 de la demo de React dejan de llamar /verify: usan /agent/run con un
   escenario explícito y visible ("trap offer", "after revocation"). El escenario lo
   decide el servidor a partir de un parámetro permitido solo para el dueño del mandato.
3. La moneda del intento debe coincidir con la del mandato.
TESTS: /verify sin service key → 401; con JWT de usuario → 401/403; replay de nonce →
REJECT; moneda distinta → REJECT; los escenarios de la demo producen los veredictos
esperados. Commit: "seguridad: /verify solo para servicios con anti-replay; demo via agent/run".
```

Cierre: PR `fase-4-rutas` → `main` con CI verde.

---

## 8. Fase 5 — Motor de decisión

Rama: `fase-5-motor`.

### 5.1 — Dinero exacto y reglas del engine `⛔ requiere P-09`

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-5-motor.
Paso 5.1: dinero exacto y reglas del engine sin huecos.
DECISIÓN P-09: <...>
1. Modelo de dinero en enteros de la unidad mínima + moneda explícita en mandato, intento,
   live_state (amount_spent) y ledger. Conversión solo en los bordes. Migra los datos de
   prueba y el contrato (cambio deliberado).
2. engine/evaluator.py:
   - monto ≤ 0, no entero o moneda distinta → REJECT;
   - categoría y comercio por igualdad exacta normalizada (hoy substring/endswith);
   - mandato sin límite de monto → REJECT (hoy aprueba cualquier monto);
   - estados PAUSED/EXPIRED/REVOKED rechazados en ambas líneas (confírmalo con test).
3. engine/grammar.py: campo ausente con != → False (hoy True); límite de tamaño para
   multiplicación de strings/listas y profundidad del AST (DoS).
4. core/agent_loop.py: si ninguna oferta cabe en el límite, no intenta la más barata;
   unifica <= vs < entre eligible y price_below.
TESTS para cada hueco (los de la auditoría original: montos negativos, travel vs
travel_giftcards, mandato sin constraints, != con campo ausente, 'a'*999999999). Mutación.
Commit: "fix(engine): dinero en centavos, igualdad exacta, gramatica sin fail-open".
```

### 5.2 — Concurrencia y presupuesto mensual

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-5-motor.
Paso 5.2: "verificar y consumir" atómico, y presupuesto mensual real.
1. Una sola operación atómica reserva el uso y el monto bajo lock; si después se rechaza,
   libera la reserva. Dos compras simultáneas no pueden superar max_uses ni el presupuesto.
2. monthly_budget se aplica; los contadores mensuales se reinician por periodo calendario
   en UTC (o la zona declarada en el mandato; justifica). uses_count total vs mensual,
   documentado.
TESTS: 50 hilos contra max_uses=3 → exactamente 3 aprobaciones; presupuesto mensual y cambio
de mes con reloj inyectado. Mutación: quita el lock.
Commit: "fix: consumo atomico de usos y presupuesto mensual".
```

### 5.3 — Capa LLM honesta `⛔ requiere P-15`

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-5-motor.
Paso 5.3: un solo cliente LLM y heurísticas sin trucos.
DECISIÓN P-15: <...>
1. core/llm.py: cliente único (modelo y timeout por entorno, reintentos acotados, sin
   claves en logs). Migra core/verify.py, core/semantic_firewall.py, engine/llm_judge.py y
   core/merchant_search.py. Elimina el parseo manual de .env (usa python-dotenv).
2. Firewall: el resultado ESCALATE siempre escala (confírmalo en ambas líneas); la
   heurística offline deja de "detectar" cargos por contener "10" o "20" y deja de usar
   palabras clave solo en español; el juez deja de usar substrings ("vale" ≠ "Valencia").
3. Identidad del comercio: no se acepta el comercio que AFIRMA el LLM. Se deriva del
   dominio/fuente verificada de la oferta y se compara contra allowed_merchants.
4. Documenta qué decide el LLM y qué decide el código determinista (para la sección de IA
   responsable del README): el LLM nunca puede aprobar lo que el engine rechaza.
TESTS herméticos con cliente simulado: respuesta malformada, timeout y veredicto
desconocido → fail-closed; comercio afirmado por el LLM distinto del dominio → REJECT.
Commit: "refactor: cliente LLM unico; firewall y comercio verificados".
```

Cierre: PR → `main` con CI verde.

---

## 9. Fase 6 — Persistencia

Rama: `fase-6-persistencia`.

### 6.1 — Mapeo y diseño (solo lectura) `⛔ requiere P-10`

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-6-persistencia.
Paso 6.1: SOLO LECTURA. No modifiques código.
DECISIÓN P-10: <...>
Inventaria todo el estado en memoria (MANDATES, MANDATE_OWNERS, MANDATE_SIGNERS,
OWNER_KEYS, ledger, escalaciones, disputas, nonces, OTP, challenges, rate limits, cuotas).
Para cada uno: forma, quién lee/escribe, invariantes, si debe persistir o es efímero y
por qué. Propón el esquema (tablas, claves, índices, restricciones de unicidad que hoy
garantiza el código: pubkey global única, nonce por dueño, etc.), la capa de repositorios
y el orden de migración con riesgo por paso. Escribe la propuesta en docs/design/persistence.md.
Commit: "docs: diseno de persistencia".
```

### 6.2 — Repositorios y migraciones

```
Lee docs/PLAN.md y docs/design/persistence.md y aplica todas las reglas.
Paso 6.2: implementa la capa de repositorios y la primera migración para mandatos, dueños,
firmantes y llaves. DATABASE_URL por entorno (SQLite por defecto en dev; archivo fuera del
repo, en .gitignore). Los tests usan una base temporal por test. Las restricciones de
unicidad viven en la base, no solo en el código. Transacciones donde hoy hay locks.
Sobrevivir a reinicios: test que crea, "reinicia" la app y lee.
Commit: "feat: persistencia de mandatos, duenos y llaves (SQLite + migraciones)".
```

### 6.3 — Ledger persistente y anti-replay

```
Lee docs/PLAN.md y docs/design/persistence.md y aplica todas las reglas.
Paso 6.3: el ledger con cadena hash, escalaciones, disputas y nonces se persisten.
- Al arrancar se verifica la cadena completa; si está rota, la app no arranca y lo explica
  (o arranca en modo solo-lectura; justifica la elección).
- El ledger es append-only también en la base (sin UPDATE/DELETE desde la app).
- Nonces anti-replay persistentes con expiración.
- OTP, challenges y rate limits siguen en memoria: documenta el punto exacto donde se
  conectaría Redis.
TESTS: alterar una fila del ledger en la base → arranque detecta; replay tras reinicio →
REJECT. Commit: "feat: ledger persistente con verificacion al arrancar y anti-replay durable".
```

Cierre: PR → `main` con CI verde.

---

## 10. Fase 7 — Higiene final y retiro del teatro restante

Rama: `fase-7-higiene`.

### 7.1 — Webhooks, inbox y recibo `⛔ requiere P-06, P-07`

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-7-higiene.
DECISIÓN P-06: <...>   DECISIÓN P-07: <...>
- Aplica P-06 (retirar los webhooks y approve-exception, o integrarlos con verificación de
  firma real y secretos por entorno).
- Aplica P-07 (inbox y send-ticket).
- Recibo de compra: plantilla en archivo (Jinja2 con autoescape), datos reales de la compra
  (hoy dice mch_vuelaya / FLT-COR-130 siempre), sin textos de marketing falsos; envío con
  timeout. IMAP con timeout si queda algo de IMAP.
Commit: "refactor: fuera webhooks/inbox de demo; recibo real con plantilla segura".
```

### 7.2 — Sin seed; demo real; legado fuera `⛔ requiere P-08, P-11`

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-7-higiene.
DECISIÓN P-08: <...>   DECISIÓN P-11: <...>
- Aplica P-11: fixtures de tests con mandatos firmados por una llave de prueba;
  scripts/bootstrap_demo.py solo con AUTH_DEV_MODE=true; fuera shared/seed_mandates.json y
  el kind system_seal (y su rama en /verify).
- Aplica P-08 (aegis_core.py, intelligent_issuer.py; run_demo.py reescrito como recorrido
  de punta a punta del flujo real que sale en verde o en rojo según el resultado real, sin
  "✅" fijos).
- La suite debe seguir verde sin ningún mandato precargado.
Commit: "refactor: sin seed ni legado; demo de punta a punta real".
```

### 7.3 — Logging, idioma y limpieza `⛔ requiere P-12`

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-7-higiene.
DECISIÓN P-12: <...>
- logging estructurado (logger por módulo, niveles, request id) en lugar de los print;
  nada de PII ni secretos en logs (test que lo comprueba en los flujos de auth).
- Mensajes de API y UI en el idioma de P-12; presentation.ts deja de traducir con regex.
- Colisión de rutas /audit/{id} con ids reservados; GET /mandates con un registro inválido
  no tumba la lista completa.
- Barrido de código muerto, imports sin uso, except Exception: pass y tipos LiveState
  incompletos en React; useEffect con dependencias correctas.
- frontend/.gitignore ignora .vite/.
Commit: "chore: logging, idioma consistente y limpieza final".
```

Cierre: PR → `main` con CI verde.

---

## 11. Fase 8 — Dependencias, CI y calidad estática

Rama: `fase-8-infra`.

### 8.1 — Dependencias y CI modernos

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-8-infra.
- Actualiza Vite a una versión mayor soportada y Vitest a la que la acompañe (cierra los
  advisories de esbuild/Vite/Vitest); revisa React/plugin compatibles. Revisa el changelog
  de cada major y reporta rupturas.
- Node del CI a 22 o 24 (LTS vigente); Python en matriz (3.13 y 3.14). Revisa la línea
  Starlette 0.52 vs 1.x que quedó anotada en requirements.txt y decide con evidencia.
- Mantén todo fijado (== y lockfile).
Commit: "build: dependencias y CI actualizados".
```

### 8.2 — Calidad estática y cadena de suministro

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-8-infra.
- ruff (lint + format) y mypy gradual (estricto en core/auth_*, mandate/, api/security.py);
  ESLint en el frontend. Arregla lo que marquen sin desactivar reglas a ciegas.
- pytest-cov y cobertura de Vitest con umbral en CI (fija el umbral en la cobertura real
  actual, no inventado).
- pip-audit y npm audit en CI; Dependabot; pre-commit opcional documentado.
Commit: "ci: lint, tipos, cobertura y auditoria de dependencias".
```

Cierre: PR → `main` con CI verde.

---

## 12. Fase 9 — Despliegue en vivo `⛔ requiere P-13, P-16`

Rama: `fase-9-deploy`.

**Verificación de René:** abrir la URL pública desde el teléfono, iniciar sesión con un correo real, enrolar, firmar un mandato y hacer una compra.

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-9-deploy.
DECISIÓN P-13: <...>   DECISIÓN P-16: <...>
- Configuración de despliegue del backend (Dockerfile o la que pida el host), disco
  persistente para SQLite, migraciones al arrancar, healthcheck.
- Frontend estático con VITE_API_BASE de producción; CORS solo para ese origen.
- Producción con AUTH_DEV_MODE apagado, JWT_SECRET y SERVICE_API_KEY generados, SMTP real.
- Cuotas de OpenAI según P-16.
- docs/DEPLOY.md: pasos exactos para desplegar desde cero y rotar secretos.
- Workflow de despliegue (o instrucciones) que solo despliega con CI verde.
NO subas secretos al repo: lista las variables que René debe cargar en el host.
Commit: "deploy: configuracion de produccion y guia de despliegue".
```

---

## 13. Fase 10 — Evidencia medida

Rama: `fase-10-resultados`.

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-10-resultados.
Paso 10.1: evidencia reproducible en docs/RESULTS.md, generada por scripts/benchmarks/ (un
comando la regenera completa).
1. Latencia de /verify y de creación de mandato (p50/p95/p99, N fijo, hardware declarado:
   laptop Windows de 8 GB) y costo aislado de firma/verificación Ed25519.
2. Matriz de ataques: cada ataque (bypass de firma A–E, 12 tokens JWT inválidos, squatting
   por 4 vectores, replay de challenge/nonce, firma de otro dueño, llave revocada, montos
   negativos, categoría por substring, TOCTOU) → bloqueado sí/no + el test que lo prueba
   (enlace a archivo:línea). Se genera ejecutando los tests, no escrito a mano.
3. Comparación contra alternativas simples, mismo banco de ataques: (a) API key compartida
   / HMAC, (b) solo sesión bearer sin firma, (c) firma del servidor por el usuario (el
   diseño anterior). Qué ataques bloquea cada una.
4. Cobertura y conteo de tests por capa.
Commit: "docs: resultados medidos y reproducibles".
```

---

## 14. Fase 11 — E2E con Playwright (pruebas pesadas, al final)

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-11-e2e.
Paso 11.1: Playwright con Chromium real (WebCrypto Ed25519 nativo).
- Recorrido: login OTP (dev) → enrolar → firmar mandato → compra aprobada (búsqueda
  simulada en el backend de test) → oferta trampa escalada → revocar → compra rechazada →
  /audit/verify válido.
- Casos: recarga vuelve al login sin error; sesión expirada muestra el aviso; segundo
  usuario en el mismo navegador no ve ni usa la llave del primero.
- Job de CI separado (no bloquea el job rápido) y modo "humo" contra la URL en vivo sin
  crear basura (o con limpieza).
Commit: "test: e2e con Playwright del flujo completo".
```

---

## 15. Fase 12 — Documentación nivel Helada `⛔ requiere P-14`

Rama: `fase-12-docs`.

**Definición de terminado:** cada afirmación del README enlaza a código, test o resultado que la respalda; ninguna afirmación sin respaldo sobrevive.

```
Lee docs/PLAN.md y aplica todas las reglas. Rama fase-12-docs.
DECISIÓN P-14: <...>
Reescribe la documentación. Regla de oro: toda afirmación enlaza a su evidencia (archivo,
test o docs/RESULTS.md). Lo que no tenga evidencia se borra.

README.md:
1. El problema (agentes que compran por humanos) con fuentes reales citadas.
2. Qué hace AgentBuyer, en una pantalla, con captura/GIF del flujo real.
3. Cómo probarlo: URL en vivo y local paso a paso (incluye JWT_SECRET/AUTH_DEV_MODE).
4. Resultados medidos (resumen de RESULTS.md) y comparación con alternativas simples.
5. Arquitectura (diagrama mermaid del flujo REAL actual) y mapa del repo.
6. Seguridad: modelo de identidad (user/admin/service), firma humana, ledger; qué protege y
   qué NO (enlace a THREAT_MODEL.md).
7. IA responsable: qué decide el LLM y qué el código; qué datos salen hacia el proveedor.
8. Datos: catálogo/búsquedas, su origen y que no hay datos personales reales.
9. Límites honestos y siguiente paso (WebAuthn con attestation, Redis, pagos reales, etc.).
10. Origen y créditos (hackathon, equipo original) y licencia según P-14.
Quita badges y afirmaciones falsas (Merkle, "Zero Raw Card Exposure", repo de otra persona).

docs/:
- ARCHITECTURE.md reescrito al sistema actual.
- DECISION_LOG.md: corrige ADRs desactualizados y agrega los de este proyecto (D-01..D-14 y
  P-01..P-16 resueltas), cada uno con contexto, alternativas, decisión y consecuencias.
- THREAT_MODEL.md: activos, actores, superficie, y por cada amenaza la defensa y el test;
  incluye los límites conocidos (la sesión/correo es la raíz de confianza; un XSS puede usar
  la llave no extraíble mientras dure; el servidor no puede probar que la llave es no
  extraíble sin attestation).
- SECURITY.md (cómo reportar), LICENSE, CONTRIBUTING corto.
- PRESENTATION.md y slides.html: actualizar al sistema real o retirar (slides.html cita un
  demo/app.py que no existe).
- docs/PLAN.md: muévelo a docs/history/ como registro del proceso.
Commit: "docs: documentacion completa con evidencia, modelo de amenazas y licencia".
```

---

## 16. Fase 13 — Auditoría de cierre y release

```
Lee docs/PLAN.md y aplica todas las reglas. En main actualizado.
Paso 13.1: SOLO LECTURA primero.
1. Repite la auditoría completa del inicio (autenticación y seguridad, bugs, arquitectura,
   tests, dependencias, calidad) sobre el código actual.
2. Cruza contra la lista original de hallazgos: para cada uno, estado = corregido (commit y
   test) / decidido y documentado (ADR) / abierto (por qué). Escríbelo en
   docs/history/audit-closure.md.
3. Si queda algo crítico o alto abierto, DETENTE y repórtalo: no hay release.
Si todo cierra: commit del documento con "docs: cierre de auditoria".
```

René: tag `v1.0.0` con notas de release, descripción y topics del repo en GitHub, pin en su perfil y enlace desde el portafolio.

---

## 17. Definición de terminado del proyecto

- [ ] Todo hallazgo de la auditoría original está corregido o decidido y documentado.
- [ ] El humano firma sus mandatos en su dispositivo; el servidor nunca firma por un usuario.
- [ ] Ninguna ruta que modifique estado o exponga datos privados es anónima.
- [ ] Estado persistente; ledger verificado al arrancar.
- [ ] CI con backend, frontend, lint, tipos, cobertura, auditoría de dependencias y E2E.
- [ ] Despliegue en vivo funcionando con correo real.
- [ ] `docs/RESULTS.md` reproducible con un comando.
- [ ] README con problema y fuentes, cómo probar (vivo y local), resultados contra alternativas, mapa del repo, datos con fuente, IA responsable, límites y siguiente paso, evidencia para cada afirmación, licencia y créditos.
- [ ] Release `v1.0.0`.

---

## 18. Bitácora de progreso

| Fecha | Paso | Commit | Tests (pytest / Vitest) | Notas |
|---|---|---|---|---|
| 2026-11-16 | 3.1 Enrolamiento del navegador | `eca397f` | 488 / 120 | Firma reproduce vectores de registro; 20 mutaciones detectadas |
| 2026-11-16 | 3.2 Spec del mandato firmado v1 | `065f1bf` | 669 / 215 | 7 vectores válidos, 23 inválidos; añade currency y off_session_consent (D-15, D-16) |
| 2026-11-16 | 3.3 Backend acepta mandatos firmados (doble vía) | `da4c784` | 756 / 215 | kind human / system_seal / legacy_client; binding de token; search_fields atados; llave revocada aún aprueba → 3.5 (P-01) |
| 2026-11-16 | Verificación del 3.3 (navegador) | `46e2f38` | 756 / 215 | Chromium headless: el wizard crea y compra igual (APPROVE); el check de firma dice "system seal". CI de la rama vía PR #1 (borrador): verde |
| 2026-11-16 | 3.4 El wizard firma el mandato | `58734f0` | 756 / 239 | Navegador (TZ America/Mexico_City): sin dispositivo no avanza; registrar → confirmar muestra "Nov 30, 2026, 11:59:59 PM CST (America/Mexico_City)" → "Signed on this device" → compra APPROVE con "cardholder signature"; otro email en el mismo navegador pide otra llave; la demo guiada enrola y firma sola en dev. Decisiones: montos como texto tecleado; off_session_consent elegible (por defecto sí); helper MandateSigner en conftest. Contrato de React: el alta congela el payload firmado (kind=human). 8 mutaciones detectadas (una pedía un caso DST nuevo: Sydney) |
| 2026-11-16 | 3.5 Exigir la firma humana | `9d51047` | 783 / 240 | POST /mandates sin firma → 422; el servidor ya no firma por usuarios; kind=system_seal solo para el seed (token emitido por el servidor y atado al hash); fuera legacy_client. P-01 (a): check signing_key_active en ambas líneas; DELETE /keys devuelve mandates_affected (la tarjeta lo muestra). P-02: fuera POST /mandates/create y las llaves humanas (_agent_key_registry para el agente). Decisión propia: también se retiró POST /adversarial/run (creaba mandatos sellados en el registro vivo, prohibido por el punto 1); la mecánica de require_service se prueba con una ruta de prueba hasta el 4.2. Sondeo permanente tests/test_mandate_signature_attacks.py (27). 12 archivos de tests migrados al helper que firma como el cliente. 8 mutaciones detectadas (3 pidieron tests nuevos). Navegador: el flujo manual y la demo siguen creando y comprando con firma del titular |
| 2026-11-16 | 3.6 Cierre de la Fase 3 | `65ff63c` (merge `06df819`) | 783 / 240 | docs/pr/fase-3.md (garantías con su test, cambios de contrato, migraciones, límites). Navegador, recorrido completo (TZ America/Mexico_City): login → registrar dispositivo → firmar → compra APPROVED ("cardholder signature") → revocar → compra REJECTED ("mandate revoked") → Audit con 18 eventos y GET /audit/verify valid=True; sin errores de consola. Pendientes vistos: la vista Audit muestra eventos de todos los usuarios (P-04, 4.1); GET /audit/verify es anónimo; el texto del agente dice "real search" aunque la búsqueda esté simulada (5.3); título de Mission Control en español (7.3) |
| 2026-11-16 | 4.1 Rutas de React con sesión y propiedad | `3466a2c` | 802 / 240 | /agent/run: dueño + cuota por usuario (20 cada 24 h, P-16; 429 + Retry-After; un 422 previo a buscar devuelve el uso). GET /audit: lo propio, admin todo (P-04). /disputes/file: dueño, el intento debe ser de ese mandato (cerraba un fraude de reembolso), evidencia sin eventos ajenos. GET /disputes: lo propio (decisión propia, misma regla que P-04). /audit/reset: admin + AUTH_DEV_MODE, si no 404; ruta duplicada fuera (P-05). Escalaciones: 409 también si la llave que firmó fue revocada; la línea estricta rechaza aprobar sobre mandatos no activos. get_trail_for filtra por attempt_id. React deja de llamar /audit/reset; la vista Audit dice "Your permissions' record" a un usuario. Contrato de React: +3 tests (las rutas exigen el token). 13 mutaciones detectadas. Navegador: flujo completo y demo guiada OK |
| 2026-11-16 | 4.2 /verify como verificación de servicio | `9712c55` | 823 / 240 | /verify exige credencial service (P-03); función interna verify_attempt para el agente. Anti-replay: nonce único por intento (se quema aunque el intento se rechace). Firma del agente verificada cuando el intento la declara (core/agent_keys.py; el agente firma sus intentos). Moneda exigida en TODO mandato. Demo: actos 4 y 5 por /agent/run con scenario ("trap_offer", "after_revocation"): oferta sintética rotulada, sin búsqueda web ni cuota, verificación sin efecto (nunca compra; evento scenario_verification, no disputable); after_revocation exige mandato revocado (409). Hallazgo: el acto 4 antiguo APROBABA la "trampa" (el firewall solo se activaba con palabras clave en español). React ya no llama /verify; guardián OpenAPI: ninguna ruta de React sin seguridad. 10 mutaciones detectadas. Navegador: demo de 5 actos completa con login (actos 2-3 APPROVE, acto 4 REJECT por el firewall, acto 5 REJECT por revocación), 0 llamadas a /verify desde el navegador. Pendiente (5.3): el resumen del firewall offline es un texto fijo que menciona "upgrade" y "48-hour hold" aunque la trampa sea otra |
| 2026-11-16 | Cierre de la Fase 4 | `6e482c7` (merge `9c8eef8`) | 823 / 240 | docs/pr/fase-4.md; PR #2 → main con CI replicado en limpio (Python 3.13 + npm ci) |
| 2026-11-16 | 5.1 Dinero exacto y reglas del engine | `fc9f9ec` | 879 / 240 | P-09: dinero en centavos enteros + moneda en mandato (lo firmado se guarda tal cual), intento (amount_cents, metadata.price_cents), live_state (amount_spent_cents), ledger (amount_cents) y ofertas (price_cents); core/money.py = única conversión de borde (la misma to_cents de la spec); seed y línea estricta (legado) convierten en su borde; React convierte solo al mostrar (y ya no redondea $139.99 a $140). Engine: REJECT para monto inválido, moneda distinta, mandato sin límite, sin categorías/comercios o condición desconocida; igualdad exacta normalizada ("*" explícito; lista vacía ya no es "cualquiera"). Gramática: campo ausente no cumple != ; topes de repetición, largo y profundidad. Línea A: un mandato PAUSADO aprobaba (hueco nuevo, cerrado). Agente: si nada cabe no intenta; misma regla que el engine (<= tope, < price_below). Contrato de React cambiado a propósito (forma en centavos; la escalación por el agente ahora es la del comercio fuera del mandato). 15 mutaciones detectadas (2 pidieron afinar tests que pasaban por la razón equivocada). Navegador: flujo completo y demo de 5 actos OK |
| 2026-11-16 | 5.2 Consumo atómico y presupuesto mensual | `bf5c80d` | 886 / 240 | reserve_purchase: verificar y consumir en UNA operación bajo el lock (estado vivo, usos de por vida, usos y presupuesto del mes); va al final de la verificación (después del firewall), así que nada rechaza después y no hace falta liberar. Si una compra simultánea gana el último uso, la perdedora se re-evalúa con el estado fresco (ESCALATE). 50 hilos contra max_uses=3 → exactamente 3; 30 hilos contra un presupuesto de 2 compras → exactamente 2. monthly_budget_cents por mes calendario UTC (justificado: el mandato firmado no declara zona y el corte debe ser verificable); contadores del mes aparte de live_state (la forma que lee React no cambia); max_uses = de por vida, max_executions_per_month = del mes. Decisión: la spec firmada v1 NO lleva monthly_budget (D-17); se aplica donde está declarado (seed, línea estricta). Las aprobaciones humanas de escalaciones consumen sin re-chequear (autorizan lo que el mandato no cubría). 6 mutaciones detectadas, incluida quitar el lock |
| 2026-11-16 | 5.3 Capa LLM honesta | `b03efe5` | 925 / 240 | P-15: core/llm.py, cliente único (Responses API, Structured Outputs, timeout y reintentos por entorno, fail-closed, sin claves ni cuerpos de error en logs). Modelo VERIFICADO hoy en la doc oficial: gpt-6-luna (default, OPENAI_MODEL). Hallazgo: el default anterior de la búsqueda, "gpt-5.6", no es un ID válido (la búsqueda real habría fallado siempre); gpt-4o/4o-mini/4.1-mini deprecados. Migrados firewall, juez, búsqueda y el auditor legado; fuera el parseo manual de .env. Firewall: corre en TODA compra aprobable (antes solo con palabras en español), ESCALATE escala en ambas líneas, fallo/veredicto desconocido → ESCALATE; heurística bilingüe con límites de palabra, sin el "10/20 = cargo", y resumen con lo realmente detectado. Juez sin substrings ("vale" ≠ "Valencia"). Identidad del comercio por dominio de la URL (no el nombre que afirma el LLM): el agente presenta el comercio del dominio; /verify rechaza un comercio que no coincide con la fuente. docs/design/responsible-ai.md: qué decide el LLM y qué el código. 11 mutaciones detectadas. Navegador: flujo completo y demo de 5 actos OK (el acto 4 ahora explica la trampa real) |
| 2026-11-16 | Cierre de la Fase 5 | `a518832` (merge `0f85984`) | 925 / 240 | docs/pr/fase-5.md; PR #3 → main con CI replicado en limpio (Python 3.13 + npm ci) |
| 2026-11-16 | Complemento P-15: presupuesto por request | `4e053bd` | 928 / 240 | Hallazgo propio al cerrar la Fase 5: el 5.3 aplicó timeout, reintentos y fail-closed, pero no el "presupuesto por request" de P-15. Ahora cada request lleva max_output_tokens (LLM_MAX_OUTPUT_TOKENS, default 2000) y una respuesta incompleta se descarta (fail-closed). .env.example documenta OPENAI_API_KEY, OPENAI_MODEL, LLM_* y la cuota del agente (no lo hacía), y deja de citar /adversarial/run (retirado en el 3.5). 2 mutaciones detectadas. El tope GLOBAL diario de P-16 sigue diferido al 9.1, documentado en core/quotas.py |
| 2026-11-16 | 6.1 Mapeo y diseño de persistencia | `7db1331` | 928 / 240 | Solo lectura. docs/design/persistence.md: inventario de 11 almacenes a persistir, 4 efímeros (P-10, con enganche a Redis) y 5 de legado que se retiran en el 7.2 sin migrarse; esquema (SQLAlchemy 2 Core + Alembic, UNIQUE de pubkey y PK de nonces en la base, triggers append-only, cabeza del ledger), repositorios con la firma pública actual y orden de migración con riesgo. Hallazgos: H1 replay de un intento capturado tras 24 h o tras un reinicio (el intento no lleva fecha firmada): alto, se resuelve en el 6.3; H2 doble decisión humana sin atomicidad; H3 /mandates/{id}/reset borra contadores firmados con solo una sesión y sin evento en el ledger: decisión P-17 para René, no bloquea; H4 truncar el final del ledger no se detecta; H5 docstring obsoleto. Decisiones de diseño: la cadena rota impide arrancar (no hay modo solo lectura); /audit/reset sale en el 6.3; la cuota del agente se persiste (control de costo, P-16) |
| 2026-11-16 | 6.2 Repositorios y migraciones | (este commit) | 952 / 240 | SQLAlchemy 2.1.6 Core + Alembic 1.20.1 (2.1.7/2.1.8 tenían menos de dos semanas). core/db.py: DATABASE_URL obligatoria fuera de dev (la API no arranca sin ella), var/agentbuyer.db en dev (en .gitignore), pragmas foreign_keys/WAL/busy_timeout, write_tx = BEGIN IMMEDIATE en lugar de los locks; la app migra al arrancar. Migración 0001 escrita a mano: owner_keys (UNIQUE global de pubkey, CHECK de alg, dueño normalizado y largo), mandates (CHECK de status y contadores), mandate_signers (FK a la llave; human exige key_id), mandate_periods (una fila por mes), mandate_creation_nonces (la PK es el anti-replay). core/mandate_store.py y core/owner_keys.py conservan su API pública; la expiración se deriva al leer; el seed no se re-crea al reiniciar. Tests: base propia por test (copia de una plantilla migrada); 70 accesos a los diccionarios pasan a la API pública o a UPDATE reales que simulan manipulación de la base (tests/storage.py); 1 test cambia de contrato (borrar del registro una llave que firmó ya es imposible por FK, y se prueba eso; la rama del key_id desconocido se prueba sobre la función). Los tests de concurrencia ahora exigen que CADA intento simultáneo reciba respuesta (sin eso, quitar BEGIN IMMEDIATE sobrevivía: SQLite impedía el gasto doble, pero fallando la transacción). 12 mutaciones detectadas. Venv limpio 3.13: pip check OK, 952 verdes. Navegador con reinicio real del backend: la misma llave figura registrada, se firma sin re-registrar, el mandato anterior conserva uses_count 1 y vuelve a comprar (2); flujo completo y demo de 5 actos OK |
