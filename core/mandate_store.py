"""Almacén autoritativo de mandatos (persistente desde el 6.2; diseño en
docs/design/persistence.md).

Cada registro que devuelve este módulo tiene la forma de siempre:
    {"mandate": {...documento...},
     "live_state": {"status", "uses_count", "amount_spent_cents", "revoked_at"}}
live_state es la ÚNICA fuente de verdad del estado vivo (status y contadores) para
ambas líneas de verificación y para lo que expone GET /mandates/{id}.

Tablas (core/db_schema.py):
- mandates: documento (JSON exacto de lo guardado: lo firmado se vuelve a verificar
  sobre esos mismos bytes), dueño, estado y contadores de por vida.
- mandate_signers: quién firmó (kind human | system_seal). Dato INTERNO de
  verificación: no sale en ninguna respuesta, igual que el dueño.
- mandate_periods: uso por mes calendario UTC (5.2). Una fila por mes: queda historial.
- mandate_creation_nonces: anti-replay de la creación de mandatos firmados.

Atomicidad: lo que antes hacía `with mandate_store._lock:` ahora es una transacción
BEGIN IMMEDIATE (core/db.write_tx), que toma el lock de escritura de la base al
empezar. Funciona igual entre hilos y entre procesos.

Expiración: se DERIVA al leer (un mandato activo cuyo expires_at pasó se ve
"expired") y no se escribe. Así restaurar un backup no "des-expira" nada y el
resultado es el mismo que cuando se guardaba en memoria.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Union

from sqlalchemy import and_, delete, func, insert, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from core.db import read_tx, write_tx, write_tx_or
from core.db_schema import mandate_creation_nonces as NONCES
from core.db_schema import mandate_periods as PERIODS
from core.db_schema import mandate_signers as SIGNERS
from core.db_schema import mandates as MANDATES_TABLE
from shared.schemas import Mandate, MandateStatus

# Por qué UTC en los periodos: un mandato firmado no declara zona horaria y el servidor
# no debe adivinarla; el corte es el mismo para todos y es verificable.


def _utcnow() -> datetime:
    """Reloj del almacén (expiración, periodos). Los tests lo sustituyen: sin esperas reales."""
    return datetime.now(timezone.utc)


def _stamp(moment: datetime) -> str:
    """Instante para columnas que se COMPARAN como texto: siempre UTC y con
    microsegundos, para que el orden lexicográfico sea el cronológico."""
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _normalize_owner(owner_email: Optional[str]) -> Optional[str]:
    if owner_email is None:
        return None
    normalized = owner_email.strip().lower()
    return normalized or None


def _dump(document: dict) -> str:
    return json.dumps(document, ensure_ascii=False)


def _new_live_state() -> dict:
    return {"status": "active", "uses_count": 0, "amount_spent_cents": 0, "revoked_at": None}


def _record(row) -> dict:
    record = {
        "mandate": json.loads(row.document),
        "live_state": {
            "status": row.status,
            "uses_count": row.uses_count,
            "amount_spent_cents": row.amount_spent_cents,
            "revoked_at": row.revoked_at,
        },
    }
    _apply_live_expiry(record)
    return record


def _apply_live_expiry(record: dict) -> None:
    """Regla de expiración única para todos los lectores: un mandato activo cuyo
    expires_at ya pasó se ve "expired" en live_state (y en el status del documento,
    si lo tiene). Se aplica a la copia que se devuelve; no se escribe.

    Una fecha ilegible se ignora aquí; core/verify la rechaza por su cuenta (fail-closed).
    """
    live_state = record["live_state"]
    expires_at = record["mandate"].get("expires_at")
    if live_state["status"] != "active" or not isinstance(expires_at, str) or not expires_at:
        return
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if _utcnow() > expiry:
        live_state["status"] = "expired"
        if "status" in record["mandate"]:
            record["mandate"]["status"] = "EXPIRED"


def _load(connection, mandate_id: str) -> Optional[dict]:
    row = connection.execute(select(MANDATES_TABLE).where(MANDATES_TABLE.c.mandate_id == mandate_id)).first()
    return _record(row) if row is not None else None


def _insert_mandate(connection, mandate_id: str, document: dict, owner: Optional[str], signer: dict) -> None:
    live_state = _new_live_state()
    connection.execute(insert(MANDATES_TABLE).values(
        mandate_id=mandate_id, owner_email=owner, document=_dump(document), status=live_state["status"],
        uses_count=0, amount_spent_cents=0, revoked_at=None, created_at=_stamp(_utcnow()),
    ))
    connection.execute(insert(SIGNERS).values(mandate_id=mandate_id, **_signer_columns(signer)))


def _signer_columns(signer: dict) -> dict:
    return {key: signer.get(key) for key in ("kind", "key_id", "public_key", "message_hash", "signed_at")}


def mandate_exists(mandate_id: str) -> bool:
    """¿Existe el mandato? Sin cargarlo: para decidir 404 antes de evaluar propiedad."""
    with read_tx() as connection:
        return connection.execute(
            select(MANDATES_TABLE.c.mandate_id).where(MANDATES_TABLE.c.mandate_id == mandate_id)
        ).first() is not None


def get_mandate_signer(mandate_id: str) -> Optional[dict]:
    """Registro del firmante del mandato, o None si no hay."""
    with read_tx() as connection:
        row = connection.execute(select(SIGNERS).where(SIGNERS.c.mandate_id == mandate_id)).first()
    if row is None:
        return None
    return {"kind": row.kind, "key_id": row.key_id, "public_key": row.public_key,
            "message_hash": row.message_hash, "signed_at": row.signed_at}


def _sealed_signer(public_key: Optional[str], sealed_bytes: Optional[bytes], kind: str) -> dict:
    return {
        "kind": kind,
        "key_id": None,
        "public_key": public_key,
        "message_hash": hashlib.sha256(sealed_bytes).hexdigest() if sealed_bytes is not None else None,
        "signed_at": _utcnow().isoformat(),
    }


def mandate_ids_owned_by(owner_email: Optional[str]) -> set:
    """Ids de los mandatos cuyo dueño es `owner_email` (vacío si no hay dueño)."""
    owner = _normalize_owner(owner_email)
    if owner is None:
        return set()
    with read_tx() as connection:
        return set(connection.execute(
            select(MANDATES_TABLE.c.mandate_id).where(MANDATES_TABLE.c.owner_email == owner)
        ).scalars())


def get_mandate_owner(mandate_id: str) -> Optional[str]:
    """Email del dueño del mandato, o None si no tiene dueño registrado (o no existe)."""
    with read_tx() as connection:
        return connection.execute(
            select(MANDATES_TABLE.c.owner_email).where(MANDATES_TABLE.c.mandate_id == mandate_id)
        ).scalar_one_or_none()


class MandateStore:
    """Fachada de la línea estricta (modelo Mandate) y de pausar/reanudar.
    CRITICAL RULE: NO CACHING. Cada consulta lee el estado vivo de la base."""

    def save_mandate(self, mandate: Union[Mandate, dict], owner_email: Optional[str] = None) -> Mandate:
        m_obj = Mandate(**mandate) if isinstance(mandate, dict) else mandate.model_copy(deep=True)
        mandate_id = m_obj.mandate_id
        document = m_obj.model_dump(mode="json")
        # mandate/issue.py firma con llaves que guarda el SERVIDOR (_key_registry):
        # es un sello de sistema, no una firma del titular.
        signer = _sealed_signer(m_obj.human_pubkey or None, None, "system_seal")
        values = {
            "owner_email": _normalize_owner(owner_email), "document": _dump(document),
            "status": m_obj.status.value.lower(), "uses_count": 0, "amount_spent_cents": 0,
            "revoked_at": m_obj.revoked_at, "created_at": _stamp(_utcnow()),
        }
        with write_tx() as connection:
            # Guardar de nuevo el mismo id lo reemplaza (comportamiento histórico de la
            # línea estricta); el uso mensual se conserva, como antes.
            statement = sqlite_insert(MANDATES_TABLE).values(mandate_id=mandate_id, **values)
            connection.execute(statement.on_conflict_do_update(index_elements=["mandate_id"], set_=values))
            signer_values = _signer_columns(signer)
            statement = sqlite_insert(SIGNERS).values(mandate_id=mandate_id, **signer_values)
            connection.execute(statement.on_conflict_do_update(index_elements=["mandate_id"], set_=signer_values))
        try:
            from audit.log import audit_ledger
            audit_ledger.append_entry(
                event_type="MANDATE_CREATED",
                actor_type="HUMAN",
                actor_id=m_obj.human_id,
                mandate_id=mandate_id,
                details={"scope": m_obj.scope.model_dump() if m_obj.scope else {}},
            )
        except Exception:
            pass
        return m_obj

    def get_mandate(self, mandate_id: str) -> Optional[Mandate]:
        record = get_mandate(mandate_id)
        if record is None:
            return None
        live_state = record["live_state"]
        # status y revoked_at salen de live_state (única fuente de verdad), no del
        # documento, que puede quedar desactualizado.
        return Mandate(**{**record["mandate"], "status": live_state["status"].upper(),
                          "revoked_at": live_state.get("revoked_at")})

    def list_mandates(self, human_id: Optional[str] = None) -> List[Mandate]:
        with read_tx() as connection:
            ids = list(connection.execute(select(MANDATES_TABLE.c.mandate_id).order_by(MANDATES_TABLE.c.created_at)).scalars())
        mandates = []
        for mandate_id in ids:
            m = self.get_mandate(mandate_id)
            if m and (human_id is None or m.human_id == human_id):
                mandates.append(m)
        return mandates

    def _update_document_and_status(self, mandate_id: str, status: str, document_changes) -> bool:
        with write_tx() as connection:
            row = connection.execute(select(MANDATES_TABLE).where(MANDATES_TABLE.c.mandate_id == mandate_id)).first()
            if row is None:
                return False
            document = json.loads(row.document)
            extra = document_changes(document) or {}
            connection.execute(update(MANDATES_TABLE).where(MANDATES_TABLE.c.mandate_id == mandate_id)
                               .values(status=status, document=_dump(document), **extra))
            return True

    def revoke_mandate(self, mandate_id: str, reason: str = "Revoked by cardholder") -> bool:
        """Live Revocation Kill Switch."""
        now_iso = datetime.now(timezone.utc).isoformat()

        def changes(document: dict) -> dict:
            if "status" in document:
                document["status"] = "REVOKED"
            if "revoked_at" in document:
                document["revoked_at"] = now_iso
            if "revocation_reason" in document:
                document["revocation_reason"] = reason
            return {"revoked_at": now_iso}
        return self._update_document_and_status(mandate_id, "revoked", changes)

    def pause_mandate(self, mandate_id: str) -> bool:
        return self._update_document_and_status(mandate_id, "paused", lambda document: document.__setitem__("status", "PAUSED"))

    def resume_mandate(self, mandate_id: str) -> bool:
        return self._update_document_and_status(mandate_id, "active", lambda document: document.__setitem__("status", "ACTIVE"))

    def get_live_status(self, mandate_id: str) -> Tuple[Optional[MandateStatus], Optional[str]]:
        m = self.get_mandate(mandate_id)
        if not m:
            return None, "Mandate not found"
        return m.status, m.revocation_reason

    def clear(self) -> None:
        """Borra todos los mandatos (y, en cascada, firmantes y periodos), sus decisiones
        humanas y los nonces de creación. SOLO tests: la app no borra mandatos."""
        from core.db_schema import escalation_decisions

        with write_tx() as connection:
            connection.execute(delete(escalation_decisions))  # referencian al mandato (FK)
            connection.execute(delete(MANDATES_TABLE))
            connection.execute(delete(NONCES))


# Global singleton instance
mandate_store = MandateStore()


# Funciones funcionales para frontend y routers
def seal_seed_mandate(mandate: dict, owner_email: Optional[str] = None) -> dict:
    """Sella el mandato SEMILLA al arrancar (api/main.load_seed_mandates): el único
    mandato que el servidor firma con una llave suya (kind=system_seal, D-12). No lo
    llama ningún endpoint: los usuarios crean mandatos firmados por ellos (3.5).

    El payment_token lo emite el servidor atado a los bytes sellados (también aquí):
    uno que venga en el seed se descarta. Una firma que venga en el seed es un error,
    no un "sello del cliente": ese camino legado ya no existe.

    Con persistencia (6.2) el seed sobrevive al reinicio: volver a cargarlo levanta
    ValueError ("ya existe"), que load_seed_mandates ignora. No se duplica ni se resetea."""
    from core.signed_mandates import issue_payment_token
    from mandate.sign import canonical_json, generate_keypair, sign_payload

    mandate_id = mandate.get("mandate_id")
    if not mandate_id:
        raise ValueError("El mandate_id es obligatorio")
    if "signature" in mandate or "human_signature" in mandate:
        raise ValueError("El seed no puede traer firma: el servidor lo sella al cargarlo.")

    m_copy = json.loads(json.dumps(mandate))
    if isinstance(m_copy.get("constraints"), dict):
        # El seed es un archivo de config en UNIDADES: su borde a centavos es aquí (5.1).
        m_copy["constraints"] = _seed_constraints_to_cents(m_copy["constraints"])
    sealed = m_copy.get("constraints", m_copy.get("scope", {}))
    sealed_bytes = canonical_json(sealed)
    h_priv, h_pub = generate_keypair()
    m_copy["human_pubkey"] = h_pub
    m_copy["signature"] = sign_payload(h_priv, sealed)
    signer = _sealed_signer(h_pub, sealed_bytes, "system_seal")
    m_copy["payment_token"] = issue_payment_token(mandate_id, signer["message_hash"])

    with write_tx() as connection:
        if _load(connection, mandate_id) is not None:
            raise ValueError("El mandate_id ya existe")
        _insert_mandate(connection, mandate_id, m_copy, _normalize_owner(owner_email), signer)
        return _load(connection, mandate_id)


def _seed_constraints_to_cents(constraints: dict) -> dict:
    """Constraints del seed (unidades) → la forma del engine (centavos enteros).
    max_amount_per_tx era un duplicado de max_amount_per_purchase: se descarta."""
    from core.money import to_cents

    converted = {key: value for key, value in constraints.items()
                 if key not in ("max_amount_per_purchase", "max_amount_per_tx", "monthly_budget", "conditions")}
    cap = constraints.get("max_amount_per_purchase", constraints.get("max_amount_per_tx"))
    if cap is not None:
        converted["max_amount_per_purchase_cents"] = to_cents(cap, "max_amount_per_purchase")
    if constraints.get("monthly_budget") is not None:
        converted["monthly_budget_cents"] = to_cents(constraints["monthly_budget"], "monthly_budget")
    converted["conditions"] = [
        {"type": condition["type"], "value_cents": to_cents(condition["value"], f"conditions.{condition['type']}")}
        if isinstance(condition, dict) and "value" in condition else condition
        for condition in constraints.get("conditions", [])
    ]
    return converted


def count_mandates_signed_with(owner_email: str, key_id: str) -> int:
    """Mandatos del dueño firmados con `key_id` que todavía podrían autorizar compras
    (activos o pausados): los que quedan sin efecto si esa llave se revoca (P-01 a)."""
    owner = _normalize_owner(owner_email)
    with read_tx() as connection:
        return connection.execute(
            select(func.count()).select_from(SIGNERS.join(MANDATES_TABLE, SIGNERS.c.mandate_id == MANDATES_TABLE.c.mandate_id))
            .where(and_(SIGNERS.c.kind == "human", SIGNERS.c.key_id == key_id, MANDATES_TABLE.c.owner_email == owner,
                        MANDATES_TABLE.c.status.in_(("active", "paused"))))
        ).scalar_one()


def create_human_signed_mandate(mandate: dict, signer: dict, owner_email: str, nonce: str, created_at: datetime) -> dict:
    """Guarda un mandato YA verificado por core/signed_mandates (kind=human).

    Atómico en UNA transacción: el anti-replay del nonce y la unicidad del mandate_id
    se deciden juntos, sin ventana entre comprobar y guardar.
    Lanza ValueError (→ 409) si el mandate_id existe o el nonce ya se usó.

    El nonce se puede olvidar cuando su created_at firmado sale de la ventana
    (MAX_AGE + MAX_CLOCK_SKEW): desde ese momento la firma ya se rechaza por vieja."""
    from core.signed_mandates import MAX_AGE, MAX_CLOCK_SKEW, _utcnow as signed_clock

    mandate_id = mandate["mandate_id"]
    owner = _normalize_owner(owner_email)
    now = signed_clock()
    with write_tx() as connection:
        if _load(connection, mandate_id) is not None:
            raise ValueError("El mandate_id ya existe")
        connection.execute(delete(NONCES).where(NONCES.c.expires_at < _stamp(now)))
        used = connection.execute(
            select(NONCES.c.nonce).where(and_(NONCES.c.owner_email == owner, NONCES.c.nonce == nonce))
        ).first()
        if used is not None:
            raise ValueError("Este nonce ya se usó para crear otro mandato (replay).")
        connection.execute(insert(NONCES).values(
            owner_email=owner, nonce=nonce, created_at=_stamp(created_at),
            expires_at=_stamp(created_at + MAX_AGE + MAX_CLOCK_SKEW),
        ))
        _insert_mandate(connection, mandate_id, mandate, owner, signer)
        return _load(connection, mandate_id)


def get_mandate(mandate_id: str) -> dict | None:
    with read_tx() as connection:
        return _load(connection, mandate_id)


def revoke_mandate(mandate_id: str) -> dict | None:
    with write_tx() as connection:
        record = _load(connection, mandate_id)
        if record is None:
            return None
        connection.execute(
            update(MANDATES_TABLE)
            .where(and_(MANDATES_TABLE.c.mandate_id == mandate_id, MANDATES_TABLE.c.status != "revoked"))
            .values(status="revoked", revoked_at=datetime.now(timezone.utc).isoformat())
        )
        return _load(connection, mandate_id)


def reset_mandate(mandate_id: str) -> dict | None:
    """Restaura el estado vivo inicial de un mandato para reiniciar una demo.
    Decisión pendiente P-17 (docs/design/persistence.md, H3): se conserva el
    comportamiento de antes del 6.2, incluido borrar el uso mensual."""
    with write_tx() as connection:
        if _load(connection, mandate_id) is None:
            return None
        live_state = _new_live_state()
        connection.execute(update(MANDATES_TABLE).where(MANDATES_TABLE.c.mandate_id == mandate_id).values(**live_state))
        connection.execute(delete(PERIODS).where(PERIODS.c.mandate_id == mandate_id))
        return _load(connection, mandate_id)


def _current_month() -> str:
    return _utcnow().strftime("%Y-%m")


def _period_of(connection, mandate_id: str) -> dict:
    """Uso del mes en curso (ceros si aún no hay fila para este mes)."""
    month = _current_month()
    row = connection.execute(
        select(PERIODS.c.uses, PERIODS.c.spent_cents).where(and_(PERIODS.c.mandate_id == mandate_id, PERIODS.c.month == month))
    ).first()
    return {"month": month, "uses": row.uses if row else 0, "spent_cents": row.spent_cents if row else 0}


def period_usage(mandate_id: str) -> dict:
    """Uso del mes en curso: {"month", "uses", "spent_cents"}."""
    with read_tx() as connection:
        return _period_of(connection, mandate_id)


def _consume(connection, mandate_id: str, amount_cents: int, period: dict) -> None:
    connection.execute(
        update(MANDATES_TABLE).where(MANDATES_TABLE.c.mandate_id == mandate_id).values(
            uses_count=MANDATES_TABLE.c.uses_count + 1,
            amount_spent_cents=MANDATES_TABLE.c.amount_spent_cents + amount_cents,
        )
    )
    statement = sqlite_insert(PERIODS).values(mandate_id=mandate_id, month=period["month"], uses=1, spent_cents=amount_cents)
    connection.execute(statement.on_conflict_do_update(
        index_elements=["mandate_id", "month"],
        set_={"uses": PERIODS.c.uses + 1, "spent_cents": PERIODS.c.spent_cents + amount_cents},
    ))


def _reservation_pause() -> None:
    """Costura para los tests de concurrencia (5.2): no hace nada. Un test la
    sustituye por una espera para ensanchar la carrera; con la transacción
    BEGIN IMMEDIATE no hay carrera."""


def reserve_purchase(mandate_id: str, amount_cents: int, constraints: dict) -> Optional[str]:
    """VERIFICAR Y CONSUMIR en una sola operación atómica (5.2).

    Dentro de una transacción BEGIN IMMEDIATE vuelve a mirar el estado VIVO (no la
    foto que evaluó el engine): mandato activo, usos de por vida (max_uses), usos del
    mes (max_executions_per_month) y presupuesto del mes (monthly_budget_cents). Si
    todo cabe, consume el uso y el monto y devuelve None; si no, no toca nada y
    devuelve la regla que lo impidió. Así dos compras simultáneas no pueden superar
    max_uses ni el presupuesto: la segunda ve el uso de la primera.

    Se llama al FINAL de la verificación, cuando ya nada puede rechazar la compra,
    así que no hace falta "liberar" una reserva."""
    from core.money import is_cents

    if not is_cents(amount_cents) or amount_cents <= 0:
        raise ValueError(f"reserve_purchase exige centavos enteros > 0 (recibido {amount_cents!r}).")
    with write_tx() as connection:
        record = _load(connection, mandate_id)
        if record is None:
            return "mandate_exists"
        live_state = record["live_state"]
        if live_state["status"] != "active":
            return "status"
        period = _period_of(connection, mandate_id)
        max_uses = constraints.get("max_uses")
        if isinstance(max_uses, int) and live_state["uses_count"] >= max_uses:
            return "uses"
        monthly_uses = constraints.get("max_executions_per_month")
        if isinstance(monthly_uses, int) and period["uses"] >= monthly_uses:
            return "uses"
        budget = constraints.get("monthly_budget_cents")
        if is_cents(budget) and period["spent_cents"] + amount_cents > budget:
            return "monthly_budget"
        _reservation_pause()
        _consume(connection, mandate_id, amount_cents, period)
        return None


def apply_approved_purchase(mandate_id: str, amount_cents: int, *, connection=None) -> dict | None:
    """Consume un uso y suma gasto SIN re-chequear límites: es el efecto de una
    APROBACIÓN HUMANA de una escalación (api/escalations, core/verify.resolve_escalation),
    que autoriza justo lo que el mandato no cubría. Las aprobaciones automáticas usan
    reserve_purchase (5.2), que verifica y consume en la misma operación atómica.

    5.1 (P-09): el gasto es un entero de centavos. Un monto que no lo sea (float,
    negativo, cero, bool) es un error del llamador: se rechaza, no se redondea.

    Con `connection` corre dentro de la transacción del llamador (6.3, H2: la decisión
    humana, la compra y su evento del ledger son una sola operación)."""
    from core.money import is_cents

    if not is_cents(amount_cents) or amount_cents <= 0:
        raise ValueError(f"apply_approved_purchase exige centavos enteros > 0 (recibido {amount_cents!r}).")
    with write_tx_or(connection) as conn:
        if _load(conn, mandate_id) is None:
            return None
        _consume(conn, mandate_id, amount_cents, _period_of(conn, mandate_id))
        return _load(conn, mandate_id)

