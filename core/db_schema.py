"""Esquema que espera el código (SQLAlchemy Core). Las migraciones de Alembic
(migrations/versions) lo construyen; tests/test_persistence.py comprueba que la base
migrada y esta definición coinciden. Diseño: docs/design/persistence.md §4.

Montos en centavos (INTEGER). Fechas: texto ISO 8601 UTC, el mismo formato que se
firma y se encadena (nada se re-serializa distinto). Los documentos firmados se
guardan como el JSON exacto que se verificó.
"""
from sqlalchemy import CheckConstraint, Column, ForeignKey, Index, Integer, MetaData, PrimaryKeyConstraint, Table, Text

metadata = MetaData()

owner_keys = Table(
    "owner_keys",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),  # orden de alta
    Column("key_id", Text, nullable=False, unique=True),
    Column("owner_email", Text, nullable=False),
    # Una pubkey = una persona, GLOBAL: la base lo hace cumplir aunque el código falle.
    Column("public_key", Text, nullable=False, unique=True),
    Column("alg", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("revoked_at", Text, nullable=True),
    CheckConstraint("alg = 'ed25519'", name="ck_owner_keys_alg"),
    CheckConstraint("owner_email = lower(trim(owner_email)) AND owner_email <> ''", name="ck_owner_keys_owner_normalized"),
    CheckConstraint("length(public_key) = 64", name="ck_owner_keys_public_key_length"),
)
Index("ix_owner_keys_owner_revoked", owner_keys.c.owner_email, owner_keys.c.revoked_at)

mandates = Table(
    "mandates",
    metadata,
    Column("mandate_id", Text, primary_key=True),
    Column("owner_email", Text, nullable=True),  # None = sin dueño conocido (legado)
    Column("document", Text, nullable=False),    # JSON exacto de lo guardado/verificado
    Column("status", Text, nullable=False),
    Column("uses_count", Integer, nullable=False),
    Column("amount_spent_cents", Integer, nullable=False),
    Column("revoked_at", Text, nullable=True),
    Column("created_at", Text, nullable=False),
    CheckConstraint("status IN ('active', 'paused', 'revoked', 'expired')", name="ck_mandates_status"),
    CheckConstraint("uses_count >= 0 AND amount_spent_cents >= 0", name="ck_mandates_counters"),
    CheckConstraint("owner_email IS NULL OR owner_email = lower(trim(owner_email))", name="ck_mandates_owner_normalized"),
)
Index("ix_mandates_owner_email", mandates.c.owner_email)

mandate_signers = Table(
    "mandate_signers",
    metadata,
    Column("mandate_id", Text, ForeignKey("mandates.mandate_id", ondelete="CASCADE"), primary_key=True),
    Column("kind", Text, nullable=False),
    Column("key_id", Text, ForeignKey("owner_keys.key_id"), nullable=True),
    Column("public_key", Text, nullable=True),
    Column("message_hash", Text, nullable=True),
    Column("signed_at", Text, nullable=False),
    CheckConstraint("kind IN ('human', 'system_seal')", name="ck_mandate_signers_kind"),
    CheckConstraint("kind <> 'human' OR key_id IS NOT NULL", name="ck_mandate_signers_human_has_key"),
)
Index("ix_mandate_signers_key_id", mandate_signers.c.key_id)

mandate_periods = Table(
    "mandate_periods",
    metadata,
    Column("mandate_id", Text, ForeignKey("mandates.mandate_id", ondelete="CASCADE"), nullable=False),
    Column("month", Text, nullable=False),
    Column("uses", Integer, nullable=False),
    Column("spent_cents", Integer, nullable=False),
    PrimaryKeyConstraint("mandate_id", "month", name="pk_mandate_periods"),
    CheckConstraint("month GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]'", name="ck_mandate_periods_month"),
    CheckConstraint("uses >= 0 AND spent_cents >= 0", name="ck_mandate_periods_counters"),
)

mandate_creation_nonces = Table(
    "mandate_creation_nonces",
    metadata,
    Column("owner_email", Text, nullable=False),
    Column("nonce", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("expires_at", Text, nullable=False),
    # La PK ES el anti-replay de creación: un nonce por dueño sirve una vez.
    PrimaryKeyConstraint("owner_email", "nonce", name="pk_mandate_creation_nonces"),
)
Index("ix_mandate_creation_nonces_expires_at", mandate_creation_nonces.c.expires_at)
