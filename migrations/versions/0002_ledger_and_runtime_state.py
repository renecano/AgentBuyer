"""Ledger con cadena hash, cabeza, nonces de intento, decisiones humanas, disputas y
cuota del agente (6.3). Diseño: docs/design/persistence.md §3-§6.

Revision ID: 0002_ledger_and_runtime_state
Revises: 0001_mandates_and_keys
Create Date: 2026-11-16

Append-only EN LA BASE (no solo en el código), con triggers:
- audit_ledger no admite UPDATE ni DELETE.
- Un INSERT solo entra si extiende la cabeza: idx = cabeza + 1 y prev_hash = hash de
  la cabeza. Después del INSERT, la propia base avanza la cabeza (trigger AFTER).
- ledger_head solo avanza de a uno y no se borra. Así truncar el final del ledger
  (H4) deja una cabeza que no coincide con la última fila, y el arranque lo detecta.
Límite honesto: quien tenga escritura sobre el archivo puede borrar los triggers y
reescribir todo; eso lo cubre el modelo de amenazas (12.1), no la base.
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_ledger_and_runtime_state"
down_revision = "0001_mandates_and_keys"
branch_labels = None
depends_on = None

GENESIS_HASH = "0" * 64


def upgrade() -> None:
    op.create_table(
        "audit_ledger",
        sa.Column("idx", sa.Integer, primary_key=True, autoincrement=False),
        sa.Column("entry_id", sa.Text, nullable=False, unique=True),
        sa.Column("prev_hash", sa.Text, nullable=False),
        sa.Column("hash", sa.Text, nullable=False, unique=True),
        sa.Column("timestamp", sa.Text, nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("actor_type", sa.Text, nullable=False),
        sa.Column("actor_id", sa.Text, nullable=False),
        sa.Column("mandate_id", sa.Text, nullable=True),
        sa.Column("attempt_id", sa.Text, nullable=True),
        sa.Column("details", sa.Text, nullable=False),
        sa.Column("signature", sa.Text, nullable=True),
        sa.CheckConstraint("idx >= 0", name="ck_audit_ledger_idx"),
        sa.CheckConstraint("length(hash) = 64 AND length(prev_hash) = 64", name="ck_audit_ledger_hash_length"),
    )
    op.create_index("ix_audit_ledger_mandate_id", "audit_ledger", ["mandate_id"])
    op.create_index("ix_audit_ledger_attempt_id", "audit_ledger", ["attempt_id"])

    op.create_table(
        "ledger_head",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=False),
        sa.Column("last_idx", sa.Integer, nullable=False),
        sa.Column("last_hash", sa.Text, nullable=False),
        sa.CheckConstraint("id = 1", name="ck_ledger_head_single_row"),
    )
    op.execute(f"INSERT INTO ledger_head (id, last_idx, last_hash) VALUES (1, -1, '{GENESIS_HASH}')")

    op.execute("""
        CREATE TRIGGER audit_ledger_no_update BEFORE UPDATE ON audit_ledger
        BEGIN SELECT RAISE(ABORT, 'audit_ledger is append-only'); END
    """)
    op.execute("""
        CREATE TRIGGER audit_ledger_no_delete BEFORE DELETE ON audit_ledger
        BEGIN SELECT RAISE(ABORT, 'audit_ledger is append-only'); END
    """)
    op.execute("""
        CREATE TRIGGER audit_ledger_extends_head BEFORE INSERT ON audit_ledger
        WHEN NEW.idx <> (SELECT last_idx + 1 FROM ledger_head WHERE id = 1)
          OR NEW.prev_hash <> (SELECT last_hash FROM ledger_head WHERE id = 1)
        BEGIN SELECT RAISE(ABORT, 'audit_ledger append must extend the head'); END
    """)
    op.execute("""
        CREATE TRIGGER audit_ledger_advance_head AFTER INSERT ON audit_ledger
        BEGIN UPDATE ledger_head SET last_idx = NEW.idx, last_hash = NEW.hash WHERE id = 1; END
    """)
    op.execute("""
        CREATE TRIGGER ledger_head_only_advances BEFORE UPDATE ON ledger_head
        WHEN NEW.last_idx <> OLD.last_idx + 1 OR NEW.id <> OLD.id
        BEGIN SELECT RAISE(ABORT, 'ledger_head only advances one entry at a time'); END
    """)
    op.execute("""
        CREATE TRIGGER ledger_head_no_delete BEFORE DELETE ON ledger_head
        BEGIN SELECT RAISE(ABORT, 'ledger_head cannot be deleted'); END
    """)

    op.create_table(
        "attempt_nonces",
        sa.Column("nonce", sa.Text, primary_key=True),
        sa.Column("mandate_id", sa.Text, nullable=True),
        sa.Column("seen_at", sa.Text, nullable=False),
        sa.Column("expires_at", sa.Text, nullable=False),
    )
    op.create_index("ix_attempt_nonces_expires_at", "attempt_nonces", ["expires_at"])

    op.create_table(
        "escalation_decisions",
        sa.Column("attempt_id", sa.Text, primary_key=True),
        sa.Column("mandate_id", sa.Text, sa.ForeignKey("mandates.mandate_id"), nullable=False),
        sa.Column("decision", sa.Text, nullable=False),
        sa.Column("decided_by", sa.Text, nullable=False),
        sa.Column("decided_at", sa.Text, nullable=False),
        sa.CheckConstraint("decision IN ('approve', 'decline')", name="ck_escalation_decisions_decision"),
    )

    op.create_table(
        "disputes",
        sa.Column("dispute_id", sa.Text, primary_key=True),
        sa.Column("mandate_id", sa.Text, nullable=False),
        sa.Column("attempt_id", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("claim", sa.Text, nullable=False),
    )
    op.create_index("ix_disputes_mandate_id", "disputes", ["mandate_id"])

    op.create_table(
        "quota_usage",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("bucket", sa.Text, nullable=False),
        sa.Column("subject", sa.Text, nullable=False),
        sa.Column("used_at", sa.Float, nullable=False),
    )
    op.create_index("ix_quota_usage_bucket_subject_used_at", "quota_usage", ["bucket", "subject", "used_at"])


def downgrade() -> None:
    op.drop_table("quota_usage")
    op.drop_table("disputes")
    op.drop_table("escalation_decisions")
    op.drop_table("attempt_nonces")
    for trigger in ("ledger_head_no_delete", "ledger_head_only_advances", "audit_ledger_advance_head",
                    "audit_ledger_extends_head", "audit_ledger_no_delete", "audit_ledger_no_update"):
        op.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    op.drop_table("ledger_head")
    op.drop_table("audit_ledger")
