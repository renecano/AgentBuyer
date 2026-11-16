"""Mandatos, dueños, firmantes, periodos, nonces de creación y llaves del titular (6.2).

Revision ID: 0001_mandates_and_keys
Revises:
Create Date: 2026-11-16

Escrita a mano (no autogenerada) y congelada: una migración describe la base en ESE
momento, no importa el esquema vivo del código. tests/test_persistence.py comprueba
que, aplicada, coincide con core/db_schema.py.
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_mandates_and_keys"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "owner_keys",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("key_id", sa.Text, nullable=False, unique=True),
        sa.Column("owner_email", sa.Text, nullable=False),
        sa.Column("public_key", sa.Text, nullable=False, unique=True),
        sa.Column("alg", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("revoked_at", sa.Text, nullable=True),
        sa.CheckConstraint("alg = 'ed25519'", name="ck_owner_keys_alg"),
        sa.CheckConstraint("owner_email = lower(trim(owner_email)) AND owner_email <> ''", name="ck_owner_keys_owner_normalized"),
        sa.CheckConstraint("length(public_key) = 64", name="ck_owner_keys_public_key_length"),
    )
    op.create_index("ix_owner_keys_owner_revoked", "owner_keys", ["owner_email", "revoked_at"])

    op.create_table(
        "mandates",
        sa.Column("mandate_id", sa.Text, primary_key=True),
        sa.Column("owner_email", sa.Text, nullable=True),
        sa.Column("document", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("uses_count", sa.Integer, nullable=False),
        sa.Column("amount_spent_cents", sa.Integer, nullable=False),
        sa.Column("revoked_at", sa.Text, nullable=True),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.CheckConstraint("status IN ('active', 'paused', 'revoked', 'expired')", name="ck_mandates_status"),
        sa.CheckConstraint("uses_count >= 0 AND amount_spent_cents >= 0", name="ck_mandates_counters"),
        sa.CheckConstraint("owner_email IS NULL OR owner_email = lower(trim(owner_email))", name="ck_mandates_owner_normalized"),
    )
    op.create_index("ix_mandates_owner_email", "mandates", ["owner_email"])

    op.create_table(
        "mandate_signers",
        sa.Column("mandate_id", sa.Text, sa.ForeignKey("mandates.mandate_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("key_id", sa.Text, sa.ForeignKey("owner_keys.key_id"), nullable=True),
        sa.Column("public_key", sa.Text, nullable=True),
        sa.Column("message_hash", sa.Text, nullable=True),
        sa.Column("signed_at", sa.Text, nullable=False),
        sa.CheckConstraint("kind IN ('human', 'system_seal')", name="ck_mandate_signers_kind"),
        sa.CheckConstraint("kind <> 'human' OR key_id IS NOT NULL", name="ck_mandate_signers_human_has_key"),
    )
    op.create_index("ix_mandate_signers_key_id", "mandate_signers", ["key_id"])

    op.create_table(
        "mandate_periods",
        sa.Column("mandate_id", sa.Text, sa.ForeignKey("mandates.mandate_id", ondelete="CASCADE"), nullable=False),
        sa.Column("month", sa.Text, nullable=False),
        sa.Column("uses", sa.Integer, nullable=False),
        sa.Column("spent_cents", sa.Integer, nullable=False),
        sa.PrimaryKeyConstraint("mandate_id", "month", name="pk_mandate_periods"),
        sa.CheckConstraint("month GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]'", name="ck_mandate_periods_month"),
        sa.CheckConstraint("uses >= 0 AND spent_cents >= 0", name="ck_mandate_periods_counters"),
    )

    op.create_table(
        "mandate_creation_nonces",
        sa.Column("owner_email", sa.Text, nullable=False),
        sa.Column("nonce", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("expires_at", sa.Text, nullable=False),
        sa.PrimaryKeyConstraint("owner_email", "nonce", name="pk_mandate_creation_nonces"),
    )
    op.create_index("ix_mandate_creation_nonces_expires_at", "mandate_creation_nonces", ["expires_at"])


def downgrade() -> None:
    op.drop_table("mandate_creation_nonces")
    op.drop_table("mandate_periods")
    op.drop_table("mandate_signers")
    op.drop_table("mandates")
    op.drop_table("owner_keys")
