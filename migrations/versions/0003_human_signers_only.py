"""Solo el titular firma mandatos (7.2, P-11): fuera el sello de sistema del seed.

Revision ID: 0003_human_signers_only
Revises: 0002_ledger_and_runtime_state
Create Date: 2026-11-16

- mandate_signers: kind = 'human' y key_id obligatorio, en la base.
- Datos previos: una base de desarrollo puede tener el mandato semilla sellado por el
  servidor (kind = 'system_seal'). Ese sello ya no es una firma válida: el mandato se
  marca REVOCADO (no se borra: su historia sigue en el ledger) y se quita su firmante.
  Dejarlo "activo" sin poder comprar sería mostrar un estado falso.
- downgrade restaura las restricciones anteriores, pero no los firmantes quitados.
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "0003_human_signers_only"
down_revision = "0002_ledger_and_runtime_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    legacy = list(bind.execute(sa.text("SELECT mandate_id FROM mandate_signers WHERE kind <> 'human'")).scalars())
    if legacy:
        now = datetime.now(timezone.utc).isoformat()
        for mandate_id in legacy:
            bind.execute(
                sa.text("UPDATE mandates SET status = 'revoked', revoked_at = COALESCE(revoked_at, :now) "
                        "WHERE mandate_id = :mandate_id"),
                {"now": now, "mandate_id": mandate_id},
            )
        bind.execute(sa.text("DELETE FROM mandate_signers WHERE kind <> 'human'"))

    with op.batch_alter_table("mandate_signers", recreate="always") as batch:
        batch.drop_constraint("ck_mandate_signers_kind", type_="check")
        batch.drop_constraint("ck_mandate_signers_human_has_key", type_="check")
        batch.alter_column("key_id", existing_type=sa.Text, nullable=False)
        batch.create_check_constraint("ck_mandate_signers_kind", "kind = 'human'")


def downgrade() -> None:
    with op.batch_alter_table("mandate_signers", recreate="always") as batch:
        batch.drop_constraint("ck_mandate_signers_kind", type_="check")
        batch.alter_column("key_id", existing_type=sa.Text, nullable=True)
        batch.create_check_constraint("ck_mandate_signers_kind", "kind IN ('human', 'system_seal')")
        batch.create_check_constraint("ck_mandate_signers_human_has_key", "kind <> 'human' OR key_id IS NOT NULL")
