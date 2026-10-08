from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c3cb826d8beb'
down_revision: Union[str, None] = 'd5a0d75358ab'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLES = ["users", "webauthn_credentials", "login_events", "audit_log", "files", "file_key_shares"]


def upgrade() -> None:
    for table in _TABLES:
        op.alter_column(table, "created_at", server_default=sa.text("now()"))


def downgrade() -> None:
    for table in _TABLES:
        op.alter_column(table, "created_at", server_default="now()")
