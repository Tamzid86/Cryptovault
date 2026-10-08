from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e4b19f2a7c61'
down_revision: Union[str, None] = 'c3cb826d8beb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('totp_last_used_step', sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'totp_last_used_step')
