from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd5a0d75358ab'
down_revision: Union[str, None] = 'c77454cd508a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('webauthn_challenge', sa.LargeBinary(), nullable=True))
    op.add_column('users', sa.Column('webauthn_challenge_issued_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'webauthn_challenge_issued_at')
    op.drop_column('users', 'webauthn_challenge')
