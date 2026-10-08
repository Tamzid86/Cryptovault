from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c77454cd508a'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('audit_log',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('sequence', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('actor_id', sa.UUID(), nullable=True),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('target_type', sa.String(length=64), nullable=False),
    sa.Column('target_id', sa.String(length=64), nullable=False),
    sa.Column('ip_address', sa.String(length=45), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default='now()', nullable=False),
    sa.Column('prev_hash', sa.String(length=64), nullable=False),
    sa.Column('entry_hash', sa.String(length=64), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('entry_hash'),
    sa.UniqueConstraint('sequence')
    )
    op.create_table('users',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('public_key', sa.LargeBinary(), nullable=False),
    sa.Column('encrypted_private_key', sa.LargeBinary(), nullable=False),
    sa.Column('private_key_kdf_salt', sa.LargeBinary(), nullable=False),
    sa.Column('private_key_nonce', sa.LargeBinary(), nullable=False),
    sa.Column('totp_secret_encrypted', sa.LargeBinary(), nullable=True),
    sa.Column('totp_enabled', sa.Boolean(), nullable=False),
    sa.Column('failed_login_attempts', sa.Integer(), nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default='now()', nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_table('files',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('owner_id', sa.UUID(), nullable=False),
    sa.Column('encrypted_filename', sa.LargeBinary(), nullable=False),
    sa.Column('filename_nonce', sa.LargeBinary(), nullable=False),
    sa.Column('size_bytes', sa.Integer(), nullable=False),
    sa.Column('chunk_size', sa.Integer(), nullable=False),
    sa.Column('num_chunks', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default='now()', nullable=False),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_files_owner_id'), 'files', ['owner_id'], unique=False)
    op.create_table('login_events',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('ip_address', sa.String(length=45), nullable=False),
    sa.Column('user_agent', sa.String(length=512), nullable=False),
    sa.Column('device_fingerprint', sa.String(length=128), nullable=False),
    sa.Column('success', sa.Boolean(), nullable=False),
    sa.Column('is_new_device', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default='now()', nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_login_events_user_id'), 'login_events', ['user_id'], unique=False)
    op.create_table('webauthn_credentials',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('credential_id', sa.LargeBinary(), nullable=False),
    sa.Column('public_key', sa.LargeBinary(), nullable=False),
    sa.Column('sign_count', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default='now()', nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('credential_id')
    )
    op.create_index(op.f('ix_webauthn_credentials_user_id'), 'webauthn_credentials', ['user_id'], unique=False)
    op.create_table('file_chunks',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('file_id', sa.UUID(), nullable=False),
    sa.Column('chunk_index', sa.Integer(), nullable=False),
    sa.Column('nonce', sa.LargeBinary(), nullable=False),
    sa.Column('storage_path', sa.String(length=512), nullable=False),
    sa.Column('size_bytes', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['file_id'], ['files.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_file_chunks_file_id'), 'file_chunks', ['file_id'], unique=False)
    op.create_table('file_key_shares',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('file_id', sa.UUID(), nullable=False),
    sa.Column('recipient_id', sa.UUID(), nullable=False),
    sa.Column('granted_by_id', sa.UUID(), nullable=False),
    sa.Column('ephemeral_public_key', sa.LargeBinary(), nullable=False),
    sa.Column('wrapped_key', sa.LargeBinary(), nullable=False),
    sa.Column('wrap_nonce', sa.LargeBinary(), nullable=False),
    sa.Column('permission', sa.Enum('OWNER', 'READ', name='permission'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default='now()', nullable=False),
    sa.ForeignKeyConstraint(['file_id'], ['files.id'], ),
    sa.ForeignKeyConstraint(['granted_by_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['recipient_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_file_key_shares_file_id'), 'file_key_shares', ['file_id'], unique=False)
    op.create_index(op.f('ix_file_key_shares_recipient_id'), 'file_key_shares', ['recipient_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_file_key_shares_recipient_id'), table_name='file_key_shares')
    op.drop_index(op.f('ix_file_key_shares_file_id'), table_name='file_key_shares')
    op.drop_table('file_key_shares')
    op.drop_index(op.f('ix_file_chunks_file_id'), table_name='file_chunks')
    op.drop_table('file_chunks')
    op.drop_index(op.f('ix_webauthn_credentials_user_id'), table_name='webauthn_credentials')
    op.drop_table('webauthn_credentials')
    op.drop_index(op.f('ix_login_events_user_id'), table_name='login_events')
    op.drop_table('login_events')
    op.drop_index(op.f('ix_files_owner_id'), table_name='files')
    op.drop_table('files')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    op.drop_table('audit_log')
