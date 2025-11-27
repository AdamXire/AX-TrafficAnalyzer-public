"""add_plugin_data_table

Revision ID: a1ba4f36fca0
Revises: b9e4c5d1f762
Create Date: 2025-11-26 02:13:15.815768

Phase 6 prerequisite: Plugin data storage table for plugin persistence.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1ba4f36fca0'
down_revision = 'b9e4c5d1f762'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create plugin_data table for plugin persistence."""
    op.create_table(
        'plugin_data',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('plugin_name', sa.String(), nullable=False),
        sa.Column('session_id', sa.String(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('data', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.session_id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_plugin_data_plugin_name', 'plugin_data', ['plugin_name'])
    op.create_index('idx_plugin_data_session_id', 'plugin_data', ['session_id'])
    op.create_index('idx_plugin_data_timestamp', 'plugin_data', ['timestamp'])


def downgrade() -> None:
    """Drop plugin_data table."""
    op.drop_index('idx_plugin_data_timestamp', 'plugin_data')
    op.drop_index('idx_plugin_data_session_id', 'plugin_data')
    op.drop_index('idx_plugin_data_plugin_name', 'plugin_data')
    op.drop_table('plugin_data')

