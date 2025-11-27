"""Add GPS columns to flows and sessions for Phase 7

Revision ID: c9d0e1f23456
Revises: b8c9d0e1f234
Create Date: 2025-11-26

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c9d0e1f23456'
down_revision = 'b8c9d0e1f234'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add GPS columns to flows (nullable for backward compatibility)
    op.add_column('flows', sa.Column('latitude', sa.Float(), nullable=True))
    op.add_column('flows', sa.Column('longitude', sa.Float(), nullable=True))
    
    # Add GPS columns to sessions
    op.add_column('sessions', sa.Column('start_latitude', sa.Float(), nullable=True))
    op.add_column('sessions', sa.Column('start_longitude', sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column('sessions', 'start_longitude')
    op.drop_column('sessions', 'start_latitude')
    op.drop_column('flows', 'longitude')
    op.drop_column('flows', 'latitude')

