"""Add wifi_frames table for Phase 7 wireless capture

Revision ID: b8c9d0e1f234
Revises: a1ba4f36fca0
Create Date: 2025-11-26

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b8c9d0e1f234'
down_revision = 'a1ba4f36fca0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'wifi_frames',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('session_id', sa.String(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('frame_type', sa.String(), nullable=False),
        sa.Column('source_mac', sa.String(), nullable=False),
        sa.Column('dest_mac', sa.String(), nullable=False),
        sa.Column('bssid', sa.String(), nullable=True),
        sa.Column('ssid', sa.String(), nullable=True),
        sa.Column('signal_strength', sa.Integer(), nullable=True),
        sa.Column('channel', sa.Integer(), nullable=True),
        sa.Column('raw_data', sa.LargeBinary(), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.session_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_wifi_frames_session_id'), 'wifi_frames', ['session_id'], unique=False)
    op.create_index(op.f('ix_wifi_frames_timestamp'), 'wifi_frames', ['timestamp'], unique=False)
    op.create_index(op.f('ix_wifi_frames_frame_type'), 'wifi_frames', ['frame_type'], unique=False)
    op.create_index(op.f('ix_wifi_frames_source_mac'), 'wifi_frames', ['source_mac'], unique=False)
    op.create_index(op.f('ix_wifi_frames_bssid'), 'wifi_frames', ['bssid'], unique=False)
    op.create_index(op.f('ix_wifi_frames_ssid'), 'wifi_frames', ['ssid'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_wifi_frames_ssid'), table_name='wifi_frames')
    op.drop_index(op.f('ix_wifi_frames_bssid'), table_name='wifi_frames')
    op.drop_index(op.f('ix_wifi_frames_source_mac'), table_name='wifi_frames')
    op.drop_index(op.f('ix_wifi_frames_frame_type'), table_name='wifi_frames')
    op.drop_index(op.f('ix_wifi_frames_timestamp'), table_name='wifi_frames')
    op.drop_index(op.f('ix_wifi_frames_session_id'), table_name='wifi_frames')
    op.drop_table('wifi_frames')

