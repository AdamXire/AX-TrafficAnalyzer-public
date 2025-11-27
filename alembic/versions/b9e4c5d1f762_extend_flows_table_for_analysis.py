"""extend_flows_table_for_analysis

Revision ID: b9e4c5d1f762
Revises: a7b3f4d2e851
Create Date: 2025-01-25 12:30:00

Extends flows table with Phase 5 analysis fields:
- request_headers: JSON storage for HTTP request headers
- response_headers: JSON storage for HTTP response headers
- cookies: JSON storage for cookies
- auth_detected: Authentication mechanism (Basic, Bearer, OAuth, etc.)
- sensitive_data_found: Boolean flag for PII/credentials detection
- duration_ms: Request/response duration in milliseconds
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b9e4c5d1f762'
down_revision = 'a7b3f4d2e851'
branch_labels = None
depends_on = None


def upgrade():
    """Add Phase 5 analysis fields to flows table."""
    
    op.add_column('flows', sa.Column('request_headers', sa.JSON(), nullable=True))
    op.add_column('flows', sa.Column('response_headers', sa.JSON(), nullable=True))
    op.add_column('flows', sa.Column('cookies', sa.JSON(), nullable=True))
    op.add_column('flows', sa.Column('auth_detected', sa.String(), nullable=True))
    op.add_column('flows', sa.Column('sensitive_data_found', sa.Boolean(), default=False, nullable=False, server_default='0'))
    op.add_column('flows', sa.Column('duration_ms', sa.Integer(), nullable=True))
    
    # Add indexes for common query patterns
    op.create_index('idx_flows_auth_detected', 'flows', ['auth_detected'])
    op.create_index('idx_flows_sensitive_data', 'flows', ['sensitive_data_found'])


def downgrade():
    """Remove Phase 5 analysis fields from flows table."""
    
    op.drop_index('idx_flows_sensitive_data', 'flows')
    op.drop_index('idx_flows_auth_detected', 'flows')
    
    op.drop_column('flows', 'duration_ms')
    op.drop_column('flows', 'sensitive_data_found')
    op.drop_column('flows', 'auth_detected')
    op.drop_column('flows', 'cookies')
    op.drop_column('flows', 'response_headers')
    op.drop_column('flows', 'request_headers')

