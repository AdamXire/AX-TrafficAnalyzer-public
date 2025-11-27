"""add_phase5_analysis_tables

Revision ID: a7b3f4d2e851
Revises: e848002d1464
Create Date: 2025-01-25 12:00:00

Adds tables for Phase 5 analysis features:
- findings: Vulnerability and anomaly findings
- analysis_results: Protocol analysis output
- threat_intel_cache: Cached threat intelligence data
- dns_queries: DNS traffic logs from tcpdump
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision = 'a7b3f4d2e851'
down_revision = 'e848002d1464'
branch_labels = None
depends_on = None


def upgrade():
    """Create Phase 5 analysis tables."""
    
    # Findings table - stores vulnerability and anomaly findings
    op.create_table(
        'findings',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('session_id', sa.String(), nullable=False),
        sa.Column('flow_id', sa.String(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('recommendation', sa.Text(), nullable=True),
        sa.Column('meta_data', sa.JSON(), nullable=True),  # Renamed from 'metadata' (SQLAlchemy reserved)
        sa.ForeignKeyConstraint(['session_id'], ['sessions.session_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['flow_id'], ['flows.flow_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_findings_session_id', 'findings', ['session_id'])
    op.create_index('idx_findings_flow_id', 'findings', ['flow_id'])
    op.create_index('idx_findings_severity', 'findings', ['severity'])
    op.create_index('idx_findings_timestamp', 'findings', ['timestamp'])
    op.create_index('idx_findings_category', 'findings', ['category'])
    
    # Analysis results table - stores protocol analysis output
    op.create_table(
        'analysis_results',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('flow_id', sa.String(), nullable=False),
        sa.Column('analyzer_name', sa.String(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('meta_data', sa.JSON(), nullable=True),  # Renamed from 'metadata' (SQLAlchemy reserved)
        sa.ForeignKeyConstraint(['flow_id'], ['flows.flow_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_analysis_results_flow_id', 'analysis_results', ['flow_id'])
    op.create_index('idx_analysis_results_analyzer', 'analysis_results', ['analyzer_name'])
    op.create_index('idx_analysis_results_timestamp', 'analysis_results', ['timestamp'])
    
    # Threat intelligence cache - caches API responses from VirusTotal, OTX, etc.
    op.create_table(
        'threat_intel_cache',
        sa.Column('domain', sa.String(), nullable=False),
        sa.Column('source', sa.String(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('reputation', sa.String(), nullable=True),
        sa.Column('meta_data', sa.JSON(), nullable=True),  # Renamed from 'metadata' (SQLAlchemy reserved)
        sa.PrimaryKeyConstraint('domain', 'source')
    )
    op.create_index('idx_threat_intel_timestamp', 'threat_intel_cache', ['timestamp'])
    op.create_index('idx_threat_intel_reputation', 'threat_intel_cache', ['reputation'])
    
    # DNS queries table - logs DNS queries from tcpdump
    op.create_table(
        'dns_queries',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('session_id', sa.String(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('query', sa.String(), nullable=False),
        sa.Column('query_type', sa.String(), nullable=False),
        sa.Column('response', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.session_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_dns_queries_session_id', 'dns_queries', ['session_id'])
    op.create_index('idx_dns_queries_query', 'dns_queries', ['query'])
    op.create_index('idx_dns_queries_timestamp', 'dns_queries', ['timestamp'])


def downgrade():
    """Drop Phase 5 analysis tables."""
    
    # Drop indexes first
    op.drop_index('idx_dns_queries_timestamp', 'dns_queries')
    op.drop_index('idx_dns_queries_query', 'dns_queries')
    op.drop_index('idx_dns_queries_session_id', 'dns_queries')
    op.drop_table('dns_queries')
    
    op.drop_index('idx_threat_intel_reputation', 'threat_intel_cache')
    op.drop_index('idx_threat_intel_timestamp', 'threat_intel_cache')
    op.drop_table('threat_intel_cache')
    
    op.drop_index('idx_analysis_results_timestamp', 'analysis_results')
    op.drop_index('idx_analysis_results_analyzer', 'analysis_results')
    op.drop_index('idx_analysis_results_flow_id', 'analysis_results')
    op.drop_table('analysis_results')
    
    op.drop_index('idx_findings_category', 'findings')
    op.drop_index('idx_findings_timestamp', 'findings')
    op.drop_index('idx_findings_severity', 'findings')
    op.drop_index('idx_findings_flow_id', 'findings')
    op.drop_index('idx_findings_session_id', 'findings')
    op.drop_table('findings')

