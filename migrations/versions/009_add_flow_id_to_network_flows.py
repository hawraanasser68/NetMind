"""Add flow_id column to network_flows for idempotent inserts.

Revision ID: 009
Revises: 008
"""

revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.execute("""
        ALTER TABLE network_flows
        ADD COLUMN IF NOT EXISTS flow_id VARCHAR(32) UNIQUE
    """)


def downgrade() -> None:
    op.execute('ALTER TABLE network_flows DROP COLUMN IF EXISTS flow_id')
