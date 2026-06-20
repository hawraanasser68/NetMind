"""Add human review decision fields to security_alerts.

Revision ID: 012
Revises: 011
"""

revision = '012'
down_revision = '011'
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.execute("""
        ALTER TABLE security_alerts
            ADD COLUMN IF NOT EXISTS human_decision VARCHAR(20),
            ADD COLUMN IF NOT EXISTS human_note     TEXT,
            ADD COLUMN IF NOT EXISTS reviewed_at    TIMESTAMP WITH TIME ZONE
    """)
    op.execute("""
        GRANT UPDATE (status, human_decision, human_note, firewall_rule, reviewed_at)
            ON security_alerts TO dashboard_user
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE security_alerts
            DROP COLUMN IF EXISTS human_decision,
            DROP COLUMN IF EXISTS human_note,
            DROP COLUMN IF EXISTS reviewed_at
    """)
