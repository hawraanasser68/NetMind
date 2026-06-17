"""Add scoring and investigation fields to security_alerts.

Revision ID: 010
Revises: 009
"""

revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.execute("""
        ALTER TABLE security_alerts
            ADD COLUMN IF NOT EXISTS classifier_score   DOUBLE PRECISION,
            ADD COLUMN IF NOT EXISTS deviation_score    DOUBLE PRECISION,
            ADD COLUMN IF NOT EXISTS machine_confidence DOUBLE PRECISION,
            ADD COLUMN IF NOT EXISTS tools_called       JSONB NOT NULL DEFAULT '[]',
            ADD COLUMN IF NOT EXISTS firewall_rule      TEXT,
            ADD COLUMN IF NOT EXISTS limit_hit          BOOLEAN NOT NULL DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS escalated_to_human BOOLEAN NOT NULL DEFAULT FALSE
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE security_alerts
            DROP COLUMN IF EXISTS classifier_score,
            DROP COLUMN IF EXISTS deviation_score,
            DROP COLUMN IF EXISTS machine_confidence,
            DROP COLUMN IF EXISTS tools_called,
            DROP COLUMN IF EXISTS firewall_rule,
            DROP COLUMN IF EXISTS limit_hit,
            DROP COLUMN IF EXISTS escalated_to_human
    """)
