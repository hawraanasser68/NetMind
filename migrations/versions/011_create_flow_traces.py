"""Create flow_traces table to record per-step agent investigation timeline.

Revision ID: 011
Revises: 010
"""

revision = '011'
down_revision = '010'
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS flow_traces (
            id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
            alert_id         UUID        REFERENCES security_alerts(id) ON DELETE CASCADE,
            flow_id          UUID,
            step_order       INTEGER     NOT NULL,
            step_type        VARCHAR(30) NOT NULL,
            tool_name        VARCHAR(50),
            tool_args        JSONB,
            result_summary   TEXT,
            duration_ms      INTEGER,
            guardrail_status VARCHAR(20),
            metadata         JSONB NOT NULL DEFAULT '{}',
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute('CREATE INDEX IF NOT EXISTS idx_ft_alert_id ON flow_traces (alert_id)')
    op.execute('CREATE INDEX IF NOT EXISTS idx_ft_flow_id  ON flow_traces (flow_id)')

    op.execute('GRANT SELECT, INSERT ON flow_traces TO agent_user')
    op.execute('GRANT SELECT         ON flow_traces TO dashboard_user')


def downgrade() -> None:
    op.execute('DROP TABLE IF EXISTS flow_traces')
