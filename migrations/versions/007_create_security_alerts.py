"""Create security_alerts table and grant per-user privileges.

Revision ID: 007
Revises: 006
"""

revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id                 UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
            machine_ip         INET         NOT NULL,
            flow_id            UUID,                    -- soft reference to network_flows
            created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            risk_level         VARCHAR(10)  NOT NULL,   -- CRITICAL / HIGH / MEDIUM / LOW

            -- Agent output
            summary            TEXT         NOT NULL,   -- Claude's natural-language investigation summary
            recommended_action TEXT         NOT NULL,   -- Claude's recommended remediation step
            iocs               JSONB        NOT NULL DEFAULT '[]', -- list of flagged IPs / domains / hashes
            osint_results      JSONB        NOT NULL DEFAULT '{}', -- raw OSINT API responses

            -- Analyst workflow
            status             VARCHAR(20)  NOT NULL DEFAULT 'open', -- open / acknowledged / resolved
            acknowledged_at    TIMESTAMPTZ,
            resolved_at        TIMESTAMPTZ
        )
    """)

    op.execute('CREATE INDEX IF NOT EXISTS idx_sa_machine_ip  ON security_alerts (machine_ip)')
    op.execute('CREATE INDEX IF NOT EXISTS idx_sa_created_at  ON security_alerts (created_at)')
    op.execute('CREATE INDEX IF NOT EXISTS idx_sa_risk_level  ON security_alerts (risk_level)')
    op.execute('CREATE INDEX IF NOT EXISTS idx_sa_status      ON security_alerts (status)')

    # Grants
    op.execute('GRANT SELECT, INSERT ON security_alerts TO agent_user')
    op.execute('GRANT SELECT         ON security_alerts TO dashboard_user')


def downgrade() -> None:
    op.execute('DROP TABLE IF EXISTS security_alerts')
