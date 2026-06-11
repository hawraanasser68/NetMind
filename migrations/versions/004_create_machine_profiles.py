"""Create machine_profiles table and grant per-user privileges.

Revision ID: 004
Revises: 003
"""

revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS machine_profiles (
            machine_ip          INET PRIMARY KEY,
            flow_count          BIGINT           NOT NULL DEFAULT 0,
            first_seen          TIMESTAMPTZ,
            last_seen           TIMESTAMPTZ,

            -- Welford online algorithm state: each tracked feature stores (mean, M2).
            -- Variance = M2 / flow_count. Std dev = sqrt(variance).

            -- Total bytes (tot_fwd_pkts + tot_bwd_pkts bytes equivalent)
            bytes_mean          DOUBLE PRECISION NOT NULL DEFAULT 0,
            bytes_m2            DOUBLE PRECISION NOT NULL DEFAULT 0,

            -- Flow bytes per second
            bytes_per_sec_mean  DOUBLE PRECISION NOT NULL DEFAULT 0,
            bytes_per_sec_m2    DOUBLE PRECISION NOT NULL DEFAULT 0,

            -- Byte ratio (forward / total bytes)
            byte_ratio_mean     DOUBLE PRECISION NOT NULL DEFAULT 0,
            byte_ratio_m2       DOUBLE PRECISION NOT NULL DEFAULT 0,

            -- Total packets (fwd + bwd)
            pkts_mean           DOUBLE PRECISION NOT NULL DEFAULT 0,
            pkts_m2             DOUBLE PRECISION NOT NULL DEFAULT 0,

            -- Flow duration
            duration_mean       DOUBLE PRECISION NOT NULL DEFAULT 0,
            duration_m2         DOUBLE PRECISION NOT NULL DEFAULT 0,

            -- Port and protocol history for new_port / new_protocol deviation features
            known_ports         INTEGER[]        NOT NULL DEFAULT '{}',
            known_protocols     SMALLINT[]       NOT NULL DEFAULT '{}'
        )
    """)

    # Grants
    op.execute('GRANT SELECT, INSERT, UPDATE ON machine_profiles TO profiler_user')
    op.execute('GRANT SELECT                 ON machine_profiles TO agent_user')
    op.execute('GRANT SELECT                 ON machine_profiles TO dashboard_user')


def downgrade() -> None:
    op.execute('DROP TABLE IF EXISTS machine_profiles')
