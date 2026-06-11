"""Create request_type_profiles table and grant per-user privileges.

Revision ID: 005
Revises: 004
"""

revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS request_type_profiles (
            machine_ip    INET         NOT NULL,
            request_type  VARCHAR(32)  NOT NULL,
            flow_count    BIGINT       NOT NULL DEFAULT 0,
            first_seen    TIMESTAMPTZ,
            last_seen     TIMESTAMPTZ,

            -- Welford state for bytes volume per request type.
            -- Used for z_bytes_request_type in the deviation formula.
            bytes_mean    DOUBLE PRECISION NOT NULL DEFAULT 0,
            bytes_m2      DOUBLE PRECISION NOT NULL DEFAULT 0,

            PRIMARY KEY (machine_ip, request_type)
        )
    """)

    op.execute('CREATE INDEX IF NOT EXISTS idx_rtp_machine_ip ON request_type_profiles (machine_ip)')

    # Grants
    op.execute('GRANT SELECT, INSERT, UPDATE ON request_type_profiles TO profiler_user')
    op.execute('GRANT SELECT                 ON request_type_profiles TO agent_user')
    op.execute('GRANT SELECT                 ON request_type_profiles TO dashboard_user')


def downgrade() -> None:
    op.execute('DROP TABLE IF EXISTS request_type_profiles')
