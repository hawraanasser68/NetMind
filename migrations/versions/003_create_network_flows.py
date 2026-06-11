"""Create network_flows table and grant per-user privileges.

Revision ID: 003
Revises: 002
"""

revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS network_flows (
            id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            machine_ip   INET             NOT NULL,
            captured_at  TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

            -- Classifier output
            label        SMALLINT         NOT NULL,   -- 0=benign 1=suspicious 2=attack
            confidence   DOUBLE PRECISION NOT NULL,
            risk_score   DOUBLE PRECISION,            -- filled by risk scorer after deviation calc
            risk_level   VARCHAR(10),                 -- CRITICAL / HIGH / MEDIUM / LOW / BENIGN

            -- CICIDS2018 features (snake_case of original column names)
            -- Volume
            tot_fwd_pkts        DOUBLE PRECISION,
            tot_bwd_pkts        DOUBLE PRECISION,
            totlen_fwd_pkts     DOUBLE PRECISION,
            totlen_bwd_pkts     DOUBLE PRECISION,
            -- Rate
            flow_byts_per_s     DOUBLE PRECISION,
            flow_pkts_per_s     DOUBLE PRECISION,
            fwd_pkts_per_s      DOUBLE PRECISION,
            bwd_pkts_per_s      DOUBLE PRECISION,
            -- Timing
            flow_duration       DOUBLE PRECISION,
            flow_iat_mean       DOUBLE PRECISION,
            flow_iat_std        DOUBLE PRECISION,
            fwd_iat_mean        DOUBLE PRECISION,
            fwd_iat_std         DOUBLE PRECISION,
            bwd_iat_mean        DOUBLE PRECISION,
            bwd_iat_std         DOUBLE PRECISION,
            -- Active/Idle
            active_mean         DOUBLE PRECISION,
            active_std          DOUBLE PRECISION,
            idle_mean           DOUBLE PRECISION,
            idle_std            DOUBLE PRECISION,
            -- TCP Flags
            syn_flag_cnt        DOUBLE PRECISION,
            fin_flag_cnt        DOUBLE PRECISION,
            rst_flag_cnt        DOUBLE PRECISION,
            psh_flag_cnt        DOUBLE PRECISION,
            ack_flag_cnt        DOUBLE PRECISION,
            urg_flag_cnt        DOUBLE PRECISION,
            -- Packet size
            pkt_len_mean        DOUBLE PRECISION,
            pkt_len_std         DOUBLE PRECISION,
            down_up_ratio       DOUBLE PRECISION,
            -- Derived
            byte_ratio          DOUBLE PRECISION,
            proto_tcp           DOUBLE PRECISION,
            proto_udp           DOUBLE PRECISION,
            proto_icmp          DOUBLE PRECISION,
            is_privileged_port  DOUBLE PRECISION
        )
    """)

    op.execute('CREATE INDEX IF NOT EXISTS idx_nf_machine_ip   ON network_flows (machine_ip)')
    op.execute('CREATE INDEX IF NOT EXISTS idx_nf_captured_at  ON network_flows (captured_at)')
    op.execute('CREATE INDEX IF NOT EXISTS idx_nf_risk_level   ON network_flows (risk_level)')

    # Per-user grants
    op.execute('GRANT INSERT          ON network_flows TO logger_user')
    op.execute('GRANT SELECT          ON network_flows TO profiler_user')
    op.execute('GRANT SELECT          ON network_flows TO agent_user')
    op.execute('GRANT SELECT          ON network_flows TO dashboard_user')


def downgrade() -> None:
    op.execute('DROP TABLE IF EXISTS network_flows')
