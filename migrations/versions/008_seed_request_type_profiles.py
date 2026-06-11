"""Seed request_type_profiles with population-level baselines.

The sentinel machine_ip '0.0.0.0' represents population norms derived from CICIDS2018.
When a machine has not yet seen a given request type, the profiler falls back to these
rows so the deviation formula has a meaningful starting point.

Welford values: flow_count=10000, mean=typical bytes per flow, m2=variance * flow_count.
Std dev = sqrt(m2 / flow_count). Values are conservative approximations — tune by running
scoring_deviation against real CICIDS2018 data once the pipeline is live.

Revision ID: 008
Revises: 007
"""

revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa

# (request_type, bytes_mean, bytes_std_approx)
# m2 = std² * flow_count  (flow_count = 10000 for all seed rows)
_POPULATION_BASELINES = [
    # request_type    bytes_mean   bytes_std
    ('HTTP',          50_000,      25_000),
    ('HTTPS',         30_000,      15_000),
    ('DNS',              500,         300),
    ('SSH',           10_000,       8_000),
    ('FTP',          200_000,     150_000),
    ('SMTP',          50_000,      30_000),
    ('UNKNOWN',       20_000,      18_000),
]

_FLOW_COUNT = 10_000
_SENTINEL_IP = '0.0.0.0'


def upgrade() -> None:
    conn = op.get_bind()
    for request_type, mean, std in _POPULATION_BASELINES:
        m2 = (std ** 2) * _FLOW_COUNT
        conn.execute(sa.text("""
            INSERT INTO request_type_profiles
                (machine_ip, request_type, flow_count, bytes_mean, bytes_m2)
            VALUES
                (:ip, :rt, :n, :mean, :m2)
            ON CONFLICT (machine_ip, request_type) DO NOTHING
        """), {
            'ip':   _SENTINEL_IP,
            'rt':   request_type,
            'n':    _FLOW_COUNT,
            'mean': float(mean),
            'm2':   float(m2),
        })


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text(
        "DELETE FROM request_type_profiles WHERE machine_ip = :ip"
    ), {'ip': _SENTINEL_IP})
