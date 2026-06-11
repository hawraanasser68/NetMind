"""Create least-privilege application database users.

Revision ID: 002
Revises: 001
"""

revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None

import os
import sqlalchemy as sa
from alembic import op

_USERS = [
    ('classifier_user', 'CLASSIFIER_DB_PASSWORD'),
    ('profiler_user',   'PROFILER_DB_PASSWORD'),
    ('logger_user',     'LOGGER_DB_PASSWORD'),
    ('agent_user',      'AGENT_DB_PASSWORD'),
    ('dashboard_user',  'DASHBOARD_DB_PASSWORD'),
]


def upgrade() -> None:
    conn = op.get_bind()
    for username, env_var in _USERS:
        password = os.environ[env_var]
        # CREATE USER only if the role does not already exist (idempotent)
        #DO $$ ... IF NOT EXISTS block makes it idempotent — if the user already exists (e.g. someone re-ran migrations), it skips silently instead of crashing
        conn.execute(sa.text(
            f"DO $$ BEGIN "
            f"  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{username}') THEN "
            f"    CREATE USER {username} WITH PASSWORD :pw; "
            f"  END IF; "
            f"END $$"
        ), {'pw': password})


def downgrade() -> None:
    conn = op.get_bind()
    for username, _ in _USERS:
        conn.execute(sa.text(f'DROP USER IF EXISTS {username}'))
