"""Install pgvector and uuid-ossp extensions.

Revision ID: 001
Revises: None
"""

revision = '001'
down_revision = None
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS vector')
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')


def downgrade() -> None:
    # Extensions are shared across the database — dropping them could break other things.
    # Leave them in place on rollback.
    pass
