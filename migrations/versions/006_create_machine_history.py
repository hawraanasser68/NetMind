"""Create machine_history table (pgvector RAG store) and grant per-user privileges.

Revision ID: 006
Revises: 005
"""

revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS machine_history (
            id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
            machine_ip      INET         NOT NULL,
            investigated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            risk_level      VARCHAR(10),
            alert_id        UUID,                   -- soft reference to security_alerts (no FK)

            -- The text that was embedded — returned as context to the agent during RAG retrieval
            summary         TEXT         NOT NULL,

            -- 384-dimensional embedding from all-MiniLM-L6-v2
            embedding       vector(384)  NOT NULL
        )
    """)

    op.execute('CREATE INDEX IF NOT EXISTS idx_mh_machine_ip ON machine_history (machine_ip)')

    # HNSW index for fast cosine similarity search (pgvector >= 0.5.0)
    # The agent queries: ORDER BY embedding <=> query_vector LIMIT 5
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_mh_embedding
        ON machine_history
        USING hnsw (embedding vector_cosine_ops)
    """)

    # Grants
    op.execute('GRANT SELECT, INSERT ON machine_history TO agent_user')
    op.execute('GRANT SELECT         ON machine_history TO dashboard_user')


def downgrade() -> None:
    op.execute('DROP TABLE IF EXISTS machine_history')
