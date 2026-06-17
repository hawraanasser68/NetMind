import os
import logging
import psycopg2
import psycopg2.extras
import psycopg2.extensions
from src.infra.infra_vault import get_secret

logger = logging.getLogger(__name__)

_connection = None


def _create_connection():
    conn = psycopg2.connect(
        host           = os.environ.get('DB_HOST', 'postgres'),
        port           = int(os.environ.get('DB_PORT', 5432)),
        dbname         = os.environ.get('DB_NAME', 'socdb'),
        user           = os.environ.get('DB_USER', 'postgres'),
        password       = get_secret(os.environ.get('DB_PASSWORD_SECRET', 'db_password')),
        cursor_factory = psycopg2.extras.RealDictCursor,
    )
    # Autocommit so read-only queries never leave the shared singleton connection
    # "idle in transaction" holding locks (which can block DDL/migrations). Writers
    # call commit() explicitly; with autocommit that is a harmless no-op.
    conn.autocommit = True
    logger.info('Database connection established.')
    return conn


def get_db_connection():
    global _connection

    if _connection is None or _connection.closed:
        _connection = _create_connection()
        return _connection

    status = _connection.get_transaction_status()

    if status == psycopg2.extensions.TRANSACTION_STATUS_INERROR:
        # A previous query failed — rollback to clear the error state.
        _connection.rollback()

    elif status == psycopg2.extensions.TRANSACTION_STATUS_UNKNOWN:
        # The server closed the connection unexpectedly — reconnect.
        try:
            _connection.close()
        except Exception:
            pass
        _connection = _create_connection()

    return _connection


def get_db_session():
    """Returns a database connection. Reconnects if the connection was closed or broken."""
    return get_db_connection()
