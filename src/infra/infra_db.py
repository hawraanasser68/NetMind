import os
import logging
import psycopg2
import psycopg2.extras
from src.infra.infra_vault import get_secret

logger = logging.getLogger(__name__)

_connection = None


def get_db_connection():
    global _connection
    if _connection is None or _connection.closed:
        _connection = psycopg2.connect(
            host           = os.environ.get('DB_HOST', 'postgres'),
            port           = int(os.environ.get('DB_PORT', 5432)),
            dbname         = os.environ.get('DB_NAME', 'socdb'),
            user           = os.environ.get('DB_USER', 'postgres'),
            password       = get_secret('db_password'),
            cursor_factory = psycopg2.extras.RealDictCursor,
        )
        logger.info('Database connection established.')
    return _connection


def get_db_session():
    """Returns a database connection. Reconnects if the connection was closed."""
    return get_db_connection()
