import os
import hvac
import logging

logger = logging.getLogger(__name__)

_vault_client = None
_secrets_cache = {}


def _get_vault_client() -> hvac.Client:
    global _vault_client
    if _vault_client is None:
        vault_addr  = os.environ.get('VAULT_ADDR', 'http://vault:8200')
        vault_token = os.environ.get('VAULT_TOKEN')

        if not vault_token:
            raise RuntimeError(
                'VAULT_TOKEN environment variable is not set. '
                'The application cannot start safely without secret management.'
            )

        _vault_client = hvac.Client(url=vault_addr, token=vault_token)

        if not _vault_client.is_authenticated():
            raise RuntimeError(
                'Cannot connect to Vault. '
                'The application cannot start safely. '
                'Check that Vault is running and the token is valid.'
            )

        logger.info(f'Connected to Vault at {vault_addr}')

    return _vault_client


def get_secret(secret_name: str) -> str:
    if secret_name in _secrets_cache:
        return _secrets_cache[secret_name]

    client = _get_vault_client()

    try:
        response = client.secrets.kv.v2.read_secret_version(
            path        = f'soc-agent/{secret_name}',
            mount_point = 'secret',
        )
        value = response['data']['data']['value']
        _secrets_cache[secret_name] = value
        return value
    except Exception as e:
        raise RuntimeError(
            f"Failed to load secret '{secret_name}' from Vault. "
            f'The application cannot start safely.'
        ) from e


def load_secrets():
    """
    Pre-load all secrets at startup.
    Required secrets: service refuses to start if missing.
    Optional secrets: logs a warning but continues.
    """
    required_secrets = [
        'claude_api_key',
        'virustotal_api_key',
        'abuseipdb_api_key',
        'alienvault_api_key',
        'db_password',
        'redis_password',
        'service_token',
    ]

    optional_secrets = [
        'greynoise_api_key',   # excluded — requires paid subscription
        'shodan_api_key',      # not needed — Shodan InternetDB is free (no key)
    ]

    for secret in required_secrets:
        try:
            get_secret(secret)
            logger.info(f'Secret loaded: {secret}')
        except RuntimeError as e:
            raise RuntimeError(
                f'Missing required secret: {secret}. '
                f'The service cannot start.'
            ) from e

    for secret in optional_secrets:
        try:
            get_secret(secret)
            logger.info(f'Optional secret loaded: {secret}')
        except RuntimeError:
            logger.warning(f'Optional secret not found, skipping: {secret}')

    logger.info('All secrets loaded successfully.')
