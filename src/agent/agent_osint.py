import json

import requests

from src.infra.infra_redaction import redact
from src.infra.infra_vault import get_secret

# Per-tool cache TTL in seconds
OSINT_TTL = {
    'lookup_ip_vt':    3600,
    'lookup_ip_abuse': 3600,
    'lookup_threats':  7200,
    'whois_domain':    86400,
    'lookup_ports':    3600,
}

# GreyNoise excluded — requires paid subscription.
# Coverage provided by VirusTotal + AbuseIPDB.


def get_osint_cache_key(tool_name: str, target: str) -> str:
    return f'osint:{target}:{tool_name}'


def call_osint_tool(tool_name: str, args: dict, redis) -> dict:
    """
    Call an OSINT tool with Redis caching and redaction.
    Returns {'source': 'cache'|'api', 'data': {...}} or {'error': '...'}.
    """
    target    = args.get('ip_address') or args.get('domain', '')
    cache_key = get_osint_cache_key(tool_name, target)

    cached = redis.get(cache_key)
    if cached:
        return {'source': 'cache', 'data': json.loads(cached)}

    try:
        if tool_name == 'lookup_ip_vt':
            result = _virustotal(target)
        elif tool_name == 'lookup_ip_abuse':
            result = _abuseipdb(target)
        elif tool_name == 'lookup_threats':
            result = _alienvault(target)
        elif tool_name == 'whois_domain':
            result = _whois(target)
        elif tool_name == 'lookup_ports':
            result = _shodan(target)
        else:
            return {'error': f'Unknown tool: {tool_name}'}

        result_str = redact(json.dumps(result))
        result     = json.loads(result_str)

        ttl = OSINT_TTL.get(tool_name, 3600)
        redis.set(cache_key, json.dumps(result), ex=ttl)

        return {'source': 'api', 'data': result}

    except Exception as e:
        return {
            'error': (
                f'{tool_name} is currently unavailable. '
                f'Analysis will proceed with available signals only.'
            ),
            'technical': str(e),
        }


def _virustotal(ip: str) -> dict:
    api_key  = get_secret('virustotal_api_key')
    response = requests.get(
        f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
        headers={'x-apikey': api_key},
        timeout=10,
    )
    response.raise_for_status()
    data  = response.json()['data']['attributes']
    stats = data.get('last_analysis_stats', {})
    total = sum(stats.values())

    return {
        'tool':       'VirusTotal',
        'ip':         ip,
        'malicious':  stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'total':      total,
        'reputation': data.get('reputation', 0),
        'tags':       data.get('tags', []),
        'country':    data.get('country', 'unknown'),
        'as_owner':   data.get('as_owner', 'unknown'),
        'summary': (
            f"VirusTotal: {stats.get('malicious', 0)}/{total} vendors "
            f"flagged {ip} as malicious. "
            f"Reputation: {data.get('reputation', 0)}. "
            f"Tags: {', '.join(data.get('tags', []))}."
        ),
    }


def _abuseipdb(ip: str) -> dict:
    api_key  = get_secret('abuseipdb_api_key')
    response = requests.get(
        'https://api.abuseipdb.com/api/v2/check',
        headers={'Key': api_key, 'Accept': 'application/json'},
        params={'ipAddress': ip, 'maxAgeInDays': 90},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()['data']

    return {
        'tool':               'AbuseIPDB',
        'ip':                 ip,
        'confidence':         data['abuseConfidenceScore'],
        'total_reports':      data['totalReports'],
        'distinct_reporters': data['numDistinctUsers'],
        'is_tor':             data['isTor'],
        'country':            data['countryCode'],
        'last_reported':      data['lastReportedAt'],
        'summary': (
            f"AbuseIPDB: {data['abuseConfidenceScore']}% confidence malicious, "
            f"{data['totalReports']} reports from {data['numDistinctUsers']} organizations. "
            f"{'Known Tor exit node. ' if data['isTor'] else ''}"
            f"Last reported: {data['lastReportedAt']}."
        ),
    }


def _alienvault(ip: str) -> dict:
    api_key  = get_secret('alienvault_api_key')
    response = requests.get(
        f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
        headers={'X-OTX-API-KEY': api_key},
        timeout=10,
    )
    response.raise_for_status()
    data        = response.json()
    pulse_count = data.get('pulse_info', {}).get('count', 0)
    pulses      = data.get('pulse_info', {}).get('pulses', [])
    pulse_names = [p.get('name', '') for p in pulses[:3]]

    return {
        'tool':        'AlienVault OTX',
        'ip':          ip,
        'pulse_count': pulse_count,
        'pulse_names': pulse_names,
        'summary': (
            f"AlienVault OTX: {ip} appears in {pulse_count} threat intelligence pulses. "
            f"{'Associated campaigns: ' + ', '.join(pulse_names) + '.' if pulse_names else 'No named campaigns.'}"
        ),
    }


def _whois(domain: str) -> dict:
    import whois  # python-whois library
    from datetime import datetime

    w             = whois.whois(domain)
    creation_date = w.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    age_days = (datetime.utcnow() - creation_date).days if creation_date else None

    return {
        'tool':          'WHOIS',
        'domain':        domain,
        'registrar':     w.registrar,
        'creation_date': str(creation_date),
        'age_days':      age_days,
        'summary': (
            f"WHOIS: {domain} registered {age_days} days ago "
            f"via {w.registrar}. "
            f"{'Newly registered domain — high suspicion. ' if age_days and age_days < 30 else ''}"
        ),
    }


def _shodan(ip: str) -> dict:
    # Shodan InternetDB — free, no API key required
    response = requests.get(
        f'https://internetdb.shodan.io/{ip}',
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()

    return {
        'tool':  'Shodan InternetDB',
        'ip':    ip,
        'ports': data.get('ports', []),
        'tags':  data.get('tags', []),
        'cves':  data.get('vulns', []),
        'summary': (
            f"Shodan: {ip} exposes ports {data.get('ports', [])}. "
            f"Tags: {', '.join(data.get('tags', []))}. "
            f"Known CVEs: {', '.join(data.get('vulns', [])[:3])}."
        ),
    }
