import os

import psycopg2
import psycopg2.extras
import psycopg2.extensions

from src.infra.infra_vault import get_secret

_conn = None


def _create_conn():
    conn = psycopg2.connect(
        host           = os.environ.get('DB_HOST', 'postgres'),
        port           = int(os.environ.get('DB_PORT', 5432)),
        dbname         = os.environ.get('DB_NAME', 'socdb'),
        user           = os.environ.get('DB_USER', 'dashboard_user'),
        password       = get_secret(os.environ.get('DB_PASSWORD_SECRET', 'dashboard_db_password')),
        cursor_factory = psycopg2.extras.RealDictCursor,
    )
    # Read-only dashboard: autocommit prevents the cached connection from sitting
    # "idle in transaction" between refreshes, which otherwise holds locks and can
    # block DDL/maintenance on the shared database.
    conn.autocommit = True
    return conn


def _get_conn():
    global _conn
    if _conn is None or _conn.closed:
        _conn = _create_conn()
        return _conn

    status = _conn.get_transaction_status()
    if status == psycopg2.extensions.TRANSACTION_STATUS_INERROR:
        _conn.rollback()
    elif status == psycopg2.extensions.TRANSACTION_STATUS_UNKNOWN:
        try:
            _conn.close()
        except Exception:
            pass
        _conn = _create_conn()

    return _conn


def get_stats_last_24h() -> dict:
    with _get_conn().cursor() as cur:
        cur.execute("""
            SELECT
                COUNT(*)                                            AS alerts,
                COUNT(*) FILTER (WHERE risk_level = 'CRITICAL')    AS critical,
                COUNT(*) FILTER (WHERE escalated_to_human = TRUE)  AS escalated
            FROM security_alerts
            WHERE created_at >= NOW() - INTERVAL '24 hours'
        """)
        alerts_row = dict(cur.fetchone())

        cur.execute("""
            SELECT COUNT(*) AS flows
            FROM network_flows
            WHERE captured_at >= NOW() - INTERVAL '24 hours'
        """)
        flows_row = dict(cur.fetchone())

        cur.execute("SELECT COUNT(DISTINCT machine_ip) AS machines FROM security_alerts")
        machines_row = dict(cur.fetchone())

    return {
        'flows':    int(flows_row['flows']),
        'alerts':   int(alerts_row['alerts']),
        'critical': int(alerts_row['critical']),
        'escalated':int(alerts_row['escalated']),
        'machines': int(machines_row['machines']),
    }


def get_stats_last_hour() -> dict:
    return get_stats_last_24h()


def get_recent_alerts(limit: int = 50) -> list[dict]:
    with _get_conn().cursor() as cur:
        cur.execute("""
            SELECT
                id, machine_ip, flow_id, created_at, risk_level, status,
                summary, recommended_action, iocs, osint_results,
                classifier_score, deviation_score, machine_confidence,
                tools_called, firewall_rule, limit_hit, escalated_to_human
            FROM security_alerts
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,))
        rows = cur.fetchall()
    return [dict(r) for r in rows]


def get_traces_for_alerts(alert_ids: list[str]) -> dict[str, list[dict]]:
    """Return {alert_id: [trace_steps ordered by step_order]} for a batch of alerts."""
    if not alert_ids:
        return {}
    with _get_conn().cursor() as cur:
        cur.execute("""
            SELECT
                alert_id, step_order, step_type, tool_name,
                tool_args, result_summary, duration_ms, guardrail_status,
                metadata, created_at
            FROM flow_traces
            WHERE alert_id = ANY(%s::uuid[])
            ORDER BY alert_id, step_order
        """, (alert_ids,))
        rows = cur.fetchall()

    result: dict[str, list[dict]] = {}
    for row in rows:
        aid = str(row['alert_id'])
        result.setdefault(aid, []).append(dict(row))
    return result


def get_escalated_alerts(limit: int = 50) -> list[dict]:
    """Fetch open alerts that need human review."""
    with _get_conn().cursor() as cur:
        cur.execute("""
            SELECT
                id, machine_ip, flow_id, created_at, risk_level, status,
                summary, recommended_action, iocs, osint_results,
                classifier_score, deviation_score, machine_confidence,
                tools_called, firewall_rule, limit_hit, escalated_to_human,
                human_decision, human_note, reviewed_at
            FROM security_alerts
            WHERE escalated_to_human = TRUE AND status = 'open'
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,))
        rows = cur.fetchall()
    return [dict(r) for r in rows]


def record_human_decision(
    alert_id: str,
    decision: str,
    custom_rule: str | None = None,
    note: str | None = None,
) -> None:
    """Record a human analyst's decision on an escalated alert."""
    with _get_conn().cursor() as cur:
        cur.execute("""
            UPDATE security_alerts
            SET
                status          = 'resolved',
                human_decision  = %s,
                human_note      = %s,
                firewall_rule   = COALESCE(%s, firewall_rule),
                reviewed_at     = NOW()
            WHERE id = %s::uuid
        """, (decision, note, custom_rule, alert_id))


def get_machine_profiles() -> list[dict]:
    with _get_conn().cursor() as cur:
        cur.execute("""
            SELECT
                machine_ip, flow_count, first_seen, last_seen,
                known_ports, known_protocols
            FROM machine_profiles
            ORDER BY flow_count DESC
            LIMIT 100
        """)
        rows = cur.fetchall()
    return [dict(r) for r in rows]
