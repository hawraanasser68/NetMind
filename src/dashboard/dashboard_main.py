import time
from datetime import datetime, timezone

import streamlit as st

from src.dashboard.dashboard_db import (
    get_machine_profiles,
    get_recent_alerts,
    get_stats_last_hour,
    get_traces_for_alerts,
)
from src.infra.infra_vault import load_secrets

_REFRESH = 10

_CYAN   = '#00C2FF'
_BLUE   = '#2563EB'
_PURPLE = '#7C3AED'
_GREEN  = '#10B981'
_RED    = '#EF4444'
_ORANGE = '#F59E0B'
_YELLOW = '#EAB308'
_GRAY   = '#94A3B8'
_TEXT   = '#E2E8F0'
_MUTED  = '#64748B'
_BG     = '#0A0B14'
_CARD   = '#0D0F1E'
_CARD2  = '#111427'
_BORDER = '#1C2038'

@st.cache_data(ttl=10)
def _load_stats() -> dict:
    return get_stats_last_hour()


@st.cache_data(ttl=10)
def _load_alerts() -> list[dict]:
    return get_recent_alerts(limit=50)


@st.cache_data(ttl=10)
def _load_traces(alert_ids: tuple) -> dict:
    return get_traces_for_alerts(list(alert_ids))


@st.cache_data(ttl=10)
def _load_profiles() -> list[dict]:
    return get_machine_profiles()


_RISK_COLOR = {'CRITICAL': _RED, 'HIGH': _ORANGE, 'MEDIUM': _YELLOW, 'LOW': _CYAN}
_RISK_BG    = {'CRITICAL': '#EF444412', 'HIGH': '#F59E0B12', 'MEDIUM': '#EAB30812', 'LOW': '#00C2FF12'}

_STEP_CFG = {
    'classify':      (_CYAN,   'ML Classifier',  '◈'),
    'input_check':   (_BLUE,   'Input Guard',    '⬡'),
    'tool_call':     (_PURPLE, 'Tool',           '◆'),
    'finding_check': (_BLUE,   'Finding Guard',  '⬡'),
}
_TOOL_META = {
    'lookup_ip_vt':    ('VT',  '#EF4444', 'VirusTotal'),
    'lookup_ip_abuse': ('AB',  '#F59E0B', 'AbuseIPDB'),
    'lookup_threats':  ('OTX', '#7C3AED', 'AlienVault'),
    'whois_domain':    ('WH',  '#64748B', 'WHOIS'),
    'lookup_ports':    ('PT',  '#2563EB', 'Port Scan'),
    'rag_search':      ('RAG', '#00C2FF', 'RAG History'),
    'generate_rule':   ('FW',  '#10B981', 'Firewall Rule'),
    'escalate':        ('ESC', '#EF4444', 'Escalate'),
}
_GUARD_BADGE = {
    'approved': (_GREEN,  'PASS'),
    'rejected': (_RED,    'BLOCK'),
    'modified': (_ORANGE, 'MOD'),
}

_LOGO_SVG = """<svg width="44" height="44" viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="nlg" x1="0" y1="0" x2="44" y2="44" gradientUnits="userSpaceOnUse">
      <stop offset="0%"   stop-color="#00C2FF"/>
      <stop offset="50%"  stop-color="#2563EB"/>
      <stop offset="100%" stop-color="#7C3AED"/>
    </linearGradient>
  </defs>
  <path d="M22 2L40 10V21C40 32 31 41 22 44C13 41 4 32 4 21V10Z" fill="url(#nlg)" opacity="0.92"/>
  <circle cx="22" cy="20" r="3.2" fill="white"/>
  <circle cx="14" cy="15" r="1.8" fill="white" opacity="0.85"/>
  <circle cx="30" cy="15" r="1.8" fill="white" opacity="0.85"/>
  <circle cx="16" cy="27" r="1.8" fill="white" opacity="0.85"/>
  <circle cx="28" cy="27" r="1.8" fill="white" opacity="0.85"/>
  <line x1="22" y1="20" x2="14" y2="15" stroke="white" stroke-width="1.2" opacity="0.65"/>
  <line x1="22" y1="20" x2="30" y2="15" stroke="white" stroke-width="1.2" opacity="0.65"/>
  <line x1="22" y1="20" x2="16" y2="27" stroke="white" stroke-width="1.2" opacity="0.65"/>
  <line x1="22" y1="20" x2="28" y2="27" stroke="white" stroke-width="1.2" opacity="0.65"/>
  <line x1="14" y1="15" x2="30" y2="15" stroke="white" stroke-width="0.6" opacity="0.3"/>
  <line x1="14" y1="15" x2="16" y2="27" stroke="white" stroke-width="0.6" opacity="0.3"/>
  <line x1="30" y1="15" x2="28" y2="27" stroke="white" stroke-width="0.6" opacity="0.3"/>
  <line x1="16" y1="27" x2="28" y2="27" stroke="white" stroke-width="0.6" opacity="0.3"/>
</svg>"""


def _css() -> None:
    st.markdown(f"""<style>
    /* ── Global ─────────────────────────────────────── */
    .stApp {{ background:{_BG} !important; }}
    #MainMenu, footer, header {{ visibility:hidden; }}
    .block-container {{ padding:1rem 2rem 2rem !important; max-width:1440px; }}

    /* ── Typography ──────────────────────────────────── */
    body, p, span, div, li, td, th {{ color:{_TEXT} !important; }}
    h1,h2,h3,h4 {{ color:#ffffff !important; }}
    .stMarkdown p {{ color:{_TEXT} !important; }}

    /* ── Sidebar ─────────────────────────────────────── */
    [data-testid="stSidebar"] {{
        background:{_CARD} !important;
        border-right:1px solid {_BORDER} !important;
    }}
    [data-testid="stSidebar"] * {{ color:{_TEXT} !important; }}
    [data-testid="stSidebarNav"] {{ display:none; }}

    /* ── Expander (alert cards) ───────────────────────── */
    details {{
        background:{_CARD} !important;
        border:1px solid {_BORDER} !important;
        border-radius:10px !important;
        margin-bottom:8px !important;
    }}
    details summary {{
        color:{_TEXT} !important;
        font-size:13px !important;
        padding:14px 18px !important;
        font-family:monospace;
        cursor:pointer;
        list-style:none;
    }}
    details summary::-webkit-details-marker {{ display:none; }}
    details[open] summary {{ border-bottom:1px solid {_BORDER}; }}
    details > div {{ padding:0 18px 16px; }}

    /* ── Code blocks ─────────────────────────────────── */
    code {{ background:#080A12 !important; color:{_CYAN} !important;
            border:1px solid {_BORDER} !important; border-radius:4px; }}
    pre  {{ background:#080A12 !important; border:1px solid {_BORDER} !important;
            border-radius:8px; }}
    pre code {{ border:none !important; }}

    /* ── Dataframe ───────────────────────────────────── */
    .stDataFrame {{ background:{_CARD} !important; border-radius:10px; border:1px solid {_BORDER}; }}
    iframe[data-testid="stDataFrame"] {{ background:{_CARD} !important; }}

    /* ── Alerts / info boxes ─────────────────────────── */
    .stAlert {{ background:{_CARD} !important; border-radius:8px !important;
                border:1px solid {_BORDER} !important; color:{_TEXT} !important; }}

    /* ── Scrollbar ───────────────────────────────────── */
    ::-webkit-scrollbar {{ width:4px; height:4px; }}
    ::-webkit-scrollbar-track {{ background:{_BG}; }}
    ::-webkit-scrollbar-thumb {{ background:{_BLUE}; border-radius:2px; }}

    /* ── HR ───────────────────────────────────────────── */
    hr {{ border-color:{_BORDER} !important; margin:20px 0 !important; }}

    /* ── Select / dropdown ───────────────────────────── */
    [data-baseweb="select"] > div {{ background:{_CARD} !important;
        border-color:{_BORDER} !important; color:{_TEXT} !important; }}
    </style>""", unsafe_allow_html=True)


def _sidebar(stats: dict, alerts: list[dict]) -> str | None:
    """Render sidebar and return selected risk filter."""
    with st.sidebar:
        st.markdown(f"""
        <div style="padding:20px 0 24px;text-align:center">
            {_LOGO_SVG}
            <div style="font-size:22px;font-weight:800;color:#fff;margin-top:12px;line-height:1">
                Net<span style="background:linear-gradient(90deg,{_CYAN},{_PURPLE});
                    -webkit-background-clip:text;-webkit-text-fill-color:transparent">Mind</span>
            </div>
            <div style="font-size:9px;color:{_MUTED};letter-spacing:3px;margin-top:4px">
                AI POWERED SOC AGENT
            </div>
        </div>
        <div style="border-top:1px solid {_BORDER};margin-bottom:20px"></div>
        """, unsafe_allow_html=True)

        # Live status
        now = datetime.now(timezone.utc).strftime('%H:%M:%S UTC')
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:20px;padding:10px 12px;
            background:{_CARD2};border-radius:8px;border:1px solid {_BORDER}">
            <div style="width:8px;height:8px;border-radius:50%;background:{_GREEN};
                box-shadow:0 0 8px {_GREEN}"></div>
            <div>
                <div style="font-size:10px;color:{_GREEN};font-weight:600;letter-spacing:1px">LIVE MONITORING</div>
                <div style="font-size:11px;color:{_MUTED};font-family:monospace">{now}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Risk breakdown
        risk_counts = {}
        for a in alerts:
            lvl = a.get('risk_level', 'UNKNOWN')
            risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

        st.markdown(f'<div style="font-size:10px;color:{_MUTED};letter-spacing:2px;text-transform:uppercase;margin-bottom:10px">Risk Breakdown</div>', unsafe_allow_html=True)
        for lvl in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = risk_counts.get(lvl, 0)
            color = _RISK_COLOR.get(lvl, _GRAY)
            pct   = int((count / len(alerts) * 100)) if alerts else 0
            st.markdown(f"""
            <div style="margin-bottom:8px">
                <div style="display:flex;justify-content:space-between;margin-bottom:3px">
                    <span style="font-size:11px;color:{color};font-weight:600">{lvl}</span>
                    <span style="font-size:11px;color:{_MUTED};font-family:monospace">{count}</span>
                </div>
                <div style="background:{_BORDER};height:3px;border-radius:2px">
                    <div style="background:{color};width:{pct}%;height:3px;border-radius:2px"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown(f'<div style="border-top:1px solid {_BORDER};margin:20px 0"></div>', unsafe_allow_html=True)

        # Filter
        st.markdown(f'<div style="font-size:10px;color:{_MUTED};letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">Filter by Risk</div>', unsafe_allow_html=True)
        choice = st.selectbox('Risk filter', ['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], label_visibility='collapsed')
        return None if choice == 'All' else choice


def _kpi_row(stats: dict) -> None:
    c1, c2, c3, c4, c5 = st.columns(5)
    kpis = [
        (c1, 'FLOWS / 24H',     stats.get('flows', 0),     _CYAN,   '▲'),
        (c2, 'ALERTS / 24H',    stats.get('alerts', 0),    _BLUE,   '⚡'),
        (c3, 'CRITICAL / 24H',  stats.get('critical', 0),  _RED,    '🔴'),
        (c4, 'ESCALATED / 24H', stats.get('escalated', 0), _ORANGE, '👤'),
        (c5, 'MACHINES',        stats.get('machines', 0),  _PURPLE, '◈'),
    ]
    for col, label, val, color, icon in kpis:
        col.markdown(f"""
        <div style="background:{_CARD};border:1px solid {_BORDER};border-top:3px solid {color};
            border-radius:12px;padding:18px 16px 14px;text-align:center">
            <div style="font-size:9px;color:{_MUTED};letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">
                {icon} {label}
            </div>
            <div style="font-size:36px;font-weight:800;color:{color};line-height:1">{val}</div>
        </div>
        """, unsafe_allow_html=True)


def _risk_badge(level: str) -> str:
    c = _RISK_COLOR.get(level, _GRAY)
    bg = _RISK_BG.get(level, '#ffffff08')
    return (
        f'<span style="background:{bg};color:{c};font-size:10px;font-weight:700;'
        f'letter-spacing:1.5px;padding:3px 9px;border-radius:4px;'
        f'border:1px solid {c}44;font-family:monospace">{level}</span>'
    )


def _tool_tag(tool: str) -> str:
    abbr, color, label = _TOOL_META.get(tool, (tool[:3].upper(), _MUTED, tool))
    return (
        f'<span style="background:{color}18;color:{color};font-size:10px;font-weight:700;'
        f'padding:2px 7px;border-radius:4px;border:1px solid {color}44;'
        f'margin-right:5px;font-family:monospace" title="{label}">{abbr}</span>'
    )


def _trace_step(step: dict, is_last: bool) -> str:
    stype  = step.get('step_type', '')
    color, label, icon = _STEP_CFG.get(stype, (_GRAY, stype, '●'))

    if stype == 'tool_call' and step.get('tool_name'):
        tname = step['tool_name']
        abbr, color, label = _TOOL_META.get(tname, (tname[:3].upper(), _PURPLE, tname.replace('_', ' ').title()))

    gs = step.get('guardrail_status') or ''
    badge = ''
    if gs in _GUARD_BADGE:
        bc, bt = _GUARD_BADGE[gs]
        badge = (
            f'<span style="background:{bc}18;color:{bc};font-size:9px;font-weight:700;'
            f'padding:1px 6px;border-radius:3px;border:1px solid {bc}33;'
            f'margin-left:8px;letter-spacing:1px">{bt}</span>'
        )

    dur = step.get('duration_ms')
    dur_html = f'<span style="color:{_MUTED};font-size:11px;margin-left:8px;font-family:monospace">{dur}ms</span>' if dur is not None else ''

    summary = (step.get('result_summary') or '').strip()
    summary_html = (
        f'<div style="color:{_MUTED};font-size:12px;margin-top:5px;line-height:1.5;'
        f'max-height:72px;overflow:hidden;font-family:monospace">{summary[:300]}</div>'
    ) if summary else ''

    connector = (
        f'<div style="width:1px;height:16px;margin-left:15px;'
        f'background:linear-gradient({color}66,{_BORDER}00)"></div>'
    ) if not is_last else ''

    return f"""
    <div style="display:flex;gap:12px;align-items:flex-start">
        <div style="width:32px;height:32px;border-radius:8px;flex-shrink:0;
            background:{color}14;border:1px solid {color}44;
            display:flex;align-items:center;justify-content:center;
            font-size:13px;color:{color};font-weight:700">{icon}</div>
        <div style="flex:1;padding-top:6px;min-width:0">
            <div style="color:{_TEXT};font-weight:600;font-size:13px">
                {label}{badge}{dur_html}
            </div>
            {summary_html}
        </div>
    </div>{connector}"""


def _render_trace(steps: list[dict]) -> None:
    if not steps:
        st.markdown(f'<span style="color:{_MUTED};font-size:12px">No investigation trace recorded.</span>', unsafe_allow_html=True)
        return

    inner = ''.join(_trace_step(s, i == len(steps) - 1) for i, s in enumerate(steps))
    st.markdown(f"""
    <div style="background:#080A12;border:1px solid {_BORDER};border-radius:10px;padding:16px 18px 10px">
        <div style="font-size:9px;color:{_MUTED};letter-spacing:2.5px;
            text-transform:uppercase;margin-bottom:14px;font-weight:600">
            ◈ INVESTIGATION TRACE — {len(steps)} STEPS
        </div>
        {inner}
    </div>""", unsafe_allow_html=True)


def _render_alerts(alerts: list[dict], traces: dict, risk_filter: str | None) -> None:
    filtered = [a for a in alerts if not risk_filter or a.get('risk_level') == risk_filter]

    hdr_right = f'<span style="color:{_MUTED};font-size:12px">{len(filtered)} of {len(alerts)} shown</span>'
    st.markdown(f"""
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
        <div style="font-size:14px;font-weight:700;color:#fff;letter-spacing:0.5px">
            ⚡ SECURITY ALERTS
        </div>
        {hdr_right}
    </div>""", unsafe_allow_html=True)

    if not filtered:
        st.markdown(f'<div style="color:{_MUTED};padding:24px;text-align:center">No alerts match the current filter.</div>', unsafe_allow_html=True)
        return

    for alert in filtered:
        level   = alert.get('risk_level', 'UNKNOWN')
        color   = _RISK_COLOR.get(level, _GRAY)
        ts      = str(alert.get('created_at', ''))[:19].replace('T', ' ')
        machine = str(alert.get('machine_ip', '—'))
        tools   = alert.get('tools_called') or []
        fw      = alert.get('firewall_rule')

        tool_tags = ''.join(_tool_tag(t) for t in tools) if tools else ''
        fw_tag = (
            f'<span style="background:{_GREEN}18;color:{_GREEN};font-size:10px;font-weight:700;'
            f'padding:2px 7px;border-radius:4px;border:1px solid {_GREEN}44;margin-left:8px">⚙ RULE</span>'
        ) if fw else ''
        esc_tag = (
            f'<span style="background:{_ORANGE}18;color:{_ORANGE};font-size:10px;font-weight:700;'
            f'padding:2px 7px;border-radius:4px;border:1px solid {_ORANGE}44;margin-left:8px">👤 ESCALATED</span>'
        ) if alert.get('escalated_to_human') else ''

        label = (
            f'{_risk_badge(level)}'
            f'<span style="font-family:monospace;font-size:13px;color:#fff;margin:0 12px">{machine}</span>'
            f'<span style="font-family:monospace;font-size:11px;color:{_MUTED}">{ts}</span>'
            f'{fw_tag}{esc_tag}'
        )

        with st.expander(f'[{level}]  {machine}  ·  {ts}', expanded=False):
            # Inject colored left border via sibling hack (best we can do in Streamlit)
            st.markdown(f"""
            <div style="border-left:3px solid {color};padding-left:14px;margin-bottom:16px">
                <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px">
                    {_risk_badge(level)}
                    <span style="font-family:monospace;font-size:14px;color:#fff;font-weight:600">{machine}</span>
                    <span style="font-family:monospace;font-size:11px;color:{_MUTED}">{ts}</span>
                    {fw_tag}{esc_tag}
                </div>
            """, unsafe_allow_html=True)

            # Score row
            cs = alert.get('classifier_score')
            ds = alert.get('deviation_score')
            mc = alert.get('machine_confidence')
            st.markdown(f"""
            <div style="display:flex;gap:0;background:#080A12;border:1px solid {_BORDER};
                border-radius:8px;overflow:hidden;margin-bottom:16px">
                <div style="flex:1;padding:12px 16px;border-right:1px solid {_BORDER}">
                    <div style="font-size:9px;color:{_MUTED};letter-spacing:2px;margin-bottom:4px">CLASSIFIER</div>
                    <div style="font-size:22px;font-weight:800;color:{_CYAN};font-family:monospace">
                        {f'{cs:.3f}' if cs is not None else '—'}
                    </div>
                </div>
                <div style="flex:1;padding:12px 16px;border-right:1px solid {_BORDER}">
                    <div style="font-size:9px;color:{_MUTED};letter-spacing:2px;margin-bottom:4px">DEVIATION</div>
                    <div style="font-size:22px;font-weight:800;color:{_PURPLE};font-family:monospace">
                        {f'{ds:.3f}' if ds is not None else '—'}
                    </div>
                </div>
                <div style="flex:1;padding:12px 16px">
                    <div style="font-size:9px;color:{_MUTED};letter-spacing:2px;margin-bottom:4px">CONFIDENCE</div>
                    <div style="font-size:22px;font-weight:800;color:{_BLUE};font-family:monospace">
                        {f'{mc:.3f}' if mc is not None else '—'}
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            col_l, col_r = st.columns([3, 2])
            with col_l:
                st.markdown(f'<div style="font-size:10px;color:{_MUTED};letter-spacing:2px;margin-bottom:6px">SUMMARY</div>', unsafe_allow_html=True)
                summary = alert.get('summary') or '—'
                st.markdown(f'<div style="color:{_TEXT};font-size:13px;line-height:1.6">{summary}</div>', unsafe_allow_html=True)

                action = alert.get('recommended_action') or '—'
                st.markdown(f"""
                <div style="margin-top:12px">
                    <div style="font-size:10px;color:{_MUTED};letter-spacing:2px;margin-bottom:6px">RECOMMENDED ACTION</div>
                    <div style="color:{_TEXT};font-size:13px;line-height:1.6">{action}</div>
                </div>""", unsafe_allow_html=True)

                if tool_tags:
                    st.markdown(f"""
                    <div style="margin-top:12px">
                        <div style="font-size:10px;color:{_MUTED};letter-spacing:2px;margin-bottom:6px">TOOLS USED</div>
                        {tool_tags}
                    </div>""", unsafe_allow_html=True)

            with col_r:
                if fw:
                    st.markdown(f'<div style="font-size:10px;color:{_MUTED};letter-spacing:2px;margin-bottom:6px">FIREWALL RULE</div>', unsafe_allow_html=True)
                    st.code(fw, language='bash')

                if alert.get('limit_hit'):
                    st.markdown(f'<div style="color:{_ORANGE};font-size:12px;margin-top:8px">⚠ LLM budget reached — investigation may be partial</div>', unsafe_allow_html=True)

            st.markdown('</div>', unsafe_allow_html=True)
            st.markdown(f'<div style="border-top:1px solid {_BORDER};margin:14px 0 12px"></div>', unsafe_allow_html=True)

            alert_id = str(alert.get('id', ''))
            _render_trace(traces.get(alert_id, []))


def _render_profiles(profiles: list[dict]) -> None:
    st.markdown(f"""
    <div style="font-size:14px;font-weight:700;color:#fff;letter-spacing:0.5px;margin-bottom:14px">
        ◈ MACHINE PROFILES
    </div>""", unsafe_allow_html=True)

    if not profiles:
        st.markdown(f'<div style="color:{_MUTED};padding:24px;text-align:center">No profiles yet.</div>', unsafe_allow_html=True)
        return

    rows = [{
        'IP':         str(p.get('machine_ip', '—')),
        'Flows':      p.get('flow_count', 0),
        'First Seen': str(p.get('first_seen', '—'))[:19],
        'Last Seen':  str(p.get('last_seen',  '—'))[:19],
        'Ports':      ', '.join(str(x) for x in (p.get('known_ports') or [])),
        'Protocols':  ', '.join(str(x) for x in (p.get('known_protocols') or [])),
    } for p in profiles]
    st.dataframe(rows, use_container_width=True, hide_index=True)


def main() -> None:
    st.set_page_config(
        page_title = 'NetMind SOC',
        page_icon  = '🛡️',
        layout     = 'wide',
    )
    _css()

    load_secrets()

    try:
        stats     = _load_stats()
        alerts    = _load_alerts()
        alert_ids = tuple(str(a['id']) for a in alerts if a.get('id'))
        traces    = _load_traces(alert_ids)
        profiles  = _load_profiles()
    except Exception as exc:
        st.error(f'Database error: {exc}')
        time.sleep(_REFRESH)
        st.rerun()
        return

    risk_filter = _sidebar(stats, alerts)

    # ── Header bar ──────────────────────────────────────────────────────────────
    st.markdown(f"""
    <div style="display:flex;align-items:center;justify-content:space-between;
        padding:8px 0 28px;border-bottom:1px solid {_BORDER};margin-bottom:24px">
        <div style="display:flex;align-items:center;gap:14px">
            {_LOGO_SVG}
            <div>
                <div style="font-size:28px;font-weight:900;color:#fff;line-height:1;letter-spacing:-0.5px">
                    Net<span style="background:linear-gradient(90deg,{_CYAN},{_BLUE},{_PURPLE});
                        -webkit-background-clip:text;-webkit-text-fill-color:transparent">Mind</span>
                </div>
                <div style="font-size:10px;color:{_MUTED};letter-spacing:3px;margin-top:3px">
                    AI POWERED SOC AGENT
                </div>
            </div>
        </div>
        <div style="text-align:right">
            <div style="display:flex;align-items:center;gap:8px;justify-content:flex-end;margin-bottom:4px">
                <div style="width:7px;height:7px;border-radius:50%;background:{_GREEN};
                    box-shadow:0 0 8px {_GREEN};animation:pulse 2s infinite"></div>
                <span style="color:{_GREEN};font-size:11px;font-weight:700;letter-spacing:1.5px">LIVE</span>
            </div>
            <div style="font-family:monospace;font-size:11px;color:{_MUTED}">
                Auto-refresh every {_REFRESH}s
            </div>
        </div>
    </div>
    <style>
    @keyframes pulse {{
        0%,100% {{ opacity:1; box-shadow:0 0 8px #10B981; }}
        50%      {{ opacity:0.6; box-shadow:0 0 16px #10B981; }}
    }}
    </style>
    """, unsafe_allow_html=True)

    # ── KPI strip ───────────────────────────────────────────────────────────────
    _kpi_row(stats)
    st.markdown('<div style="margin:24px 0"></div>', unsafe_allow_html=True)

    # ── Main content ────────────────────────────────────────────────────────────
    _render_alerts(alerts, traces, risk_filter)

    st.markdown(f'<hr style="margin:28px 0">', unsafe_allow_html=True)
    _render_profiles(profiles)

    time.sleep(_REFRESH)
    st.rerun()


if __name__ == '__main__':
    main()
