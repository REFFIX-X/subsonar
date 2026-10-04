"""Streamlit web dashboard — Monokai Pro Dark.

Run with::

    streamlit run subsonar/ui/dashboard.py

or through the CLI::

    python main.py --web --domain example.com
"""

from __future__ import annotations

import html
import os
from collections import deque
from typing import Any, Sequence

import streamlit as st

from subsonar.core.config import DNS_RESOLVER_POOL, PORT_MATRIX, PORT_MATRIX_EXTENDED, ScanConfig
from subsonar.core.engine import Finding, ScanResult
from subsonar.core.events import BUS
from subsonar.core.ports import describe_matrix
from subsonar.core.profiles import PROFILES, get_profile
from subsonar.core.theme import Palette, logo_block
from subsonar.reporters import write_reports
from subsonar.runner import ScanRunner
from subsonar.ui.render import STAT_COLORS, progress_bar

st.set_page_config(
    page_title="subsonar",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)

CSS = f"""
<style>
  .stApp {{ background: {Palette.BACKGROUND}; color: {Palette.TEXT}; }}
  /* 4K / ultrawide: Streamlit caps the content column at ~730px by default,
     which wastes 80% of a 3840px screen.  Use the whole canvas and scale the
     type up on very large displays. */
  .block-container, div[data-testid="stAppViewBlockContainer"] {{
      max-width: 100% !important; padding: 1.0rem 1.6rem 2rem 1.6rem !important;
  }}
  section[data-testid="stSidebar"] {{
      background: {Palette.SURFACE}; border-right: 1px solid {Palette.SURFACE_ALT};
      min-width: 340px !important; max-width: 380px !important;
  }}
  h1, h2, h3 {{ color: {Palette.PINK} !important; font-family: "JetBrains Mono", monospace; }}
  .logo {{ color: {Palette.PINK}; font-family: "JetBrains Mono", Consolas, monospace;
           font-size: 11px; line-height: 1.05; white-space: pre; }}
  .tag {{ color: {Palette.MUTED}; font-family: monospace; margin-bottom: 8px; }}
  /* --- KPI grid: fills the whole width, wraps by itself ------------------ */
  .kpi-grid {{ display: grid; gap: 10px;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      margin-bottom: 10px; }}
  .stat-card {{ background: {Palette.SURFACE}; border: 1px solid {Palette.SURFACE_ALT};
                border-radius: 8px; padding: 10px 14px; }}
  .stat-label {{ color: {Palette.MUTED}; font-size: 11px; text-transform: uppercase;
                 letter-spacing: 1px; font-family: monospace; }}
  .stat-value {{ font-size: 24px; font-family: monospace; font-weight: 700;
                 line-height: 1.15; }}
  .stat-sub {{ color: {Palette.MUTED}; font-size: 11px; font-family: monospace; }}
  /* --- live log: tall, dense, newest line always visible ----------------- */
  .log {{ background: {Palette.SURFACE}; border: 1px solid {Palette.SURFACE_ALT};
          border-radius: 8px; padding: 10px; height: 68vh; min-height: 520px;
          overflow-y: auto; overscroll-behavior: contain;
          scrollbar-width: thin; scrollbar-color: {Palette.PINK} {Palette.SURFACE};
          font-family: "JetBrains Mono", Consolas, monospace;
          font-size: 12.5px; line-height: 1.45; }}
  .log div {{ white-space: pre-wrap; word-break: break-word; }}
  .log div:hover {{ background: rgba(255, 255, 255, .04); }}
  .log::-webkit-scrollbar {{ width: 11px; }}
  .log::-webkit-scrollbar-track {{ background: {Palette.SURFACE}; }}
  .log::-webkit-scrollbar-thumb {{ background: {Palette.SURFACE_ALT};
      border: 2px solid {Palette.SURFACE}; border-radius: 6px; }}
  .log::-webkit-scrollbar-thumb:hover {{ background: {Palette.PINK}; }}
  .log.compact {{ font-size: 11.5px; line-height: 1.3; }}
  .ts {{ color: {Palette.MUTED}; }}
  .tag-cat {{ font-weight: 700; }}
  a.url {{ color: {Palette.YELLOW} !important; text-decoration: none;
           font-family: monospace; }}
  a.url:hover {{ color: {Palette.PINK} !important; text-decoration: underline; }}
  .probe {{ color: {Palette.GREEN}; }}
  .stProgress > div > div > div > div {{ background: {Palette.PINK}; }}
  .stButton > button {{ background: {Palette.SURFACE_ALT}; color: {Palette.TEXT};
                        border: 1px solid {Palette.PINK}; font-family: monospace; }}
  .stButton > button:hover {{ background: {Palette.PINK}; color: {Palette.BACKGROUND}; }}
  div[data-testid="stMetricValue"] {{ color: {Palette.ORANGE}; font-family: monospace; }}
  /* --- findings table (HTML, full width, hover tooltips on the flags) ---- */
  table.findings {{ border-collapse: collapse; width: 100%;
      font-family: "JetBrains Mono", Consolas, monospace; font-size: 13px; }}
  table.findings th {{ position: sticky; top: 0; z-index: 2;
      background: {Palette.SURFACE}; color: {Palette.YELLOW}; text-align: left;
      padding: 8px 10px; border-bottom: 1px solid {Palette.SURFACE_ALT};
      cursor: pointer; white-space: nowrap; }}
  table.findings td {{ padding: 6px 10px; border-bottom: 1px solid rgba(64,62,65,.45);
      vertical-align: top; }}
  table.findings tbody tr:nth-child(even) td {{ background: rgba(44,42,45,.45); }}
  table.findings tbody tr:hover td {{ background: {Palette.SURFACE}; }}
  table.findings td.host {{ color: {Palette.CYAN}; white-space: nowrap; }}
  table.findings td.ip {{ color: {Palette.GREEN}; white-space: nowrap; }}
  table.findings td.num {{ color: {Palette.ORANGE}; text-align: right; }}
  table.findings td.muted {{ color: {Palette.MUTED}; }}
  table.findings .wrap {{ max-width: 46vw; overflow-wrap: anywhere; }}
  img.flag {{ height: 14px; width: auto; vertical-align: -2px; border-radius: 2px;
              border: 1px solid {Palette.SURFACE_ALT}; cursor: help; }}
  .cc {{ color: {Palette.MUTED}; font-size: 11px; margin-left: 3px; }}
  .prev {{ color: {Palette.MUTED}; font-size: 10px; border: 1px solid {Palette.MUTED};
           border-radius: 3px; padding: 0 4px; margin-left: 6px; }}
  .intel-card {{ background: {Palette.SURFACE}; border: 1px solid {Palette.SURFACE_ALT};
      border-radius: 8px; padding: 12px 16px; font-family: monospace; }}
  /* --- very large displays (4K / ultrawide) ------------------------------ */
  @media (min-width: 2400px) {{
      .stat-value {{ font-size: 30px; }}
      .stat-label {{ font-size: 12px; }}
      .log {{ font-size: 14px; height: 72vh; }}
      table.findings {{ font-size: 14.5px; }}
      .kpi-grid {{ grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); }}
  }}
  @media (min-width: 3200px) {{
      .log {{ font-size: 15.5px; }}
      table.findings {{ font-size: 16px; }}
      .stat-value {{ font-size: 34px; }}
  }}
</style>
"""


def _initial_domain() -> str:
    """Target pre-filled by ``python main.py web <domain>``, if one was given."""
    raw = (os.environ.get("SUBSONAR_WEB_DOMAIN") or "").strip()
    if not raw:
        return ""
    try:  # normalise (strip scheme/path/port) exactly like the CLI does
        return ScanConfig(domain=raw).domain
    except ValueError:
        return raw


#: How many events the dashboard keeps in its own log buffer.  Streamlit's
#: ``EventBus.history`` also keeps 20 000, so the buffer is only the *rendered*
#: subset — it exists so the panel can grow while you read it.
LOG_BUFFER_MAX = 6000
#: Lines rendered into the DOM per refresh; the rest stay downloadable.
LOG_RENDER_MAX = 1500
#: Events inspected per refresh when syncing the buffer.
LOG_SYNC_WINDOW = 4000
#: Live refresh cadence of the log/stats fragment, in seconds.
LOG_REFRESH_SECONDS = 1.0


def _init_state() -> None:
    defaults: dict[str, Any] = {
        "runner": None,
        "domain": _initial_domain(),
        "profile_id": 3,
        "scan_running": False,
        "exported": {},
        # -- live log panel -------------------------------------------------
        # A growing buffer instead of ``BUS.drain()``: drain *removes* the events
        # it returns, so the panel used to show only the few lines emitted since
        # the previous rerun and appeared to clear itself every second.
        "log_buffer": deque(maxlen=LOG_BUFFER_MAX),
        "log_seq": 0,
        "log_appended": 0,
        "log_dropped": 0,
        "log_paused": False,
        "log_newest_first": True,
        # -- scan lifecycle -------------------------------------------------
        #: The engine thread finished and the transition has been handled (this is
        #: what keeps the completion rerun from looping).
        "finished_announced": False,
        #: ``("success" | "error" | "info", message)`` for the outcome banner.
        "scan_banner": None,
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def append_new_events(
    buffer: deque,
    last_seq: int,
    events: Sequence[Any],
    *,
    maxlen: int = LOG_BUFFER_MAX,
) -> tuple[int, int, int]:
    """Append the events newer than ``last_seq``; return ``(appended, dropped, last_seq)``.

    Pure (no Streamlit, no bus) so the "the log only ever grows" contract can be
    tested directly: consecutive calls with overlapping windows must neither
    duplicate nor lose a line, and a window that starts *after* ``last_seq`` must
    account for the gap as dropped.
    """
    if not events:
        return 0, 0, last_seq
    first_seq = int(events[0].seq)
    dropped = 0
    if last_seq and first_seq > last_seq + 1:
        dropped += first_seq - last_seq - 1
    new = [event for event in events if int(event.seq) > last_seq]
    if not new:
        return 0, dropped, last_seq
    before = len(buffer)
    for event in new:
        buffer.append(event)
    appended = len(buffer) - before
    dropped += len(new) - appended
    return appended, dropped, int(new[-1].seq)


def _sync_log_buffer() -> int:
    """Append every new bus event to the session buffer exactly once.

    Returns the number of events appended.  Uses the monotonic event ``seq`` so
    a rerun that happens to span more events than the sync window cannot lose
    (or duplicate) a line: the gap is added to ``log_dropped`` and reported.
    """
    state = st.session_state
    events = BUS.history(limit=LOG_SYNC_WINDOW)
    if not events:
        return 0
    appended, dropped, last_seq = append_new_events(
        state.log_buffer, int(state.log_seq or 0), events
    )
    if dropped:
        state.log_dropped = int(state.log_dropped) + dropped
    if appended:
        state.log_appended = int(state.log_appended) + appended
    state.log_seq = last_seq
    return appended


def _is_log_noise(event: Any) -> bool:
    """Debug/filter chatter hidden by the sidebar *Quiet log* switch."""
    return event.severity in {"debug", "trace"} or event.category == "filter"


def _log_line(event: Any) -> str:
    """One rendered log line (HTML)."""
    colour = _severity_color(event.severity, event.category)
    target = ""
    if event.host:
        target = f" <b style='color:{Palette.CYAN}'>{_escape(event.host)}"
        if event.port:
            target += f"<span style='color:{Palette.ORANGE}'>:{event.port}</span>"
        target += "</b>"
    return (
        f"<div><span class='ts'>{event.clock}</span> "
        f"<span class='tag-cat' style='color:{colour}'>"
        f"[{event.category or event.severity}]</span>{target} "
        f"<span style='color:{colour}'>{_escape(event.message)}</span></div>"
    )


def _render_log(*, compact: bool = False, frozen: bool = False) -> None:
    """Render the buffered log — newest first, scrollable, never reset.

    ``frozen=True`` renders whatever is already buffered without pulling in new
    events, which is what the *Pause* switch uses so the panel stops moving while
    the user scrolls back through it.
    """
    state = st.session_state
    if not frozen:
        _sync_log_buffer()
    quiet = bool(state.get("quiet", False))
    events = [
        event for event in state.log_buffer if not (quiet and _is_log_noise(event))
    ]
    total = len(events)
    if state.log_newest_first:
        events = list(reversed(events))
    shown = events[:LOG_RENDER_MAX]
    if not shown:
        body = f"<div style='color:{Palette.MUTED}'>waiting for scan activity…</div>"
    else:
        body = "".join(_log_line(event) for event in shown)
    dropped = int(state.log_dropped)
    note = (
        f"{total:,} line(s) buffered · showing {len(shown):,}"
        + (" · newest first — scroll down for history" if state.log_newest_first else "")
        + (f" · {len(events) - len(shown):,} older line(s) hidden" if len(events) > len(shown) else "")
        + (f" · {dropped:,} dropped (bus evicted)" if dropped else "")
        + (" · ⏸ paused" if state.log_paused else "")
    )
    st.caption(note)
    st.markdown(
        f"<div class='log{' compact' if compact else ''}'>{body}</div>",
        unsafe_allow_html=True,
    )


def _severity_color(severity: str, category: str) -> str:
    return Palette.for_event(severity, category)


def _stat_cards(snapshot: dict[str, Any]) -> None:
    """One responsive KPI strip that uses the full width of the display."""
    cards = [
        ("candidates", "Candidates", ""),
        ("dns_resolved", "Resolved", ""),
        ("dns_queries", "DNS Queries", ""),
        ("dns_failed", "DNS Failures", ""),
        ("dns_cache_hits", "Cache Hits", ""),
        ("ports_open", "Open Ports", ""),
        ("http_probes", "HTTP Probes", ""),
        ("findings", "Web Found", ""),
        ("filtered_no_web", "Filtered", ""),
        ("provider_skipped", "3rd-party Skip", ""),
        ("carried_over", "Carried Over", ""),
        ("osint_unique", "OSINT Hosts", ""),
        ("brute_unique", "Brute Hosts", ""),
        ("active_tasks", "In Flight", ""),
    ]
    cards_html: list[str] = []
    for key, label, sub in cards:
        value = snapshot.get(key, 0)
        colour = STAT_COLORS.get(key, Palette.MUTED)
        if isinstance(value, (int, float)):
            shown = f"{value:,.0f}" if isinstance(value, float) else f"{value:,}"
        else:
            shown = str(value)
        sub_html = f"<div class='stat-sub'>{sub}</div>" if sub else ""
        cards_html.append(
            f"<div class='stat-card'><div class='stat-label'>{label}</div>"
            f"<div class='stat-value' style='color:{colour}'>{shown}</div>{sub_html}</div>"
        )
    st.markdown(f"<div class='kpi-grid'>{''.join(cards_html)}</div>", unsafe_allow_html=True)


def _escape(text: str) -> str:
    # ``quote=True`` matters: the result is interpolated into single-quoted
    # attributes (``title='…'``, ``href='…'``), so a value containing a quote
    # would otherwise break out of the attribute.
    return html.escape(str(text), quote=True)


def _findings_rows(findings: list[Finding]) -> list[dict[str, Any]]:
    return [
        {
            "#": index,
            "Subdomain": finding.subdomain,
            "Resolved IP": finding.ip,
            "Geo": finding.geo_label,
            "Country": finding.country or "",
            "AS": finding.asn or "",
            "AS org": finding.as_org or "",
            "PTR": finding.ptr or "",
            "Port": finding.port,
            "Status": finding.status,
            "Title": finding.title or "",
            "URL": finding.link,
            "Server": finding.server or "",
            "TLS": finding.tls_version or ("cleartext" if not finding.tls else "yes"),
            "Provider": finding.provider or "",
            "Conf": f"{finding.confidence} {finding.confidence_label}",
            "Seen": "previous scan" if finding.from_previous_scan else "this scan",
        }
        for index, finding in enumerate(findings, start=1)
    ]


def _matches(finding: Finding, needle: str) -> bool:
    """Free-text match over every column the user can see."""
    haystack = [
        finding.subdomain.lower(),
        finding.url.lower(),
        (finding.title or "").lower(),
        finding.ip,
        (finding.country_code or "").lower(),
        (finding.country or "").lower(),
        (finding.as_org or "").lower(),
        (finding.ptr or "").lower(),
        (finding.provider or "").lower(),
        str(finding.port),
        f"as{finding.asn}" if finding.asn else "",
    ]
    return any(needle in value for value in haystack if value)


def _sort_findings(findings: list[Finding], key: str) -> list[Finding]:
    """Sort findings by one of the columns offered in the UI."""
    if key == "ip":
        return sorted(findings, key=lambda item: (item.ip, item.subdomain, item.port))
    if key == "port":
        return sorted(findings, key=lambda item: (item.port, item.subdomain))
    if key == "status":
        return sorted(findings, key=lambda item: (item.status or 0, item.subdomain))
    if key == "country":
        return sorted(
            findings,
            key=lambda item: (item.country_code or "zz", item.subdomain, item.port),
        )
    if key == "subdomain":
        return sorted(findings, key=lambda item: (item.subdomain, item.port))
    return sorted(findings, key=lambda item: (-item.confidence, item.subdomain, item.port))


def _flag_cell(finding: Finding) -> str:
    """Flag image (hover = country + AS org) or the emoji fallback."""
    from subsonar.core import geoip

    code = finding.country_code
    if not code:
        return "<span class='muted'>—</span>"
    tip = " · ".join(
        part
        for part in (
            finding.country or geoip.country_name(code) or code,
            finding.as_org or "",
            f"AS{finding.asn}" if finding.asn else "",
            finding.ptr or "",
        )
        if part
    )
    url = geoip.flag_image_url(code)
    fallback = geoip.flag_emoji(code) or code
    if not url:
        return f"<span title='{_escape(tip)}'>{fallback}</span>"
    return (
        f"<img class='flag' src='{url}' alt='{_escape(code)}' "
        f"title='{_escape(tip)}'><span class='cc'>{_escape(code)}</span>"
    )


def _findings_html(findings: list[Finding]) -> str:
    """Dense, full-width HTML table with clickable URLs and flag tooltips."""
    head = (
        "<th>#</th><th>Subdomain</th><th>Resolved IP</th><th>Geo</th>"
        "<th>AS organisation</th><th>PTR</th><th>Port</th><th>Code</th>"
        "<th>Conf</th><th>Kind</th><th>Provider</th><th>Title</th><th>URL</th>"
    )
    rows: list[str] = []
    for index, finding in enumerate(findings, start=1):
        port_text = str(finding.port)
        if finding.aliases:
            port_text += f" +{len(finding.aliases)}"
        title = _escape(finding.title or "")
        if finding.from_previous_scan:
            title += "<span class='prev'>prev</span>"
        rows.append(
            "<tr>"
            f"<td class='num'>{index}</td>"
            f"<td class='host'>{_escape(finding.subdomain)}</td>"
            f"<td class='ip'>{_escape(finding.ip)}</td>"
            f"<td>{_flag_cell(finding)}</td>"
            f"<td class='muted'>{_escape(finding.as_org or '')}</td>"
            f"<td class='muted wrap'>{_escape(finding.ptr or '')}</td>"
            f"<td class='num'>{port_text}</td>"
            f"<td class='num'>{finding.status if finding.status is not None else '-'}</td>"
            f"<td class='num'>{finding.confidence} {_escape(finding.confidence_label)}</td>"
            f"<td class='muted'>{_escape(finding.kind)}</td>"
            f"<td class='muted'>{_escape(finding.provider or '')}</td>"
            f"<td class='wrap'>{title}</td>"
            f"<td><a class='url' href='{_escape(finding.link)}' target='_blank' "
            f"rel='noopener'>{_escape(finding.url)}</a></td>"
            "</tr>"
        )
    return (
        "<div style='overflow:auto;max-height:78vh'>"
        f"<table class='findings'><thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _sidebar() -> tuple[str, int, bool, bool]:
    with st.sidebar:
        st.markdown(
            f"<div class='logo'>{_escape(logo_block(compact=True))}</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"<div class='tag'>asynchronous subdomain &amp; web-interface sonar<br>"
            f"anonymous resolver pool · no Google · no Cloudflare<br>"
            f"Top-{len(PORT_MATRIX)} core / {len(PORT_MATRIX_EXTENDED)} extended port "
            f"matrix (--port-matrix extended)</div>",
            unsafe_allow_html=True,
        )
        domain = st.text_input("Target domain", value=st.session_state.domain or "", placeholder="example.com")
        profile_names = [f"{p.id}. {p.name}" for p in PROFILES]
        choice = st.selectbox(
            "Scan profile",
            profile_names,
            index=max(0, min(len(PROFILES) - 1, st.session_state.profile_id - 1)),
        )
        profile_id = int(choice.split(".")[0])
        profile = get_profile(profile_id)
        st.caption(profile.description)
        st.markdown(
            f"<div class='stat-label'>packets</div>"
            f"<div style='color:{Palette.CYAN}'>{profile.packet_profile}</div>",
            unsafe_allow_html=True,
        )
        offline = st.toggle("Offline (cache only)", value=False)
        quiet = st.toggle("Quiet log (hide debug/filter)", value=False)
        st.divider()
        st.markdown(
            f"<div class='stat-label'>scope &amp; osint (free, no api key)</div>",
            unsafe_allow_html=True,
        )
        from subsonar.core.ports import parse_port_spec
        from subsonar.core.wordlists import WORDLISTS

        registry = list(WORDLISTS)
        # Same names the CLI offers, so both front-ends accept the same input.
        matrix_names = ["core", "extended", "web", "audit"]
        chosen_list = st.selectbox(
            "Wordlist",
            [item.name for item in registry],
            index=max(
                0,
                next(
                    (
                        i
                        for i, item in enumerate(registry)
                        if item.name == st.session_state.get("wordlist")
                    ),
                    0,
                ),
            ),
            help="The profile still sizes the slice taken from the list.",
        )
        matrix = st.selectbox(
            "Port matrix",
            matrix_names,
            index=(
                matrix_names.index(st.session_state.get("port_matrix"))
                if st.session_state.get("port_matrix") in matrix_names
                else 0
            ),
            help="core = Top-50, extended = ~170 web/admin/dev ports, web, audit.",
        )
        carry_over = st.toggle(
            "Merge previous results",
            value=bool(st.session_state.get("carry_over", True)),
            help=(
                "Merge the newest report of this domain into the run, so switching "
                "profile never clears what was already found."
            ),
        )
        geoip = st.toggle(
            "Offline geo (flag + ASN)",
            value=bool(st.session_state.get("geoip", True)),
            help=(
                "Country flag, country name and AS organisation per resolved IP, "
                "from local BGP/RIR data — the address never leaves this machine."
            ),
        )
        rate = st.number_input(
            "DNS rate limit (q/s, 0 = profile default)",
            min_value=0.0,
            max_value=5000.0,
            value=float(st.session_state.get("dns_rate") or 0.0),
            step=5.0,
            help=(
                "Token bucket over the whole resolver pool.  0 keeps the profile's "
                f"sane default ({get_profile(profile_id).rate_summary()})."
            ),
        )
        port_rate = st.number_input(
            "Port rate limit (connects/s, 0 = profile default)",
            min_value=0.0,
            max_value=20000.0,
            value=float(st.session_state.get("port_rate") or 0.0),
            step=25.0,
            help=(
                "TCP connects/second for the port sweep, plus a per-host cap.  "
                "0 keeps the profile default; lower it if the target's firewall "
                "or IPS starts dropping you."
            ),
        )
        st.caption(
            "DNS intel (MX/SPF/DMARC/CAA/DNSSEC), PTR lookups and robots/sitemap "
            "mining run with every non-passive profile."
        )
        st.session_state.wordlist = chosen_list
        st.session_state.port_matrix = matrix
        st.session_state.carry_over = carry_over
        st.session_state.geoip = geoip
        st.session_state.dns_rate = rate
        st.session_state.port_rate = port_rate
        st.divider()
        col_a, col_b = st.columns(2)
        start = col_a.button("▶ Start", type="primary", use_container_width=True)
        stop = col_b.button("■ Stop", use_container_width=True)
        st.divider()
        st.markdown(
            f"<div class='stat-label'>resolver rotation</div>", unsafe_allow_html=True
        )
        # The effective pool is the module constant — never rebuilt per render.
        # Building ``ScanConfig(domain=...)`` here used to crash the whole page
        # with ``ValueError`` as soon as the target box held a partial domain.
        st.code("\n".join(DNS_RESOLVER_POOL), language="text")
        st.session_state.quiet = quiet
        if stop:
            runner = st.session_state.runner
            if runner is not None:
                runner.stop()
                st.session_state.scan_running = False
        if start:
            _begin_scan(domain, profile_id, offline)
    return domain, profile_id, offline, quiet


def _settle_scan_state() -> str:
    """Advance the dashboard's scan state machine; returns the resulting state.

    ``"running"``  — the engine thread is alive.
    ``"finished"`` — it has *just* finished; the caller must force one app-wide
                     rerun so the findings/export tabs and the banner pick up the
                     final result (the live panel is a fragment, so nothing else
                     re-runs the page when a scan ends).
    ``"idle"``     — nothing to do.

    The transition happens exactly once (``finished_announced``), which is what
    keeps the app-wide rerun from looping.
    """
    state = st.session_state
    runner: ScanRunner | None = state.get("runner")
    if runner is None:
        return "idle"
    if runner.running:
        state.scan_running = True
        state.finished_announced = False
        return "running"
    if not runner.finished or state.get("finished_announced"):
        return "idle"
    state.finished_announced = True
    state.scan_running = False
    if state.get("log_paused"):
        state.log_paused = False
    if runner.error is not None:
        state.scan_banner = ("error", f"scan aborted: {runner.error}")
    else:
        result = runner.live_result
        if result is not None:
            state.scan_banner = (
                "success",
                f"scan finished — {len(result.findings)} web interface(s) "
                f"confirmed in {result.duration:.1f}s",
            )
        else:
            state.scan_banner = ("info", "scan finished without a result")
    return "finished"


def _render_scan_banner() -> None:
    """Show (and keep showing) the outcome of the last scan.

    Deliberately plain ``if/elif/else``: Streamlit inspects the *source* of the
    calling frame when it validates fragment/rerun rules, and a statement-level
    conditional expression spanning several lines makes it extract a source
    snippet that cannot be compiled ("'(' was never closed" at app start-up).
    """
    banner = st.session_state.get("scan_banner")
    if not banner:
        return
    kind, message = banner
    if kind == "error":
        st.error(message)
    elif kind == "success":
        st.success(message)
    else:
        st.info(message)


def _begin_scan(domain: str, profile_id: int, offline: bool) -> None:
    """Validate the target, build the config and start the engine thread."""
    if not domain or "." not in domain:
        st.sidebar.error("enter a valid target domain, e.g. example.com")
        return
    try:
        config = ScanConfig(domain=domain, profile_id=profile_id, offline=offline)
        # Sidebar choices override the profile defaults.
        wordlist = st.session_state.get("wordlist")
        if wordlist:
            from subsonar.core.wordlists import resolve_wordlist

            config.wordlist = resolve_wordlist(wordlist).name
        matrix = st.session_state.get("port_matrix")
        if matrix and matrix != "core":
            from subsonar.core.ports import parse_port_spec

            config.ports = parse_port_spec(str(matrix))
            config.ports_override = True
        config.carry_over = bool(st.session_state.get("carry_over", True))
        config.geoip = bool(st.session_state.get("geoip", True))
        rate = float(st.session_state.get("dns_rate") or 0.0)
        if rate > 0:
            config.dns_rate_limit = rate
            config.dns_rate_override = True
        port_rate = float(st.session_state.get("port_rate") or 0.0)
        if port_rate > 0:
            config.port_rate_limit = port_rate
            config.port_rate_override = True
    except ValueError as exc:
        st.sidebar.error(str(exc))
        return
    BUS.clear()
    st.session_state.exported = {}
    runner = ScanRunner(config, profile=get_profile(profile_id), bus=BUS)
    runner.start()
    st.session_state.runner = runner
    st.session_state.domain = config.domain
    st.session_state.profile_id = profile_id
    st.session_state.scan_running = True
    # New run: drop the previous outcome and let the transition fire again.
    st.session_state.finished_announced = False
    st.session_state.scan_banner = None
    st.session_state.log_paused = False


def _export(result: ScanResult) -> None:
    if st.session_state.exported:
        return
    written = write_reports(
        result, result.config.output_dir, formats=("json", "csv", "md", "html", "txt")
    )
    st.session_state.exported = written


@st.fragment(run_every=LOG_REFRESH_SECONDS)
def _live_panel() -> None:
    """Live statistics + progress + log, refreshed by its own fragment.

    A Streamlit fragment re-runs *only itself*, so the rest of the page (tabs,
    filters, findings table, scroll positions) is not torn down every second —
    that page-wide ``st.rerun()`` loop was what made the interface flash.
    """
    runner: ScanRunner | None = st.session_state.runner
    if st.session_state.get("log_paused"):
        # Paused: freeze the *view* (the buffer keeps filling, so nothing is lost
        # and pressing Resume shows everything that happened meanwhile).
        st.caption("⏸ live updates paused — press ▶ Resume to follow the scan again")
        _render_log(frozen=True)
        return
    # This fragment is the only thing that runs while a scan is in progress, so it
    # is also what notices that the scan ended — and it is what asks for the one
    # app-wide rerun that lets the findings/export tabs show the final result.
    if _settle_scan_state() == "finished":
        st.rerun(scope="app")
    snapshot = BUS.snapshot() if runner else {}
    _stat_cards(snapshot)
    fraction = float(snapshot.get("progress") or 0.0)
    st.markdown(
        f"<div style='font-family:monospace;color:{Palette.ORANGE}'>"
        f"{progress_bar(fraction, 46)} {fraction * 100:5.1f}% · "
        f"phase: {snapshot.get('phase', 'idle')} · "
        f"elapsed {snapshot.get('elapsed', 0)}s · {snapshot.get('rate', 0)} queries/s</div>",
        unsafe_allow_html=True,
    )
    _render_log()


def _log_controls() -> None:
    """Controls for the log panel: pause, order, clear, download."""
    state = st.session_state
    controls = st.columns([1, 1, 1, 1, 2])
    paused = controls[0].toggle(
        "⏸ Pause live view",
        value=bool(state.log_paused),
        help=(
            "Freezes the panel so you can scroll back through the whole log "
            "without the newest lines shifting under the cursor."
        ),
    )
    newest = controls[1].toggle(
        "Newest first",
        value=bool(state.log_newest_first),
        help="Off = oldest first, which follows the scan at the bottom of the panel.",
    )
    if controls[2].button("↺ Clear", use_container_width=True):
        state.log_buffer.clear()
        state.log_dropped = 0
        state.log_appended = 0
    state.log_paused = paused
    state.log_newest_first = newest
    dumped = "\n".join(
        f"{event.clock} [{event.category or event.severity}] "
        + (f"{event.host}:{event.port} " if event.port else (f"{event.host} " if event.host else ""))
        + event.message
        for event in state.log_buffer
    )
    controls[3].download_button(
        "⇩ Download log",
        data=dumped or "no events yet\n",
        file_name=f"subsonar-log-{state.get('domain') or 'scan'}.txt",
        mime="text/plain",
        use_container_width=True,
        help="The full buffered log, even the part not currently rendered.",
    )
    if state.log_dropped:
        controls[4].caption(
            f"{state.log_dropped:,} event(s) were evicted by the bus window — "
            "lower the profile's verbosity or raise the buffer to keep everything."
        )


@st.fragment(run_every=2.0)
def _findings_panel() -> None:
    """Findings table — live during the scan, complete when it finishes.

    Own fragment for two reasons: the table then updates while a scan runs even
    though the page itself no longer re-renders every second, and typing in the
    filter box re-runs only the table instead of rebuilding the whole app.
    ``runner.live_result`` is what makes that work: the engine records findings
    into its ``ScanResult`` as each one is confirmed, while ``runner.result`` only
    exists once the engine thread has returned.
    """
    runner: ScanRunner | None = st.session_state.get("runner")
    result = runner.live_result if runner is not None else None
    findings = list(result.findings) if result is not None else []
    running = bool(runner is not None and runner.running)

    controls = st.columns([3, 1, 1, 1])
    filter_text = controls[0].text_input(
        "Filter findings (subdomain / IP / port / title / URL / country / ASN)",
        value="",
    )
    sort_key = controls[1].selectbox(
        "Sort by",
        ["confidence", "subdomain", "ip", "port", "status", "country"],
        index=0,
    )
    view = controls[2].selectbox("View", ["rich table", "sortable grid"], index=0)
    only_prev = controls[3].toggle("Only merged", value=False)
    if filter_text:
        needle = filter_text.lower()
        findings = [finding for finding in findings if _matches(finding, needle)]
    if only_prev:
        findings = [finding for finding in findings if finding.from_previous_scan]
    findings = _sort_findings(findings, sort_key)
    if findings:
        carried = sum(1 for finding in findings if finding.from_previous_scan)
        caption = (
            f"{len(findings)} web interface(s) — hover a flag for the country "
            f"and AS organisation"
        )
        if carried:
            caption += f" · {carried} merged from a previous scan"
        if running:
            caption += (
                " · scan still running, the list grows as hosts are confirmed "
                "(per-port view — the final report collapses one vhost serving "
                "several ports into a single row)"
            )
        st.caption(caption)
        if view == "sortable grid":
            st.dataframe(
                _findings_rows(findings),
                use_container_width=True,
                hide_index=True,
                height=880,
                column_config={
                    "URL": st.column_config.LinkColumn(
                        "URL", display_text=r"(https?://.*)"
                    ),
                    "Status": st.column_config.NumberColumn("Status", format="%d"),
                    "Geo": st.column_config.TextColumn(
                        "Geo", help="Hover the flag for country + AS organisation"
                    ),
                    "AS": st.column_config.NumberColumn("ASN", format="%d"),
                },
            )
        else:
            st.markdown(_findings_html(findings), unsafe_allow_html=True)
    elif running:
        st.info(
            "Scan running — subdomains appear here as soon as an HTTP/HTTPS probe "
            "confirms one on a port of the matrix."
        )
    else:
        st.info(
            "No web interface confirmed yet. subsonar only reports subdomains "
            "that answer an HTTP/HTTPS probe on at least one port of the matrix."
        )


def main() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
    _init_state()
    domain, profile_id, offline, quiet = _sidebar()

    st.markdown(
        f"<div class='logo'>{_escape(logo_block(width=100))}</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        f"<div class='tag'>» asynchronous subdomain &amp; web-interface sonar «</div>",
        unsafe_allow_html=True,
    )

    transition = _settle_scan_state()
    runner: ScanRunner | None = st.session_state.runner
    _render_scan_banner()

    tab_live, tab_findings, tab_plan, tab_export = st.tabs(
        ["◉ Live scanning log", "◎ Findings", "≡ Scan plan", "⇩ Export"]
    )

    with tab_live:
        _log_controls()
        _live_panel()

    with tab_findings:
        _findings_panel()

    with tab_plan:
        if runner is not None:
            config = runner.config
            spec = None
            try:
                from subsonar.core.wordlists import resolve_wordlist

                spec = resolve_wordlist(config.wordlist)
            except Exception:  # pragma: no cover - unknown registry name
                spec = None
            wordlist_line = (
                f"{runner.profile.wordlist_size:,} label(s) of "
                f"{spec.name if spec else config.wordlist}"
                if runner.profile.brute
                else "none (passive / OSINT only)"
            )
            plan = [
                "— what this run will actually do —",
                f"target            : {config.domain}",
                f"profile           : {runner.profile.id}. {runner.profile.name}",
                f"packets           : {runner.profile.packet_profile}",
                f"wordlist          : {wordlist_line}",
                f"port matrix       : {describe_matrix(config.ports)} "
                f"({len(config.ports)} ports"
                + (", profile default" if not config.ports_override else ", explicit")
                + ")",
                "— pacing (protects the resolvers and the target) —",
                f"dns rate limit    : {config.dns_rate_limit:g} q/s"
                + (f" ({config.dns_rate_per_server:g}/node)" if config.dns_rate_per_server else ""),
                f"port rate limit   : "
                + (f"{config.port_rate_limit:g} connects/s" if config.port_rate_limit else "off")
                + (f" ({config.port_rate_per_host:g}/host)" if config.port_rate_per_host else ""),
                f"dns concurrency   : {config.dns_concurrency}",
                f"port concurrency  : {config.port_concurrency}",
                f"http concurrency  : {config.http_concurrency}",
                f"stealth delay     : {config.stealth_delay[0]:.2f}"
                f"-{config.stealth_delay[1]:.2f}s",
                f"resolvers         : {len(config.resolver_pool)} anonymous",
            ]
            st.code("\n".join(plan), language="text")
        else:
            st.info("Configure a target in the sidebar and press ▶ Start.")
        st.markdown(
            f"<div style='color:{Palette.MUTED}'>Matrix: "
            + ", ".join(str(port) for port in sorted(PORT_MATRIX))
            + "</div>",
            unsafe_allow_html=True,
        )

    with tab_export:
        if runner is not None and runner.result is not None:
            _export(runner.result)
        exported = st.session_state.exported
        if exported:
            for fmt, path in exported.items():
                st.markdown(
                    f"<div style='font-family:monospace'>"
                    f"<span style='color:{Palette.GREEN}'>✔ {fmt:<5}</span>"
                    f"<span style='color:{Palette.MUTED}'>{path}</span></div>",
                    unsafe_allow_html=True,
                )
        else:
            st.info("Reports are written automatically when the scan completes.")

    # A finished scan still forces exactly one app-wide rerun: the live panels are
    # fragments (so the page is never rebuilt under the user's cursor), which means
    # only this transition can refresh the *other* tabs against the final result.
    if transition == "finished":
        st.rerun(scope="app")


def _has_script_context() -> bool:
    """True when Streamlit is driving this module (``streamlit run``)."""
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx

        return get_script_run_ctx() is not None
    except Exception:  # pragma: no cover - alternative Streamlit layouts
        return False


if _has_script_context():
    main()
