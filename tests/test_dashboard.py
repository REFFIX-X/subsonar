"""Headless render test for the Streamlit dashboard.

Chrome is not needed: Streamlit's own ``AppTest`` harness executes
``subsonar/ui/dashboard.py`` in-process, so a Streamlit API break, a syntax
error or a widget regression fails the suite instead of only showing up when
someone opens the browser.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest  # noqa: E402

from subsonar.core.config import ScanConfig  # noqa: E402
from subsonar.core.engine import Finding, ScanResult  # noqa: E402
from subsonar.core.profiles import get_profile  # noqa: E402

DASHBOARD = (
    Path(__file__).resolve().parent.parent / "subsonar" / "ui" / "dashboard.py"
)


def _run() -> AppTest:
    at = AppTest.from_file(str(DASHBOARD), default_timeout=120)
    at.run()
    return at


def test_dashboard_renders_without_exceptions() -> None:
    at = _run()
    assert not at.exception, [str(exc.value) for exc in at.exception]


def test_dashboard_exposes_the_scan_controls() -> None:
    at = _run()
    text_inputs = [widget.label for widget in at.text_input]
    assert any("Target domain" in label for label in text_inputs), text_inputs

    selectboxes = [widget.label for widget in at.selectbox]
    assert any("Scan profile" in label for label in selectboxes), selectboxes

    buttons = [widget.label for widget in at.button]
    assert any("Start" in label for label in buttons), buttons
    assert any("Stop" in label for label in buttons), buttons

    toggles = [widget.label for widget in at.toggle]
    assert any("Offline" in label for label in toggles), toggles
    assert any("Quiet" in label for label in toggles), toggles

    assert len(at.tabs) == 4, len(at.tabs)


def test_dashboard_profile_selectbox_lists_all_eight_profiles() -> None:
    from subsonar.core.profiles import PROFILES

    at = _run()
    selectbox = next(
        widget for widget in at.selectbox if "Scan profile" in widget.label
    )
    assert len(selectbox.options) == len(PROFILES)


def test_dashboard_rejects_an_invalid_domain_with_an_error() -> None:
    """Pressing Start with a junk target must surface a sidebar error."""
    at = _run()
    domain = next(
        widget for widget in at.text_input if "Target domain" in widget.label
    )
    domain.set_value("not-a-domain")
    next(widget for widget in at.button if "Start" in widget.label).click()
    at.run()

    assert not at.exception, [str(exc.value) for exc in at.exception]
    assert at.sidebar.error, "expected a validation error for an invalid domain"
    assert any("valid target domain" in str(err.value) for err in at.sidebar.error)


def test_dashboard_prefills_the_domain_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``python main.py web example.com`` must show up in the target box."""
    monkeypatch.setenv("SUBSONAR_WEB_DOMAIN", "https://Example.COM/some/path")
    at = _run()
    domain = next(
        widget for widget in at.text_input if "Target domain" in widget.label
    )
    assert domain.value == "example.com"


def test_dashboard_ignores_an_empty_or_absent_prefill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SUBSONAR_WEB_DOMAIN", raising=False)
    at = _run()
    domain = next(
        widget for widget in at.text_input if "Target domain" in widget.label
    )
    assert domain.value == ""


def test_dashboard_exposes_the_new_scope_controls() -> None:
    """Wordlist, port matrix, carry-over, geo and the rate limits are in the UI."""
    at = _run()
    selectboxes = [widget.label for widget in at.selectbox]
    assert any("Wordlist" in label for label in selectboxes), selectboxes
    assert any("Port matrix" in label for label in selectboxes), selectboxes
    assert any("Sort by" in label for label in selectboxes), selectboxes

    toggles = [widget.label for widget in at.toggle]
    assert any("Merge previous results" in label for label in toggles), toggles
    assert any("Offline geo" in label for label in toggles), toggles
    assert any("Only merged" in label for label in toggles), toggles
    assert any("Pause live view" in label for label in toggles), toggles
    assert any("Newest first" in label for label in toggles), toggles

    numbers = [widget.label for widget in at.number_input]
    assert any("DNS rate limit" in label for label in numbers), numbers
    assert any("Port rate limit" in label for label in numbers), numbers

    buttons = [widget.label for widget in at.button]
    assert any("Clear" in label for label in buttons), buttons
    downloads = [widget.label for widget in at.get("download_button")]
    assert any("Download log" in label for label in downloads), downloads

    # Every registered wordlist is offered, and the matrices match the CLI.
    wordlist = next(w for w in at.selectbox if "Wordlist" in w.label)
    from subsonar.core.wordlists import WORDLISTS

    assert len(wordlist.options) == len(WORDLISTS)
    matrix = next(w for w in at.selectbox if "Port matrix" in w.label)
    assert matrix.options == ["core", "extended", "web", "audit"]


def test_dashboard_live_panel_is_a_self_refreshing_fragment() -> None:
    """Regression: the page-wide ``st.rerun()`` loop made the UI flash.

    The live log/stats panel must refresh through a fragment (``run_every``) and
    ``main()`` must not sleep-and-rerun the whole app while a scan runs.
    """
    from pathlib import Path

    from subsonar.ui import dashboard

    assert dashboard.LOG_REFRESH_SECONDS > 0
    source = Path(dashboard.__file__).read_text(encoding="utf-8")
    assert "@st.fragment(run_every=LOG_REFRESH_SECONDS)" in source
    assert "st.rerun(scope=\"app\")" in source
    assert "time.sleep(0.5)" not in source  # the old flashing loop is gone
    # The log is rendered from an accumulating buffer, never from drain().
    assert "_sync_log_buffer()" in source
    assert "BUS.drain(limit=" not in source


def test_dashboard_css_uses_the_full_width_and_scales_for_4k() -> None:
    """Regression: the default Streamlit column left 4K screens 80% empty."""
    from subsonar.ui.dashboard import CSS

    assert "max-width: 100%" in CSS
    assert "kpi-grid" in CSS and "auto-fit" in CSS
    assert "@media (min-width: 2400px)" in CSS
    assert "@media (min-width: 3200px)" in CSS
    assert "table.findings" in CSS
    assert "img.flag" in CSS
    assert "height: 68vh" in CSS


def test_findings_html_renders_flags_tooltips_and_links() -> None:
    from subsonar.core.engine import Finding
    from subsonar.ui.dashboard import _findings_html

    finding = Finding(
        subdomain="shop.example.com",
        ip="23.227.38.74",
        port=443,
        scheme="https",
        url="https://shop.example.com",
        status=200,
        title="Shop & Save <now>",
    )
    finding.country_code = "DK"
    finding.country = "Denmark"
    finding.asn = 13335
    finding.as_org = "CLOUDFLARENET"
    finding.ptr = "shop.example.com"
    finding.from_previous_scan = True
    html_text = _findings_html([finding])

    assert "<table class='findings'>" in html_text
    assert "<th>Geo</th>" in html_text and "<th>AS organisation</th>" in html_text
    assert "https://flagcdn.com/20x15/dk.png" in html_text
    assert "title='Denmark · CLOUDFLARENET · AS13335 · shop.example.com'" in html_text
    assert "class='prev'>prev<" in html_text
    assert "Shop &amp; Save &lt;now&gt;" in html_text  # escaped, never raw HTML
    assert "rel='noopener'" in html_text


def test_findings_html_falls_back_to_the_emoji_flag() -> None:
    from subsonar.core.engine import Finding
    from subsonar.ui.dashboard import _findings_html

    finding = Finding(
        subdomain="a.example.com",
        ip="203.0.113.1",
        port=443,
        scheme="https",
        url="https://a.example.com",
        status=200,
        title="",
    )
    assert "—" in _findings_html([finding])  # no country: an em dash, not a crash
    finding.country_code = "A1"  # pseudo-code: no flag image exists
    assert "flagcdn" not in _findings_html([finding])


def test_findings_filter_and_sort_helpers() -> None:
    from subsonar.core.engine import Finding
    from subsonar.ui.dashboard import _matches, _sort_findings

    def make(host: str, ip: str, port: int, confidence: int) -> Finding:
        finding = Finding(
            subdomain=host,
            ip=ip,
            port=port,
            scheme="https",
            url=f"https://{host}",
            status=200,
            title="Portal",
        )
        finding.confidence = confidence
        return finding

    a = make("a.example.com", "203.0.113.1", 80, 40)
    b = make("b.example.com", "203.0.113.2", 443, 90)
    assert [f.subdomain for f in _sort_findings([a, b], "confidence")] == [
        "b.example.com",
        "a.example.com",
    ]
    assert [f.subdomain for f in _sort_findings([a, b], "ip")] == [
        "a.example.com",
        "b.example.com",
    ]
    assert [f.port for f in _sort_findings([b, a], "port")] == [80, 443]
    assert _sort_findings([a, b], "status") == [a, b]

    b.country_code = "DK"
    b.as_org = "CLOUDFLARENET"
    b.asn = 13335
    assert _matches(b, "dk") is True
    assert _matches(b, "cloudflare") is True
    assert _matches(b, "as13335") is True
    assert _matches(a, "cloudflare") is False
    assert _matches(a, "443") is False


def test_dashboard_kpi_strip_includes_the_carried_over_counter() -> None:
    from subsonar.core.events import Stats

    stats = Stats()
    stats.carried_over = 3
    assert stats.snapshot()["carried_over"] == 3


def _fake_runner(findings: list[Any], *, running: bool = False, error: Any = None):
    """A duck-typed stand-in for :class:`ScanRunner` (no engine, no threads)."""

    class _Runner:
        def __init__(self) -> None:
            self.config = ScanConfig(domain="example.com")
            self.profile = get_profile(3)
            self.result = None if running else _result(findings)
            self.error = error
            self.running = running
            self.finished = not running
            self.live_result = _result(findings)

        def stop(self) -> None:
            self.running = False
            self.finished = True

    return _Runner()


def _result(findings: list[Any]) -> ScanResult:
    """A real ``ScanResult`` holding *findings* (no engine involved)."""
    result = ScanResult(ScanConfig(domain="example.com"), get_profile(3))
    result.findings = list(findings)
    # ``duration`` is a derived property, so set the timestamps it reads.
    result.started_at = time.time() - 12.5
    result.finished_at = time.time()
    return result


def _finding(subdomain: str, port: int = 443, **extra: Any) -> Finding:
    scheme = "http" if port in (80, 8080) else "https"
    host = subdomain if port in (80, 443) else f"{subdomain}:{port}"
    finding = Finding(
        subdomain=subdomain,
        ip="94.237.103.2",
        port=port,
        scheme=scheme,
        url=f"{scheme}://{host}",
        status=200,
        title="Example",
    )
    for key, value in extra.items():
        setattr(finding, key, value)
    return finding


def test_findings_tab_shows_the_findings_the_scan_confirmed() -> None:
    """Regression: the KPI strip counted findings while the tab showed none.

    The live panel is a fragment, so during a scan only *that* fragment re-renders
    — and the findings table read ``runner.result``, which the runner only assigns
    once the engine thread has returned.  The tab therefore stayed on its initial,
    empty render ("No web interface confirmed yet") while the KPI strip (fed by the
    bus counters the fragment refreshes) happily reported "web found 9".
    """
    findings = [
        _finding("www.example.com", 443),
        _finding("ftp.example.com", 80, status=301),
    ]
    at = _run()
    at.session_state["runner"] = _fake_runner(findings)
    at.session_state["finished_announced"] = True  # the banner/rerun already ran
    at.run()

    assert not at.exception, [str(exc.value) for exc in at.exception]
    rendered = "".join(str(value.value) for value in at.markdown)
    assert "www.example.com" in rendered
    assert "ftp.example.com" in rendered
    assert "No web interface confirmed yet" not in rendered
    captions = " ".join(str(item.value) for item in at.caption)
    assert "2 web interface(s)" in captions


def test_findings_tab_updates_while_the_scan_is_still_running() -> None:
    """``live_result`` streams findings in, so the tab is never stale mid-scan."""
    at = _run()
    at.session_state["runner"] = _fake_runner([], running=True)
    at.run()
    infos = " ".join(str(item.value) for item in at.info)
    assert "Scan running" in infos

    # The engine records findings as it confirms them: the same runner now reports
    # one, with the scan still in progress.
    at.session_state["runner"] = _fake_runner(
        [_finding("portal.example.com")], running=True
    )
    at.run()
    rendered = "".join(str(value.value) for value in at.markdown)
    captions = " ".join(str(item.value) for item in at.caption)
    assert "portal.example.com" in rendered
    assert "scan still running" in captions


def test_finished_scan_triggers_exactly_one_app_rerun_and_a_banner() -> None:
    """The completion transition must repaint the non-fragment tabs — once."""
    at = _run()
    runner = _fake_runner([_finding("www.example.com")])
    at.session_state["runner"] = runner
    at.session_state["scan_running"] = True
    at.session_state["finished_announced"] = False
    at.run()

    assert not at.exception, [str(exc.value) for exc in at.exception]
    assert at.session_state["finished_announced"] is True
    assert at.session_state["scan_running"] is False
    assert at.session_state["scan_banner"][0] == "success"
    success = " ".join(str(item.value) for item in at.success)
    assert "1 web interface(s)" in success
    # Not re-announced on the next pass (this is what prevents a rerun loop).
    banner = at.session_state["scan_banner"]
    at.run()
    assert at.session_state["scan_banner"] == banner


def test_failed_scan_surfaces_an_error_banner() -> None:
    at = _run()
    at.session_state["runner"] = _fake_runner([], error=RuntimeError("boom"))
    at.session_state["scan_running"] = True
    at.session_state["finished_announced"] = False
    at.run()
    assert at.session_state["scan_banner"] == ("error", "scan aborted: boom")
    errors = " ".join(str(item.value) for item in at.error)
    assert "scan aborted: boom" in errors


def test_live_log_grows_across_reruns_and_respects_quiet() -> None:
    """The reported regression: every rerun used to clear the live log.

    Three reruns with one new event each must show one, two and three lines —
    and the *Quiet log* switch must hide debug/filter chatter retroactively.
    """
    from pathlib import Path

    from subsonar.core.events import BUS

    dashboard_source = Path(DASHBOARD).read_text(encoding="utf-8")
    assert "log_buffer" in dashboard_source

    at = _run()
    for index in range(3):
        BUS.emit(f"kept line {index}", "info", "dns", host="h.example.com")
        at.run()
        assert not at.exception, [str(exc.value) for exc in at.exception]
        assert len(at.session_state["log_buffer"]) == index + 1
    rendered = "".join(str(value.value) for value in at.markdown)
    for index in range(3):
        assert f"kept line {index}" in rendered
    assert at.session_state["log_seq"] > 0

    # Debug chatter is filtered at render time, so toggling quiet rewrites the
    # past as well as the future (the lines stay buffered and downloadable).
    BUS.emit("noisy debug detail", "debug", "dns")
    quiet = next(w for w in at.toggle if "Quiet log" in w.label)
    quiet.set_value(True)
    at.run()
    rendered = "".join(str(value.value) for value in at.markdown)
    assert "noisy debug detail" not in rendered
    assert "kept line 2" in rendered
    assert len(at.session_state["log_buffer"]) == 4


def test_web_command_passes_the_domain_to_the_dashboard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: ``web <domain>`` was accepted but silently ignored."""
    import subprocess

    import main

    captured: dict[str, object] = {}

    def fake_call(command, env=None):  # noqa: ANN001, ANN202
        captured["command"] = command
        captured["domain"] = (env or {}).get("SUBSONAR_WEB_DOMAIN")
        return 0

    monkeypatch.setattr(subprocess, "call", fake_call)
    monkeypatch.delenv("SUBSONAR_WEB_DOMAIN", raising=False)

    args = main.build_parser().parse_args(["web", "example.com", "--port", "8599"])
    assert main.cmd_web(args) == 0
    assert captured["domain"] == "example.com"
    command = captured["command"]
    assert isinstance(command, list)
    assert "streamlit" in command and "8599" in command

    # Without a positional domain nothing is injected.
    captured.clear()
    args = main.build_parser().parse_args(["web", "--port", "8599"])
    assert main.cmd_web(args) == 0
    assert captured["domain"] is None
