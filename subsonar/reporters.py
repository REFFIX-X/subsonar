"""Report writers — JSON, CSV, Markdown, HTML and plain text.

Every writer emits the same filtered dataset: only subdomains with a verified
web interface, each with a fully actionable hyperlink.
"""

from __future__ import annotations

import csv
import html
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence, TextIO

from .core.engine import Finding, ScanResult

CSV_COLUMNS = (
    "subdomain",
    "ip",
    "port",
    "port_label",
    "status",
    "kind",
    "confidence",
    "confidence_label",
    "title",
    "scheme",
    "url",
    "final_url",
    "server",
    "tls",
    "tls_version",
    "also_on_ports",
    "technologies",
    "favicon_hash",
    "data_files",
    "confidence_why",
    "checks",
    "sources",
    "provider",
    "country_code",
    "country",
    "asn",
    "as_org",
    "ptr",
    "carried_over",
    "latency_ms",
)


def _ensure_parent(path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def _atomic_write(path: Path, *, newline: str | None = None) -> Iterator[TextIO]:
    """Write *path* through a temp file + ``os.replace``.

    A crash mid-write otherwise leaves a truncated report, which a later
    carry-over read would silently ignore — losing the previous scan's findings.
    """
    path = _ensure_parent(path)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline=newline) as handle:
            yield handle
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _md_cell(value: Any) -> str:
    """Escape one Markdown table cell: collapse newlines and escape pipes."""
    text = " ".join(str(value).split())
    return text.replace("\\", "\\\\").replace("|", "\\|")


def write_json(result: ScanResult, path: Path) -> Path:
    path = Path(path)
    with _atomic_write(path) as handle:
        json.dump(result.to_dict(), handle, indent=2, ensure_ascii=False)
    return path


def write_jsonl(result: ScanResult, path: Path) -> Path:
    """Newline-delimited JSON: one metadata line, then one finding per line."""
    path = Path(path)
    payload = result.to_dict()
    findings = payload.pop("findings", [])
    with _atomic_write(path) as handle:
        handle.write(json.dumps({"event": "meta", "data": payload}, ensure_ascii=False))
        handle.write("\n")
        for finding in findings:
            handle.write(json.dumps({"event": "finding", "data": finding}, ensure_ascii=False))
            handle.write("\n")
    return path


class JsonlSink:
    """Streaming NDJSON writer for live export.

    Findings are appended as they are confirmed, so an interrupted scan still
    leaves every finding discovered up to that point on disk.  Thread-safe: the
    engine runs in its own thread while a UI may read the file.
    """

    def __init__(self, path: Path, *, domain: str = "") -> None:
        self.path = Path(path)
        self.domain = domain
        self._handle: Any = None
        self._lock = None

    def open(self, meta: dict[str, Any] | None = None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self.path, "w", encoding="utf-8")
        import threading

        self._lock = threading.Lock()
        self.write({"event": "meta", "data": meta or {}})

    def write(self, record: dict[str, Any]) -> None:
        if self._handle is None:
            return
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with self._lock:
            self._handle.write(line)
            self._handle.flush()

    def finding(self, data: dict[str, Any]) -> None:
        self.write({"event": "finding", "data": data})

    def close(self) -> None:
        if self._handle is not None:
            with self._lock:
                self._handle.close()
            self._handle = None


def write_csv(result: ScanResult, path: Path) -> Path:
    path = Path(path)
    with _atomic_write(path, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(CSV_COLUMNS))
        writer.writeheader()
        for finding in result.findings:
            writer.writerow(finding.to_row())
    return path


def write_markdown(result: ScanResult, path: Path) -> Path:
    path = Path(path)
    lines: list[str] = []
    lines.append(f"# subsonar report — {result.config.domain}")
    lines.append("")
    lines.append(f"**Profile:** {result.profile.id}. {result.profile.name}  ")
    lines.append(f"**Duration:** {result.duration:.1f}s  ")
    lines.append(f"**Generated:** {_timestamp()}  ")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    for line in result.summary_lines():
        key, _, value = line.partition(":")
        lines.append(f"| {_md_cell(key.strip())} | {_md_cell(value.strip())} |")
    if result.wildcard and result.wildcard.wildcard:
        lines.append("")
        lines.append(
            f"> **Wildcard DNS detected** — false positives filtered against "
            f"{', '.join(sorted(result.wildcard.ips))}"
        )
    lines.append("")
    lines.append("## Web interfaces")
    lines.append("")
    if not result.findings:
        lines.append("_No web interface was confirmed on this target._")
    else:
        lines.append(
            "| # | Subdomain | IP | Geo | Port | Status | Kind | Conf | Provider | Title | Tech | URL |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for index, finding in enumerate(result.findings, start=1):
            title = _md_cell(finding.title or "")[:60]
            if finding.from_previous_scan:
                title = f"_(prev)_ {title}".strip()
            port_text = str(finding.port)
            if finding.aliases:
                port_text += " (+" + ", ".join(str(p) for p in finding.aliases) + ")"
            tech = _md_cell(", ".join(finding.technologies[:4]))
            geo = finding.geo_label or ""
            if finding.asn:
                geo = f"{geo} AS{finding.asn}".strip()
            lines.append(
                f"| {index} | `{finding.subdomain}` | `{finding.ip}` | "
                f"{geo} | {port_text} | {finding.status} | {finding.kind} | "
                f"{finding.confidence} {finding.confidence_label} | "
                f"{finding.provider or ''} | {title} | "
                f"{tech} | [{finding.url}]({finding.link}) |"
            )
    exposed = [f for f in result.findings if getattr(f, "exposures", None)]
    if exposed:
        lines.append("")
        lines.append("## Template checks (exposures)")
        lines.append("")
        lines.append("| Subdomain | Severity | Check | Evidence |")
        lines.append("| --- | --- | --- | --- |")
        for finding in exposed:
            for exp in finding.exposures:
                lines.append(
                    f"| `{_md_cell(finding.subdomain)}` | "
                    f"{_md_cell(exp.get('severity', '?'))} | "
                    f"{_md_cell(exp.get('name', ''))} | "
                    f"{_md_cell(exp.get('evidence', ''))} |"
                )
    if result.mined_hosts:
        lines.append("")
        lines.append("## Mined hostnames (robots/sitemap/security.txt/headers)")
        lines.append("")
        lines.append(
            "Extra in-scope names found in files the target publishes on purpose "
            + ("— the ones marked \\* were scanned in the second wave:"
               if result.wave2_hosts else ":")
        )
        lines.append("")
        lines.append("| Host | Scanned |")
        lines.append("| --- | --- |")
        for host in sorted(result.mined_hosts):
            marker = "yes" if host in result.wave2_hosts else ""
            lines.append(f"| `{_md_cell(host)}` | {marker} |")
    intel = result.dns_intel
    if intel is not None:
        lines.append("")
        lines.append("## DNS intelligence (free, DNS only)")
        lines.append("")
        lines.append("| Signal | Value |")
        lines.append("| --- | --- |")
        for signal in intel.signals():
            key, _, value = signal.partition(":")
            lines.append(f"| {_md_cell(key.strip())} | {_md_cell(value.strip())} |")
        if intel.notes:
            lines.append("")
            lines.append("**Posture**")
            lines.append("")
            for note in intel.notes:
                lines.append(f"- {note}")
        if intel.verifications:
            lines.append("")
            lines.append("**Third-party verifications**")
            lines.append("")
            for vendor, token in sorted(intel.verifications.items()):
                token_text = token if len(token) <= 40 else token[:37] + "..."
                lines.append(f"- {vendor}: `{token_text}`")
    if result.ptr:
        lines.append("")
        lines.append("## Reverse DNS (PTR)")
        lines.append("")
        lines.append("| Address | PTR |")
        lines.append("| --- | --- |")
        for address, name in sorted(result.ptr.items()):
            lines.append(f"| `{address}` | `{name}` |")
    if result.provider_hosts:
        lines.append("")
        lines.append("## Third-party hosted (not scanned)")
        lines.append("")
        lines.append(
            "These hosts are Office 365-style shared tenants (mail / identity / "
            "collaboration), so they were skipped entirely — no port sweep and no "
            "HTTP probe against somebody else's fleet:"
        )
        lines.append("")
        lines.append("| Host | Provider |")
        lines.append("| --- | --- |")
        for host, provider in sorted(result.provider_hosts.items()):
            lines.append(f"| `{host}` | {provider} |")
    sources = result.to_dict().get("sources", {})
    if sources:
        lines.append("")
        lines.append("## OSINT sources")
        lines.append("")
        lines.append("| Source | Hosts | Errors | Duration |")
        lines.append("| --- | --- | --- | --- |")
        for name, report in sources.items():
            lines.append(
                f"| {name} | {report['hosts']} | {report['errors']} | "
                f"{report['duration']}s |"
            )
    lines.append("")
    lines.append(
        "_Generated by subsonar — asynchronous subdomain & web-interface sonar._"
    )
    lines.append("")
    with _atomic_write(path) as handle:
        handle.write("\n".join(lines))
    return path


def _flag_html(finding: Any) -> str:
    """Flag image (with a hover title) or the emoji fallback for one finding."""
    from .core import geoip

    code = getattr(finding, "country_code", None)
    if not code:
        return ""
    asn = getattr(finding, "asn", None)
    as_label = f"AS{asn} {finding.as_org or ''}".strip() if asn else None
    tip = " · ".join(
        part
        for part in (
            finding.country or geoip.country_name(code) or code,
            as_label,
            getattr(finding, "ptr", None),
        )
        if part
    )
    url = geoip.flag_image_url(code)
    fallback = geoip.flag_emoji(code) or code
    if not url:
        return f"<span class='geo' title='{html.escape(tip)}'>{fallback}</span>"
    return (
        f"<img class='flag' src='{html.escape(url)}' alt='{html.escape(code)}' "
        f"title='{html.escape(tip)}'>"
        f"<span class='code'>{html.escape(code)}</span>"
    )


def _intel_html(result: ScanResult) -> str:
    """DNS-intelligence, mined-host and PTR blocks for the HTML report."""
    parts: list[str] = []

    def escape(value: Any) -> str:
        return html.escape(str(value))

    intel = result.dns_intel
    if intel is not None:
        items = "".join(
            f"<div class='stat'><span class='k'>{escape(signal.partition(':')[0].strip())}</span>"
            f"<span class='v'>{escape(signal.partition(':')[2].strip())}</span></div>"
            for signal in intel.signals()
        )
        notes = "".join(f"<li class='warn'>{escape(note)}</li>" for note in intel.notes)
        verify = "".join(
            f"<li>{escape(vendor)} — <code>{escape(token[:48])}</code></li>"
            for vendor, token in sorted(intel.verifications.items())
        )
        parts.append(
            "<h2>DNS intelligence (free, DNS only)</h2><div class='intel'>"
            f"<div class='summary'>{items or '<em>nothing published</em>'}</div>"
            + (f"<h3>Posture</h3><ul>{notes}</ul>" if notes else "")
            + (f"<h3>Third-party verifications</h3><ul>{verify}</ul>" if verify else "")
            + "</div>"
        )
    if result.mined_hosts:
        rows = "".join(
            f"<tr><td class='host'>{escape(host)}</td>"
            f"<td class='num'>{'scanned' if host in result.wave2_hosts else ''}</td></tr>"
            for host in sorted(result.mined_hosts)
        )
        parts.append(
            f"<h2>Mined hostnames ({len(result.mined_hosts)})</h2>"
            "<table><thead><tr><th>Host</th><th>Second wave</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )
    if result.ptr:
        rows = "".join(
            f"<tr><td class='ip'>{escape(address)}</td><td>{escape(name)}</td></tr>"
            for address, name in sorted(result.ptr.items())
        )
        parts.append(
            "<h2>Reverse DNS (PTR)</h2>"
            "<table><thead><tr><th>Address</th><th>PTR</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )
    exposed = [f for f in result.findings if getattr(f, "exposures", None)]
    if exposed:
        from .core.theme import Palette

        sev_colour = {
            "critical": Palette.RED,
            "high": Palette.ORANGE,
            "medium": Palette.YELLOW,
            "low": Palette.CYAN,
            "info": Palette.MUTED,
        }
        rows = "".join(
            "<tr>"
            f"<td class='host'>{escape(finding.subdomain)}</td>"
            f"<td style='color:{sev_colour.get(exp.get('severity'), Palette.MUTED)}'>"
            f"{escape(exp.get('severity', '?'))}</td>"
            f"<td>{escape(exp.get('name', ''))}</td>"
            f"<td class='muted'>{escape(exp.get('evidence', ''))}</td>"
            "</tr>"
            for finding in exposed
            for exp in finding.exposures
        )
        parts.append(
            "<h2>Template checks (exposures)</h2>"
            "<table><thead><tr><th>Host</th><th>Severity</th><th>Check</th>"
            "<th>Evidence</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )
    return "\n".join(parts)


def write_html(result: ScanResult, path: Path) -> Path:
    from .core.theme import Palette

    path = Path(path)
    rows: list[str] = []
    kind_colour = {
        "interface": Palette.GREEN,
        "restricted": Palette.ORANGE,
        "misconfigured": Palette.RED,
        "redirect": Palette.YELLOW,
    }
    confidence_colour = {
        "high": Palette.GREEN,
        "medium": Palette.ORANGE,
        "low": Palette.RED,
    }
    for index, finding in enumerate(result.findings, start=1):
        port_text = str(finding.port)
        if finding.aliases:
            port_text += " +" + ", ".join(str(p) for p in finding.aliases)
        tech = ", ".join(finding.technologies[:5])
        files = ", ".join(
            f"{path}={status}" for path, status in sorted(finding.data_files.items())
        )
        detail = " · ".join(filter(None, (tech, files)))
        geo_cell = _flag_html(finding)
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td class='host'>{html.escape(finding.subdomain)}</td>"
            f"<td class='ip'>{html.escape(finding.ip)} {geo_cell}</td>"
            f"<td class='num'>{port_text}</td>"
            f"<td class='num'>{finding.status if finding.status is not None else '-'}</td>"
            f"<td style='color:{kind_colour.get(finding.kind, Palette.MUTED)}'>"
            f"{html.escape(finding.kind)}</td>"
            f"<td style='color:{confidence_colour.get(finding.confidence_label, Palette.MUTED)};"
            f"text-align:right'>{finding.confidence}</td>"
            f"<td class='provider'>{html.escape(finding.provider or '')}</td>"
            f"<td class='title'>{html.escape(finding.title or '')}</td>"
            f"<td class='asn'>{html.escape(finding.as_org or '')}</td>"
            f"<td style='color:{Palette.CYAN};font-size:12px'>{html.escape(detail)}</td>"
            f"<td><a class='url' href='{html.escape(finding.link)}' "
            f"target='_blank' rel='noopener'>{html.escape(finding.url)}</a></td>"
            "</tr>"
        )
    summary_rows = "".join(
        f"<div class='stat'><span class='k'>{html.escape(k.strip())}</span>"
        f"<span class='v'>{html.escape(v.strip())}</span></div>"
        for k, _, v in (line.partition(":") for line in result.summary_lines())
    )
    document = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>subsonar — {html.escape(result.config.domain)}</title>
<style>
  :root {{
    --bg: {Palette.BACKGROUND}; --surface: {Palette.SURFACE};
    --alt: {Palette.SURFACE_ALT}; --text: {Palette.TEXT};
    --muted: {Palette.MUTED}; --pink: {Palette.PINK};
    --green: {Palette.GREEN}; --orange: {Palette.ORANGE};
    --yellow: {Palette.YELLOW}; --cyan: {Palette.CYAN}; --red: {Palette.RED};
  }}
  * {{ box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text); margin: 0;
         font-family: "JetBrains Mono", Consolas, monospace; padding: 32px; }}
  h1 {{ color: var(--pink); letter-spacing: 2px; margin: 0 0 4px; }}
  h2 {{ color: var(--cyan); border-bottom: 1px solid var(--alt);
        padding-bottom: 6px; margin-top: 36px; }}
  .sub {{ color: var(--muted); margin-bottom: 24px; }}
  .summary {{ display: flex; flex-wrap: wrap; gap: 12px; }}
  .stat {{ background: var(--surface); border: 1px solid var(--alt);
           border-radius: 6px; padding: 10px 16px; min-width: 180px; }}
  .stat .k {{ display: block; color: var(--muted); font-size: 12px;
              text-transform: uppercase; }}
  .stat .v {{ color: var(--orange); font-size: 18px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
  th {{ background: var(--surface); color: var(--yellow); text-align: left;
        padding: 10px; border-bottom: 1px solid var(--alt); }}
  td {{ padding: 9px 10px; border-bottom: 1px solid rgba(64,62,65,.5); }}
  tr:hover td {{ background: var(--surface); }}
  .host {{ color: var(--green); }}
  .ip {{ color: var(--cyan); }}
  .num {{ color: var(--orange); }}
  .title {{ color: var(--text); }}
  a.url {{ color: var(--yellow); text-decoration: none; }}
  a.url:hover {{ color: var(--pink); text-decoration: underline; }}
  .warn {{ color: var(--red); }}
  img.flag {{ height: 13px; width: auto; vertical-align: -1px;
              border: 1px solid var(--alt); border-radius: 2px; }}
  .code {{ color: var(--muted); font-size: 11px; margin-left: 3px; }}
  .geo {{ cursor: help; }}
  .asn {{ color: var(--muted); font-size: 12px; }}
  .intel {{ background: var(--surface); border: 1px solid var(--alt);
            border-radius: 6px; padding: 14px 18px; }}
  .intel li {{ margin: 4px 0; }}
</style></head><body>
<h1>subsonar</h1>
<div class="sub">asynchronous subdomain &amp; web-interface sonar —
  target <strong>{html.escape(result.config.domain)}</strong> ·
  {html.escape(result.profile.name)} · {result.duration:.1f}s</div>
<div class="summary">{summary_rows}</div>
{"<p class='warn'>Wildcard DNS detected — false positives filtered against " + html.escape(", ".join(sorted(result.wildcard.ips))) + "</p>" if result.wildcard and result.wildcard.wildcard else ""}
<h2>Web interfaces ({len(result.findings)})</h2>
<table><thead><tr><th>#</th><th>Subdomain</th><th>Resolved IP</th><th>Port</th>
<th>Status</th><th>Kind</th><th>Conf</th><th>Provider</th><th>Title</th>
<th>AS organisation</th>
<th>Technologies / files</th>
<th>URL</th></tr></thead>
<tbody>{"".join(rows) or "<tr><td colspan='12'>No web interface confirmed.</td></tr>"}</tbody>
</table>
{_intel_html(result)}
</body></html>
"""
    with _atomic_write(path) as handle:
        handle.write(document)
    return path


def write_text(result: ScanResult, path: Path) -> Path:
    path = Path(path)
    lines = [
        "subsonar — asynchronous subdomain & web-interface sonar",
        "=" * 78,
        *result.summary_lines(),
        "",
        f"{'SUBDOMAIN':<38}{'IP':<17}{'PORT':<7}{'CODE':<6}TITLE",
        "-" * 118,
    ]
    for finding in result.findings:
        lines.append(
            f"{finding.subdomain[:37]:<38}{finding.ip[:16]:<17}"
            f"{finding.port:<7}{str(finding.status or '-'):<6}"
            f"{(finding.title or '')[:44]}"
        )
        lines.append(f"    ↳ {finding.url}")
    if not result.findings:
        lines.append("No web interface confirmed on this target.")
    lines.append("")
    with _atomic_write(path) as handle:
        handle.write("\n".join(lines))
    return path


def write_urls(result: ScanResult, path: Path) -> Path:
    """One actionable URL per line — pipes straight into httpx/nuclei/gau."""
    path = Path(path)
    with _atomic_write(path) as handle:
        for finding in result.findings:
            handle.write(finding.link + "\n")
    return path


#: Template severity → SARIF result level.
_SEVERITY_TO_SARIF: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """Render the result as SARIF 2.1.0 for CI/security-tooling consumption."""
    from . import __version__

    rules: dict[str, dict[str, Any]] = {}

    def rule(rule_id: str, name: str, level: str) -> None:
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": name},
                "defaultConfiguration": {"level": level},
            },
        )

    rule("subsonar.web-interface", "Web interface exposed", "note")
    sarif_results: list[dict[str, Any]] = []
    for finding in result.findings:
        sarif_results.append(
            {
                "ruleId": "subsonar.web-interface",
                "level": "note",
                "message": {
                    "text": f"{finding.scheme}://{finding.host_port} — "
                    f"{finding.title or 'no title'} ({finding.status})"
                },
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": finding.link}}}
                ],
                "properties": {
                    "confidence": finding.confidence,
                    "confidenceLabel": finding.confidence_label,
                    "kind": finding.kind,
                },
            }
        )
        for exposure in getattr(finding, "exposures", None) or []:
            rule_id = "subsonar." + str(exposure.get("id") or "check")
            level = _SEVERITY_TO_SARIF.get(
                str(exposure.get("severity") or "info").lower(), "note"
            )
            rule(rule_id, str(exposure.get("name") or rule_id), level)
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {
                        "text": f"{exposure.get('name', 'check')} — "
                        f"{exposure.get('evidence', '')}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.link}
                            }
                        }
                    ],
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "subsonar",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def write_sarif(result: ScanResult, path: Path) -> Path:
    path = Path(path)
    with _atomic_write(path) as handle:
        json.dump(to_sarif(result), handle, indent=2, ensure_ascii=False)
    return path


WRITERS = {
    "json": (write_json, ".json"),
    "jsonl": (write_jsonl, ".jsonl"),
    "ndjson": (write_jsonl, ".jsonl"),
    "csv": (write_csv, ".csv"),
    "md": (write_markdown, ".md"),
    "markdown": (write_markdown, ".md"),
    "html": (write_html, ".html"),
    "txt": (write_text, ".txt"),
    "text": (write_text, ".txt"),
    # Interop formats — opt-in via ``--formats`` (not written by default).
    "urls": (write_urls, ".urls.txt"),
    "sarif": (write_sarif, ".sarif"),
}

#: Accepted spelling variants → canonical writer key.
FORMAT_ALIASES: dict[str, str] = {
    "markdown": "md",
    "text": "txt",
    "ndjson": "jsonl",
    "url": "urls",
    "urllist": "urls",
}

#: Canonical formats, in the order reports are written.
CANONICAL_FORMATS: tuple[str, ...] = ("json", "csv", "md", "html", "txt")


def canonical_format(name: str) -> str | None:
    """Resolve *name* (or an alias) to a canonical writer key, else ``None``."""
    key = str(name).strip().lower()
    key = FORMAT_ALIASES.get(key, key)
    return key if key in WRITERS else None


def report_stem(result: ScanResult) -> str:
    """Timestamped filename stem shared by every report of one scan."""
    stem = getattr(result, "stem", None)
    return stem or f"subsonar_{result.config.domain}_{_timestamp(compact=True)}"


def default_paths(result: ScanResult, output_dir: Path) -> dict[str, Path]:
    stem = report_stem(result)
    return {
        fmt: Path(output_dir) / f"{stem}{WRITERS[fmt][1]}" for fmt in CANONICAL_FORMATS
    }


def write_reports(
    result: ScanResult,
    output_dir: Path,
    formats: Iterable[str] = ("json", "csv", "md", "html", "txt"),
) -> dict[str, Path]:
    """Write every requested format and return ``{canonical format: path}``.

    Aliases (``markdown``, ``text``) resolve to their canonical format, so asking
    for ``markdown`` writes the same timestamped ``.md`` file as ``md`` instead of
    a timestamp-less file that overwrote the previous run's report.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = default_paths(result, output_dir)
    written: dict[str, Path] = {}
    for name in formats:
        fmt = canonical_format(name)
        if fmt is None:
            continue
        writer, suffix = WRITERS[fmt]
        target = paths.get(fmt) or output_dir / f"{report_stem(result)}{suffix}"
        written[fmt] = writer(result, target)
    return written


def _timestamp(compact: bool = False) -> str:
    import datetime as _dt

    now = _dt.datetime.now()
    return now.strftime("%Y%m%d-%H%M%S") if compact else now.isoformat(timespec="seconds")


def findings_table_rows(findings: Sequence[Finding]) -> list[dict[str, Any]]:
    return [finding.to_row() for finding in findings]

