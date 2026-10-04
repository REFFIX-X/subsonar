"""Passive → brute must never clear what the passive pass already found.

The regression this file guards against: running profile 1 and then profile 3 on
the same domain produced an empty findings table, because the second run started
from a fresh :class:`ScanResult`.  The engine now merges the newest report of the
same domain into the new run and marks those rows ``from_previous_scan``.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import pytest

from subsonar.core.config import ScanConfig
from subsonar.core.engine import Finding, ScanEngine
from subsonar.core.events import EventBus
from subsonar.core.workflow import ScanSettings, load_previous_report


def _finding_row(
    host: str = "legacy.example.com", ip: str = "203.0.113.9", port: int = 443
) -> dict[str, object]:
    """A JSON report row exactly as :meth:`Finding.to_dict` writes it."""
    return {
        "subdomain": host,
        "ip": ip,
        "port": port,
        "port_label": "https",
        "status": 200,
        "kind": "interface",
        "title": "Legacy portal",
        "scheme": "https",
        "url": f"https://{host}",
        "final_url": "",
        "server": "nginx",
        "tls": True,
        "tls_version": "TLSv1.3",
        "also_on_ports": "8443",
        "favicon_hash": "123456",
        "technologies": "nginx,React",
        "data_files": "/robots.txt:200",
        "confidence": 88,
        "confidence_label": "high",
        "confidence_why": "title, TLS",
        "sources": "crtsh,osint",
        "provider": "",
        "country_code": "DK",
        "country": "Denmark",
        "asn": 13335,
        "as_org": "CLOUDFLARENET",
        "ptr": "legacy.example.com",
        "carried_over": "",
        "latency_ms": 12.5,
        "content_type": "text/html",
        "content_length": 2048,
        "declared_length": 2048,
        "redirect_chain": [],
        "fingerprint": "nginx",
        "headers": {"server": "nginx"},
        "confidence_reasons": ["title", "TLS"],
        "confidence_penalties": [],
        "from_previous_scan": False,
        "discovered_at": time.time() - 3600,
    }


def _write_report(output_dir: Path, domain: str, findings: list[dict]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"subsonar_{domain}_20250101-1200.json"
    path.write_text(
        json.dumps(
            {
                "config": {"domain": domain},
                "finished_at": time.time() - 600,
                "findings": findings,
            }
        ),
        encoding="utf-8",
    )
    return path


def _engine(domain: str = "example.com", **kwargs) -> ScanEngine:
    config = ScanConfig(domain=domain, **kwargs)
    return ScanEngine(config, profile=3, bus=EventBus())


# --------------------------------------------------------------------------- #
# Finding round-trip
# --------------------------------------------------------------------------- #


def test_finding_from_dict_round_trips_every_field() -> None:
    row = _finding_row()
    finding = Finding.from_dict(row)
    assert finding.subdomain == "legacy.example.com"
    assert finding.port == 443 and finding.status == 200
    assert finding.aliases == [8443]
    assert finding.technologies == ["nginx", "React"]
    assert finding.sources == ["crtsh", "osint"]
    assert finding.data_files == {"/robots.txt": 200}
    assert finding.confidence == 88 and finding.confidence_label == "high"
    assert finding.asn == 13335 and finding.as_org == "CLOUDFLARENET"
    assert finding.ptr == "legacy.example.com"
    assert finding.geo_label == "🇩🇰 DK"
    assert finding.tls is True and finding.tls_version == "TLSv1.3"
    # Marked as carried over, and its own row reflects that.
    assert finding.from_previous_scan is True
    assert finding.to_row()["carried_over"] == "yes"
    assert finding.to_dict()["from_previous_scan"] is True


def test_finding_from_dict_is_lenient() -> None:
    minimal = Finding.from_dict({"subdomain": "a.example.com", "port": "8443"})
    assert minimal.port == 8443 and minimal.scheme == "http"
    assert minimal.kind == "interface" and minimal.aliases == []
    assert minimal.status is None and minimal.country_code is None
    broken = Finding.from_dict(
        {"subdomain": "b.example.com", "port": "not-a-port", "also_on_ports": "x,,443"}
    )
    assert broken.port == 0 and broken.aliases == [443]


# --------------------------------------------------------------------------- #
# Seeding a new run from the previous report
# --------------------------------------------------------------------------- #


def test_previous_findings_are_merged_not_cleared(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _write_report(output, "example.com", [_finding_row(), _finding_row("api.example.com")])
    engine = _engine(output_dir=output)
    seeded = engine._seed_previous_findings()
    assert seeded == 2
    assert engine.result.carried_over == 2
    assert [finding.subdomain for finding in engine.result.findings] == [
        "legacy.example.com",
        "api.example.com",
    ]
    assert all(finding.from_previous_scan for finding in engine.result.findings)
    # ... and the new run adds to them instead of replacing them.
    engine.result.findings.append(
        Finding(
            subdomain="new.example.com",
            ip="203.0.113.10",
            port=443,
            scheme="https",
            url="https://new.example.com",
            status=200,
            title="New",
        )
    )
    assert len(engine.result.findings) == 3


def test_seeding_emits_a_visible_log_line(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _write_report(output, "example.com", [_finding_row()])
    bus = EventBus()
    config = ScanConfig(domain="example.com", output_dir=output)
    engine = ScanEngine(config, profile=3, bus=bus)
    engine._seed_previous_findings()
    messages = [event.message for event in bus.history()]
    assert any("Merged 1 finding(s) from the previous scan" in text for text in messages)
    assert any("never cleared" in text for text in messages)
    snapshot = bus.snapshot()
    assert snapshot["carried_over"] == 1


def test_no_previous_report_is_a_no_op(tmp_path: Path) -> None:
    engine = _engine(output_dir=tmp_path / "empty")
    assert engine._seed_previous_findings() == 0
    assert engine.result.carried_over == 0
    assert engine.result.findings == []


def test_carry_over_can_be_switched_off(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _write_report(output, "example.com", [_finding_row()])
    engine = _engine(output_dir=output, carry_over=False)
    assert engine._seed_previous_findings() == 0
    assert engine.result.findings == []


def test_each_domain_seeds_only_from_its_own_report(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _write_report(output, "example.com", [_finding_row("a.example.com")])
    _write_report(output, "other.test", [_finding_row("b.other.test")])
    engine = _engine("other.test", output_dir=output)
    assert engine._seed_previous_findings() == 1
    assert engine.result.findings[0].subdomain == "b.other.test"


def test_a_corrupt_report_is_ignored(tmp_path: Path) -> None:
    output = tmp_path / "out"
    output.mkdir(parents=True)
    (output / "subsonar_example.com_broken.json").write_text("{not json", encoding="utf-8")
    engine = _engine(output_dir=output)
    assert engine._seed_previous_findings() == 0


def test_incomplete_rows_are_skipped(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _write_report(
        output,
        "example.com",
        [
            _finding_row(),
            {"subdomain": "no-port.example.com"},
            {"port": 443},
            "not-a-dict",  # type: ignore[list-item]
            {"subdomain": "ok.example.com", "port": "8443", "scheme": "https"},
        ],
    )
    engine = _engine(output_dir=output)
    assert engine._seed_previous_findings() == 2
    assert [finding.subdomain for finding in engine.result.findings] == [
        "legacy.example.com",
        "ok.example.com",
    ]


def test_the_engine_merges_the_previous_report_on_start(tmp_path: Path, monkeypatch) -> None:
    """Full ``run()`` path: the merge happens before anything is collected."""
    from subsonar.core import engine as engine_module

    output = tmp_path / "out"
    _write_report(output, "example.com", [_finding_row()])
    seen: dict[str, int] = {}

    async def fake_collect(self) -> list[str]:
        # By the time candidates are collected the previous rows must be there.
        seen["findings"] = len(self.result.findings)
        seen["carried"] = self.result.carried_over
        return []

    monkeypatch.setattr(engine_module.ScanEngine, "_collect_candidates", fake_collect)
    monkeypatch.setattr(engine_module.ScanEngine, "_phase_health", _noop)
    monkeypatch.setattr(engine_module.ScanEngine, "_phase_geo", _noop)
    monkeypatch.setattr(engine_module.ScanEngine, "_phase_dns_intel", _noop)
    monkeypatch.setattr(engine_module.ScanEngine, "_phase_mining", _noop)
    monkeypatch.setattr(engine_module.ScanEngine, "_enrich_findings", _noop)
    config = ScanConfig(domain="example.com", output_dir=output, offline=True)
    engine = ScanEngine(config, profile=3, bus=EventBus())
    result = asyncio.run(engine.run())
    assert seen == {"findings": 1, "carried": 1}
    assert result.carried_over == 1
    assert result.findings[0].from_previous_scan is True
    assert "from prev. scan : 1 finding(s) merged (nothing was cleared)" in (
        result.summary_lines()
    )
    assert result.to_dict()["carried_over"] == 1


async def _noop(self, *args: Any, **kwargs: Any) -> None:
    return None


# --------------------------------------------------------------------------- #
# Dedupe: a re-confirmed row must beat the carried-over copy
# --------------------------------------------------------------------------- #


def _mk(host: str, port: int, *, carried: bool, scheme: str = "https", status: int | None = 200):
    finding = Finding(
        subdomain=host,
        ip="203.0.113.9",
        port=port,
        scheme=scheme,
        url=f"{scheme}://{host}",
        status=status,
        title="Legacy portal",
    )
    finding.fingerprint = "nginx"
    finding.from_previous_scan = carried
    return finding


def test_a_reconfirmed_row_replaces_the_carried_over_copy() -> None:
    engine = _engine()
    stale = _mk("legacy.example.com", 443, carried=True)
    fresh = _mk("legacy.example.com", 443, carried=False)
    engine.result.findings = [stale, fresh]
    engine._dedupe_findings()
    assert len(engine.result.findings) == 1
    assert engine.result.findings[0] is fresh
    assert engine.result.findings[0].from_previous_scan is False


def test_a_carried_over_row_survives_when_the_new_run_misses_it() -> None:
    engine = _engine()
    engine.result.findings = [_mk("gone.example.com", 443, carried=True)]
    engine._dedupe_findings()
    assert len(engine.result.findings) == 1
    assert engine.result.findings[0].from_previous_scan is True
    assert engine.result.carried_over == 0  # nothing new was merged *this* run


def test_duplicate_ports_still_collapse_with_provenance() -> None:
    engine = _engine()
    engine.result.findings = [
        _mk("legacy.example.com", 8080, carried=True),
        _mk("legacy.example.com", 443, carried=True),
        _mk("legacy.example.com", 8443, carried=True),
    ]
    engine._dedupe_findings()
    assert len(engine.result.findings) == 1
    winner = engine.result.findings[0]
    assert winner.port == 443
    assert winner.aliases == [8080, 8443]
    assert winner.from_previous_scan is True


def test_a_carried_over_row_on_a_rotated_address_is_dropped() -> None:
    """Round-robin DNS must not leave the same URL in the table twice."""
    engine = _engine()
    stale = _mk("www.example.com", 443, carried=True)  # ip 203.0.113.9
    fresh = _mk("www.example.com", 443, carried=False)
    fresh.ip = "198.51.100.7"  # the edge answered with a different address
    engine.result.findings = [stale, fresh]
    engine._dedupe_findings()
    assert engine.result.findings == [fresh]
    assert engine.result.filtered["www.example.com:443"] == "superseded by this run"
    messages = [event.message for event in engine.bus.history()]
    assert any("address rotated from 203.0.113.9" in text for text in messages)


def test_a_carried_over_row_is_kept_when_only_the_port_was_not_rescanned() -> None:
    engine = _engine()
    stale = _mk("old.example.com", 8443, carried=True)
    fresh = _mk("old.example.com", 443, carried=False)
    engine.result.findings = [stale, fresh]
    engine._dedupe_findings()
    # 443 is the canonical port, but the two rows are different ports of the same
    # host, so the old one becomes an alias — not two findings.
    assert len(engine.result.findings) == 1
    assert engine.result.findings[0].port == 443
    assert engine.result.findings[0].aliases == [8443]

