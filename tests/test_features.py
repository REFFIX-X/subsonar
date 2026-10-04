"""Tests for the newer subsystems: service detection, template checks, JSONL."""

from __future__ import annotations

import json
from pathlib import Path

from subsonar.core.services import detect_service
from subsonar.core.templates import run_template_checks
from subsonar.reporters import JsonlSink, write_jsonl


# --------------------------------------------------------------------------- #
# Service detection
# --------------------------------------------------------------------------- #


def test_detect_service_banners() -> None:
    assert detect_service(22, b"SSH-2.0-OpenSSH_8.9") == "SSH"
    assert detect_service(25, b"220 mail.example.com ESMTP") == "SMTP"
    assert detect_service(21, b"220-FileZilla Server") == "FTP"
    assert detect_service(5900, b"RFB 003.008") == "VNC"
    assert detect_service(3389, b"\x03\x00\x00\x13") == "RDP"
    assert detect_service(3306, b"\n8.0.36\x00mysql") == "MySQL"


def test_detect_service_uses_port_default_when_silent() -> None:
    assert detect_service(6379, None) == "Redis"
    assert detect_service(5432, b"") == "PostgreSQL"
    assert detect_service(27017, b"") == "MongoDB"
    assert detect_service(8000, b"") is None  # web port, no default


# --------------------------------------------------------------------------- #
# Template checks
# --------------------------------------------------------------------------- #


class _FakeProber:
    def __init__(self, statuses: dict[str, int]) -> None:
        self.statuses = statuses
        self.calls: list[str] = []

    async def probe_status(self, host: str, port: int, path: str, *, scheme: str) -> dict:
        self.calls.append(path)
        return {"status": self.statuses.get(path, 404)}


async def test_template_check_detects_exposed_dotenv() -> None:
    probe = _FakeProber({"/.env": 200, "/.git/config": 200})
    matches = await run_template_checks(probe, "http", "app.example.com", "1.2.3.4", 80)
    ids = {m.id for m in matches}
    assert "dotenv-exposed" in ids
    assert "git-config-exposed" in ids
    match = next(m for m in matches if m.id == "dotenv-exposed")
    assert match.severity == "critical"
    assert match.evidence == "/.env → HTTP 200"


async def test_template_check_no_matches_on_404() -> None:
    probe = _FakeProber({})
    matches = await run_template_checks(probe, "http", "app.example.com", "1.2.3.4", 80)
    assert matches == []


async def test_template_check_requires_probe_status() -> None:
    matches = await run_template_checks(None, "http", "x.example.com", "1.2.3.4", 80)
    assert matches == []


# --------------------------------------------------------------------------- #
# JSONL export
# --------------------------------------------------------------------------- #


def test_jsonl_sink_writes_ndjson(tmp_path: Path) -> None:
    path = tmp_path / "sub.jsonl"
    sink = JsonlSink(path, domain="example.com")
    sink.open(meta={"tool": "subsonar", "target": "example.com"})
    sink.finding({"subdomain": "a.example.com", "port": 443})
    sink.finding({"subdomain": "b.example.com", "port": 80})
    sink.close()

    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["event"] == "meta"
    assert [line["event"] for line in lines[1:]] == ["finding", "finding"]
    assert lines[1]["data"]["subdomain"] == "a.example.com"


def test_write_jsonl_format(tmp_path: Path) -> None:
    from subsonar.core.config import ScanConfig
    from subsonar.core.engine import ScanResult
    from subsonar.core.profiles import get_profile

    config = ScanConfig(domain="example.com")
    result = ScanResult(config, get_profile(1))
    path = write_jsonl(result, tmp_path / "report.jsonl")
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["event"] == "meta"
    assert lines[0]["data"]["target"] == "example.com"


def test_wordlist_permutation_config_flows() -> None:
    from subsonar.core.config import ScanConfig
    from subsonar.core.workflow import ScanSettings

    settings = ScanSettings(wordlist_permutations=True, wordlist_permutation_limit=123)
    config = settings.build_config("example.com", profile=settings.resolve_profile())
    assert config.wordlist_permutations is True
    assert config.wordlist_permutation_limit == 123
