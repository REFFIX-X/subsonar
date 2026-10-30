"""Install-time edge cases that should fail quickly and say why."""

from __future__ import annotations

import os

import pytest

from subsonar.core.config import ScanConfig
from subsonar.core.dns import AnonymousResolver, ResolverPoolUnreachable
from subsonar.core.engine import ScanEngine
from subsonar.core.events import EventBus


async def test_health_check_with_no_live_resolver_stops_the_scan(monkeypatch) -> None:
    async def dead(self, *args, **kwargs):  # noqa: ANN001, ANN202
        return {server: "TimeoutError" for server in self.servers}

    monkeypatch.setattr(AnonymousResolver, "health_check", dead)
    engine = ScanEngine(
        ScanConfig(domain="example.com", geoip=False, geoip_download=False),
        profile=1,
        bus=EventBus(),
    )
    with pytest.raises(ResolverPoolUnreachable, match=r"0/18"):
        await engine._phase_health()


async def test_health_check_with_one_live_resolver_continues(monkeypatch) -> None:
    async def one_live(self, *args, **kwargs):  # noqa: ANN001, ANN202
        servers = list(self.servers)
        report = {server: "TimeoutError" for server in servers}
        report[servers[0]] = None
        self._healthy = {servers[0]}
        return report

    monkeypatch.setattr(AnonymousResolver, "health_check", one_live)
    engine = ScanEngine(
        ScanConfig(domain="example.com", geoip=False, geoip_download=False),
        profile=1,
        bus=EventBus(),
    )
    await engine._phase_health()
    engine._resolver.stop_health_loop()
    assert engine._resolver.live_servers


def test_cli_reports_an_unreachable_pool_and_exits_1(monkeypatch, capsys) -> None:
    import subsonar.cli as cli

    async def boom(*args, **kwargs):  # noqa: ANN001, ANN202
        raise ResolverPoolUnreachable(
            "no anonymous DNS resolver answered UDP/53 (0/18)"
        )

    monkeypatch.setattr("subsonar.ui.console.run_console", boom)
    code = cli.main(["scan", "example.com", "--no-geo", "--no-reports"])
    assert code == cli.EXIT_ERROR
    assert "0/18" in capsys.readouterr().err


def test_init_in_a_read_only_directory_is_a_clean_error(tmp_path, monkeypatch, capsys) -> None:
    import subsonar.cli as cli

    readonly = tmp_path / "readonly"
    readonly.mkdir()
    readonly.chmod(0o555)
    monkeypatch.chdir(readonly)
    try:
        code = cli.main(["init"])
    finally:
        os.chmod(readonly, 0o755)
    assert code == cli.EXIT_ERROR
    assert "cannot write" in capsys.readouterr().err


def test_invalid_domains_are_a_clean_error(capsys) -> None:
    import subsonar.cli as cli

    assert cli.main(["scan", "localhost"]) == cli.EXIT_ERROR
    assert "invalid target domain" in capsys.readouterr().err
    assert cli.main(["scan", "co.uk"]) == cli.EXIT_ERROR
    assert "public suffix" in capsys.readouterr().err
    assert cli.main(["scan", "example.com", "--ports", "nope"]) == cli.EXIT_ERROR
    assert "invalid port" in capsys.readouterr().err.lower()
