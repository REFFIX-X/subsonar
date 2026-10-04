"""Third-party hosting: the Office 365-style policy, the CDN/PaaS exceptions.

Hosts whose CNAME chain lands on a shared *tenant* (Exchange Online, SharePoint,
Entra ID, Okta, Auth0, …) are skipped entirely — no port sweep, no HTTP probe, no
finding.  Hosts fronted by a CDN/PaaS/hosting provider (CloudFront, S3, Heroku,
Netlify, Akamai, …) are the target's own service and **are** scanned; the report
just records where they live.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from subsonar.core.config import PORT_MATRIX, ScanConfig
from subsonar.core.dns import DNSResult
from subsonar.core.engine import ScanEngine
from subsonar.core.events import EventBus
from subsonar.core.providers import (
    PROVIDERS,
    cname_providers,
    detect_batch,
    detect_provider,
    is_third_party,
    provider_for,
    provider_name,
)
from subsonar.reporters import CSV_COLUMNS, write_reports
from subsonar.core.engine import Finding

# --------------------------------------------------------------------------- #
# Table + ordering invariant
# --------------------------------------------------------------------------- #


def test_table_entries_are_unique_and_most_specific_first() -> None:
    suffixes = [provider.suffix for provider in PROVIDERS]
    assert len(suffixes) == len(set(suffixes))
    for index, provider in enumerate(PROVIDERS):
        for later in PROVIDERS[index + 1 :]:
            assert not provider.matches(later.suffix), (
                f"{provider.suffix!r} shadows the later {later.suffix!r}"
            )


def test_order_validator_rejects_a_shadowing_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """A broad suffix listed before a narrow one must fail at import time."""
    import subsonar.core.providers as providers

    # A broad suffix listed before a narrower one it contains
    # (``protection.outlook.com`` before ``mail.protection.outlook.com``) makes
    # the narrow entry unreachable.
    broken = (providers.Provider("Broad", "protection.outlook.com", "x"),) + PROVIDERS
    monkeypatch.setattr(providers, "PROVIDERS", broken)
    with pytest.raises(RuntimeError, match="shadows"):
        providers._validate_order()


def test_order_validator_rejects_duplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    import subsonar.core.providers as providers

    duplicated = PROVIDERS + (PROVIDERS[0],)
    monkeypatch.setattr(providers, "PROVIDERS", duplicated)
    with pytest.raises(RuntimeError, match="duplicate"):
        providers._validate_order()


def test_specific_providers_beat_generic_ones() -> None:
    # Regression: ``amazonaws.com`` used to precede the more specific entries, so
    # ELB / S3 hosts were reported as plain "AWS".
    assert provider_name("my-lb.eu-west-1.elb.amazonaws.com") == "AWS ELB"
    assert provider_name("bucket.s3.amazonaws.com") == "AWS S3"
    assert provider_name("d111111abcdef8.cloudfront.net") == "AWS CloudFront"
    assert provider_name("acme.github.io") == "GitHub Pages"
    assert provider_name("unknown.example.net") is None
    assert provider_for("") is None and provider_for(None) is None


def test_cname_providers_mirrors_the_table() -> None:
    pairs = cname_providers()
    assert pairs[0][0] == PROVIDERS[0].suffix
    assert all(name and suffix for suffix, name in pairs)


# --------------------------------------------------------------------------- #
# Chain detection
# --------------------------------------------------------------------------- #


def test_office365_chain_is_detected_from_the_terminal_hop() -> None:
    chain = ["login.example.com", "example-com.mail.protection.outlook.com"]
    provider = detect_provider(chain, "autodiscover.example.com")
    assert provider is not None
    assert provider.name == "Microsoft 365 (Exchange Online)"
    assert provider.category == "mail"
    assert provider.skip is True
    assert is_third_party(chain, "autodiscover.example.com") is True


def test_cdn_paas_and_hosting_hosts_are_still_scanned() -> None:
    """Only the Office 365-style families are skipped; CDN/PaaS vhosts are ours."""
    for target in (
        "d111111abcdef8.cloudfront.net",
        "thing.eu-west-1.elb.amazonaws.com",
        "bucket.s3.amazonaws.com",
        "acme.herokuapp.com",
        "site.netlify.app",
        "app.vercel.app",
        "acme.github.io",
        "edge.akamaiedge.net",
        "docs.readthedocs.io",
        "acme.zendesk.com",
    ):
        provider = detect_provider([target], "assets.example.com")
        assert provider is not None, target
        assert provider.skip is False, f"{target} must still be scanned"
        assert is_third_party([target], "assets.example.com") is False, target


def test_skip_categories_are_the_office365_families() -> None:
    from subsonar.core.providers import SKIP_CATEGORIES

    assert SKIP_CATEGORIES == frozenset({"mail", "identity", "collaboration"})
    categories = {provider.category for provider in PROVIDERS}
    assert categories.issuperset(SKIP_CATEGORIES)
    assert "cdn" in categories and "paas" in categories  # both scanned


def test_identity_and_collaboration_hosts_are_skipped_too() -> None:
    for target in (
        "login.microsoftonline.com",
        "acme.sharepoint.com",
        "acme.onmicrosoft.com",
        "acme.okta.com",
        "acme.auth0.com",
        "mailgun.org",
    ):
        assert is_third_party([target], "x.example.com") is True, target


def test_own_infrastructure_is_not_provider_hosted() -> None:
    assert detect_provider([], "portal.example.com") is None
    assert is_third_party(["api.example.com"], "portal.example.com") is False


def test_detect_batch_maps_only_provider_hosts() -> None:
    found = detect_batch(
        {
            "a.example.com": ["a.example.com", "thing.herokuapp.com"],
            "b.example.com": [],
        }
    )
    assert list(found) == ["a.example.com"]
    assert found["a.example.com"].name == "Heroku"



# --------------------------------------------------------------------------- #
# Engine behaviour: third-party hosts are never scanned, own hosts are
# --------------------------------------------------------------------------- #


class _FakeScanner:
    """Returns one open port for every host it is asked to sweep."""

    def __init__(self, open_port: int = 80) -> None:
        self.open_port = open_port
        self.calls: list[tuple[list[str], tuple[int, ...]]] = []

    async def sweep_hosts(self, hosts, ports, *, on_open=None):  # noqa: ANN001, ANN202
        self.calls.append(([host for host, _ in hosts], tuple(ports)))
        from subsonar.core.scanner import PortResult

        return {
            host: [
                PortResult(
                    host=host,
                    ip=ip,
                    port=self.open_port,
                    label="HTTP",
                    open=True,
                    failure="open",
                )
            ]
            for host, ip in hosts
        }


class _FakeProbe:
    """Reports one plain web interface for whatever it is asked to probe."""

    def __init__(self) -> None:
        self.probed: list[str] = []

    async def probe_multi(self, host, ip, ports):  # noqa: ANN001, ANN202
        self.probed.append(host)
        from subsonar.core.web_probe import WebProbeResult

        result = WebProbeResult(
            host=host,
            ip=ip,
            port=ports[0],
            scheme="http",
            url=f"http://{host}:{ports[0]}",
        )
        result.status = 200
        result.ok = True
        result.kind = "interface"
        result.title = f"{host} portal"
        result.content_length = 4096
        return [result]


def _engine(**overrides) -> ScanEngine:  # noqa: ANN003
    config = ScanConfig(
        domain="example.com", profile_id=3, fingerprint_findings=False, **overrides
    )
    return ScanEngine(config, profile=3, bus=EventBus())


def _owned(host: str) -> DNSResult:
    return DNSResult(name=host, addresses=["192.0.2.10"])


def _hosted(host: str) -> DNSResult:
    """An Office 365 / Exchange Online tenant (mail) — must be skipped."""
    result = DNSResult(name=host, addresses=["192.0.2.20"])
    result.cnames = ["example-com.mail.protection.outlook.com"]
    return result


def _cdn_hosted(host: str) -> DNSResult:
    """A CDN-fronted host — the target's own service, must be scanned."""
    result = DNSResult(name=host, addresses=["192.0.2.30"])
    result.cnames = ["d111111abcdef8.cloudfront.net"]
    return result


@pytest.mark.asyncio
async def test_provider_hosts_are_skipped_entirely() -> None:
    """Office 365-style hosts get no port sweep, no probe and no finding."""
    engine = _engine()
    scanner = _FakeScanner()
    probe = _FakeProbe()
    engine._scanner = scanner  # type: ignore[assignment]
    engine._probe = probe  # type: ignore[assignment]

    await engine._sweep_batch(
        [_owned("portal.example.com"), _hosted("autodiscover.example.com")],
        list(PORT_MATRIX),
    )

    # Only the target's own host was swept, with the full matrix.
    assert len(scanner.calls) == 1, scanner.calls
    assert scanner.calls[0][0] == ["portal.example.com"]
    assert len(scanner.calls[0][1]) == len(PORT_MATRIX)
    # Only the target's own host reached the HTTP prober.
    assert probe.probed == ["portal.example.com"]
    assert [finding.subdomain for finding in engine.result.findings] == [
        "portal.example.com"
    ]
    # The skipped host is recorded with its provider and the reason.
    assert engine.result.provider_hosts == {
        "autodiscover.example.com": "Microsoft 365 (Exchange Online)"
    }
    assert engine.result.filtered["autodiscover.example.com"] == (
        "third-party host (Microsoft 365 (Exchange Online)) — not scanned"
    )
    assert engine.bus.snapshot()["provider_skipped"] == 1


@pytest.mark.asyncio
async def test_provider_skip_can_be_disabled() -> None:
    engine = _engine(skip_provider_hosts=False)
    scanner = _FakeScanner()
    engine._scanner = scanner  # type: ignore[assignment]
    engine._probe = _FakeProbe()  # type: ignore[assignment]

    await engine._sweep_batch([_hosted("autodiscover.example.com")], list(PORT_MATRIX))

    assert scanner.calls == [(["autodiscover.example.com"], tuple(PORT_MATRIX))]
    assert engine.bus.snapshot()["provider_skipped"] == 0
    assert engine.result.filtered == {}  # nothing was skipped as third-party


@pytest.mark.asyncio
async def test_scanned_provider_host_still_carries_its_provider() -> None:
    """With the skip disabled the finding records where the host is hosted."""
    engine = _engine(skip_provider_hosts=False)
    engine._scanner = _FakeScanner()  # type: ignore[assignment]
    engine._probe = _FakeProbe()  # type: ignore[assignment]

    await engine._sweep_batch([_hosted("autodiscover.example.com")], list(PORT_MATRIX))

    finding = engine.result.findings[0]
    assert finding.provider == "Microsoft 365 (Exchange Online)"
    assert finding.to_row()["provider"] == "Microsoft 365 (Exchange Online)"


@pytest.mark.asyncio
async def test_all_provider_batch_never_touches_the_network() -> None:
    engine = _engine()
    scanner = _FakeScanner()
    probe = _FakeProbe()
    engine._scanner = scanner  # type: ignore[assignment]
    engine._probe = probe  # type: ignore[assignment]

    await engine._sweep_batch(
        [_hosted("autodiscover.example.com"), _hosted("mail.example.com")],
        list(PORT_MATRIX),
    )

    assert scanner.calls == []
    assert probe.probed == []
    assert engine.result.findings == []
    assert engine.bus.snapshot()["provider_skipped"] == 2
    assert any(
        "Skipped 2 Office 365-style tenant host(s)" in event.message
        for event in engine.bus.history()
    )


@pytest.mark.asyncio
async def test_cdn_fronted_host_is_scanned_like_any_other() -> None:
    """A CDN/PaaS vhost is the target's own service: sweep it, label it."""
    engine = _engine()
    scanner = _FakeScanner()
    probe = _FakeProbe()
    engine._scanner = scanner  # type: ignore[assignment]
    engine._probe = probe  # type: ignore[assignment]

    await engine._sweep_batch([_cdn_hosted("assets.example.com")], list(PORT_MATRIX))

    assert scanner.calls == [(["assets.example.com"], tuple(PORT_MATRIX))]
    assert probe.probed == ["assets.example.com"]
    assert engine.bus.snapshot()["provider_skipped"] == 0
    assert engine.result.provider_hosts == {}  # nothing was skipped
    assert engine.result.filtered == {}
    finding = engine.result.findings[0]
    assert finding.provider == "AWS CloudFront"
    assert finding.to_row()["provider"] == "AWS CloudFront"


@pytest.mark.asyncio
async def test_mixed_batch_skips_only_the_tenant_host() -> None:
    engine = _engine()
    scanner = _FakeScanner()
    probe = _FakeProbe()
    engine._scanner = scanner  # type: ignore[assignment]
    engine._probe = probe  # type: ignore[assignment]

    await engine._sweep_batch(
        [
            _owned("portal.example.com"),
            _cdn_hosted("assets.example.com"),
            _hosted("autodiscover.example.com"),
        ],
        list(PORT_MATRIX),
    )

    assert scanner.calls[0][0] == ["portal.example.com", "assets.example.com"]
    assert sorted(probe.probed) == ["assets.example.com", "portal.example.com"]
    assert engine.result.provider_hosts == {
        "autodiscover.example.com": "Microsoft 365 (Exchange Online)"
    }
    assert engine.bus.snapshot()["provider_skipped"] == 1



# --------------------------------------------------------------------------- #
# Reporting + configuration plumbing
# --------------------------------------------------------------------------- #


def _result_with_provider(provider: str | None):
    engine = ScanEngine(ScanConfig(domain="example.com"), profile=3, bus=EventBus())
    engine.result.findings.append(
        Finding(
            subdomain="autodiscover.example.com",
            ip="192.0.2.20",
            port=443,
            scheme="https",
            url="https://autodiscover.example.com",
            status=200,
            title="Outlook",
            provider=provider,
        )
    )
    if provider:
        engine.result.provider_hosts = {"autodiscover.example.com": provider}
    return engine.result


def test_provider_is_reported_in_json_csv_markdown_and_html(tmp_path: Path) -> None:
    assert "provider" in CSV_COLUMNS
    provider = "Microsoft 365 (Exchange Online)"
    result = _result_with_provider(provider)
    written = write_reports(result, tmp_path, formats=("json", "csv", "md", "html"))

    payload = written["json"].read_text(encoding="utf-8")
    assert provider in payload
    assert "provider_hosts" in payload

    csv_text = written["csv"].read_text(encoding="utf-8")
    assert "provider" in csv_text.splitlines()[0]
    assert provider in csv_text

    markdown = written["md"].read_text(encoding="utf-8")
    assert "## Third-party hosted (not scanned)" in markdown
    assert f"| `autodiscover.example.com` | {provider} |" in markdown

    html = written["html"].read_text(encoding="utf-8")
    assert provider in html


def test_finding_without_a_provider_reports_blank() -> None:
    assert _result_with_provider(None).findings[0].to_row()["provider"] == ""


def test_scan_config_defaults_expose_the_switch() -> None:
    config = ScanConfig(domain="example.com")
    assert config.skip_provider_hosts is True
    assert not hasattr(config, "provider_ports")


def test_toml_settings_and_cli_flag_round_trip() -> None:
    from main import _settings_from_args, build_parser
    from subsonar.core.workflow import ScanSettings

    assert ScanSettings().skip_provider_hosts is True
    mapped = ScanSettings.from_mapping({"scan": {"skip_provider_hosts": False}})
    assert mapped.skip_provider_hosts is False

    args = build_parser().parse_args(["scan", "example.com", "--scan-provider-hosts"])
    settings = _settings_from_args(args)
    assert settings.skip_provider_hosts is False
    assert settings.build_config("example.com").skip_provider_hosts is False

    default = _settings_from_args(build_parser().parse_args(["scan", "example.com"]))
    assert default.skip_provider_hosts is True


def test_report_aliases_write_one_timestamped_file(tmp_path: Path) -> None:
    """``markdown`` must not write a second, timestamp-less report."""
    result = _result_with_provider(None)
    written = write_reports(result, tmp_path, formats=("md", "markdown", "text", "txt"))
    assert set(written) == {"md", "txt"}
    assert written["md"].name.startswith("subsonar_example.com_")
    assert len(list(tmp_path.glob("*.md"))) == 1
