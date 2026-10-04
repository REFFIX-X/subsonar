"""Offline geo/ASN enrichment: parsers, index, lookups, flags, engine wiring.

No test in this file touches the network: the index is built from synthetic rows
with :func:`subsonar.core.geoip.write_index`, which is exactly the same code path
the real build uses once the download is done.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from subsonar.core import geoip
from subsonar.core.config import ScanConfig
from subsonar.core.engine import Finding


@pytest.fixture(autouse=True)
def _clean_cache() -> None:
    geoip.reset_cache()
    yield
    geoip.reset_cache()


def _rows() -> list[tuple[int, str, str, int, str, str]]:
    """Three IPv4 ranges, one IPv6 range — a miniature world map."""
    return [
        (4, "17e32600", "17e326ff", 13335, "US", "CLOUDFLARENET"),
        (4, "02690000", "0270ffff", 0, "DK", ""),
        (4, "08080800", "080808ff", 15169, "US", "GOOGLE"),
        (6, "20010db8000000000000000000000000", "20010db8ffffffffffffffffffffffff", 0, "NL", ""),
    ]


@pytest.fixture
def cache(tmp_path: Path) -> Path:
    directory = tmp_path / "cache"
    geoip.write_index(_rows(), directory, sources=("test-fixture",))
    return directory


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #


def test_parse_ip2asn_u32_line() -> None:
    row = geoip.parse_line(
        "23.227.38.0\t23.227.38.255\t13335\tUS\tCLOUDFLARENET", "v4"
    )
    assert row == (4, "17e32600", "17e326ff", 13335, "US", "CLOUDFLARENET")
    numeric = geoip.parse_line(
        f"{int.from_bytes(bytes([23, 227, 38, 0]), 'big')}\t"
        f"{int.from_bytes(bytes([23, 227, 38, 255]), 'big')}\t13335\tUS\tCLOUDFLARENET",
        "v4u32",
    )
    assert numeric == row


def test_parse_line_rejects_malformed_rows() -> None:
    assert geoip.parse_line("", "v4") is None
    assert geoip.parse_line("# a comment", "v4") is None
    assert geoip.parse_line("only-one-column", "v4") is None
    assert geoip.parse_line("1.2.3.4\t1.2.3.5\tnot-a-number\tUS\tX", "v4") is None
    assert geoip.parse_line("8.8.8.8\t8.8.8.7\t15169\tUS\tGOOGLE", "v4") is None
    # A v6 file must not accept v4 ranges and vice versa.
    assert geoip.parse_line("8.8.8.0\t8.8.8.255\t15169\tUS\tG", "v6") is None
    assert geoip.parse_line("0\t16777215\t0\t\t", "v4u32") == (4, "00000000", "00ffffff", 0, "", "")
    assert geoip.parse_line("-1\t10\t1\tUS\tX", "v4u32") is None


def test_parse_rir_delegation_lines() -> None:
    row = geoip.parse_rir_line("ripencc|DK|ipv4|2.105.0.0|524288|20250312|allocated|")
    assert row is not None
    family, start, end, asn, country, org = row
    assert (family, country, asn, org) == (4, "DK", 0, "")
    assert start == geoip.address_key("2.105.0.0")[1]
    assert int(end, 16) - int(start, 16) + 1 == 524288
    v6 = geoip.parse_rir_line("apnic|CN|ipv6|2400:cb00::|32|20101006|allocated")
    assert v6 is not None and v6[0] == 6 and v6[4] == "CN"
    # Non-address records, wildcard countries and broken counts are skipped.
    assert geoip.parse_rir_line("apnic|CN|asn|4808|1|20101006|allocated") is None
    assert geoip.parse_rir_line("ripencc|*|ipv4|1.2.3.0|256|20200101|allocated") is not None
    assert geoip.parse_rir_line("ripencc|DK|ipv4|1.2.3.0|nope|x|allocated") is None
    assert geoip.parse_rir_line("short|line") is None


def test_country_cleanup_and_lookup_helpers() -> None:
    assert geoip._clean_country("*") == ""
    assert geoip._clean_country("dk") == "DK"
    assert geoip._clean_country("None") == ""
    assert geoip.is_enrichable("8.8.8.8") is True
    for private in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "::1", "fe80::1", "not-an-ip"):
        assert geoip.is_enrichable(private) is False


# --------------------------------------------------------------------------- #
# Flags / names
# --------------------------------------------------------------------------- #


def test_flag_emoji_and_image_url() -> None:
    assert geoip.flag_emoji("dk") == "🇩🇰"
    assert geoip.country_name("dk") == "Denmark"
    assert geoip.flag_image_url("DK") == "https://flagcdn.com/20x15/dk.png"
    # Pseudo-codes have no regional-indicator flag and no flag image.
    assert geoip.flag_emoji("A1") == ""
    assert geoip.flag_image_url("A1") is None
    assert geoip.flag_emoji(None) == ""
    assert geoip.flag_emoji("") == ""
    assert geoip.flag_image_url("xx") == "https://flagcdn.com/20x15/xx.png"


def test_country_table_is_complete_enough() -> None:
    assert len(geoip.COUNTRIES) > 240
    for code in ("DK", "DE", "GB", "US", "JP", "BR", "ZA", "AU", "EU", "XK"):
        assert geoip.COUNTRIES[code]
    # Unknown codes degrade to the code itself rather than to None.
    assert geoip.country_name("QQ") == "QQ"
    assert geoip.country_name(None) is None


# --------------------------------------------------------------------------- #
# Index + lookups
# --------------------------------------------------------------------------- #


def test_index_lookup_returns_country_and_asn(cache: Path) -> None:
    index = geoip.load_index(cache)
    assert index is not None
    record = index.lookup("23.227.38.74")
    assert record is not None
    assert (record.country_code, record.asn, record.as_org) == (
        "US",
        13335,
        "CLOUDFLARENET",
    )
    assert record.country == "United States"
    assert record.label.startswith("🇺🇸 US · AS13335")
    assert record.range_label == "23.227.38.0 - 23.227.38.255"


def test_index_lookup_binary_search_boundaries(cache: Path) -> None:
    index = geoip.load_index(cache)
    assert index is not None
    # First and last address of a range are inside; the neighbours are not.
    assert index.lookup("23.227.38.0") is not None
    assert index.lookup("23.227.38.255") is not None
    assert index.lookup("23.227.37.255") is None
    assert index.lookup("23.227.39.0") is None
    # Ranges are matched by longest prefix, not by the first row.
    assert index.lookup("8.8.8.8").asn == 15169
    # A country-only row still answers with a flag and no ASN.
    dk = index.lookup("2.105.0.5")
    assert dk is not None and dk.country_code == "DK" and dk.asn == 0
    assert dk.as_label is None


def test_index_handles_ipv6_and_bad_input(cache: Path) -> None:
    index = geoip.load_index(cache)
    assert index is not None
    assert index.lookup("2001:db8::1").country_code == "NL"
    assert index.lookup("2001:db9::1") is None
    assert index.lookup("") is None
    assert index.lookup("not-an-address") is None


def test_lookup_many_skips_private_and_deduplicates(cache: Path) -> None:
    index = geoip.load_index(cache)
    assert index is not None
    found = index.lookup_many(
        ["8.8.8.8", "8.8.8.8", "10.0.0.1", "23.227.38.74", "192.168.0.1"]
    )
    assert set(found) == {"8.8.8.8", "23.227.38.74"}


def test_index_stats_and_meta(cache: Path) -> None:
    index = geoip.load_index(cache)
    assert index is not None
    stats = index.stats()
    assert stats["entries"] == 4
    assert stats["ipv4"] == 3 and stats["ipv6"] == 1
    assert stats["sources"] == ["test-fixture"]
    assert stats["schema"] == geoip.SCHEMA_VERSION
    assert geoip.index_available(cache) is True
    age = geoip.index_age_days(cache)
    assert age is not None and age < 1.0
    meta = geoip.read_meta(cache)
    assert meta["generator"] == "subsonar.geoip.write_index"


def test_missing_index_is_unavailable_and_enrich_is_none(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    assert geoip.index_available(empty) is False
    assert geoip.load_index(empty) is None
    assert geoip.enrich("8.8.8.8", empty) is None
    assert geoip.describe("8.8.8.8", empty) == ""
    # Offline with no index and require=False is a silent "no enrichment".
    assert geoip.ensure_index(empty, offline=True) is None
    with pytest.raises(geoip.GeoError):
        geoip.ensure_index(empty, offline=True, require=True)


def test_enrich_and_describe_use_the_local_index(cache: Path) -> None:
    assert geoip.enrich("8.8.8.8", cache).asn == 15169
    assert geoip.describe("8.8.8.8", cache).startswith("🇺🇸 US")
    assert geoip.describe("10.0.0.1", cache) == ""



def _finding(host: str = "shop.example.com", ip: str = "23.227.38.74", port: int = 443):
    """Minimal, fully-populated finding (the dataclass requires six fields)."""
    return Finding(
        subdomain=host,
        ip=ip,
        port=port,
        scheme="https",
        url=f"https://{host}",
        status=200,
        title="ok",
    )


def test_stale_index_is_kept_when_a_refresh_cannot_download(cache: Path, monkeypatch) -> None:
    geoip.write_index(
        _rows(), cache, sources=("test-fixture",), built_at=time.time() - 999 * 86400
    )
    geoip.reset_cache()

    def boom(*args, **kwargs):
        raise OSError("no network")

    monkeypatch.setattr(geoip, "build_index", boom)
    index = geoip.ensure_index(cache, max_age_days=1.0)
    assert index is not None and index.count == 4
    # ... and offline mode never even tries to refresh.
    monkeypatch.setattr(
        geoip, "build_index", lambda *a, **k: pytest.fail("attempted download")
    )
    index = geoip.ensure_index(cache, offline=True, max_age_days=0.0)
    assert index is not None and index.count == 4


def test_fresh_index_is_not_rebuilt(cache: Path, monkeypatch) -> None:
    def boom(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("a fresh index must not be rebuilt")

    monkeypatch.setattr(geoip, "build_index", boom)
    index = geoip.ensure_index(cache, max_age_days=21.0)
    assert index is not None and index.count == 4


class _EmptyStream:
    """Minimal stand-in for the text stream :func:`open_source` returns."""

    def __iter__(self):  # pragma: no cover - trivial
        return iter(())

    def close(self) -> None:  # pragma: no cover - trivial
        return None


def test_build_index_reports_a_total_failure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(geoip, "SOURCES", (("broken", "https://x.invalid/d.gz", "v4"),))
    monkeypatch.setattr(geoip, "RIR_SOURCES", ())
    monkeypatch.setattr(geoip, "open_source", lambda url, timeout=0: _EmptyStream())
    with pytest.raises(geoip.GeoError):
        geoip.build_index(tmp_path / "cache")


def test_open_source_sniffs_gzip_without_buffering(monkeypatch) -> None:
    """The gzip magic number is detected from the first bytes of the stream."""
    import gzip
    import io

    payload = gzip.compress(b"8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n")

    class Response(io.BytesIO):
        def release_conn(self) -> None:  # pragma: no cover - urllib parity
            return None

    monkeypatch.setattr(geoip, "urlopen", lambda request, timeout=0: Response(payload))
    handle = geoip.open_source("https://iptoasn.com/data/x.tsv.gz")
    try:
        rows = [geoip.parse_line(line, "v4") for line in handle]
    finally:
        handle.close()
    assert rows[0] == (4, "08080800", "080808ff", 15169, "US", "GOOGLE")


def test_geo_enrichment_can_be_disabled_entirely(tmp_path: Path) -> None:
    """With ``geoip=False`` the engine must not even open an index."""
    import asyncio

    from subsonar.core.engine import ScanEngine

    config = ScanConfig(domain="example.com", geoip=False, cache_dir=tmp_path)
    engine = ScanEngine(config, profile=1)
    asyncio.run(engine._phase_geo())
    assert engine._geo is None
    assert engine._geo_label("8.8.8.8") == ""
    finding = _finding("a.example.com", "8.8.8.8")
    engine._annotate(finding)
    assert finding.country_code is None


def test_engine_survives_a_failing_geo_index(tmp_path: Path, monkeypatch) -> None:
    import asyncio

    from subsonar.core.engine import ScanEngine

    async def boom(*args, **kwargs):
        raise RuntimeError("downloader exploded")

    monkeypatch.setattr(geoip, "ensure_index_async", boom)
    config = ScanConfig(domain="example.com", cache_dir=tmp_path)
    engine = ScanEngine(config, profile=1)
    asyncio.run(engine._phase_geo())
    assert engine._geo is None


def test_engine_annotates_findings_from_the_index(cache: Path) -> None:
    import asyncio

    from subsonar.core.engine import ScanEngine

    config = ScanConfig(domain="example.com", cache_dir=cache, reverse_dns=False)
    engine = ScanEngine(config, profile=1)
    engine._geo = geoip.load_index(cache)
    assert engine._geo is not None
    finding = _finding()
    asyncio.run(_enrich(engine, finding))
    assert finding.country_code == "US"
    assert finding.as_org == "CLOUDFLARENET"
    assert finding.geo_label == "🇺🇸 US"
    assert finding.to_row()["country"] == "United States"


async def _enrich(engine, finding) -> None:
    engine.result.findings.append(finding)
    await engine._enrich_findings()



# --------------------------------------------------------------------------- #
# CLI: flags, `geoip` subcommand
# --------------------------------------------------------------------------- #


def test_cli_geo_flags_flow_into_the_settings() -> None:
    from main import _settings_from_args, build_parser

    args = build_parser().parse_args(
        ["scan", "example.com", "--no-geo", "--no-geo-download", "--no-reverse-dns"]
    )
    settings = _settings_from_args(args)
    assert settings.geoip is False
    assert settings.geoip_download is False
    assert settings.reverse_dns is False

    args = build_parser().parse_args(
        ["scan", "example.com", "--no-dns-intel", "--no-mining", "--no-carry-over"]
    )
    settings = _settings_from_args(args)
    assert settings.dns_intel is False
    assert settings.web_mining is False
    assert settings.carry_over is False
    config = settings.build_config("example.com")
    assert config.dns_intel is False
    assert config.web_mining is False
    assert config.carry_over is False


def test_cli_defaults_keep_the_new_enrichment_on() -> None:
    from main import _settings_from_args, build_parser

    settings = _settings_from_args(build_parser().parse_args(["scan", "example.com"]))
    assert settings.geoip is True and settings.geoip_download is True
    assert settings.reverse_dns is True
    assert settings.dns_intel is True and settings.web_mining is True
    assert settings.carry_over is True
    config = settings.build_config("example.com")
    assert config.geoip is True and config.dns_intel is True
    assert config.reverse_dns is True and config.web_mining is True


def test_geoip_command_reports_stats_and_lookups(cache: Path, capsys) -> None:
    import main

    args = main.build_parser().parse_args(
        ["geoip", "--cache-dir", str(cache), "--lookup", "23.227.38.74"]
    )
    assert main.cmd_geoip(args) == main.EXIT_OK
    out = capsys.readouterr().out
    assert "CLOUDFLARENET" in out and "United States" in out

    args = main.build_parser().parse_args(["geoip", "--cache-dir", str(cache), "--json"])
    assert main.cmd_geoip(args) == main.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["entries"] == 4
    # The statistics output is a superset of the metadata file.
    assert payload["ipv4"] == 3 and payload["ipv6"] == 1


def test_geoip_command_without_an_index_explains_how_to_build_it(
    tmp_path: Path, capsys
) -> None:
    import main

    args = main.build_parser().parse_args(
        ["geoip", "--cache-dir", str(tmp_path / "none")]
    )
    assert main.cmd_geoip(args) == main.EXIT_OK
    out = capsys.readouterr().out
    assert "no offline geo index yet" in out
    assert "geoip --build" in out

    args = main.build_parser().parse_args(
        ["geoip", "--cache-dir", str(tmp_path / "none"), "--lookup", "8.8.8.8"]
    )
    assert main.cmd_geoip(args) == main.EXIT_ERROR


def test_geoip_command_build_reports_progress(tmp_path: Path, capsys, monkeypatch) -> None:
    import main

    summary = {
        "schema": geoip.SCHEMA_VERSION,
        "built_at": time.time(),
        "entries": 42,
        "ipv4": 40,
        "ipv6": 2,
        "sources": ["test-fixture"],
    }
    monkeypatch.setattr(geoip, "build_index", lambda cache_dir, **kw: summary)
    args = main.build_parser().parse_args(
        ["geoip", "--cache-dir", str(tmp_path), "--build"]
    )
    assert main.cmd_geoip(args) == main.EXIT_OK
    out = capsys.readouterr().out
    assert "42 range(s)" in out and "test-fixture" in out


def test_geoip_command_survives_a_failed_build(tmp_path: Path, capsys, monkeypatch) -> None:
    import main

    def boom(*args, **kwargs):
        raise geoip.GeoError("no geo data could be downloaded")

    monkeypatch.setattr(geoip, "build_index", boom)
    args = main.build_parser().parse_args(
        ["geoip", "--cache-dir", str(tmp_path), "--build"]
    )
    assert main.cmd_geoip(args) == main.EXIT_ERROR
    assert "no geo data" in capsys.readouterr().err


def test_offline_env_switch_blocks_downloads(cache: Path, monkeypatch) -> None:
    geoip.write_index(
        _rows(), cache, sources=("test-fixture",), built_at=time.time() - 999 * 86400
    )
    geoip.reset_cache()
    monkeypatch.setenv(geoip.OFFLINE_ENV, "1")
    assert geoip.downloads_forbidden() is True
    monkeypatch.setattr(
        geoip, "build_index", lambda *a, **k: pytest.fail("download attempted")
    )
    index = geoip.ensure_index(cache, max_age_days=0.0)
    assert index is not None and index.count == 4
    monkeypatch.setenv(geoip.OFFLINE_ENV, "0")
    assert geoip.downloads_forbidden() is False

