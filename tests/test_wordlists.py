"""Wordlist registry, the generated AI Super list and the manager wiring.

Nothing here touches the network: the built-in list is packaged, and the remote
lists are only checked for shape (the URLs themselves are verified against the
GitHub API in the README's provenance notes).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from subsonar.core.config import ScanConfig
from subsonar.core.engine import ScanEngine
from subsonar.core.events import EventBus
from subsonar.core.wordlist import EMBEDDED_SEED, WordlistManager, parse_wordlist
from subsonar.core.wordlistgen import (
    BUILTIN_PATH,
    DEFAULT_LIMIT,
    build_labels,
    curated_labels,
    render_default,
    validate_labels,
)
from subsonar.core.wordlists import (
    DEFAULT_WORDLIST,
    WORDLISTS,
    get_wordlist,
    mirror_urls,
    resolve_wordlist,
)

REMOTE_URL_ROOT = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/"
)

# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


def test_registry_offers_at_least_ten_lists_including_the_builtin_one() -> None:
    remote = [spec for spec in WORDLISTS if not spec.builtin]
    builtin = [spec for spec in WORDLISTS if spec.builtin]
    assert len(remote) >= 9, [spec.name for spec in remote]
    assert [spec.name for spec in builtin] == ["ai-super"]


def test_registry_entries_are_well_formed_and_unique() -> None:
    names = [spec.name for spec in WORDLISTS]
    assert len(names) == len(set(names))
    for spec in WORDLISTS:
        assert spec.label and spec.licence and spec.approx_size > 0
        assert spec.tags
        if spec.builtin:
            assert spec.path is not None and spec.path.name == spec.filename
        else:
            assert spec.source.startswith(REMOTE_URL_ROOT), spec.source
            assert spec.source.endswith(".txt"), spec.source
            assert spec.filename.endswith(".txt")


def test_every_verified_list_is_present() -> None:
    assert {spec.name for spec in WORDLISTS} == {
        "seclists-top1m",
        "seclists-5k",
        "seclists-20k",
        "bitquark",
        "namelist",
        "deepmagic",
        "deepmagic-50k",
        "fierce",
        "shubs",
        "jhaddix",
        "ai-super",
    }


def test_default_and_aliases_resolve() -> None:
    assert DEFAULT_WORDLIST == "seclists-top1m"
    assert resolve_wordlist(None).name == DEFAULT_WORDLIST
    assert resolve_wordlist("").name == DEFAULT_WORDLIST
    assert resolve_wordlist("default").name == DEFAULT_WORDLIST
    assert resolve_wordlist("5k").name == "seclists-5k"
    assert resolve_wordlist("ai").name == "ai-super"
    assert resolve_wordlist(" AI-Super ").name == "ai-super"
    assert resolve_wordlist("dnsrecon").name == "namelist"


def test_unknown_name_reports_the_valid_ones() -> None:
    with pytest.raises(KeyError, match="choose one of"):
        resolve_wordlist("nope")
    with pytest.raises(ValueError, match="choose one of"):
        get_wordlist("nope")


def test_mirrors_serve_the_same_file() -> None:
    spec = resolve_wordlist("seclists-20k")
    mirrors = mirror_urls(spec)
    assert len(mirrors) == 2
    assert all(spec.filename in url for url in mirrors)
    assert any("cdn.jsdelivr.net" in url for url in mirrors)
    assert any("raw.githack.com" in url for url in mirrors)
    assert mirror_urls(resolve_wordlist("ai-super")) == ()



# --------------------------------------------------------------------------- #
# The generated AI Super list
# --------------------------------------------------------------------------- #


def test_shipped_ai_super_file_matches_the_generator() -> None:
    """The packaged list must be exactly what the generator produces."""
    assert BUILTIN_PATH.is_file(), (
        "missing subsonar/data/ai-super-subdomains.txt — run "
        "python tools/build_ai_wordlist.py"
    )
    assert BUILTIN_PATH.read_text(encoding="utf-8") == render_default()


def test_ai_super_labels_are_valid_unique_and_lead_with_the_curated_names() -> None:
    labels = build_labels()
    assert len(labels) >= 20_000
    assert len(labels) == len(set(labels))
    assert validate_labels(labels) == []
    assert all(label == label.lower() and len(label) <= 63 for label in labels)
    # Curated names come first, in a stable order.
    assert labels[:3] == ["www", "mail", "smtp"]
    assert labels[: len(curated_labels())] == curated_labels()
    for expected in (
        "autodiscover",
        "sso",
        "argocd",
        "vault",
        "k8s",
        "api-dev",
        "dev-api",
        "prod-db",
        "web-eu",
        "grafana2",
        "checkout-dev",
    ):
        assert expected in labels, expected


def test_ai_super_generation_is_deterministic_and_capped() -> None:
    assert build_labels(100) == build_labels(100)
    assert len(build_labels(100)) == 100
    assert build_labels(DEFAULT_LIMIT) == build_labels()  # cap not reached
    assert build_labels(10) == curated_labels()[:10]


def test_generated_file_is_scanner_parseable() -> None:
    text = BUILTIN_PATH.read_text(encoding="utf-8")
    words = parse_wordlist(text, limit=500, domain="example.com")
    assert len(words) == 500
    assert all("." not in word for word in words)



# --------------------------------------------------------------------------- #
# Manager + engine + CLI plumbing
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_builtin_list_loads_offline_without_any_download(tmp_path: Path) -> None:
    bus = EventBus()
    manager = WordlistManager(
        spec=resolve_wordlist("ai-super"), cache_dir=tmp_path, bus=bus
    )
    assert manager.name == "ai-super"

    result = await manager.load(250, domain="example.com", offline=True)

    assert result.wordlist == "ai-super"
    assert result.size == 250
    assert result.cached_path == manager.cached_file()
    assert manager.cache_is_fresh() is True
    assert any(
        "built-in wordlist ai-super" in event.message for event in bus.history()
    ), [event.message for event in bus.history()]


@pytest.mark.asyncio
async def test_missing_builtin_file_falls_back_to_the_embedded_seed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = WordlistManager(
        spec=resolve_wordlist("ai-super"), cache_dir=tmp_path, bus=EventBus()
    )
    monkeypatch.setattr(WordlistManager, "builtin_path", property(lambda self: None))

    result = await manager.load(40, domain="example.com", offline=True)

    assert result.size == 40
    assert result.source == "embedded"
    assert all(word in EMBEDDED_SEED for word in result.words)


@pytest.mark.asyncio
async def test_remote_spec_uses_its_own_url_and_mirrors(tmp_path: Path) -> None:
    spec = resolve_wordlist("bitquark")
    manager = WordlistManager(spec=spec, cache_dir=tmp_path, bus=EventBus())
    assert manager.url == spec.source
    assert spec.filename in manager.cached_file().name
    assert mirror_urls(spec)[0] in manager.fallbacks


def test_engine_adopts_the_configured_wordlist() -> None:
    engine = ScanEngine(ScanConfig(domain="example.com"), profile=3, bus=EventBus())
    assert engine._wordlists.name == DEFAULT_WORDLIST

    engine = ScanEngine(
        ScanConfig(domain="example.com", wordlist="ai-super"), profile=3, bus=EventBus()
    )
    assert engine._wordlists.name == "ai-super"


def test_engine_rejects_an_unknown_wordlist() -> None:
    with pytest.raises(KeyError, match="choose one of"):
        ScanEngine(
            ScanConfig(domain="example.com", wordlist="nope"), profile=3, bus=EventBus()
        )


def test_cli_wordlist_flag_wires_into_the_config() -> None:
    from main import _settings_from_args, build_parser

    args = build_parser().parse_args(["scan", "example.com", "--wordlist", "ai"])
    settings = _settings_from_args(args)
    assert settings.wordlist == "ai-super"
    assert settings.build_config("example.com").wordlist == "ai-super"

    default = _settings_from_args(build_parser().parse_args(["scan", "example.com"]))
    assert default.wordlist is None
    assert default.build_config("example.com").wordlist == DEFAULT_WORDLIST


def test_cli_rejects_an_unknown_wordlist() -> None:
    from main import _settings_from_args, build_parser

    args = build_parser().parse_args(["scan", "example.com", "--wordlist", "nope"])
    with pytest.raises(KeyError, match="choose one of"):
        _settings_from_args(args)


def test_wordlists_command_prints_every_list(capsys: pytest.CaptureFixture[str]) -> None:
    from main import build_parser, cmd_wordlists

    args = build_parser().parse_args(["wordlists"])
    assert cmd_wordlists(args) == 0
    out = capsys.readouterr().out
    for spec in WORDLISTS:
        assert spec.name in out
    assert "ai-super" in out and "built-in" in out


def test_toml_settings_carry_the_wordlist() -> None:
    from subsonar.core.workflow import ScanSettings

    settings = ScanSettings.from_mapping({"scan": {"wordlist": "shubs"}})
    assert settings.wordlist == "shubs"
    assert settings.build_config("example.com").wordlist == "shubs"
    assert ScanSettings().wordlist is None  # unset → ScanConfig default
