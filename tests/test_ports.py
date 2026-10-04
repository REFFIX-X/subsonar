"""Port matrices, port-spec parsing and the ``--ports`` / ``--port-matrix`` flags."""

from __future__ import annotations

import pytest

from subsonar.core.config import (
    PORT_LABELS,
    PORT_MATRIX,
    PORT_MATRIX_EXTENDED,
    TLS_FIRST_PORTS,
    ScanConfig,
)
from subsonar.core.engine import ScanEngine
from subsonar.core.events import EventBus
from subsonar.core.ports import (
    MATRICES,
    describe,
    parse_port_spec,
    resolve_matrix,
    validate_matrix,
)
from subsonar.core.profiles import get_profile

# --------------------------------------------------------------------------- #
# Matrices
# --------------------------------------------------------------------------- #


def test_core_matrix_is_still_the_documented_top_fifty() -> None:
    assert len(PORT_MATRIX) == 50
    assert 80 in PORT_MATRIX and 443 in PORT_MATRIX
    validate_matrix()  # raises if the embedded data is inconsistent


def test_extended_matrix_is_a_superset_of_at_least_one_hundred_fifty_ports() -> None:
    core = set(PORT_MATRIX)
    extended = set(PORT_MATRIX_EXTENDED)
    assert core.issubset(extended)
    assert len(extended) >= 150, len(extended)
    assert len(PORT_MATRIX_EXTENDED) == len(extended)  # no duplicates


def test_extended_matrix_covers_the_ports_people_actually_expose() -> None:
    for port in (
        5601,  # Kibana
        8086,  # InfluxDB
        8200,  # Vault UI
        6379,  # Redis
        5432,  # PostgreSQL
        6443,  # Kubernetes API
        2375,  # Docker API
        11434,  # Ollama
        5985,  # WinRM
        9092,  # Kafka
        16686,  # Jaeger
        19999,  # Netdata
        32400,  # Plex
        8006,  # Proxmox
        10050,  # Zabbix agent
    ):
        assert port in PORT_MATRIX_EXTENDED, port
        assert describe(port) != "Unknown", port


def test_core_labels_win_and_tls_first_covers_the_new_listeners() -> None:
    # Overlapping entries keep the core label.
    assert PORT_LABELS[9090] == PORT_MATRIX[9090]
    for port in (2376, 5001, 5061, 5986, 6443, 8243, 8531, 8883):
        assert port in TLS_FIRST_PORTS, port
        assert port in PORT_MATRIX_EXTENDED, port


def test_describe_falls_back_to_unknown() -> None:
    assert describe(8443) == PORT_MATRIX[8443]
    assert describe(5601) == "Kibana"
    assert describe(65533) == "Unknown"



# --------------------------------------------------------------------------- #
# Named matrices
# --------------------------------------------------------------------------- #


def test_named_matrices_and_aliases_resolve() -> None:
    assert resolve_matrix("core") == PORT_MATRIX
    assert resolve_matrix("top50") == PORT_MATRIX
    assert resolve_matrix("extended") == PORT_MATRIX_EXTENDED
    assert resolve_matrix("full") == PORT_MATRIX_EXTENDED
    assert set(resolve_matrix("audit")) == set(MATRICES["audit"])
    assert set(resolve_matrix("web")) == {
        80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443
    }


def test_unknown_matrix_name_lists_the_valid_ones() -> None:
    with pytest.raises(ValueError, match="choose one of"):
        resolve_matrix("nope")


def test_profiles_keep_their_documented_matrices() -> None:
    assert get_profile(3).ports() == PORT_MATRIX  # medium brute → core
    assert get_profile(1).ports() == MATRICES["web"]  # passive → web core
    assert set(get_profile(7).ports()) == set(MATRICES["audit"])  # infra audit


# --------------------------------------------------------------------------- #
# Port specs
# --------------------------------------------------------------------------- #


def test_parse_port_spec_accepts_names_lists_and_ranges() -> None:
    assert parse_port_spec("extended") == PORT_MATRIX_EXTENDED
    assert list(parse_port_spec("80,443")) == [80, 443]
    assert list(parse_port_spec("8000-8004")) == [8000, 8001, 8002, 8003, 8004]
    mixed = parse_port_spec("80, 9000-9002, 11434")
    assert list(mixed) == [80, 9000, 9001, 9002, 11434]
    assert mixed[11434] == "Ollama-API"
    assert parse_port_spec("core,11434")[11434] == "Ollama-API"
    assert len(parse_port_spec("core,11434")) == len(PORT_MATRIX) + 1


def test_parse_port_spec_is_order_preserving_and_deduplicates() -> None:
    spec = parse_port_spec("9002,80,9002,80")
    assert list(spec) == [9002, 80]


def test_parse_port_spec_rejects_junk() -> None:
    for bad in ("", "   ", "80,abc", "8000-abc", "9000-8000", "0", "70000", "1-70000"):
        with pytest.raises(ValueError):
            parse_port_spec(bad)


# --------------------------------------------------------------------------- #
# CLI / TOML / engine wiring
# --------------------------------------------------------------------------- #


def test_cli_ports_spec_wires_into_the_config() -> None:
    from main import _settings_from_args, build_parser

    for flag, value in (("--ports", "extended"), ("--port-matrix", "extended")):
        args = build_parser().parse_args(["scan", "example.com", flag, value])
        config = _settings_from_args(args).build_config("example.com")
        assert config.ports == PORT_MATRIX_EXTENDED, flag

    args = build_parser().parse_args(["scan", "example.com", "--ports", "80,443,8443"])
    config = _settings_from_args(args).build_config("example.com")
    assert config.ports == {
        80: describe(80),
        443: describe(443),
        8443: describe(8443),
    }


def test_cli_rejects_a_bad_port_spec() -> None:
    from main import _settings_from_args, build_parser

    args = build_parser().parse_args(["scan", "example.com", "--ports", "8000-abc"])
    with pytest.raises(ValueError):
        _settings_from_args(args)


def test_cli_rejects_an_unknown_matrix_name() -> None:
    from main import build_parser

    # argparse rejects it (choices=…), so nothing reaches the settings builder.
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan", "example.com", "--port-matrix", "nope"])


def test_toml_settings_carry_port_matrix_and_legacy_port_lists() -> None:
    from subsonar.core.workflow import ScanSettings

    named = ScanSettings.from_mapping({"scan": {"port_matrix": "extended"}})
    assert named.build_config("example.com").ports == PORT_MATRIX_EXTENDED

    legacy = ScanSettings.from_mapping({"scan": {"ports": [80, 443]}})
    assert legacy.build_config("example.com").ports == {
        80: describe(80),
        443: describe(443),
    }


def test_engine_scans_the_configured_matrix() -> None:
    config = ScanConfig(domain="example.com", ports=dict(PORT_MATRIX_EXTENDED))
    engine = ScanEngine(config, profile=3, bus=EventBus())
    assert len(engine._scanner.ports) == len(PORT_MATRIX_EXTENDED)
    assert engine.config.ports == PORT_MATRIX_EXTENDED


def test_explicit_ports_survive_profile_application() -> None:
    """Regression: ``--ports`` was silently replaced by the profile matrix."""
    from main import _settings_from_args, build_parser

    # Profile 7 would normally swap in the 30-port audit matrix.
    args = build_parser().parse_args(
        ["scan", "example.com", "-p", "7", "--ports", "extended"]
    )
    config = _settings_from_args(args).build_config("example.com")
    engine = ScanEngine(config, profile=7, bus=EventBus())
    assert engine.config.ports == PORT_MATRIX_EXTENDED
    assert len(engine._scanner.ports) == len(PORT_MATRIX_EXTENDED)

    # Without an explicit choice the profile matrix still applies.
    plain = ScanEngine(
        ScanConfig(domain="example.com"), profile=7, bus=EventBus()
    )
    assert set(plain.config.ports) == set(MATRICES["audit"])
