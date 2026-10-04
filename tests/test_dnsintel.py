"""Apex DNS intelligence (MX/SPF/DKIM/DMARC/CAA/DNSSEC) — parsers and collection.

Two layers are covered separately:

* the **wire decoder** (SOA/DS/DNSKEY/CAA/TXT/MX records added to
  :mod:`subsonar.core.dns`) using hand-built response packets, so a decoding bug
  can never hide behind a fake resolver,
* the **collector** using a scripted fake resolver, so provider inference, the
  SPF include walk, DKIM probing and the posture notes are all exercised without
  a single network packet.
"""

from __future__ import annotations

import struct

import pytest

from subsonar.core import dnsintel
from subsonar.core.dns import DNSRecord, DNSResult, encode_name, parse_response
from subsonar.core.dnsintel import (
    collect_dns_intel,
    infer_mail_provider,
    infer_nameserver_provider,
    parse_dmarc,
    parse_spf_all,
    parse_spf_includes,
    parse_spf_ips,
    provider_for_host,
    verification_vendor,
)


# --------------------------------------------------------------------------- #
# Wire decoding of the new record types
# --------------------------------------------------------------------------- #


def _response(
    rtype: int, rdata: bytes, *, name: str = "example.com", qid: int = 0x1234
) -> bytes:
    """One-answer response for *name*/*rtype* with the given rdata."""
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    question = encode_name(name) + struct.pack("!HH", rtype, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata
    return header + question + answer


def _decode(rtype: int, rdata: bytes) -> str | None:
    records, rcode = parse_response(_response(rtype, rdata), 0x1234)
    assert rcode == 0
    assert len(records) == 1
    return records[0].value


def test_soa_record_decodes_primary_mailbox_and_serial() -> None:
    rdata = (
        encode_name("ns1.example.com")
        + encode_name("hostmaster.example.com")
        + struct.pack("!IIIII", 2024010101, 7200, 3600, 1209600, 300)
    )
    value = _decode(6, rdata)  # SOA
    assert value is not None
    primary, mailbox, serial = value.split()
    assert primary == "ns1.example.com"
    assert mailbox == "hostmaster.example.com"
    assert serial == "2024010101"


def test_ds_and_dnskey_records_decode() -> None:
    ds = struct.pack("!HBB", 2371, 13, 2) + bytes.fromhex("ab" * 32)
    value = _decode(43, ds)  # DS
    assert value is not None
    key_tag, algorithm, digest_type, digest = value.split()
    assert (key_tag, algorithm, digest_type) == ("2371", "13", "2")
    assert len(digest) == 64

    dnskey = struct.pack("!HBB", 257, 3, 13) + bytes.fromhex("cd" * 40)
    value = _decode(48, dnskey)  # DNSKEY
    assert value is not None
    assert value.startswith("257 3 13 cdc")
    assert len(value.split()[-1]) == 64  # truncated for readability


def test_caa_record_decodes_flags_tag_and_value() -> None:
    rdata = b"\x00" + bytes([5]) + b"issue" + b"letsencrypt.org"
    assert _decode(257, rdata) == "0 issue letsencrypt.org"
    assert dnsintel.caa_issuer_name("letsencrypt.org") == "Let's Encrypt"
    assert (
        dnsintel.caa_issuer_name("digicert.com; cansignhttpexchanges=yes") == "DigiCert"
    )
    assert dnsintel.caa_issuer_name("unknown-ca.example") == "unknown-ca.example"


def test_short_or_broken_rdata_never_raises() -> None:
    def _maybe(rtype: int, rdata: bytes) -> str | None:
        records, _rcode = parse_response(_response(rtype, rdata), 0x1234)
        return records[0].value if records else None

    assert _maybe(257, b"\x00") is None  # CAA without a tag length
    assert _maybe(257, b"\x00\x05ab") is None  # tag longer than the rdata
    assert _maybe(43, b"\x01\x02") is None  # DS too short
    assert _maybe(48, b"\x01\x02") is None  # DNSKEY too short
    # A TXT record split over several character-strings is joined.
    txt = bytes([5]) + b"v=spf" + bytes([6]) + b"1 -all"
    assert _decode(16, txt) == "v=spf1 -all"
    # MX carries the preference in the first two bytes.
    mx = struct.pack("!H", 10) + encode_name("mail.example.com")
    assert _decode(15, mx) == "10 mail.example.com"


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_provider_inference() -> None:
    assert (
        provider_for_host(
            "example-com.mail.protection.outlook.com", dnsintel.MAIL_PROVIDER_SUFFIXES
        )
        == "Microsoft 365 (Exchange Online)"
    )
    assert infer_mail_provider(
        ["aspmx.l.google.com", "alt1.aspmx.l.google.com", "mx.example.org"]
    ) == ["Google Workspace"]
    assert infer_nameserver_provider(["ns1.dandomain.dk", "ns2.dandomain.dk"]) == [
        "DanDomain DNS"
    ]
    assert infer_mail_provider(["mx.unknown.invalid"]) == []
    assert provider_for_host("", dnsintel.MAIL_PROVIDER_SUFFIXES) is None


def test_spf_parsing() -> None:
    record = (
        "v=spf1 include:_spf.google.com include:spf.protection.outlook.com "
        "ip4:192.0.2.0/24 -all"
    )
    assert parse_spf_includes(record) == [
        "_spf.google.com",
        "spf.protection.outlook.com",
    ]
    assert parse_spf_ips(record) == ["192.0.2.0/24"]
    assert parse_spf_all(record) == "-"
    assert parse_spf_all("v=spf1 ~all") == "~"
    assert parse_spf_all("v=spf1 mx") is None
    assert dnsintel.is_spf(record) is True
    assert dnsintel.is_spf("google-site-verification=x") is False


def test_dmarc_parsing_and_grading() -> None:
    tags = parse_dmarc(
        "v=DMARC1; p=reject; sp=quarantine; rua=mailto:agg@example.com; pct=100"
    )
    assert tags["p"] == "reject"
    assert tags["sp"] == "quarantine"
    assert tags["rua"] == "mailto:agg@example.com"
    intel = dnsintel.DNSIntel(domain="example.com", dmarc=tags, dmarc_record="v=DMARC1")
    assert intel.dmarc_policy == "reject"
    assert intel.dmarc_strong is True
    weak = dnsintel.DNSIntel(
        domain="example.com",
        dmarc={"p": "reject", "pct": "10"},
        dmarc_record="v=DMARC1",
    )
    assert weak.dmarc_strong is False


def test_verification_tokens_are_attributed_case_insensitively() -> None:
    assert verification_vendor("google-site-verification=abc123") == (
        "Google Search Console",
        "abc123",
    )
    assert verification_vendor("MS=ms12345678")[0].startswith("Microsoft")
    assert verification_vendor("atlassian-domain-verification=xyz")[0] == "Atlassian"
    assert verification_vendor("v=spf1 -all") is None
    assert verification_vendor("facebook-domain-verification=a b c")[1] == "a b c"



# --------------------------------------------------------------------------- #
# Collection (scripted fake resolver)
# --------------------------------------------------------------------------- #


class FakeResolver:
    """Answers ``(name, qtype)`` from a script; anything else is NXDOMAIN."""

    def __init__(self, script: dict[tuple[str, int], list[str]]) -> None:
        self.script = script
        self.asked: list[tuple[str, int]] = []

    async def query_raw(self, name, qtype=1, **kwargs):
        key = (name.lower().rstrip("."), qtype)
        self.asked.append(key)
        values = self.script.get(key)
        result = DNSResult(name=name)
        if values is None:
            result.error = "NXDOMAIN"
            return result
        for value in values:
            result.records.append(
                DNSRecord(name=name, rtype=qtype, ttl=300, value=value)
            )
        if qtype in (1, 28):
            result.addresses = list(values)
        return result


def _script() -> dict[tuple[str, int], list[str]]:
    return {
        ("example.com", 15): ["10 mx1.dandomain.dk", "20 mx2.dandomain.dk"],
        ("example.com", 2): ["ns1.dandomain.dk", "ns2.dandomain.dk"],
        ("example.com", 6): ["ns1.dandomain.dk hostmaster.example.com 2024010101"],
        ("example.com", 16): [
            "v=spf1 include:_spf.google.com include:spf.example.net "
            "ip4:192.0.2.0/24 ~all",
            "google-site-verification=token123",
            "MS=ms999",
            "unrelated text record",
        ],
        ("_spf.google.com", 16): ["v=spf1 include:_netblocks.google.com ~all"],
        ("_netblocks.google.com", 16): ["v=spf1 ip4:35.190.0.0/17 ~all"],
        ("spf.example.net", 16): ["v=spf1 -all"],
        ("default._domainkey.example.com", 16): ["v=DKIM1; k=rsa; p=MIIBIjANBg"],
        ("selector1._domainkey.example.com", 16): ["v=DKIM1; k=rsa; p=MIIBIjANBg"],
        ("_dmarc.example.com", 16): [
            "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; pct=100"
        ],
        ("example.com", 257): [
            "0 issue letsencrypt.org",
            "0 iodef mailto:sec@example.com",
        ],
        ("example.com", 43): ["2371 13 2 abcd"],
    }


async def test_collect_dns_intel_builds_the_whole_picture() -> None:
    resolver = FakeResolver(_script())
    intel = await collect_dns_intel("example.com", resolver, spf_depth=3, max_dkim=3)

    assert intel.mx == [(10, "mx1.dandomain.dk"), (20, "mx2.dandomain.dk")]
    assert intel.mail_hosts == ["mx1.dandomain.dk", "mx2.dandomain.dk"]
    assert "DanDomain" in " ".join(intel.mail_providers)
    assert intel.ns == ["ns1.dandomain.dk", "ns2.dandomain.dk"]
    assert intel.dns_providers == ["DanDomain DNS"]
    assert intel.soa["primary"] == "ns1.dandomain.dk"
    assert intel.soa["mailbox"] == "hostmaster@example.com"

    # SPF: includes walked recursively, IPs collected, ~all detected.
    assert intel.spf_all == "~"
    assert intel.spf_strict is False
    assert "_spf.google.com" in intel.spf_includes
    assert "_netblocks.google.com" in intel.spf_includes
    assert "35.190.0.0/17" in intel.spf_ips
    assert "Google Workspace" in intel.mail_providers

    # DKIM, DMARC, CAA, DNSSEC and verification tokens.
    assert intel.dkim_selectors == ["default", "selector1"]
    assert intel.dmarc_policy == "quarantine"
    assert intel.dmarc["rua"] == "mailto:dmarc@example.com"
    assert intel.caa_issuers == ["Let's Encrypt"]
    assert intel.dnssec is True
    assert intel.verifications["Google Search Console"] == "token123"
    assert intel.verifications["Microsoft (Office 365 / Azure AD)"] == "ms999"

    # Weak SPF is reported, but the records that *are* present are not.
    notes = " | ".join(intel.notes)
    assert "-all" in notes
    assert "no DMARC record" not in notes
    assert "no CAA record" not in notes
    assert "not DNSSEC signed" not in notes



async def test_collect_dns_intel_reports_a_naked_domain() -> None:
    """Nothing published at all: every posture warning fires, and no crash."""
    resolver = FakeResolver({})
    intel = await collect_dns_intel("bare.example", resolver)
    assert intel.mx == [] and intel.ns == [] and intel.spf == []
    assert intel.dmarc_record is None and intel.dnssec is False
    assert intel.caa == [] and intel.dkim_selectors == []
    notes = " | ".join(intel.notes)
    for expected in (
        "no SPF record",
        "no DMARC record",
        "no DKIM selector answered",
        "no CAA record",
        "zone is not DNSSEC signed",
    ):
        assert expected in notes
    assert "unsigned" in " ".join(intel.signals())


async def test_collect_dns_intel_survives_a_broken_resolver() -> None:
    class Broken:
        async def query_raw(self, *args, **kwargs):
            raise RuntimeError("resolver on fire")

    intel = await collect_dns_intel("example.com", Broken())
    assert intel.mx == [] and intel.notes
    assert intel.to_dict()["domain"] == "example.com"


async def test_collect_dns_intel_is_bounded_by_depth_and_selector_count() -> None:
    resolver = FakeResolver(_script())
    intel = await collect_dns_intel(
        "example.com", resolver, spf_depth=1, max_dkim=1, dkim_selectors=["default"]
    )
    assert intel.dkim_selectors == ["default"]
    # Depth 1 stops after the first hop: the nested include is never fetched.
    assert "_spf.google.com" in intel.spf_includes
    assert ("_netblocks.google.com", 16) not in resolver.asked
    assert ("selector1._domainkey.example.com", 16) not in resolver.asked


async def test_collect_dns_intel_reports_signals_and_serialises() -> None:
    intel = await collect_dns_intel("example.com", FakeResolver(_script()))
    signals = "\n".join(intel.signals())
    assert "mail:" in signals and "mx:" in signals
    assert "dns:" in signals and "spf includes:" in signals
    assert "dmarc: p=quarantine" in signals
    assert "dnssec: signed" in signals
    assert "verifications:" in signals
    payload = intel.to_dict()
    assert payload["dmarc"]["p"] == "quarantine"
    assert payload["mx"][0] == {"priority": 10, "host": "mx1.dandomain.dk"}
    assert payload["caa_issuers"] == ["Let's Encrypt"]
    assert payload["dnssec"] is True
    assert payload["spf_ips"] and payload["soa"]["mailbox"] == "hostmaster@example.com"


async def test_engine_phase_dns_intel_populates_the_result(monkeypatch) -> None:
    from subsonar.core.config import ScanConfig
    from subsonar.core.engine import ScanEngine

    config = ScanConfig(domain="example.com")
    engine = ScanEngine(config, profile=1)
    engine._resolver = FakeResolver(_script())  # type: ignore[assignment]
    await engine._phase_dns_intel()
    assert engine.result.dns_intel is not None
    assert engine.result.dns_intel.dmarc_policy == "quarantine"
    assert "mail platform" in "\n".join(engine.result.summary_lines())
    assert engine.result.to_dict()["dns_intel"]["dnssec"] is True

    # ... and the phase is skippable.
    config = ScanConfig(domain="example.com", dns_intel=False)
    engine = ScanEngine(config, profile=1)
    await engine._phase_dns_intel()
    assert engine.result.dns_intel is None

