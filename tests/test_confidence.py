"""Verification suite for :mod:`subsonar.core.confidence`.

The scorer is duck-typed, so the tests drive it with a local finding stub, a
plain ``dict`` and — when the concurrent workstreams have left them importable —
the real ``WebProbeResult`` and ``Finding`` types.  Every assertion about a
signal checks the *explanation*, not just the number, because an unexplainable
score is the failure mode this module exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from subsonar.core.confidence import (
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    WEIGHTS,
    ConfidenceBreakdown,
    label_for,
    rank_findings,
    score_finding,
)

# --------------------------------------------------------------------------- #
# Fixtures / stubs
# --------------------------------------------------------------------------- #


@dataclass
class FindingStub:
    """Mirror of :class:`subsonar.core.engine.Finding` (field names matter)."""

    subdomain: str = "a.example.com"
    ip: str = "203.0.113.10"
    port: int = 443
    scheme: str = "https"
    url: str = "https://a.example.com"
    status: int | None = 200
    title: str | None = "Example Domain"
    server: str | None = "nginx"
    tls: bool = True
    tls_version: str | None = "TLSv1.3"
    content_type: str | None = "text/html"
    content_length: int = 4096
    redirect_chain: list[str] = field(default_factory=list)
    port_label: str = "https"
    sources: list[str] = field(default_factory=list)
    fingerprint: str | None = "0123456789abcdef"
    kind: str = "interface"
    initial_status: int | None = 200
    final_url: str | None = None
    aliases: list[int] = field(default_factory=list)
    latency_ms: float = 12.0


@dataclass
class MergedFinding(FindingStub):
    """A finding that also carries the fingerprinting subsystem's output."""

    favicon_hash: str | None = None
    technologies: list[Any] = field(default_factory=list)
    data_files: dict[str, int] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Tech:
    name: str
    category: str = "web server"
    evidence: str = "header Server: 'nginx'"


def _dict_finding(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "subdomain": "d.example.com",
        "ip": "203.0.113.11",
        "port": 80,
        "url": "http://d.example.com",
        "status": 200,
        "title": "Dashboard",
        "server": "nginx",
        "tls": False,
        "content_length": 2048,
        "fingerprint": "feedfacecafebeef",
        "kind": "interface",
        "aliases": [],
    }
    base.update(overrides)
    return base


def _blame(
    breakdown: ConfidenceBreakdown, *, reasons: str = "", penalties: str = ""
) -> None:
    """Assert a signal landed in the reason/penalty list it belongs to."""
    if reasons:
        assert any(reasons in text for text in breakdown.reasons), (
            reasons,
            breakdown.reasons,
        )
    if penalties:
        assert any(penalties in text for text in breakdown.penalties), (
            penalties,
            breakdown.penalties,
        )


# --------------------------------------------------------------------------- #
# Score spread
# --------------------------------------------------------------------------- #


def test_clean_unique_finding_is_high_confidence() -> None:
    finding = FindingStub()
    breakdown = score_finding(
        finding,
        favicon_hash="116323821",
        technologies=[Tech("nginx"), Tech("PHP", "language"), Tech("WordPress", "CMS")],
        data_files={"/robots.txt": 200, "/sitemap.xml": 200},
        headers={"Server": "nginx", "X-Frame-Options": "DENY"},
        resolvers_agreeing=2,
    )
    assert breakdown.label == "high"
    assert breakdown.score >= HIGH_THRESHOLD
    assert breakdown.score <= 100
    assert breakdown.reasons
    assert breakdown.explainable
    _blame(breakdown, reasons="HTTP 200")
    _blame(breakdown, reasons="TLS negotiated")
    _blame(breakdown, reasons="favicon hash")


def test_redirect_only_bounce_is_low_confidence() -> None:
    finding = FindingStub(
        port=2082,
        scheme="http",
        url="http://a.example.com:2082",
        status=301,
        kind="redirect",
        initial_status=301,
        final_url="https://a.example.com/",
        title="redirects to https://a.example.com/",
        server=None,
        tls=False,
        tls_version=None,
        content_length=0,
        fingerprint=None,
    )
    breakdown = score_finding(finding)
    assert breakdown.label == "low"
    assert breakdown.score < MEDIUM_THRESHOLD
    _blame(breakdown, penalties="bounces the request elsewhere")
    _blame(breakdown, penalties="synthetic redirect label")
    _blame(breakdown, penalties="empty response body")


def test_plain_page_without_extra_evidence_is_medium() -> None:
    breakdown = score_finding(
        FindingStub(server=None, tls=False, tls_version=None, fingerprint=None)
    )
    assert breakdown.label == "medium"
    assert MEDIUM_THRESHOLD <= breakdown.score < HIGH_THRESHOLD


def test_auth_gated_scores_between_open_and_missing() -> None:
    common = dict(content_length=2048, fingerprint=None, server=None, tls=False)
    open_score = score_finding(FindingStub(status=200, **common)).score
    gated_score = score_finding(FindingStub(status=401, **common)).score
    missing_score = score_finding(FindingStub(status=404, **common)).score
    assert open_score > gated_score > missing_score

    gated = score_finding(FindingStub(status=403, title="Login", **common))
    _blame(gated, reasons="gated")
    _blame(gated, penalties="client error")


def test_scores_are_clamped_to_zero_and_one_hundred() -> None:
    hostile = FindingStub(
        status=500,
        title=None,
        server=None,
        tls=False,
        content_length=0,
        fingerprint="wildcardfingerprint",
        aliases=[8443, 8080, 8000],
    )
    breakdown = score_finding(
        hostile,
        wildcard_ips=("203.0.113.10",),
        wildcard_fingerprints=("wildcardfingerprint",),
        resolvers_agreeing=1,
        shared_content_lengths=9,
        shared_fingerprints=9,
    )
    assert breakdown.score == 0
    assert breakdown.label == "low"
    assert len(breakdown.penalties) >= 6

    maximal = score_finding(
        FindingStub(aliases=[8443]),
        resolvers_agreeing=3,
        favicon_hash="116323821",
        technologies=[Tech("nginx"), Tech("PHP", "language"), Tech("WordPress", "CMS")],
        data_files={"/robots.txt": 200, "/sitemap.xml": 200, "/crossdomain.xml": 200},
        headers={"Server": "nginx", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"},
    )
    assert maximal.score == 100
    assert maximal.label == "high"


# --------------------------------------------------------------------------- #
# Individual signals
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("overrides", "kwargs", "expected"),
    [
        (
            {},
            {},
            {
                "reasons": [
                    "HTTP 200 — the application served a real response",
                    "page title present",
                    "content length 4096 bytes is in a plausible range",
                    "Server header present",
                    "TLS negotiated (TLSv1.3)",
                    "distinct from siblings",
                ]
            },
        ),
        ({"status": 301, "kind": "interface"}, {}, {"reasons": ["redirect that stays on the scanned port"]}),
        ({"status": 401}, {}, {"reasons": ["gated"], "penalties": ["client error"]}),
        ({"status": 429}, {}, {"reasons": ["gated"], "penalties": ["client error"]}),
        (
            {"status": 404},
            {},
            {"penalties": ["HTTP 404 — client error"], "no_reasons": ["served a real response"]},
        ),
        ({"status": 500}, {}, {"penalties": ["HTTP 500 — server error"]}),
        ({"status": None}, {}, {"penalties": ["no HTTP status was recorded"]}),
        ({"title": None}, {}, {"penalties": ["no page title"]}),
        (
            {"title": "redirects to https://x/"},
            {},
            {"penalties": ["synthetic redirect label"], "no_reasons": ["page title present"]},
        ),
        ({"content_length": 0}, {}, {"penalties": ["empty response body"]}),
        ({"content_length": 12}, {}, {"penalties": ["likely a placeholder"]}),
        ({"content_length": 4096}, {}, {"reasons": ["plausible range"]}),
        ({"server": None}, {}, {"no_reasons": ["Server header present"]}),
        ({"server": "nginx"}, {}, {"reasons": ["Server header present"]}),
        ({"tls": False}, {}, {"no_reasons": ["TLS negotiated"]}),
        ({"tls": True}, {}, {"reasons": ["TLS negotiated"]}),
        ({"fingerprint": None}, {}, {"no_reasons": ["distinct from siblings"]}),
        ({"fingerprint": "abc"}, {}, {"reasons": ["distinct from siblings"]}),
        (
            {"kind": "redirect", "status": 302},
            {},
            {"penalties": ["bounces the request elsewhere"], "no_reasons": ["redirect that stays"]},
        ),
        (
            {"aliases": [1, 2]},
            {},
            {"reasons": ["multi-service host"], "penalties": ["serving identical content"]},
        ),
        ({}, {"favicon_hash": "116323821"}, {"reasons": ["favicon hash 116323821"]}),
        ({}, {"technologies": [Tech("nginx")]}, {"reasons": ["1 technologies detected"]}),
        ({}, {"data_files": {"/robots.txt": 200}}, {"reasons": ["well-known data files answered"]}),
        (
            {},
            {"data_files": {"/robots.txt": 404, "/.env": 404}},
            {"no_reasons": ["well-known data files"]},
        ),
        (
            {},
            {"headers": {"X-Frame-Options": "DENY"}},
            {"reasons": ["security/technology headers present"]},
        ),
        ({}, {"headers": {}}, {"no_reasons": ["security/technology headers"]}),
        ({}, {"resolvers_agreeing": 2}, {"reasons": ["resolvers agree"]}),
        ({}, {"resolvers_agreeing": 1}, {"penalties": ["only one resolver returned this IP"]}),
        (
            {},
            {"resolvers_agreeing": 0},
            {"no_reasons": ["resolvers agree"], "no_penalties": ["only one resolver"]},
        ),
        ({}, {"shared_content_lengths": 4}, {"penalties": ["uniform responses"]}),
        ({}, {"shared_content_lengths": 1}, {"no_penalties": ["uniform responses"]}),
        ({}, {"shared_fingerprints": 3}, {"penalties": ["identical boilerplate"]}),
        # One other host on the same scheme serving the byte-identical response
        # is already boilerplate, so the threshold is >= 1 rather than >= 2.
        (
            {},
            {"shared_fingerprints": 1},
            {"no_reasons": ["distinct from siblings"], "penalties": ["boilerplate"]},
        ),
        ({}, {"wildcard_ips": ("203.0.113.10",)}, {"penalties": ["wildcard responder"]}),
        (
            {},
            {"wildcard_fingerprints": ("0123456789abcdef",)},
            {"penalties": ["matches the wildcard signature"]},
        ),
        ({}, {"open_ports": 5}, {"reasons": ["host answers on 5 ports"]}),
    ],
)
def test_each_signal_is_explained(
    overrides: dict[str, Any], kwargs: dict[str, Any], expected: dict[str, list[str]]
) -> None:
    breakdown = score_finding(FindingStub(**overrides), **kwargs)
    for text in expected.get("reasons", []):
        assert any(text in reason for reason in breakdown.reasons), (text, breakdown.reasons)
    for text in expected.get("penalties", []):
        assert any(text in penalty for penalty in breakdown.penalties), (
            text,
            breakdown.penalties,
        )
    for text in expected.get("no_reasons", []):
        assert not any(text in reason for reason in breakdown.reasons), (
            text,
            breakdown.reasons,
        )
    for text in expected.get("no_penalties", []):
        assert not any(text in penalty for penalty in breakdown.penalties), (
            text,
            breakdown.penalties,
        )


def test_technology_header_and_data_file_weights_are_capped() -> None:
    def base(**overrides: Any) -> FindingStub:
        return FindingStub(
            status=200, title="x", content_length=4096, server=None, tls=False,
            fingerprint=None, **overrides,
        )

    one = score_finding(base(), technologies=[Tech("a")]).score
    two = score_finding(base(), technologies=[Tech("a"), Tech("b")]).score
    three = score_finding(base(), technologies=[Tech(x) for x in "abc"]).score
    ten = score_finding(base(), technologies=[Tech(x) for x in "abcdefghij"]).score
    assert (one, two, three) == (
        score_finding(base()).score + WEIGHTS["technology_each"],
        score_finding(base()).score + 2 * WEIGHTS["technology_each"],
        score_finding(base()).score + WEIGHTS["technology_max"],
    )
    assert ten == three, "technology weight must be capped"

    headers_three = score_finding(base(), headers={f"H{i}": "x" for i in range(3)}).score
    headers_six = score_finding(base(), headers={f"H{i}": "x" for i in range(6)}).score
    assert headers_six == headers_three == score_finding(base()).score + WEIGHTS["security_header_max"]

    files_three = score_finding(base(), data_files={f"/f{i}": 200 for i in range(3)}).score
    files_six = score_finding(base(), data_files={f"/f{i}": 200 for i in range(6)}).score
    assert files_six == files_three == score_finding(base()).score + WEIGHTS["data_file_max"]


def test_no_signal_contribution_is_silent() -> None:
    """Every weighted signal must appear in one of the two explanation lists."""
    documented = {
        "status_2xx",
        "status_3xx_same_port",
        "status_auth_gated",
        "status_client_error",
        "status_server_error",
        "status_missing",
        "title_present",
        "title_missing",
        "title_redirect_label",
        "content_length_plausible",
        "content_length_tiny",
        "content_length_empty",
        "content_length_uniform",
        "server_header",
        "tls",
        "multi_port_host",
        "favicon",
        "technology_each",
        "technology_max",
        "security_header_each",
        "security_header_max",
        "data_file_each",
        "data_file_max",
        "fingerprint_distinct",
        "fingerprint_shared",
        "fingerprint_wildcard",
        "wildcard_ip",
        "resolvers_single",
        "resolvers_agreeing",
        "alias_ports",
        "kind_redirect",
    }
    assert set(WEIGHTS) == documented
    assert all(isinstance(weight, int) for weight in WEIGHTS.values())


# --------------------------------------------------------------------------- #
# Robustness / explainability invariants
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "finding",
    [
        FindingStub(),
        FindingStub(status=None, title=None, server=None, tls=False, content_length=0, fingerprint=None),
        FindingStub(status=500, kind="misconfigured"),
        FindingStub(status=301, kind="redirect", title="redirects to https://x/", content_length=0),
        FindingStub(status=401, kind="restricted", title="Sign in"),
        _dict_finding(),
        _dict_finding(status=204, title=None, content_length=0),
        {},
        object(),
    ],
    ids=["clean", "empty", "5xx", "redirect", "gated", "dict", "dict-204", "empty-dict", "object"],
)
def test_every_score_is_bounded_explained_and_labelled(finding: Any) -> None:
    breakdown = score_finding(finding)
    assert isinstance(breakdown, ConfidenceBreakdown)
    assert 0 <= breakdown.score <= 100
    assert breakdown.label in {"high", "medium", "low"}
    assert breakdown.reasons or breakdown.penalties, "a score with no explanation"
    assert all(text.strip() for text in breakdown.reasons + breakdown.penalties)
    assert breakdown.to_dict()["score"] == breakdown.score
    assert breakdown.render().startswith(f"{breakdown.label} {breakdown.score}")


def test_unknown_attributes_do_not_break_scoring() -> None:
    breakdown = score_finding({"status": "200", "content_length": "4096", "title": 12345})
    assert 0 <= breakdown.score <= 100
    assert breakdown.reasons or breakdown.penalties


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "low"),
        (44, "low"),
        (MEDIUM_THRESHOLD, "medium"),
        (74, "medium"),
        (HIGH_THRESHOLD, "high"),
        (100, "high"),
    ],
)
def test_label_thresholds(score: int, expected: str) -> None:
    assert label_for(score) == expected
    assert HIGH_THRESHOLD == 75
    assert MEDIUM_THRESHOLD == 45


def test_breakdown_explanation_text_is_stable() -> None:
    breakdown = score_finding(
        FindingStub(server=None, tls=False, tls_version=None, fingerprint=None)
    )
    rendered = breakdown.render()
    assert "medium" in rendered
    assert "HTTP 200" in rendered
    payload = breakdown.to_dict()
    assert payload["label"] == breakdown.label
    assert payload["reasons"] == breakdown.reasons
    assert payload["penalties"] == breakdown.penalties


# --------------------------------------------------------------------------- #
# rank_findings
# --------------------------------------------------------------------------- #


def test_ranking_is_sorted_by_score_descending() -> None:
    clean = FindingStub(
        subdomain="clean.example.com",
        url="https://clean.example.com",
        content_length=4096,
    )
    plain = FindingStub(
        subdomain="plain.example.com",
        url="https://plain.example.com",
        server=None,
        tls=False,
        fingerprint=None,
        content_length=3072,
    )
    gated = FindingStub(
        subdomain="gated.example.com",
        url="https://gated.example.com",
        status=401,
        title="Sign in",
        server=None,
        tls=False,
        fingerprint=None,
        content_length=2048,
    )
    bounce = FindingStub(
        subdomain="bounce.example.com",
        url="http://bounce.example.com:2082",
        status=301,
        kind="redirect",
        title="redirects to https://bounce.example.com/",
        content_length=0,
        server=None,
        tls=False,
        fingerprint=None,
    )
    ranked = rank_findings([bounce, gated, plain, clean], favicon_hash="116323821")
    assert [finding for finding, _ in ranked] == [clean, plain, gated, bounce]
    scores = [breakdown.score for _, breakdown in ranked]
    assert scores == sorted(scores, reverse=True)
    assert ranked[0][1].label == "high"
    assert ranked[-1][1].label == "low"
    # the original objects are returned, not copies
    assert ranked[0][0] is clean


def test_ranking_detects_uniform_content_length_and_shared_fingerprint() -> None:
    twins = [
        FindingStub(subdomain=f"twin{i}.example.com", url=f"https://twin{i}.example.com")
        for i in range(3)
    ]
    unique = FindingStub(
        subdomain="unique.example.com",
        url="https://unique.example.com",
        content_length=9999,
        fingerprint="unique-fingerprint",
    )
    ranked = rank_findings([*twins, unique])
    by_host = {finding.subdomain: breakdown for finding, breakdown in ranked}
    for twin in twins:
        _blame(by_host[twin.subdomain], penalties="uniform responses")
        _blame(by_host[twin.subdomain], penalties="identical boilerplate")
    assert not any("uniform" in text for text in by_host["unique.example.com"].penalties)
    assert not any("boilerplate" in text for text in by_host["unique.example.com"].penalties)
    _blame(by_host["unique.example.com"], reasons="distinct from siblings")
    assert by_host["unique.example.com"].score > by_host["twin0.example.com"].score


def test_ranking_resolves_per_host_context_maps() -> None:
    a = FindingStub(subdomain="a.example.com", url="https://a.example.com")
    b = FindingStub(subdomain="b.example.com", url="https://b.example.com")
    ranked = rank_findings(
        [a, b],
        technologies={"a.example.com": [Tech("nginx"), Tech("WordPress", "CMS")]},
        favicon_hash={"a.example.com": "116323821"},
        data_files={"a.example.com": {"/robots.txt": 200}},
    )
    by_host = {finding.subdomain: breakdown for finding, breakdown in ranked}
    _blame(by_host["a.example.com"], reasons="2 technologies detected")
    _blame(by_host["a.example.com"], reasons="favicon hash")
    _blame(by_host["a.example.com"], reasons="well-known data files")
    assert not any("technologies" in text for text in by_host["b.example.com"].reasons)
    assert not any("favicon" in text for text in by_host["b.example.com"].reasons)
    assert by_host["a.example.com"].score > by_host["b.example.com"].score


def test_ranking_treats_a_path_to_status_map_as_global_context() -> None:
    findings = [
        FindingStub(subdomain="a.example.com", url="https://a.example.com"),
        FindingStub(subdomain="b.example.com", url="https://b.example.com"),
    ]
    ranked = rank_findings(findings, data_files={"/robots.txt": 200, "/.env": 404})
    for _, breakdown in ranked:
        _blame(breakdown, reasons="well-known data files")


def test_ranking_ignores_unknown_context_keys() -> None:
    ranked = rank_findings([FindingStub()], not_a_signal=1, another="x")
    assert len(ranked) == 1
    assert ranked[0][1].score > 0


def test_ranking_of_an_empty_sequence() -> None:
    assert rank_findings([]) == []


def test_ranking_accepts_single_findings_and_dicts() -> None:
    ranked = rank_findings([_dict_finding(), FindingStub()], resolvers_agreeing=2)
    assert len(ranked) == 2
    for _, breakdown in ranked:
        _blame(breakdown, reasons="resolvers agree")


# --------------------------------------------------------------------------- #
# Fingerprinting output feeds scoring
# --------------------------------------------------------------------------- #


def test_fingerprinting_output_on_the_finding_is_used() -> None:
    finding = MergedFinding(
        favicon_hash="-391155043",
        technologies=[Tech("nginx"), Tech("WordPress", "CMS")],
        data_files={"/robots.txt": 200, "/wp-login.php": 302},
        headers={"Server": "nginx", "X-Frame-Options": "DENY"},
    )
    breakdown = score_finding(finding)
    _blame(breakdown, reasons="favicon hash -391155043")
    _blame(breakdown, reasons="2 technologies detected")
    _blame(breakdown, reasons="2 well-known data files answered")
    _blame(breakdown, reasons="2 security/technology headers present")
    assert breakdown.label == "high"


def test_explicit_arguments_override_finding_attributes() -> None:
    finding = MergedFinding(favicon_hash="from-finding", technologies=[Tech("nginx")])
    breakdown = score_finding(finding, favicon_hash="from-argument", technologies=[])
    _blame(breakdown, reasons="favicon hash from-argument")
    assert not any("technologies detected" in text for text in breakdown.reasons)


def test_scores_a_real_web_probe_result_when_importable() -> None:
    try:
        from subsonar.core.web_probe import WebProbeResult
    except Exception as exc:  # pragma: no cover - concurrent workstream
        pytest.skip(f"web_probe unavailable: {exc}")
    result = WebProbeResult(
        host="a.example.com",
        ip="203.0.113.10",
        port=443,
        scheme="https",
        url="https://a.example.com",
        status=200,
        title="Example Domain",
        server="nginx",
        content_length=4096,
        tls=True,
        tls_version="TLSv1.3",
        fingerprint="0123456789abcdef",
        kind="interface",
    )
    breakdown = score_finding(result, favicon_hash="116323821")
    assert breakdown.label == "high"
    assert breakdown.score >= HIGH_THRESHOLD


def test_scores_a_real_engine_finding_when_importable() -> None:
    try:
        from subsonar.core.engine import Finding
    except Exception as exc:  # pragma: no cover - concurrent workstream
        pytest.skip(f"engine unavailable: {exc}")
    finding = Finding(
        subdomain="a.example.com",
        ip="203.0.113.10",
        port=443,
        scheme="https",
        url="https://a.example.com",
        status=200,
        title="Example Domain",
        server="nginx",
        tls=True,
        tls_version="TLSv1.3",
        content_length=4096,
        fingerprint="0123456789abcdef",
        kind="interface",
    )
    breakdown = score_finding(finding, favicon_hash="116323821", resolvers_agreeing=2)
    assert breakdown.label == "high"
    assert breakdown.score > score_finding(finding).score - 1
    assert rank_findings([finding])[0][1].score == score_finding(finding).score
