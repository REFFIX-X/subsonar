"""Lightweight template-style checks run against confirmed web interfaces.

A small, dependency-free engine in the spirit of nuclei templates: every check
is a declarative rule — a set of paths, the statuses that count as a match, and
a severity — and each match is reported with evidence.  Checks are **status
only**: the response body is never read, so probing for ``/.env`` or
``/.git/config`` can never capture their contents.

All requests go through the caller's :class:`~subsonar.core.web_probe.WebProbe`
session, so the anonymous-resolver privacy guarantee is preserved and no new
HTTP session (or OS resolver) is ever created here.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

__all__ = ["TemplateMatch", "TemplateRule", "TEMPLATES", "run_template_checks"]

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True, slots=True)
class TemplateRule:
    """One check: probe ``paths``, flag the rule when any status matches."""

    id: str
    name: str
    severity: str
    description: str = ""
    paths: tuple[str, ...] = ()
    statuses: frozenset[int] = frozenset({200})


@dataclass(slots=True)
class TemplateMatch:
    """One confirmed exposure."""

    id: str
    name: str
    severity: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "evidence": self.evidence,
        }


#: The built-in check set.  All sensitive-file rules are status-only by design.
TEMPLATES: tuple[TemplateRule, ...] = (
    TemplateRule(
        "dotenv-exposed",
        "Environment file exposed",
        "critical",
        "A /.env file is being served (secrets are likely inside).",
        ("/.env",),
        # 200 only: a 301/302 is what a catch-all server returns for *every*
        # unknown path (the soft-404), which is not evidence of a served file.
        frozenset({200}),
    ),
    TemplateRule(
        "git-config-exposed",
        "Git repository exposed",
        "high",
        "The .git directory is reachable — source history may be disclosed.",
        ("/.git/config", "/.git/HEAD"),
        frozenset({200}),
    ),
    TemplateRule(
        "svn-entries-exposed",
        "Subversion metadata exposed",
        "high",
        ".svn/entries is reachable — repository metadata may be disclosed.",
        ("/.svn/entries",),
        frozenset({200}),
    ),
    TemplateRule(
        "aws-credentials-exposed",
        "AWS credentials exposed",
        "critical",
        "An .aws/credentials file is being served.",
        ("/.aws/credentials",),
        frozenset({200}),
    ),
    TemplateRule(
        "phpinfo-exposed",
        "phpinfo() exposed",
        "medium",
        "phpinfo.php is reachable and discloses the PHP configuration.",
        ("/phpinfo.php",),
        frozenset({200}),
    ),
    TemplateRule(
        "server-status-exposed",
        "Apache server-status exposed",
        "medium",
        "The server-status page is reachable and leaks request state.",
        ("/server-status",),
        frozenset({200}),
    ),
    TemplateRule(
        "actuator-exposed",
        "Spring Boot actuator exposed",
        "medium",
        "Actuator endpoints are reachable — runtime internals may be disclosed.",
        ("/actuator", "/actuator/health", "/actuator/env"),
        frozenset({200}),
    ),
    TemplateRule(
        "tomcat-manager-exposed",
        "Tomcat manager exposed",
        "medium",
        "The Tomcat manager application is reachable (possibly auth-gated).",
        ("/manager/html",),
        frozenset({200, 401, 403}),
    ),
    TemplateRule(
        "adminer-exposed",
        "Adminer exposed",
        "high",
        "Adminer (database admin) is reachable.",
        ("/adminer.php",),
        frozenset({200}),
    ),
    TemplateRule(
        "docker-api-exposed",
        "Docker API exposed",
        "high",
        "The Docker daemon HTTP API answers on this port.",
        ("/version",),
        frozenset({200}),
    ),
    TemplateRule(
        "grafana-login",
        "Grafana login exposed",
        "info",
        "A Grafana login page is reachable.",
        ("/login",),
        frozenset({200}),
    ),
    TemplateRule(
        "jenkins-script",
        "Jenkins script console exposed",
        "high",
        "The Jenkins script console is reachable.",
        ("/script",),
        frozenset({200}),
    ),
)


async def run_template_checks(
    probe: Any,
    scheme: str,
    host: str,
    ip: str,
    port: int,
    *,
    concurrency: int = 8,
    known_statuses: Mapping[str, int] | None = None,
) -> list[TemplateMatch]:
    """Run every template against ``scheme://host:port`` and return matches.

    *probe* must expose ``probe_status(host, port, path, scheme=...)`` returning
    a ``dict`` with a ``status`` key (the :class:`WebProbe` API).  Never raises.

    *known_statuses* maps a path to a status the caller already measured (the
    fingerprinter probes several of the same paths), so those are not fetched a
    second time.
    """
    if probe is None:
        return []
    checker = getattr(probe, "probe_status", None)
    if checker is None:
        return []

    known = dict(known_statuses or {})
    jobs: list[tuple[TemplateRule, str]] = [
        (rule, path) for rule in TEMPLATES for path in rule.paths
    ]
    limiter = asyncio.Semaphore(max(1, concurrency))
    matches: list[TemplateMatch] = []
    seen_rules: set[str] = set()

    async def one(rule: TemplateRule, path: str) -> None:
        if path in known:
            status: int | None = known[path]
        else:
            async with limiter:
                try:
                    info = await checker(host, port, path, scheme=scheme)
                except Exception:  # pragma: no cover - best effort
                    return
            status = info.get("status") if isinstance(info, dict) else None
        if status in rule.statuses and rule.id not in seen_rules:
            seen_rules.add(rule.id)
            matches.append(
                TemplateMatch(
                    id=rule.id,
                    name=rule.name,
                    severity=rule.severity,
                    evidence=f"{path} → HTTP {status}",
                )
            )

    await asyncio.gather(*(one(rule, path) for rule, path in jobs), return_exceptions=True)
    matches.sort(key=lambda m: (SEVERITY_ORDER.index(m.severity), m.name))
    return matches
