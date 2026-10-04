"""Embedded port matrices, port profiles and port-spec parsing."""

from __future__ import annotations

import re
from typing import Iterable, Mapping

from .config import (
    INFRASTRUCTURE_PORTS,
    PORT_LABELS,
    PORT_MATRIX,
    PORT_MATRIX_EXTENDED,
    TLS_FIRST_PORTS,
)

#: Total size of the embedded *core* matrix — asserted at import time.
PORT_MATRIX_SIZE = len(PORT_MATRIX)

#: Ports that make up the "web" core of the matrix.
WEB_CORE_PORTS: tuple[int, ...] = (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443)

#: Ports reserved for the infrastructure audit profile.
AUDIT_PORTS: tuple[int, ...] = INFRASTRUCTURE_PORTS

#: Selectable matrices.  ``core`` is the Top-50 default; ``extended`` is the
#: "catch more" set (~1/3 of the ports people actually expose); ``web`` and
#: ``audit`` back the passive and infrastructure-audit profiles.
MATRICES: dict[str, dict[int, str]] = {
    "core": dict(PORT_MATRIX),
    "top50": dict(PORT_MATRIX),
    "extended": dict(PORT_MATRIX_EXTENDED),
    "web": {port: PORT_LABELS[port] for port in WEB_CORE_PORTS if port in PORT_LABELS},
    "audit": {port: PORT_LABELS.get(port, "Admin-Alt") for port in AUDIT_PORTS},
}

#: Accepted spellings for the matrix names.
MATRIX_ALIASES: dict[str, str] = {
    "top-50": "core",
    "top50": "core",
    "50": "core",
    "default": "core",
    "full": "extended",
    "top200": "extended",
    "top-200": "extended",
    "infra": "audit",
    "infrastructure": "audit",
}

_PORT_RANGE_RE = re.compile(r"^(\d{1,5})\s*-\s*(\d{1,5})$")


def describe(port: int) -> str:
    """Human label for a port, e.g. ``8443 → HTTPS-Alt``."""
    return PORT_LABELS.get(port, "Unknown")


def describe_matrix(matrix: Mapping[int, str] | None) -> str:
    """Name of a matrix by its port set, else ``custom``.

    Used by the scan plan so the UI can state *which* matrix is really in use
    (a profile supplies one, an explicit ``--port-matrix``/``--ports`` replaces
    it, and the difference matters when reading a report later).
    """
    ports = set(matrix or {})
    if not ports:
        return "empty"
    for name in ("core", "extended", "web", "audit"):
        if set(MATRICES[name]) == ports:
            return name
    return f"custom {len(ports)}-port"


def resolve_matrix(name: str) -> dict[int, str]:
    """Return a named matrix (``core``, ``extended``, ``web``, ``audit``)."""
    key = str(name or "").strip().lower().replace(" ", "")
    key = MATRIX_ALIASES.get(key, key)
    try:
        return dict(MATRICES[key])
    except KeyError:
        raise ValueError(
            f"unknown port matrix {name!r} — choose one of "
            + ", ".join(sorted({"core", "extended", "web", "audit"}))
        ) from None


def parse_port_spec(spec: str) -> dict[int, str]:
    """Parse a port spec into ``{port: label}``.

    Accepts a matrix name (``extended``), a comma list (``80,443``), ranges
    (``8000-8100``) or any mix (``core,9000-9010,11434``).  Order is preserved
    and duplicates collapse onto the first mention.
    """
    text = str(spec or "").strip()
    if not text:
        raise ValueError("empty port spec — try 'core', 'extended' or '80,443'")

    matrix = MATRICES.get(MATRIX_ALIASES.get(text.replace(" ", "").lower(), text.lower()))
    if matrix is not None:
        return dict(matrix)

    ports: dict[int, str] = {}
    for raw_token in text.split(","):
        token = raw_token.strip()
        if not token:
            continue
        if token.lower() in MATRICES or token.lower() in MATRIX_ALIASES:
            for port, label in resolve_matrix(token).items():
                ports.setdefault(port, label)
            continue
        match = _PORT_RANGE_RE.match(token)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start > end:
                raise ValueError(f"port range {token!r} is descending")
            if not 0 < start <= 65535 or not 0 < end <= 65535:
                raise ValueError(f"port range {token!r} is outside 1-65535")
            for port in range(start, end + 1):
                ports.setdefault(port, describe(port))
            continue
        if not token.isdigit():
            raise ValueError(
                f"invalid port token {token!r} — use 80,443 / 8000-8100 / core"
            )
        port = int(token)
        if not 0 < port <= 65535:
            raise ValueError(f"port {token!r} is outside 1-65535")
        ports.setdefault(port, describe(port))
    if not ports:
        raise ValueError(f"port spec {spec!r} selected no ports")
    return ports


def port_map(ports: Iterable[int]) -> dict[int, str]:
    """Ordered ``{port: label}`` mapping for the requested ports."""
    return {port: describe(port) for port in ports}


def full_matrix() -> dict[int, str]:
    return dict(PORT_MATRIX)


def extended_matrix() -> dict[int, str]:
    return dict(PORT_MATRIX_EXTENDED)


def audit_matrix() -> dict[int, str]:
    """Alternative-admin-only matrix used by profile 7."""
    return resolve_matrix("audit")


def web_matrix() -> dict[int, str]:
    return resolve_matrix("web")


def prefers_tls(port: int) -> bool:
    """True when the port is expected to speak TLS first."""
    return port in TLS_FIRST_PORTS


def is_https_likely(port: int) -> bool:
    return port in TLS_FIRST_PORTS or port in (443, 8443, 9443)


def scheme_order(port: int) -> tuple[str, ...]:
    """Probe order for a port: TLS-first ports try ``https`` before ``http``."""
    return ("https", "http") if prefers_tls(port) else ("http", "https")


def summarise(matrix: Mapping[int, str] | None = None) -> str:
    matrix = matrix or PORT_MATRIX
    return f"{len(matrix)} ports: " + ", ".join(str(p) for p in sorted(matrix))


def validate_matrix() -> None:
    """Fail loudly if the embedded matrices are inconsistent."""
    if PORT_MATRIX_SIZE != 50:
        raise RuntimeError(
            f"PORT_MATRIX must contain exactly 50 ports, found {PORT_MATRIX_SIZE}"
        )
    core = set(PORT_MATRIX)
    for name, matrix in MATRICES.items():
        invalid = sorted(port for port in matrix if not 0 < port < 65536)
        if invalid:
            raise RuntimeError(f"{name} matrix has invalid port numbers: {invalid}")
    extended = set(PORT_MATRIX_EXTENDED)
    if len(PORT_MATRIX_EXTENDED) != len(extended):
        raise RuntimeError("PORT_MATRIX_EXTENDED contains duplicate ports")
    if not core.issubset(extended):
        raise RuntimeError("the extended matrix must contain every core port")
    if len(extended) < 100:
        raise RuntimeError(
            f"the extended matrix should offer a meaningful superset, found "
            f"{len(extended)} ports"
        )
    unknown = sorted(port for port in PORT_LABELS if not 0 < port < 65536)
    if unknown:
        raise RuntimeError(f"invalid port numbers in PORT_LABELS: {unknown}")


validate_matrix()
