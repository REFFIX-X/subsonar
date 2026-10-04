"""Direct PyPI wheel installer for sandboxed environments.

``pip`` cannot complete inside this workspace sandbox: ``ensurepip`` fails while
cleaning its temporary directory and a ``pip install`` run stalls with no output
before touching site-packages.  This module does the one thing subsonar needs —
resolve a package's wheels from the PyPI JSON API and extract them straight into
``site-packages`` — using only the standard library.

Usage::

    python tools/wheel_installer.py aiohttp textual streamlit
    python tools/wheel_installer.py --list aiohttp
    python tools/wheel_installer.py --check aiohttp textual
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import sys
import sysconfig
import zipfile
from dataclasses import dataclass, field
from email.parser import Parser
from pathlib import Path
from typing import Iterable, Sequence
from urllib.request import Request, urlopen

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
USER_AGENT = "subsonar-wheel-installer/1.0"

#: Marker variables used when evaluating environment markers in METADATA.
MARKER_ENV = {
    "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
    "python_full_version": sys.version.split()[0],
    "sys_platform": sys.platform,
    "platform_system": {"win32": "Windows", "linux": "Linux", "darwin": "Darwin"}.get(
        sys.platform, sys.platform
    ),
    "os_name": os.name,
    "platform_machine": os.environ.get("PROCESSOR_ARCHITECTURE", "").lower() or "unknown",
    "implementation_name": sys.implementation.name,
    "extra": "",
}


def site_packages() -> Path:
    """The active interpreter's ``site-packages`` directory."""
    return Path(sysconfig.get_path("purelib"))


def scripts_dir() -> Path:
    return Path(sysconfig.get_path("scripts") or Path(sys.executable).parent)


# --------------------------------------------------------------------------- #
# Tag matching
# --------------------------------------------------------------------------- #


def supported_tags() -> list[tuple[str, str, str, str]]:
    """Ordered list of (python, abi, platform) tags this interpreter accepts."""
    impl = sys.implementation.name
    major, minor = sys.version_info.major, sys.version_info.minor
    tags: list[tuple[str, str, str, str]] = []
    py_tags = [f"cp{major}{minor}", f"cp{major}", f"py{major}{minor}", f"py{major}", "py3", "py2.py3"]
    abi_tags = [f"cp{major}{minor}", f"cp{major}{minor}m", "abi3", "none"]
    if os.name == "nt":
        arch = "arm64" if os.environ.get("PROCESSOR_ARCHITECTURE", "").lower() == "arm64" else (
            "win_amd64" if sys.maxsize > 2**32 else "win32"
        )
        platform_tags = [f"win_{arch}", "win_amd64", "win32", "any"]
    elif sys.platform == "darwin":
        platform_tags = ["macosx_11_0_arm64", "macosx_10_9_x86_64", "any"]
    else:
        platform_tags = ["manylinux2014_x86_64", "manylinux_2_17_x86_64", "linux_x86_64", "any"]
    for py in py_tags:
        for abi in abi_tags:
            for plat in platform_tags:
                tags.append((py, abi, plat))
    return tags


TAG_ORDER = {tag: index for index, tag in enumerate(supported_tags())}


def wheel_tag_score(filename: str) -> int | None:
    """Return a preference score for a wheel filename, or None if unusable."""
    m = re.match(
        r"^(?P<name>[^-]+)-(?P<ver>[^-]+)(?:-(?P<build>\d[^-]*))?-(?P<py>[^-]+)-(?P<abi>[^-]+)-(?P<plat>[^.]+)\.whl$",
        filename,
    )
    if not m:
        return None
    candidates: list[tuple[str, str, str]] = []
    for py in m.group("py").split("."):
        for abi in m.group("abi").split("."):
            for plat in m.group("plat").split("."):
                candidates.append((py, abi, plat))
    best: int | None = None
    for tag in candidates:
        rank = TAG_ORDER.get(tag)
        if rank is not None and (best is None or rank < best):
            best = rank
    return best


def is_sdist(filename: str) -> bool:
    return filename.endswith((".tar.gz", ".zip")) and not filename.endswith(".whl")


# --------------------------------------------------------------------------- #
# PyPI access
# --------------------------------------------------------------------------- #


def fetch_json(url: str) -> dict:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    ctx = None
    try:
        import ssl

        ctx = ssl.create_default_context()
    except Exception:  # pragma: no cover
        ctx = None
    with urlopen(request, timeout=60, context=ctx) as response:
        return json.loads(response.read().decode("utf-8"))


def download(url: str, *, expected_sha256: str | None = None) -> bytes:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    import ssl

    with urlopen(request, timeout=180, context=ssl.create_default_context()) as response:
        data = response.read()
    if expected_sha256:
        digest = hashlib.sha256(data).hexdigest()
        if digest.lower() != expected_sha256.lower():
            raise RuntimeError(
                f"sha256 mismatch for {url}: {digest} != {expected_sha256}"
            )
    return data


@dataclass
class Candidate:
    name: str
    version: str
    filename: str
    url: str
    sha256: str | None
    score: int
    requires_python: str | None = None
    size: int = 0


def python_ok(requires_python: str | None) -> bool:
    if not requires_python:
        return True
    spec = requires_python.strip()
    try:
        from packaging.specifiers import SpecifierSet  # type: ignore

        return sys.version.split()[0] in SpecifierSet(spec)
    except Exception:
        pass
    # Fallback: understand the common ">=3.8" / ">=3.9,<4" shapes.
    for clause in spec.split(","):
        clause = clause.strip()
        m = re.match(r"^(>=|<=|==|>|<|~=)\s*(\d+(?:\.\d+)*)", clause)
        if not m:
            continue
        op, raw = m.group(1), m.group(2)
        want = tuple(int(part) for part in raw.split("."))
        have = sys.version_info[: len(want)]
        if op == ">=" and not have >= want:
            return False
        if op == "<=" and not have <= want:
            return False
        if op == ">" and not have > want:
            return False
        if op == "<" and not have < want:
            return False
        if op == "==" and not have == want:
            return False
        if op == "~=" and not (have >= want and have[0] == want[0]):
            return False
    return True


def candidates_for(name: str, *, version: str | None = None) -> list[Candidate]:
    url = PYPI_JSON.format(name=name if version is None else f"{name}/{version}")
    try:
        payload = fetch_json(url)
    except Exception as exc:
        raise RuntimeError(f"PyPI lookup failed for {name}: {exc}") from exc
    releases = payload.get("releases") or {}
    if version:
        releases = {payload["info"]["version"]: releases.get(payload["info"]["version"], [])}
    out: list[Candidate] = []
    for release_version, files in releases.items():
        if not files:
            continue
        for entry in files:
            filename = entry.get("filename", "")
            score = wheel_tag_score(filename)
            if score is None:
                continue
            if not python_ok(entry.get("requires_python")):
                continue
            out.append(
                Candidate(
                    name=payload["info"]["name"],
                    version=release_version,
                    filename=filename,
                    url=entry["url"],
                    sha256=(entry.get("digests") or {}).get("sha256"),
                    score=score,
                    requires_python=entry.get("requires_python"),
                    size=entry.get("size") or 0,
                )
            )
    out.sort(key=lambda c: (version_sort_key(c.version), -c.score), reverse=True)
    return out


def version_sort_key(version: str) -> tuple:
    parts = re.split(r"[.\-+]", version)
    key: list[tuple[int, object]] = []
    for part in parts:
        if part.isdigit():
            key.append((1, int(part)))
        else:
            key.append((0, part))
    return tuple(key)


# --------------------------------------------------------------------------- #
# Metadata / dependency parsing
# --------------------------------------------------------------------------- #


@dataclass
class Requirement:
    name: str
    extras: list[str] = field(default_factory=list)
    specifier: str = ""
    marker: str = ""


REQ_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)\s*"
    r"(?:\[(?P<extras>[^\]]+)\])?\s*"
    r"(?P<spec>[^;]*)"
    r"(?:;\s*(?P<marker>.+))?\s*$"
)


def parse_requires(entries: Iterable[str]) -> list[Requirement]:
    out: list[Requirement] = []
    for entry in entries:
        match = REQ_RE.match(entry)
        if not match:
            continue
        out.append(
            Requirement(
                name=match.group("name"),
                extras=[e.strip() for e in (match.group("extras") or "").split(",") if e.strip()],
                specifier=(match.group("spec") or "").strip(),
                marker=(match.group("marker") or "").strip(),
            )
        )
    return out


def marker_applies(marker: str) -> bool:
    """Evaluate a PEP 508 marker with a small safe evaluator."""
    if not marker:
        return True
    expression = marker
    for key, value in MARKER_ENV.items():
        expression = expression.replace(key, repr(str(value)))
    expression = re.sub(r"\bextra\b", "''", expression)
    expression = expression.replace("and", " and ").replace("or", " or ")
    expression = re.sub(r"\bnot\s+in\b", " not in ", expression)
    expression = re.sub(r"\bin\b", " in ", expression)
    allowed = {"__builtins__": {}}
    try:
        return bool(eval(expression, allowed, {}))  # noqa: S307 - sandboxed namespace
    except Exception:
        return True  # unknown marker → install it rather than break the tree


def read_metadata(blob: bytes) -> tuple[dict, dict[str, str]]:
    """Return ``(metadata, package_name_map)`` from a wheel's METADATA."""
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        names = archive.namelist()
        metadata_name = next(
            (n for n in names if n.endswith(".dist-info/METADATA")), None
        )
        if metadata_name is None:
            raise RuntimeError("wheel has no METADATA")
        raw = archive.read(metadata_name).decode("utf-8", "replace")
        wheel_name = next((n for n in names if n.endswith(".dist-info/WHEEL")), None)
        wheel_text = archive.read(wheel_name).decode("utf-8", "replace") if wheel_name else ""
        top_level_name = next(
            (n for n in names if n.endswith(".dist-info/top_level.txt")), None
        )
        top_level = (
            archive.read(top_level_name).decode("utf-8", "replace").split()
            if top_level_name
            else []
        )
    message = Parser().parsestr(raw)
    metadata = {
        "name": message.get("Name", ""),
        "version": message.get("Version", ""),
        "requires": message.get_all("Requires-Dist") or [],
        "summary": message.get("Summary", ""),
        "top_level": top_level,
        "wheel": wheel_text,
    }
    return metadata, {"wheel": wheel_text}


# --------------------------------------------------------------------------- #
# Installation
# --------------------------------------------------------------------------- #


def record_path(dist_info: Path) -> Path:
    return dist_info.with_suffix(".dist-info") if dist_info.suffix != ".dist-info" else dist_info


def already_installed(name: str, version: str | None = None) -> bool:
    target = site_packages()
    normalised = re.sub(r"[-_.]+", "-", name).lower()
    for entry in target.glob("*.dist-info"):
        stem = entry.name[: -len(".dist-info")]
        dist_name, _, dist_version = stem.rpartition("-")
        if re.sub(r"[-_.]+", "-", dist_name).lower() == normalised:
            if version is None or dist_version == version:
                return True
    return False


def install_wheel(blob: bytes, candidate: Candidate) -> Path:
    """Extract a wheel into site-packages, handling ``.data`` subdirectories."""
    target = site_packages()
    target.mkdir(parents=True, exist_ok=True)
    data_scheme = {
        "purelib": target,
        "platlib": target,
        "scripts": scripts_dir(),
        "data": sysconfig.get_path("data") or target,
        "headers": Path(sysconfig.get_path("include") or target),
    }
    recorded: list[str] = []
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        for member in archive.infolist():
            name = member.filename
            if name.endswith("/"):
                continue
            parts = name.split("/")
            if len(parts) > 1 and parts[0].endswith(".data"):
                scheme = parts[1]
                destination_root = data_scheme.get(scheme, target)
                relative = Path(*parts[2:])
                destination = destination_root / relative
            else:
                destination = target / Path(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, open(destination, "wb") as handle:
                shutil.copyfileobj(source, handle)
            if destination.parent.name == ".dist-info" or ".dist-info" in name:
                recorded.append(name)
    # Write the RECORD-independent INSTALLER marker so tooling can spot us.
    dist_infos = list(target.glob(f"{candidate.name.replace('-', '_')}*.dist-info"))
    dist_infos += list(target.glob("*.dist-info"))
    installer = next(
        (d for d in dist_infos if d.name.startswith(candidate.name.replace("-", "_"))),
        dist_infos[0] if dist_infos else target,
    )
    if installer.is_dir():
        (installer / "INSTALLER").write_text("subsonar-wheel-installer\n", encoding="utf-8")
        (installer / "direct_url.json").write_text(
            json.dumps({"url": candidate.url, "archive_info": {"hash": f"sha256={candidate.sha256 or ''}"}}),
            encoding="utf-8",
        )
    # Fix up console scripts in Scripts/ (entry_points) — best effort.
    _write_console_scripts(installer)
    return installer


def _write_console_scripts(dist_info: Path) -> None:
    entry_points = dist_info / "entry_points.txt"
    if not entry_points.is_file():
        return
    text = entry_points.read_text(encoding="utf-8", errors="replace")
    section = None
    scripts: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section != "console_scripts" or not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        if _ and value.strip():
            scripts[key.strip()] = value.strip()
    for script, target in scripts.items():
        module, _, attribute = target.partition(":")
        attribute = attribute.strip() or "main"
        script_path = scripts_dir() / (f"{script}.cmd" if os.name == "nt" else script)
        if os.name == "nt":
            script_path.write_text(
                "@echo off\r\n"
                f"\"{sys.executable}\" -c \"import sys;from {module} import {attribute} as _m;"
                f"sys.exit(_m())\" %*\r\n",
                encoding="utf-8",
            )
        else:
            script_path.write_text(
                f"#!{sys.executable}\nimport sys\nfrom {module} import {attribute} as _m\n"
                f"sys.exit(_m())\n",
                encoding="utf-8",
            )
            script_path.chmod(0o755)


def install(
    names: Sequence[str],
    *,
    upgrade: bool = False,
    skip_deps: bool = False,
    quiet: bool = False,
    depth: int = 0,
) -> dict[str, str]:
    """Resolve and install *names* plus their dependencies."""
    installed: dict[str, str] = {}
    queue: list[tuple[Requirement, int]] = [
        (Requirement(name=name), depth) for name in names
    ]
    seen: set[str] = set()
    while queue:
        requirement, level = queue.pop(0)
        normalised = re.sub(r"[-_.]+", "-", requirement.name).lower()
        if normalised in seen:
            continue
        seen.add(normalised)
        if not marker_applies(requirement.marker):
            continue
        if already_installed(requirement.name) and not upgrade:
            if not quiet:
                print(f"  = {requirement.name} already present")
            installed[requirement.name] = "present"
            continue
        candidates = candidates_for(requirement.name)
        if not candidates:
            print(f"  ! no compatible wheel for {requirement.name}", file=sys.stderr)
            continue
        candidate = candidates[0]
        if level == 0 and not quiet:
            print(
                f"  ↓ {candidate.name} {candidate.version} "
                f"({candidate.filename}, {candidate.size / 1024:.0f} KB)"
            )
        blob = download(candidate.url, expected_sha256=candidate.sha256)
        metadata, _ = read_metadata(blob)
        install_wheel(blob, candidate)
        installed[candidate.name] = candidate.version
        if not quiet:
            indent = "    " * (level + 1)
            print(f"{indent}✔ installed {candidate.name} {candidate.version}")
        if skip_deps:
            continue
        extras = set(requirement.extras)
        for entry in parse_requires(metadata["requires"]):
            if entry.extras and not extras.intersection(entry.extras):
                continue
            if entry.marker and "extra ==" in entry.marker:
                wanted = re.findall(r"extra\s*==\s*['\"]([^'\"]+)['\"]", entry.marker)
                if wanted and not extras.intersection(wanted):
                    continue
            queue.append((entry, level + 1))
    return installed


def check(names: Sequence[str]) -> dict[str, bool]:
    status: dict[str, bool] = {}
    for name in names:
        try:
            __import__(name)
            status[name] = True
        except Exception:
            status[name] = False
    return status


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="direct PyPI wheel installer")
    parser.add_argument("packages", nargs="*", help="packages to install")
    parser.add_argument("--upgrade", action="store_true")
    parser.add_argument("--no-deps", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--list", metavar="PKG", help="list compatible wheels for a package")
    parser.add_argument("--check", nargs="*", metavar="MODULE", help="import-check modules")
    parser.add_argument("--target", action="store_true", help="print site-packages path")
    args = parser.parse_args(argv)

    if args.target:
        print(site_packages())
        return 0

    if args.check is not None:
        results = check(args.check)
        for module, ok in results.items():
            print(f"{'✔' if ok else '✖'} {module}")
        return 0 if all(results.values()) else 1

    if args.list:
        for candidate in candidates_for(args.list)[:25]:
            print(
                f"{candidate.version:<14} {candidate.filename:<60} "
                f"score={candidate.score:<5} py={candidate.requires_python}"
            )
        return 0

    if not args.packages:
        parser.print_help()
        return 1

    print(f"target: {site_packages()}")
    installed = install(
        args.packages, upgrade=args.upgrade, skip_deps=args.no_deps, quiet=args.quiet
    )
    print(f"installed/verified {len(installed)} distribution(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
