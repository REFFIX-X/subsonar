"""subsonar test-suite configuration.

The DSH file sandbox places a *deny* ACE for ``DeleteSubdirectoriesAndFiles`` on
temporary directories, so pytest's built-in ``tmp_path`` fixture and its dead
symlink cleanup raise ``PermissionError`` at teardown.  This module provides a
workspace-local ``tmp_path`` replacement and makes the cleanup hooks tolerant.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# The offline geo index is built from a ~10 MB BGP dump.  Tests must never
# download it: with this switch set, `geoip.ensure_index()` uses only what is
# already on disk (and the geo tests build their own synthetic index).
os.environ.setdefault("SUBSONAR_GEOIP_OFFLINE", "1")

#: Workspace-local scratch root (writable, but not deletable by design).
SCRATCH = ROOT / ".tmp" / "pytest"
SCRATCH.mkdir(parents=True, exist_ok=True)


@pytest.fixture
def tmp_path(request: pytest.FixtureRequest) -> Path:  # noqa: F811 - intentional override
    """Unique per-test scratch directory inside the workspace."""
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in request.node.name)[:60]
    path = SCRATCH / f"{safe}-{int(time.time() * 1000) % 1_000_000}"
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture(scope="session")
def tmp_path_factory() -> object:  # noqa: F811 - intentional override
    class _Factory:
        def mktemp(self, name: str, numbered: bool = True) -> Path:
            suffix = f"-{int(time.time() * 1000) % 1_000_000}" if numbered else ""
            path = SCRATCH / f"{name}{suffix}"
            path.mkdir(parents=True, exist_ok=True)
            return path

        def getbasetemp(self) -> Path:
            return SCRATCH

    return _Factory()


def _soft_cleanup(target: Path) -> None:
    try:
        shutil.rmtree(target, ignore_errors=True)
    except Exception:
        pass


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:  # noqa: ARG001
    """Prune scratch directories without letting the sandbox abort the run."""
    for entry in list(SCRATCH.glob("*")):
        _soft_cleanup(entry)
