#!/usr/bin/env python3
"""subsonar smoke driver — build, launch and drive the app end-to-end.

Every subcommand here was run and verified on a clean checkout.  It shells out
to ``main.py`` through the *same* virtualenv Python that runs this script
(``sys.executable``), so it works identically on Windows and Linux:

    .venv\\Scripts\\python.exe .claude\\skills\\run-subzonar\\driver.py check   # Windows
    .venv/bin/python          .claude/skills/run-subzonar/driver.py check       # Linux

Subcommands:
    selftest            offline full-engine check (loopback mocks, no internet)
    scan [domain]       real bounded scan (default: example.com, profile 1)
    web                 launch the Streamlit dashboard and verify it answers
    check               selftest + scan; exit non-zero if either fails
"""

from __future__ import annotations

import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PY = sys.executable  # the venv python that runs this driver


def _run(*args: str, timeout: int | None = None) -> int:
    print(f"\n$ {Path(PY).name} {' '.join(args)}", flush=True)
    return subprocess.run([PY, *args], cwd=ROOT, timeout=timeout).returncode


def selftest() -> int:
    """The deterministic gate: full engine over loopback mocks, no internet.

    Runs the same pipeline a scan uses (DNS wire round-trip, wildcard filtering,
    port matrix, HTTP verification, report writers) against mock servers on
    127.0.0.1.  Expected output ends with ``26/26 checks passed``; exit 0 means
    the engine is healthy.
    """
    return _run("main.py", "selftest")


def scan(domain: str = "example.com") -> int:
    """One real end-to-end scan of a safe test domain.

    Profile 1 is Passive Only — OSINT scraping + verification of discovered
    80/443 interfaces, zero brute force, zero packets to the target.  Geo is
    skipped to avoid the ~10 MB BGP dump.  Reports land in ``.tmp/smoke/``.
    Exit 0 = findings written, 2 = clean scan with no web interface.
    """
    return _run(
        "main.py", "scan", domain, "-p", "1",
        "--no-geo", "--no-geo-download", "--output", ".tmp/smoke",
    )


def web(port: int = 8501) -> int:
    """Launch the Streamlit dashboard headless and verify it serves HTTP 200.

    Streamlit needs a few seconds to boot, so this polls ``http://127.0.0.1:<port>``
    for up to 60 s.  When it answers, the dashboard is left running in the
    foreground (Ctrl-C to stop).  ``check()`` does not include this: the dashboard
    is a launch-and-drive surface, not a pass/fail gate.
    """
    print(f"\nlaunching Streamlit dashboard on http://127.0.0.1:{port} …", flush=True)
    proc = subprocess.Popen(
        [PY, "main.py", "web", "--headless", "--port", str(port)], cwd=ROOT
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    print(f"dashboard up: {url} (pid {proc.pid})", flush=True)
                    break
        except Exception:
            time.sleep(1)
    else:
        proc.terminate()
        print("dashboard did not come up within 60 s", file=sys.stderr)
        return 1
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
    return 0


def check() -> int:
    """selftest + a bounded scan; the CI-friendly "does the app work" command."""
    code = selftest()
    if code != 0:
        print("selftest FAILED", file=sys.stderr)
        return code
    code = scan()
    if code not in (0, 2):
        print("scan FAILED", file=sys.stderr)
        return code
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("selftest", help="offline full-engine check")
    scan_p = sub.add_parser("scan", help="real bounded scan")
    scan_p.add_argument("domain", nargs="?", default="example.com")
    web_p = sub.add_parser("web", help="launch the Streamlit dashboard")
    web_p.add_argument("--port", type=int, default=8501)
    sub.add_parser("check", help="selftest + scan")
    args = parser.parse_args()

    if args.command == "selftest":
        raise SystemExit(selftest())
    if args.command == "scan":
        raise SystemExit(scan(args.domain))
    if args.command == "web":
        raise SystemExit(web(args.port))
    if args.command == "check":
        raise SystemExit(check())
    parser.print_help()
    raise SystemExit(1)
