---
name: run-subzonar
description: Run, test and screenshot subsonar — the asynchronous subdomain & web-interface scanner. Covers the headless `scan` CLI, the offline `selftest` engine check, the pytest suite, and the Streamlit web dashboard.
---

# run-subzonar

subsonar is a Python scanner for discovering a domain's subdomains and web
interfaces (async DNS, OSINT sources, port matrix, HTTP verification). It has
four entry points, all behind `main.py`:

| Surface | Command | Driver |
|---|---|---|
| Headless scan (CLI) | `main.py scan <domain> -p 1` | `driver.py scan` |
| Offline engine self-test | `main.py selftest` | `driver.py selftest` |
| Textual TUI (interactive) | `main.py` (needs a TTY) | — (pytest drives it headless) |
| Streamlit web dashboard | `main.py web` | browser automation (below) |

The engine is a library first; the CLI, TUI and dashboard are thin layers on
`subsonar/`. Most PRs touch `subsonar/core/`, so the primary driver path is the
offline self-test plus a direct `import` — not the GUI.

All paths below are relative to the repo root (where `main.py` lives).

## Prerequisites

* Python 3.11+ (this checkout's `.venv` is Python 3.12.10 with every dep already
  installed — nothing to do here).
* On a clean machine: `python -m venv .venv` then
  `pip install -r requirements.txt`. On Windows the bundled `install.ps1` does
  this end-to-end. If `pip` stalls in a restricted sandbox, the repo ships
  `tools/wheel_installer.py` as a fallback (see the README "Tooling & sandbox
  notes").

There is no build step — pure Python, and `main.py` inserts the repo root onto
`sys.path` so it runs straight from a source checkout.

## Run (agent path) — the driver

`.claude/skills/run-subzonar/driver.py` wraps the CLI and checks exit codes. It
uses `sys.executable`, so it must be run with the venv Python:

```bash
.venv/Scripts/python.exe .claude/skills/run-subzonar/driver.py check
```

`check` runs the offline self-test then one real scan and exits non-zero on
failure — the CI-style "does the app work" command. Individual subcommands:

```bash
# offline full-engine check (loopback mocks, no internet) — ~70 s, 26/26 checks
.venv/Scripts/python.exe .claude/skills/run-subzonar/driver.py selftest

# one real bounded scan (example.com, profile 1) — ~70 s, writes .tmp/smoke/*
.venv/Scripts/python.exe .claude/skills/run-subzonar/driver.py scan

# launch the Streamlit dashboard, poll until HTTP 200, then stay in foreground
.venv/Scripts/python.exe .claude/skills/run-subzonar/driver.py web --port 8501
```

On Linux replace `.venv/Scripts/python.exe` with `.venv/bin/python`.

## Direct invocation (library) — the layer PRs touch

For a change to one function, import it and call it directly; no full app needed.
The engine self-test is callable as a library and is the fastest way to run the
*whole* pipeline offline:

```bash
.venv/Scripts/python.exe -c "import asyncio; from subsonar.core.selftest import run_selftest; r = asyncio.run(run_selftest()); print(r['passed'], '/', r['total'])"
```

Real scans go through the same `subsonar.runner.ScanRunner` the dashboard uses,
so a small script can drive a scan without the CLI:

```bash
.venv/Scripts/python.exe -c "import asyncio; from subsonar.core.config import ScanConfig; from subsonar.runner import ScanRunner; from subsonar.core.events import BUS; from subsonar.core.profiles import get_profile; r = ScanRunner(ScanConfig(domain='example.com', profile_id=1, geoip=False, geoip_download=False), profile=get_profile(1), bus=BUS); r.start(); r.join(); print(len(r.live_result.findings), 'finding(s)')"
```

## Run (web dashboard) + driving it

Launch headless (blocks, keeps serving):

```bash
.venv/Scripts/python.exe main.py web --headless --port 8501
```

The dashboard is Streamlit, driven through the browser pane / `chromium-cli`.
The two controls that matter, verified against the running app:

* target box: `input[aria-label="Target domain"]`
* start button: `button[kind="primary"]` (the "▶ Start" primary button)

Flow: fill the target box → click Start → the resolver pre-flight and live log
start streaming (`[dns] Resolver health check`, `[geo] Geo index building`), and
the findings tab shows "Scan running". Stop with `button[kind="secondary"]`
("■ Stop"). The default profile is 3 (Medium Brute), which is slow — set profile
1 or check "Offline (cache only)" for a quick smoke.

## Test

```bash
.venv/Scripts/python.exe -m pytest tests -q
```

The full suite passes (the README pegs it at 545 tests) and covers the TUI
headlessly via Textual's `run_test` pilot — so you do not need a real TTY to
exercise the TUI.

## Gotchas

* **`selftest` is slow (~70 s) but deterministic** — it boots a mock DNS server
  and a mock web server on loopback and runs the real engine over them. It is
  the network-free "did I break the engine" gate, not a quick smoke.
* **A first real scan downloads the ~10 MB geo index** (ip2asn.com/RIR BGP
  dumps) before it scans. Pass `--no-geo --no-geo-download` to skip it; the
  driver's `scan` already does.
* **The TUI needs a real TTY.** Running `main.py` in a pipe/non-TTY prints usage
  guidance instead of launching. Drive the TUI through pytest, not a live shell.
* **Streamlit takes a few seconds to boot** — poll `http://127.0.0.1:8501` until
  200 rather than assuming it is ready instantly (the driver's `web` does this).
* **Profile 1 vs the dashboard default.** The CLI's `scan -p 1` is passive-only
  (fast, no brute force); the dashboard defaults to profile 3 (5000-subdomain
  brute + full port matrix), so a dashboard scan is much longer.
* **One `selftest` at a time.** Its mock web server binds a fixed loopback port
  (`http://127.0.0.1:8000`), so two concurrent selftests collide. Run the
  driver's subcommands sequentially, not in parallel.

## Troubleshooting

* **Scan exits `2`** — that is not an error: `2` means the scan completed with
  no confirmed web interface (exit `0` = findings, `1` = error, `130` =
  interrupted).
* **`driver.py` can't find `main.py`** — the driver locates the repo root as
  `Path(__file__).parents[3]`. If you move the skill directory up or down a
  level, that count changes and the subprocess cwd is wrong.
