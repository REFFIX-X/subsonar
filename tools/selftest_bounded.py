"""Run the self-test under a hard timeout so a hang is reported, not waited on."""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from subsonar.core.selftest import run_selftest


async def main() -> None:
    started = time.perf_counter()

    def progress(message: str) -> None:
        print(f"  [{time.perf_counter() - started:6.1f}s] {message}", flush=True)

    task = asyncio.create_task(
        run_selftest(report_dir=Path(".tmp/selftest-bounded"), progress=progress)
    )
    try:
        report = await asyncio.wait_for(task, timeout=90)
    except asyncio.TimeoutError:
        print(f"TIMED OUT after {time.perf_counter() - started:.1f}s — cancelling")
        task.cancel()
        return
    elapsed = time.perf_counter() - started
    print(f"completed in {elapsed:.1f}s — {report['passed']}/{report['total']} passed")
    for check in report["checks"]:
        marker = "OK  " if check["ok"] else "FAIL"
        print(f"  {marker} {check['name']:<34} {check['detail'][:150]}")


if __name__ == "__main__":
    asyncio.run(main())
