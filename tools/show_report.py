"""Print the newest JSON report in a readable table."""

from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

paths = sorted(glob.glob("output/*.json"), key=lambda p: Path(p).stat().st_mtime)
if not paths:
    print("no reports found in output/")
    sys.exit(1)
path = paths[-1]
data = json.loads(Path(path).read_text(encoding="utf-8"))
print("report :", path)
print("profile:", data["profile"]["name"], "| duration", data["duration_seconds"], "s")
print()
print(f"{'SUBDOMAIN':<22}{'IP':<17}{'PORT':<7}{'CODE':<6}{'SERVER':<26}TITLE")
print("-" * 118)
for finding in data["findings"]:
    print(
        f"{finding['subdomain']:<22}{finding['ip']:<17}{finding['port']:<7}"
        f"{str(finding['status']):<6}{str(finding['server'])[:24]:<26}"
        f"{(finding['title'] or '')[:40]}"
    )
print()
print("urls:", [f["url"] for f in data["findings"]])
print("notes:", data["notes"])
print("sources:", {k: v["hosts"] for k, v in data["sources"].items()})
print("stats:", data["statistics"])
print("filtered sample:", list(data["filtered"].items())[:5])
