"""Show the newest report's findings with their confidence breakdown."""

from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

pattern = sys.argv[1] if len(sys.argv) > 1 else "output/*.json"
paths = sorted(glob.glob(pattern), key=lambda p: Path(p).stat().st_mtime)
if not paths:
    print(f"no reports matching {pattern}")
    raise SystemExit(1)
path = paths[-1]
data = json.loads(Path(path).read_text(encoding="utf-8"))
print(f"report : {Path(path).name}")
print(f"target : {data['target']}  profile {data['profile']['name']}  {data['duration_seconds']}s")
print()
for finding in data["findings"]:
    print(
        f"{finding['subdomain']}:{finding['port']}  "
        f"conf={finding['confidence']:>3} ({finding['confidence_label']})  "
        f"kind={finding['kind']}  status={finding['status']}"
    )
    tech = finding.get("technologies") or "-"
    print(f"    tech={tech}")
    print(
        f"    favicon={finding.get('favicon_hash') or '-'}  "
        f"files={finding.get('data_files') or '-'}  "
        f"also_on={finding.get('also_on_ports') or '-'}"
    )
    print(f"    why: {finding.get('confidence_why') or '-'}")
    print()
print("notes:", data.get("notes"))
