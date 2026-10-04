"""Generate (or verify) the built-in **AI Super** subdomain wordlist.

    python tools/build_ai_wordlist.py            # write subsonar/data/*.txt
    python tools/build_ai_wordlist.py --stats    # numbers only, write nothing
    python tools/build_ai_wordlist.py --check    # fail if the file is stale
    python tools/build_ai_wordlist.py --limit 20000

The output is deterministic, so ``--check`` is a useful CI guard: it fails when
the shipped file and ``subsonar/core/wordlistgen.py`` disagree.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from subsonar.core.wordlistgen import (  # noqa: E402
    BUILTIN_PATH,
    DEFAULT_LIMIT,
    build_labels,
    curated_labels,
    env_role_labels,
    family_labels,
    numbered_labels,
    region_labels,
    render_file,
    theme_labels,
    theme_pair_labels,
    validate_labels,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_ai_wordlist", description=__doc__
    )
    parser.add_argument(
        "--limit", type=int, default=DEFAULT_LIMIT, help="cap the list size"
    )
    parser.add_argument(
        "--stats", action="store_true", help="print statistics only (write nothing)"
    )
    parser.add_argument(
        "--check", action="store_true", help="verify the shipped file is up to date"
    )
    parser.add_argument("--quiet", action="store_true", help="suppress the stage table")
    args = parser.parse_args(argv)

    labels = build_labels(args.limit)
    payload = render_file(labels, source="tools/build_ai_wordlist.py")
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    if not args.quiet:
        stages = (
            ("curated (hand-picked)", len(curated_labels())),
            ("theme vocabulary", len(theme_labels())),
            ("role x environment", len(family_labels())),
            ("environment x role", len(env_role_labels())),
            ("role x number", len(numbered_labels())),
            ("role x region", len(region_labels())),
            ("theme pairs", len(theme_pair_labels())),
        )
        print("  stage                    candidates")
        for name, count in stages:
            print(f"  {name:<24} {count:>10,}")

    rejected = validate_labels(labels)
    print(f"  labels                   {len(labels):>10,}")
    print(f"  unique labels            {len(set(labels)):>10,}")
    print(f"  invalid labels           {len(rejected):>10,}")
    print(f"  payload                  {len(payload) / 1024:>9.0f} KB")
    print(f"  sha256                   {digest}")
    if rejected:
        print(f"  rejected examples: {rejected[:10]}", file=sys.stderr)
        return 1

    if args.stats:
        return 0

    if args.check:
        if not BUILTIN_PATH.is_file():
            print(f"  MISSING: {BUILTIN_PATH}", file=sys.stderr)
            return 1
        current = BUILTIN_PATH.read_text(encoding="utf-8")
        if current == payload:
            print(f"  up to date: {BUILTIN_PATH}")
            return 0
        print(
            f"  OUT OF DATE: {BUILTIN_PATH} — regenerate with "
            f"python tools/build_ai_wordlist.py",
            file=sys.stderr,
        )
        return 1

    BUILTIN_PATH.parent.mkdir(parents=True, exist_ok=True)
    BUILTIN_PATH.write_text(payload, encoding="utf-8", newline="\n")
    print(f"  wrote: {BUILTIN_PATH} ({BUILTIN_PATH.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
