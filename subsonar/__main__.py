"""``python -m subsonar`` — same entry point as the ``subsonar`` command."""

from __future__ import annotations

from subsonar.cli import console_main

if __name__ == "__main__":
    console_main()
