"""Run subsonar from a source checkout: ``python main.py ...``.

The implementation lives in :mod:`subsonar.cli`. This module re-exports it so
``import main`` and ``python main.py`` keep working. After installation, use
the ``subsonar`` command (or ``python -m subsonar``).
"""

from __future__ import annotations

import subsonar.cli as _cli

# Re-export the CLI, including private helpers the test suite imports.
globals().update(
    {
        name: getattr(_cli, name)
        for name in dir(_cli)
        if not name.startswith("__")
    }
)

if __name__ == "__main__":
    _cli.console_main()
