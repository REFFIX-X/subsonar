"""pip bootstrap shim for environments where pip is not importable.

The embedded Python used by this workspace ships pip only as a bundled wheel
(``ensurepip/_bundled/pip-*.whl``) and ``ensurepip`` cannot complete because its
temporary-directory cleanup is blocked.  This shim imports pip straight out of
that wheel and forwards all CLI arguments to it.

Usage::

    python tools/pip_shim.py install aiohttp
"""

from __future__ import annotations

import glob
import os
import sys

_BUNDLED_GLOBS = [
    os.path.join(
        os.path.dirname(os.__file__), "ensurepip", "_bundled", "pip-*.whl"
    ),
    os.path.join(
        sys.base_prefix, "Lib", "ensurepip", "_bundled", "pip-*.whl"
    ),
]


def _find_pip_wheel() -> str:
    for pattern in _BUNDLED_GLOBS:
        matches = sorted(glob.glob(pattern))
        if matches:
            return matches[-1]
    raise SystemExit("pip_shim: unable to locate a bundled pip wheel")


def main() -> int:
    wheel = _find_pip_wheel()
    sys.path.insert(0, wheel)
    from pip._internal.cli.main import main as pip_main

    return pip_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
