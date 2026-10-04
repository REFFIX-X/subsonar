"""Engine runner — drives the async scan engine from any UI.

The engine owns an asyncio event loop.  Textual and Streamlit both need the
main thread, so :class:`ScanRunner` runs ``asyncio.run(engine.run())`` inside a
daemon thread and bridges state back through :class:`EventBus` (thread-safe by
design).  A plain ``asyncio.run`` is used for the headless console.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from typing import Any, Callable

from .core.config import ScanConfig
from .core.engine import Finding, ScanEngine, ScanResult
from .core.events import BUS, EventBus
from .core.profiles import Profile, get_profile


class ScanRunner:
    """Thread-hosted engine wrapper with start/stop/introspection."""

    def __init__(
        self,
        config: ScanConfig,
        *,
        profile: Profile | int | str | None = None,
        bus: EventBus | None = None,
        on_finding: Callable[[Finding], Any] | None = None,
        on_done: Callable[[ScanResult | None, BaseException | None], Any] | None = None,
    ) -> None:
        self.config = config
        self.profile = profile if isinstance(profile, Profile) else get_profile(profile or config.profile_id)
        self.bus = bus or BUS
        self.on_finding = on_finding
        self.on_done = on_done
        self._engine: ScanEngine | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self.result: ScanResult | None = None
        self.error: BaseException | None = None
        self.started_at: float | None = None
        self.finished_at: float | None = None

    # -- lifecycle --------------------------------------------------------- #
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def finished(self) -> bool:
        return self.finished_at is not None

    @property
    def live_result(self) -> ScanResult | None:
        """The result *as it is being built*, so UIs can show findings live.

        ``result`` is only assigned when the engine thread returns, but the
        engine records findings into its own :class:`ScanResult` as each one is
        confirmed.  A UI that reads ``result`` alone shows nothing until the very
        end — and, when it no longer re-renders every second, nothing at all.
        """
        if self.result is not None:
            return self.result
        engine = self._engine
        return engine.result if engine is not None else None

    def start(self) -> None:
        if self.running:
            return
        self.started_at = time.time()
        self.bus.clear()
        self.bus.set_field("phase", "starting")
        self._thread = threading.Thread(
            target=self._run, name="subsonar-engine", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            self._engine = ScanEngine(
                self.config,
                profile=self.profile,
                bus=self.bus,
                on_finding=self.on_finding,
            )
            self.result = loop.run_until_complete(self._engine.run())
        except BaseException as exc:  # noqa: BLE001 - surfaced to the UI
            self.error = exc
        finally:
            with contextlib.suppress(Exception):
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
            with contextlib.suppress(Exception):
                loop.close()
            self._loop = None
            self.finished_at = time.time()
            self.bus.set_field("finished_at", self.finished_at)
            self.bus.close_stream()
            if self.on_done is not None:
                with contextlib.suppress(Exception):
                    self.on_done(self.result, self.error)

    def stop(self) -> None:
        """Cooperative cancellation, then hard fallback."""
        engine = self._engine
        loop = self._loop
        if engine is None or loop is None or loop.is_closed():
            return
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(engine.stop)

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def snapshot(self) -> dict[str, Any]:
        return self.bus.snapshot()
