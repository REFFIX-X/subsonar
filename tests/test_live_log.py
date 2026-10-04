"""The live-log panel must only ever grow — and never lose a line.

Regression this file guards: the panel rendered ``BUS.drain()``, which *removes*
the events it returns.  During a scan the page reran every half second, so each
rerun showed only the handful of lines emitted since the previous one — the log
appeared to flash and clear itself, and nothing could be scrolled back into.
"""

from __future__ import annotations

from collections import deque

import pytest

from subsonar.core.dns import DNSResult
from subsonar.core.events import EventBus
from subsonar.ui.dashboard import (
    LOG_BUFFER_MAX,
    LOG_RENDER_MAX,
    append_new_events,
    _is_log_noise,
    _log_line,
)


def _bus_with(count: int, bus: EventBus | None = None) -> EventBus:
    bus = bus or EventBus()
    for index in range(count):
        bus.emit(f"line {index}", "info", "dns", host=f"h{index}.example.com")
    return bus


def test_buffer_grows_instead_of_being_replaced() -> None:
    """Three overlapping windows must leave every line in the buffer, once."""
    bus = _bus_with(3)
    buffer: deque = deque(maxlen=LOG_BUFFER_MAX)
    seq = 0

    appended, _dropped, seq = append_new_events(buffer, seq, bus.history(limit=100))
    assert appended == 3 and len(buffer) == 3

    bus.emit("fourth", "info", "dns")
    appended, _dropped, seq = append_new_events(buffer, seq, bus.history(limit=100))
    assert appended == 1 and len(buffer) == 4

    # A no-op refresh (nothing new) must not duplicate or shrink anything.
    appended, _dropped, seq = append_new_events(buffer, seq, bus.history(limit=100))
    assert appended == 0 and len(buffer) == 4
    assert [event.message for event in buffer] == [
        "line 0",
        "line 1",
        "line 2",
        "fourth",
    ]


def test_a_later_window_only_appends_newer_events() -> None:
    """Sequence-ordered sync: it never rewinds, never duplicates, never shrinks."""
    bus = _bus_with(50)
    buffer: deque = deque(maxlen=LOG_BUFFER_MAX)
    appended, _dropped, seq = append_new_events(buffer, 0, bus.history(limit=5000))
    assert appended == 50 and seq == 50 and len(buffer) == 50

    # A window that reaches *back* (a different limit) must add nothing.
    appended, _dropped, seq = append_new_events(buffer, seq, bus.history(limit=10))
    assert appended == 0 and seq == 50 and len(buffer) == 50

    bus.emit("line 51", "info", "dns")
    appended, _dropped, seq = append_new_events(buffer, seq, bus.history(limit=5000))
    assert appended == 1 and seq == 51 and len(buffer) == 51
    assert [event.seq for event in buffer] == list(range(1, 52))


def test_evicted_events_are_counted_not_silently_lost() -> None:
    bus = _bus_with(10)
    buffer: deque = deque(maxlen=LOG_BUFFER_MAX)
    _appended, _dropped, seq = append_new_events(
        buffer, 0, [event for event in bus.history(limit=100) if event.seq <= 4]
    )
    assert seq == 4 and len(buffer) == 4
    # The next window starts at 7: 5 and 6 were evicted in between.
    appended, dropped, seq = append_new_events(
        buffer, seq, [event for event in bus.history(limit=100) if event.seq >= 7]
    )
    assert appended == 4  # 7, 8, 9, 10
    assert dropped == 2
    assert seq == 10 and len(buffer) == 8


def test_ring_overflow_is_reported_as_dropped() -> None:
    bus = _bus_with(12)
    buffer: deque = deque(maxlen=5)
    appended, dropped, seq = append_new_events(buffer, 0, bus.history(limit=100))
    assert appended == 5
    assert dropped == 7  # 12 events into a 5-slot ring
    assert len(buffer) == 5
    assert [event.seq for event in buffer] == [8, 9, 10, 11, 12]


def test_empty_window_is_a_no_op() -> None:
    buffer: deque = deque(maxlen=10)
    assert append_new_events(buffer, 7, []) == (0, 0, 7)
    assert append_new_events(buffer, 7, [])[2] == 7


def test_quiet_filter_hides_debug_and_filter_events() -> None:
    bus = EventBus()
    debug = bus.emit("debug chatter", "debug", "dns")
    filtered = bus.emit("filtered out", "debug", "filter")
    info = bus.emit("resolved", "info", "dns")
    assert _is_log_noise(debug) is True
    assert _is_log_noise(filtered) is True
    assert _is_log_noise(info) is False


def test_log_line_renders_host_port_and_escapes_html() -> None:
    bus = EventBus()
    event = bus.emit(
        "Probe <script>alert(1)</script> & done",
        "success",
        "probe",
        host="portal.example.com",
        port=8443,
    )
    line = _log_line(event)
    assert "portal.example.com" in line and ":8443" in line
    assert "<script>" not in line  # escaped, never injected
    assert "&lt;script&gt;" in line and "&amp; done" in line


def test_log_constants_are_sane() -> None:
    assert LOG_BUFFER_MAX >= 1000
    assert 0 < LOG_RENDER_MAX <= LOG_BUFFER_MAX
