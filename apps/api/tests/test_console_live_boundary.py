"""R84 simulator-only checks for real serial completion boundaries.

These tests do not open a real serial port.  They document that prompt delivery
from a finite replay queue is not a proof that a live serial read is complete;
the live serial path remains disabled and NOT_VERIFIED.
"""

from __future__ import annotations

from collections import deque

import pytest

from event_switch_manager.console.discovery import IdentityQuality, SerialPortInfo
from event_switch_manager.console.lease import OS_EXCLUSIVITY_STATUS
from event_switch_manager.console.models import ConsoleSource
from event_switch_manager.console.session import (
    AmbiguousConsoleOutput,
    ConsoleSession,
    ConsoleTimeout,
)
from event_switch_manager.console.transport import (
    LIVE_SERIAL_AUTHORIZATION_ENABLED,
    LiveSerialDisabled,
    SerialTransport,
)
from event_switch_manager.integrations import ConsoleQuery


class _BoundaryTransport:
    source = ConsoleSource.SIMULATOR
    port_identity = "sim:r84-boundary"
    lease_endpoint = "sim:r84-boundary"
    identity_quality = "stable"

    def __init__(self, responses: dict[ConsoleQuery, tuple[str, ...]]) -> None:
        self._initial: deque[str] = deque(["R1>\n"])
        self._responses = responses
        self._queue: deque[str] = deque()
        self.writes: list[str] = []
        self._open = False

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def pending_data(self) -> bool:
        return bool(self._queue)

    def read_chunk(self, timeout: float) -> str:
        _ = timeout
        if not self._open:
            raise RuntimeError("closed")
        return self._queue.popleft() if self._queue else ""

    def write(self, value: str) -> None:
        if not self._open:
            raise RuntimeError("closed")
        self.writes.append(value)
        command = value.rstrip("\r")
        for query, chunks in self._responses.items():
            if command == f"show {query.value}":
                self._queue.extend(chunks)
                return


def _session(transport: _BoundaryTransport, timeout: float = 0.2) -> ConsoleSession:
    transport._queue = transport._initial
    session = ConsoleSession(transport, timeout=timeout)
    return session


def test_delayed_chunks_are_not_accepted_before_prompt() -> None:
    transport = _BoundaryTransport({
        ConsoleQuery.VERSION: (
            "show version\nsynthetic output\n", "", "R1>\n",
        ),
    })
    session = _session(transport)
    session.open(None)
    try:
        assert session.query(ConsoleQuery.VERSION) == "synthetic output"
        assert transport.writes == ["show version\r"]
        assert session.state.value == "USER_EXEC"
    finally:
        session.close()


def test_delayed_prompt_like_body_fails_closed_and_sends_no_next_command() -> None:
    transport = _BoundaryTransport({
        ConsoleQuery.VERSION: ("show version\nR1#", "\nstill body\nR1>\n"),
    })
    session = _session(transport)
    session.open(None)
    with pytest.raises(AmbiguousConsoleOutput):
        session.query(ConsoleQuery.VERSION)
    assert transport.writes == ["show version\r"]
    assert session.state.value == "FAILED"


def test_incomplete_explicit_prompt_times_out_without_advancing() -> None:
    transport = _BoundaryTransport({
        ConsoleQuery.VERSION: ("show version\nunterminated response",),
    })
    session = _session(transport, timeout=0.03)
    session.open(None)
    with pytest.raises(ConsoleTimeout):
        session.query(ConsoleQuery.VERSION)
    assert transport.writes == ["show version\r"]
    assert session.state.value == "FAILED"


def test_first_character_after_pagination_is_not_treated_as_whitespace() -> None:
    transport = _BoundaryTransport({
        ConsoleQuery.VERSION: ("show version\n--More--", "\nR1>\n"),
    })
    session = _session(transport)
    session.open(None)
    with pytest.raises(AmbiguousConsoleOutput):
        session.query(ConsoleQuery.VERSION)
    assert transport.writes == ["show version\r"]
    assert session.state.value == "FAILED"


def test_live_serial_replay_boundary_remains_disabled_and_unverified() -> None:
    assert LIVE_SERIAL_AUTHORIZATION_ENABLED is False
    assert OS_EXCLUSIVITY_STATUS == "NOT_VERIFIED"
    port = SerialPortInfo(
        port="COM3",
        description="synthetic",
        adapter_identity="usb:0403:6001:R84BOUNDARY",
        identity_quality=IdentityQuality.STABLE,
    )
    with pytest.raises(LiveSerialDisabled):
        SerialTransport(port).open()
    with pytest.raises(LiveSerialDisabled):
        SerialTransport(port, allow_live=True).open()
    assert ConsoleSource.LIVE_DEVICE.value == "LIVE_DEVICE"
