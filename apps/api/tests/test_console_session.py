from __future__ import annotations

from dataclasses import replace

import pytest

from event_switch_manager.console.allowlist import (
    FamilyUnknown,
    QueryNotAllowed,
    QueryNotSupported,
)
from event_switch_manager.console.lease import ConsoleLeaseManager, LeaseConflict
from event_switch_manager.console.models import ConsoleSource
from event_switch_manager.console.session import (
    AuthenticationError,
    ConsoleCredentials,
    ConsoleSession,
    ConsoleTimeout,
    DeviceCommandError,
    EnableError,
    SessionError,
    SessionState,
)
from event_switch_manager.console.simulator import (
    SimulatedConsoleTransport,
    SimulatorProfile,
    profiles,
)
from event_switch_manager.domain import DeviceFamily
from event_switch_manager.integrations import ConsoleQuery

PROFILE = profiles()[3]
CREDS = ConsoleCredentials("console", "synthetic-password", "synthetic-enable")


def _session(
    profile: SimulatorProfile = PROFILE, *,
    manager: ConsoleLeaseManager | None = None,
    wrong_password: bool = False,
    enable_failure: bool = False,
    timeout_commands: frozenset[ConsoleQuery] = frozenset(),
    disconnect_commands: frozenset[ConsoleQuery] = frozenset(),
    error_commands: frozenset[ConsoleQuery] = frozenset(),
    pagination: bool = True,
    chunk_size: int = 5,
) -> ConsoleSession:
    transport = SimulatedConsoleTransport(
        profile=profile,
        chunk_size=chunk_size,
        pagination=pagination,
        wrong_password=wrong_password,
        enable_failure=enable_failure,
        timeout_commands=timeout_commands,
        disconnect_commands=disconnect_commands,
        error_commands=error_commands,
    )
    return ConsoleSession(
        transport,
        lease_manager=manager,
        timeout=1.0,
    )


def test_open_query_close_lease_and_source() -> None:
    session = _session()
    session.open(CREDS)
    assert session.state is SessionState.PRIVILEGED_EXEC
    assert session.source.value == "SIMULATOR"
    assert session.port_identity == "sim:synthetic-9300"
    output = session.query(ConsoleQuery.VERSION)
    assert "FIXTURE930001" in output
    assert "show version" not in output
    assert session.last_query_results[-1].query is ConsoleQuery.VERSION
    session.close()
    assert session.state.value == "CLOSED"
    assert session.last_query_results  # evidence is not lost on close
    session.close()
    assert session.state.value == "CLOSED"


def test_wrong_password_fails_closed_without_secret_or_lease() -> None:
    manager = ConsoleLeaseManager()
    session = _session(manager=manager, wrong_password=True)
    with pytest.raises(AuthenticationError) as error:
        session.open(CREDS)
    assert "synthetic-password" not in str(error.value)
    assert session.state is SessionState.FAILED
    assert manager.active_owner("sim:synthetic-9300") is None


def test_enable_failure_fails_closed_and_releases_lease() -> None:
    manager = ConsoleLeaseManager()
    session = _session(manager=manager, enable_failure=True)
    with pytest.raises(EnableError):
        session.open(CREDS)
    assert session.state is SessionState.FAILED
    assert manager.active_owner("sim:synthetic-9300") is None


def test_single_owner_lease_rejects_concurrent_session_and_recovers() -> None:
    manager = ConsoleLeaseManager()
    first = _session(manager=manager)
    second = _session(manager=manager)
    first.open(CREDS)
    with pytest.raises(LeaseConflict):
        second.open(CREDS)
    first.close()
    second.open(CREDS)
    assert second.state is SessionState.PRIVILEGED_EXEC
    second.close()


def test_unsupported_and_arbitrary_queries_are_rejected() -> None:
    session = _session(profiles()[4])  # C1000
    session.open(ConsoleCredentials("console", "synthetic-password", None))
    session.set_family(DeviceFamily.CATALYST_C1000)
    with pytest.raises(QueryNotSupported):
        session.query(ConsoleQuery.STACK)
    with pytest.raises(QueryNotAllowed):
        session.query("show version")  # type: ignore[arg-type]
    # still usable after a rejected query; no command was sent
    assert "C1000-24P-4G-L" in session.query(ConsoleQuery.INVENTORY)
    session.close()


def test_timeout_closes_session_and_releases_lease() -> None:
    manager = ConsoleLeaseManager()
    session = _session(
        manager=manager,
        timeout_commands=frozenset({ConsoleQuery.VERSION}),
    )
    session.open(CREDS)
    with pytest.raises(ConsoleTimeout):
        session.query(ConsoleQuery.VERSION)
    assert session.state is SessionState.FAILED
    assert manager.active_owner("sim:synthetic-9300") is None


def test_disconnect_closes_session_and_releases_lease() -> None:
    manager = ConsoleLeaseManager()
    session = _session(
        manager=manager,
        disconnect_commands=frozenset({ConsoleQuery.INVENTORY}),
    )
    session.open(CREDS)
    with pytest.raises(SessionError):
        session.query(ConsoleQuery.INVENTORY)
    assert session.state is SessionState.FAILED
    assert manager.active_owner("sim:synthetic-9300") is None


def test_device_command_error_is_bounded_and_does_not_auto_retry() -> None:
    manager = ConsoleLeaseManager()
    session = _session(
        manager=manager,
        error_commands=frozenset({ConsoleQuery.INVENTORY}),
    )
    session.open(CREDS)
    with pytest.raises(DeviceCommandError):
        session.query(ConsoleQuery.INVENTORY)
    assert session.state is SessionState.PRIVILEGED_EXEC
    assert manager.active_owner("sim:synthetic-9300") is not None
    session.close()


def test_pagination_is_bounded_and_does_not_expose_marker() -> None:
    profile = replace(
        PROFILE,
        interfaces=tuple(f"Gi1/0/{index}" for index in range(1, 10)),
    )
    session = _session(profile=profile, pagination=True, chunk_size=7)
    session.open(CREDS)
    session.set_family(DeviceFamily.CATALYST_9300)
    output = session.query(ConsoleQuery.INTERFACES)
    assert "--More--" not in output
    assert "Gi1/0/9" in output
    session.close()


def test_family_must_be_established_for_non_bootstrap_queries() -> None:
    session = _session()
    session.open(CREDS)
    with pytest.raises(FamilyUnknown):
        session.query(ConsoleQuery.LICENSE)
    session.close()


class _UnsafeTransport:
    source = ConsoleSource.SIMULATOR
    port_identity = "sim:unsafe-mode"

    def __init__(self) -> None:
        self._sent = False
        self._open = False

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def write(self, text: str) -> None:
        _ = text

    def read_chunk(self, timeout: float) -> str:
        _ = timeout
        if not self._open:
            raise RuntimeError("closed")
        if self._sent:
            return ""
        self._sent = True
        return "R1(config)#"


def test_configuration_mode_is_rejected_before_queries() -> None:
    manager = ConsoleLeaseManager()
    session = ConsoleSession(
        _UnsafeTransport(), lease_manager=manager, timeout=1.0,
    )
    with pytest.raises(SessionError):
        session.open(CREDS)
    assert session.state is SessionState.FAILED
    assert manager.active_owner("sim:unsafe-mode") is None
