from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace

import pytest

from event_switch_manager.console.allowlist import (
    FamilyUnknown,
    QueryNotAllowed,
    QueryNotSupported,
    resolve_profile,
)
from event_switch_manager.console.lease import (
    ConsoleLeaseManager,
    LeaseConflict,
    default_lease_manager,
    normalize_endpoint,
)
from event_switch_manager.console.models import ConsoleSource
from event_switch_manager.console.session import (
    AmbiguousAdapterIdentity,
    AmbiguousConsoleOutput,
    AuthenticationError,
    ConsoleCredentials,
    ConsoleSession,
    ConsoleTimeout,
    CredentialInputError,
    DeviceCommandError,
    EnableError,
    LiveDeviceDisabled,
    SessionCleanupError,
    SessionError,
    SessionState,
    UnexpectedAuthPrompt,
    UnexpectedConsolePrompt,
)
from event_switch_manager.console.simulator import (
    SimulatedConsoleTransport,
    SimulatorProfile,
    profiles,
)
from event_switch_manager.console.transport import TransportError
from event_switch_manager.integrations import ConsoleQuery

PROFILE = profiles()[3]
CREDS = ConsoleCredentials("console", "synthetic-password", "synthetic-enable")


@pytest.fixture(autouse=True)
def _reset_default_lease_manager() -> Iterator[None]:
    default_lease_manager().reset_for_tests()
    yield
    default_lease_manager().reset_for_tests()


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


def test_two_default_sessions_share_the_global_lease_manager() -> None:
    first = _session()
    second = _session()
    first.open(CREDS)
    try:
        with pytest.raises(LeaseConflict):
            second.open(CREDS)
    finally:
        first.close()


def test_two_default_sessions_on_different_ports_both_open() -> None:
    first = _session(profiles()[3])
    second = _session(profiles()[2])
    first.open(CREDS)
    second.open(ConsoleCredentials("console", "synthetic-password", "synthetic-enable"))
    try:
        assert first.port_identity != second.port_identity
    finally:
        second.close()
        first.close()


def test_same_owner_cannot_acquire_the_same_endpoint_twice() -> None:
    manager = ConsoleLeaseManager()
    first = manager.acquire("usb:0403:6001:ABC", "owner-a", endpoint="COM3")
    try:
        with pytest.raises(LeaseConflict):
            manager.acquire("usb:0403:6001:ABC", "owner-a", endpoint="COM3")
    finally:
        first.release()


def test_lease_aliases_com_and_physical_identity_are_not_reacquired() -> None:
    manager = ConsoleLeaseManager()
    first = manager.acquire(
        "usb:0403:6001:ABC", "owner-a", endpoint="COM3",
    )
    try:
        with pytest.raises(LeaseConflict):
            manager.acquire(
                "usb:0403:9999:XYZ", "owner-b", endpoint=r"\\.\com3",
            )
        assert normalize_endpoint("COM3") == normalize_endpoint(r"\\.\com3")
    finally:
        first.release()
    second = manager.acquire(
        "usb:0403:9999:XYZ", "owner-b", endpoint="COM3",
    )
    first.release()  # stale lease must not release the new owner's lease
    assert manager.active_owner("COM3") == "owner-b"
    second.release()


def test_unsupported_and_arbitrary_queries_are_rejected() -> None:
    session = _session(profiles()[4])  # C1000
    session.open(ConsoleCredentials("console", "synthetic-password", None))
    session.set_profile(resolve_profile("C1000-24P-4G-L", "15.2(7)E1"))
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
    session.set_profile(resolve_profile("C9300L-24P-4X", "17.12.4"))
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

    def pending_data(self) -> bool:
        return False

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


class _ScriptedTransport:
    source = ConsoleSource.SIMULATOR
    port_identity = "sim:scripted"
    lease_endpoint = "sim:scripted"
    identity_quality = "stable"

    def __init__(
        self,
        initial: str,
        responses: dict[str, str | tuple[str, ...]],
    ) -> None:
        self._queue: list[str] = [initial]
        self._responses = responses
        self._open = False
        self.writes: list[str] = []

    def pending_data(self) -> bool:
        return bool(self._queue)

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def write(self, text: str) -> None:
        self.writes.append(text)
        response = self._responses.get(text.rstrip("\r\n"))
        if isinstance(response, str):
            self._queue.append(response)
        elif response is not None:
            self._queue.extend(response)

    def read_chunk(self, timeout: float) -> str:
        _ = timeout
        if not self._open:
            raise RuntimeError("closed")
        return self._queue.pop(0) if self._queue else ""


def test_configuration_mode_is_rejected_before_queries() -> None:
    manager = ConsoleLeaseManager()
    session = ConsoleSession(
        _UnsafeTransport(), lease_manager=manager, timeout=1.0,
    )
    with pytest.raises(SessionError):
        session.open(CREDS)
    assert session.state is SessionState.FAILED
    assert manager.active_owner("sim:unsafe-mode") is None


def test_prompt_identity_must_remain_bound_to_initial_exec_prompt() -> None:
    manager = ConsoleLeaseManager()
    transport = _ScriptedTransport(
        "R1>\n",
        {"show version": "show version\nCisco IOS XE\nEvil#\n"},
    )
    session = ConsoleSession(transport, lease_manager=manager, timeout=1.0)
    session.open(None)
    with pytest.raises(UnexpectedConsolePrompt):
        session.query(ConsoleQuery.VERSION)
    assert session.state is SessionState.FAILED
    assert manager.active_owner("sim:scripted") is None


def test_prompt_like_text_in_body_fails_complete_output() -> None:
    manager = ConsoleLeaseManager()
    transport = _ScriptedTransport(
        "R1>\n",
        {"show version": "show version\nR1#\nmore output\nR1>\n"},
    )
    session = ConsoleSession(transport, lease_manager=manager, timeout=1.0)
    session.open(None)
    with pytest.raises(AmbiguousConsoleOutput):
        session.query(ConsoleQuery.VERSION)
    assert session.state is SessionState.FAILED
    assert manager.active_owner("sim:scripted") is None


def test_prompt_like_chunk_boundary_is_not_accepted() -> None:
    transport = _ScriptedTransport(
        "R1>\n",
        {"show version": ("show version\nR1#", "\nmore output\nR1>\n")},
    )
    session = ConsoleSession(transport, lease_manager=ConsoleLeaseManager(), timeout=1.0)
    session.open(None)
    with pytest.raises(AmbiguousConsoleOutput):
        session.query(ConsoleQuery.VERSION)


def test_auth_prompt_during_query_does_not_send_credentials() -> None:
    transport = _ScriptedTransport(
        "R1>\n",
        {"show version": "Username: "},
    )
    session = ConsoleSession(transport, lease_manager=ConsoleLeaseManager(), timeout=1.0)
    session.open(None)
    with pytest.raises(UnexpectedAuthPrompt):
        session.query(ConsoleQuery.VERSION)
    assert transport.writes == ["show version\r"]


def test_buffered_trailing_response_after_candidate_prompt_is_rejected() -> None:
    transport = _ScriptedTransport(
        "R1>\n",
        {"show version": ("show version\nR1>", "\nstill in response")},
    )
    session = ConsoleSession(transport, lease_manager=ConsoleLeaseManager(), timeout=1.0)
    session.open(None)
    with pytest.raises(SessionError):
        session.query(ConsoleQuery.VERSION)
    assert transport.writes == ["show version\r"]


def test_simulator_restores_exec_state_after_pagination() -> None:
    profile = replace(
        PROFILE,
        interfaces=tuple(f"Gi1/0/{index}" for index in range(1, 10)),
    )
    session = _session(profile=profile, pagination=True, chunk_size=9)
    session.open(CREDS)
    session.set_profile(resolve_profile("C9300L-24P-4X", "17.12.4"))
    try:
        interfaces = session.query(ConsoleQuery.INTERFACES)
        assert "Gi1/0/9" in interfaces
        assert "FIXTURE930001" in session.query(ConsoleQuery.VERSION)
        assert session.state is SessionState.PRIVILEGED_EXEC
    finally:
        session.close()


def test_body_pagination_at_chunk_boundary_is_not_continued() -> None:
    transport = _ScriptedTransport(
        "R1>\n",
        {"show version": ("show version\n--More--", "\nmore output\nR1>\n")},
    )
    session = ConsoleSession(transport, lease_manager=ConsoleLeaseManager(), timeout=1.0)
    session.open(None)
    with pytest.raises(SessionError):
        session.query(ConsoleQuery.VERSION)
    assert transport.writes == ["show version\r"]


def test_login_pagination_is_not_continued() -> None:
    manager = ConsoleLeaseManager()
    transport = _ScriptedTransport("R1>\n--More--\n", {})
    session = ConsoleSession(transport, lease_manager=manager, timeout=1.0)
    with pytest.raises(SessionError):
        session.open(None)
    assert transport.writes == []
    assert manager.active_owner("sim:scripted") is None


def test_cumulative_session_response_limit_fails_closed() -> None:
    transport = _ScriptedTransport(
        "R1>\n",
        {"show version": "show version\n" + "x" * 100 + "\nR1>\n"},
    )
    session = ConsoleSession(
        transport,
        lease_manager=ConsoleLeaseManager(),
        timeout=1.0,
        max_total_response_bytes=20,
    )
    session.open(None)
    with pytest.raises(SessionError):
        session.query(ConsoleQuery.VERSION)
    assert session.state is SessionState.FAILED


@pytest.mark.parametrize("value", [
    "bad\rvalue",
    "bad\nvalue",
    "bad\x1bvalue",
    "bad\x00value",
    "bad\x7fvalue",
    "x" * 129,
])
def test_authentication_inputs_reject_terminal_control_and_overlength(
    value: str,
) -> None:
    manager = ConsoleLeaseManager()
    session = ConsoleSession(
        SimulatedConsoleTransport(profile=PROFILE), lease_manager=manager, timeout=1.0,
    )
    credentials = ConsoleCredentials(value, "synthetic-password", None)
    with pytest.raises(CredentialInputError):
        session.open(credentials)
    assert manager.active_owner("sim:synthetic-9300") is None


def test_live_and_ambiguous_transports_are_not_connectable() -> None:
    class Live(_ScriptedTransport):
        source = ConsoleSource.LIVE_DEVICE

    class Ambiguous(_ScriptedTransport):
        identity_quality = "ambiguous"

    live = ConsoleSession(Live("R1>\n", {}), timeout=1.0)
    with pytest.raises(LiveDeviceDisabled):
        live.open(None)
    ambiguous = ConsoleSession(Ambiguous("R1>\n", {}), timeout=1.0)
    with pytest.raises(AmbiguousAdapterIdentity):
        ambiguous.open(None)


def test_two_concurrent_queries_on_one_session_are_serialized() -> None:
    from concurrent.futures import ThreadPoolExecutor

    session = _session()
    session.open(CREDS)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                session.query,
                [ConsoleQuery.VERSION, ConsoleQuery.INVENTORY],
            ))
        assert any("FIXTURE930001" in item for item in results)
        assert session.state is SessionState.PRIVILEGED_EXEC
    finally:
        session.close()


class _SlowTransport(_ScriptedTransport):
    def read_chunk(self, timeout: float) -> str:
        import time

        time.sleep(0.03)
        return super().read_chunk(timeout)


def test_cancel_discovery_does_not_block_on_query_held_state_lock() -> None:
    import threading
    import time

    session = ConsoleSession(
        _SlowTransport("R1>\n", {"show version": "show version\nR1>\n"}),
        lease_manager=ConsoleLeaseManager(),
        timeout=2.0,
    )
    session.open(None)
    session.start_discovery(deadline_seconds=30)
    errors: list[BaseException] = []

    def run_query() -> None:
        try:
            session.query(ConsoleQuery.VERSION)
        except BaseException as exc:  # record the expected cancellation
            errors.append(exc)

    query_thread = threading.Thread(target=run_query)
    query_thread.start()
    time.sleep(0.01)
    started = time.monotonic()
    session.cancel_discovery()
    cancel_elapsed = time.monotonic() - started
    query_thread.join(timeout=5)
    try:
        assert not query_thread.is_alive()
        assert cancel_elapsed < 0.5
        assert errors and isinstance(errors[0], SessionError)
        assert session.state is SessionState.FAILED
    finally:
        session.close()


def test_close_during_query_has_a_defined_serialized_outcome() -> None:
    import threading
    import time

    session = ConsoleSession(
        _SlowTransport("R1>\n", {"show version": "show version\nR1>\n"}),
        lease_manager=ConsoleLeaseManager(),
        timeout=2.0,
    )
    session.open(None)
    result: list[str | None] = [None]

    def run_query() -> None:
        try:
            result[0] = session.query(ConsoleQuery.VERSION)
        except SessionError:
            result[0] = None

    query_thread = threading.Thread(target=run_query)
    query_thread.start()
    time.sleep(0.01)
    closer = threading.Thread(target=session.close)
    closer.start()
    query_thread.join(timeout=5)
    closer.join(timeout=5)
    assert not query_thread.is_alive()
    assert not closer.is_alive()
    assert session.state is SessionState.CLOSED
    assert result[0] is None or "show version" not in result[0]


class _OpenFailure(_ScriptedTransport):
    def open(self) -> None:
        raise TransportError("safe-open-failure")


class _CloseFailure(_ScriptedTransport):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.close_attempts = 0

    def close(self) -> None:
        self.close_attempts += 1
        raise TransportError("safe-close-failure")


class _RecoveringCloseFailure(_CloseFailure):
    def close(self) -> None:
        self.close_attempts += 1
        if self.close_attempts == 1:
            raise TransportError("safe-close-failure")
        super(_CloseFailure, self).close()


class _WriteFailure(_ScriptedTransport):
    def write(self, text: str) -> None:
        raise TransportError("safe-write-failure")


def test_transport_open_failure_releases_lease() -> None:
    manager = ConsoleLeaseManager()
    session = ConsoleSession(_OpenFailure("R1>\n", {}), lease_manager=manager)
    with pytest.raises(SessionError):
        session.open(None)
    assert session.state is SessionState.FAILED
    assert manager.active_owner("sim:scripted") is None


def test_transport_close_failure_does_not_claim_safe_release() -> None:
    manager = ConsoleLeaseManager()
    session = ConsoleSession(_CloseFailure("R1>\n", {}), lease_manager=manager)
    session.open(None)
    with pytest.raises(SessionCleanupError):
        session.close()
    assert session.state is SessionState.FAILED
    # The transport may still own the endpoint; the application lease must
    # remain held rather than falsely advertising a safe release.
    assert manager.active_owner("sim:scripted") is not None


def test_failed_cleanup_can_be_retried_after_transport_recovers() -> None:
    manager = ConsoleLeaseManager()
    transport = _RecoveringCloseFailure("R1>\n", {})
    session = ConsoleSession(transport, lease_manager=manager)
    session.open(None)
    with pytest.raises(SessionCleanupError):
        session.close()
    assert manager.active_owner("sim:scripted") is not None
    session.close()
    assert session.state is SessionState.CLOSED
    assert manager.active_owner("sim:scripted") is None


class _ReadAndCloseFailure(_ScriptedTransport):
    def read_chunk(self, timeout: float) -> str:
        _ = timeout
        if self._queue:
            return self._queue.pop(0)
        raise TransportError("safe-read-failure")

    def close(self) -> None:
        raise TransportError("safe-close-failure")


def test_transport_read_failure_retains_lease_when_close_fails() -> None:
    manager = ConsoleLeaseManager()
    session = ConsoleSession(
        _ReadAndCloseFailure("R1>\n", {}), lease_manager=manager,
    )
    session.open(None)
    with pytest.raises(SessionCleanupError):
        session.query(ConsoleQuery.VERSION)
    assert session.state is SessionState.FAILED
    assert manager.active_owner("sim:scripted") is not None


def test_transport_write_failure_closes_and_releases_lease() -> None:
    manager = ConsoleLeaseManager()
    session = ConsoleSession(_WriteFailure("R1>\n", {}), lease_manager=manager)
    session.open(None)
    with pytest.raises(SessionError) as error:
        session.query(ConsoleQuery.VERSION)
    assert "safe-write-failure" not in str(error.value)
    assert manager.active_owner("sim:scripted") is None


def test_query_output_redacts_exact_credential_values() -> None:
    transport = _ScriptedTransport(
        "R1>\n",
        {"show version": "show version\nsynthetic-password\nR1>\n"},
    )
    session = ConsoleSession(
        transport, lease_manager=ConsoleLeaseManager(), timeout=1.0,
    )
    session.open(ConsoleCredentials("console", "synthetic-password", None))
    try:
        output = session.query(ConsoleQuery.VERSION)
    finally:
        session.close()
    assert "synthetic-password" not in output
    assert "[REDACTED]" in output
