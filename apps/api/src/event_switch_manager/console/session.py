"""Read-only console session and explicit authentication state machine."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from uuid import uuid4

from event_switch_manager.domain import DeviceFamily
from event_switch_manager.integrations import ConsoleQuery

from .allowlist import (
    BOOTSTRAP_QUERIES,
    FamilyUnknown,
    QueryNotAllowed,
    resolve_query,
    validate_family,
)
from .lease import (
    OS_EXCLUSIVITY_STATUS,
    ConsoleLease,
    ConsoleLeaseManager,
)
from .models import ConsoleQueryResult, ConsoleSource, QueryStatus
from .parser import (
    AuthPromptKind,
    ConsoleOutputLimit,
    ConsolePaginationLimit,
    ConsolePromptParser,
    ParserEventKind,
    PromptMode,
    command_error_present,
)
from .redaction import redact_console_output
from .transport import ConsoleTransport, TransportDisconnected

DEFAULT_SESSION_TIMEOUT = 2.0


class SessionState(StrEnum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    AWAITING_PROMPT = "AWAITING_PROMPT"
    AUTHENTICATING = "AUTHENTICATING"
    USER_EXEC = "USER_EXEC"
    PRIVILEGED_EXEC = "PRIVILEGED_EXEC"
    QUERYING = "QUERYING"
    FAILED = "FAILED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"


class SessionError(RuntimeError):
    """Safe base error; no credential is included in its message."""


class SessionStateError(SessionError):
    pass


class AuthenticationError(SessionError):
    pass


class EnableError(SessionError):
    pass


class ConsoleTimeout(SessionError):
    pass


class UnsafeConsoleState(SessionError):
    pass


class DeviceCommandError(SessionError):
    pass


class SessionClosed(SessionError):
    pass


@dataclass(frozen=True, slots=True)
class ConsoleCredentials:
    username: str = field(repr=False)
    password: str = field(repr=False)
    enable_password: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class _PromptRead:
    output: str
    mode: PromptMode | None
    auth: AuthPromptKind | None


class ConsoleSession:
    """One application-leased, read-only console session.

    There is deliberately no generic command method.  Session-control commands
    are limited to login/enable, and data queries are typed ``ConsoleQuery``
    values from the allowlist.
    """

    os_exclusive_access = OS_EXCLUSIVITY_STATUS

    def __init__(
        self,
        transport: ConsoleTransport,
        *,
        family: DeviceFamily | None = None,
        lease_manager: ConsoleLeaseManager | None = None,
        owner: str | None = None,
        timeout: float = DEFAULT_SESSION_TIMEOUT,
        max_pagination_pages: int = 20,
        max_response_bytes: int = 256 * 1024,
    ) -> None:
        validate_family(family)
        if not 0 < timeout <= 30:
            raise ValueError("session timeout must be in (0, 30] seconds")
        self._transport = transport
        self._family = family
        self._lease_manager = lease_manager or ConsoleLeaseManager()
        self._owner = owner or f"con-{uuid4()}"
        self._timeout = timeout
        self._parser = ConsolePromptParser(
            max_response_bytes=max_response_bytes,
            max_pagination_pages=max_pagination_pages,
        )
        self._state = SessionState.DISCONNECTED
        self._lease: ConsoleLease | None = None
        self._session_id = str(uuid4())
        self._last_results: list[ConsoleQueryResult] = []

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def family(self) -> DeviceFamily | None:
        return self._family

    @property
    def session_identity(self) -> str:
        return self._session_id

    @property
    def port_identity(self) -> str | None:
        return self._transport.port_identity

    @property
    def source(self) -> ConsoleSource:
        return self._transport.source

    @property
    def fixture_id(self) -> str | None:
        return getattr(self._transport, "fixture_id", None)

    @property
    def last_query_results(self) -> tuple[ConsoleQueryResult, ...]:
        return tuple(self._last_results)

    def set_family(self, family: DeviceFamily) -> None:
        validate_family(family)
        if self._family is not None and self._family is not family:
            raise SessionStateError("console family is already established")
        self._family = family

    def open(self, credentials: ConsoleCredentials | None = None) -> None:
        if self._state is not SessionState.DISCONNECTED:
            raise SessionStateError("console session is not disconnected")
        port_identity = self._transport.port_identity
        if not port_identity:
            self._state = SessionState.FAILED
            raise SessionStateError("console transport has no port identity")
        self._lease = self._lease_manager.acquire(port_identity, self._owner)
        try:
            self._state = SessionState.CONNECTING
            self._transport.open()
            self._state = SessionState.AWAITING_PROMPT
            read = self._read_for_prompt()
            attempts = 0
            auth_events = 0
            while read.auth is not None:
                auth_events += 1
                if auth_events > 6:
                    raise AuthenticationError("console authentication failed")
                if credentials is None:
                    raise AuthenticationError("console credentials are required")
                self._state = SessionState.AUTHENTICATING
                if read.auth is AuthPromptKind.USERNAME:
                    self._transport.write(credentials.username + "\r")
                elif read.auth is AuthPromptKind.ENABLE_PASSWORD:
                    raise AuthenticationError("unexpected enable prompt during login")
                else:
                    attempts += 1
                    if attempts > 2:
                        raise AuthenticationError("console authentication failed")
                    self._transport.write(credentials.password + "\r")
                read = self._read_for_prompt()
            if read.mode is PromptMode.PRIVILEGED_EXEC:
                self._state = SessionState.PRIVILEGED_EXEC
            elif read.mode is PromptMode.USER_EXEC:
                self._state = SessionState.USER_EXEC
            else:
                raise UnsafeConsoleState("console did not reach a safe EXEC mode")
            if (
                credentials is not None
                and credentials.enable_password is not None
                and self._state is SessionState.USER_EXEC
            ):
                self._enable(credentials.enable_password)
        except Exception as exc:
            self._fail()
            if isinstance(exc, SessionError):
                raise
            raise SessionError("console session failed") from exc

    def _enable(self, enable_password: str) -> None:
        self._state = SessionState.AUTHENTICATING
        self._parser.reset()
        self._transport.write("enable\r")
        read = self._read_for_prompt()
        if read.auth is AuthPromptKind.PASSWORD:
            self._transport.write(enable_password + "\r")
            read = self._read_for_prompt()
        if read.auth is not None or read.mode is not PromptMode.PRIVILEGED_EXEC:
            raise EnableError("enable authentication failed")
        self._state = SessionState.PRIVILEGED_EXEC

    def query(self, query: ConsoleQuery) -> str:
        result = self.query_result(query)
        if result.status is not QueryStatus.OK:
            raise DeviceCommandError(f"read-only query failed: {result.status.value}")
        return result.output

    def query_result(self, query: ConsoleQuery) -> ConsoleQueryResult:
        if self._state not in {SessionState.USER_EXEC, SessionState.PRIVILEGED_EXEC}:
            raise SessionStateError("console session is not ready for queries")
        if not isinstance(query, ConsoleQuery):
            raise QueryNotAllowed("query must be a typed ConsoleQuery")
        if self._family is None and query not in BOOTSTRAP_QUERIES:
            raise FamilyUnknown("only bootstrap queries are allowed before identity")
        if self._family is None:
            family = DeviceFamily.CATALYST_9300
        else:
            family = self._family
        spec = resolve_query(family, query)
        previous_state = self._state
        self._state = SessionState.QUERYING
        self._parser.reset()
        try:
            self._transport.write(spec.command + "\r")
            read = self._read_for_prompt()
            if read.mode is None:
                raise ConsoleTimeout("console did not return a prompt")
            output = redact_console_output(_strip_echo(read.output, spec.command))
            status = (
                QueryStatus.FAILED if command_error_present(output) else QueryStatus.OK
            )
            result = ConsoleQueryResult(
                query=query,
                command=spec.command,
                status=status,
                output=output,
            )
            self._last_results.append(result)
            self._state = (
                SessionState.PRIVILEGED_EXEC
                if read.mode is PromptMode.PRIVILEGED_EXEC
                else SessionState.USER_EXEC
            )
            if status is QueryStatus.FAILED:
                raise DeviceCommandError("device rejected the read-only query")
            return result
        except (ConsoleTimeout, TransportDisconnected, UnsafeConsoleState) as exc:
            self._fail()
            if isinstance(exc, SessionError):
                raise
            raise SessionError("console query interrupted") from exc
        except (ConsolePaginationLimit, ConsoleOutputLimit) as exc:
            self._fail()
            raise ConsoleTimeout("console output bound exceeded") from exc
        except DeviceCommandError:
            self._state = previous_state
            raise
        except Exception:
            self._fail()
            raise

    def _read_for_prompt(self) -> _PromptRead:
        deadline = time.monotonic() + self._timeout
        output = ""
        while time.monotonic() < deadline:
            remaining = max(0.01, deadline - time.monotonic())
            chunk = self._transport.read_chunk(remaining)
            if not chunk:
                time.sleep(0.002)
                continue
            for event in self._parser.feed(chunk):
                if event.kind is ParserEventKind.OUTPUT:
                    output += event.output
                elif event.kind is ParserEventKind.AUTH_PROMPT:
                    return _PromptRead(output, None, event.auth_prompt)
                elif event.kind is ParserEventKind.PAGINATION:
                    self._transport.write(" ")
                elif event.kind is ParserEventKind.PROMPT:
                    return _PromptRead(output, event.mode, None)
                elif event.kind is ParserEventKind.UNSAFE_STATE:
                    raise UnsafeConsoleState(event.reason or "unsafe console state")
        raise ConsoleTimeout("console prompt timeout")

    def close(self) -> None:
        if self._state in {SessionState.CLOSED, SessionState.DISCONNECTED}:
            return
        self._state = SessionState.CLOSING
        try:
            self._transport.close()
        finally:
            if self._lease is not None:
                self._lease.release()
                self._lease = None
            self._state = SessionState.CLOSED

    def _fail(self) -> None:
        try:
            self._transport.close()
        finally:
            if self._lease is not None:
                self._lease.release()
                self._lease = None
            self._state = SessionState.FAILED

    def __enter__(self) -> ConsoleSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _strip_echo(output: str, command: str) -> str:
    lines = output.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].strip() == command:
        lines.pop(0)
    return "\n".join(lines).strip()


__all__ = [
    "AuthenticationError",
    "ConsoleCredentials",
    "ConsoleSession",
    "ConsoleTimeout",
    "DeviceCommandError",
    "EnableError",
    "SessionClosed",
    "SessionError",
    "SessionState",
    "SessionStateError",
    "UnsafeConsoleState",
]
