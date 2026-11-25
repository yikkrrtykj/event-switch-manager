"""Read-only console session and explicit authentication state machine."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum
from uuid import uuid4

from event_switch_manager.domain import DeviceFamily
from event_switch_manager.integrations import ConsoleQuery

from .allowlist import (
    BOOTSTRAP_QUERIES,
    ConsoleProfile,
    FamilyUnknown,
    ProfileNotVerified,
    QueryNotAllowed,
    resolve_query,
    resolve_query_for_profile,
    validate_family,
)
from .lease import (
    OS_EXCLUSIVITY_STATUS,
    ConsoleLease,
    ConsoleLeaseManager,
    default_lease_manager,
)
from .lease import (
    ConsoleLeaseManager as _LeaseManagerType,
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


class AmbiguousAdapterIdentity(SessionError):
    pass


class LiveDeviceDisabled(SessionError):
    pass


class SessionCleanupError(SessionError):
    pass


class CredentialInputError(SessionError):
    pass


class UnexpectedConsolePrompt(SessionError):
    pass


class AmbiguousConsoleOutput(SessionError):
    pass


class UnexpectedAuthPrompt(SessionError):
    pass


class DiscoveryTimeout(SessionError):
    pass


class DiscoveryCancelled(SessionError):
    pass


MAX_AUTH_INPUT_LENGTH = 128


def validate_console_input(name: str, value: str) -> str:
    """Validate an authentication value without truncating or echoing it."""
    if not isinstance(value, str):
        raise CredentialInputError(f"{name} must be text")
    if not value or len(value) > MAX_AUTH_INPUT_LENGTH:
        raise CredentialInputError(f"{name} has an invalid length")
    for character in value:
        code = ord(character)
        if code < 0x20 or code > 0x7E:
            raise CredentialInputError(f"{name} contains an unsupported character")
    return value


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
    prompt: str | None = None


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
        max_total_response_bytes: int = 512 * 1024,
    ) -> None:
        validate_family(family)
        if not 0 < timeout <= 30:
            raise ValueError("session timeout must be in (0, 30] seconds")
        if max_total_response_bytes <= 0:
            raise ValueError("total response limit must be positive")
        self._transport = transport
        self._family = family
        self._profile: ConsoleProfile | None = None
        self._lease_manager: _LeaseManagerType = (
            lease_manager if lease_manager is not None else default_lease_manager()
        )
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
        self._state_lock = threading.RLock()
        self._total_response_bytes = 0
        self._max_total_response_bytes = max_total_response_bytes
        self._prompt_name: str | None = None
        self._prompt_mode: PromptMode | None = None
        self._redaction_secrets: tuple[str, ...] = ()
        self._discovery_deadline: float | None = None
        self._cancel_discovery_event: threading.Event | None = None

    @property
    def state(self) -> SessionState:
        with self._state_lock:
            return self._state

    @property
    def family(self) -> DeviceFamily | None:
        with self._state_lock:
            return self._family

    @property
    def profile(self) -> ConsoleProfile | None:
        with self._state_lock:
            return self._profile

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
        with self._state_lock:
            return tuple(self._last_results)

    def set_family(self, family: DeviceFamily) -> None:
        validate_family(family)
        with self._state_lock:
            if self._family is not None and self._family is not family:
                raise SessionStateError("console family is already established")
            self._family = family

    def start_discovery(
        self,
        *,
        deadline_seconds: float = 30.0,
        cancel_event: threading.Event | None = None,
    ) -> None:
        if not 0 < deadline_seconds <= 300:
            raise ValueError("discovery deadline must be in (0, 300] seconds")
        with self._state_lock:
            self._discovery_deadline = time.monotonic() + deadline_seconds
            self._cancel_discovery_event = cancel_event or threading.Event()

    def end_discovery(self) -> None:
        with self._state_lock:
            self._discovery_deadline = None
            self._cancel_discovery_event = None

    def cancel_discovery(self) -> None:
        # Cancellation must not queue behind a query holding the state lock.
        # Reading the immutable event reference is sufficient; setting an Event
        # is thread-safe.
        event = self._cancel_discovery_event
        if event is not None:
            event.set()

    def _check_discovery_budget(self) -> None:
        if (
            self._cancel_discovery_event is not None
            and self._cancel_discovery_event.is_set()
        ):
            raise DiscoveryCancelled("console discovery was cancelled")
        if (
            self._discovery_deadline is not None
            and time.monotonic() >= self._discovery_deadline
        ):
            raise DiscoveryTimeout("console discovery deadline exceeded")

    def set_profile(self, profile: ConsoleProfile) -> None:
        if not isinstance(profile, ConsoleProfile):
            raise ProfileNotVerified("exact console profile is required")
        with self._state_lock:
            if self._profile is not None and self._profile != profile:
                raise SessionStateError("console profile is already established")
            if self._family is not None and self._family is not profile.family:
                raise SessionStateError("console profile family conflicts")
            if self._family is None:
                self._family = profile.family
            self._profile = profile

    def open(self, credentials: ConsoleCredentials | None = None) -> None:
        with self._state_lock:
            self._open_locked(credentials)

    def _open_locked(self, credentials: ConsoleCredentials | None) -> None:
        if self._state is not SessionState.DISCONNECTED:
            raise SessionStateError("console session is not disconnected")
        if credentials is not None:
            validate_console_input("username", credentials.username)
            validate_console_input("password", credentials.password)
            if credentials.enable_password is not None:
                validate_console_input("enable password", credentials.enable_password)
            self._redaction_secrets = tuple(
                value for value in (
                    credentials.username,
                    credentials.password,
                    credentials.enable_password,
                ) if value is not None
            )
        if self.source is ConsoleSource.LIVE_DEVICE:
            raise LiveDeviceDisabled("live device sessions are disabled in CON-01")
        port_identity = self._transport.port_identity
        if not port_identity:
            self._state = SessionState.FAILED
            raise SessionStateError("console transport has no port identity")
        quality = getattr(self._transport, "identity_quality", "stable")
        if quality in {"ambiguous", "duplicate"}:
            raise AmbiguousAdapterIdentity("ambiguous adapter identity is not connectable")
        endpoint = getattr(self._transport, "lease_endpoint", port_identity)
        self._lease = self._lease_manager.acquire(
            port_identity, self._owner, endpoint=endpoint,
        )
        try:
            self._total_response_bytes = 0
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
            self._bind_initial_prompt(read)
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
        validate_console_input("enable password", enable_password)
        self._state = SessionState.AUTHENTICATING
        self._parser.reset()
        self._transport.write("enable\r")
        read = self._read_for_prompt()
        if read.auth is AuthPromptKind.PASSWORD:
            self._transport.write(enable_password + "\r")
            read = self._read_for_prompt()
        if read.auth is not None or read.mode is not PromptMode.PRIVILEGED_EXEC:
            raise EnableError("enable authentication failed")
        self._check_bound_prompt(read)
        self._state = SessionState.PRIVILEGED_EXEC
        self._prompt_mode = PromptMode.PRIVILEGED_EXEC

    def _bind_initial_prompt(self, read: _PromptRead) -> None:
        if read.prompt is None or read.mode is None:
            raise UnsafeConsoleState("console did not reach a safe EXEC mode")
        name = read.prompt[:-1].strip()
        if not name:
            raise UnsafeConsoleState("console prompt identity is empty")
        self._prompt_name = name
        self._prompt_mode = read.mode
        self._state = (
            SessionState.PRIVILEGED_EXEC
            if read.mode is PromptMode.PRIVILEGED_EXEC
            else SessionState.USER_EXEC
        )

    def _check_bound_prompt(self, read: _PromptRead) -> None:
        if read.prompt is None or read.mode is None:
            raise UnexpectedConsolePrompt("console did not return an EXEC prompt")
        name = read.prompt[:-1].strip()
        if self._prompt_name is None or name != self._prompt_name:
            raise UnexpectedConsolePrompt("console prompt identity changed")
        expected_suffix = "#" if read.mode is PromptMode.PRIVILEGED_EXEC else ">"
        if not read.prompt.endswith(expected_suffix):
            raise UnexpectedConsolePrompt("console prompt mode changed")
        self._prompt_mode = read.mode

    def query(self, query: ConsoleQuery) -> str:
        result = self.query_result(query)
        if result.status is not QueryStatus.OK:
            raise DeviceCommandError(f"read-only query failed: {result.status.value}")
        return result.output

    def query_result(self, query: ConsoleQuery) -> ConsoleQueryResult:
        with self._state_lock:
            return self._query_result_locked(query)

    def _query_result_locked(self, query: ConsoleQuery) -> ConsoleQueryResult:
        if self._state not in {SessionState.USER_EXEC, SessionState.PRIVILEGED_EXEC}:
            raise SessionStateError("console session is not ready for queries")
        if not isinstance(query, ConsoleQuery):
            raise QueryNotAllowed("query must be a typed ConsoleQuery")
        if self._profile is None and query not in BOOTSTRAP_QUERIES:
            raise FamilyUnknown("only bootstrap queries are allowed before identity")
        if self._profile is not None:
            spec = resolve_query_for_profile(self._profile, query)
        else:
            family = self._family or DeviceFamily.CATALYST_9300
            spec = resolve_query(family, query)
        previous_state = self._state
        self._state = SessionState.QUERYING
        self._parser.reset()
        try:
            self._check_discovery_budget()
            self._transport.write(spec.command + "\r")
            read = self._read_for_prompt(allow_pagination=True)
            if read.auth is not None:
                raise UnexpectedAuthPrompt("authentication prompt during query")
            self._check_bound_prompt(read)
            output = redact_console_output(
                _strip_echo(read.output, spec.command),
                self._redaction_secrets,
            )
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
        except Exception as exc:
            self._fail()
            if isinstance(exc, SessionError):
                raise
            raise SessionError("console operation failed") from exc

    def _read_for_prompt(self, *, allow_pagination: bool = False) -> _PromptRead:
        deadline = time.monotonic() + self._timeout
        output = ""
        candidate: _PromptRead | None = None
        while time.monotonic() < deadline:
            self._check_discovery_budget()
            pending_fn = getattr(self._transport, "pending_data", None)
            pending = bool(pending_fn()) if callable(pending_fn) else False
            if candidate is not None and not pending:
                extra = output[len(candidate.output):].strip()
                if extra:
                    self._parser.mark_prompt_collision()
                    raise AmbiguousConsoleOutput(
                        "prompt-like text occurred in command output",
                    )
                return candidate
            remaining = max(0.01, deadline - time.monotonic())
            chunk = self._transport.read_chunk(remaining)
            if not chunk:
                continue
            for event in self._parser.feed(chunk):
                if event.kind is ParserEventKind.OUTPUT:
                    output += event.output
                    self._total_response_bytes += len(event.output.encode("utf-8"))
                    if self._total_response_bytes > self._max_total_response_bytes:
                        raise ConsoleOutputLimit("console session output limit exceeded")
                elif event.kind is ParserEventKind.AUTH_PROMPT:
                    if candidate is not None:
                        raise AmbiguousConsoleOutput("duplicate terminal response")
                    return _PromptRead(output, None, event.auth_prompt)
                elif event.kind is ParserEventKind.PAGINATION:
                    if candidate is not None:
                        raise AmbiguousConsoleOutput("pagination after prompt")
                    if not allow_pagination:
                        raise UnsafeConsoleState("unexpected console pagination")
                    pending_pages = getattr(self._transport, "pending_data", None)
                    if callable(pending_pages) and pending_pages():
                        raise AmbiguousConsoleOutput(
                            "pagination marker occurred with pending terminal data",
                        )
                    self._transport.write(" ")
                elif event.kind is ParserEventKind.PROMPT:
                    if candidate is not None and output[len(candidate.output):].strip():
                        self._parser.mark_prompt_collision()
                    candidate = _PromptRead(
                        output, event.mode, None, event.prompt,
                    )
                elif event.kind is ParserEventKind.UNSAFE_STATE:
                    raise UnsafeConsoleState(event.reason or "unsafe console state")
            if candidate is not None and self._parser.prompt_collision:
                raise AmbiguousConsoleOutput(
                    "prompt-like text occurred in command output",
                )
        raise ConsoleTimeout("console prompt timeout")

    def close(self) -> None:
        with self._state_lock:
            if self._state in {SessionState.CLOSED, SessionState.DISCONNECTED}:
                return
            self._state = SessionState.CLOSING
            cleanup_error: Exception | None = None
            try:
                self._transport.close()
            except Exception as exc:
                cleanup_error = exc
            self._redaction_secrets = ()
            if cleanup_error is None:
                lease = self._lease
                self._lease = None
                if lease is not None:
                    try:
                        lease.release()
                    except Exception as exc:
                        cleanup_error = exc
            if cleanup_error is not None:
                # Keep the lease when the transport may still own the OS
                # endpoint. A later close() may retry cleanup.
                self._state = SessionState.FAILED
                raise SessionCleanupError("console cleanup failed") from cleanup_error
            self._state = SessionState.CLOSED

    def _fail(self) -> None:
        cleanup_error: Exception | None = None
        try:
            self._transport.close()
        except Exception as exc:
            cleanup_error = exc
        self._redaction_secrets = ()
        if cleanup_error is None:
            lease = self._lease
            self._lease = None
            if lease is not None:
                try:
                    lease.release()
                except Exception as exc:
                    cleanup_error = exc
        self._state = SessionState.FAILED
        if cleanup_error is not None:
            raise SessionCleanupError("console cleanup failed") from cleanup_error

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
    "AmbiguousAdapterIdentity",
    "AuthenticationError",
    "ConsoleCredentials",
    "ConsoleSession",
    "ConsoleTimeout",
    "CredentialInputError",
    "DeviceCommandError",
    "DiscoveryCancelled",
    "DiscoveryTimeout",
    "EnableError",
    "LiveDeviceDisabled",
    "MAX_AUTH_INPUT_LENGTH",
    "SessionCleanupError",
    "SessionClosed",
    "SessionError",
    "SessionState",
    "SessionStateError",
    "UnsafeConsoleState",
    "validate_console_input",
]
