"""Read-only console session and explicit authentication state machine."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol
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
    validate_profile,
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


class ConsoleSendOperation(StrEnum):
    WAKE = "wake"
    USERNAME = "username"
    PASSWORD = "password"
    ENABLE = "enable"
    ENABLE_PASSWORD = "enable-password"
    QUERY = "query"
    PAGINATION = "pagination"


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


class ConsoleOperatorAbort(SessionError):
    """The operator refused to confirm a query or continue the lab run."""


class LabSessionGate(Protocol):
    def authorize_open(self, transport: object) -> None: ...

    def authorize_query(self, query: ConsoleQuery) -> None: ...

    def authorize_send(
        self,
        operation: ConsoleSendOperation,
        text: str,
        query: ConsoleQuery | None = None,
    ) -> None: ...

    def check_active(self) -> None: ...

    def remaining_seconds(self) -> float | None: ...


class PromptCompletionPolicy(Protocol):
    def observe_chunk(self, chunk: str) -> None: ...

    def candidate_seen(self) -> None: ...

    def candidate_ready(self) -> bool: ...

    def next_check_seconds(self) -> float: ...


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
        lab_gate: LabSessionGate | None = None,
        completion_policy: PromptCompletionPolicy | None = None,
        credential_provider: Callable[[AuthPromptKind], str] | None = None,
        auth_timeout: float = 30.0,
    ) -> None:
        validate_family(family)
        if not 0 < timeout <= 120:
            raise ValueError("session timeout must be in (0, 120] seconds")
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
        self._lab_gate = lab_gate
        self._completion_policy = completion_policy
        self._credential_provider = credential_provider
        self._auth_timeout = auth_timeout
        self._active_query: ConsoleQuery | None = None
        self._wake_sent = False
        self._cancel_event = threading.Event()
        self._last_prompt_read_saw_data = False
        self._write_token = object()
        self._last_failure: dict[str, object] | None = None
        self._cleanup_error: dict[str, object] | None = None

    @property
    def state(self) -> SessionState:
        with self._state_lock:
            return self._state

    @property
    def last_results(self) -> tuple[ConsoleQueryResult, ...]:
        with self._state_lock:
            return tuple(self._last_results)

    @property
    def last_failure(self) -> dict[str, object] | None:
        with self._state_lock:
            return dict(self._last_failure) if self._last_failure else None

    @property
    def cleanup_error(self) -> dict[str, object] | None:
        with self._state_lock:
            return dict(self._cleanup_error) if self._cleanup_error else None

    def _record_failure(
        self, stage: str, code: str, exc: BaseException | None = None,
    ) -> None:
        if self._last_failure is not None:
            return
        cause = exc
        os_error_type = None
        winerror = None
        errno = None
        if cause is not None:
            cause_type = type(cause).__name__
            os_error_type = getattr(cause, "os_error_type", None) or (
                cause_type if isinstance(cause, OSError) else None
            )
            winerror = getattr(cause, "winerror", None)
            errno = getattr(cause, "errno", None)
        else:
            cause_type = None
        self._last_failure = {
            "stage": stage,
            "code": code,
            "exception_type": cause_type,
            "os_error_type": os_error_type,
            "winerror": winerror,
            "errno": errno,
        }

    @property
    def transport_ever_opened(self) -> bool:
        return bool(getattr(self._transport, "ever_opened", False))

    @property
    def is_attached(self) -> bool:
        with self._state_lock:
            return self._state in {
                SessionState.USER_EXEC,
                SessionState.PRIVILEGED_EXEC,
            }

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

    def extend_discovery_budget(self, seconds: float) -> None:
        """Exclude operator-only wait from the observation I/O deadline."""
        if seconds > 0 and self._discovery_deadline is not None:
            self._discovery_deadline += seconds

    def end_discovery(self) -> None:
        with self._state_lock:
            self._discovery_deadline = None
            self._cancel_discovery_event = None

    def cancel(self) -> None:
        """Request bounded cancellation of an in-flight read/session."""
        self._cancel_event.set()

    def cancel_discovery(self) -> None:
        # Cancellation must not queue behind a query holding the state lock.
        # Reading the immutable event reference is sufficient; setting an Event
        # is thread-safe.
        event = self._cancel_discovery_event
        if event is not None:
            event.set()

    def _check_discovery_budget(self) -> None:
        if self._cancel_event.is_set():
            raise SessionError("console session was cancelled")
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
        profile = validate_profile(profile)
        with self._state_lock:
            if self._profile is not None and self._profile != profile:
                raise SessionStateError("console profile is already established")
            if self._family is not None and self._family is not profile.family:
                raise SessionStateError("console profile family conflicts")
            if self._family is None:
                self._family = profile.family
            self._profile = profile

    def open(
        self,
        credentials: ConsoleCredentials | None = None,
        *,
        initial_timeout: float | None = None,
        allow_silent: bool = False,
    ) -> None:
        with self._state_lock:
            self._open_locked(
                credentials,
                initial_timeout=initial_timeout,
                allow_silent=allow_silent,
            )

    def _open_locked(
        self,
        credentials: ConsoleCredentials | None,
        *,
        initial_timeout: float | None = None,
        allow_silent: bool = False,
    ) -> None:
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
        if self.source is ConsoleSource.AUTHORIZED_LIVE_LAB:
            if self._lab_gate is None:
                raise LiveDeviceDisabled("authorized live lab requires a lab gate")
            transport_authorization = getattr(self._transport, "authorization", None)
            gate_authorization = getattr(self._lab_gate, "authorization", self._lab_gate)
            if (
                transport_authorization is None
                or gate_authorization is not transport_authorization
            ):
                raise LiveDeviceDisabled("lab gate and transport authorization are not bound")
            self._lab_gate.authorize_open(self._transport)
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
            self._wake_sent = False
            self._state = SessionState.CONNECTING
            self._transport.open()
            bind_token = getattr(self._transport, "bind_write_token", None)
            if callable(bind_token):
                bind_token(self._write_token, lambda: self._state)
            self._state = SessionState.AWAITING_PROMPT
            try:
                read = self._read_for_prompt(timeout=initial_timeout)
            except ConsoleTimeout:
                if allow_silent and not self._last_prompt_read_saw_data:
                    # True silence can be offered an explicit, operator-
                    # confirmed single wake.  Any consumed banner/output is
                    # ambiguous and must fail closed instead.
                    self._state = SessionState.AWAITING_PROMPT
                    return
                raise
            self._complete_attach(read, credentials)
        except Exception as exc:
            self._record_failure(
                "open",
                getattr(exc, "code", type(exc).__name__),
                exc,
            )
            self._fail()
            if isinstance(exc, SessionError):
                raise
            raise SessionError("console session failed") from exc

    def _drain_auth_prompt_padding(self) -> None:
        """Consume bounded trailing whitespace from a split auth prompt.

        Windows terminals may deliver ``Password:`` and its trailing space in
        separate reads.  Only immediately-following whitespace is tolerated;
        any non-whitespace byte is an unexpected terminal state and fails
        closed.  No byte is written here.
        """
        pending_fn = getattr(self._transport, "pending_data", None)
        if not callable(pending_fn):
            return
        deadline = time.monotonic() + 0.2
        drained = 0
        while pending_fn():
            remaining = deadline - time.monotonic()
            if remaining <= 0 or drained >= 16:
                raise AmbiguousConsoleOutput("authentication prompt padding did not settle")
            chunk = self._transport.read_chunk(min(0.02, remaining))
            if not chunk:
                continue
            drained += len(chunk)
            if chunk.strip():
                raise AmbiguousConsoleOutput(
                    "unexpected non-whitespace data at authentication prompt",
                )

    def _credential_value(
        self,
        credentials: ConsoleCredentials | None,
        kind: AuthPromptKind,
    ) -> str:
        if credentials is not None:
            if kind is AuthPromptKind.USERNAME:
                return credentials.username
            if kind is AuthPromptKind.PASSWORD:
                return credentials.password
        if self._credential_provider is not None:
            value = self._credential_provider(kind)
            validate_console_input(kind.value, value)
            self._redaction_secrets = (*self._redaction_secrets, value)
            return value
        raise AuthenticationError("console credentials are required")

    def _send(
        self,
        text: str,
        operation: ConsoleSendOperation,
        *,
        query: ConsoleQuery | None = None,
    ) -> int:
        if self._cancel_event.is_set():
            raise SessionError("console session was cancelled")
        if self._lab_gate is not None:
            self._lab_gate.check_active()
        write_authorized = getattr(self._transport, "write_authorized", None)
        if callable(write_authorized):
            # The real transport is the final per-write authorization boundary;
            # the session capability token prevents direct callers bypassing it.
            sent = write_authorized(
                text,
                operation=operation,
                query=query,
                session_token=self._write_token,
            )
            return int(sent) if isinstance(sent, int) else len(text.encode("ascii"))
        self._transport.write(text)
        return len(text.encode("ascii"))

    def _complete_attach(
        self,
        read: _PromptRead,
        credentials: ConsoleCredentials | None,
    ) -> None:
        attempts = 0
        auth_events = 0
        auth_deadline = time.monotonic() + self._auth_timeout
        while read.auth is not None:
            auth_events += 1
            if auth_events > 6:
                raise AuthenticationError("console authentication failed")
            remaining = auth_deadline - time.monotonic()
            if remaining <= 0:
                raise AuthenticationError("console authentication budget expired")
            self._state = SessionState.AUTHENTICATING
            self._drain_auth_prompt_padding()
            if read.auth is AuthPromptKind.USERNAME:
                value = self._credential_value(credentials, AuthPromptKind.USERNAME)
                self._drain_auth_prompt_padding()
                if time.monotonic() >= auth_deadline:
                    raise AuthenticationError("console authentication budget expired")
                self._send(value + "\r", ConsoleSendOperation.USERNAME)
            elif read.auth is AuthPromptKind.ENABLE_PASSWORD:
                raise AuthenticationError("unexpected enable prompt during login")
            else:
                attempts += 1
                if attempts > 2:
                    raise AuthenticationError("console authentication failed")
                value = self._credential_value(credentials, AuthPromptKind.PASSWORD)
                self._drain_auth_prompt_padding()
                if time.monotonic() >= auth_deadline:
                    raise AuthenticationError("console authentication budget expired")
                self._send(value + "\r", ConsoleSendOperation.PASSWORD)
            remaining = auth_deadline - time.monotonic()
            if remaining <= 0:
                raise AuthenticationError("console authentication budget expired")
            read = self._read_for_prompt(timeout=remaining)
        self._bind_initial_prompt(read)
        if (
            credentials is not None
            and credentials.enable_password is not None
            and self._state is SessionState.USER_EXEC
        ):
            self._enable(credentials.enable_password)

    def finish_attach(
        self,
        credentials: ConsoleCredentials | None = None,
        *,
        timeout: float | None = None,
    ) -> None:
        """Complete a passive attach after an explicit wake/resume decision."""
        with self._state_lock:
            if self._state is not SessionState.AWAITING_PROMPT:
                raise SessionStateError("console session is not awaiting a prompt")
            try:
                read = self._read_for_prompt(
                    timeout=min(
                        self._auth_timeout,
                        timeout if timeout is not None else self._auth_timeout,
                    ),
                )
                self._complete_attach(read, credentials)
            except Exception as exc:
                self._record_failure(
                    "attach",
                    getattr(exc, "code", type(exc).__name__),
                    exc,
                )
                self._fail()
                if isinstance(exc, SessionError):
                    raise
                raise SessionError("console attach failed") from exc

    def wake_once(self) -> None:
        """Send at most one operator-authorized CR to a silent device."""
        with self._state_lock:
            if self._state is not SessionState.AWAITING_PROMPT:
                raise SessionStateError("console session is not awaiting a prompt")
            if self._lab_gate is None:
                raise LiveDeviceDisabled("wake is only available to the lab runner")
            if self._wake_sent:
                raise UnsafeConsoleState("a wake CR was already sent")
            self._send("\r", ConsoleSendOperation.WAKE)
            self._wake_sent = True
            self._state = SessionState.AWAITING_PROMPT

    def _enable(self, enable_password: str | None = None) -> None:
        self._state = SessionState.AUTHENTICATING
        self._parser.reset()
        deadline = time.monotonic() + self._auth_timeout
        self._send("enable\r", ConsoleSendOperation.ENABLE)
        read = self._read_for_prompt(timeout=max(0.001, deadline - time.monotonic()))
        if read.auth is AuthPromptKind.PASSWORD:
            self._drain_auth_prompt_padding()
            value = enable_password or self._credential_value(
                None, AuthPromptKind.ENABLE_PASSWORD,
            )
            self._drain_auth_prompt_padding()
            validate_console_input("enable password", value)
            if time.monotonic() >= deadline:
                raise EnableError("enable authentication budget expired")
            self._send(value + "\r", ConsoleSendOperation.ENABLE_PASSWORD)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise EnableError("enable authentication budget expired")
            read = self._read_for_prompt(timeout=remaining)
        if read.auth is not None or read.mode is not PromptMode.PRIVILEGED_EXEC:
            raise EnableError("enable authentication failed")
        self._check_bound_prompt(read, allow_privilege_upgrade=True)
        self._state = SessionState.PRIVILEGED_EXEC
        self._prompt_mode = PromptMode.PRIVILEGED_EXEC

    def enable_with_operator(self) -> None:
        """Request enable only after an explicit operator decision."""
        with self._state_lock:
            if self._state is not SessionState.USER_EXEC:
                raise SessionStateError("enable is only available from USER EXEC")
            try:
                self._enable(None)
            except Exception as exc:
                self._fail()
                if isinstance(exc, SessionError):
                    raise
                raise SessionError("enable failed") from exc

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

    def _check_bound_prompt(
        self,
        read: _PromptRead,
        *,
        allow_privilege_upgrade: bool = False,
    ) -> None:
        if read.prompt is None or read.mode is None:
            raise UnexpectedConsolePrompt("console did not return an EXEC prompt")
        name = read.prompt[:-1].strip()
        if self._prompt_name is None or name != self._prompt_name:
            raise UnexpectedConsolePrompt("console prompt identity changed")
        if self._prompt_mode is None:
            raise UnexpectedConsolePrompt("console prompt mode was not bound")
        upgrade = (
            allow_privilege_upgrade
            and self._prompt_mode is PromptMode.USER_EXEC
            and read.mode is PromptMode.PRIVILEGED_EXEC
        )
        if read.mode is not self._prompt_mode and not upgrade:
            raise UnexpectedConsolePrompt("console prompt mode changed")
        expected_suffix = "#" if read.mode is PromptMode.PRIVILEGED_EXEC else ">"
        if not read.prompt.endswith(expected_suffix):
            raise UnexpectedConsolePrompt("console prompt mode changed")

    def query(self, query: ConsoleQuery) -> str:
        result = self.query_result(query)
        if result.status is not QueryStatus.OK:
            raise DeviceCommandError(f"read-only query failed: {result.status.value}")
        return result.output

    def phase(self) -> str:
        with self._state_lock:
            return self._state.value

    def pending_data(self) -> bool:
        pending = getattr(self._transport, "pending_data", None)
        return bool(pending()) if callable(pending) else False

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
        self._active_query = query
        started = time.monotonic()
        execution_started: float | None = None
        command_sent = False
        sent_bytes = 0
        response_start = self._total_response_bytes
        stage = "authorize-query"

        def failed_result(exc: BaseException) -> ConsoleQueryResult:
            nonlocal command_sent, sent_bytes
            sent_bytes = max(
                sent_bytes,
                int(getattr(self._transport, "last_write_bytes", 0) or 0),
            )
            command_sent = command_sent or sent_bytes > 0
            return ConsoleQueryResult(
                query=query,
                command=spec.command,
                status=QueryStatus.FAILED,
                duration_seconds=round(
                    time.monotonic() - (execution_started or started), 6,
                ),
                command_sent=command_sent,
                sent_bytes=sent_bytes,
                response_bytes=max(0, self._total_response_bytes - response_start),
                completion_status=(
                    "not-sent" if not command_sent else "unverified"
                ),
                failure_stage=stage,
                failure_code=type(exc).__name__,
                unknown_fields=("bootstrap-query-failed",),
            )

        try:
            if self._lab_gate is not None:
                self._lab_gate.authorize_query(query)
            self._check_discovery_budget()
            # Operator reading/confirmation time is not part of the device
            # command timing or the observation I/O budget.
            execution_started = time.monotonic()
            stage = "send"
            sent_bytes = self._send(
                spec.command + "\r", ConsoleSendOperation.QUERY, query=query,
            )
            command_sent = sent_bytes > 0
            stage = "read"
            read = self._read_for_prompt(allow_pagination=True)
            stage = "parse"
            if read.auth is not None:
                raise UnexpectedAuthPrompt("authentication prompt during query")
            self._check_bound_prompt(read)
            raw_output = _strip_echo(read.output, spec.command)
            status = (
                QueryStatus.FAILED
                if command_error_present(raw_output)
                else QueryStatus.OK
            )
            output = redact_console_output(
                raw_output,
                self._redaction_secrets,
            )
            result = ConsoleQueryResult(
                query=query,
                command=spec.command,
                status=status,
                output=output,
                duration_seconds=round(
                    time.monotonic() - (execution_started or started), 6,
                ),
                output_bytes=len(output.encode("utf-8", errors="replace")),
                output_lines=len(output.splitlines()),
                pagination_events=self._parser.pages,
                completion_status=(
                    "candidate-quiet-window"
                    if self._completion_policy is not None
                    else "legacy-parser-timing"
                ),
                command_sent=command_sent,
                sent_bytes=sent_bytes,
                response_bytes=max(0, self._total_response_bytes - response_start),
                failure_stage=(
                    "device-command" if status is QueryStatus.FAILED else None
                ),
                failure_code=(
                    "device-command-error" if status is QueryStatus.FAILED else None
                ),
            )
            self._last_results.append(result)
            self._state = (
                SessionState.PRIVILEGED_EXEC
                if read.mode is PromptMode.PRIVILEGED_EXEC
                else SessionState.USER_EXEC
            )
            if status is QueryStatus.FAILED:
                self._record_failure("device-command", "device-command-error")
                raise DeviceCommandError("device rejected the read-only query")
            return result
        except DeviceCommandError:
            self._state = previous_state
            raise
        except (ConsoleTimeout, TransportDisconnected, UnsafeConsoleState) as exc:
            self._last_results.append(failed_result(exc))
            self._record_failure(stage, type(exc).__name__, exc)
            self._fail()
            if isinstance(exc, SessionError):
                raise
            raise SessionError("console query interrupted") from exc
        except (ConsolePaginationLimit, ConsoleOutputLimit) as exc:
            self._last_results.append(failed_result(exc))
            self._record_failure(stage, type(exc).__name__, exc)
            self._fail()
            raise ConsoleTimeout("console output bound exceeded") from exc
        except Exception as exc:
            self._last_results.append(failed_result(exc))
            self._record_failure(stage, type(exc).__name__, exc)
            self._fail()
            if isinstance(exc, SessionError):
                raise
            raise SessionError("console operation failed") from exc

    def _drain_pending_whitespace(self, deadline: float) -> bool:
        """Drain pending bytes only when they are terminal whitespace."""
        pending_fn = getattr(self._transport, "pending_data", None)
        while callable(pending_fn) and pending_fn():
            self._check_discovery_budget()
            if self._lab_gate is not None:
                self._lab_gate.check_active()
            remaining = min(deadline - time.monotonic(), 0.1)
            if remaining <= 0:
                self._check_discovery_budget()
                return False
            chunk = self._transport.read_chunk(max(0.001, remaining))
            if not chunk:
                break
            if chunk.strip():
                return False
        return True

    def _read_deadline(self, *, timeout: float | None = None) -> float:
        prompt_deadline = time.monotonic() + (
            self._timeout if timeout is None else timeout
        )
        deadlines = [prompt_deadline]
        if self._discovery_deadline is not None:
            deadlines.append(self._discovery_deadline)
        if self._lab_gate is not None:
            remaining = self._lab_gate.remaining_seconds()
            if remaining is not None:
                deadlines.append(time.monotonic() + max(0.0, remaining))
        return min(deadlines)

    def _read_for_prompt(
        self,
        *,
        allow_pagination: bool = False,
        timeout: float | None = None,
    ) -> _PromptRead:
        deadline = self._read_deadline(timeout=timeout)
        self._last_prompt_read_saw_data = False
        output = ""
        candidate: _PromptRead | None = None
        while time.monotonic() < deadline:
            self._check_discovery_budget()
            pending_fn = getattr(self._transport, "pending_data", None)
            pending = bool(pending_fn()) if callable(pending_fn) else False
            if candidate is not None and not pending:
                policy_ready = (
                    self._completion_policy is None
                    or self._completion_policy.candidate_ready()
                )
                if policy_ready:
                    if self._parser.has_unconsumed_non_whitespace:
                        raise AmbiguousConsoleOutput(
                            "terminal output remained after candidate prompt",
                        )
                    extra = output[len(candidate.output):].strip()
                    if extra:
                        self._parser.mark_prompt_collision()
                        raise AmbiguousConsoleOutput(
                            "prompt-like text occurred in command output",
                        )
                    return candidate
            read_limit = max(0.001, deadline - time.monotonic())
            if self._lab_gate is not None:
                # Poll cancellation/expiry without ever using the full command
                # deadline for one blocking pySerial read.
                read_limit = min(read_limit, 0.1)
                if candidate is not None and self._completion_policy is not None:
                    read_limit = min(
                        read_limit,
                        max(0.001, self._completion_policy.next_check_seconds()),
                    )
            chunk = self._transport.read_chunk(read_limit)
            if not chunk:
                continue
            self._last_prompt_read_saw_data = True
            if self._completion_policy is not None:
                self._completion_policy.observe_chunk(chunk)
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
                    if not self._drain_pending_whitespace(deadline):
                        raise AmbiguousConsoleOutput(
                            "pagination marker occurred with pending terminal data",
                        )
                    self._send(
                        " ",
                        ConsoleSendOperation.PAGINATION,
                        query=self._active_query,
                    )
                elif event.kind is ParserEventKind.PROMPT:
                    self._last_prompt_read_saw_data = True
                    if candidate is not None and output[len(candidate.output):].strip():
                        self._parser.mark_prompt_collision()
                    candidate = _PromptRead(
                        output, event.mode, None, event.prompt,
                    )
                    if self._completion_policy is not None:
                        self._completion_policy.candidate_seen()
                elif event.kind is ParserEventKind.UNSAFE_STATE:
                    raise UnsafeConsoleState(event.reason or "unsafe console state")
            if candidate is not None and self._parser.prompt_collision:
                raise AmbiguousConsoleOutput(
                    "prompt-like text occurred in command output",
                )
        # A blocking read can consume the last slice of the deadline.  Check a
        # candidate that became ready during that read before declaring timeout.
        if candidate is not None and (
            self._completion_policy is None
            or self._completion_policy.candidate_ready()
        ):
            self._check_discovery_budget()
            if self._lab_gate is not None:
                self._lab_gate.check_active()
            pending_fn = getattr(self._transport, "pending_data", None)
            pending = bool(pending_fn()) if callable(pending_fn) else False
            if pending:
                # Bluetooth may deliver the terminal CR/LF/space after the
                # prompt candidate.  Consume only bounded terminal whitespace;
                # non-whitespace still fails closed.
                self._drain_pending_whitespace(deadline)
                pending = bool(pending_fn()) if callable(pending_fn) else False
            if not pending and not self._parser.has_unconsumed_non_whitespace:
                return candidate
        self._check_discovery_budget()
        if self._lab_gate is not None:
            self._lab_gate.check_active()
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

    def _fail(self, *, preserve_primary: bool = False) -> None:
        cleanup_error: Exception | None = None
        self._state = SessionState.FAILED
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
            self._cleanup_error = {
                "stage": "cleanup",
                "code": "cleanup-failed",
                "exception_type": type(cleanup_error).__name__,
            }
            if not preserve_primary:
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
    "ConsoleOperatorAbort",
    "ConsoleSendOperation",
    "ConsoleSession",
    "ConsoleTimeout",
    "CredentialInputError",
    "DeviceCommandError",
    "DiscoveryCancelled",
    "DiscoveryTimeout",
    "EnableError",
    "LabSessionGate",
    "LiveDeviceDisabled",
    "MAX_AUTH_INPUT_LENGTH",
    "PromptCompletionPolicy",
    "SessionCleanupError",
    "SessionClosed",
    "SessionError",
    "SessionState",
    "SessionStateError",
    "UnsafeConsoleState",
    "validate_console_input",
]
