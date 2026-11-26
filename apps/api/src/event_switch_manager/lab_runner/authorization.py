"""Single-use authorization contract for a controlled live console experiment."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from event_switch_manager.console.allowlist import resolve_query_for_profile
from event_switch_manager.console.discovery import SerialPortInfo
from event_switch_manager.console.lease import normalize_endpoint
from event_switch_manager.console.session import ConsoleSendOperation
from event_switch_manager.integrations import ConsoleQuery

from .targets import LAB_TARGETS, LabTarget

LAB_AUTHORIZATION_TTL_LIMIT_SECONDS = 30 * 60


class LabAuthorizationError(RuntimeError):
    """The lab authorization is missing, expired, mismatched or already used."""


@dataclass(slots=True)
class LabAuthorization:
    experiment_id: str
    target: LabTarget
    com_endpoint: str
    adapter_identity: str
    allowed_queries: tuple[ConsoleQuery, ...]
    issued_at: datetime
    expires_at: datetime
    operator_confirmed: bool
    artifact_sha256: str
    software_git_sha: str
    _consumed: bool = field(default=False, init=False)
    _cancelled: bool = field(default=False, init=False)
    _bound_transport: object | None = field(default=None, init=False)
    _wake_count: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    _IMMUTABLE = frozenset({
        "experiment_id", "target", "com_endpoint", "adapter_identity",
        "allowed_queries", "issued_at", "expires_at", "operator_confirmed",
        "artifact_sha256", "software_git_sha",
    })

    def __setattr__(self, name: str, value: object) -> None:
        if name in self._IMMUTABLE and hasattr(self, name):
            raise AttributeError(f"lab authorization field {name} is immutable")
        object.__setattr__(self, name, value)

    @property
    def consumed(self) -> bool:
        return self._consumed

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @property
    def digest(self) -> str:
        payload = {
            "experiment_id": self.experiment_id,
            "target": self.target.key,
            "expected_pid": self.target.expected_pid,
            "expected_release": self.target.expected_release,
            "com_endpoint": normalize_endpoint(self.com_endpoint),
            "adapter_identity": self.adapter_identity,
            "allowed_queries": [query.value for query in self.allowed_queries],
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "operator_confirmed": self.operator_confirmed,
            "artifact_sha256": self.artifact_sha256,
            "software_git_sha": self.software_git_sha,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _ensure_valid(self) -> None:
        canonical = LAB_TARGETS.get(self.target.key)
        if canonical != self.target or self.allowed_queries != canonical.allowed_queries:
            raise LabAuthorizationError("lab target or query scope is not canonical")
        if not self.operator_confirmed:
            raise LabAuthorizationError("lab authorization requires operator confirmation")
        if self._cancelled:
            raise LabAuthorizationError("lab authorization was cancelled")
        if datetime.now(UTC) >= self.expires_at:
            raise LabAuthorizationError("lab authorization has expired")

    def authorize_open(self, transport: object) -> None:
        """Validate the transport request without consuming the one-shot token."""
        self._ensure_valid()
        if getattr(transport, "authorization", None) is not self:
            raise LabAuthorizationError("transport is not bound to this authorization")
        if getattr(transport, "source", None) is None:
            raise LabAuthorizationError("transport has no source")
        endpoint = str(getattr(transport, "lease_endpoint", ""))
        identity = str(getattr(transport, "port_identity", ""))
        if normalize_endpoint(endpoint) != normalize_endpoint(self.com_endpoint):
            raise LabAuthorizationError("COM endpoint does not match authorization")
        if identity != self.adapter_identity:
            raise LabAuthorizationError("adapter identity does not match authorization")
        if self._consumed:
            raise LabAuthorizationError("lab authorization was already used")

    def check_port(self, port: SerialPortInfo) -> None:
        self._ensure_valid()
        if normalize_endpoint(port.port) != normalize_endpoint(self.com_endpoint):
            raise LabAuthorizationError("enumerated COM endpoint changed")
        if port.adapter_identity != self.adapter_identity:
            raise LabAuthorizationError("enumeration adapter identity changed")
        if port.duplicate_identity or port.identity_quality.value != "stable":
            raise LabAuthorizationError("adapter identity is not unique and stable")

    def consume_for_open(self, port: SerialPortInfo) -> None:
        self.check_port(port)
        with self._lock:
            if self._consumed:
                raise LabAuthorizationError("lab authorization was already used")
            if self._cancelled:
                raise LabAuthorizationError("lab authorization was cancelled")
            if datetime.now(UTC) >= self.expires_at:
                raise LabAuthorizationError("lab authorization has expired")
            self._consumed = True
            self._bound_transport = None

    def bind_transport(self, transport: object) -> None:
        self._bound_transport = transport

    def check_active(self) -> None:
        self._ensure_valid()

    def remaining_seconds(self) -> float | None:
        return max(0.0, (self.expires_at - datetime.now(UTC)).total_seconds())

    def _check_send(
        self,
        operation: ConsoleSendOperation,
        text: str,
        query: ConsoleQuery | None,
        *,
        consume_wake: bool,
    ) -> None:
        self._ensure_valid()
        if not self._consumed:
            raise LabAuthorizationError("live connection was not opened under authorization")
        if len(text.encode("utf-8", errors="replace")) > 512:
            raise LabAuthorizationError("lab send exceeds the authorized bound")
        if operation in {
            ConsoleSendOperation.USERNAME,
            ConsoleSendOperation.PASSWORD,
            ConsoleSendOperation.ENABLE,
            ConsoleSendOperation.ENABLE_PASSWORD,
        }:
            # Credential sends are only legitimate while the session is in an
            # authentication state; the Session itself enforces that state.
            return
        if self._bound_transport is None:
            raise LabAuthorizationError("lab transport is not bound")
        pending = getattr(self._bound_transport, "pending_data", None)
        if callable(pending) and pending():
            raise LabAuthorizationError("late terminal data is pending")
        if getattr(self._bound_transport, "cleanup_required", False):
            raise LabAuthorizationError("serial cleanup is required")
        if operation is ConsoleSendOperation.WAKE:
            if text != "\r" or self._wake_count >= 1:
                raise LabAuthorizationError("only one authorized wake CR is allowed")
            if consume_wake:
                self._wake_count += 1
            return
        if query is None:
            raise LabAuthorizationError("query identity is required for this send")
        if query not in self.allowed_queries:
            raise LabAuthorizationError("query is outside the authorized scope")
        spec = resolve_query_for_profile(self.target.profile, query)
        if operation is ConsoleSendOperation.QUERY:
            if text != spec.command + "\r":
                raise LabAuthorizationError("send text does not match the typed query")
            return
        if operation is ConsoleSendOperation.PAGINATION:
            if text != " ":
                raise LabAuthorizationError("pagination text is not permitted")
            return
        raise LabAuthorizationError("unrecognized lab send operation")

    def authorize_send(
        self,
        operation: ConsoleSendOperation,
        text: str,
        query: ConsoleQuery | None = None,
    ) -> None:
        self._check_send(operation, text, query, consume_wake=True)

    def authorize_query(self, query: ConsoleQuery) -> None:
        self._ensure_valid()
        if not self._consumed:
            raise LabAuthorizationError("live connection was not opened under authorization")
        if query not in self.allowed_queries:
            raise LabAuthorizationError("query is outside the authorized scope")
        transport = self._bound_transport
        pending = getattr(transport, "pending_data", None)
        if callable(pending) and pending():
            # Do not accept a candidate completion while bytes are still
            # arriving.  The operator-assisted runner also checks this.
            raise LabAuthorizationError("late terminal data is pending")
        cleanup = getattr(transport, "cleanup_required", False)
        if cleanup:
            raise LabAuthorizationError("serial cleanup is required")

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True


def issue_authorization(
    target: LabTarget,
    *,
    com_endpoint: str,
    adapter_identity: str,
    ttl_seconds: float = 20 * 60,
    operator_confirmed: bool,
    artifact_sha256: str = "source-run",
    software_git_sha: str = "unknown",
    experiment_id: str | None = None,
) -> LabAuthorization:
    """Create a fresh in-memory authorization; nothing is persisted."""
    if not operator_confirmed:
        raise LabAuthorizationError("operator confirmation is required")
    if not com_endpoint.strip() or not adapter_identity.strip():
        raise LabAuthorizationError("COM endpoint and adapter identity are required")
    if not 0 < ttl_seconds <= LAB_AUTHORIZATION_TTL_LIMIT_SECONDS:
        raise LabAuthorizationError("authorization TTL is outside the allowed range")
    canonical = LAB_TARGETS.get(target.key)
    if canonical is None or canonical != target:
        raise LabAuthorizationError("forged lab target is not accepted")
    if not target.allowed_queries:
        raise LabAuthorizationError("target has no authorized queries")
    now = datetime.now(UTC)
    return LabAuthorization(
        experiment_id=experiment_id or str(uuid4()),
        target=target,
        com_endpoint=com_endpoint.strip(),
        adapter_identity=adapter_identity.strip(),
        allowed_queries=tuple(target.allowed_queries),
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        operator_confirmed=True,
        artifact_sha256=artifact_sha256,
        software_git_sha=software_git_sha,
    )


def wait_for_authorization_expiry(authorization: LabAuthorization) -> None:
    """Test/helper hook; never used by product runtime."""
    remaining = authorization.remaining_seconds()
    if remaining is not None and remaining > 0:
        time.sleep(remaining)


__all__ = [
    "LAB_AUTHORIZATION_TTL_LIMIT_SECONDS",
    "LabAuthorization",
    "LabAuthorizationError",
    "issue_authorization",
]
