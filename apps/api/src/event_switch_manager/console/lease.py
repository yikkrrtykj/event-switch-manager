"""Application-level console leases.

This is intentionally only an in-process exclusive lease.  It is not proof that
the Windows serial driver or another process cannot open the COM port.  The
OS-level exclusivity status remains NOT_VERIFIED until a real isolated serial
or virtual-port experiment is performed.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from uuid import UUID, uuid4

OS_EXCLUSIVITY_STATUS = "NOT_VERIFIED"

_COM_NAME = re.compile(r"^(?:\\\\\.\\)?com(\d+)$", re.IGNORECASE)
_POSIX_TTY = re.compile(r"^/dev/tty[a-z0-9._-]+$", re.IGNORECASE)


def normalize_endpoint(value: str) -> str:
    """Canonicalize a COM/transport endpoint for application-level aliasing."""
    if not value or not value.strip():
        raise ValueError("console endpoint is required")
    text = value.strip()
    com = _COM_NAME.fullmatch(text)
    if com is not None:
        return f"com{com.group(1)}"
    if _POSIX_TTY.fullmatch(text):
        return text.casefold()
    return text.casefold()


class LeaseConflict(RuntimeError):
    """Another owner already holds the application-level lease."""


class LeaseCleanupError(RuntimeError):
    """A lease could not be released cleanly."""


@dataclass(slots=True)
class ConsoleLease:
    manager: ConsoleLeaseManager
    port_identity: str
    owner: str
    aliases: frozenset[str]
    token: UUID = field(default_factory=uuid4)
    _released: bool = field(default=False, init=False)

    @property
    def released(self) -> bool:
        return self._released

    def release(self) -> None:
        if self._released:
            return
        self.manager._release(self.token)
        self._released = True


@dataclass(slots=True)
class _LeaseRecord:
    owner: str
    token: UUID
    aliases: frozenset[str]


class ConsoleLeaseManager:
    """Thread-safe process-local lease keyed by physical identity and endpoint."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[UUID, _LeaseRecord] = {}
        self._aliases: dict[str, UUID] = {}

    def acquire(
        self,
        port_identity: str,
        owner: str,
        *,
        endpoint: str | None = None,
    ) -> ConsoleLease:
        if not port_identity or not owner:
            raise ValueError("port_identity and owner are required")
        aliases = frozenset({
            normalize_endpoint(port_identity),
            *(
                (normalize_endpoint(endpoint),)
                if endpoint is not None
                else ()
            ),
        })
        with self._lock:
            for alias in aliases:
                token = self._aliases.get(alias)
                if token is not None:
                    record = self._records.get(token)
                    if record is not None:
                        raise LeaseConflict(
                            f"console lease already held for {alias} by {record.owner}",
                        )
                    # Defensive cleanup if an alias map entry is orphaned.
                    self._aliases.pop(alias, None)
            token = uuid4()
            self._records[token] = _LeaseRecord(owner, token, aliases)
            for alias in aliases:
                self._aliases[alias] = token
            return ConsoleLease(self, port_identity, owner, aliases, token)

    def _release(self, token: UUID) -> None:
        with self._lock:
            record = self._records.pop(token, None)
            if record is None:
                return
            for alias in record.aliases:
                if self._aliases.get(alias) == token:
                    del self._aliases[alias]

    def active_owner(self, endpoint: str) -> str | None:
        with self._lock:
            token = self._aliases.get(normalize_endpoint(endpoint))
            if token is None:
                return None
            record = self._records.get(token)
            return record.owner if record else None

    def active_aliases(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._aliases))

    def reset_for_tests(self) -> None:
        """Test-only reset; never called by the product runtime."""
        with self._lock:
            self._records.clear()
            self._aliases.clear()


_DEFAULT_LEASE_MANAGER = ConsoleLeaseManager()
DEFAULT_LEASE_MANAGER = _DEFAULT_LEASE_MANAGER


def default_lease_manager() -> ConsoleLeaseManager:
    """Shared process-local manager used by production and tests."""
    return _DEFAULT_LEASE_MANAGER


__all__ = [
    "DEFAULT_LEASE_MANAGER",
    "OS_EXCLUSIVITY_STATUS",
    "ConsoleLease",
    "ConsoleLeaseManager",
    "LeaseCleanupError",
    "LeaseConflict",
    "default_lease_manager",
    "normalize_endpoint",
]
