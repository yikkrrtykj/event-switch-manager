"""Application-level console leases.

This is intentionally only an in-process exclusive lease.  It is not proof that
the Windows serial driver or another process cannot open the COM port.  The
OS-level exclusivity status remains NOT_VERIFIED until a real isolated serial
or virtual-port experiment is performed.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from uuid import UUID, uuid4

OS_EXCLUSIVITY_STATUS = "NOT_VERIFIED"


class LeaseConflict(RuntimeError):
    """Another owner already holds the application-level lease."""


@dataclass(slots=True)
class ConsoleLease:
    manager: ConsoleLeaseManager
    port_identity: str
    owner: str
    token: UUID = field(default_factory=uuid4)
    _released: bool = field(default=False, init=False)

    @property
    def released(self) -> bool:
        return self._released

    def release(self) -> None:
        if self._released:
            return
        self.manager._release(self.port_identity, self.token)
        self._released = True

    def __enter__(self) -> ConsoleLease:
        return self

    def __exit__(self, *_: object) -> None:
        self.release()


class ConsoleLeaseManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owners: dict[str, tuple[str, UUID]] = {}

    def acquire(self, port_identity: str, owner: str) -> ConsoleLease:
        if not port_identity or not owner:
            raise ValueError("port_identity and owner are required")
        with self._lock:
            current = self._owners.get(port_identity)
            if current is not None:
                raise LeaseConflict(
                    f"console lease already held for {port_identity} by {current[0]}",
                )
            lease = ConsoleLease(self, port_identity, owner)
            self._owners[port_identity] = (owner, lease.token)
            return lease

    def _release(self, port_identity: str, token: UUID) -> None:
        with self._lock:
            current = self._owners.get(port_identity)
            if current is not None and current[1] == token:
                del self._owners[port_identity]

    def active_owner(self, port_identity: str) -> str | None:
        with self._lock:
            current = self._owners.get(port_identity)
            return current[0] if current else None

    def reset(self) -> None:
        """Test-only reset; never called by the product runtime."""
        with self._lock:
            self._owners.clear()


__all__ = [
    "OS_EXCLUSIVITY_STATUS",
    "ConsoleLease",
    "ConsoleLeaseManager",
    "LeaseConflict",
]
