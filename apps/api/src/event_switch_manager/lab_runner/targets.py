"""Exact R86 hardware targets and their reviewed read-only query scopes."""

from __future__ import annotations

from dataclasses import dataclass

from event_switch_manager.console.allowlist import (
    ConsoleProfile,
    resolve_profile,
    supported_queries_for_profile,
)
from event_switch_manager.console.models import ConsoleSource
from event_switch_manager.integrations import ConsoleQuery

LAB_SOURCE = ConsoleSource.AUTHORIZED_LIVE_LAB


@dataclass(frozen=True, slots=True)
class LabTarget:
    key: str
    label: str
    expected_pid: str
    expected_release: str
    allowed_queries: tuple[ConsoleQuery, ...]

    @property
    def profile(self) -> ConsoleProfile:
        return resolve_profile(self.expected_pid, self.expected_release)


def _target(
    key: str, label: str, pid: str, release: str,
) -> LabTarget:
    profile = resolve_profile(pid, release)
    queries = supported_queries_for_profile(profile)
    return LabTarget(key, label, pid, release, tuple(queries))


LAB_TARGETS: dict[str, LabTarget] = {
    "2960x": _target(
        "2960x",
        "Cisco Catalyst 2960X-24TS-L, IOS 15.2(7)E10, LAN Base/FlexStack-Plus",
        "WS-C2960X-24TS-L",
        "15.2(7)E10",
    ),
    "c1000": _target(
        "c1000",
        "Cisco Catalyst C1000-16T-2G-L, IOS 15.2(7)E2",
        "C1000-16T-2G-L",
        "15.2(7)E2",
    ),
}


def get_target(key: str) -> LabTarget:
    try:
        return LAB_TARGETS[key.casefold()]
    except KeyError as exc:
        raise ValueError("unknown lab target") from exc


__all__ = ["LAB_SOURCE", "LAB_TARGETS", "LabTarget", "get_target"]
