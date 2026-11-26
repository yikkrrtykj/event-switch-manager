"""Typed read-only command allowlist for CON-01.

Only commands in this table can reach the session.  There is no string command
entry point, reflection fallback or automatic alternative command.
"""

from __future__ import annotations

from dataclasses import dataclass

from event_switch_manager.cisco_catalog import (
    G2960,
    G3850,
    G9200,
    G9300,
    GUIDE_SCOPES,
    I1000,
    I2960,
    I3850,
    I9200,
    I9300,
    PROFILES,
    RELEASES,
)
from event_switch_manager.domain import DeviceFamily
from event_switch_manager.integrations import ConsoleQuery

BOOTSTRAP_QUERIES: tuple[ConsoleQuery, ...] = (
    ConsoleQuery.VERSION,
    ConsoleQuery.INVENTORY,
)

COMMON_QUERIES: tuple[ConsoleQuery, ...] = (
    ConsoleQuery.VERSION,
    ConsoleQuery.INVENTORY,
    ConsoleQuery.INTERFACES,
)
IOS_XE_QUERIES: tuple[ConsoleQuery, ...] = (
    ConsoleQuery.LICENSE,
    ConsoleQuery.BOOT,
    ConsoleQuery.STORAGE,
)
STACK_FAMILIES = frozenset({
    DeviceFamily.CATALYST_2960X,
    DeviceFamily.CATALYST_3850,
    DeviceFamily.CATALYST_9200,
    DeviceFamily.CATALYST_9300,
})
IOS_XE_FAMILIES = frozenset({
    DeviceFamily.CATALYST_3850,
    DeviceFamily.CATALYST_9200,
    DeviceFamily.CATALYST_9300,
})

# R84 exact console review adds these releases even though the production
# release/capability inventories remain frozen at their R83 scopes.
CONSOLE_RELEASE_EXTRAS: dict[str, tuple[str, ...]] = {
    "WS-C2960X-24TS-L": ("15.2(7)E10",),
    "C1000-16T-2G-L": ("15.2(7)E2",),
}
CONSOLE_INTERFACE_RELEASES = {
    DeviceFamily.CATALYST_2960X: ("15.2(7)E", "15.2(7)E7", "15.2(7)E10"),
    DeviceFamily.CATALYST_C1000: ("15.2(7)E1", "15.2(7)E2"),
    DeviceFamily.CATALYST_3850: GUIDE_SCOPES[DeviceFamily.CATALYST_3850].interfaces,
    DeviceFamily.CATALYST_9200: GUIDE_SCOPES[DeviceFamily.CATALYST_9200].interfaces,
    DeviceFamily.CATALYST_9300: GUIDE_SCOPES[DeviceFamily.CATALYST_9300].interfaces,
}
CONSOLE_QUERY_RELEASES = {
    (DeviceFamily.CATALYST_2960X, ConsoleQuery.LICENSE): ("15.2(7)E10",),
    (DeviceFamily.CATALYST_2960X, ConsoleQuery.BOOT): ("15.2(7)E10",),
    (DeviceFamily.CATALYST_2960X, ConsoleQuery.STORAGE): ("15.2(7)E10",),
    (DeviceFamily.CATALYST_C1000, ConsoleQuery.BOOT): ("15.2(7)E2",),
    (DeviceFamily.CATALYST_C1000, ConsoleQuery.STORAGE): ("15.2(7)E2",),
}


class QueryNotAllowed(ValueError):
    """The requested query is not a typed allowlisted query."""


class QueryNotSupported(QueryNotAllowed):
    """The typed query is not documented for this family."""


class FamilyUnknown(QueryNotAllowed):
    """Identity is not established; only bootstrap queries are allowed."""


class ProfileNotVerified(QueryNotAllowed):
    """Exact PID or release is not in the reviewed console profile scope."""


@dataclass(frozen=True, slots=True)
class ConsoleProfile:
    family: DeviceFamily
    exact_pid: str
    release: str


@dataclass(frozen=True, slots=True)
class QuerySpec:
    query: ConsoleQuery
    command: str
    source_url: str
    source_section: str


def _interface_source(family: DeviceFamily) -> str:
    return {
        DeviceFamily.CATALYST_2960X: I2960,
        DeviceFamily.CATALYST_3850: I3850,
        DeviceFamily.CATALYST_9200: I9200,
        DeviceFamily.CATALYST_9300: I9300,
        DeviceFamily.CATALYST_C1000: I1000,
    }[family]


def _stack_source(family: DeviceFamily) -> str:
    scope = GUIDE_SCOPES[family].stacks
    if scope is not None:
        return scope.url
    return {
        DeviceFamily.CATALYST_2960X: G2960 + "m_stck_cg.html",
        DeviceFamily.CATALYST_3850: G3850,
        DeviceFamily.CATALYST_9200: G9200,
        DeviceFamily.CATALYST_9300: G9300,
    }[family]


def _common_specs(family: DeviceFamily) -> dict[ConsoleQuery, QuerySpec]:
    return {
        ConsoleQuery.VERSION: QuerySpec(
            ConsoleQuery.VERSION, "show version", RELEASES[family].source.url,
            "Software Images / release identity",
        ),
        ConsoleQuery.INVENTORY: QuerySpec(
            ConsoleQuery.INVENTORY, "show inventory", RELEASES[family].source.url,
            "Supported hardware / inventory",
        ),
        ConsoleQuery.INTERFACES: QuerySpec(
            ConsoleQuery.INTERFACES, "show interfaces status", _interface_source(family),
            "Interface characteristics",
        ),
    }


def _build_specs() -> dict[DeviceFamily, dict[ConsoleQuery, QuerySpec]]:
    specs: dict[DeviceFamily, dict[ConsoleQuery, QuerySpec]] = {}
    for family in DeviceFamily:
        table = _common_specs(family)
        if family in IOS_XE_FAMILIES or family is DeviceFamily.CATALYST_2960X:
            source = RELEASES[family].source.url
            table.update({
                ConsoleQuery.LICENSE: QuerySpec(
                    ConsoleQuery.LICENSE, "show license", source, "Licensing",
                ),
                ConsoleQuery.BOOT: QuerySpec(
                    ConsoleQuery.BOOT, "show boot", source, "Software boot modes",
                ),
                ConsoleQuery.STORAGE: QuerySpec(
                    ConsoleQuery.STORAGE, "show file systems", source,
                    "File systems and storage",
                ),
            })
        if family is DeviceFamily.CATALYST_C1000:
            source = RELEASES[family].source.url
            table.update({
                ConsoleQuery.BOOT: QuerySpec(
                    ConsoleQuery.BOOT, "show boot", source, "Software boot modes",
                ),
                ConsoleQuery.STORAGE: QuerySpec(
                    ConsoleQuery.STORAGE, "show file systems", source,
                    "File systems and storage",
                ),
            })
        if family in STACK_FAMILIES:
            table[ConsoleQuery.STACK] = QuerySpec(
                ConsoleQuery.STACK, "show switch", _stack_source(family),
                "Switch stack membership",
            )
        specs[family] = table
    return specs


QUERY_SPECS = _build_specs()


_PROFILE_PIDS = {pid.upper(): profile for pid, profile in PROFILES.items()}


def resolve_profile(exact_pid: str, release: str) -> ConsoleProfile:
    """Resolve an exact registered PID and reviewed release, fail closed."""
    if not exact_pid or not release:
        raise ProfileNotVerified("exact PID and release are required")
    canonical_pid = exact_pid.strip().upper()
    profile = _PROFILE_PIDS.get(canonical_pid)
    if profile is None:
        raise ProfileNotVerified("exact PID is not registered")
    inventory = RELEASES[profile.family]
    candidates = tuple(inventory.releases) + CONSOLE_RELEASE_EXTRAS.get(canonical_pid, ())
    wanted = release.strip().casefold()
    canonical = next(
        (version for version in candidates if version.casefold() == wanted),
        None,
    )
    if canonical is None:
        raise ProfileNotVerified("release is not registered for this PID")
    return ConsoleProfile(profile.family, canonical_pid, canonical)


def _release_in_scope(profile: ConsoleProfile, query: ConsoleQuery) -> bool:
    if query in BOOTSTRAP_QUERIES:
        return True
    release = profile.release.casefold()
    if query in {ConsoleQuery.INTERFACES, ConsoleQuery.STACK}:
        if query is ConsoleQuery.STACK:
            if profile.exact_pid not in PROFILES:
                return False
            if not PROFILES[profile.exact_pid].stack_limit:
                return False
        return release in {
            item.casefold()
            for item in CONSOLE_INTERFACE_RELEASES[profile.family]
        }
    exact_releases = CONSOLE_QUERY_RELEASES.get((profile.family, query))
    if exact_releases is not None:
        return release in {item.casefold() for item in exact_releases}
    if profile.family in IOS_XE_FAMILIES and query in {
        ConsoleQuery.LICENSE, ConsoleQuery.BOOT, ConsoleQuery.STORAGE,
    }:
        return release in {
            item.casefold()
            for item in GUIDE_SCOPES[profile.family].interfaces
        }
    return False


def resolve_query_for_profile(
    profile: ConsoleProfile, query: ConsoleQuery,
) -> QuerySpec:
    if not isinstance(query, ConsoleQuery):
        raise QueryNotAllowed("query must be a ConsoleQuery")
    spec = QUERY_SPECS[profile.family].get(query)
    if spec is None:
        raise QueryNotSupported(
            f"query not supported for {profile.family.value}: {query.value}",
        )
    if not _release_in_scope(profile, query):
        raise QueryNotSupported(
            f"query not verified for {profile.exact_pid} {profile.release}: {query.value}",
        )
    return spec


def supported_queries_for_profile(profile: ConsoleProfile) -> tuple[ConsoleQuery, ...]:
    allowed: list[ConsoleQuery] = []
    for query in QUERY_SPECS[profile.family]:
        try:
            resolve_query_for_profile(profile, query)
        except QueryNotAllowed:
            continue
        allowed.append(query)
    return tuple(allowed)


def resolve_query(family: DeviceFamily | None, query: ConsoleQuery) -> QuerySpec:
    if not isinstance(query, ConsoleQuery):
        raise QueryNotAllowed("query must be a ConsoleQuery")
    if family is None:
        if query in BOOTSTRAP_QUERIES:
            family = DeviceFamily.CATALYST_9300
        else:
            raise FamilyUnknown("family is not established")
    spec = QUERY_SPECS[family].get(query)
    if spec is None:
        raise QueryNotSupported(f"query not supported for {family.value}: {query.value}")
    return spec


def supported_queries(family: DeviceFamily | None) -> tuple[ConsoleQuery, ...]:
    if family is None:
        return BOOTSTRAP_QUERIES
    return tuple(QUERY_SPECS[family])


def validate_family(family: DeviceFamily | None) -> None:
    if family is not None and not isinstance(family, DeviceFamily):
        raise QueryNotAllowed("family must be a DeviceFamily")


__all__ = [
    "BOOTSTRAP_QUERIES",
    "COMMON_QUERIES",
    "IOS_XE_QUERIES",
    "QUERY_SPECS",
    "ConsoleProfile",
    "QueryNotAllowed",
    "QueryNotSupported",
    "QuerySpec",
    "FamilyUnknown",
    "ProfileNotVerified",
    "resolve_profile",
    "resolve_query",
    "resolve_query_for_profile",
    "supported_queries",
    "supported_queries_for_profile",
    "validate_family",
]
