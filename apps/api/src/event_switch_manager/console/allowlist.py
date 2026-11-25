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


class QueryNotAllowed(ValueError):
    """The requested query is not a typed allowlisted query."""


class QueryNotSupported(QueryNotAllowed):
    """The typed query is not documented for this family."""


class FamilyUnknown(QueryNotAllowed):
    """Identity is not established; only bootstrap queries are allowed."""


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
        if family in IOS_XE_FAMILIES:
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
        if family in STACK_FAMILIES:
            table[ConsoleQuery.STACK] = QuerySpec(
                ConsoleQuery.STACK, "show switch", _stack_source(family),
                "Switch stack membership",
            )
        specs[family] = table
    return specs


QUERY_SPECS = _build_specs()


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
    "QueryNotAllowed",
    "QueryNotSupported",
    "QuerySpec",
    "FamilyUnknown",
    "resolve_query",
    "supported_queries",
    "validate_family",
]
