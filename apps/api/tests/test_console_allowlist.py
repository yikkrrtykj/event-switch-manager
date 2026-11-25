from __future__ import annotations

import pytest

from event_switch_manager.console.allowlist import (
    BOOTSTRAP_QUERIES,
    QUERY_SPECS,
    FamilyUnknown,
    QueryNotAllowed,
    QueryNotSupported,
    resolve_query,
    supported_queries,
)
from event_switch_manager.domain import DeviceFamily
from event_switch_manager.integrations import ConsoleQuery


def test_all_families_expose_only_typed_queries_and_commands() -> None:
    assert set(QUERY_SPECS) == set(DeviceFamily)
    for family in DeviceFamily:
        commands = [item.command for item in QUERY_SPECS[family].values()]
        assert commands
        assert len(commands) == len(set(commands))
        assert all(
            item.source_url.startswith("https://www.cisco.com/")
            for item in QUERY_SPECS[family].values()
        )


def test_five_family_query_scope_is_conservative() -> None:
    assert supported_queries(None) == BOOTSTRAP_QUERIES
    assert ConsoleQuery.VERSION in supported_queries(DeviceFamily.CATALYST_C1000)
    assert ConsoleQuery.STACK not in supported_queries(DeviceFamily.CATALYST_C1000)
    assert ConsoleQuery.LICENSE not in supported_queries(DeviceFamily.CATALYST_2960X)
    assert ConsoleQuery.LICENSE in supported_queries(DeviceFamily.CATALYST_3850)
    assert ConsoleQuery.LICENSE in supported_queries(DeviceFamily.CATALYST_9200)
    assert ConsoleQuery.LICENSE in supported_queries(DeviceFamily.CATALYST_9300)
    assert ConsoleQuery.BOOT in supported_queries(DeviceFamily.CATALYST_9300)
    assert ConsoleQuery.STORAGE in supported_queries(DeviceFamily.CATALYST_9300)


def test_unknown_family_allows_only_bootstrap() -> None:
    assert resolve_query(None, ConsoleQuery.VERSION).command == "show version"
    with pytest.raises(FamilyUnknown):
        resolve_query(None, ConsoleQuery.LICENSE)


def test_unsupported_query_and_arbitrary_string_are_rejected() -> None:
    with pytest.raises(QueryNotSupported):
        resolve_query(DeviceFamily.CATALYST_C1000, ConsoleQuery.STACK)
    with pytest.raises(QueryNotAllowed):
        resolve_query(DeviceFamily.CATALYST_9300, "show version")  # type: ignore[arg-type]


def test_no_generic_cli_or_write_command_exists() -> None:
    commands = {
        spec.command for specs in QUERY_SPECS.values() for spec in specs.values()
    }
    assert "configure terminal" not in commands
    assert "copy running-config startup-config" not in commands
    assert "write memory" not in commands
    assert "reload" not in commands
    assert all(
        command.startswith("show ") for command in commands
    )
