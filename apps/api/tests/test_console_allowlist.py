from __future__ import annotations

import pytest

from event_switch_manager.console.allowlist import (
    BOOTSTRAP_QUERIES,
    QUERY_SPECS,
    FamilyUnknown,
    ProfileNotVerified,
    QueryNotAllowed,
    QueryNotSupported,
    resolve_profile,
    resolve_query,
    resolve_query_for_profile,
    supported_queries,
    supported_queries_for_profile,
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


def test_exact_profile_resolution_and_release_scope_are_component_based() -> None:
    c9300 = resolve_profile("C9300L-24P-4X", "17.12.4")
    assert c9300.family is DeviceFamily.CATALYST_9300
    assert ConsoleQuery.LICENSE in supported_queries_for_profile(c9300)
    assert resolve_query_for_profile(c9300, ConsoleQuery.LICENSE).command == "show license"

    future_release = resolve_profile("C9300L-24P-4X", "17.12.5")
    assert supported_queries_for_profile(future_release) == BOOTSTRAP_QUERIES
    with pytest.raises(QueryNotSupported):
        resolve_query_for_profile(future_release, ConsoleQuery.LICENSE)

    ios_xe_maintenance = resolve_profile("WS-C3850-24P", "16.12.10a")
    assert supported_queries_for_profile(ios_xe_maintenance) == BOOTSTRAP_QUERIES

    c1000 = resolve_profile("C1000-24P-4G-L", "15.2(7)E1")
    assert ConsoleQuery.STACK not in supported_queries_for_profile(c1000)

    with pytest.raises(ProfileNotVerified):
        resolve_profile("C9300-99T", "17.12.4")
    with pytest.raises(ProfileNotVerified):
        resolve_profile("C9300L-24P-4X", "17.12.99")


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
