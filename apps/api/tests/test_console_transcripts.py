from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from event_switch_manager.cisco_catalog import (
    PROFILES,
    R84_CONSOLE_ONLY_PIDS,
)
from event_switch_manager.console.allowlist import (
    QueryNotSupported,
    resolve_profile,
    resolve_query_for_profile,
)
from event_switch_manager.console.models import (
    ConsoleEvidence,
    ConsoleSource,
    ObservationCompleteness,
)
from event_switch_manager.console.observation import CiscoObservationAdapter
from event_switch_manager.console.session import ConsoleCredentials, ConsoleSession
from event_switch_manager.console.simulator import SimulatedConsoleTransport, SimulatorProfile
from event_switch_manager.domain import DeviceFamily
from event_switch_manager.integrations import ConsoleQuery

FIXTURES = Path(__file__).parent / "fixtures" / "console"
CREDS = ConsoleCredentials("console", "synthetic-password", "synthetic-enable")


def _load(name: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((FIXTURES / name).read_text(encoding="utf-8")),
    )


def _profile(data: dict[str, Any]) -> SimulatorProfile:
    raw = data["profile"]
    family = DeviceFamily(raw["family"])
    return SimulatorProfile(
        family=family,
        hostname=raw["hostname"],
        model=raw["model"],
        serial_number=raw["serial_number"],
        software_version=raw["software_version"],
        license_declared="LAN Base" if family is DeviceFamily.CATALYST_2960X else None,
        license_observed=None,
        license_status=None,
        license_next_boot=None,
        interfaces=(),
        stack=(),
        boot_state=None,
        storage=(),
        source=ConsoleSource.RECORDED_FIXTURE,
        fixture_id=data["fixture_id"],
    )


def _responses(data: dict[str, Any]) -> dict[ConsoleQuery, str]:
    return {
        ConsoleQuery(key.casefold()): value
        for key, value in data["responses"].items()
    }


def _session(data: dict[str, Any], *, chunk_size: int = 17) -> ConsoleSession:
    transport = SimulatedConsoleTransport(
        profile=_profile(data),
        responses=_responses(data),
        chunk_size=chunk_size,
        pagination=True,
    )
    return ConsoleSession(transport, timeout=2.0)


def _observe(data: dict[str, Any], *, chunk_size: int = 17) -> ConsoleEvidence:
    session = _session(data, chunk_size=chunk_size)
    session.open(CREDS)
    try:
        return CiscoObservationAdapter().observe(session)
    finally:
        session.close()


def test_2960x_recorded_fixture_stack_identity_and_module_association() -> None:
    evidence = _observe(_load("r84_2960x_stack.json"))
    observation = evidence.observation
    assert evidence.source is ConsoleSource.RECORDED_FIXTURE
    assert evidence.fixture_id == "r84-2960x-24ts-l-e10-stack2"
    assert observation.family is DeviceFamily.CATALYST_2960X
    assert observation.exact_pid == "WS-C2960X-24TS-L"
    assert observation.software_version == "15.2(7)E10"
    assert observation.completeness is ObservationCompleteness.COMPLETE
    assert len(observation.inventory) == 2
    assert [item.member for item in observation.inventory] == [1, 2]
    assert observation.inventory[0].pid == "WS-C2960X-24TS-L"
    assert observation.inventory[0].serial_number == "R84STACK01"
    assert observation.inventory[1].serial_number == "R84STACK02"
    assert observation.inventory[0].module_pid == "C2960X-STACK"
    assert observation.inventory[0].module_serial == "R84MOD01"
    assert observation.inventory[1].module_serial == "R84MOD02"
    assert len(observation.stack) == 2
    first, second = observation.stack
    assert (first.number, first.role, first.priority, first.hardware_version) == (
        1, "Master", 15, "V04",
    )
    assert (second.number, second.role, second.priority, second.hardware_version) == (
        2, "Member", 11, "V04",
    )
    assert first.serial_number == "R84STACK01"
    assert second.serial_number == "R84STACK02"
    assert first.serial_number != second.serial_number
    assert first.module_serial != second.module_serial
    assert first.exact_pid != "C2960X-STACK"
    assert first.state == "Ready"
    assert first.mac == "0011.2233.4401"
    assert second.mac == "0011.2233.4402"
    assert first.hardware_version == "V04"
    assert observation.software_version == "15.2(7)E10"


def test_2960x_recorded_fixture_parses_license_boot_storage_and_interfaces() -> None:
    observation = _observe(_load("r84_2960x_stack.json")).observation
    assert [feature.feature for feature in observation.license.features] == [
        "LAN Lite", "LAN Base",
    ]
    assert observation.license.active_features == ("LAN Base",)
    assert observation.license.observed == "LAN Base"
    assert observation.license.declared == "LAN Base"
    assert observation.license.ambiguous is False
    assert observation.license.features[1].life_time == "Life time"
    assert len(observation.boot_entries) == 2
    assert [entry.member for entry in observation.boot_entries] == [1, 2]
    assert observation.boot_state == "flash:/c2960x-universalk9-mz.152-7.E10.bin"
    assert observation.storage_entries
    flash_entry = next(
        entry for entry in observation.storage_entries
        if entry.file_type == "flash"
    )
    assert flash_entry.prefixes == ("flash:", "flash1:")
    flash2 = next(
        entry for entry in observation.storage_entries
        if entry.prefixes == ("flash2:",)
    )
    assert flash2.total_bytes == 100000000
    assert observation.storage == ("flash:", "nvram:", "system:", "flash2:")
    physical = [item for item in observation.interfaces if item.physical]
    copper = [item for item in physical if item.medium == "copper"]
    assert len(physical) == 56
    assert len(copper) == 48
    assert len([item for item in physical if not item.present]) == 8
    assert all(item.name.startswith(("Gi1/", "Gi2/")) for item in physical)


def test_c1000_16t_recorded_fixture_exact_profile_and_physical_logical_split() -> None:
    evidence = _observe(_load("r84_c1000_16t.json"))
    observation = evidence.observation
    assert observation.family is DeviceFamily.CATALYST_C1000
    assert observation.exact_pid == "C1000-16T-2G-L"
    assert observation.software_version == "15.2(7)E2"
    assert observation.stack == ()
    assert observation.inventory[0].pid == "C1000-16T-2G-L"
    physical = [item for item in observation.interfaces if item.physical]
    logical = [item for item in observation.interfaces if not item.physical]
    assert len(physical) == 18
    assert len([item for item in physical if item.present]) == 16
    assert [item.name for item in logical] == ["Po1"]
    assert observation.license.features == ()
    assert ConsoleQuery.LICENSE in evidence.unsupported_queries
    assert evidence.query_results and all(
        item.query is not ConsoleQuery.LICENSE for item in evidence.query_results
    )
    assert "version-model-missing" in observation.unknown_fields
    assert observation.completeness is ObservationCompleteness.PARTIAL


def test_c1000_16t_profile_has_exact_16_plus_2_layout_and_no_native_stack() -> None:
    profile = PROFILES["C1000-16T-2G-L"]
    assert len(profile.ports) == 2
    copper, sfp = profile.ports
    assert (copper.medium.value, copper.first, copper.count) == ("copper-rj45", 1, 16)
    assert (sfp.medium.value, sfp.first, sfp.count) == ("sfp", 17, 2)
    assert profile.stack_limit is None
    assert "C1000-16T-2G-L" in R84_CONSOLE_ONLY_PIDS
    console = resolve_profile("C1000-16T-2G-L", "15.2(7)E2")
    with pytest.raises(QueryNotSupported):
        resolve_query_for_profile(console, ConsoleQuery.LICENSE)
    with pytest.raises(QueryNotSupported):
        resolve_query_for_profile(console, ConsoleQuery.STACK)


def test_c1000_incomplete_license_is_not_interpreted_as_supported() -> None:
    data = _load("r84_c1000_16t.json")
    from event_switch_manager.console.observation import _license_info

    info = _license_info(data["responses"]["VERSION"], data["responses"]["LICENSE"])
    assert info.features == ()
    assert info.active_features == ()
    assert info.observed is None


def test_truncated_inventory_first_character_does_not_invent_identity() -> None:
    data = _load("r84_2960x_stack.json")
    data = json.loads(json.dumps(data))
    data["responses"]["INVENTORY"] = data["responses"]["INVENTORY"].replace(
        'NAME: "1"', 'AME: "1"', 1,
    ).replace('NAME: "2"', 'AME: "2"', 1)
    observation = _observe(data).observation
    assert observation.inventory == ()
    assert "inventory-chassis-missing" in observation.unknown_fields
    # The complete version model is still real evidence, but no member/module
    # identity or serial is fabricated from the damaged inventory line.
    assert observation.exact_pid == "WS-C2960X-24TS-L"
    assert all(member.serial_number is None for member in observation.stack)
    assert "stack-member-not-ready" not in observation.unknown_fields


def test_non_ready_stack_member_is_partial_but_preserved() -> None:
    data = _load("r84_2960x_stack.json")
    data = json.loads(json.dumps(data))
    data["responses"]["STACK"] = data["responses"]["STACK"].replace(
        "11       V04       Ready", "11       V04       Provisioning",
    )
    observation = _observe(data).observation
    assert [item.state for item in observation.stack] == ["Ready", "Provisioning"]
    assert "stack-member-not-ready" in observation.unknown_fields
    assert observation.completeness is ObservationCompleteness.PARTIAL


def test_duplicate_table_headers_are_ignored() -> None:
    data = _load("r84_2960x_stack.json")
    data = json.loads(json.dumps(data))
    data["responses"]["INTERFACES"] = (
        "Port      Name               Status       Vlan       Duplex  Speed Type\n"
        + data["responses"]["INTERFACES"]
    )
    observation = _observe(data).observation
    assert len([item for item in observation.interfaces if item.physical]) == 56


def test_boot_path_list_and_member_fields_are_preserved() -> None:
    from event_switch_manager.console.observation import _boot_info

    entries = _boot_info(
        "Switch 1\n"
        "BOOT variable = flash:first.bin;flash:second.bin;\n"
        "CONFIG_FILE variable = flash:config.text\n"
        "PRIVATE_CONFIG_FILE variable = flash:private.text\n"
        "Manual Boot = no\n"
        "Enable Break = no\n",
    )
    assert len(entries) == 1
    assert entries[0].member == 1
    assert entries[0].boot_variable == "flash:first.bin;flash:second.bin"
    assert entries[0].config_file == "flash:config.text"
    assert entries[0].private_config_file == "flash:private.text"
    assert entries[0].manual_boot == "no"
    assert entries[0].enable_break == "no"


def test_recorded_transport_is_never_live_or_hardware_verified() -> None:
    evidence = _observe(_load("r84_2960x_stack.json"))
    assert evidence.source is ConsoleSource.RECORDED_FIXTURE
    assert evidence.hardware_verified is False
    assert evidence.deployment_approved is False
    # A recorded transcript is a fixture, never a live session substitution.
    assert evidence.observation.hardware_verified is False
