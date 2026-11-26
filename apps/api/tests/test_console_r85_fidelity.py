from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from event_switch_manager.console.allowlist import (
    ConsoleProfile,
    ProfileNotVerified,
    QueryNotSupported,
    resolve_profile,
    resolve_query_for_profile,
    supported_queries_for_profile,
    validate_profile,
)
from event_switch_manager.console.models import (
    ConsoleEvidence,
    ConsoleSource,
    ObservationCompleteness,
)
from event_switch_manager.console.observation import (
    CiscoObservationAdapter,
    IdentityConflict,
    _boot_info,
    _license_info,
    _stack,
    _storage_entries,
)
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


def _session(data: dict[str, Any], *, chunk_size: int = 17) -> ConsoleSession:
    raw = data["profile"]
    family = DeviceFamily(raw["family"])
    profile = SimulatorProfile(
        family=family,
        hostname=raw["hostname"],
        model=raw["model"],
        serial_number=raw["serial_number"],
        software_version=raw["software_version"],
        license_declared=None,
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
    responses = {
        ConsoleQuery(key.casefold()): value
        for key, value in data["responses"].items()
    }
    # The manual interface excerpt is partial; keep it as supplied rather than
    # filling the missing stack interfaces.
    return ConsoleSession(
        SimulatedConsoleTransport(
            profile=profile,
            responses=responses,
            chunk_size=chunk_size,
            pagination=True,
        ),
        timeout=2.0,
    )


def _observe(data: dict[str, Any]) -> ConsoleEvidence:
    session = _session(data)
    session.open(CREDS)
    try:
        return CiscoObservationAdapter().observe(session)
    finally:
        session.close()


def test_manual_fixture_provenance_is_explicit() -> None:
    data = _load("r85_2960x_manual.json")
    provenance = data["provenance"]
    assert provenance["kind"] == "MANUAL_TRANSCRIPT_SANITIZED"
    assert provenance["not_single_live_session"] is True
    assert provenance["actual_fields"]
    assert provenance["synthetic_fields"]
    assert provenance["missing_fields"]
    synthetic = _load("r84_2960x_stack.json")
    assert synthetic["provenance"] == "SYNTHETIC_RECONSTRUCTED"


def test_synthetic_complete_contract_is_not_confused_with_manual_evidence() -> None:
    evidence = _observe(_load("r84_2960x_stack.json"))
    assert evidence.observation.completeness is ObservationCompleteness.COMPLETE
    assert evidence.source is ConsoleSource.RECORDED_FIXTURE
    assert _load("r84_2960x_stack.json")["provenance"] == "SYNTHETIC_RECONSTRUCTED"
    assert _load("r85_2960x_manual.json")["provenance"]["kind"] == (
        "MANUAL_TRANSCRIPT_SANITIZED"
    )


def test_manual_2960x_keeps_truncation_and_is_partial_not_complete() -> None:
    evidence = _observe(_load("r85_2960x_manual.json"))
    observation = evidence.observation
    assert observation.exact_pid == "WS-C2960X-24TS-L"
    assert observation.software_version == "15.2(7)E10"
    assert observation.serial_number == "R84STACK01"
    assert "version-model-missing" in observation.unknown_fields
    assert len(observation.interfaces) == 11
    # 11 observed rows must not become a fabricated 56-port complete layout.
    assert len([item for item in observation.interfaces if item.physical]) == 11
    assert "interfaces-partial" in observation.unknown_fields
    assert observation.completeness is ObservationCompleteness.PARTIAL


def test_manual_2960x_boot_keeps_unlabelled_first_section_and_sparse_member2() -> None:
    observation = _observe(_load("r85_2960x_manual.json")).observation
    assert [entry.member for entry in observation.boot_entries] == [None, 2]
    first, second = observation.boot_entries
    assert first.boot_path_list == "flash:c2960x-universalk9-mz.152-7.E10.bin"
    assert first.config_file == "flash:/config.text"
    assert first.private_config_file == "flash:/private-config.text"
    assert first.enable_break == "yes"
    assert first.manual_boot == "no"
    assert second.boot_path_list == "flash:c2960x-universalk9-mz.152-7.E10.bin"
    assert second.config_file == "flash:/config.text"
    assert second.private_config_file == "flash:/private-config.text"
    # The real second section did not provide these fields.
    assert second.manual_boot is None
    assert second.enable_break is None


def test_manual_2960x_license_period_and_missing_lanlite_fields() -> None:
    observation = _observe(_load("r85_2960x_manual.json")).observation
    lanlite, lanbase = observation.license.features
    assert lanlite.feature == "LAN Lite"
    assert lanlite.license_type is None
    assert lanlite.status is None
    assert lanlite.period_left == "0  minute  0  second"
    assert lanbase.feature == "LAN Base"
    assert lanbase.license_type == "Permanent"
    assert lanbase.status == "Active, In Use"
    assert lanbase.period_left == "Life time"
    assert observation.license.active_features == ("LAN Base",)
    assert observation.license.observed == "LAN Base"
    assert observation.license.next_boot is None
    assert observation.license.active_verified is False


def test_manual_2960x_storage_has_two_flash_filesystems_and_aliases() -> None:
    observation = _observe(_load("r85_2960x_manual.json")).observation
    flash = [entry for entry in observation.storage_entries if entry.file_type == "flash"]
    assert len(flash) == 2
    first, second = flash
    assert first.total_bytes == 122185728
    assert first.free_bytes == 63155712
    assert first.prefixes == ("flash:", "flash1:")
    assert second.total_bytes == 122185728
    assert second.free_bytes == 53388800
    assert second.prefixes == ("flash2:",)
    nvram = next(entry for entry in observation.storage_entries if entry.prefixes == ("nvram:",))
    assert nvram.file_type == "nvram"
    assert nvram.flags == "rw"
    opaque = [entry for entry in observation.storage_entries if entry.file_type == "opaque"]
    assert opaque
    assert all(entry.total_bytes is None and entry.free_bytes is None for entry in opaque)
    network = [entry for entry in observation.storage_entries if entry.file_type == "network"]
    assert network
    syslog = next(
        entry for entry in observation.storage_entries
        if entry.prefixes == ("syslog:",)
    )
    assert syslog.flags == "wo"
    assert observation.storage.count("flash:") == 1
    assert "flash2:" in observation.storage


def test_manual_2960x_stack_and_inventory_cross_binding() -> None:
    observation = _observe(_load("r85_2960x_manual.json")).observation
    assert observation.serial_number == "R84STACK01"
    assert len(observation.inventory) == 2
    first, second = observation.stack
    assert (first.number, first.role, first.priority, first.hardware_version) == (
        1, "Master", 15, "4",
    )
    assert first.master_star is True
    assert second.master_star is False
    assert first.serial_number == "R84STACK01"
    assert second.serial_number == "R84STACK02"
    assert first.exact_pid == "WS-C2960X-24TS-L"
    assert first.module_pid == "C2960X-STACK"
    assert first.module_serial == "R84MOD01"
    assert second.module_serial == "R84MOD02"
    assert first.software_version is None
    assert observation.software_version == "15.2(7)E10"


def test_manual_c1000_license_incomplete_is_unsupported_not_absence() -> None:
    evidence = _observe(_load("r85_c1000_manual.json"))
    observation = evidence.observation
    assert observation.exact_pid == "C1000-16T-2G-L"
    assert observation.software_version == "15.2(7)E2"
    assert observation.license.features == ()
    assert observation.license.observed is None
    assert ConsoleQuery.LICENSE in evidence.unsupported_queries
    assert not any(item.query is ConsoleQuery.LICENSE for item in evidence.query_results)
    assert observation.completeness is ObservationCompleteness.PARTIAL


def test_manual_c1000_physical_layout_and_logical_port_channel() -> None:
    observation = _observe(_load("r85_c1000_manual.json")).observation
    physical = [item for item in observation.interfaces if item.physical]
    logical = [item for item in observation.interfaces if not item.physical]
    assert len(physical) == 18
    assert len([item for item in physical if item.present]) == 16
    assert [item.name for item in logical] == ["Po1"]
    assert logical[0].status == "notconnect"
    assert "version-model-missing" in observation.unknown_fields


def test_ancillary_boot_fields_without_boot_path_are_not_complete() -> None:
    data = _load("r85_c1000_manual.json")
    data = json.loads(json.dumps(data))
    data["responses"]["BOOT"] = (
        "Config file         : flash:/config.text\n"
        "Private Config file : flash:/private-config.text\n"
        "Manual Boot         : no\n"
        "Enable Break        : yes\n"
    )
    observation = _observe(data).observation
    assert observation.boot_entries
    assert observation.boot_state is None
    assert "boot" in observation.unknown_fields
    assert observation.completeness is ObservationCompleteness.PARTIAL


def test_manual_c1000_boot_and_storage_key_rows() -> None:
    observation = _observe(_load("r85_c1000_manual.json")).observation
    assert len(observation.boot_entries) == 1
    boot = observation.boot_entries[0]
    assert boot.member is None
    assert boot.boot_path_list == (
        "flash:/c1000-universalk9-mz.152-7.E2/"
        "c1000-universalk9-mz.152-7.E2.bin"
    )
    flash = next(
        entry for entry in observation.storage_entries
        if entry.prefixes == ("flash:", "flash1:")
    )
    assert flash.total_bytes == 244711424
    assert flash.free_bytes == 206448640
    nvram = next(
        entry for entry in observation.storage_entries
        if entry.prefixes == ("nvram:",)
    )
    assert nvram.total_bytes == 524288
    assert nvram.free_bytes == 511901


def test_inventory_rejects_duplicate_serial_and_duplicate_module() -> None:
    from event_switch_manager.console.observation import _inventory_members

    manual = _load("r85_2960x_manual.json")["responses"]["INVENTORY"]
    duplicate_serial = manual.replace("SN: R84STACK02", "SN: R84STACK01")
    with pytest.raises(IdentityConflict):
        _inventory_members(duplicate_serial)
    duplicate_module = manual + (
        'NAME: "Switch 1 - FlexStackPlus Module", DESCR: "duplicate module"\n'
        "PID: C2960X-STACK, VID: V02, SN: R84MOD01\n"
    )
    with pytest.raises(IdentityConflict):
        _inventory_members(duplicate_module)


def test_stack_member_set_must_match_inventory_even_with_same_count() -> None:
    from event_switch_manager.console.observation import _inventory_members

    inventory = _load("r85_2960x_manual.json")["responses"]["INVENTORY"]
    members = _inventory_members(inventory)
    stack = (
        "Switch#  Role   Mac Address     Priority Version  State\n"
        "*1       Master 0011.2233.4401     15     4       Ready\n"
        " 3       Member 0011.2233.4402     11     4       Ready\n"
    )
    with pytest.raises(IdentityConflict):
        _stack(stack, members)


def test_boot_parser_supports_path_list_and_legacy_variable() -> None:
    real = _boot_info(
        "BOOT path-list      : flash:first.bin;flash:second.bin\n"
        "Config file         : flash:/config.text\n"
        "Private Config file : flash:/private-config.text\n"
        "Enable Break        : yes\n"
        "Manual Boot         : no\n"
        "Switch 2\n"
        "BOOT path-list      : flash:member2.bin\n",
    )
    assert real[0].member is None
    assert real[0].boot_path_list == "flash:first.bin;flash:second.bin"
    assert real[1].member == 2
    assert real[1].manual_boot is None
    legacy = _boot_info("BOOT variable = flash:legacy.bin;\n")
    assert legacy[0].boot_variable == "flash:legacy.bin"
    assert legacy[0].boot_path_list == "flash:legacy.bin"


def test_license_status_semantics_are_exact() -> None:
    def status(text: str | None) -> bool:
        output = _license_info(
            "License Level: LAN Base\n",
            "Index 1 Feature: lanbase\n"
            + ("" if text is None else f"        License State: {text}\n"),
        )
        return bool(output.active_features)

    assert status("Active, In Use") is True
    assert status("Active, Not In Use") is False
    assert status("Inactive") is False
    assert status("Not In Use") is False
    assert status("In Use") is True
    assert status(None) is False


def test_multiple_active_features_and_declared_conflict() -> None:
    info = _license_info(
        "License Level: IP Base\n",
        "Index 1 Feature: lanbase\n"
        "        License State: Active, In Use\n"
        "Index 2 Feature: dna-essentials\n"
        "        License State: Active, In Use\n",
    )
    assert info.active_features == ("LAN Base", "DNA Essentials")
    assert info.observed == "LAN Base, DNA Essentials"
    assert info.ambiguous is True


def test_storage_alias_conflict_is_marked() -> None:
    entries = _storage_entries(
        "File Systems:\n"
        "  100  50  flash rw flash: flash1:\n"
        "  200  60  flash rw flash1:\n",
    )
    assert len(entries) == 2
    assert [entry.alias_conflict for entry in entries] == [True, True]


def test_identical_storage_rows_collapse_but_conflicting_rows_survive() -> None:
    identical = _storage_entries(
        "File Systems:\n"
        "  100  50  flash rw flash:\n"
        "  100  50  flash rw flash:\n",
    )
    assert len(identical) == 1
    conflicting = _storage_entries(
        "File Systems:\n"
        "  100  50  flash rw flash:\n"
        "  200  60  flash rw flash:\n",
    )
    assert len(conflicting) == 2
    assert [entry.alias_conflict for entry in conflicting] == [True, True]


def test_stack_rejects_duplicate_or_reassigned_members() -> None:
    inventory = _load("r85_2960x_manual.json")["responses"]["INVENTORY"]
    from event_switch_manager.console.observation import _inventory_members

    members = _inventory_members(inventory)
    duplicate = inventory + (
        'NAME: "1", DESCR: "duplicate"\n'
        "PID: WS-C2960X-24TS-L, VID: V05, SN: DUPSERIAL\n"
    )
    with pytest.raises(IdentityConflict):
        _inventory_members(duplicate)
    stack = (
        "Switch/Stack Mac Address : 0011.2233.4401\n"
        "                                           H/W   Current\n"
        "Switch#  Role   Mac Address     Priority Version  State\n"
        "----------------------------------------------------------\n"
        "*1       Master 0011.2233.4401     15     4       Ready\n"
        " 3       Member 0011.2233.4402     11     4       Ready\n"
    )
    with pytest.raises(IdentityConflict):
        _stack(stack, members)


def test_stack_master_can_be_member_two_and_controls_top_level_serial() -> None:
    data = _load("r85_2960x_manual.json")
    data = json.loads(json.dumps(data))
    data["responses"]["STACK"] = (
        "Switch/Stack Mac Address : 0011.2233.4402\n"
        "                                           H/W   Current\n"
        "Switch#  Role   Mac Address     Priority Version  State\n"
        "----------------------------------------------------------\n"
        " 1       Member 0011.2233.4401     15     4       Ready\n"
        "*2       Master 0011.2233.4402     11     4       Ready\n"
    )
    observation = _observe(data).observation
    master = next(member for member in observation.stack if member.role == "Master")
    assert master.number == 2
    assert master.master_star is True
    assert observation.serial_number == "R84STACK02"


def test_stack_rejects_no_or_multiple_master() -> None:
    inventory = _load("r85_2960x_manual.json")["responses"]["INVENTORY"]
    from event_switch_manager.console.observation import _inventory_members

    members = _inventory_members(inventory)
    no_master = (
        "Switch#  Role   Mac Address     Priority Version  State\n"
        " 1       Member 0011.2233.4401     15     4       Ready\n"
        " 2       Member 0011.2233.4402     11     4       Ready\n"
    )
    with pytest.raises(IdentityConflict):
        _stack(no_master, members)
    two_master = (
        "Switch#  Role   Mac Address     Priority Version  State\n"
        "*1       Master 0011.2233.4401     15     4       Ready\n"
        "*2       Master 0011.2233.4402     11     4       Ready\n"
    )
    with pytest.raises(IdentityConflict):
        _stack(two_master, members)


def test_exact_profile_rejects_inherited_release_and_forged_object() -> None:
    with pytest.raises(ProfileNotVerified):
        resolve_profile("C1000-16T-2G-L", "15.2(7)E1")
    with pytest.raises(ProfileNotVerified):
        resolve_profile("WS-C2960X-24TS-L", "15.2(7)E7")
    assert resolve_profile("C1000-16T-2G-L", "15.2(7)E2").release == "15.2(7)E2"
    assert resolve_profile("WS-C2960X-24TS-L", "15.2(7)E10").release == "15.2(7)E10"
    forged = ConsoleProfile(
        DeviceFamily.CATALYST_C1000,
        "C1000-16T-2G-L",
        "15.2(7)E1",
    )
    with pytest.raises(ProfileNotVerified):
        validate_profile(forged)
    valid = resolve_profile("C1000-16T-2G-L", "15.2(7)E2")
    with pytest.raises(QueryNotSupported):
        resolve_query_for_profile(valid, ConsoleQuery.LICENSE)
    with pytest.raises(ProfileNotVerified):
        resolve_query_for_profile(forged, ConsoleQuery.VERSION)
    session = ConsoleSession(
        SimulatedConsoleTransport(profile=SimulatorProfile(
            family=DeviceFamily.CATALYST_C1000,
            hostname="sanitized-c1000",
            model="C1000-16T-2G-L",
            serial_number="R84C100001",
            software_version="15.2(7)E2",
            license_declared=None,
            license_observed=None,
            license_status=None,
            license_next_boot=None,
            interfaces=(),
            stack=(),
            boot_state=None,
            storage=(),
        )),
        timeout=1.0,
    )
    with pytest.raises(ProfileNotVerified):
        session.set_profile(forged)
    assert set(supported_queries_for_profile(valid)) == {
        ConsoleQuery.VERSION, ConsoleQuery.INVENTORY, ConsoleQuery.INTERFACES,
        ConsoleQuery.BOOT, ConsoleQuery.STORAGE,
    }
