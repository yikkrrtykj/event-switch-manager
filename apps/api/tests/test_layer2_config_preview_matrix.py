"""CIS-02B1 model, Stack, transition and fail-closed matrix regressions."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from test_event_plans import ORIGIN
from test_layer2_config_preview import (
    CLI_LINE,
    device_document,
    item,
    items,
    preview,
    revision_for,
)
from test_layer2_intent import event, make_plan, make_stack_plan, new_id, save

import event_switch_manager.planning.layer2_intent as layer2_intent
from event_switch_manager.app import create_app
from event_switch_manager.integrations import Support
from event_switch_manager.planning.layer2_config_preview import (
    build_layer2_config_preview,
)
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.settings import Settings

Device = dict[str, Any]
Item = dict[str, Any]


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "layer2-preview-matrix.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as session:
        yield session


def first_device(result: dict[str, Any]) -> Device:
    return cast(Device, result["devices"][0])


def add_channel(
    plan: dict[str, Any], *, number: int, member_indices: list[int],
    lacp: str, settings: dict[str, Any],
) -> None:
    logical_id = new_id()
    plan.setdefault("logical_interfaces", []).append({
        "id": logical_id,
        "assignment_id": plan["assignments"][0]["id"],
        "name": f"Port-channel{number}",
        "kind": "port-channel",
    })
    plan.setdefault("port_channels", []).append({
        "interface_id": logical_id,
        "number": number,
        "member_ids": [
            plan["physical_interfaces"][index]["id"] for index in member_indices
        ],
        "settings": dict(settings),
        "lacp": lacp,
    })


def channels(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], plan.setdefault("port_channels", []))


ACCESS = {"mode": "access", "access_vlan": 20}
TRUNK = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}


@pytest.mark.parametrize(("pid", "image", "license_name", "family", "documented"), [
    ("WS-C2960X-24TS-L", "15.2(7)E", "LAN Base", "catalyst-2960x", "unknown"),
    ("WS-C3850-24T", "16.12.12", "IP Base", "catalyst-3850", "unknown"),
    ("C9200L-24T-4G", "17.12.4", "Network Advantage", "catalyst-9200", "supported"),
    ("C9300L-24P-4X", "17.12.4", "Network Advantage", "catalyst-9300", "supported"),
    ("C1000-24T-4G-L", "15.2(7)E1", None, "catalyst-c1000", "unknown"),
])
def test_preview_covers_reviewed_family_matrix(
    client: TestClient, pid: str, image: str, license_name: str | None,
    family: str, documented: str,
) -> None:
    event_id = event(client, f"Preview family {pid}")
    plan = make_plan(
        event_id, pid=pid, image=image, license_name=license_name, family=family,
        ports=[
            {"name": "Gi1/0/1", "settings": dict(ACCESS)},
            {"name": "Gi1/0/2", "settings": dict(TRUNK)},
        ],
    )
    saved = save(client, event_id, plan)
    result = preview(client, event_id, saved["id"])
    device = first_device(result)
    identity = device["identity"]
    assert (identity["pid"], identity["software_image"], identity["software_license"]) == (
        pid, image, license_name,
    )
    assert result["readiness"]["vendor_documentation"] == documented
    assert result["readiness"]["hardware_verified"] is False
    assert result["readiness"]["deployment_allowed"] is False
    categories = {candidate["category"] for candidate in items(device)}
    assert {"vlan", "stp", "vtp", "root-priority", "access", "trunk"} <= categories
    assert item(device, "Gi1/0/1", "mode")["planned"]["value"] == "access"
    assert item(device, "Gi1/0/2", "mode")["planned"]["value"] == "trunk"
    deployability = device["deployability"]
    assert deployability["deployable"] is False
    assert deployability["deployment_allowed"] is False
    if documented == "supported":
        assert deployability["evidence_gate"] == "pass"
        assert deployability["capability_gate"]["verdict"] == "supported"
    else:
        assert deployability["evidence_gate"] in {
            "unknown", "identity-incomplete", "unsupported",
        }
        assert deployability["capability_gate"]["verdict"] in {"unknown", "unsupported"}
    for candidate in items(device):
        assert candidate["deployability"]["deployable"] is False
        if documented == "supported":
            assert candidate["deployability"]["evidence_gate"] == "pass"
        human = device["human_readable"]
        assert human["display_only"] is True
        assert human["executable"] is False
    for statement in cast(list[str], device["human_readable"]["statements"]):
        assert not CLI_LINE.match(statement.strip())


def test_stack_identity_member_state_and_unresolved_pid_fail_closed(
    client: TestClient,
) -> None:
    event_id = event(client, "Preview Stack identity")
    first_plan = make_stack_plan(event_id)
    first = save(client, event_id, first_plan)
    result = preview(client, event_id, first["id"])
    device = first_device(result)
    assert device["identity"]["stack_identity"] == "resolved"
    identity_gate = device["deployability"]["identity_gate"]
    assert identity_gate["status"] == "pass"
    assert identity_gate["stack_member_count"] == 2
    assert identity_gate["stack_ready_member_count"] == 2
    assert device["deployability"]["evidence_gate"] == "pass"
    assert item(device, "Gi1/0/1", "mode")["deployability"]["evidence_gate"] == "pass"
    stack_changes = [
        change for change in cast(list[dict[str, Any]], device["planned_diff"])
        if change["field"] == "stack_member"
        or change["field"].startswith("stack_member:")
    ]
    assert len(stack_changes) == 2

    missing_plan = copy.deepcopy(first_plan)
    missing_plan["stacks"][0]["members"][1]["state"] = "missing"
    missing = save(client, event_id, missing_plan)
    missing_result = preview(client, event_id, missing["id"])
    missing_device = first_device(missing_result)
    gate = missing_device["deployability"]["identity_gate"]
    assert gate["status"] == "incomplete"
    assert "stack-member-not-ready:2:missing" in gate["codes"]
    assert missing_device["deployability"]["evidence_gate"] == "identity-incomplete"
    assert missing_device["deployability"]["deployable"] is False
    for candidate in items(missing_device):
        assert candidate["deployability"]["evidence_gate"] == "identity-incomplete"
        assert candidate["deployability"]["deployable"] is False
    state_change = next(
        change for change in cast(list[dict[str, Any]], missing_device["planned_diff"])
        if change["field"] == "stack-member:2:state"
    )
    assert state_change["transition"] == "stack-member-state-change"
    assert (state_change["before"], state_change["after"]) == ("ready", "missing")
    conflict_codes = {
        conflict["code"] for conflict in missing_device["conflicts"]
    }
    assert "stack-member-state-change-requires-field-verification" in conflict_codes
    assert any(
        blocker.startswith("identity-incomplete:stack-member-not-ready:2:missing")
        for blocker in missing_device["deployability"]["blockers"]
    )

    unresolved_plan = copy.deepcopy(first_plan)
    unresolved_plan["physical_devices"][1]["verified_serial"] = None
    unresolved = save(client, event_id, unresolved_plan)
    unresolved_result = preview(client, event_id, unresolved["id"])
    unresolved_device = first_device(unresolved_result)
    assert unresolved_device["identity"]["stack_identity"] == "unresolved"
    unresolved_gate = unresolved_device["deployability"]["identity_gate"]
    assert "stack-identity-unresolved" in unresolved_gate["codes"]
    assert "stack-member-pid-missing:2" in unresolved_gate["codes"]
    assert unresolved_device["deployability"]["evidence_gate"] == "identity-incomplete"


def test_access_trunk_boundaries_are_previewed_in_both_directions(
    client: TestClient,
) -> None:
    event_id = event(client, "Preview access trunk")
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(ACCESS)},
        {"name": "Gi1/0/2", "settings": dict(TRUNK)},
    ])
    first = save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][0]["settings"] = dict(TRUNK)
    second_plan["physical_interfaces"][1]["settings"] = dict(ACCESS)
    second = save(client, event_id, second_plan)
    result = preview(client, event_id, second["id"])
    device = first_device(result)
    assert result["baseline"]["revision_id"] == first["id"]

    access_to_trunk = item(device, "Gi1/0/1", "mode")
    assert access_to_trunk["category"] == "trunk"
    assert (access_to_trunk["planned"]["value"], access_to_trunk["baseline"]["value"]) == (
        "trunk", "access",
    )
    assert access_to_trunk["diff"]["transition"] == "access-to-trunk"
    assert "access_vlan" in access_to_trunk["diff"]["cleanup"]
    cleared_access = item(device, "Gi1/0/1", "access_vlan")
    assert cleared_access["planned"]["present"] is False
    assert cleared_access["baseline"]["value"] == 20
    assert cleared_access["diff"]["changed"] is True
    native = item(device, "Gi1/0/1", "native_vlan")
    assert native["planned"]["value"] == 10
    assert native["capability"]["verdict"] == "supported"

    trunk_to_access = item(device, "Gi1/0/2", "mode")
    assert trunk_to_access["category"] == "access"
    assert trunk_to_access["diff"]["transition"] == "trunk-to-access"
    assert {"native_vlan", "allowed_vlans"} <= set(
        trunk_to_access["diff"]["cleanup"]
    )
    assert item(device, "Gi1/0/2", "access_vlan")["planned"]["value"] == 20
    cleared_allowed = item(device, "Gi1/0/2", "allowed_vlans")
    assert cleared_allowed["planned"]["present"] is False
    assert cleared_allowed["baseline"]["value"] == [10, 20]


def test_port_channel_lacp_modes_and_direct_member_migration(
    client: TestClient,
) -> None:
    event_id = event(client, "Preview channel migration")
    ports = [{"name": f"Gi1/0/{index}", "settings": dict(ACCESS)} for index in (1, 2, 3, 4)]
    independent = make_plan(event_id, ports=ports)
    save(client, event_id, independent)

    active_plan = copy.deepcopy(independent)
    add_channel(active_plan, number=1, member_indices=[0, 1], lacp="active",
                settings=ACCESS)
    active = save(client, event_id, active_plan)
    active_result = preview(client, event_id, active["id"])
    active_device = first_device(active_result)
    membership = item(active_device, "Gi1/0/1", "port_channel")
    assert membership["planned"]["value"] == 1
    assert membership["diff"]["transition"] == "independent-to-port-channel-member"
    assert membership["capability"]["verdict"] == "supported"
    channel_lacp = item(active_device, "Port-channel1", "lacp")
    assert channel_lacp["planned"]["value"] == "active"
    assert channel_lacp["capability"]["capability"] == "lacp"
    assert channel_lacp["capability"]["verdict"] == "supported"
    assert item(active_device, "Port-channel1", "number")["planned"]["value"] == 1
    member_ids = item(active_device, "Port-channel1", "member_ids")
    assert set(member_ids["planned"]["value"]["member_ids"]) == {
        active_plan["physical_interfaces"][0]["id"],
        active_plan["physical_interfaces"][1]["id"],
    }
    assert set(member_ids["planned"]["value"]["member_names"]) == {"Gi1/0/1", "Gi1/0/2"}

    passive_plan = copy.deepcopy(active_plan)
    channels(passive_plan)[0]["lacp"] = "passive"
    passive = save(client, event_id, passive_plan)
    passive_device = first_device(preview(client, event_id, passive["id"]))
    passive_lacp = item(passive_device, "Port-channel1", "lacp")
    assert passive_lacp["planned"]["value"] == "passive"
    assert passive_lacp["baseline"]["value"] == "active"
    assert passive_lacp["diff"]["transition"] == "lacp-active-to-passive"

    migrated_plan = copy.deepcopy(passive_plan)
    channels(migrated_plan)[0]["member_ids"] = [
        migrated_plan["physical_interfaces"][2]["id"],
        migrated_plan["physical_interfaces"][3]["id"],
    ]
    add_channel(migrated_plan, number=2, member_indices=[0, 1], lacp="active",
                settings=ACCESS)
    migrated = save(client, event_id, migrated_plan)
    migrated_device = first_device(preview(client, event_id, migrated["id"]))
    migration = item(migrated_device, "Gi1/0/1", "port_channel")
    assert (migration["planned"]["value"], migration["baseline"]["value"]) == (2, 1)
    assert migration["diff"]["transition"] == "port-channel-member-migrate"
    assert migration["diff"]["changed"] is True
    assert item(migrated_device, "Gi1/0/3", "port_channel")["diff"]["transition"] == (
        "independent-to-port-channel-member"
    )
    assert item(migrated_device, "Port-channel2", "lacp")["planned"]["value"] == "active"
    dependency_kinds = {
        dependency["kind"]
        for dependency in cast(list[dict[str, Any]], migrated_device["dependencies"])
    }
    assert "member-detach" in dependency_kinds
    assert "port-channel-membership" in dependency_kinds
    change_ids = {
        change["change_id"]
        for change in cast(list[dict[str, Any]], migrated_device["planned_diff"])
    }
    required_by = {
        change_id
        for dependency in cast(list[dict[str, Any]], migrated_device["dependencies"])
        for change_id in dependency["required_by"]
    }
    assert required_by <= change_ids
    assert migration["diff"]["change_id"] in required_by

    static_plan = copy.deepcopy(migrated_plan)
    for channel in channels(static_plan):
        channel["lacp"] = "static"
    static = save(client, event_id, static_plan)
    static_device = first_device(preview(client, event_id, static["id"]))
    static_lacp = item(static_device, "Port-channel2", "lacp")
    assert static_lacp["planned"]["value"] == "static"
    assert static_lacp["capability"] == {
        "capability": None,
        "verdict": "not-required",
        "reason_code": "capability-not-required",
        "reason": "static-channel-requires-no-lacp-evidence",
        "check_id": None,
        "evidence": [],
    }
    assert not any(
        check["capability"] == "lacp"
        for check in cast(list[dict[str, Any]], static_device["capability_checks"])
    )
    assert static_device["deployability"]["capability_gate"]["verdict"] == "supported"
    assert static_device["deployability"]["evidence_gate"] == "pass"

    detached_plan = copy.deepcopy(static_plan)
    removed_channel = channels(detached_plan)[1]
    removed_logical = removed_channel["interface_id"]
    detached_plan["port_channels"] = detached_plan["port_channels"][:1]
    detached_plan["logical_interfaces"] = [
        interface for interface in detached_plan["logical_interfaces"]
        if interface["id"] != removed_logical
    ]
    detached = save(client, event_id, detached_plan)
    detached_device = first_device(preview(client, event_id, detached["id"]))
    detached_membership = item(detached_device, "Gi1/0/1", "port_channel")
    assert detached_membership["planned"]["present"] is False
    assert detached_membership["planned"]["source"] == "not-in-plan"
    assert detached_membership["baseline"]["value"] == 2
    assert detached_membership["diff"]["transition"] == (
        "port-channel-member-to-independent"
    )
    removed_number = item(detached_device, "Port-channel2", "number")
    assert removed_number["planned"]["present"] is False
    assert removed_number["baseline"]["value"] == 2
    removal = next(
        change for change in cast(list[dict[str, Any]], detached_device["planned_diff"])
        if change["target_id"] == removed_logical and change["field"] == "presence"
    )
    assert removal["transition"] == "port-channel-removed"
    assert any(
        dependency["kind"] == "port-channel-removal"
        for dependency in cast(
            list[dict[str, Any]], detached_device["dependencies"],
        )
    )


def test_vlan_create_rename_and_delete_are_previewed(
    client: TestClient,
) -> None:
    event_id = event(client, "Preview VLAN lifecycle")
    first_plan = make_plan(
        event_id,
        ports=[
            {"name": "Gi1/0/1", "settings": dict(ACCESS)},
            {"name": "Gi1/0/2", "settings": {"mode": "access", "access_vlan": 20}},
        ],
    )
    first = save(client, event_id, first_plan)

    renamed_plan = copy.deepcopy(first_plan)
    renamed_plan["vlans"] = [
        vlan for vlan in renamed_plan["vlans"] if vlan["id"] != 30
    ]
    for vlan in renamed_plan["vlans"]:
        if vlan["id"] == 20:
            vlan["name"] = "Team"
    renamed_plan["vlans"].append({"id": 40, "name": "Temporary", "purpose": "ordinary"})
    renamed_plan["physical_interfaces"][1]["settings"] = {
        "mode": "access", "access_vlan": 40,
    }
    renamed = save(client, event_id, renamed_plan)
    renamed_result = preview(client, event_id, renamed["id"])
    renamed_device = first_device(renamed_result)
    rename_item = item(renamed_device, "Team", "definition")
    assert rename_item["planned"]["value"] == {"vlan_id": 20, "name": "Team"}
    assert rename_item["baseline"]["value"] == {"vlan_id": 20, "name": "Players"}
    assert rename_item["diff"]["transition"] == "vlan-renamed"
    assert rename_item["diff"]["changed"] is True
    created_item = item(renamed_device, "Temporary", "definition")
    assert created_item["planned"]["value"] == {"vlan_id": 40, "name": "Temporary"}
    assert created_item["baseline"]["state"] == "not-in-baseline"
    assert created_item["diff"]["transition"] == "vlan-created"
    assert created_item["capability"]["capability"] == "vlan"
    assert created_item["capability"]["verdict"] == "supported"
    definitions = {
        definition["vlan_id"]: definition
        for definition in cast(
            list[dict[str, Any]], renamed_result["vlan_scope"]["definitions"],
        )
    }
    assert set(definitions) == {10, 20, 40}
    assert definitions[20]["name"] == "Team"
    assert definitions[20]["transition"] == "vlan-renamed"
    assert definitions[40]["transition"] == "vlan-created"
    rename_changes = [
        change for change in cast(
            list[dict[str, Any]], renamed_result["vlan_scope"]["changes"],
        ) if change["target_id"] == "20"
    ]
    assert rename_changes[0]["field"] == "name"
    assert rename_changes[0]["transition"] == "vlan-renamed"

    deleted_plan = copy.deepcopy(renamed_plan)
    deleted_plan["physical_interfaces"][1]["settings"] = dict(ACCESS)
    deleted_plan["vlans"] = [
        vlan for vlan in deleted_plan["vlans"] if vlan["id"] != 40
    ]
    deleted = save(client, event_id, deleted_plan)
    deleted_result = preview(client, event_id, deleted["id"])
    deleted_device = first_device(deleted_result)
    removed_item = item(deleted_device, "Temporary", "definition")
    assert removed_item["planned"]["present"] is False
    assert removed_item["planned"]["source"] == "not-in-plan"
    assert removed_item["baseline"]["value"] == {"vlan_id": 40, "name": "Temporary"}
    assert removed_item["diff"]["transition"] == "vlan-removed"
    assert removed_item["deployability"]["evidence_gate"] == "pass"
    assert item(deleted_device, "Gi1/0/2", "access_vlan")["diff"]["changed"] is True
    assert 40 not in {
        definition["vlan_id"]
        for definition in cast(
            list[dict[str, Any]], deleted_result["vlan_scope"]["definitions"],
        )
    }
    assert any(
        change["target_id"] == "40" and change["transition"] == "vlan-removed"
        for change in cast(
            list[dict[str, Any]], deleted_result["vlan_scope"]["changes"],
        )
    )
    assert first["content_hash"] != renamed["content_hash"]


def test_vlan_reference_removal_without_definition_change_is_a_difference(
    client: TestClient,
) -> None:
    event_id = event(client, "Preview VLAN reference removal")
    first_plan = make_plan(
        event_id,
        ports=[
            {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 10}},
            {"name": "Gi1/0/2", "settings": dict(ACCESS)},
        ],
    )
    save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][1]["settings"] = {
        "mode": "access", "access_vlan": 10,
    }
    second = save(client, event_id, second_plan)
    result = preview(client, event_id, second["id"])
    device = first_device(result)
    vlan_item = item(device, "Players", "definition")
    assert vlan_item["planned"]["present"] is False
    assert vlan_item["baseline"]["value"] == {"vlan_id": 20, "name": "Players"}
    assert vlan_item["diff"]["changed"] is True
    assert vlan_item["diff"]["transition"] == "vlan-unreferenced"
    assert vlan_item["diff"]["change_id"] is None
    assert any(
        code == "no-current-plan-intent" for code in vlan_item["risk"]["codes"]
    )
    definitions = {
        definition["vlan_id"]: definition
        for definition in cast(
            list[dict[str, Any]], result["vlan_scope"]["definitions"],
        )
    }
    assert definitions[20]["name"] == "Players"
    assert definitions[20]["change_id"] is None
    assert definitions[20]["transition"] is None
    assert item(device, "Gi1/0/2", "access_vlan")["planned"]["value"] == 10


def test_unused_port_shutdown_and_explicit_admin_state_provenance(
    client: TestClient,
) -> None:
    event_id = event(client, "Preview shutdown provenance")
    plan = make_plan(
        event_id,
        ports=[
            {"name": "Gi1/0/1", "settings": {**ACCESS, "admin_state": "down"}},
            {"name": "Gi1/0/2", "settings": {**ACCESS, "admin_state": "up"}},
            {"name": "Gi1/0/3", "settings": dict(ACCESS)},
            {"name": "Gi1/0/4", "settings": dict(ACCESS)},
            {"name": "Gi1/0/5", "settings": dict(ACCESS)},
        ],
        channel={"members": [2, 3], "settings": ACCESS, "lacp": "active"},
    )
    saved = save(client, event_id, plan)
    device = first_device(preview(client, event_id, saved["id"]))

    explicit_down = item(device, "Gi1/0/1", "shutdown_intent")
    assert explicit_down["planned"]["value"] == {
        "intent": "shutdown", "source": "event-plan", "admin_state": "down",
    }
    assert item(device, "Gi1/0/1", "admin_state")["planned"] == {
        "value": "down", "present": True, "source": "event-plan",
    }
    explicit_up = item(device, "Gi1/0/2", "shutdown_intent")
    assert explicit_up["planned"]["value"] == {
        "intent": "no-shutdown", "source": "event-plan", "admin_state": "up",
    }
    assert item(device, "Gi1/0/2", "admin_state")["planned"]["value"] == "up"

    policy_port = item(device, "Gi1/0/5", "shutdown_intent")
    assert policy_port["planned"]["value"] == {
        "intent": "shutdown", "source": "reviewed-default-policy",
        "admin_state": None,
    }
    assert policy_port["risk"]["requires_field_verification"] is True
    assert any(
        code.startswith("intent-conflict:unused-port-policy-inference")
        for code in policy_port["risk"]["codes"]
    )
    member_port = item(device, "Gi1/0/4", "shutdown_intent")
    assert member_port["planned"]["value"]["intent"] == "platform-default"
    assert member_port["planned"]["value"]["source"] is None
    assert member_port["planned"]["source"] == "platform-default"
    assert not any(
        candidate["field"] == "admin_state" and candidate["target_name"] == "Gi1/0/4"
        for candidate in items(device)
    )
    policy = item(device, "L2-Access", "unused-port-shutdown")
    assert policy["planned"]["value"]["requires_field_verification"] is True
    assert policy["risk"]["level"] == "field-verification"


def test_same_interface_names_across_assignments_stay_isolated(
    client: TestClient,
) -> None:
    event_id = event(client, "Preview same interface names")
    plan = make_plan(
        event_id,
        ports=[{"name": "Gi1/0/1", "settings": dict(ACCESS)}],
    )
    second_device, second_assignment, second_port = new_id(), new_id(), new_id()
    plan["physical_devices"].append({
        "id": second_device, "vendor": "cisco", "model": "C9300L-24P-4X",
        "verified_serial": "SYN-L2-SAME-NAME",
    })
    plan["assignments"].append({
        "id": second_assignment, "hostname": "L2-Second", "role": "access",
        "family": "catalyst-9300", "physical_device_id": second_device,
        "software": {"image": "17.12.4", "license": "Network Advantage"},
    })
    plan["physical_interfaces"].append({
        "id": second_port, "assignment_id": second_assignment,
        "physical_device_id": second_device, "name": "Gi1/0/1",
        "settings": dict(TRUNK),
    })
    saved = save(client, event_id, plan)
    result = preview(client, event_id, saved["id"])
    devices = cast(list[Device], result["devices"])
    assert [device["hostname"] for device in devices] == ["L2-Access", "L2-Second"]
    assert item(devices[0], "Gi1/0/1", "mode")["planned"]["value"] == "access"
    assert item(devices[1], "Gi1/0/1", "mode")["planned"]["value"] == "trunk"
    assert item(devices[0], "Gi1/0/1", "mode")["target_id"] == (
        plan["physical_interfaces"][0]["id"]
    )
    assert item(devices[1], "Gi1/0/1", "mode")["target_id"] == second_port
    first_document = device_document(
        client, event_id, saved["id"], devices[0]["assignment_id"],
    )
    second_document = device_document(
        client, event_id, saved["id"], devices[1]["assignment_id"],
    )
    assert first_document["device"]["assignment_id"] == plan["assignments"][0]["id"]
    assert second_document["device"]["assignment_id"] == second_assignment
    assert first_document["device"]["preview_fingerprint"] != (
        second_document["device"]["preview_fingerprint"]
    )
    assert second_port not in {
        candidate["target_id"]
        for candidate in items(cast(Device, first_document["device"]))
    }


def test_unknown_pid_license_and_rommon_fail_closed(
    client: TestClient,
) -> None:
    unknown_pid_event = event(client, "Preview unknown PID")
    unknown_pid = save(client, unknown_pid_event, make_plan(
        unknown_pid_event, with_serial=False,
        ports=[{"name": "Gi1/0/1", "settings": dict(ACCESS)}],
    ))
    unknown_pid_device = first_device(preview(
        client, unknown_pid_event, unknown_pid["id"],
    ))
    assert unknown_pid_device["identity"]["pid_evidence"] == "model-only"
    identity_gate = unknown_pid_device["deployability"]["identity_gate"]
    assert identity_gate["status"] == "incomplete"
    assert "pid-not-verified" in identity_gate["codes"]
    assert unknown_pid_device["deployability"]["evidence_gate"] == (
        "identity-incomplete"
    )
    for candidate in items(unknown_pid_device):
        assert candidate["deployability"]["evidence_gate"] == "identity-incomplete"
        assert candidate["deployability"]["deployable"] is False

    license_event = event(client, "Preview missing license")
    missing_license = save(client, license_event, make_plan(
        license_event, license_name=None,
        ports=[{"name": "Gi1/0/1", "settings": dict(ACCESS)}],
    ))
    license_device = first_device(preview(
        client, license_event, missing_license["id"],
    ))
    license_gate = license_device["deployability"]["identity_gate"]
    assert "license-unverified" in license_gate["codes"]
    assert license_device["deployability"]["evidence_gate"] == "identity-incomplete"
    assert license_device["deployability"]["capability_gate"]["verdict"] == "unknown"
    assert any(
        blocker.startswith("identity-incomplete:license-unverified")
        for blocker in license_device["deployability"]["blockers"]
    )

    rommon_event = event(client, "Preview ROMMON image")
    rommon = save(client, rommon_event, make_plan(
        rommon_event, image="17.12.2r",
        ports=[{"name": "Gi1/0/1", "settings": dict(ACCESS)}],
    ))
    rommon_device = first_device(preview(client, rommon_event, rommon["id"]))
    rommon_gate = rommon_device["deployability"]["identity_gate"]
    assert "software-release-unverified" in rommon_gate["codes"]
    assert rommon_device["deployability"]["evidence_gate"] == "identity-incomplete"
    stp = item(rommon_device, "L2-Access", "spanning-tree-mode")
    assert stp["capability"]["verdict"] == "unknown"
    assert stp["deployability"]["evidence_gate"] == "identity-incomplete"


def test_synthetic_unsupported_and_unknown_capabilities_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SyntheticDecision:
        def __init__(self, verdict: Support) -> None:
            self.verdict = verdict
            self.reason_code = "synthetic-capability"
            self.reason = "Synthetic unit-test evidence."
            self.evidence = ()

    plan = make_plan(
        new_id(),
        ports=[{"name": "Gi1/0/1", "settings": dict(ACCESS)}],
    )
    revision = revision_for(plan)

    def fake_resolve(
        _revision: Any, _assignment_id: UUID, capability: Any, **kwargs: Any,
    ) -> SyntheticDecision:
        del _revision, _assignment_id, kwargs
        if str(capability.value) in {"access"}:
            return SyntheticDecision(Support.UNSUPPORTED)
        if str(capability.value) in {"rapid-pvst"}:
            return SyntheticDecision(Support.UNKNOWN)
        return SyntheticDecision(Support.SUPPORTED)

    monkeypatch.setattr(layer2_intent, "resolve_capability", fake_resolve)
    intent_model = build_layer2_intent(revision, None)
    result = build_layer2_config_preview(revision, intent_model)
    device = result.devices[0]
    assert device.deployability.capability_gate.unsupported == ("access:L2-Access",)
    assert device.deployability.capability_gate.unknown == (
        "rapid-pvst:L2-Access",
    )
    assert device.deployability.capability_gate.verdict == "unsupported"
    assert device.deployability.evidence_gate == "unsupported"
    access_items = [
        config_item for config_item in device.config_items
        if config_item.target_name == "Gi1/0/1" and config_item.field == "mode"
    ]
    assert len(access_items) == 1
    access_item = access_items[0]
    assert access_item.capability.verdict == "unsupported"
    assert access_item.deployability.evidence_gate == "unsupported"
    assert access_item.deployability.deployable is False
    assert any(
        blocker.startswith("capability-unsupported:access:")
        for blocker in access_item.deployability.blockers
    )
    stp = next(
        config_item for config_item in device.config_items
        if config_item.field == "spanning-tree-mode"
    )
    assert stp.capability.verdict == "unknown"
    assert stp.deployability.evidence_gate == "unknown"
    assert stp.deployability.deployable is False
    assert any(
        blocker.startswith("capability-unknown:rapid-pvst:")
        for blocker in stp.deployability.blockers
    )
    for config_item in device.config_items:
        assert config_item.deployability.deployable is False
    assert result.executable is False
    assert result.cli is None
    assert result.device_writes_enabled is False
