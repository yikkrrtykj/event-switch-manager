"""ChangeSet completeness regressions for CIS-02A."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from test_event_plans import ORIGIN
from test_layer2_intent import (
    event,
    intent,
    make_plan,
    make_stack_plan,
    new_id,
    save,
    serial,
)

from event_switch_manager.app import create_app
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.planning.plan import EventPlan, PlanRevision
from event_switch_manager.settings import Settings


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "layer2-changeset.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as session:
        yield session


def device_of(result: dict[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], result["devices"][0])


def all_changes(result: dict[str, Any]) -> list[dict[str, Any]]:
    changes = list(cast(list[dict[str, Any]], result.get("vlan_changes", [])))
    for device in result["devices"]:
        changes.extend(cast(list[dict[str, Any]], device["changes"]))
    return changes


def find_change(
    result: dict[str, Any], target_id: str, field: str,
) -> dict[str, Any]:
    for change in all_changes(result):
        if change["target_id"] == target_id and change["field"] == field:
            return change
    raise AssertionError(f"Missing change {target_id} / {field}")


def test_vlan_definition_create_rename_delete_are_structural(client: TestClient) -> None:
    event_id = event(client)
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/2", "settings": {
            "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
        }},
    ])
    first_plan["vlans"] = [
        {"id": 10, "name": "Management", "purpose": "management"},
        {"id": 20, "name": "Players", "purpose": "ordinary"},
    ]
    save(client, event_id, first_plan)

    second_plan = copy.deepcopy(first_plan)
    second_plan["vlans"] = [
        {"id": 10, "name": "Management", "purpose": "management"},
        {"id": 20, "name": "Competitors", "purpose": "ordinary"},
        {"id": 30, "name": "Stage", "purpose": "ordinary"},
        {"id": 40, "name": "Voice", "purpose": "ordinary"},
    ]
    second_plan["physical_interfaces"][1]["settings"]["allowed_vlans"] = [10, 20, 40]
    second = save(client, event_id, second_plan)
    renamed = intent(client, event_id, second["id"])

    event_vlans = {
        entry["vlan_id"]: entry for entry in cast(list[dict[str, Any]], renamed["vlans"])
    }
    assert event_vlans[20]["name"] == "Competitors"
    assert event_vlans[30]["name"] == "Stage"
    assert event_vlans[20]["source"] == "event-plan"
    assert event_vlans[10]["source"] == "event-plan"
    device_vlans = {
        entry["vlan_id"]: entry
        for entry in cast(list[dict[str, Any]], device_of(renamed)["desired"]["vlans"])
    }
    assert device_vlans[20]["name"] == "Competitors"
    assert 30 not in device_vlans  # unreferenced declaration is event-level only
    assert device_vlans[40]["name"] == "Voice"

    rename = find_change(renamed, "20", "name")
    assert rename["target_kind"] == "vlan"
    assert rename["transition"] == "vlan-renamed"
    assert (rename["before"], rename["after"]) == ("Players", "Competitors")
    assert rename["before_source"] == "planning-baseline"
    create_30 = find_change(renamed, "30", "definition")
    assert create_30["transition"] == "vlan-created"
    assert create_30["before"] is None
    assert create_30["after"]["vlan_id"] == 30
    assert create_30["after"]["name"] == "Stage"
    create_40 = find_change(renamed, "40", "definition")
    assert create_40["transition"] == "vlan-created"
    assert all(
        change["field"] != "definition" or change["target_id"] != "20"
        for change in renamed["vlan_changes"]
    )

    dependencies = {
        dependency["target"]: dependency
        for dependency in cast(list[dict[str, Any]], renamed["vlan_dependencies"])
    }
    interface_change = find_change(renamed, str(
        second_plan["physical_interfaces"][1]["id"]
    ), "allowed_vlans")
    assert interface_change["transition"] == "allowed-vlans-change"
    assert interface_change["before"] == [10, 20]
    assert interface_change["after"] == [10, 20, 40]
    assert create_40["change_id"] in dependencies["vlan:40"]["required_by"]
    assert interface_change["change_id"] in dependencies["vlan:40"]["required_by"]
    assert create_30["change_id"] in dependencies["vlan:30"]["required_by"]
    change_ids = {change["change_id"] for change in all_changes(renamed)}
    for dependency in renamed["vlan_dependencies"]:
        assert set(dependency["required_by"]) <= change_ids

    third_plan = copy.deepcopy(second_plan)
    third_plan["vlans"] = [vlan for vlan in second_plan["vlans"] if vlan["id"] != 30]
    third = save(client, event_id, third_plan)
    removed = intent(client, event_id, third["id"])
    remove_30 = find_change(removed, "30", "definition")
    assert remove_30["transition"] == "vlan-removed"
    assert remove_30["after"] is None
    assert remove_30["before"]["name"] == "Stage"
    assert not any(
        change["transition"] == "vlan-created" and change["target_id"] == "30"
        for change in removed["vlan_changes"]
    )
    assert removed["baseline"]["revision_id"] == second["id"]
    assert removed["baseline"]["revision_hash"] == second["content_hash"]
    removal_dependencies = {
        dependency["target"]: dependency
        for dependency in cast(list[dict[str, Any]], removed["vlan_dependencies"])
    }
    assert remove_30["change_id"] in removal_dependencies["vlan:30"]["required_by"]
    assert rename["change_id"] in dependencies["vlan:20"]["required_by"]


def test_stack_member_chassis_replacement_is_recorded_and_evidence_refreshed(
    client: TestClient,
) -> None:
    event_id = event(client)
    first_plan = make_stack_plan(event_id)
    first_member_device = str(first_plan["physical_devices"][0]["id"])
    first = save(client, event_id, first_plan)

    replacement = {
        "id": new_id(), "vendor": "cisco", "model": "Catalyst 9300",
    }
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_devices"].append(replacement)
    second_plan["assignments"][0]["physical_device_id"] = replacement["id"]
    second_plan["stacks"][0]["members"][0]["physical_device_id"] = replacement["id"]
    second_plan["physical_interfaces"][0]["physical_device_id"] = replacement["id"]
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    assert result["baseline"]["revision_id"] == first["id"]
    device = device_of(result)
    assert device["identity"]["physical_device_id"] == replacement["id"]
    assert device["identity"]["stack_members"][0]["physical_device_id"] == (
        replacement["id"]
    )
    assert device["identity"]["stack_identity"] == "unresolved"
    port = device["desired"]["physical_ports"][0]
    assert port["physical_device_id"] == replacement["id"]
    assert find_change(result, str(device["identity"]["assignment_id"]),
                       "physical-device-id")["transition"] == (
        "assignment-physical-device-change"
    )
    stack_change = next(
        change for change in all_changes(result)
        if change["field"] == "stack-member:1:physical-device-id"
    )
    assert stack_change["before"] == first_member_device
    assert stack_change["after"] == replacement["id"]
    assert stack_change["target_kind"] == "device"
    assert stack_change["target_name"] == "L2-Stack"
    assert any(
        conflict["code"] == "stack-identity-change-requires-field-verification"
        for conflict in device["conflicts"]
    )
    assert any(
        blocker.startswith("field-verification-required:")
        for blocker in result["deployment_blockers"]
    )
    assert result["readiness"]["hardware_verified"] is False
    assert result["readiness"]["deployment_allowed"] is False
    identity_check = next(
        check for check in device["capability_checks"]
        if check["capability"] == "identity"
    )
    assert identity_check["verdict"] == "unknown"
    assert identity_check["reason_code"] == "target-binding-unknown"
    assert result["verification"] == "not-verified"
    assert result["cli"] is None
    assert result["executable"] is False
    assert result["device_writes_enabled"] is False


def test_assignment_chassis_binding_change_does_not_reuse_old_evidence(
    client: TestClient,
) -> None:
    event_id = event(client)
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    first_device = str(first_plan["physical_devices"][0]["id"])
    first = save(client, event_id, first_plan)
    replacement = {
        "id": new_id(), "vendor": "cisco", "model": "Catalyst 9300",
    }
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_devices"].append(replacement)
    second_plan["assignments"][0]["physical_device_id"] = replacement["id"]
    second_plan["physical_interfaces"][0]["physical_device_id"] = replacement["id"]
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    assert result["baseline"]["revision_id"] == first["id"]
    device = device_of(result)
    change = find_change(result, str(device["identity"]["assignment_id"]),
                         "physical-device-id")
    assert change["before"] == first_device
    assert change["after"] == replacement["id"]
    assert change["transition"] == "assignment-physical-device-change"
    port_change = find_change(result, str(second_plan["physical_interfaces"][0]["id"]),
                              "physical_device_id")
    assert (port_change["before"], port_change["after"]) == (
        first_device, replacement["id"],
    )
    assert port_change["transition"] == "physical-device-change"
    assert any(
        conflict["code"] == "device-identity-change-requires-field-verification"
        for conflict in device["conflicts"]
    )
    identity_check = next(
        check for check in device["capability_checks"]
        if check["capability"] == "identity"
    )
    assert identity_check["verdict"] == "unknown"
    assert result["readiness"]["vendor_documentation"] == "unknown"
    assert result["readiness"]["hardware_verified"] is False
    assert result["readiness"]["deployment_allowed"] is False


def test_port_channel_mode_cleanup_dependencies_and_removal(client: TestClient) -> None:
    event_id = event(client)
    access_settings = {"mode": "access", "access_vlan": 20}
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(access_settings)},
        {"name": "Gi1/0/2", "settings": dict(access_settings)},
    ])
    first_plan["logical_interfaces"] = [{
        "id": new_id(), "assignment_id": first_plan["assignments"][0]["id"],
        "name": "Port-channel1", "kind": "port-channel",
    }]
    first_plan["port_channels"] = [{
        "interface_id": first_plan["logical_interfaces"][0]["id"], "number": 1,
        "member_ids": [
            first_plan["physical_interfaces"][0]["id"],
            first_plan["physical_interfaces"][1]["id"],
        ],
        "settings": dict(access_settings), "lacp": "active",
    }]
    first = save(client, event_id, first_plan)
    channel_id = str(first_plan["logical_interfaces"][0]["id"])

    second_plan = copy.deepcopy(first_plan)
    second_plan["port_channels"][0]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
    }
    second_plan["port_channels"][0]["lacp"] = "passive"
    for port in second_plan["physical_interfaces"]:
        port["settings"] = {
            "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
        }
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    assert result["baseline"]["revision_id"] == first["id"]
    mode_change = next(
        change for change in device_of(result)["changes"]
        if change["target_kind"] == "port-channel" and change["field"] == "mode"
    )
    assert mode_change["transition"] == "access-to-trunk"
    assert "access_vlan" in mode_change["cleanup"]
    assert find_change(result, channel_id, "allowed_vlans")["transition"] == (
        "allowed-vlans-change"
    )
    assert find_change(result, channel_id, "lacp")["transition"] == (
        "lacp-active-to-passive"
    )
    mode_dependencies = [
        dependency for dependency in device_of(result)["dependencies"]
        if dependency["kind"] == "mode-cleanup"
    ]
    assert mode_dependencies
    assert any(
        mode_change["change_id"] in dependency["required_by"]
        for dependency in mode_dependencies
    )
    desired_channel = device_of(result)["desired"]["port_channels"][0]
    assert desired_channel["settings"]["mode"] == "trunk"
    assert desired_channel["settings"]["access_vlan"] is None
    assert desired_channel["settings"]["native_vlan"] == 10
    assert desired_channel["settings"]["allowed_vlans"] == [10, 20]

    third_plan = copy.deepcopy(second_plan)
    third_plan["port_channels"][0]["settings"] = {
        "mode": "access", "access_vlan": 20,
    }
    for port in third_plan["physical_interfaces"]:
        port["settings"] = {"mode": "access", "access_vlan": 20}
    third = save(client, event_id, third_plan)
    third_intent = intent(client, event_id, third["id"])
    trunk_to_access = next(
        change for change in device_of(third_intent)["changes"]
        if change["target_kind"] == "port-channel" and change["field"] == "mode"
    )
    assert trunk_to_access["transition"] == "trunk-to-access"
    assert "native_vlan" in trunk_to_access["cleanup"]
    assert "allowed_vlans" in trunk_to_access["cleanup"]

    fourth_plan = copy.deepcopy(third_plan)
    fourth_plan["port_channels"][0]["settings"] = {
        "mode": "routed", "address": "10.10.10.1/30",
    }
    for port in fourth_plan["physical_interfaces"]:
        port["settings"] = {"mode": "routed"}
    fourth = save(client, event_id, fourth_plan)
    fourth_intent = intent(client, event_id, fourth["id"])
    routed_change = next(
        change for change in device_of(fourth_intent)["changes"]
        if change["target_kind"] == "port-channel" and change["field"] == "mode"
    )
    assert routed_change["transition"] == "switchport-to-routed"
    assert "access_vlan" in routed_change["cleanup"]
    desired_routed = device_of(fourth_intent)["desired"]["port_channels"][0]
    assert desired_routed["settings"]["routed_address"] == "10.10.10.1/30"
    assert desired_routed["settings"]["access_vlan"] is None

    fifth_plan = copy.deepcopy(fourth_plan)
    fifth_plan["port_channels"][0]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20, 30],
    }
    for port in fifth_plan["physical_interfaces"]:
        port["settings"] = {
            "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20, 30],
        }
    fifth = save(client, event_id, fifth_plan)
    fifth_intent = intent(client, event_id, fifth["id"])
    switchport_change = next(
        change for change in device_of(fifth_intent)["changes"]
        if change["target_kind"] == "port-channel" and change["field"] == "mode"
    )
    assert switchport_change["transition"] == "routed-to-switchport"
    assert "routed_address" in switchport_change["cleanup"]
    desired_switchport = device_of(fifth_intent)["desired"]["port_channels"][0]
    assert desired_switchport["settings"]["routed_address"] is None
    assert desired_switchport["settings"]["mode"] == "trunk"

    sixth_plan = copy.deepcopy(fifth_plan)
    sixth_plan["port_channels"] = []
    sixth_plan["logical_interfaces"] = []
    sixth_plan["physical_interfaces"][0]["settings"] = dict(access_settings)
    sixth_plan["physical_interfaces"][1]["settings"] = dict(access_settings)
    sixth = save(client, event_id, sixth_plan)
    sixth_intent = intent(client, event_id, sixth["id"])
    removal = next(
        change for change in device_of(sixth_intent)["changes"]
        if change["target_kind"] == "port-channel"
    )
    assert removal["transition"] == "port-channel-removed"
    detach_changes = [
        change for change in device_of(sixth_intent)["changes"]
        if change["target_kind"] == "interface"
        and change["field"] == "port_channel"
        and change["transition"] == "port-channel-member-to-independent"
    ]
    assert len(detach_changes) == 2
    removal_dependency = next(
        dependency for dependency in device_of(sixth_intent)["dependencies"]
        if dependency["kind"] == "port-channel-removal"
    )
    assert removal["change_id"] in removal_dependency["required_by"]
    for change in detach_changes:
        assert change["change_id"] in removal_dependency["required_by"]
    desired = device_of(sixth_intent)["desired"]
    assert desired["port_channels"] == []
    assert all(port["port_channel"] is None for port in desired["physical_ports"])


def test_legal_multi_port_stack_members_do_not_conflict(client: TestClient) -> None:
    event_id = event(client)
    plan = make_stack_plan(event_id)
    first_device = plan["physical_devices"][0]["id"]
    second_device = plan["physical_devices"][1]["id"]
    settings = {"mode": "access", "access_vlan": 20}
    plan["physical_interfaces"] = [
        {"id": new_id(), "assignment_id": plan["assignments"][0]["id"],
         "physical_device_id": first_device, "name": "Gi1/0/1",
         "stack_member": 1, "settings": dict(settings)},
        {"id": new_id(), "assignment_id": plan["assignments"][0]["id"],
         "physical_device_id": first_device, "name": "Gi1/0/2",
         "stack_member": 1, "settings": dict(settings)},
        {"id": new_id(), "assignment_id": plan["assignments"][0]["id"],
         "physical_device_id": first_device, "name": "Gi1/0/3",
         "stack_member": 1, "settings": dict(settings)},
        {"id": new_id(), "assignment_id": plan["assignments"][0]["id"],
         "physical_device_id": second_device, "name": "Gi2/0/1",
         "stack_member": 2, "settings": dict(settings)},
        {"id": new_id(), "assignment_id": plan["assignments"][0]["id"],
         "physical_device_id": second_device, "name": "Gi2/0/2",
         "stack_member": 2, "settings": dict(settings)},
    ]
    saved = save(client, event_id, plan)
    result = intent(client, event_id, saved["id"])
    device = device_of(result)
    assert device["identity"]["stack_identity"] == "resolved"
    assert not any(
        conflict["code"] in {"stack-member-conflict", "stack-interface-ownership-mismatch"}
        for conflict in device["conflicts"]
    )
    assert result["readiness"]["structured_intent_valid"] is True

    standalone = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    standalone_saved = save(client, event_id, standalone)
    standalone_intent = intent(client, event_id, standalone_saved["id"])
    assert not any(
        "stack" in conflict["code"]
        for conflict in device_of(standalone_intent)["conflicts"]
    )


def test_inconsistent_stack_interface_ownership_is_reported() -> None:
    event_id = new_id()
    device_a, device_b = new_id(), new_id()
    assignment = new_id()
    first_port, second_port = new_id(), new_id()
    settings = {"mode": "access", "access_vlan": 20}
    plan: dict[str, Any] = {
        "schema_version": 1, "event_id": event_id, "management_vlan": 10,
        "vlans": [{"id": 20, "name": "Players", "purpose": "ordinary"}],
        "physical_devices": [
            {"id": device_a, "vendor": "cisco", "model": "C9300L-24P-4X",
             "verified_serial": serial()},
            {"id": device_b, "vendor": "cisco", "model": "C9300L-24P-4X",
             "verified_serial": serial()},
        ],
        "assignments": [{
            "id": assignment, "hostname": "L2-Stack-Conflict", "role": "access",
            "family": "catalyst-9300", "physical_device_id": device_a,
            "software": {"image": "17.12.4", "license": "Network Advantage"},
        }],
        "stacks": [{
            "assignment_id": assignment,
            "members": [
                {"number": 1, "physical_device_id": device_a, "state": "ready"},
                {"number": 2, "physical_device_id": device_b, "state": "ready"},
            ],
        }],
        "physical_interfaces": [
            {"id": first_port, "assignment_id": assignment,
             "physical_device_id": device_a, "name": "Gi1/0/1",
             "stack_member": 2, "settings": settings},
            {"id": second_port, "assignment_id": assignment,
             "physical_device_id": device_a, "name": "Gi1/0/2",
             "stack_member": 3, "settings": settings},
        ],
    }
    revision = PlanRevision(
        id=UUID(new_id()), number=1, created_at=datetime.now(UTC),
        content_hash="a" * 64, schema_version=1,
        plan=EventPlan.model_validate(plan), warnings=(), validation_errors=(),
        validation_status="VALID_WITH_WARNINGS",
    )
    result = build_layer2_intent(revision, None)
    codes = {conflict.code for conflict in result.devices[0].conflicts}
    assert "stack-interface-ownership-mismatch" in codes
    assert "stack-member-not-in-stack" in codes
    assert result.readiness.structured_intent_valid is False
    assert "structured-intent-invalid" in result.deployment_blockers
    assert result.cli is None
    assert result.executable is False
    assert result.device_writes_enabled is False


def test_unused_port_policy_boundary_and_source_are_explicit(client: TestClient) -> None:
    event_id = event(client)
    plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/2", "settings": {
            "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
        }},
    ])
    saved = save(client, event_id, plan)
    result = intent(client, event_id, saved["id"])
    device = device_of(result)
    policy = device["desired"]["unused_port_policy"]
    assert policy["shutdown"] is True
    assert policy["source"] == "reviewed-default-policy"
    assert policy["requires_field_verification"] is True
    assert "links" in policy["semantics"]
    for port in device["desired"]["physical_ports"]:
        assert port["unused"] is True
        assert port["shutdown_intent"] == "shutdown"
        assert port["shutdown_intent_source"] == "reviewed-default-policy"
    assert sum(
        1 for conflict in device["conflicts"]
        if conflict["code"] == "unused-port-policy-inference"
    ) == 2
    inference = next(
        conflict for conflict in device["conflicts"]
        if conflict["code"] == "unused-port-policy-inference"
    )
    assert inference["severity"] == "WARNING"
    assert "field" in inference["message"].lower() or "site" in inference["message"]
    assert result["readiness"]["structured_intent_valid"] is True
    assert result["readiness"]["hardware_verified"] is False
    assert result["readiness"]["deployment_allowed"] is False
    assert result["verification"] == "not-verified"
    assert result["deployment_status"] == "blocked"


def test_stack_member_add_remove_and_renumber_are_separate(client: TestClient) -> None:
    event_id = event(client)
    first_plan = make_stack_plan(event_id)
    first = save(client, event_id, first_plan)
    access = {"mode": "access", "access_vlan": 20}
    third_device = {
        "id": new_id(), "vendor": "cisco", "model": "C9300L-24P-4X",
        "verified_serial": serial(),
    }
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_devices"].append(third_device)
    second_plan["stacks"][0]["members"].append({
        "number": 3, "physical_device_id": third_device["id"], "state": "ready",
    })
    second_plan["physical_interfaces"].append({
        "id": new_id(), "assignment_id": first_plan["assignments"][0]["id"],
        "physical_device_id": third_device["id"], "name": "Gi3/0/1",
        "stack_member": 3, "settings": dict(access),
    })
    second = save(client, event_id, second_plan)
    added = intent(client, event_id, second["id"])
    assert added["baseline"]["revision_id"] == first["id"]
    added_member = find_change(added, str(first_plan["assignments"][0]["id"]),
                               "stack-member:3:definition")
    assert added_member["transition"] == "stack-member-added"
    assert added_member["after"]["physical_device_id"] == third_device["id"]
    assert len(device_of(added)["identity"]["stack_members"]) == 3
    assert any(
        conflict["code"] == "stack-identity-change-requires-field-verification"
        for conflict in device_of(added)["conflicts"]
    )

    third_plan = copy.deepcopy(second_plan)
    third_plan["physical_devices"] = [
        device for device in third_plan["physical_devices"]
        if device["id"] != third_device["id"]
    ]
    third_plan["stacks"][0]["members"] = [
        member for member in third_plan["stacks"][0]["members"]
        if member["number"] != 3
    ]
    third_plan["physical_interfaces"] = [
        port for port in third_plan["physical_interfaces"]
        if port["name"] != "Gi3/0/1"
    ]
    third_plan["physical_interfaces"][0]["settings"]["description"] = (
        "Field check required"
    )
    third = save(client, event_id, third_plan)
    removed = intent(client, event_id, third["id"])
    assert removed["baseline"]["revision_id"] == second["id"]
    removed_member = find_change(removed, str(first_plan["assignments"][0]["id"]),
                                 "stack-member:3:definition")
    assert removed_member["transition"] == "stack-member-removed"
    assert removed_member["after"] is None
    removed_port = next(
        change for change in device_of(removed)["changes"]
        if change["target_kind"] == "interface"
        and change["field"] == "presence"
        and change["transition"] == "interface-removed"
    )
    assert removed_port["before"] == "present"

    fourth_plan = copy.deepcopy(third_plan)
    for member in fourth_plan["stacks"][0]["members"]:
        if member["number"] == 2:
            member["number"] = 3
    for port in fourth_plan["physical_interfaces"]:
        if port["stack_member"] == 2:
            port["stack_member"] = 3
            port["name"] = "Gi3/0/1"
    fourth = save(client, event_id, fourth_plan)
    renumbered = intent(client, event_id, fourth["id"])
    assert renumbered["baseline"]["revision_id"] == third["id"]
    removed_two = find_change(renumbered, str(first_plan["assignments"][0]["id"]),
                              "stack-member:2:definition")
    added_three = find_change(renumbered, str(first_plan["assignments"][0]["id"]),
                              "stack-member:3:definition")
    assert removed_two["transition"] == "stack-member-removed"
    assert added_three["transition"] == "stack-member-added"
    stack_member_change = next(
        change for change in device_of(renumbered)["changes"]
        if change["target_kind"] == "interface"
        and change["field"] == "stack_member"
    )
    assert (stack_member_change["before"], stack_member_change["after"]) == (2, 3)
    assert stack_member_change["transition"] == "stack-member-change"
    name_change = next(
        change for change in device_of(renumbered)["changes"]
        if change["target_kind"] == "interface" and change["field"] == "name"
    )
    assert (name_change["before"], name_change["after"]) == ("Gi2/0/1", "Gi3/0/1")
    assert name_change["transition"] == "interface-name-change"
    assert renumbered["readiness"]["deployment_allowed"] is False
    assert renumbered["cli"] is None
    assert renumbered["executable"] is False
    assert renumbered["device_writes_enabled"] is False
