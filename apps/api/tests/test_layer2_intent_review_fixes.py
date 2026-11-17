"""Regression tests for the three post-review P2 contract findings."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from test_event_plans import ORIGIN
from test_layer2_intent import (
    event,
    intent,
    make_plan,
    new_id,
    save,
    serial,
)

from event_switch_manager.app import create_app
from event_switch_manager.settings import Settings


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "layer2-review-fixes.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as session:
        yield session


def device_map(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        cast(dict[str, Any], device)["identity"]["hostname"]: cast(
            dict[str, Any], device,
        )
        for device in result["devices"]
    }


def all_changes(result: dict[str, Any]) -> list[dict[str, Any]]:
    changes = list(cast(list[dict[str, Any]], result.get("vlan_changes", [])))
    for device in result["devices"]:
        changes.extend(cast(list[dict[str, Any]], device["changes"]))
    return changes


def all_dependencies(result: dict[str, Any]) -> list[dict[str, Any]]:
    dependencies = list(
        cast(list[dict[str, Any]], result.get("vlan_dependencies", []))
    )
    for device in result["devices"]:
        dependencies.extend(cast(list[dict[str, Any]], device["dependencies"]))
    return dependencies


def find_change(
    result: dict[str, Any], target_name: str, field: str,
) -> dict[str, Any]:
    for change in all_changes(result):
        if change["target_name"] == target_name and change["field"] == field:
            return change
    raise AssertionError(f"Missing change {target_name} / {field}")


def dependency_rows(
    result: dict[str, Any], kind: str, target: str,
) -> list[dict[str, Any]]:
    return [
        dependency for dependency in all_dependencies(result)
        if dependency["kind"] == kind and dependency["target"] == target
    ]


def device_dependency_rows(
    result: dict[str, Any], hostname: str, kind: str, target: str,
) -> list[dict[str, Any]]:
    return [
        dependency for dependency in device_map(result)[hostname]["dependencies"]
        if dependency["kind"] == kind and dependency["target"] == target
    ]


def dual_assignment_plan(event_id: str) -> dict[str, Any]:
    access = {"mode": "access", "access_vlan": 20}
    physical_devices: list[dict[str, Any]] = []
    assignments: list[dict[str, Any]] = []
    interfaces: list[dict[str, Any]] = []
    for hostname in ("L2-A", "L2-B"):
        device_id, assignment_id = new_id(), new_id()
        physical_devices.append({
            "id": device_id, "vendor": "cisco", "model": "C9300L-24T-4G",
            "verified_serial": serial(),
        })
        assignments.append({
            "id": assignment_id, "hostname": hostname, "role": "access",
            "family": "catalyst-9300", "physical_device_id": device_id,
            "software": {"image": "17.12.4", "license": "Network Advantage"},
        })
        for port_index in range(2):
            interfaces.append({
                "id": new_id(), "assignment_id": assignment_id,
                "physical_device_id": device_id,
                "name": f"Gi1/0/{port_index + 1}",
                "settings": dict(access),
            })
    return {
        "schema_version": 1, "event_id": event_id, "management_vlan": 10,
        "vlans": [
            {"id": 10, "name": "Management", "purpose": "management"},
            {"id": 20, "name": "Players", "purpose": "ordinary"},
        ],
        "physical_devices": physical_devices,
        "assignments": assignments,
        "physical_interfaces": interfaces,
    }


def test_dependency_ids_are_globally_unique_across_assignments(
    client: TestClient,
) -> None:
    event_id = event(client)
    first_plan = dual_assignment_plan(event_id)
    first = save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    for port in second_plan["physical_interfaces"]:
        port["settings"] = {
            "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
        }
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    assert result["baseline"]["revision_id"] == first["id"]

    dependencies = all_dependencies(result)
    dependency_ids = [dependency["dependency_id"] for dependency in dependencies]
    assert len(dependency_ids) == len(set(dependency_ids))
    change_by_id = {change["change_id"]: change for change in all_changes(result)}
    dependency_by_id = {
        dependency["dependency_id"]: dependency for dependency in dependencies
    }
    mode_dependencies = [
        dependency for dependency in dependencies
        if dependency["kind"] == "mode-cleanup"
    ]
    assert len(mode_dependencies) == 4
    assert len({
        dependency["dependency_id"] for dependency in mode_dependencies
    }) == 4
    for dependency in mode_dependencies:
        required_by = dependency["required_by"]
        assert required_by
        assert len(required_by) == len(set(required_by))
        assert set(required_by) <= set(change_by_id)
        device_ids = {
            next(
                device["identity"]["assignment_id"]
                for device in result["devices"]
                if change_by_id[change_id] in device["changes"]
            )
            for change_id in required_by
        }
        assert len(device_ids) == 1
        for change_id in required_by:
            change = change_by_id[change_id]
            assert change["target_kind"] == "interface"
            assert change["field"] == "mode"
            assert change["target_name"] == dependency["target"]
            assert dependency["dependency_id"] in change["dependencies"]
    for change in all_changes(result):
        links = change["dependencies"]
        assert len(links) == len(set(links))
        for dependency_id in links:
            assert dependency_id in dependency_by_id
            assert change["change_id"] in dependency_by_id[dependency_id][
                "required_by"
            ]
    assert intent(client, event_id, second["id"]) == result


def test_channel_member_direct_migration_creates_detach_and_attach_dependencies(
    client: TestClient,
) -> None:
    event_id = event(client)
    access = {"mode": "access", "access_vlan": 20}
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(access)},
        {"name": "Gi1/0/2", "settings": dict(access)},
        {"name": "Gi1/0/3", "settings": dict(access)},
    ])
    first_logical, second_logical = new_id(), new_id()
    assignment = first_plan["assignments"][0]["id"]
    first_port, second_port, third_port = (
        port["id"] for port in first_plan["physical_interfaces"]
    )
    first_plan["logical_interfaces"] = [
        {"id": first_logical, "assignment_id": assignment,
         "name": "Port-channel1", "kind": "port-channel"},
        {"id": second_logical, "assignment_id": assignment,
         "name": "Port-channel2", "kind": "port-channel"},
    ]
    first_plan["port_channels"] = [
        {"interface_id": first_logical, "number": 1,
         "member_ids": [first_port, second_port],
         "settings": dict(access), "lacp": "active"},
        {"interface_id": second_logical, "number": 2,
         "member_ids": [third_port], "settings": dict(access), "lacp": "active"},
    ]
    first = save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["logical_interfaces"] = [first_plan["logical_interfaces"][1]]
    second_plan["port_channels"] = [{
        **first_plan["port_channels"][1],
        "member_ids": [first_port, second_port, third_port],
    }]
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    device = result["devices"][0]
    assert result["baseline"]["revision_id"] == first["id"]
    removal = next(
        change for change in device["changes"]
        if change["target_kind"] == "port-channel"
        and change["target_id"] == first_logical
        and change["transition"] == "port-channel-removed"
    )
    migrations = {
        change["target_name"]: change
        for change in device["changes"]
        if change["target_kind"] == "interface"
        and change["field"] == "port_channel"
        and change["transition"] == "port-channel-member-migrate"
    }
    assert set(migrations) == {"Gi1/0/1", "Gi1/0/2"}
    for name in ("Gi1/0/1", "Gi1/0/2"):
        change = migrations[name]
        assert (change["before"], change["after"]) == (1, 2)
    removal_dependency = next(
        dependency for dependency in device["dependencies"]
        if dependency["kind"] == "port-channel-removal"
        and dependency["target"] == "Port-channel1"
    )
    assert set(removal_dependency["required_by"]) == {
        removal["change_id"],
        migrations["Gi1/0/1"]["change_id"],
        migrations["Gi1/0/2"]["change_id"],
    }
    membership_dependency = next(
        dependency for dependency in device["dependencies"]
        if dependency["kind"] == "port-channel-membership"
        and dependency["target"] == "Port-channel2"
    )
    assert migrations["Gi1/0/1"]["change_id"] in membership_dependency[
        "required_by"
    ]
    assert migrations["Gi1/0/2"]["change_id"] in membership_dependency[
        "required_by"
    ]
    for change in migrations.values():
        assert removal_dependency["dependency_id"] in change["dependencies"]
        assert membership_dependency["dependency_id"] in change["dependencies"]
    assert len(device["desired"]["port_channels"]) == 1
    assert set(device["desired"]["port_channels"][0]["member_ids"]) == {
        first_plan["physical_interfaces"][0]["id"],
        first_plan["physical_interfaces"][1]["id"],
        first_plan["physical_interfaces"][2]["id"],
    }
    assert intent(client, event_id, second["id"]) == result


def test_two_removed_channels_migrate_members_without_cross_binding(
    client: TestClient,
) -> None:
    event_id = event(client)
    access = {"mode": "access", "access_vlan": 20}
    first_plan = make_plan(event_id, ports=[
        {"name": f"Gi1/0/{index + 1}", "settings": dict(access)}
        for index in range(4)
    ])
    assignment = first_plan["assignments"][0]["id"]
    ports = [port["id"] for port in first_plan["physical_interfaces"]]
    first_logical, second_logical = new_id(), new_id()
    first_plan["logical_interfaces"] = [
        {"id": first_logical, "assignment_id": assignment,
         "name": "Port-channel1", "kind": "port-channel"},
        {"id": second_logical, "assignment_id": assignment,
         "name": "Port-channel2", "kind": "port-channel"},
    ]
    first_plan["port_channels"] = [
        {"interface_id": first_logical, "number": 1,
         "member_ids": [ports[0], ports[1]], "settings": dict(access),
         "lacp": "active"},
        {"interface_id": second_logical, "number": 2,
         "member_ids": [ports[2], ports[3]], "settings": dict(access),
         "lacp": "active"},
    ]
    first = save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    target_logical = new_id()
    second_plan["logical_interfaces"] = [{
        "id": target_logical, "assignment_id": assignment,
        "name": "Port-channel3", "kind": "port-channel",
    }]
    second_plan["port_channels"] = [{
        "interface_id": target_logical, "number": 3,
        "member_ids": ports, "settings": dict(access), "lacp": "active",
    }]
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    device = result["devices"][0]
    assert result["baseline"]["revision_id"] == first["id"]
    removals = [
        change for change in device["changes"]
        if change["target_kind"] == "port-channel"
        and change["transition"] == "port-channel-removed"
    ]
    assert {change["target_id"] for change in removals} == {
        first_logical, second_logical,
    }
    migrations = {
        change["target_name"]: change
        for change in device["changes"]
        if change["target_kind"] == "interface"
        and change["field"] == "port_channel"
        and change["transition"] == "port-channel-member-migrate"
    }
    assert set(migrations) == {"Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4"}
    for change in migrations.values():
        assert (change["before"], change["after"]) in {(1, 3), (2, 3)}
    removal_dependencies = {
        dependency["target"]: dependency
        for dependency in device["dependencies"]
        if dependency["kind"] == "port-channel-removal"
    }
    assert set(removal_dependencies) == {
        "Port-channel1", "Port-channel2",
    }
    assert set(removal_dependencies["Port-channel1"]["required_by"]) == {
        next(change["change_id"] for change in removals
             if change["target_id"] == first_logical),
        migrations["Gi1/0/1"]["change_id"],
        migrations["Gi1/0/2"]["change_id"],
    }
    assert set(removal_dependencies["Port-channel2"]["required_by"]) == {
        next(change["change_id"] for change in removals
             if change["target_id"] == second_logical),
        migrations["Gi1/0/3"]["change_id"],
        migrations["Gi1/0/4"]["change_id"],
    }
    assert not (
        set(removal_dependencies["Port-channel1"]["required_by"])
        & set(removal_dependencies["Port-channel2"]["required_by"])
    )
    membership = next(
        dependency for dependency in device["dependencies"]
        if dependency["kind"] == "port-channel-membership"
        and dependency["target"] == "Port-channel3"
    )
    for change in migrations.values():
        assert change["change_id"] in membership["required_by"]
        assert membership["dependency_id"] in change["dependencies"]
    assert intent(client, event_id, second["id"]) == result


def test_channel_member_swap_is_tracked_by_stable_channel_identity(
    client: TestClient,
) -> None:
    event_id = event(client)
    access = {"mode": "access", "access_vlan": 20}
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(access)},
        {"name": "Gi1/0/2", "settings": dict(access)},
        {"name": "Gi1/0/3", "settings": dict(access)},
        {"name": "Gi1/0/4", "settings": dict(access)},
    ])
    first_logical, second_logical = new_id(), new_id()
    assignment = first_plan["assignments"][0]["id"]
    ports = [port["id"] for port in first_plan["physical_interfaces"]]
    first_plan["logical_interfaces"] = [
        {"id": first_logical, "assignment_id": assignment,
         "name": "Port-channel1", "kind": "port-channel"},
        {"id": second_logical, "assignment_id": assignment,
         "name": "Port-channel2", "kind": "port-channel"},
    ]
    first_plan["port_channels"] = [
        {"interface_id": first_logical, "number": 1,
         "member_ids": [ports[0], ports[1]], "settings": dict(access),
         "lacp": "active"},
        {"interface_id": second_logical, "number": 2,
         "member_ids": [ports[2], ports[3]], "settings": dict(access),
         "lacp": "active"},
    ]
    save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["port_channels"][0]["member_ids"] = [ports[2], ports[3]]
    second_plan["port_channels"][1]["member_ids"] = [ports[0], ports[1]]
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    device = result["devices"][0]
    migrations = [
        change for change in device["changes"]
        if change["target_kind"] == "interface"
        and change["field"] == "port_channel"
    ]
    assert len(migrations) == 4
    assert all(
        change["transition"] == "port-channel-member-migrate"
        for change in migrations
    )
    dependencies = {
        (dependency["kind"], dependency["target"]): dependency
        for dependency in device["dependencies"]
    }
    for change in migrations:
        target = f"Port-channel{change['after']}"
        dependency = dependencies[("port-channel-membership", target)]
        assert change["change_id"] in dependency["required_by"]
        assert dependency["dependency_id"] in change["dependencies"]
    assert not any(
        dependency["kind"] == "port-channel-removal"
        for dependency in device["dependencies"]
    )
    desired = {
        channel["interface_id"]: channel["member_ids"]
        for channel in device["desired"]["port_channels"]
    }
    assert set(desired[str(first_logical)]) == {ports[2], ports[3]}
    assert set(desired[str(second_logical)]) == {ports[0], ports[1]}


def test_explicit_admin_state_provenance_and_default_policy_dependency(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = dual_assignment_plan(event_id)
    first_assignment = plan["assignments"][0]["id"]
    a_ports = [
        port for port in plan["physical_interfaces"]
        if port["assignment_id"] == first_assignment
    ]
    other_ports = [
        port for port in plan["physical_interfaces"]
        if port["assignment_id"] != first_assignment
    ]
    plan["links"] = [
        {"id": new_id(), "endpoints": [a_ports[0]["id"], other_ports[0]["id"]]},
        {"id": new_id(), "endpoints": [a_ports[1]["id"], other_ports[1]["id"]]},
    ]
    first = save(client, event_id, plan)

    unlinked_plan = copy.deepcopy(plan)
    unlinked_plan["links"] = []
    unlinked = save(client, event_id, unlinked_plan)
    unlinked_result = intent(client, event_id, unlinked["id"])
    assert unlinked_result["baseline"]["revision_id"] == first["id"]
    policy_changes = {
        change["target_name"]: change
        for change in device_map(unlinked_result)["L2-A"]["changes"]
        if change["field"] == "shutdown_intent"
    }
    assert set(policy_changes) == {"Gi1/0/1", "Gi1/0/2"}
    for change in policy_changes.values():
        assert change["after_source"] == "reviewed-default-policy"
        assert change["dependencies"]
    assert device_dependency_rows(
        unlinked_result, "L2-A", "unused-port-policy", "Gi1/0/1",
    )
    assert device_dependency_rows(
        unlinked_result, "L2-A", "unused-port-policy", "Gi1/0/2",
    )

    explicit_down = copy.deepcopy(unlinked_plan)
    explicit_down["links"] = [
        {"id": new_id(), "endpoints": [a_ports[0]["id"], other_ports[0]["id"]]},
        {"id": new_id(), "endpoints": [a_ports[1]["id"], other_ports[1]["id"]]},
    ]
    explicit_down["physical_interfaces"][0]["settings"]["admin_state"] = "down"
    explicit_down["physical_interfaces"][1]["settings"]["admin_state"] = "up"
    down = save(client, event_id, explicit_down)
    down_result = intent(client, event_id, down["id"])
    down_changes = {
        change["target_name"]: change
        for change in device_map(down_result)["L2-A"]["changes"]
        if change["field"] == "shutdown_intent"
    }
    assert down_changes["Gi1/0/2"]["after"] == "no-shutdown"
    assert down_changes["Gi1/0/2"]["after_source"] == "event-plan"
    assert not device_dependency_rows(
        down_result, "L2-A", "unused-port-policy", "Gi1/0/1",
    )
    assert not device_dependency_rows(
        down_result, "L2-A", "unused-port-policy", "Gi1/0/2",
    )

    explicit_up = copy.deepcopy(explicit_down)
    explicit_up["links"] = [
        {"id": new_id(), "endpoints": [a_ports[0]["id"], other_ports[0]["id"]]},
        {"id": new_id(), "endpoints": [a_ports[1]["id"], other_ports[1]["id"]]},
    ]
    explicit_up["physical_interfaces"][0]["settings"]["admin_state"] = "up"
    explicit_up["physical_interfaces"][1]["settings"]["admin_state"] = "down"
    up = save(client, event_id, explicit_up)
    up_result = intent(client, event_id, up["id"])
    up_changes = {
        change["target_name"]: change
        for change in device_map(up_result)["L2-A"]["changes"]
        if change["field"] == "shutdown_intent"
    }
    assert up_changes["Gi1/0/1"]["after"] == "no-shutdown"
    assert up_changes["Gi1/0/1"]["after_source"] == "event-plan"
    assert up_changes["Gi1/0/2"]["after"] == "shutdown"
    assert up_changes["Gi1/0/2"]["after_source"] == "event-plan"
    assert not device_dependency_rows(
        up_result, "L2-A", "unused-port-policy", "Gi1/0/1",
    )
    assert not device_dependency_rows(
        up_result, "L2-A", "unused-port-policy", "Gi1/0/2",
    )

    unused_explicit = copy.deepcopy(unlinked_plan)
    unused_explicit["physical_interfaces"][0]["settings"]["admin_state"] = "down"
    unused_explicit["physical_interfaces"][1]["settings"]["admin_state"] = "up"
    unused = save(client, event_id, unused_explicit)
    unused_result = intent(client, event_id, unused["id"])
    unused_changes = {
        change["target_name"]: change
        for change in device_map(unused_result)["L2-A"]["changes"]
        if change["field"] == "shutdown_intent"
    }
    assert unused_changes["Gi1/0/2"]["after_source"] == "event-plan"
    assert not device_dependency_rows(
        unused_result, "L2-A", "unused-port-policy", "Gi1/0/1",
    )
    assert not device_dependency_rows(
        unused_result, "L2-A", "unused-port-policy", "Gi1/0/2",
    )


def test_first_revision_explicit_admin_state_uses_event_plan_source(
    client: TestClient,
) -> None:
    event_id = event(client)
    access = {"mode": "access", "access_vlan": 20}
    plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": {**access, "admin_state": "up"}},
        {"name": "Gi1/0/2", "settings": {**access, "admin_state": "down"}},
    ])
    saved = save(client, event_id, plan)
    result = intent(client, event_id, saved["id"])
    changes = {
        change["target_name"]: change
        for change in device_map(result)["L2-Access"]["changes"]
        if change["field"] == "shutdown_intent"
    }
    assert changes["Gi1/0/1"]["after"] == "no-shutdown"
    assert changes["Gi1/0/1"]["after_source"] == "event-plan"
    assert changes["Gi1/0/2"]["after"] == "shutdown"
    assert changes["Gi1/0/2"]["after_source"] == "event-plan"
    assert not dependency_rows(result, "unused-port-policy", "Gi1/0/1")
    assert not dependency_rows(result, "unused-port-policy", "Gi1/0/2")
