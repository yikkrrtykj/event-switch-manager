"""Dependency completeness regressions for CIS-02A."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from test_event_plans import ORIGIN
from test_layer2_intent import event, intent, make_plan, new_id, save

from event_switch_manager.app import create_app
from event_switch_manager.settings import Settings


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "layer2-dependencies.sqlite3")
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


def all_dependencies(result: dict[str, Any]) -> list[dict[str, Any]]:
    dependencies = list(
        cast(list[dict[str, Any]], result.get("vlan_dependencies", []))
    )
    for device in result["devices"]:
        dependencies.extend(cast(list[dict[str, Any]], device["dependencies"]))
    return dependencies


def find_change(
    result: dict[str, Any], target_id: str, field: str,
) -> dict[str, Any]:
    for change in all_changes(result):
        if change["target_id"] == target_id and change["field"] == field:
            return change
    raise AssertionError(f"Missing change {target_id} / {field}")


def dependency_of(result: dict[str, Any], kind: str, target: str) -> dict[str, Any]:
    for dependency in all_dependencies(result):
        if dependency["kind"] == kind and dependency["target"] == target:
            return dependency
    raise AssertionError(f"Missing dependency {kind} / {target}")


def two_channel_plan(event_id: str) -> dict[str, Any]:
    access = {"mode": "access", "access_vlan": 20}
    plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(access)},
        {"name": "Gi1/0/2", "settings": dict(access)},
        {"name": "Gi1/0/3", "settings": dict(access)},
        {"name": "Gi1/0/4", "settings": dict(access)},
    ])
    first_logical, second_logical = new_id(), new_id()
    assignment = plan["assignments"][0]["id"]
    first, second, third, fourth = (
        port["id"] for port in plan["physical_interfaces"]
    )
    plan["logical_interfaces"] = [
        {"id": first_logical, "assignment_id": assignment,
         "name": "Port-channel1", "kind": "port-channel"},
        {"id": second_logical, "assignment_id": assignment,
         "name": "Port-channel2", "kind": "port-channel"},
    ]
    plan["port_channels"] = [
        {"interface_id": first_logical, "number": 1,
         "member_ids": [first, second], "settings": dict(access), "lacp": "active"},
        {"interface_id": second_logical, "number": 2,
         "member_ids": [third, fourth], "settings": dict(access), "lacp": "active"},
    ]
    return plan


def assert_dependency_graph_consistent(result: dict[str, Any]) -> None:
    changes = {change["change_id"]: change for change in all_changes(result)}
    dependencies = all_dependencies(result)
    assert len({dependency["dependency_id"] for dependency in dependencies}) == len(
        dependencies
    )
    for dependency in dependencies:
        required_by = list(dependency["required_by"])
        assert required_by
        assert len(required_by) == len(set(required_by))
        assert set(required_by) <= set(changes)
    for change in changes.values():
        links = list(change["dependencies"])
        assert len(links) == len(set(links))
        assert links
        for dependency_id in links:
            matching = [
                dependency for dependency in dependencies
                if dependency["dependency_id"] == dependency_id
            ]
            assert len(matching) == 1
            assert change["change_id"] in matching[0]["required_by"]
        assert not set(links) & set(changes)


def test_port_channel_removal_only_binds_own_members(client: TestClient) -> None:
    event_id = event(client)
    first_plan = two_channel_plan(event_id)
    first = save(client, event_id, first_plan)
    first_export = f"/api/v1/events/{event_id}/plan-revisions/{first['id']}/export"
    first_export_before = client.get(first_export)

    second_plan = copy.deepcopy(first_plan)
    second_plan["logical_interfaces"] = [first_plan["logical_interfaces"][1]]
    second_plan["port_channels"] = [{
        **first_plan["port_channels"][1],
        "member_ids": [first_plan["physical_interfaces"][2]["id"]],
    }]
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    device = device_of(result)
    assert result["baseline"]["revision_id"] == first["id"]
    removal = find_change(
        result, str(first_plan["logical_interfaces"][0]["id"]), "presence",
    )
    assert removal["transition"] == "port-channel-removed"
    detach_by_name = {
        change["target_name"]: change
        for change in device["changes"]
        if change["target_kind"] == "interface"
        and change["field"] == "port_channel"
        and change["transition"] == "port-channel-member-to-independent"
    }
    assert set(detach_by_name) == {"Gi1/0/1", "Gi1/0/2", "Gi1/0/4"}
    removal_dependency = dependency_of(result, "port-channel-removal", "Port-channel1")
    expected = {
        removal["change_id"],
        detach_by_name["Gi1/0/1"]["change_id"],
        detach_by_name["Gi1/0/2"]["change_id"],
    }
    assert set(removal_dependency["required_by"]) == expected
    assert detach_by_name["Gi1/0/4"]["change_id"] not in removal_dependency["required_by"]
    assert removal_dependency["dependency_id"] in removal["dependencies"]
    for name in ("Gi1/0/1", "Gi1/0/2"):
        assert removal_dependency["dependency_id"] in detach_by_name[name]["dependencies"]
    assert removal_dependency["dependency_id"] not in detach_by_name["Gi1/0/4"][
        "dependencies"
    ]
    assert device["desired"]["port_channels"][0]["name"] == "Port-channel2"
    assert len(device["desired"]["port_channels"]) == 1
    assert client.get(first_export).content == first_export_before.content
    assert intent(client, event_id, second["id"]) == result
    first_intent = intent(client, event_id, first["id"])
    assert intent(client, event_id, first["id"]) == first_intent


def test_multiple_port_channel_removals_bind_separately(client: TestClient) -> None:
    event_id = event(client)
    first_plan = two_channel_plan(event_id)
    save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["logical_interfaces"] = []
    second_plan["port_channels"] = []
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    device = device_of(result)
    removals = [
        change for change in device["changes"]
        if change["target_kind"] == "port-channel"
        and change["transition"] == "port-channel-removed"
    ]
    assert len(removals) == 2
    detaches = {
        change["target_name"]: change for change in device["changes"]
        if change["target_kind"] == "interface"
        and change["field"] == "port_channel"
        and change["transition"] == "port-channel-member-to-independent"
    }
    first_removal = dependency_of(result, "port-channel-removal", "Port-channel1")
    second_removal = dependency_of(result, "port-channel-removal", "Port-channel2")
    assert set(first_removal["required_by"]) == {
        next(change["change_id"] for change in removals
             if change["target_name"] == "Port-channel1"),
        detaches["Gi1/0/1"]["change_id"],
        detaches["Gi1/0/2"]["change_id"],
    }
    assert set(second_removal["required_by"]) == {
        next(change["change_id"] for change in removals
             if change["target_name"] == "Port-channel2"),
        detaches["Gi1/0/3"]["change_id"],
        detaches["Gi1/0/4"]["change_id"],
    }
    assert not set(first_removal["required_by"]) & set(second_removal["required_by"])
    assert first_removal["dependency_id"] != second_removal["dependency_id"]
    for removal in removals:
        dependency = dependency_of(
            result, "port-channel-removal", removal["target_name"],
        )
        assert dependency["dependency_id"] in removal["dependencies"]
    assert intent(client, event_id, second["id"]) == result


def test_vlan_dependencies_backlink_changes_and_cover_lifecycle(
    client: TestClient,
) -> None:
    event_id = event(client)
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(trunk)},
    ])
    first_plan["vlans"] = [
        {"id": 10, "name": "Management", "purpose": "management"},
        {"id": 20, "name": "Players", "purpose": "ordinary"},
    ]
    first = save(client, event_id, first_plan)

    second_plan = copy.deepcopy(first_plan)
    second_plan["vlans"].append({"id": 40, "name": "Voice", "purpose": "ordinary"})
    second_plan["physical_interfaces"][0]["settings"]["allowed_vlans"] = [10, 20, 40]
    second = save(client, event_id, second_plan)
    created = intent(client, event_id, second["id"])
    assert created["baseline"]["revision_id"] == first["id"]
    create_vlan = find_change(created, "40", "definition")
    assert create_vlan["transition"] == "vlan-created"
    allowed_change = find_change(
        created, str(second_plan["physical_interfaces"][0]["id"]), "allowed_vlans",
    )
    assert (allowed_change["before"], allowed_change["after"]) == (
        [10, 20], [10, 20, 40],
    )
    device_vlans_change = find_change(
        created, str(second_plan["assignments"][0]["id"]), "vlans",
    )
    vlan_dependency = dependency_of(created, "vlan-definition", "vlan:40")
    assert set(vlan_dependency["required_by"]) == {
        create_vlan["change_id"],
        allowed_change["change_id"],
        device_vlans_change["change_id"],
    }
    for change in (create_vlan, allowed_change, device_vlans_change):
        assert vlan_dependency["dependency_id"] in change["dependencies"]
    assert_dependency_graph_consistent(created)

    third_plan = copy.deepcopy(second_plan)
    third_plan["vlans"] = [
        {"id": 10, "name": "Management", "purpose": "management"},
        {"id": 40, "name": "Stage", "purpose": "ordinary"},
        {"id": 50, "name": "Unreferenced", "purpose": "ordinary"},
    ]
    third_plan["physical_interfaces"][0]["settings"]["allowed_vlans"] = [10, 40]
    third = save(client, event_id, third_plan)
    lifecycle = intent(client, event_id, third["id"])
    assert lifecycle["baseline"]["revision_id"] == second["id"]
    renamed = find_change(lifecycle, "40", "name")
    removed = find_change(lifecycle, "20", "definition")
    created_unreferenced = find_change(lifecycle, "50", "definition")
    assert renamed["transition"] == "vlan-renamed"
    assert removed["transition"] == "vlan-removed"
    assert created_unreferenced["transition"] == "vlan-created"
    removed_change = find_change(
        lifecycle, str(second_plan["physical_interfaces"][0]["id"]), "allowed_vlans",
    )
    assert removed_change["before"] == [10, 20, 40]
    assert removed_change["after"] == [10, 40]
    renamed_dependency = dependency_of(lifecycle, "vlan-definition", "vlan:40")
    removed_dependency = dependency_of(lifecycle, "vlan-definition", "vlan:20")
    unreferenced_dependency = dependency_of(lifecycle, "vlan-definition", "vlan:50")
    assert renamed["change_id"] in renamed_dependency["required_by"]
    assert removed["change_id"] in removed_dependency["required_by"]
    assert removed_change["change_id"] in removed_dependency["required_by"]
    assert unreferenced_dependency["required_by"] == [created_unreferenced["change_id"]]
    for change, dependency in (
        (renamed, renamed_dependency),
        (removed, removed_dependency),
        (created_unreferenced, unreferenced_dependency),
    ):
        assert dependency["dependency_id"] in change["dependencies"]
    assert_dependency_graph_consistent(lifecycle)
    assert intent(client, event_id, third["id"]) == lifecycle
