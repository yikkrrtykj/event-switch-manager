"""CIS-02B1 hotfix regressions: device VLAN reference additions vs definitions."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from test_event_plans import API, ORIGIN
from test_layer2_config_preview import device_document, item, preview
from test_layer2_intent import event, make_plan, new_id, save

from event_switch_manager.app import create_app
from event_switch_manager.settings import Settings

Device = dict[str, Any]
Item = dict[str, Any]

ACCESS20: dict[str, Any] = {"mode": "access", "access_vlan": 20}
ACCESS30: dict[str, Any] = {"mode": "access", "access_vlan": 30}
ACCESS40: dict[str, Any] = {"mode": "access", "access_vlan": 40}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "vlan-reference-diff.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as session:
        yield session


def first_device(result: dict[str, Any]) -> Device:
    return cast(Device, result["devices"][0])


def device_by_hostname(result: dict[str, Any], hostname: str) -> Device:
    return next(
        device for device in cast(list[Device], result["devices"])
        if device["hostname"] == hostname
    )


def device_vlans_change(device: Device) -> dict[str, Any]:
    return next(
        change for change in cast(list[dict[str, Any]], device["planned_diff"])
        if change["target_kind"] == "device" and change["field"] == "vlans"
    )


def vlan_statements(device: Device) -> list[str]:
    statements = cast(
        list[str], device["human_readable"]["statements"],
    )
    return [statement for statement in statements if statement.startswith("VLAN ")]


def add_assignment(
    plan: dict[str, Any], *, hostname: str, settings: dict[str, Any],
    serial: str,
) -> tuple[dict[str, Any], str]:
    device_id, assignment_id, port_id = new_id(), new_id(), new_id()
    plan["physical_devices"].append({
        "id": device_id, "vendor": "cisco", "model": "C9300L-24P-4X",
        "verified_serial": serial,
    })
    plan["assignments"].append({
        "id": assignment_id, "hostname": hostname, "role": "access",
        "family": "catalyst-9300", "physical_device_id": device_id,
        "software": {"image": "17.12.4", "license": "Network Advantage"},
    })
    plan["physical_interfaces"].append({
        "id": port_id, "assignment_id": assignment_id,
        "physical_device_id": device_id, "name": "Gi1/0/1",
        "settings": dict(settings),
    })
    return plan["physical_devices"][-1], assignment_id


def test_existing_assignment_newly_references_declared_vlan(
    client: TestClient,
) -> None:
    event_id = event(client, "VLAN reference added")
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(ACCESS20)},
        {"name": "Gi1/0/2", "settings": dict(ACCESS20)},
    ])
    first = save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][1]["settings"] = dict(ACCESS30)
    second = save(client, event_id, second_plan)
    result = preview(client, event_id, second["id"])
    device = first_device(result)

    guest = item(device, "Guest", "definition")
    assert guest["planned"] == {
        "value": {"vlan_id": 30, "name": "Guest"},
        "present": True,
        "source": "event-plan",
    }
    assert guest["baseline"] == {
        "state": "not-in-baseline",
        "value": None,
        "revision_id": first["id"],
        "revision_hash": first["content_hash"],
    }
    assert guest["diff"]["changed"] is True
    assert guest["diff"]["transition"] == "vlan-referenced"
    set_change = device_vlans_change(device)
    assert set_change["transition"] == "vlan-set-change"
    assert guest["diff"]["change_id"] == set_change["change_id"]
    assert "planned-difference" in guest["risk"]["codes"]
    assert len(guest["risk"]["codes"]) == len(set(guest["risk"]["codes"]))
    assert device["summary"]["changed_items"] == 2
    statements = vlan_statements(device)
    assert any(
        "VLAN 30" in statement and "vlan-referenced" in statement
        for statement in statements
    )
    assert any("Guest" in statement for statement in statements)
    assert preview(client, event_id, second["id"]) == result
    assert guest["capability"]["verdict"] == "supported"
    assert guest["deployability"]["deployable"] is False
    assert guest["deployability"]["evidence_gate"] == "pass"


def test_existing_assignment_removes_declared_vlan_reference(
    client: TestClient,
) -> None:
    event_id = event(client, "VLAN reference removed")
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(ACCESS20)},
        {"name": "Gi1/0/2", "settings": dict(ACCESS30)},
    ])
    first = save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][1]["settings"] = dict(ACCESS20)
    second = save(client, event_id, second_plan)
    result = preview(client, event_id, second["id"])
    device = first_device(result)

    guest = item(device, "Guest", "definition")
    assert guest["planned"]["present"] is False
    assert guest["planned"]["source"] == "not-in-plan"
    assert guest["baseline"]["state"] == "planning-baseline"
    assert guest["baseline"]["value"] == {"vlan_id": 30, "name": "Guest"}
    assert guest["baseline"]["revision_id"] == first["id"]
    assert guest["diff"]["changed"] is True
    assert guest["diff"]["transition"] == "vlan-unreferenced"
    assert guest["diff"]["change_id"] == device_vlans_change(device)["change_id"]
    assert "planned-difference" in guest["risk"]["codes"]
    assert device["summary"]["changed_items"] == 2
    assert any(
        "VLAN 30" in statement and "vlan-unreferenced" in statement
        for statement in vlan_statements(device)
    )


def test_event_creates_vlan_and_device_references_it_together(
    client: TestClient,
) -> None:
    event_id = event(client, "VLAN created and referenced")
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(ACCESS20)},
        {"name": "Gi1/0/2", "settings": dict(ACCESS20)},
    ])
    save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["vlans"].append({"id": 40, "name": "Temporary", "purpose": "ordinary"})
    second_plan["physical_interfaces"][1]["settings"] = dict(ACCESS40)
    second = save(client, event_id, second_plan)
    result = preview(client, event_id, second["id"])
    device = first_device(result)

    created = item(device, "Temporary", "definition")
    assert created["planned"]["value"] == {"vlan_id": 40, "name": "Temporary"}
    assert created["baseline"]["state"] == "not-in-baseline"
    assert created["diff"]["changed"] is True
    assert created["diff"]["transition"] == "vlan-created"
    event_change = next(
        change for change in cast(
            list[dict[str, Any]], result["vlan_scope"]["changes"],
        ) if change["target_id"] == "40"
    )
    assert event_change["transition"] == "vlan-created"
    assert created["diff"]["change_id"] == event_change["change_id"]
    assert created["diff"]["transition"] != "vlan-referenced"


def test_event_removes_vlan_and_device_reference_together(
    client: TestClient,
) -> None:
    event_id = event(client, "VLAN deleted and unreferenced")
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(ACCESS20)},
        {"name": "Gi1/0/2", "settings": dict(ACCESS20)},
    ])
    first_plan["vlans"].append({"id": 40, "name": "Temporary", "purpose": "ordinary"})
    first_plan["physical_interfaces"][1]["settings"] = dict(ACCESS40)
    save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["vlans"] = [
        vlan for vlan in second_plan["vlans"] if vlan["id"] != 40
    ]
    second_plan["physical_interfaces"][1]["settings"] = dict(ACCESS20)
    second = save(client, event_id, second_plan)
    result = preview(client, event_id, second["id"])
    device = first_device(result)

    removed = item(device, "Temporary", "definition")
    assert removed["planned"]["present"] is False
    assert removed["baseline"]["value"] == {"vlan_id": 40, "name": "Temporary"}
    assert removed["diff"]["changed"] is True
    assert removed["diff"]["transition"] == "vlan-removed"
    event_change = next(
        change for change in cast(
            list[dict[str, Any]], result["vlan_scope"]["changes"],
        ) if change["target_id"] == "40"
    )
    assert event_change["transition"] == "vlan-removed"
    assert removed["diff"]["change_id"] == event_change["change_id"]
    assert removed["diff"]["transition"] != "vlan-unreferenced"


def test_vlan_rename_does_not_become_a_reference_change(
    client: TestClient,
) -> None:
    event_id = event(client, "VLAN rename only")
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(ACCESS20)},
    ])
    save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    for vlan in second_plan["vlans"]:
        if vlan["id"] == 20:
            vlan["name"] = "Team"
    second = save(client, event_id, second_plan)
    result = preview(client, event_id, second["id"])
    device = first_device(result)

    renamed = item(device, "Team", "definition")
    assert renamed["planned"]["value"] == {"vlan_id": 20, "name": "Team"}
    assert renamed["baseline"]["value"] == {"vlan_id": 20, "name": "Players"}
    assert renamed["diff"]["changed"] is True
    assert renamed["diff"]["transition"] == "vlan-renamed"
    assert renamed["diff"]["transition"] != "vlan-referenced"
    assert not any(
        change["field"] == "vlans"
        for change in cast(list[dict[str, Any]], device["planned_diff"])
    )


def test_first_revision_has_no_planning_baseline_and_no_reference_change(
    client: TestClient,
) -> None:
    event_id = event(client, "First revision no baseline")
    saved = save(client, event_id, make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(ACCESS20)},
    ]))
    result = preview(client, event_id, saved["id"])
    device = first_device(result)
    assert result["before_state_evidence"] == "planning-baseline-unavailable"
    assert result["baseline"]["source"] == "none"
    players = item(device, "Players", "definition")
    assert players["baseline"]["state"] == "planning-baseline-unavailable"
    assert players["baseline"]["revision_id"] is None
    assert players["diff"]["changed"] is True
    assert players["diff"]["transition"] == "initial-plan"
    assert players["diff"]["transition"] != "vlan-referenced"
    assert 30 not in {
        candidate["planned"]["value"]["vlan_id"]
        for candidate in cast(list[Item], device["config_items"])
        if candidate["category"] == "vlan" and candidate["planned"]["present"]
    }


def test_new_assignment_initial_intent_is_not_a_reference_change(
    client: TestClient,
) -> None:
    event_id = event(client, "New assignment second revision")
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(ACCESS20)},
    ])
    first = save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    _, second_assignment = add_assignment(
        second_plan, hostname="L2-Late", settings=dict(ACCESS30),
        serial="SYN-L2-REF-LATE",
    )
    second = save(client, event_id, second_plan)
    result = preview(client, event_id, second["id"])
    late = device_by_hostname(result, "L2-Late")

    guest = item(late, "Guest", "definition")
    assert guest["planned"]["present"] is True
    assert guest["planned"]["value"] == {"vlan_id": 30, "name": "Guest"}
    assert guest["baseline"]["state"] == "not-in-baseline"
    assert guest["baseline"]["revision_id"] == first["id"]
    assert guest["diff"]["changed"] is False
    assert guest["diff"]["transition"] is None
    assert guest["diff"]["change_id"] is None
    assert guest["diff"]["transition"] != "vlan-referenced"
    set_change = device_vlans_change(late)
    assert set_change["transition"] == "initial-plan"
    assert guest["diff"]["change_id"] != set_change["change_id"]
    assert late["identity"]["assignment_id"] == second_assignment
    assert device_by_hostname(result, "L2-Access")["summary"]["changed_items"] == 0


def test_only_the_changed_assignment_reports_the_new_reference(
    client: TestClient,
) -> None:
    event_id = event(client, "Two assignments reference isolation")
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(ACCESS20)},
        {"name": "Gi1/0/2", "settings": dict(ACCESS20)},
    ])
    add_assignment(
        first_plan, hostname="L2-B", settings=dict(ACCESS20),
        serial="SYN-L2-REF-B",
    )
    save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][1]["settings"] = dict(ACCESS30)
    second = save(client, event_id, second_plan)
    result = preview(client, event_id, second["id"])
    device_a = device_by_hostname(result, "L2-Access")
    device_b = device_by_hostname(result, "L2-B")

    guest = item(device_a, "Guest", "definition")
    assert guest["diff"]["transition"] == "vlan-referenced"
    assert guest["diff"]["changed"] is True
    assert device_a["summary"]["changed_items"] == 2
    assert not any(
        candidate["category"] == "vlan" and candidate["target_name"] == "Guest"
        for candidate in cast(list[Item], device_b["config_items"])
    )
    assert item(device_b, "Players", "definition")["diff"]["changed"] is False
    assert device_b["summary"]["changed_items"] == 0
    assert device_a["preview_fingerprint"] != device_b["preview_fingerprint"]


def test_second_interface_reference_does_not_duplicate_vlan_definition_change(
    client: TestClient,
) -> None:
    event_id = event(client, "Second interface reference")
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(ACCESS30)},
        {"name": "Gi1/0/2", "settings": dict(ACCESS20)},
        {"name": "Gi1/0/3", "settings": dict(ACCESS20)},
    ])
    save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][1]["settings"] = dict(ACCESS30)
    second = save(client, event_id, second_plan)
    result = preview(client, event_id, second["id"])
    device = first_device(result)

    guest = item(device, "Guest", "definition")
    assert guest["planned"]["present"] is True
    assert guest["baseline"]["state"] == "planning-baseline"
    assert guest["diff"]["changed"] is False
    assert guest["diff"]["transition"] is None
    assert guest["diff"]["change_id"] is None
    assert not any(
        change["field"] == "vlans"
        for change in cast(list[dict[str, Any]], device["planned_diff"])
    )
    changed_access = item(device, "Gi1/0/2", "access_vlan")
    assert changed_access["diff"]["changed"] is True
    assert changed_access["planned"]["value"] == 30
    assert device["summary"]["changed_items"] == 1
    assert not any("VLAN 30" in statement for statement in vlan_statements(device))


def test_repeated_get_and_fingerprints_are_deterministic(
    client: TestClient,
) -> None:
    event_id = event(client, "Reference diff determinism")
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": dict(ACCESS20)},
        {"name": "Gi1/0/2", "settings": dict(ACCESS20)},
    ])
    save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][1]["settings"] = dict(ACCESS30)
    second = save(client, event_id, second_plan)
    url = (
        f"{API}/events/{event_id}/plan-revisions/{second['id']}"
        "/layer2-config-preview"
    )
    first = client.get(url)
    second_response = client.get(url)
    assert first.status_code == second_response.status_code == 200
    assert first.content == second_response.content
    document = cast(dict[str, Any], first.json())
    device = first_device(document)
    assert device["preview_fingerprint"] == preview(
        client, event_id, second["id"],
    )["devices"][0]["preview_fingerprint"]
    assignment_id = device["assignment_id"]
    document_url = (
        f"{API}/events/{event_id}/plan-revisions/{second['id']}"
        f"/layer2-config-preview/devices/{assignment_id}"
    )
    assert client.get(document_url).content == client.get(document_url).content
    device_doc = device_document(
        client, event_id, second["id"], assignment_id,
    )
    assert device_doc["device"]["preview_fingerprint"] == (
        device["preview_fingerprint"]
    )
