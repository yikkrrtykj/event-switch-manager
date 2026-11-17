from __future__ import annotations

import copy
from collections.abc import Iterator
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from test_event_plans import API, ORIGIN

from event_switch_manager.app import create_app
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.planning.plan import EventPlan, PlanRevision
from event_switch_manager.planning.validation import PlanIssue
from event_switch_manager.settings import Settings

CapabilityCheck = dict[str, Any]
Intent = dict[str, Any]


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "layer2-intent.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as session:
        yield session


def new_id() -> str:
    return str(uuid4())


def event(client: TestClient, name: str = "Synthetic Layer 2 intent") -> str:
    response = client.post(f"{API}/events", json={"name": name})
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def serial() -> str:
    return "SYN-L2-" + new_id().replace("-", "")[:8].upper()


def save(client: TestClient, event_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = client.post(f"{API}/events/{event_id}/plan-revisions", json=payload)
    assert response.status_code == 200, response.text
    record = cast(dict[str, Any], response.json())
    return record


def intent(client: TestClient, event_id: str, revision_id: str) -> Intent:
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision_id}/layer2-intent",
    )
    assert response.status_code == 200, response.text
    record = cast(Intent, response.json())
    return record


def make_plan(
    event_id: str,
    *,
    pid: str = "C9300L-24T-4G",
    image: str = "17.12.4",
    license_name: str | None = "Network Advantage",
    family: str = "catalyst-9300",
    model: str | None = None,
    verified_serial: str | None = None,
    with_serial: bool = True,
    ports: list[dict[str, Any]],
    channel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    device_id = new_id()
    assignment_id = new_id()
    port_ids = [new_id() for _ in ports]
    plan: dict[str, Any] = {
        "schema_version": 1, "event_id": event_id, "management_vlan": 10,
        "vlans": [
            {"id": 10, "name": "Management", "purpose": "management"},
            {"id": 20, "name": "Players", "purpose": "ordinary"},
            {"id": 30, "name": "Guest", "purpose": "guest"},
        ],
        "physical_devices": [{
            "id": device_id, "vendor": "cisco",
            "model": pid if model is None else model,
            "verified_serial": (
                verified_serial
                if verified_serial is not None
                else serial() if with_serial else None
            ),
        }],
        "assignments": [{
            "id": assignment_id, "hostname": "L2-Access", "role": "access",
            "family": family, "physical_device_id": device_id,
            "software": (
                None if image is None else {
                    "image": image, "license": license_name,
                }
            ),
        }],
        "physical_interfaces": [
            {
                "id": port_ids[index],
                "assignment_id": assignment_id,
                "physical_device_id": device_id,
                "name": port["name"],
                "settings": port["settings"],
            }
            for index, port in enumerate(ports)
        ],
    }
    if channel is not None:
        logical_id = new_id()
        plan["logical_interfaces"] = [{
            "id": logical_id, "assignment_id": assignment_id,
            "name": "Port-channel1", "kind": "port-channel",
        }]
        plan["port_channels"] = [{
            "interface_id": logical_id,
            "number": channel.get("number", 1),
            "member_ids": [port_ids[index] for index in channel["members"]],
            "settings": channel["settings"],
            "lacp": channel.get("lacp", "active"),
        }]
    return plan


def make_stack_plan(event_id: str, *, pid: str = "C9300L-24P-4X") -> dict[str, Any]:
    first_device, second_device = new_id(), new_id()
    assignment_id = new_id()
    first_port, second_port = new_id(), new_id()
    settings = {"mode": "access", "access_vlan": 20}
    return {
        "schema_version": 1, "event_id": event_id, "management_vlan": 10,
        "vlans": [
            {"id": 10, "name": "Management", "purpose": "management"},
            {"id": 20, "name": "Players", "purpose": "ordinary"},
        ],
        "physical_devices": [
            {"id": first_device, "vendor": "cisco", "model": pid, "verified_serial": serial()},
            {"id": second_device, "vendor": "cisco", "model": pid, "verified_serial": serial()},
        ],
        "assignments": [{
            "id": assignment_id, "hostname": "L2-Stack", "role": "access",
            "family": "catalyst-9300", "physical_device_id": first_device,
            "software": {"image": "17.12.4", "license": "Network Advantage"},
        }],
        "stacks": [{
            "assignment_id": assignment_id,
            "members": [
                {"number": 1, "physical_device_id": first_device, "state": "ready"},
                {"number": 2, "physical_device_id": second_device, "state": "ready"},
            ],
        }],
        "physical_interfaces": [
            {"id": first_port, "assignment_id": assignment_id,
             "physical_device_id": first_device, "name": "Gi1/0/1",
             "stack_member": 1, "settings": dict(settings)},
            {"id": second_port, "assignment_id": assignment_id,
             "physical_device_id": second_device, "name": "Gi2/0/1",
             "stack_member": 2, "settings": dict(settings)},
        ],
    }


def device_intent(result: Intent) -> dict[str, Any]:
    return cast(dict[str, Any], result["devices"][0])


def change_index(result: Intent) -> dict[tuple[str, str], dict[str, Any]]:
    device = device_intent(result)
    return cast(dict[tuple[str, str], dict[str, Any]], {
        (change["target_name"], change["field"]): change
        for change in device["changes"]
    })


def check_of(result: Intent, capability: str, subject: str | None = None) -> CapabilityCheck:
    for check in device_intent(result)["capability_checks"]:
        if check["capability"] == capability and (
            subject is None or check["subject"] == subject
        ):
            return cast(CapabilityCheck, check)
    raise AssertionError(f"Missing capability check {capability} / {subject}")


def test_intent_binds_revision_identity_and_never_claims_device_state(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/2", "settings": {"mode": "trunk", "native_vlan": 10,
                                        "allowed_vlans": [10, 20]}},
    ])
    saved = save(client, event_id, plan)
    export_url = f"{API}/events/{event_id}/plan-revisions/{saved['id']}/export"
    before = client.get(export_url)
    result = intent(client, event_id, saved["id"])

    assert result["source"] == "saved-revision"
    assert result["intent_schema_version"] == 1
    assert result["event_id"] == event_id
    assert result["revision_id"] == saved["id"]
    assert result["revision_hash"] == saved["content_hash"]
    assert result["baseline"] == {
        "source": "none", "revision_id": None, "revision_hash": None,
        "device_state": "unknown",
    }
    assert result["device_state"] == "unknown"
    assert result["before_state_evidence"] == "planning-baseline-unavailable"
    assert len(result["intent_fingerprint"]) == 64
    assert set(result).isdisjoint({"commands", "configuration", "config", "cli_commands"})
    assert result["cli"] is None
    assert result["executable"] is False
    assert result["device_writes_enabled"] is False
    assert result["verification"] == "not-verified"
    assert result["deployment_status"] == "blocked"
    for blocker in (
        "deployment-generation-disabled", "hardware-not-verified",
        "device-state-unknown", "intent-not-deployment-ready",
    ):
        assert blocker in result["deployment_blockers"]
    assert result["readiness"] == {
        "structured_intent_valid": True,
        "vendor_documentation": "supported",
        "hardware_verified": False,
        "deployment_allowed": False,
    }

    device = device_intent(result)
    assert device["identity"]["pid"] == "C9300L-24T-4G"
    assert device["identity"]["pid_evidence"] == "exact-verified-pid"
    assert device["identity"]["software_image"] == "17.12.4"
    assert device["identity"]["software_license"] == "Network Advantage"
    assert device["before"]["source"] == "planning-baseline-unavailable"
    assert device["before"]["device_state"] == "unknown"
    assert device["before"]["state"] is None
    desired = device["desired"]
    assert [vlan["vlan_id"] for vlan in desired["vlans"]] == [10, 20]
    assert desired["spanning_tree"] == {
        "mode": "rapid-pvst", "source": "reviewed-default-policy",
    }
    assert desired["vtp"] == {"mode": "transparent", "source": "reviewed-default-policy"}
    assert desired["root_priority"]["priority"] == 32768
    assert desired["unused_port_policy"]["shutdown"] is True
    ports = {port["name"]: port for port in desired["physical_ports"]}
    assert ports["Gi1/0/1"]["mode"] == "access"
    assert ports["Gi1/0/2"]["allowed_vlans"] == [10, 20]
    assert ports["Gi1/0/2"]["switchport"] is True
    assert all(port["unused"] for port in desired["physical_ports"])

    assert check_of(result, "identity", "L2-Access")["verdict"] == "supported"
    assert check_of(result, "vlan", "L2-Access")["verdict"] == "supported"
    assert check_of(result, "rapid-pvst", "L2-Access")["verdict"] == "supported"

    after = client.get(export_url)
    assert after.content == before.content
    assert after.headers["etag"] == before.headers["etag"]
    assert sha256(after.content).hexdigest() == saved["content_hash"]
    assert len(client.get(f"{API}/events/{event_id}/plan-revisions").json()) == 1


@pytest.mark.parametrize(("pid", "image", "license_name", "family", "documented"), [
    ("WS-C2960X-24TS-L", "15.2(7)E", "LAN Base", "catalyst-2960x", "unknown"),
    ("WS-C3850-24T", "16.12.12", "IP Base", "catalyst-3850", "unknown"),
    ("C9200L-24T-4G", "17.12.4", "Network Advantage", "catalyst-9200", "supported"),
    ("C9300L-24T-4G", "17.12.4", "Network Advantage", "catalyst-9300", "supported"),
    ("C1000-24T-4G-L", "15.2(7)E1", None, "catalyst-c1000", "unknown"),
])
def test_intent_covers_reviewed_cisco_families(
    client: TestClient, pid: str, image: str, license_name: str | None,
    family: str, documented: str,
) -> None:
    event_id = event(client, f"Synthetic Layer 2 {pid}")
    plan = make_plan(
        event_id, pid=pid, image=image, license_name=license_name, family=family,
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
    )
    saved = save(client, event_id, plan)
    first = intent(client, event_id, saved["id"])
    second = intent(client, event_id, saved["id"])
    assert first == second
    assert first["readiness"]["vendor_documentation"] == documented
    assert first["readiness"]["hardware_verified"] is False
    assert first["readiness"]["deployment_allowed"] is False
    assert first["readiness"]["structured_intent_valid"] is True
    identity = device_intent(first)["identity"]
    assert (identity["pid"], identity["software_image"], identity["software_license"]) == (
        pid, image, license_name,
    )
    checks = device_intent(first)["capability_checks"]
    verdicts = {check["verdict"] for check in checks}
    if documented == "supported":
        assert verdicts == {"supported"}
    else:
        assert "unknown" in verdicts
        assert "unsupported" not in verdicts
    assert first["deployment_blockers"][:4] == [
        "deployment-generation-disabled", "hardware-not-verified",
        "device-state-unknown", "intent-not-deployment-ready",
    ]


def test_mode_and_routed_transitions_use_planning_baseline(client: TestClient) -> None:
    event_id = event(client)
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/2", "settings": {"mode": "trunk", "native_vlan": 10,
                                        "allowed_vlans": [10, 20]}},
        {"name": "Gi1/0/3", "settings": {"mode": "routed", "address": "10.0.0.1/30"}},
    ])
    first = save(client, event_id, first_plan)
    first_export = f"{API}/events/{event_id}/plan-revisions/{first['id']}/export"
    first_before = client.get(first_export)
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][0]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
    }
    second_plan["physical_interfaces"][1]["settings"] = {
        "mode": "routed", "address": "10.0.1.1/30",
    }
    second_plan["physical_interfaces"][2]["settings"] = {
        "mode": "access", "access_vlan": 20,
    }
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])

    assert result["before_state_evidence"] == "planning-baseline"
    assert result["baseline"]["source"] == "previous-saved-revision"
    assert result["baseline"]["revision_id"] == first["id"]
    assert result["baseline"]["revision_hash"] == first["content_hash"]
    assert result["baseline"]["device_state"] == "unknown"
    device = device_intent(result)
    assert device["before"]["source"] == "planning-baseline"
    assert device["before"]["state"] is not None
    changes = change_index(result)
    access_to_trunk = changes[("Gi1/0/1", "mode")]
    assert access_to_trunk["transition"] == "access-to-trunk"
    assert access_to_trunk["before"] == "access"
    assert access_to_trunk["after"] == "trunk"
    assert access_to_trunk["before_source"] == "planning-baseline"
    assert access_to_trunk["after_source"] == "event-plan"
    assert "access_vlan" in access_to_trunk["cleanup"]
    assert access_to_trunk["dependencies"]
    switchport_to_routed = changes[("Gi1/0/2", "mode")]
    assert switchport_to_routed["transition"] == "switchport-to-routed"
    assert "native_vlan" in switchport_to_routed["cleanup"]
    routed_to_switchport = changes[("Gi1/0/3", "mode")]
    assert routed_to_switchport["transition"] == "routed-to-switchport"
    assert "routed_address" in routed_to_switchport["cleanup"]
    dependencies = {dependency["kind"] for dependency in device["dependencies"]}
    assert "mode-cleanup" in dependencies
    mode_dependency = next(
        dependency for dependency in device["dependencies"]
        if dependency["kind"] == "mode-cleanup"
    )
    assert "Gi1/0/1" in mode_dependency["target"]
    assert mode_dependency["required_by"]
    first_after = client.get(first_export)
    assert first_after.content == first_before.content
    first_intent = intent(client, event_id, first["id"])
    assert first_intent["baseline"]["source"] == "none"
    assert first_intent["before_state_evidence"] == "planning-baseline-unavailable"


def test_port_channel_membership_and_lacp_transitions(client: TestClient) -> None:
    event_id = event(client)
    independent = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/2", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/3", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    first = save(client, event_id, independent)
    channel_settings = {"mode": "access", "access_vlan": 20}
    active = copy.deepcopy(independent)
    logical_id = new_id()
    active["logical_interfaces"] = [{
        "id": logical_id, "assignment_id": independent["assignments"][0]["id"],
        "name": "Port-channel1", "kind": "port-channel",
    }]
    active["port_channels"] = [{
        "interface_id": logical_id, "number": 1,
        "member_ids": [
            independent["physical_interfaces"][0]["id"],
            independent["physical_interfaces"][1]["id"],
        ],
        "settings": channel_settings, "lacp": "active",
    }]
    second = save(client, event_id, active)
    active_intent = intent(client, event_id, second["id"])
    assert active_intent["baseline"]["revision_id"] == first["id"]
    changes = change_index(active_intent)
    for name in ("Gi1/0/1", "Gi1/0/2"):
        assert changes[(name, "port_channel")]["transition"] == (
            "independent-to-port-channel-member"
        )
        assert changes[(name, "port_channel")]["after"] == 1
    channel_changes = {
        change["field"]: change for change in device_intent(active_intent)["changes"]
        if change["target_kind"] == "port-channel"
    }
    assert len(channel_changes["member_ids"]["after"]) == 2
    assert channel_changes["lacp"]["after"] == "active"
    dependencies = {
        dependency["kind"]
        for dependency in device_intent(active_intent)["dependencies"]
    }
    assert "port-channel-interface" in dependencies
    assert "port-channel-membership" in dependencies
    member_names = device_intent(active_intent)["desired"]["port_channels"][0][
        "member_names"
    ]
    assert sorted(member_names) == ["Gi1/0/1", "Gi1/0/2"]

    passive = copy.deepcopy(active)
    passive["port_channels"][0]["lacp"] = "passive"
    third = save(client, event_id, passive)
    passive_intent = intent(client, event_id, third["id"])
    passive_changes = change_index(passive_intent)
    assert passive_changes[("Port-channel1", "lacp")]["transition"] == (
        "lacp-active-to-passive"
    )

    one_member = copy.deepcopy(passive)
    one_member["port_channels"][0]["member_ids"] = [
        independent["physical_interfaces"][0]["id"],
    ]
    fourth = save(client, event_id, one_member)
    fourth_intent = intent(client, event_id, fourth["id"])
    fourth_changes = change_index(fourth_intent)
    assert fourth_changes[("Gi1/0/2", "port_channel")]["transition"] == (
        "port-channel-member-to-independent"
    )
    assert fourth_changes[("Gi1/0/2", "port_channel")]["after"] is None
    assert fourth_intent["baseline"]["revision_id"] == third["id"]


def test_vlan_stp_power_and_unused_port_policy_intent(client: TestClient) -> None:
    event_id = event(client)
    first_plan = make_plan(event_id, pid="C9300L-24P-4X", ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/2", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/3", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    first = save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][0]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
        "portfast": "edge-trunk", "bpdu_guard": "enabled",
        "description": "Uplink", "admin_state": "up",
        "speed": 1000, "duplex": "full", "poe_mode": "static",
    }
    second_plan["physical_interfaces"][2]["settings"] = {
        "mode": "access", "access_vlan": 20, "admin_state": "up",
    }
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    assert result["baseline"]["revision_id"] == first["id"]
    device = device_intent(result)
    changes = change_index(result)
    for field, transition in (
        ("native_vlan", "native-vlan-change"),
        ("allowed_vlans", "allowed-vlans-change"),
        ("portfast", "spanning-tree-edge-change"),
        ("bpdu_guard", "bpdu-guard-change"),
        ("poe_mode", "poe-mode-change"),
        ("speed", "speed-change"),
        ("duplex", "duplex-change"),
        ("shutdown_intent", "shutdown-intent-change"),
    ):
        assert ("Gi1/0/1", field) in changes
        assert changes[("Gi1/0/1", field)]["transition"] == transition
    desired = device["desired"]
    assert desired["spanning_tree"]["mode"] == "rapid-pvst"
    assert desired["vtp"]["mode"] == "transparent"
    assert desired["root_priority"]["priority"] == 32768
    port_three = next(
        port for port in desired["physical_ports"] if port["name"] == "Gi1/0/3"
    )
    assert port_three["unused"] is True
    assert port_three["shutdown_intent"] == "no-shutdown"
    assert port_three["admin_state"] == "up"
    assert any(
        conflict["code"] == "unused-port-explicitly-enabled"
        and conflict["severity"] == "WARNING"
        for conflict in device["conflicts"]
    )
    assert check_of(result, "poe", "Gi1/0/1")["verdict"] == "supported"
    assert check_of(result, "speed", "Gi1/0/1")["verdict"] == "supported"
    assert check_of(result, "duplex", "Gi1/0/1")["verdict"] == "supported"
    assert result["readiness"]["vendor_documentation"] == "supported"
    assert result["readiness"]["deployment_allowed"] is False


def test_rommon_release_fails_closed_but_keeps_diagnostic_intent(client: TestClient) -> None:
    event_id = event(client)
    plan = make_plan(event_id, image="17.12.2r", ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    saved = save(client, event_id, plan)
    result = intent(client, event_id, saved["id"])
    assert result["readiness"] == {
        "structured_intent_valid": True,
        "vendor_documentation": "unknown",
        "hardware_verified": False,
        "deployment_allowed": False,
    }
    assert result["deployment_status"] == "blocked"
    assert any(
        blocker.startswith("capability-unknown:") for blocker in result["deployment_blockers"]
    )
    check = check_of(result, "vlan", "L2-Access")
    assert (check["verdict"], check["reason_code"]) == ("unknown", "software-is-rommon")
    assert check["evidence"] == []
    assert device_intent(result)["changes"]


def test_unknown_identity_and_optics_fail_closed(client: TestClient) -> None:
    event_id = event(client)
    plan = make_plan(
        event_id, model="Catalyst 9300", verified_serial=None, with_serial=False,
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
    )
    saved = save(client, event_id, plan)
    result = intent(client, event_id, saved["id"])
    identity = device_intent(result)["identity"]
    assert identity["pid"] is None
    assert identity["pid_evidence"] == "model-only"
    assert result["readiness"]["vendor_documentation"] == "unknown"
    check = check_of(result, "identity", "L2-Access")
    assert check["verdict"] == "unknown"

    optics_event = event(client, "Synthetic Layer 2 optics")
    optics_plan = make_plan(optics_event, pid="C9300L-24T-4G", ports=[
        {"name": "Gi1/1/4", "settings": {"mode": "access", "access_vlan": 20,
                                         "speed": 1000}},
    ])
    optics_saved = save(client, optics_event, optics_plan)
    optics = intent(client, optics_event, optics_saved["id"])
    speed = check_of(optics, "speed", "Gi1/1/4")
    assert (speed["verdict"], speed["reason_code"]) == ("unknown", "optic-unknown")
    assert optics["readiness"]["vendor_documentation"] == "unknown"
    assert optics["readiness"]["hardware_verified"] is False
    assert optics["readiness"]["deployment_allowed"] is False


def test_missing_baseline_is_reported_and_old_revision_stays_immutable(
    client: TestClient,
) -> None:
    event_id = event(client)
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    first = save(client, event_id, first_plan)
    first_result = intent(client, event_id, first["id"])
    assert first_result["baseline"]["source"] == "none"
    assert first_result["before_state_evidence"] == "planning-baseline-unavailable"
    assert device_intent(first_result)["before"]["source"] == (
        "planning-baseline-unavailable"
    )
    assert device_intent(first_result)["before"]["state"] is None
    assert all(
        change["before_source"] == "planning-baseline-unavailable"
        for change in device_intent(first_result)["changes"]
    )
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][0]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
    }
    second = save(client, event_id, second_plan)
    second_result = intent(client, event_id, second["id"])
    assert second_result["baseline"]["revision_id"] == first["id"]
    assert device_intent(second_result)["before"]["source"] == "planning-baseline"
    assert first_result == intent(client, event_id, first["id"])


def test_cross_event_isolation_and_export_immutability(client: TestClient) -> None:
    first_event = event(client, "Synthetic Layer 2 event A")
    second_event = event(client, "Synthetic Layer 2 event B")
    first_plan = make_plan(first_event, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    second_plan = make_plan(second_event, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    first = save(client, first_event, first_plan)
    second = save(client, second_event, second_plan)
    first_export = f"{API}/events/{first_event}/plan-revisions/{first['id']}/export"
    second_export = f"{API}/events/{second_event}/plan-revisions/{second['id']}/export"
    first_before = client.get(first_export)
    second_before = client.get(second_export)

    wrong_event = client.get(
        f"{API}/events/{second_event}/plan-revisions/{first['id']}/layer2-intent",
    )
    assert wrong_event.status_code == 404
    wrong_reverse = client.get(
        f"{API}/events/{first_event}/plan-revisions/{second['id']}/layer2-intent",
    )
    assert wrong_reverse.status_code == 404
    result = intent(client, first_event, first["id"])
    assert result["baseline"]["source"] == "none"
    assert result["baseline"]["revision_id"] is None

    assert client.get(first_export).content == first_before.content
    assert client.get(second_export).content == second_before.content
    assert client.get(first_export).headers["etag"] == first_before.headers["etag"]
    assert client.get(second_export).headers["etag"] == second_before.headers["etag"]
    assert len(client.get(f"{API}/events/{first_event}/plan-revisions").json()) == 1
    assert len(client.get(f"{API}/events/{second_event}/plan-revisions").json()) == 1


def test_stack_identity_and_member_interface_binding(client: TestClient) -> None:
    event_id = event(client)
    plan = make_stack_plan(event_id)
    saved = save(client, event_id, plan)
    result = intent(client, event_id, saved["id"])
    identity = device_intent(result)["identity"]
    assert identity["stack_identity"] == "resolved"
    assert [member["number"] for member in identity["stack_members"]] == [1, 2]
    assert all(member["pid"] == "C9300L-24P-4X" for member in identity["stack_members"])
    stack_numbers = [
        port["stack_member"]
        for port in device_intent(result)["desired"]["physical_ports"]
    ]
    assert stack_numbers == [1, 2]
    stack_check = check_of(result, "stack", "L2-Stack")
    assert stack_check["verdict"] == "supported"
    assert result["readiness"]["structured_intent_valid"] is True
    assert result["readiness"]["hardware_verified"] is False
    assert result["readiness"]["deployment_allowed"] is False


def test_structural_conflicts_are_separate_from_capability_evidence() -> None:
    event_id = new_id()
    device_id, assignment_id = new_id(), new_id()
    first_port, second_port = new_id(), new_id()
    settings = {"mode": "access", "access_vlan": 20}
    plan: dict[str, Any] = {
        "schema_version": 1, "event_id": event_id, "management_vlan": 10,
        "vlans": [{"id": 20, "name": "Players", "purpose": "ordinary"}],
        "physical_devices": [{
            "id": device_id, "vendor": "cisco", "model": "C9300L-24T-4G",
            "verified_serial": serial(),
        }],
        "assignments": [{
            "id": assignment_id, "hostname": "L2-Conflict", "role": "access",
            "family": "catalyst-9300", "physical_device_id": device_id,
            "software": {"image": "17.12.4", "license": "Network Advantage"},
        }],
        "physical_interfaces": [
            {"id": first_port, "assignment_id": assignment_id,
             "physical_device_id": device_id, "name": "Gi1/0/1", "settings": settings},
            {"id": second_port, "assignment_id": assignment_id,
             "physical_device_id": device_id, "name": "Gi1/0/2", "settings": settings},
        ],
        "logical_interfaces": [
            {"id": new_id(), "assignment_id": assignment_id,
             "name": "Port-channel1", "kind": "port-channel"},
            {"id": new_id(), "assignment_id": assignment_id,
             "name": "Port-channel2", "kind": "port-channel"},
        ],
        "port_channels": [
            {"interface_id": None, "number": 1, "member_ids": [first_port],
             "settings": settings, "lacp": "active"},
            {"interface_id": None, "number": 1, "member_ids": [first_port],
             "settings": settings, "lacp": "active"},
        ],
    }
    logical_ids = [item["id"] for item in plan["logical_interfaces"]]
    plan["port_channels"][0]["interface_id"] = logical_ids[0]
    plan["port_channels"][1]["interface_id"] = logical_ids[1]
    model = EventPlan.model_validate(plan)
    revision = PlanRevision(
        id=UUID(new_id()),
        number=1,
        created_at=datetime.now(UTC),
        content_hash="a" * 64,
        schema_version=1,
        plan=model,
        warnings=(),
        validation_errors=(),
        validation_status="VALID_WITH_WARNINGS",
    )
    result = build_layer2_intent(revision, None)
    codes = {conflict.code for conflict in result.conflicts}
    assert "port-channel-member-conflict" in codes
    assert "duplicate-port-channel-number" in codes
    assert result.readiness.structured_intent_valid is False
    assert "structured-intent-invalid" in result.deployment_blockers
    assert result.readiness.hardware_verified is False
    assert result.readiness.deployment_allowed is False
    assert result.cli is None
    assert result.executable is False
    assert result.device_writes_enabled is False
    assert all(
        device.capability_checks for device in result.devices
    )

    invalid_revision = revision.model_copy(update={
        "validation_status": "INVALID",
        "validation_errors": (
            PlanIssue(
                path="physical_interfaces.0",
                code="port_mode",
                message="Synthetic invalid intent",
                severity="ERROR",
            ),
        ),
        "warnings": (),
    })
    invalid = build_layer2_intent(invalid_revision, None)
    assert invalid.readiness.structured_intent_valid is False
    assert invalid.readiness.deployment_allowed is False
    assert "plan-invalid" in invalid.deployment_blockers
    assert invalid.cli is None
    assert invalid.executable is False


def test_role_policy_change_is_emitted_for_root_priority(client: TestClient) -> None:
    event_id = event(client)
    first_plan = make_plan(event_id, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    first = save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["assignments"][0]["role"] = "core"
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    assert result["baseline"]["revision_id"] == first["id"]
    changes = change_index(result)
    root_priority = changes[("L2-Access", "root-priority")]
    assert root_priority["before"] == 32768
    assert root_priority["after"] == 4096
    assert root_priority["after_source"] == "reviewed-default-policy"
    device = device_intent(result)
    assert device["desired"]["root_priority"] == {
        "priority": 4096, "source": "reviewed-default-policy", "policy": "role-priority-v1",
    }
    assert device["desired"]["spanning_tree"]["source"] == "reviewed-default-policy"
    assert device["desired"]["vtp"]["source"] == "reviewed-default-policy"
    assert result["readiness"]["structured_intent_valid"] is True


def test_stack_member_interface_ownership_change_is_in_changeset() -> None:
    event_id = new_id()
    first_plan = make_stack_plan(event_id)
    first_state = EventPlan.model_validate(first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][0]["stack_member"] = 2
    second_state = EventPlan.model_validate(second_plan)

    first_revision = PlanRevision(
        id=UUID(new_id()), number=1, created_at=datetime.now(UTC),
        content_hash="a" * 64, schema_version=1, plan=first_state,
        warnings=(), validation_errors=(), validation_status="VALID_WITH_WARNINGS",
    )
    second_revision = PlanRevision(
        id=UUID(new_id()), number=2, created_at=datetime.now(UTC),
        content_hash="b" * 64, schema_version=1, plan=second_state,
        warnings=(), validation_errors=(), validation_status="VALID_WITH_WARNINGS",
    )
    result = build_layer2_intent(second_revision, first_revision)
    changes = {
        (change.target_name, change.field): change
        for change in result.devices[0].changes
    }
    stack_change = changes[("Gi1/0/1", "stack_member")]
    assert stack_change.transition == "stack-member-change"
    assert (stack_change.before, stack_change.after) == (1, 2)
    assert stack_change.dependencies
    dependency_kinds = {dependency.kind for dependency in result.devices[0].dependencies}
    assert "stack-member-binding" in dependency_kinds
    dependent = next(
        dependency for dependency in result.devices[0].dependencies
        if dependency.kind == "stack-member-binding"
    )
    assert stack_change.change_id in dependent.required_by
    assert result.readiness.deployment_allowed is False
    assert result.cli is None
    assert result.executable is False
    assert result.device_writes_enabled is False
