"""Final CIS-02A contract regressions: removals, Stack state, static LACP."""

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

import event_switch_manager.planning.layer2_intent as layer2_intent
from event_switch_manager.app import create_app
from event_switch_manager.integrations import Support
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.planning.plan import EventPlan, PlanRevision
from event_switch_manager.settings import Settings


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "layer2-contract.sqlite3")
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


def find_change(
    result: dict[str, Any], target_id: str, field: str,
) -> dict[str, Any]:
    for change in all_changes(result):
        if change["target_id"] == target_id and change["field"] == field:
            return change
    raise AssertionError(f"Missing change {target_id} / {field}")


def assignment(
    idx: int, *, hostname: str, pid: str, family: str, image: str,
    license_name: str | None = "Network Advantage",
) -> dict[str, Any]:
    return {
        "key": idx, "hostname": hostname, "pid": pid, "family": family,
        "image": image, "license": license_name,
    }


def multi_assignment_plan(
    event_id: str, specs: list[dict[str, Any]],
) -> dict[str, Any]:
    vlans = [
        {"id": 10, "name": "Management", "purpose": "management"},
        {"id": 20, "name": "Players", "purpose": "ordinary"},
    ]
    physical_devices: list[dict[str, Any]] = []
    assignments: list[dict[str, Any]] = []
    interfaces: list[dict[str, Any]] = []
    for spec in specs:
        device_id, assignment_id, port_id = new_id(), new_id(), new_id()
        physical_devices.append({
            "id": device_id, "vendor": "cisco", "model": spec["pid"],
            "verified_serial": serial(),
        })
        assignments.append({
            "id": assignment_id, "hostname": spec["hostname"], "role": "access",
            "family": spec["family"], "physical_device_id": device_id,
            "software": {
                "image": spec["image"], "license": spec["license"],
            },
        })
        interfaces.append({
            "id": port_id, "assignment_id": assignment_id,
            "physical_device_id": device_id, "name": "Gi1/0/1",
            "settings": {"mode": "access", "access_vlan": 20},
        })
    return {
        "schema_version": 1, "event_id": event_id, "management_vlan": 10,
        "vlans": vlans, "physical_devices": physical_devices,
        "assignments": assignments, "physical_interfaces": interfaces,
    }


def channel_plan(
    event_id: str,
    *,
    lacp_modes: list[str],
    pid: str = "C1000-24T-4G-L",
    family: str = "catalyst-c1000",
    image: str = "15.2(7)E1",
    license_name: str | None = None,
) -> dict[str, Any]:
    access = {"mode": "access", "access_vlan": 20}
    port_count = len(lacp_modes) * 2
    plan = make_plan(
        event_id, pid=pid, image=image, license_name=license_name, family=family,
        ports=[
            {"name": f"Gi1/0/{index + 1}", "settings": dict(access)}
            for index in range(port_count)
        ],
    )
    logicals = []
    channels = []
    for channel_index, mode in enumerate(lacp_modes):
        logical_id = new_id()
        logicals.append({
            "id": logical_id,
            "assignment_id": plan["assignments"][0]["id"],
            "name": f"Port-channel{channel_index + 1}",
            "kind": "port-channel",
        })
        channels.append({
            "interface_id": logical_id,
            "number": channel_index + 1,
            "member_ids": [
                plan["physical_interfaces"][channel_index * 2]["id"],
                plan["physical_interfaces"][channel_index * 2 + 1]["id"],
            ],
            "settings": dict(access),
            "lacp": mode,
        })
    plan["logical_interfaces"] = logicals
    plan["port_channels"] = channels
    return plan


def test_removed_assignment_is_recorded_with_baseline_identity(
    client: TestClient,
) -> None:
    event_id = event(client)
    first_plan = multi_assignment_plan(event_id, [
        assignment(1, hostname="L2-A", pid="C9300L-24T-4G",
                   family="catalyst-9300", image="17.12.4"),
        assignment(2, hostname="L2-B", pid="C9200L-24T-4G",
                   family="catalyst-9200", image="17.12.4"),
    ])
    first = save(client, event_id, first_plan)
    first_intent = intent(client, event_id, first["id"])
    assert first_intent["removed_assignments"] == []
    first_export_url = (
        f"/api/v1/events/{event_id}/plan-revisions/{first['id']}/export"
    )
    first_export = client.get(first_export_url)
    first_identity = device_map(first_intent)["L2-B"]["identity"]

    second_plan = copy.deepcopy(first_plan)
    second_plan["assignments"] = [first_plan["assignments"][0]]
    second_plan["physical_devices"] = [first_plan["physical_devices"][0]]
    second_plan["physical_interfaces"] = [first_plan["physical_interfaces"][0]]
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    assert result["baseline"]["revision_id"] == first["id"]
    assert result["baseline"]["revision_hash"] == first["content_hash"]
    assert set(device_map(result)) == {"L2-A"}
    removed = result["removed_assignments"]
    assert len(removed) == 1
    entry = removed[0]
    assert entry["transition"] == "assignment-removed"
    assert entry["assignment_id"] == first_identity["assignment_id"]
    assert entry["identity"]["assignment_id"] == first_identity["assignment_id"]
    assert entry["identity"]["hostname"] == "L2-B"
    assert entry["identity"]["pid"] == "C9200L-24T-4G"
    assert entry["identity"]["family"] == "catalyst-9200"
    assert entry["identity"]["software_image"] == "17.12.4"
    assert entry["baseline_revision_id"] == first["id"]
    assert entry["baseline_revision_hash"] == first["content_hash"]
    assert entry["before_source"] == "planning-baseline"
    assert entry["after"] is None
    assert entry["after_exists"] is False
    assert entry["requires_field_verification"] is True
    assert "planning" in entry["note"].lower()
    assert "wipe" in entry["note"].lower() or "clear" in entry["note"].lower()
    assert entry["change_id"].startswith("chg-")
    assert any(
        conflict["code"] == "assignment-removed-requires-field-verification"
        for conflict in result["conflicts"]
    )
    removed_id = str(entry["assignment_id"])
    assert f"assignment-removal-requires-field-verification:{removed_id}" in (
        result["deployment_blockers"]
    )
    assert f"device-wipe-not-authorized:{removed_id}" in result["deployment_blockers"]
    assert not any(
        check["subject"] == "L2-B"
        for device in result["devices"]
        for check in device["capability_checks"]
    )
    assert result["devices"][0]["desired"] == first_intent["devices"][0]["desired"]
    assert result["devices"][0]["changes"] == []
    assert result["readiness"]["structured_intent_valid"] is True
    assert result["readiness"]["hardware_verified"] is False
    assert result["readiness"]["deployment_allowed"] is False
    assert client.get(first_export_url).content == first_export.content
    assert intent(client, event_id, first["id"]) == first_intent
    assert intent(client, event_id, second["id"]) == result
    assert len(client.get(f"/api/v1/events/{event_id}/plan-revisions").json()) == 2


def test_assignment_removal_delete_all_and_retain_multiple(
    client: TestClient,
) -> None:
    event_id = event(client)
    first_plan = multi_assignment_plan(event_id, [
        assignment(1, hostname="L2-A", pid="C9300L-24T-4G",
                   family="catalyst-9300", image="17.12.4"),
        assignment(2, hostname="L2-B", pid="C9200L-24T-4G",
                   family="catalyst-9200", image="17.12.4"),
        assignment(3, hostname="L2-C", pid="C9300L-24T-4G",
                   family="catalyst-9300", image="17.12.4"),
    ])
    first = save(client, event_id, first_plan)
    first_intent = intent(client, event_id, first["id"])
    second_plan = copy.deepcopy(first_plan)
    removed_interface = first_plan["physical_interfaces"][1]
    removed_device = first_plan["physical_devices"][1]
    second_plan["assignments"] = [
        first_plan["assignments"][0], first_plan["assignments"][2],
    ]
    second_plan["physical_devices"] = [
        first_plan["physical_devices"][0], first_plan["physical_devices"][2],
    ]
    second_plan["physical_interfaces"] = [
        first_plan["physical_interfaces"][0], first_plan["physical_interfaces"][2],
    ]
    assert removed_interface["id"] not in {
        port["id"] for port in second_plan["physical_interfaces"]
    }
    assert removed_device["id"] not in {
        device["id"] for device in second_plan["physical_devices"]
    }
    second = save(client, event_id, second_plan)
    partial = intent(client, event_id, second["id"])
    assert set(device_map(partial)) == {"L2-A", "L2-C"}
    assert [entry["identity"]["hostname"] for entry in partial["removed_assignments"]] == [
        "L2-B",
    ]
    for retained in ("L2-A", "L2-C"):
        assert device_map(partial)[retained]["desired"] == (
            device_map(first_intent)[retained]["desired"]
        )

    third_plan = copy.deepcopy(second_plan)
    third_plan["assignments"] = []
    third_plan["physical_devices"] = []
    third_plan["physical_interfaces"] = []
    third = save(client, event_id, third_plan)
    empty = intent(client, event_id, third["id"])
    assert empty["devices"] == []
    assert {
        entry["identity"]["hostname"] for entry in empty["removed_assignments"]
    } == {"L2-A", "L2-C"}
    assert {entry["assignment_id"] for entry in empty["removed_assignments"]} == {
        entry["identity"]["assignment_id"] for entry in first_intent["devices"]
        if entry["identity"]["hostname"] in {"L2-A", "L2-C"}
    }
    for entry in empty["removed_assignments"]:
        assert entry["before_source"] == "planning-baseline"
        assert entry["after_exists"] is False
    assert empty["deployment_blockers"]
    assert empty["readiness"]["vendor_documentation"] == "unknown"
    assert empty["readiness"]["hardware_verified"] is False
    assert empty["readiness"]["deployment_allowed"] is False
    assert empty["verification"] == "not-verified"
    assert empty["cli"] is None
    assert empty["executable"] is False
    assert empty["device_writes_enabled"] is False


def test_removed_then_recreated_same_hostname_is_new_assignment(
    client: TestClient,
) -> None:
    event_id = event(client)
    first_plan = multi_assignment_plan(event_id, [
        assignment(1, hostname="L2-A", pid="C9300L-24T-4G",
                   family="catalyst-9300", image="17.12.4"),
        assignment(2, hostname="L2-B", pid="C9200L-24T-4G",
                   family="catalyst-9200", image="17.12.4"),
    ])
    save(client, event_id, first_plan)
    old_assignment = first_plan["assignments"][1]
    replacement_device, replacement_assignment, replacement_port = (
        new_id(), new_id(), new_id(),
    )
    second_plan = copy.deepcopy(first_plan)
    second_plan["assignments"] = [first_plan["assignments"][0]]
    second_plan["physical_devices"] = [first_plan["physical_devices"][0]]
    second_plan["physical_interfaces"] = [first_plan["physical_interfaces"][0]]
    second_plan["physical_devices"].append({
        "id": replacement_device, "vendor": "cisco",
        "model": "C9200L-24T-4G", "verified_serial": serial(),
    })
    second_plan["assignments"].append({
        "id": replacement_assignment, "hostname": "L2-B", "role": "access",
        "family": "catalyst-9200", "physical_device_id": replacement_device,
        "software": {"image": "17.12.4", "license": "Network Advantage"},
    })
    second_plan["physical_interfaces"].append({
        "id": replacement_port, "assignment_id": replacement_assignment,
        "physical_device_id": replacement_device, "name": "Gi1/0/1",
        "settings": {"mode": "access", "access_vlan": 20},
    })
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    assert set(device_map(result)) == {"L2-A", "L2-B"}
    new_identity = device_map(result)["L2-B"]["identity"]
    assert new_identity["assignment_id"] == replacement_assignment
    assert new_identity["physical_device_id"] == replacement_device
    assert device_map(result)["L2-B"]["before"]["source"] == "not-in-baseline"
    removed = result["removed_assignments"]
    assert len(removed) == 1
    assert removed[0]["identity"]["hostname"] == "L2-B"
    assert removed[0]["assignment_id"] == old_assignment["id"]
    assert removed[0]["assignment_id"] != replacement_assignment
    assert result["device_state"] == "unknown"
    assert result["readiness"]["hardware_verified"] is False


def test_assignment_hostname_rename_is_not_removal(client: TestClient) -> None:
    event_id = event(client)
    first_plan = multi_assignment_plan(event_id, [
        assignment(1, hostname="L2-A", pid="C9300L-24T-4G",
                   family="catalyst-9300", image="17.12.4"),
        assignment(2, hostname="L2-B", pid="C9200L-24T-4G",
                   family="catalyst-9200", image="17.12.4"),
    ])
    save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["assignments"][1]["hostname"] = "L2-B-Renamed"
    second = save(client, event_id, second_plan)
    result = intent(client, event_id, second["id"])
    assert result["removed_assignments"] == []
    assert set(device_map(result)) == {"L2-A", "L2-B-Renamed"}
    assert device_map(result)["L2-B-Renamed"]["identity"]["assignment_id"] == (
        first_plan["assignments"][1]["id"]
    )
    assert not any(
        conflict["code"] == "assignment-removed-requires-field-verification"
        for conflict in result["conflicts"]
    )


def test_stack_member_state_changes_are_tracked_without_hardware_claim(
    client: TestClient,
) -> None:
    event_id = event(client)
    first_plan = make_stack_plan(event_id)
    first = save(client, event_id, first_plan)

    def save_state(sequence: int, state: str) -> dict[str, Any]:
        plan = copy.deepcopy(first_plan)
        plan["stacks"][0]["members"][1]["state"] = state
        plan["physical_interfaces"][0]["settings"]["description"] = (
            f"state sequence {sequence}"
        )
        return save(client, event_id, plan)

    missing = save_state(1, "missing")
    missing_result = intent(client, event_id, missing["id"])
    assert missing_result["baseline"]["revision_id"] == first["id"]
    state_change = find_change(
        missing_result, str(missing_result["devices"][0]["identity"]["assignment_id"]),
        "stack-member:2:state",
    )
    assert (state_change["before"], state_change["after"]) == ("ready", "missing")
    assert state_change["transition"] == "stack-member-state-change"
    assert device_map(missing_result)["L2-Stack"]["identity"]["stack_members"][1][
        "state"
    ] == "missing"
    assert any(
        conflict["code"] in {
            "stack-member-state-change-requires-field-verification",
            "stack-member-not-ready",
        }
        for conflict in missing_result["conflicts"]
    )
    assert any(
        blocker.startswith("field-verification-required:stack-member-state")
        for blocker in missing_result["deployment_blockers"]
    )
    assert missing_result["readiness"]["hardware_verified"] is False
    assert missing_result["readiness"]["deployment_allowed"] is False
    assert missing_result["device_state"] == "unknown"

    recovered = save_state(2, "ready")
    recovered_result = intent(client, event_id, recovered["id"])
    recovered_change = find_change(
        recovered_result,
        str(recovered_result["devices"][0]["identity"]["assignment_id"]),
        "stack-member:2:state",
    )
    assert (recovered_change["before"], recovered_change["after"]) == (
        "missing", "ready",
    )
    assert recovered_change["transition"] == "stack-member-state-change"
    assert any(
        conflict["code"] == "stack-member-state-change-requires-field-verification"
        for conflict in recovered_result["conflicts"]
    )
    assert recovered_result["readiness"]["hardware_verified"] is False

    unknown = save_state(3, "unknown")
    unknown_result = intent(client, event_id, unknown["id"])
    assert find_change(
        unknown_result,
        str(unknown_result["devices"][0]["identity"]["assignment_id"]),
        "stack-member:2:state",
    )["after"] == "unknown"
    assert any(
        conflict["code"] == "stack-member-not-ready"
        for conflict in unknown_result["conflicts"]
    )
    unknown_ready = save_state(4, "ready")
    unknown_ready_result = intent(client, event_id, unknown_ready["id"])
    unknown_ready_change = find_change(
        unknown_ready_result,
        str(unknown_ready_result["devices"][0]["identity"]["assignment_id"]),
        "stack-member:2:state",
    )
    assert (unknown_ready_change["before"], unknown_ready_change["after"]) == (
        "unknown", "ready",
    )
    assert any(
        conflict["code"] == "stack-member-state-change-requires-field-verification"
        for conflict in unknown_ready_result["conflicts"]
    )
    assert unknown_ready_result["readiness"]["hardware_verified"] is False


def test_stack_member_identity_incomplete_is_not_healthy() -> None:
    event_id = new_id()
    plan = make_stack_plan(event_id)
    plan["physical_devices"][1]["model"] = "Catalyst 9300"
    plan["physical_devices"][1].pop("verified_serial")
    model = EventPlan.model_validate(plan)
    revision = PlanRevision(
        id=UUID(new_id()), number=1, created_at=datetime.now(UTC),
        content_hash="a" * 64, schema_version=1, plan=model,
        warnings=(), validation_errors=(), validation_status="VALID_WITH_WARNINGS",
    )
    result = build_layer2_intent(revision, None)
    device = result.devices[0]
    assert device.identity.stack_identity == "unresolved"
    assert any(
        conflict.code == "stack-member-identity-incomplete"
        for conflict in device.conflicts
    )
    assert device.readiness.hardware_verified is False
    assert device.readiness.deployment_allowed is False
    assert any(
        blocker.startswith("field-verification-required:stack-member-identity")
        for blocker in result.deployment_blockers
    )


def test_static_port_channel_does_not_require_lacp(client: TestClient) -> None:
    event_id = event(client)
    static_plan = channel_plan(event_id, lacp_modes=["static"])
    static = save(client, event_id, static_plan)
    static_result = intent(client, event_id, static["id"])
    static_checks = [
        check for check in device_map(static_result)["L2-Access"][
            "capability_checks"
        ]
    ]
    assert all(check["capability"] != "lacp" for check in static_checks)
    assert any(check["capability"] == "port-channel" for check in static_checks)
    assert static_result["readiness"]["vendor_documentation"] == "unknown"
    assert static_result["readiness"]["deployment_allowed"] is False

    for mode in ("active", "passive"):
        mode_event = event(client, f"Static {mode} comparison")
        mode_plan = channel_plan(mode_event, lacp_modes=[mode])
        mode_saved = save(client, mode_event, mode_plan)
        mode_result = intent(client, mode_event, mode_saved["id"])
        assert any(
            check["capability"] == "lacp"
            for check in device_map(mode_result)["L2-Access"]["capability_checks"]
        )

    mixed_event = event(client, "Static mixed comparison")
    mixed_plan = channel_plan(mixed_event, lacp_modes=["static", "active"])
    mixed = save(client, mixed_event, mixed_plan)
    mixed_result = intent(client, mixed_event, mixed["id"])
    assert any(
        check["capability"] == "lacp"
        for check in device_map(mixed_result)["L2-Access"]["capability_checks"]
    )

    rommon_event = event(client, "Static ROMMON comparison")
    rommon_plan = channel_plan(
        rommon_event, lacp_modes=["static"], pid="C9300L-24T-4G",
        family="catalyst-9300", image="17.12.2r",
        license_name="Network Advantage",
    )
    rommon = save(client, rommon_event, rommon_plan)
    rommon_result = intent(client, rommon_event, rommon["id"])
    assert all(
        check["capability"] != "lacp"
        for check in device_map(rommon_result)["L2-Access"]["capability_checks"]
    )
    assert rommon_result["readiness"]["vendor_documentation"] == "unknown"

    license_event = event(client, "Static unknown-license comparison")
    license_plan = channel_plan(
        license_event, lacp_modes=["static"], pid="C9300L-24T-4G",
        family="catalyst-9300", image="17.12.4", license_name=None,
    )
    unknown_license = save(client, license_event, license_plan)
    unknown_license_result = intent(client, license_event, unknown_license["id"])
    assert all(
        check["capability"] != "lacp"
        for check in device_map(unknown_license_result)["L2-Access"][
            "capability_checks"
        ]
    )
    assert unknown_license_result["readiness"]["vendor_documentation"] == "unknown"


def test_synthetic_unsupported_capability_is_not_promoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SyntheticDecision:
        def __init__(self, verdict: Support) -> None:
            self.verdict = verdict
            self.reason_code = "synthetic-unsupported"
            self.reason = "Synthetic unit-test evidence."
            self.evidence = ()

    def build(
        mode: str, unsupported: set[str] | None = None,
        unknown: set[str] | None = None,
    ) -> Any:
        unsupported = unsupported or set()
        unknown = unknown or set()
        plan = channel_plan(new_id(), lacp_modes=[mode])
        revision = PlanRevision(
            id=UUID(new_id()), number=1, created_at=datetime.now(UTC),
            content_hash="b" * 64, schema_version=1,
            plan=EventPlan.model_validate(plan), warnings=(),
            validation_errors=(), validation_status="VALID_WITH_WARNINGS",
        )

        def fake_resolve(
            _revision: PlanRevision, _assignment_id: UUID, capability: Any,
            **kwargs: Any,
        ) -> SyntheticDecision:
            del _revision, _assignment_id, kwargs
            value = str(capability.value)
            if value in unsupported:
                return SyntheticDecision(Support.UNSUPPORTED)
            if value in unknown:
                return SyntheticDecision(Support.UNKNOWN)
            return SyntheticDecision(Support.SUPPORTED)

        monkeypatch.setattr(layer2_intent, "resolve_capability", fake_resolve)
        return build_layer2_intent(revision, None)

    static_result = build("static", {"port-channel"})
    static_device = static_result.devices[0]
    assert not any(
        check.capability.value == "lacp"
        for check in static_device.capability_checks
    )
    assert any(
        check.capability.value == "port-channel"
        and check.verdict is Support.UNSUPPORTED
        for check in static_device.capability_checks
    )
    assert static_result.readiness.vendor_documentation.value == "unsupported"
    assert any(
        blocker.startswith("capability-unsupported:port-channel:")
        for blocker in static_result.deployment_blockers
    )

    active_result = build("active", {"lacp"})
    active_device = active_result.devices[0]
    assert any(
        check.capability.value == "lacp"
        and check.verdict is Support.UNSUPPORTED
        for check in active_device.capability_checks
    )
    assert active_result.readiness.vendor_documentation.value == "unsupported"
    assert active_result.readiness.deployment_allowed is False

    unknown_result = build("static", unknown={"port-channel"})
    unknown_device = unknown_result.devices[0]
    assert not any(
        check.capability.value == "lacp"
        for check in unknown_device.capability_checks
    )
    assert any(
        check.capability.value == "port-channel"
        and check.verdict is Support.UNKNOWN
        for check in unknown_device.capability_checks
    )
    assert unknown_result.readiness.vendor_documentation.value == "unknown"
    assert unknown_result.readiness.deployment_allowed is False


def test_revision_difference_matrix_is_traceable() -> None:
    event_id = new_id()
    first_device, second_device, fourth_device = new_id(), new_id(), new_id()
    second_assignment_device = new_id()
    first_assignment = new_id()
    second_assignment = new_id()
    first_port, second_port, fourth_port = new_id(), new_id(), new_id()
    second_assignment_port = new_id()
    first_logical, second_logical = new_id(), new_id()
    access = {"mode": "access", "access_vlan": 20}
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    first: dict[str, Any] = {
        "schema_version": 1, "event_id": event_id, "management_vlan": 10,
        "vlans": [
            {"id": 10, "name": "Management", "purpose": "management"},
            {"id": 20, "name": "Players", "purpose": "ordinary"},
            {"id": 30, "name": "Removed", "purpose": "ordinary"},
        ],
        "physical_devices": [
            {"id": first_device, "vendor": "cisco", "model": "C9300L-24P-4X",
             "verified_serial": serial()},
            {"id": second_device, "vendor": "cisco", "model": "C9300L-24P-4X",
             "verified_serial": serial()},
            {"id": fourth_device, "vendor": "cisco", "model": "C9300L-24P-4X",
             "verified_serial": serial()},
            {"id": second_assignment_device, "vendor": "cisco",
             "model": "C9200L-24T-4G", "verified_serial": serial()},
        ],
        "assignments": [
            {"id": first_assignment, "hostname": "L2-Stack", "role": "access",
             "family": "catalyst-9300", "physical_device_id": first_device,
             "software": {"image": "17.12.4", "license": "Network Advantage"}},
            {"id": second_assignment, "hostname": "L2-B", "role": "access",
             "family": "catalyst-9200",
             "physical_device_id": second_assignment_device,
             "software": {"image": "17.12.4", "license": "Network Advantage"}},
        ],
        "stacks": [{
            "assignment_id": first_assignment,
            "members": [
                {"number": 1, "physical_device_id": first_device, "state": "ready"},
                {"number": 2, "physical_device_id": second_device, "state": "ready"},
                {"number": 4, "physical_device_id": fourth_device, "state": "ready"},
            ],
        }],
        "physical_interfaces": [
            {"id": first_port, "assignment_id": first_assignment,
             "physical_device_id": first_device, "name": "Gi1/0/1",
             "stack_member": 1, "settings": dict(access)},
            {"id": second_port, "assignment_id": first_assignment,
             "physical_device_id": second_device, "name": "Gi2/0/1",
             "stack_member": 2, "settings": dict(trunk)},
            {"id": fourth_port, "assignment_id": first_assignment,
             "physical_device_id": fourth_device, "name": "Gi4/0/1",
             "stack_member": 4, "settings": dict(access)},
            {"id": second_assignment_port, "assignment_id": second_assignment,
             "physical_device_id": second_assignment_device, "name": "Gi1/0/1",
             "settings": dict(access)},
        ],
        "logical_interfaces": [
            {"id": first_logical, "assignment_id": first_assignment,
             "name": "Port-channel1", "kind": "port-channel"},
            {"id": second_logical, "assignment_id": first_assignment,
             "name": "Port-channel2", "kind": "port-channel"},
        ],
        "port_channels": [
            {"interface_id": first_logical, "number": 1,
             "member_ids": [second_port], "settings": dict(trunk),
             "lacp": "active"},
            {"interface_id": second_logical, "number": 2,
             "member_ids": [fourth_port], "settings": dict(access),
             "lacp": "active"},
        ],
    }
    replacement_device = new_id()
    replacement_assignment = new_id()
    added_third_device = new_id()
    added_third_port = new_id()
    added_logical = new_id()
    second: dict[str, Any] = copy.deepcopy(first)
    second["vlans"] = [
        {"id": 10, "name": "Management", "purpose": "management"},
        {"id": 20, "name": "Competitors", "purpose": "ordinary"},
        {"id": 40, "name": "Voice", "purpose": "ordinary"},
    ]
    second["physical_devices"] = [
        {"id": replacement_device, "vendor": "cisco",
         "model": "C9300L-24P-4X", "verified_serial": serial()},
        first["physical_devices"][1],
        first["physical_devices"][2],
        {"id": added_third_device, "vendor": "cisco",
         "model": "C9300L-24P-4X", "verified_serial": serial()},
        {"id": second_assignment_device, "vendor": "cisco",
         "model": "C9200L-24T-4G", "verified_serial": serial()},
    ]
    second["assignments"] = [
        {"id": first_assignment, "hostname": "L2-Stack", "role": "access",
         "family": "catalyst-9300", "physical_device_id": replacement_device,
         "software": {"image": "17.12.4", "license": "Network Advantage"}},
        {"id": replacement_assignment, "hostname": "L2-C", "role": "access",
         "family": "catalyst-9200",
         "physical_device_id": second_assignment_device,
         "software": {"image": "17.12.4", "license": "Network Advantage"}},
    ]
    second["stacks"] = [{
        "assignment_id": first_assignment,
        "members": [
            {"number": 1, "physical_device_id": replacement_device,
             "state": "ready"},
            {"number": 2, "physical_device_id": second_device, "state": "missing"},
            {"number": 3, "physical_device_id": added_third_device,
             "state": "ready"},
        ],
    }]
    second["physical_interfaces"] = [
        {"id": first_port, "assignment_id": first_assignment,
         "physical_device_id": replacement_device, "name": "Gi1/0/1",
         "stack_member": 1,
         "settings": {"mode": "trunk", "native_vlan": 10,
                      "allowed_vlans": [10, 20, 40]}},
        {"id": second_port, "assignment_id": first_assignment,
         "physical_device_id": second_device, "name": "Gi2/0/1",
         "stack_member": 2,
         "settings": {"mode": "routed", "address": "10.10.10.2/30"}},
        {"id": added_third_port, "assignment_id": first_assignment,
         "physical_device_id": added_third_device, "name": "Gi3/0/1",
         "stack_member": 3, "settings": dict(access)},
        {"id": second_assignment_port, "assignment_id": replacement_assignment,
         "physical_device_id": second_assignment_device, "name": "Gi1/0/1",
         "settings": dict(access)},
    ]
    second["logical_interfaces"] = [
        first["logical_interfaces"][0],
        {"id": added_logical, "assignment_id": first_assignment,
         "name": "Port-channel3", "kind": "port-channel"},
    ]
    second["port_channels"] = [
        {"interface_id": first_logical, "number": 1,
         "member_ids": [second_port, added_third_port],
         "settings": {"mode": "access", "access_vlan": 20},
         "lacp": "active"},
        {"interface_id": added_logical, "number": 3,
         "member_ids": [first_port], "settings": dict(access),
         "lacp": "static"},
    ]
    first_revision = PlanRevision(
        id=UUID(new_id()), number=1, created_at=datetime.now(UTC),
        content_hash="c" * 64, schema_version=1,
        plan=EventPlan.model_validate(first), warnings=(),
        validation_errors=(), validation_status="VALID_WITH_WARNINGS",
    )
    second_revision = PlanRevision(
        id=UUID(new_id()), number=2, created_at=datetime.now(UTC),
        content_hash="d" * 64, schema_version=1,
        plan=EventPlan.model_validate(second), warnings=(),
        validation_errors=(), validation_status="VALID_WITH_WARNINGS",
    )
    result = build_layer2_intent(second_revision, first_revision)
    assert result.before_state_evidence == "planning-baseline"
    by_transition = {
        (change.target_kind.value, change.transition)
        for change in (
            *result.vlan_changes,
            *(change for device in result.devices for change in device.changes),
        )
    }
    assert ("vlan", "vlan-created") in by_transition
    assert ("vlan", "vlan-renamed") in by_transition
    assert ("vlan", "vlan-removed") in by_transition
    assert any(entry.transition == "assignment-removed"
               for entry in result.removed_assignments)
    assert {device.identity.hostname for device in result.devices} == {
        "L2-Stack", "L2-C",
    }
    added_device = next(
        device for device in result.devices if device.identity.hostname == "L2-C"
    )
    assert added_device.before.source.value == "not-in-baseline"
    stack_device = next(
        device for device in result.devices
        if device.identity.hostname == "L2-Stack"
    )
    stack_fields = {change.field for change in stack_device.changes}
    assert "stack-member:1:physical-device-id" in stack_fields
    assert "stack-member:2:state" in stack_fields
    assert "stack-member:3:definition" in stack_fields
    assert "stack-member:4:definition" in stack_fields
    interface_fields = {
        (change.target_name, change.field, change.transition)
        for change in stack_device.changes
        if change.target_kind.value == "interface"
    }
    assert ("Gi1/0/1", "physical_device_id", "physical-device-change") in (
        interface_fields
    )
    assert ("Gi3/0/1", "presence", "interface-added") in interface_fields
    assert ("Gi4/0/1", "presence", "interface-removed") in interface_fields
    assert ("Gi1/0/1", "mode", "access-to-trunk") in interface_fields
    assert ("Gi2/0/1", "mode", "switchport-to-routed") in interface_fields
    channel_fields = {
        (change.target_name, change.field, change.transition)
        for change in stack_device.changes
        if change.target_kind.value == "port-channel"
    }
    assert ("Port-channel2", "presence", "port-channel-removed") in channel_fields
    assert ("Port-channel3", "presence", "initial-plan") in channel_fields
    assert ("Port-channel1", "member_ids", "port-channel-members-change") in (
        channel_fields
    )
    matrix = {
        "vlan": {change.target_id for change in result.vlan_changes},
        "assignment_removed": {
            str(entry.assignment_id) for entry in result.removed_assignments
        },
        "device_added": {
            device.identity.assignment_id for device in result.devices
            if device.before.source.value == "not-in-baseline"
        },
        "stack_fields": stack_fields,
        "interface_fields": interface_fields,
        "channel_fields": channel_fields,
    }
    assert matrix["vlan"] == {"20", "30", "40"}
    assert matrix["assignment_removed"] == {
        str(first["assignments"][1]["id"]),
    }
    assert matrix["device_added"] == {UUID(replacement_assignment)}
    assert result.readiness.hardware_verified is False
    assert result.readiness.deployment_allowed is False
    assert result.executable is False
    assert result.cli is None
    assert result.device_writes_enabled is False
