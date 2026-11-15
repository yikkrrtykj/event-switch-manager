import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_event_plans import API, ORIGIN, plan_model, synthetic_plan, uid

from event_switch_manager.app import create_app
from event_switch_manager.planning.checks import validate_plan
from event_switch_manager.planning.inventory import PortSettings
from event_switch_manager.planning.plan import EventPlan, canonical_plan, plan_hash
from event_switch_manager.settings import Settings

UNSET_INTENT = {
    "description": None, "admin_state": None, "speed": None, "duplex": None,
    "poe_mode": None, "portfast": None, "bpdu_guard": None,
}


def fixture_plan(event_id: str) -> dict[str, Any]:
    raw = synthetic_plan(event_id)
    for collection in ("physical_interfaces", "port_channels"):
        for row in raw[collection]:
            row["settings"] = dict(row["settings"])
    return raw


@pytest.mark.parametrize(("field", "value"), [
    ("speed", True),
    ("speed", 1000.0),
    ("speed", "1000"),
    ("speed", 0),
    ("speed", 12345),
    ("duplex", "automatic"),
    ("poe_mode", False),
    ("poe_mode", "forced"),
    ("admin_state", True),
    ("portfast", True),
    ("bpdu_guard", False),
    ("description", "Lab port\n"),
    ("description", "Lab\u0085port"),
    ("description", "x" * 241),
])
def test_port_intent_rejects_invalid_scalar_values(field: str, value: object) -> None:
    with pytest.raises(ValidationError) as caught:
        PortSettings.model_validate({"mode": "access", "access_vlan": 9, field: value})
    assert any(error["loc"][0] == field for error in caught.value.errors())


def test_unset_port_fields_preserve_legacy_canonical_bytes() -> None:
    old = canonical_plan(plan_model())
    raw = json.loads(old)
    for collection in ("physical_interfaces", "port_channels"):
        for item in raw[collection]:
            assert not (item["settings"].keys() & UNSET_INTENT.keys())
            item["settings"].update(UNSET_INTENT)
    parsed = EventPlan.model_validate(raw)
    assert canonical_plan(parsed) == old
    assert canonical_plan(EventPlan.model_validate_json(old)) == old


@pytest.mark.parametrize(("name", "value"), [
    ("description", ""),
    ("admin_state", "down"),
    ("speed", "auto"),
    ("duplex", "auto"),
    ("poe_mode", "never"),
    ("portfast", "disabled"),
    ("bpdu_guard", "disabled"),
])
def test_explicit_default_or_disabled_intent_is_distinct_from_unset(
    name: str, value: str,
) -> None:
    raw = fixture_plan(uid(99))
    port_id = raw["physical_interfaces"][0]["id"]
    raw["physical_interfaces"][0]["settings"][name] = value
    canonical = canonical_plan(EventPlan.model_validate(raw))
    assert plan_hash(canonical) != plan_hash(canonical_plan(plan_model()))
    physical = json.loads(canonical)["physical_interfaces"]
    port = next(item for item in physical if item["id"] == port_id)
    assert port["settings"][name] == value
    assert canonical_plan(EventPlan.model_validate_json(canonical)) == canonical


@pytest.mark.parametrize("settings", [
    {"mode": "access", "access_vlan": 9, "portfast": "edge", "bpdu_guard": "enabled"},
    {"mode": "trunk", "native_vlan": 9, "allowed_vlans": [9, 20],
     "portfast": "edge-trunk", "bpdu_guard": "disabled"},
    {"mode": "routed", "address": "10.20.30.1/24", "poe_mode": "static"},
    {"mode": "access", "access_vlan": 9, "portfast": "disabled", "bpdu_guard": "enabled"},
])
def test_stack_spare_port_intent_is_valid_in_each_compatible_mode(
    settings: dict[str, object],
) -> None:
    raw = fixture_plan(uid(99))
    raw["physical_interfaces"].append({
        **raw["physical_interfaces"][0], "id": uid(80), "name": "Gi1/0/20",
        "capability_status": "verified",
        "settings": {**settings, "description": "Spare 工位", "admin_state": "up",
                     "speed": 100, "duplex": "half"},
    })
    plan = EventPlan.model_validate(raw)
    issues = validate_plan(plan)
    assert not any(issue.severity == "ERROR" for issue in issues)
    assert any(issue.path == "physical_interfaces.6.settings.duplex"
               and issue.code == "port_setting_unverified" and issue.severity == "WARNING"
               for issue in issues)


@pytest.mark.parametrize(("settings", "field", "code"), [
    ({"mode": "routed", "portfast": "edge"}, "portfast", "port_layer2_only"),
    ({"mode": "routed", "bpdu_guard": "disabled"}, "bpdu_guard", "port_layer2_only"),
    ({"mode": "access", "access_vlan": 9, "portfast": "edge-trunk"}, "portfast", "portfast_mode"),
    ({"mode": "trunk", "allowed_vlans": [9], "portfast": "edge"}, "portfast", "portfast_mode"),
    ({"mode": "access", "access_vlan": 9, "speed": 2500, "duplex": "half"},
     "duplex", "port_speed_duplex"),
])
def test_incompatible_intent_has_a_field_error(
    settings: dict[str, object], field: str, code: str,
) -> None:
    raw = fixture_plan(uid(99))
    raw["physical_interfaces"].append({
        **raw["physical_interfaces"][0], "id": uid(80), "name": "Gi1/0/20",
        "settings": settings,
    })
    issues = validate_plan(EventPlan.model_validate(raw))
    assert any(issue.path == f"physical_interfaces.6.settings.{field}"
               and issue.code == code and issue.severity == "ERROR" for issue in issues)


def test_gigabit_half_duplex_requires_port_evidence() -> None:
    raw = fixture_plan(uid(99))
    raw["physical_interfaces"][0]["settings"].update(speed=1000, duplex="half")
    issues = validate_plan(EventPlan.model_validate(raw))
    assert not any(issue.severity == "ERROR" for issue in issues)
    assert any(issue.code == "port_gigabit_half_unverified" and issue.severity == "WARNING"
               for issue in issues)


@pytest.mark.parametrize(
    ("name", "value"), [("speed", "auto"), ("duplex", "full"), ("poe_mode", "never")]
)
def test_aggregate_does_not_take_physical_settings(name: str, value: str) -> None:
    raw = fixture_plan(uid(99))
    raw["port_channels"][0]["settings"][name] = value
    issues = validate_plan(EventPlan.model_validate(raw))
    assert any(issue.path == f"port_channels.0.settings.{name}"
               and issue.code == "port_physical_only" and issue.severity == "ERROR"
               for issue in issues)


@pytest.mark.parametrize(("name", "values", "code", "severity"), [
    ("speed", (1000, 10000), "port_channel_speed_conflict", "ERROR"),
    ("duplex", ("full", "half"), "port_channel_duplex_conflict", "ERROR"),
    ("speed", (1000, "auto"), "port_channel_speed_unverified", "WARNING"),
    ("duplex", ("full", None), "port_channel_duplex_unverified", "WARNING"),
    ("bpdu_guard", ("enabled", "disabled"), "port_channel_stp_conflict", "ERROR"),
    ("portfast", ("edge-trunk", "disabled"), "port_channel_stp_conflict", "ERROR"),
])
def test_stack_channel_members_report_conflicting_or_unverified_intent(
    name: str, values: tuple[int | str | None, int | str | None], code: str, severity: str,
) -> None:
    raw = fixture_plan(uid(99))
    for value, member_index in zip(values, (2, 3), strict=True):
        raw["physical_interfaces"][member_index]["settings"][name] = value
    issues = validate_plan(EventPlan.model_validate(raw))
    assert any(issue.path.startswith("port_channels.0.") and issue.code == code
               and issue.severity == severity for issue in issues)
    if severity == "WARNING":
        assert not any(issue.severity == "ERROR" for issue in issues)


def test_channel_and_stack_member_cannot_set_opposing_spanning_tree_intent() -> None:
    raw = fixture_plan(uid(99))
    raw["port_channels"][0]["settings"].update(portfast="edge-trunk")
    raw["physical_interfaces"][2]["settings"].update(portfast="disabled")
    issues = validate_plan(EventPlan.model_validate(raw))
    assert any(issue.path == "port_channels.0.settings.portfast"
               and issue.code == "port_channel_stp_conflict" and issue.severity == "ERROR"
               for issue in issues)


def test_port_intent_api_preserves_revisions_and_isolates_shared_chassis(tmp_path: Path) -> None:
    app = create_app(Settings(database_path=tmp_path / "ports.sqlite3"))
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        events = f"{API}/events"
        first = client.post(events, json={"name": "Synthetic event one"}).json()["id"]
        second = client.post(events, json={"name": "Synthetic event two"}).json()["id"]
        url = f"{events}/{first}/plan-revisions"
        raw = fixture_plan(first)
        old = client.post(url, json=raw)
        assert old.status_code == 200
        old_revision = old.json()
        legacy_export = url + "/" + old_revision["id"] + "/export"
        exported = client.get(legacy_export)
        assert exported.headers["etag"] == f'"{old_revision["content_hash"]}"'
        assert plan_hash(exported.text) == old_revision["content_hash"]
        assert not (exported.json()["physical_interfaces"][0]["settings"].keys()
                    & UNSET_INTENT.keys())
        assert client.post(url, json=exported.json()).json()["id"] == old_revision["id"]

        member = raw["physical_interfaces"][2]
        member["settings"].update(description="Player tray 02", admin_state="down", speed=1000,
                                  duplex="full", poe_mode="never", portfast="disabled",
                                  bpdu_guard="disabled")
        raw["port_channels"][0]["settings"].update(
            description="Fixture bundle",
            admin_state="up",
            portfast="disabled",
            bpdu_guard="disabled",
        )
        current = client.post(url, json=raw)
        assert current.status_code == 200
        saved = current.json()
        assert saved["id"] != old_revision["id"]
        assert saved["content_hash"] != old_revision["content_hash"]
        assert saved["validation_status"] == "VALID_WITH_WARNINGS"
        assert saved["validation_errors"] == []
        assert any(issue["code"] == "port_setting_unverified" and issue["severity"] == "WARNING"
                   for issue in saved["warnings"])

        latest = url + "/" + saved["id"]
        reread = client.get(latest).json()
        assert reread == saved
        saved_port = next(port for port in reread["plan"]["physical_interfaces"]
                          if port["id"] == member["id"])
        assert all(saved_port["settings"][key] == value
                   for key, value in member["settings"].items())
        assert reread["plan"]["port_channels"][0]["settings"]["description"] == "Fixture bundle"
        current_export = client.get(latest + "/export")
        assert plan_hash(current_export.text) == saved["content_hash"]
        assert current_export.headers["etag"] == f'"{saved["content_hash"]}"'
        assert client.post(url, json=current_export.json()).json()["id"] == saved["id"]

        other_url = f"{events}/{second}/plan-revisions"
        other_plan = {
            "schema_version": 1, "event_id": second,
            "physical_devices": [raw["physical_devices"][0]],
            "assignments": [{"id": uid(81), "hostname": "Other-Event", "role": "access",
                             "physical_device_id": member["physical_device_id"]}],
            "vlans": [{"id": 10, "name": "Management"}],
            "physical_interfaces": [{
                "id": member["id"], "assignment_id": uid(81),
                "physical_device_id": member["physical_device_id"], "name": member["name"],
                "settings": {"mode": "access", "access_vlan": 10, "admin_state": "up",
                             "description": "Other layout", "poe_mode": "auto"},
            }],
        }
        other = client.post(other_url, json=other_plan)
        assert other.status_code == 200
        other_port = other.json()["plan"]["physical_interfaces"][0]
        assert other_port["id"] == saved_port["id"]
        assert other_port["physical_device_id"] == saved_port["physical_device_id"]
        assert other_port["settings"]["admin_state"] == "up"
        assert client.get(latest).json() == saved
        assert client.get(other_url + "/" + saved["id"]).status_code == 404
        unchanged = client.get(legacy_export)
        assert unchanged.content == exported.content
        assert unchanged.headers["etag"] == exported.headers["etag"]
        assert client.get(f"{API}/health").json()["device_writes_enabled"] is False

        member["settings"].update(speed=2500, duplex="half")
        findings = client.post(f"{events}/{first}/plan/validate", json=raw)
        assert findings.status_code == 200
        assert any(issue["code"] == "port_speed_duplex" and issue["severity"] == "ERROR"
                   for issue in findings.json())
        assert client.post(url, json=raw).status_code == 422
        assert len(client.get(url).json()) == 2
