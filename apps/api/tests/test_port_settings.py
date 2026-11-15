import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text
from test_event_plans import API, ORIGIN, plan_model, synthetic_plan, uid

from event_switch_manager.app import create_app
from event_switch_manager.database import create_database_engine
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
    if code in ("port_channel_speed_conflict", "port_channel_duplex_conflict"):
        expected_paths = {f"physical_interfaces.{index}.settings.{name}" for index in (2, 3)}
    elif code == "port_channel_stp_conflict":
        expected_paths = {f"port_channels.0.settings.{name}"}
    else:
        expected_paths = {"port_channels.0.member_ids"}
    assert {issue.path for issue in issues if issue.code == code
            and issue.severity == severity} == expected_paths
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


@pytest.mark.parametrize(("intents", "expected_errors", "expected_warnings"), [
    pytest.param(
        ({"speed": 10000}, {"duplex": "half"}),
        {(2, "speed", "port_channel_speed_duplex_conflict"),
         (3, "duplex", "port_channel_speed_duplex_conflict")},
        set(), id="cross-stack-10g-half",
    ),
    pytest.param(
        ({"duplex": "half"}, {"speed": "auto", "duplex": "auto"}, {"speed": 2500}),
        {(2, "duplex", "port_channel_speed_duplex_conflict"),
         (6, "speed", "port_channel_speed_duplex_conflict")},
        set(), id="three-members-reversed-constraints",
    ),
    pytest.param(
        ({"speed": 10000, "duplex": "half"}, {}),
        {(2, "duplex", "port_speed_duplex")}, set(), id="same-member-10g-half",
    ),
    pytest.param(
        ({"speed": 10000, "duplex": "full"}, {"speed": 10000, "duplex": "full"}),
        set(), {"port_setting_unverified"}, id="both-10g-full",
    ),
    pytest.param(
        ({"speed": 10000, "duplex": "full"}, {"speed": "auto", "duplex": "auto"}),
        set(), {"port_channel_speed_unverified", "port_channel_duplex_unverified"},
        id="fixed-and-auto",
    ),
    pytest.param(
        ({"speed": 10000, "duplex": "full"}, {}, {"duplex": "auto"}),
        set(), {"port_channel_speed_unverified", "port_channel_duplex_unverified"},
        id="three-members-with-unset-and-auto",
    ),
    pytest.param(
        ({"speed": 1000}, {"duplex": "half"}),
        set(), {"port_channel_speed_unverified", "port_channel_duplex_unverified"},
        id="gigabit-half-needs-evidence",
    ),
    pytest.param(
        ({"speed": 100, "duplex": "half"}, {"speed": 100, "duplex": "half"}, {}),
        set(), {"port_channel_speed_unverified", "port_channel_duplex_unverified"},
        id="common-fast-ethernet-half",
    ),
])
def test_stack_channel_members_need_a_common_speed_and_duplex(
    intents: tuple[dict[str, object], ...],
    expected_errors: set[tuple[int, str, str]],
    expected_warnings: set[str],
) -> None:
    raw = fixture_plan(uid(99))
    ports = raw["physical_interfaces"]
    if len(intents) == 3:
        ports.append({
            **ports[3], "id": uid(80), "name": "Gi2/0/20", "settings": dict(ports[3]["settings"]),
        })
        raw["port_channels"][0]["member_ids"].append(uid(80))
    for index, intent in zip((2, 3, 6)[:len(intents)], intents, strict=True):
        ports[index]["settings"].update(intent)

    # An independent port can use a different feasible combination.
    ports.append({
        **ports[2], "id": uid(81), "name": "Gi1/0/21",
        "settings": {"mode": "access", "access_vlan": 20, "speed": 100, "duplex": "half"},
    })
    issues = validate_plan(EventPlan.model_validate(raw))
    assert {(issue.path, issue.code) for issue in issues if issue.severity == "ERROR"} == {
        (f"physical_interfaces.{index}.settings.{field}", code)
        for index, field, code in expected_errors
    }
    assert {issue.code for issue in issues if issue.severity == "WARNING"} >= expected_warnings
    if expected_errors:
        assert not any(issue.code in {
            "port_channel_speed_unverified", "port_channel_duplex_unverified",
        } for issue in issues)


@pytest.mark.parametrize(("core", "hillstone", "down_indices"), [
    pytest.param({"admin_state": "down"}, {}, (0,), id="core-down"),
    pytest.param({}, {"admin_state": "down"}, (1,), id="hillstone-down"),
    pytest.param({"admin_state": "down"}, {"admin_state": "down"}, (0, 1), id="both-down"),
    pytest.param({"admin_state": "up"}, {"admin_state": "up"}, (), id="both-up"),
    pytest.param({}, {}, (), id="implicit-default"),
    pytest.param({"admin_state": None}, {"admin_state": None}, (), id="explicit-null"),
])
def test_transit_shutdown_is_reported_at_each_referenced_endpoint(
    core: dict[str, str | None], hillstone: dict[str, str | None], down_indices: tuple[int, ...],
) -> None:
    raw = fixture_plan(uid(99))
    ports = raw["physical_interfaces"]
    ports[0]["settings"].update(core)
    ports[1]["settings"].update(hillstone)
    ports.append({
        **ports[0], "id": uid(80), "name": "Gi1/0/20",
        "settings": {"mode": "access", "access_vlan": 20, "admin_state": "down"},
    })
    errors = [issue for issue in validate_plan(EventPlan.model_validate(raw))
              if issue.severity == "ERROR"]
    assert [(issue.path, issue.code) for issue in errors] == [
        (f"physical_interfaces.{index}.settings.admin_state", "transit_port_shutdown")
        for index in down_indices
    ]
    for issue, index in zip(errors, down_indices, strict=True):
        side = ("core_port_id", "hillstone_port_id")[index]
        assert f"transit.{side}" in issue.message


def test_plan_without_transit_can_shut_down_an_independent_port() -> None:
    fixture = fixture_plan(uid(99))
    port = fixture["physical_interfaces"][1]
    port["settings"]["admin_state"] = "down"
    raw = {
        "schema_version": 1, "event_id": uid(99), "physical_interfaces": [port],
        "physical_devices": [fixture["physical_devices"][2]],
        "assignments": [fixture["assignments"][1]],
        "vlans": fixture["vlans"],
    }
    issues = validate_plan(EventPlan.model_validate(raw))
    assert not any(issue.severity == "ERROR" for issue in issues)


def test_transit_shutdown_keeps_vlan_link_and_route_diagnostics() -> None:
    raw = fixture_plan(uid(99))
    raw["physical_interfaces"][0]["settings"].update(admin_state="down", access_vlan=20)
    raw["default_routes"].clear()
    raw["static_routes"].pop(0)
    raw["links"].clear()
    issues = validate_plan(EventPlan.model_validate(raw))
    assert {issue.code for issue in issues if issue.severity == "ERROR"} >= {
        "transit_port_shutdown", "transit_port", "transit_link", "core_default", "return_route",
    }


SafetyCase = Literal["channel", "transit"]


def unsafe_plan(event_id: str, case: SafetyCase) -> tuple[dict[str, Any], str, set[str]]:
    raw = fixture_plan(event_id)
    ports = raw["physical_interfaces"]
    if case == "channel":
        ports[2]["settings"]["speed"] = 10000
        ports[3]["settings"]["duplex"] = "half"
        return raw, "port_channel_speed_duplex_conflict", {
            "physical_interfaces.2.settings.speed", "physical_interfaces.3.settings.duplex",
        }
    ports[0]["settings"]["admin_state"] = "down"
    return raw, "transit_port_shutdown", {"physical_interfaces.0.settings.admin_state"}


@pytest.mark.parametrize("case", ["channel", "transit"])
def test_unsafe_port_configuration_is_rejected_by_plan_api(
    tmp_path: Path, case: SafetyCase,
) -> None:
    app = create_app(Settings(database_path=tmp_path / "unsafe-port.sqlite3"))
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        event_id = client.post(f"{API}/events", json={"name": "Unsafe port plan"}).json()["id"]
        event_url = f"{API}/events/{event_id}"
        revisions_url = f"{event_url}/plan-revisions"
        raw, code, paths = unsafe_plan(event_id, case)
        findings = client.post(f"{event_url}/plan/validate", json=raw)
        assert findings.status_code == 200
        assert {(issue["code"], issue["path"]) for issue in findings.json()
                if issue["severity"] == "ERROR"} == {(code, path) for path in paths}
        assert any(issue["severity"] == "WARNING" for issue in findings.json())

        rejected = client.post(revisions_url, json=raw)
        assert rejected.status_code == 422
        assert rejected.json()["detail"] == findings.json()
        assert client.get(revisions_url).json() == []


@pytest.mark.parametrize("case", ["channel", "transit"])
def test_pre_fix_unsafe_port_revisions_keep_identity_and_become_invalid(
    tmp_path: Path, case: SafetyCase,
) -> None:
    event_id, revision_id = uid(99), uid(98)
    raw, code, _ = unsafe_plan(event_id, case)
    expected_paths = {
        "channel": {
            "physical_interfaces.1.settings.speed", "physical_interfaces.2.settings.duplex",
        },
        "transit": {"physical_interfaces.0.settings.admin_state"},
    }
    old_content = canonical_plan(EventPlan.model_validate(raw))
    old_hash = sha256(old_content.encode("utf-8")).hexdigest()
    settings = Settings(database_path=tmp_path / "old-port-plan.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        # Store the revision as the pre-fix build did, bypassing the current import check.
        engine = create_database_engine(settings.database_path)
        try:
            with engine.begin() as connection:
                connection.execute(text(
                    "INSERT INTO events (id, name, management_vlan) VALUES (:id, 'Legacy', 10)"
                ), {"id": UUID(event_id).hex})
                connection.execute(text(
                    "INSERT INTO event_plan_revisions "
                    "(id, event_id, number, schema_version, created_at, content_hash, "
                    "canonical_json) "
                    "VALUES (:id, :event, 1, 1, '2026-11-15 00:00:00', :hash, :content)"
                ), {"id": UUID(revision_id).hex, "event": UUID(event_id).hex,
                    "hash": old_hash, "content": old_content})
        finally:
            engine.dispose()

        url = f"{API}/events/{event_id}/plan-revisions"
        detail = client.get(f"{url}/{revision_id}")
        assert detail.status_code == 200
        legacy = detail.json()
        assert (legacy["id"], legacy["content_hash"], legacy["schema_version"]) == (
            revision_id, old_hash, 1,
        )
        assert legacy["validation_status"] == "INVALID"
        assert {(issue["code"], issue["path"], issue["severity"])
                for issue in legacy["validation_errors"]} == {
            (code, path, "ERROR") for path in expected_paths[case]
        }

        export_url = f"{url}/{revision_id}/export"
        exported = client.get(export_url)
        assert exported.status_code == 200
        assert exported.content == old_content.encode("utf-8")
        assert exported.headers["etag"] == f'"{old_hash}"'

        repeated = client.post(url, json=exported.json())
        assert repeated.status_code == 200
        assert repeated.json() == legacy
        edited = exported.json()
        edited["vlans"][2]["name"] = "Modified players"
        rejected = client.post(url, json=edited)
        assert rejected.status_code == 422
        assert [issue for issue in rejected.json()["detail"] if issue["severity"] == "ERROR"] == (
            legacy["validation_errors"]
        )
        assert [revision["id"] for revision in client.get(url).json()] == [revision_id]
        unchanged = client.get(export_url)
        assert unchanged.content == exported.content
        assert unchanged.headers["etag"] == exported.headers["etag"]
