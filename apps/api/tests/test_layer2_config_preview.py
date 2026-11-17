"""CIS-02B1 contract, binding, determinism and safety regressions."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from test_event_plans import API, ORIGIN
from test_layer2_intent import event, intent, make_plan, make_stack_plan, new_id, save

import event_switch_manager.planning.layer2_config_preview as layer2_config_preview
from event_switch_manager.app import create_app
from event_switch_manager.planning.layer2_config_preview import (
    JSON_SCHEMA_DIALECT,
    PREVIEW_CONTRACT_ID,
    PREVIEW_SCHEMA_VERSION,
    Layer2ConfigPreview,
    Layer2DeviceConfigPreview,
    PreviewInputError,
    aggregate_preview_json_schema,
    build_layer2_config_preview,
    config_preview_json_schema,
    device_preview_json_schema,
    preview_contract_fingerprint,
    verify_intent_binding,
)
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.planning.plan import EventPlan, PlanRevision
from event_switch_manager.planning.validation import PlanIssue
from event_switch_manager.settings import Settings

Preview = dict[str, Any]
Device = dict[str, Any]
Item = dict[str, Any]

CLI_LINE = re.compile(
    r"^(interface|switchport|spanning-tree|vlan\s|hostname|enable|configure|"
    r"no\s|shutdown|copy\s|ip\s)"
)
FORBIDDEN_TOP_LEVEL = {
    "commands", "command_lines", "configuration", "config", "config_snippet",
    "cli_commands", "cli_lines", "script", "execution_order", "sequence",
}
ALL_CATEGORIES = {
    "vlan", "stp", "vtp", "root-priority", "access", "trunk", "port-channel",
    "lacp", "portfast", "bpdu-guard", "poe", "speed", "duplex", "description",
    "shutdown", "unused-port-policy",
}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "layer2-preview.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as session:
        yield session


def preview(client: TestClient, event_id: str, revision_id: str) -> Preview:
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision_id}/layer2-config-preview"
    )
    assert response.status_code == 200, response.text
    return cast(Preview, response.json())


def raw_preview(
    client: TestClient, event_id: str, revision_id: str,
) -> Any:
    return client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision_id}/layer2-config-preview"
    )


def device_document(
    client: TestClient, event_id: str, revision_id: str, assignment_id: str,
) -> Device:
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision_id}"
        f"/layer2-config-preview/devices/{assignment_id}"
    )
    assert response.status_code == 200, response.text
    return cast(Device, response.json())


def items(device: Device) -> list[Item]:
    return cast(list[Item], device["config_items"])


def item(device: Device, target_name: str, field: str) -> Item:
    for candidate in items(device):
        if candidate["target_name"] == target_name and candidate["field"] == field:
            return candidate
    raise AssertionError(f"Missing item {target_name} / {field}")


def revision_for(
    plan: dict[str, Any], *, number: int = 1, hash_char: str = "a",
    validation_status: str = "VALID_WITH_WARNINGS",
) -> PlanRevision:
    return PlanRevision(
        id=UUID(new_id()),
        number=number,
        created_at=datetime.now(UTC),
        content_hash=hash_char * 64,
        schema_version=1,
        plan=EventPlan.model_validate(plan),
        warnings=(),
        validation_errors=(),
        validation_status=cast(Any, validation_status),
    )


def fingerprint_of(document: dict[str, Any]) -> str:
    payload = {
        key: value for key, value in document.items() if key != "preview_fingerprint"
    }
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def walk_strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        mapping = cast(dict[str, object], value)
        for key, item_value in mapping.items():
            yield key
            yield from walk_strings(item_value)
    elif isinstance(value, list):
        for item_value in cast(list[object], value):
            yield from walk_strings(item_value)


def walk_keys(value: object) -> Iterator[str]:
    if isinstance(value, dict):
        mapping = cast(dict[str, object], value)
        for key, item_value in mapping.items():
            yield key
            yield from walk_keys(item_value)
    elif isinstance(value, list):
        for item_value in cast(list[object], value):
            yield from walk_keys(item_value)


def full_plan(event_id: str) -> dict[str, Any]:
    return make_plan(
        event_id,
        pid="C9300L-24P-4X",
        ports=[
            {
                "name": "Gi1/0/1",
                "settings": {
                    "mode": "access", "access_vlan": 20,
                    "description": "Players desk", "admin_state": "up",
                    "speed": 1000, "duplex": "full", "poe_mode": "auto",
                    "portfast": "edge", "bpdu_guard": "enabled",
                },
            },
            {
                "name": "Gi1/0/2",
                "settings": {
                    "mode": "trunk", "native_vlan": 10,
                    "allowed_vlans": [10, 20, 30],
                },
            },
            {"name": "Gi1/0/3", "settings": {"mode": "access", "access_vlan": 20}},
            {"name": "Gi1/0/4", "settings": {"mode": "access", "access_vlan": 20}},
        ],
        channel={
            "members": [2, 3],
            "settings": {"mode": "access", "access_vlan": 20},
            "lacp": "active",
        },
    )


def test_preview_binds_saved_revision_intent_and_never_claims_device_state(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = full_plan(event_id)
    saved = save(client, event_id, plan)
    intent_document = intent(client, event_id, saved["id"])
    result = preview(client, event_id, saved["id"])

    assert result["preview_schema_version"] == PREVIEW_SCHEMA_VERSION == 1
    assert result["contract_id"] == PREVIEW_CONTRACT_ID
    assert result["source"] == "cis-02a-layer2-intent"
    assert result["event_id"] == event_id
    assert result["revision_id"] == saved["id"]
    assert result["revision_number"] == 1
    assert result["revision_hash"] == saved["content_hash"]
    assert result["intent_schema_version"] == 1
    assert result["intent_fingerprint"] == intent_document["intent_fingerprint"]
    assert result["default_policy_id"] == "cis-02a-reviewed-defaults-v1"
    assert result["baseline"] == {
        "source": "none", "revision_id": None, "revision_hash": None,
        "device_state": "unknown",
    }
    assert result["device_state"] == "unknown"
    assert result["before_state_evidence"] == "planning-baseline-unavailable"
    assert result["running_config_read"] is False
    assert result["observed_device_state"] == "not-read"
    assert result["dependency_semantics"] == (
        "association-only-not-an-execution-order"
    )
    assert result["planning_scope"] == {
        "planned_configuration": "cis-02a-desired-state",
        "planned_difference": "planning-baseline-changeset",
        "device_running_state": "unknown-not-read",
    }
    assert result["readiness"] == {
        "preview_contract_valid": True,
        "intent_contract_valid": True,
        "structured_intent_valid": True,
        "vendor_documentation": "supported",
        "hardware_verified": False,
        "deployment_allowed": False,
    }
    assert result["verification"] == "not-verified"
    assert result["deployment_status"] == "blocked"
    assert result["executable"] is False
    assert result["cli"] is None
    assert result["device_writes_enabled"] is False
    assert set(result).isdisjoint(FORBIDDEN_TOP_LEVEL)
    assert len(result["preview_fingerprint"]) == 64
    assert result["deployment_blockers"][:5] == [
        "preview-only-no-execution",
        "deployment-generation-disabled",
        "hardware-not-verified",
        "device-state-unknown",
        "intent-not-deployment-ready",
    ]
    assert "preview-only-no-execution" in result["deployment_blockers"]

    device = cast(Device, result["devices"][0])
    categories = {candidate["category"] for candidate in items(device)}
    assert ALL_CATEGORIES <= categories

    stp = item(device, "L2-Access", "spanning-tree-mode")
    assert stp["planned"] == {
        "value": "rapid-pvst", "present": True,
        "source": "reviewed-default-policy",
    }
    vtp = item(device, "L2-Access", "vtp-mode")
    assert vtp["planned"]["source"] == "reviewed-default-policy"
    root_priority = item(device, "L2-Access", "root-priority")
    assert root_priority["planned"]["value"] == {
        "priority": 32768, "policy": "role-priority-v1",
    }
    access_vlan = item(device, "Gi1/0/1", "access_vlan")
    assert access_vlan["planned"] == {
        "value": 20, "present": True, "source": "event-plan",
    }
    description = item(device, "Gi1/0/1", "description")
    assert description["planned"]["value"] == "Players desk"
    for field, expected in (
        ("speed", 1000), ("duplex", "full"), ("poe_mode", "auto"),
        ("portfast", "edge"), ("bpdu_guard", "enabled"),
    ):
        candidate = item(device, "Gi1/0/1", field)
        assert candidate["planned"]["value"] == expected
        assert candidate["capability"]["verdict"] == "supported"
    shutdown = item(device, "Gi1/0/2", "shutdown_intent")
    assert shutdown["planned"]["value"]["intent"] == "shutdown"
    assert shutdown["planned"]["value"]["source"] == "reviewed-default-policy"
    assert shutdown["risk"]["requires_field_verification"] is True
    member = item(device, "Gi1/0/3", "shutdown_intent")
    assert member["planned"]["value"]["intent"] == "platform-default"
    assert member["planned"]["value"]["source"] is None
    explicit = item(device, "Gi1/0/1", "shutdown_intent")
    assert explicit["planned"]["value"]["source"] == "event-plan"
    unused_policy = item(device, "L2-Access", "unused-port-shutdown")
    assert unused_policy["planned"]["value"]["shutdown"] is True
    assert unused_policy["risk"]["requires_field_verification"] is True

    lacp = [
        candidate for candidate in items(device) if candidate["category"] == "lacp"
    ]
    assert len(lacp) == 1
    assert lacp[0]["planned"]["value"] == "active"
    assert lacp[0]["capability"]["capability"] == "lacp"
    assert lacp[0]["capability"]["verdict"] == "supported"
    for candidate in items(device):
        assert candidate["deployability"]["deployable"] is False
        assert candidate["deployability"]["evidence_gate"] in {
            "pass", "unknown", "unsupported", "identity-incomplete", "intent-invalid",
        }
        assert candidate["baseline"]["state"] == "planning-baseline-unavailable"
        assert candidate["risk"]["level"] in {
            "none", "field-verification", "unknown", "unsupported",
            "identity-incomplete", "intent-invalid",
        }
    assert device["deployability"]["deployable"] is False
    assert device["deployability"]["deployment_allowed"] is False
    assert device["intent_readiness"]["deployment_allowed"] is False
    assert device["human_readable"]["display_only"] is True
    assert device["human_readable"]["executable"] is False
    assert device["human_readable"]["statements"]


def test_intent_binding_rejects_tampering_and_wrong_revision() -> None:
    plan = full_plan(new_id())
    revision = revision_for(plan)
    intent_model = build_layer2_intent(revision, None)
    verify_intent_binding(revision, intent_model)
    assert len(intent_model.intent_fingerprint) == 64

    other_revision = revision_for(plan, number=2, hash_char="b")
    for tampered, expected in (
        (intent_model.model_copy(update={"revision_hash": "f" * 64}),
         "intent-revision-hash-mismatch"),
        (intent_model.model_copy(update={"revision_id": other_revision.id}),
         "intent-revision-mismatch"),
        (intent_model.model_copy(update={"event_id": UUID(new_id())}),
         "intent-event-mismatch"),
        (intent_model.model_copy(update={"intent_schema_version": 2}),
         "unsupported-intent-schema-version"),
        (intent_model.model_copy(update={"intent_fingerprint": "0" * 64}),
         "intent-fingerprint-mismatch"),
    ):
        with pytest.raises(PreviewInputError) as error:
            verify_intent_binding(revision, tampered)
        assert error.value.reason_code == expected
    with pytest.raises(PreviewInputError) as error:
        build_layer2_config_preview(other_revision, intent_model)
    assert error.value.reason_code == "intent-revision-mismatch"


def test_preview_is_deterministic_and_revision_history_is_immutable(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = full_plan(event_id)
    first = save(client, event_id, plan)
    export_url = f"{API}/events/{event_id}/plan-revisions/{first['id']}/export"
    export_before = client.get(export_url)
    first_response = raw_preview(client, event_id, first["id"])
    second_response = raw_preview(client, event_id, first["id"])
    assert first_response.content == second_response.content
    document = cast(Preview, first_response.json())
    assert document["preview_fingerprint"] == fingerprint_of(document)
    for device in cast(list[Device], document["devices"]):
        assert device["preview_fingerprint"] == fingerprint_of(device)

    second_plan = copy.deepcopy(plan)
    second_plan["physical_interfaces"][0]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
    }
    second = save(client, event_id, second_plan)
    after = raw_preview(client, event_id, first["id"])
    assert after.content == first_response.content
    assert client.get(export_url).content == export_before.content
    assert first["content_hash"] == export_before.headers["etag"].strip('"')

    second_document = preview(client, event_id, second["id"])
    assert second_document["revision_id"] == second["id"]
    assert second_document["baseline"]["revision_id"] == first["id"]
    assert second_document["baseline"]["revision_hash"] == first["content_hash"]
    assert second_document["before_state_evidence"] == "planning-baseline"
    assert second_document["preview_fingerprint"] != document["preview_fingerprint"]
    assert preview(client, event_id, second["id"]) == second_document


def test_per_device_preview_is_isolated_from_other_assignments(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = make_plan(
        event_id,
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
    )
    second_device, second_assignment, second_port = new_id(), new_id(), new_id()
    plan["physical_devices"].append({
        "id": second_device, "vendor": "cisco", "model": "C9300L-24T-4G",
        "verified_serial": "SYN-L2-PREVIEW-B",
    })
    plan["assignments"].append({
        "id": second_assignment, "hostname": "L2-Access-B", "role": "access",
        "family": "catalyst-9300", "physical_device_id": second_device,
        "software": {"image": "17.12.4", "license": "Network Advantage"},
    })
    plan["physical_interfaces"].append({
        "id": second_port, "assignment_id": second_assignment,
        "physical_device_id": second_device, "name": "Gi1/0/1",
        "settings": {"mode": "trunk", "native_vlan": 10,
                     "allowed_vlans": [10, 30]},
    })
    saved = save(client, event_id, plan)
    aggregate = preview(client, event_id, saved["id"])
    devices = cast(list[Device], aggregate["devices"])
    assert [device["hostname"] for device in devices] == [
        "L2-Access", "L2-Access-B",
    ]
    fingerprints = {device["preview_fingerprint"] for device in devices}
    assert len(fingerprints) == 2

    for device, other_port, expected_vlans in (
        (devices[0], second_port, {20}),
        (devices[1], plan["physical_interfaces"][0]["id"], {10, 30}),
    ):
        document = device_document(
            client, event_id, saved["id"], device["assignment_id"],
        )
        assert "devices" not in document
        assert document["device"]["preview_fingerprint"] == (
            device["preview_fingerprint"]
        )
        assert document["device"] == device
        device_items = items(cast(Device, document["device"]))
        target_ids = {candidate["target_id"] for candidate in device_items}
        assert other_port not in target_ids
        vlan_items = [
            candidate for candidate in device_items
            if candidate["category"] == "vlan"
        ]
        assert {
            candidate["planned"]["value"]["vlan_id"] for candidate in vlan_items
        } == expected_vlans
        for change in cast(list[dict[str, Any]], device["planned_diff"]):
            if change["target_kind"] == "interface":
                assert change["target_id"] in target_ids
    assert len({
        candidate["item_id"] for candidate in items(devices[0])
    } & {
        candidate["item_id"] for candidate in items(devices[1])
    }) == 0
    unknown = client.get(
        f"{API}/events/{event_id}/plan-revisions/{saved['id']}"
        f"/layer2-config-preview/devices/{new_id()}"
    )
    assert unknown.status_code == 404


def test_removed_assignments_are_reported_but_never_previewed(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = make_plan(
        event_id,
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
    )
    removed_device, removed_assignment, removed_port = new_id(), new_id(), new_id()
    plan["physical_devices"].append({
        "id": removed_device, "vendor": "cisco", "model": "C9300L-24T-4G",
        "verified_serial": "SYN-L2-REMOVED",
    })
    plan["assignments"].append({
        "id": removed_assignment, "hostname": "L2-Removed", "role": "access",
        "family": "catalyst-9300", "physical_device_id": removed_device,
        "software": {"image": "17.12.4", "license": "Network Advantage"},
    })
    plan["physical_interfaces"].append({
        "id": removed_port, "assignment_id": removed_assignment,
        "physical_device_id": removed_device, "name": "Gi1/0/1",
        "settings": {"mode": "access", "access_vlan": 20},
    })
    first = save(client, event_id, plan)
    retained = copy.deepcopy(plan)
    retained["physical_devices"] = [
        device for device in retained["physical_devices"]
        if device["id"] != removed_device
    ]
    retained["assignments"] = [
        assignment for assignment in retained["assignments"]
        if assignment["id"] != removed_assignment
    ]
    retained["physical_interfaces"] = [
        interface for interface in retained["physical_interfaces"]
        if interface["assignment_id"] != removed_assignment
    ]
    second = save(client, event_id, retained)

    result = preview(client, event_id, second["id"])
    assert [device["hostname"] for device in result["devices"]] == ["L2-Access"]
    removed = cast(list[dict[str, Any]], result["removed_assignments"])
    assert len(removed) == 1
    assert removed[0]["assignment_id"] == removed_assignment
    assert removed[0]["identity"]["hostname"] == "L2-Removed"
    assert removed[0]["after"] is None
    assert removed[0]["after_exists"] is False
    assert removed[0]["before_source"] == "planning-baseline"
    assert removed[0]["baseline_revision_id"] == first["id"]
    assert (
        f"assignment-removal-requires-field-verification:{removed_assignment}"
        in result["deployment_blockers"]
    )
    assert (
        f"device-wipe-not-authorized:{removed_assignment}"
        in result["deployment_blockers"]
    )
    conflict_codes = {conflict["code"] for conflict in result["conflicts"]}
    assert "assignment-removed-requires-field-verification" in conflict_codes
    missing = client.get(
        f"{API}/events/{event_id}/plan-revisions/{second['id']}"
        f"/layer2-config-preview/devices/{removed_assignment}"
    )
    assert missing.status_code == 404


def test_vlan_scope_is_event_wide_while_device_items_stay_reference_scoped(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = make_plan(
        event_id,
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
    )
    plan["vlans"].append({"id": 40, "name": "Declared only", "purpose": "ordinary"})
    saved = save(client, event_id, plan)
    result = preview(client, event_id, saved["id"])
    scope = cast(dict[str, Any], result["vlan_scope"])
    assert scope["scope"] == "event-plan"
    assert scope["semantics"] == (
        "event-wide-vlan-definitions-not-per-device-intent"
    )
    declared = {definition["vlan_id"]: definition for definition in scope["definitions"]}
    assert set(declared) == {10, 20, 30, 40}
    assert declared[40]["name"] == "Declared only"
    assert declared[40]["transition"] == "initial-plan"
    assert declared[40]["change_id"].startswith("chg-")
    assert len(scope["fingerprint"]) == 64
    device = cast(Device, result["devices"][0])
    device_vlans = {
        candidate["planned"]["value"]["vlan_id"]
        for candidate in items(device) if candidate["category"] == "vlan"
    }
    assert device_vlans == {20}
    assert 40 not in device_vlans


def test_preview_exposes_no_cli_or_device_operation_path(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = full_plan(event_id)
    saved = save(client, event_id, plan)
    result = preview(client, event_id, saved["id"])

    for text in walk_strings(result):
        assert "\n" not in text
        assert "\r" not in text
    assert set(walk_keys(result)).isdisjoint(FORBIDDEN_TOP_LEVEL)
    human = cast(Device, result["devices"][0])["human_readable"]
    for statement in cast(list[str], human["statements"]):
        assert not CLI_LINE.match(statement.strip())
        assert "config" not in statement.split(" ")[0].lower()
    assert human["display_only"] is True
    assert human["executable"] is False

    routes = [
        route for route in getattr(client.app, "routes", ())
        if "layer2-config-preview" in getattr(route, "path", "")
    ]
    assert routes
    for route in routes:
        assert set(getattr(route, "methods", ()) or ()) == {"GET"}

    source = Path(layer2_config_preview.__file__).read_text(encoding="utf-8")
    lowered = source.lower()
    for token in (
        "socket", "paramiko", "netmiko", "telnetlib", "subprocess", "requests",
        "httpx", "scp ", "os.system", "popen",
    ):
        assert token not in lowered
    assert "device_writes_enabled: Literal[False]" in source
    assert "executable: Literal[False]" in source
    assert "cli: None" in source


_MISSING = object()


def published_schema(client: TestClient, kind: str) -> dict[str, Any]:
    response = client.get(f"{API}/contracts/layer2-config-preview/schema/{kind}")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/schema+json")
    return cast(dict[str, Any], response.json())


def collect_refs(value: object) -> Iterator[str]:
    if isinstance(value, dict):
        mapping = cast(dict[str, object], value)
        for key, item_value in mapping.items():
            if key == "$ref" and isinstance(item_value, str):
                yield item_value
            yield from collect_refs(item_value)
    elif isinstance(value, list):
        for item_value in cast(list[object], value):
            yield from collect_refs(item_value)


def resolve_pointer(document: object, pointer: str) -> object:
    assert pointer.startswith("#/"), pointer
    node: object = document
    for token in pointer[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            node = cast(list[object], node)[int(token)]
        else:
            mapping = cast(dict[str, object], node)
            assert token in mapping, pointer
            node = mapping[token]
    return node


def mutate(
    document: dict[str, Any], path: tuple[str | int, ...], value: object,
) -> dict[str, Any]:
    clone = copy.deepcopy(document)
    node: Any = clone
    for token in path[:-1]:
        node = node[token]
    if value is _MISSING:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return clone


def schema_errors(schema: dict[str, Any], document: object) -> list[str]:
    validator = Draft202012Validator(schema)
    return [error.message for error in validator.iter_errors(document)]


def test_schema_catalog_and_document_schema_media_types(
    client: TestClient,
) -> None:
    catalog_response = client.get(f"{API}/contracts/layer2-config-preview/schema")
    assert catalog_response.status_code == 200
    assert catalog_response.headers["content-type"].startswith("application/json")
    catalog = cast(dict[str, Any], catalog_response.json())
    assert catalog == config_preview_json_schema()
    assert catalog["contract_id"] == PREVIEW_CONTRACT_ID
    assert catalog["preview_schema_version"] == PREVIEW_SCHEMA_VERSION
    assert catalog["intent_schema_version"] == 1
    assert "$schema" not in catalog
    assert "properties" not in catalog
    assert preview_contract_fingerprint() == preview_contract_fingerprint()
    assert len(preview_contract_fingerprint()) == 64

    aggregate_schema = published_schema(client, "aggregate")
    device_schema = published_schema(client, "device")
    assert catalog["aggregate"] == aggregate_schema
    assert catalog["device"] == device_schema
    assert aggregate_schema == aggregate_preview_json_schema()
    assert device_schema == device_preview_json_schema()
    assert aggregate_schema["$schema"] == JSON_SCHEMA_DIALECT
    assert device_schema["$schema"] == JSON_SCHEMA_DIALECT
    assert aggregate_schema["title"] == "Layer2ConfigPreview"
    assert device_schema["title"] == "Layer2DeviceConfigPreview"
    properties = cast(dict[str, dict[str, Any]], aggregate_schema["properties"])
    assert properties["executable"]["const"] is False
    assert properties["device_writes_enabled"]["const"] is False
    assert properties["cli"]["type"] == "null"
    assert properties["cli"]["default"] is None
    assert properties["preview_schema_version"]["const"] == 1
    assert properties["contract_id"]["const"] == PREVIEW_CONTRACT_ID
    assert "ConfigItem" in cast(dict[str, Any], aggregate_schema["$defs"])

    openapi = cast(
        dict[str, Any], client.get(f"{API}/openapi.json").json(),
    )
    paths = cast(dict[str, dict[str, Any]], openapi["paths"])
    catalog_content = cast(
        dict[str, Any],
        paths[f"{API}/contracts/layer2-config-preview/schema"]["get"]["responses"][
            "200"
        ]["content"],
    )
    assert "application/json" in catalog_content
    assert "application/schema+json" not in catalog_content
    for kind in ("aggregate", "device"):
        content = cast(
            dict[str, Any],
            paths[f"{API}/contracts/layer2-config-preview/schema/{kind}"]["get"][
                "responses"
            ]["200"]["content"],
        )
        assert "application/schema+json" in content
        assert "application/json" not in content


def test_published_document_schemas_validate_real_preview_documents(
    client: TestClient,
) -> None:
    aggregate_schema = published_schema(client, "aggregate")
    device_schema = published_schema(client, "device")
    for schema in (aggregate_schema, device_schema):
        Draft202012Validator.check_schema(schema)
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert schema["$defs"]
        refs = set(collect_refs(schema))
        assert refs
        for ref in refs:
            assert ref.startswith("#/")
            assert resolve_pointer(schema, ref) is not None

    def routed_plan(event_id: str) -> dict[str, Any]:
        return make_plan(event_id, ports=[{
            "name": "Gi1/0/1",
            "settings": {"mode": "routed", "address": "10.0.0.1/30"},
        }])

    builders = (
        ("channel", full_plan),
        ("stack", make_stack_plan),
        ("routed", routed_plan),
    )
    for label, builder in builders:
        event_id = event(client, f"Schema validation {label}")
        saved = save(client, event_id, builder(event_id))
        aggregate = preview(client, event_id, saved["id"])
        errors = schema_errors(aggregate_schema, aggregate)
        assert not errors, f"{label} aggregate: {errors[:3]}"
        assert isinstance(
            Layer2ConfigPreview.model_validate(aggregate), Layer2ConfigPreview,
        )
        for device in cast(list[Device], aggregate["devices"]):
            document = device_document(
                client, event_id, saved["id"], device["assignment_id"],
            )
            errors = schema_errors(device_schema, document)
            assert not errors, f"{label} device {device['hostname']}: {errors[:3]}"
            assert isinstance(
                Layer2DeviceConfigPreview.model_validate(document),
                Layer2DeviceConfigPreview,
            )

    baseline_event = event(client, "Schema validation baseline")
    first_plan = full_plan(baseline_event)
    save(client, baseline_event, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][0]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
    }
    second = save(client, baseline_event, second_plan)
    aggregate = preview(client, baseline_event, second["id"])
    assert aggregate["before_state_evidence"] == "planning-baseline"
    assert not schema_errors(aggregate_schema, aggregate)
    for device in cast(list[Device], aggregate["devices"]):
        document = device_document(
            client, baseline_event, second["id"], device["assignment_id"],
        )
        assert not schema_errors(device_schema, document)


def test_published_document_schemas_reject_unsafe_or_malformed_documents(
    client: TestClient,
) -> None:
    aggregate_schema = published_schema(client, "aggregate")
    device_schema = published_schema(client, "device")
    event_id = event(client, "Schema rejection")
    saved = save(client, event_id, full_plan(event_id))
    aggregate = preview(client, event_id, saved["id"])
    device = device_document(
        client, event_id, saved["id"],
        cast(Device, aggregate["devices"][0])["assignment_id"],
    )
    aggregate_mutations: tuple[tuple[str, tuple[str | int, ...], object], ...] = (
        ("executable true", ("executable",), True),
        ("device writes true", ("device_writes_enabled",), True),
        ("cli string", ("cli",), "interface Gi1/0/1"),
        ("preview schema version", ("preview_schema_version",), 2),
        ("contract id", ("contract_id",), "other-contract"),
        ("missing preview fingerprint", ("preview_fingerprint",), _MISSING),
        ("missing event id", ("event_id",), _MISSING),
        ("devices type", ("devices",), "not-a-list"),
        (
            "nested deployable",
            ("devices", 0, "deployability", "deployable"),
            True,
        ),
    )
    for label, path, value in aggregate_mutations:
        mutated = mutate(aggregate, path, value)
        errors = schema_errors(aggregate_schema, mutated)
        assert errors, label
    device_mutations: tuple[tuple[str, tuple[str | int, ...], object], ...] = (
        ("executable true", ("executable",), True),
        ("device writes true", ("device_writes_enabled",), True),
        ("cli string", ("cli",), "interface Gi1/0/1"),
        ("preview schema version", ("preview_schema_version",), 2),
        ("contract id", ("contract_id",), "other-contract"),
        ("missing device", ("device",), _MISSING),
        ("missing revision id", ("revision_id",), _MISSING),
        ("vlan scope type", ("vlan_scope",), []),
        (
            "nested deployable",
            ("device", "deployability", "deployable"),
            True,
        ),
    )
    for label, path, value in device_mutations:
        mutated = mutate(device, path, value)
        errors = schema_errors(device_schema, mutated)
        assert errors, label
    assert not Draft202012Validator(aggregate_schema).is_valid({})
    assert not Draft202012Validator(device_schema).is_valid({})


def test_planning_baseline_values_and_unknown_baseline_fields(
    client: TestClient,
) -> None:
    event_id = event(client)
    first_plan = make_plan(
        event_id,
        ports=[{
            "name": "Gi1/0/1",
            "settings": {
                "mode": "access", "access_vlan": 20, "description": "Before",
            },
        }],
    )
    first = save(client, event_id, first_plan)
    first_preview = preview(client, event_id, first["id"])
    first_device = cast(Device, first_preview["devices"][0])
    assert item(first_device, "Gi1/0/1", "mode")["baseline"]["state"] == (
        "planning-baseline-unavailable"
    )

    second_plan = copy.deepcopy(first_plan)
    second_plan["physical_interfaces"][0]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
        "description": "After", "speed": 1000,
    }
    second = save(client, event_id, second_plan)
    result = preview(client, event_id, second["id"])
    device = cast(Device, result["devices"][0])
    mode = item(device, "Gi1/0/1", "mode")
    assert mode["planned"]["value"] == "trunk"
    assert mode["baseline"] == {
        "state": "planning-baseline",
        "value": "access",
        "revision_id": first["id"],
        "revision_hash": first["content_hash"],
    }
    assert mode["diff"]["changed"] is True
    assert mode["diff"]["transition"] == "access-to-trunk"
    assert mode["diff"]["cleanup"] == ["access_vlan", "routed_address"]
    assert mode["diff"]["change_id"].startswith("chg-")
    description = item(device, "Gi1/0/1", "description")
    assert description["planned"]["value"] == "After"
    assert description["baseline"]["value"] == "Before"
    assert description["diff"]["changed"] is True
    speed = item(device, "Gi1/0/1", "speed")
    assert speed["planned"]["value"] == 1000
    assert speed["baseline"]["state"] == "not-in-baseline"
    assert speed["baseline"]["value"] is None
    assert speed["baseline"]["revision_id"] == first["id"]
    assert speed["baseline"]["revision_hash"] == first["content_hash"]
    access_vlan = item(device, "Gi1/0/1", "access_vlan")
    assert access_vlan["planned"]["present"] is False
    assert access_vlan["planned"]["source"] == "not-in-plan"
    assert access_vlan["baseline"]["value"] == 20
    assert access_vlan["capability"]["verdict"] == "not-required"


def test_invalid_revision_fails_closed_for_every_item() -> None:
    plan = full_plan(new_id())
    revision = revision_for(plan, validation_status="INVALID").model_copy(update={
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
    intent_model = build_layer2_intent(revision, None)
    result = build_layer2_config_preview(revision, intent_model)
    assert result.readiness.structured_intent_valid is False
    assert result.readiness.hardware_verified is False
    assert result.readiness.deployment_allowed is False
    assert result.executable is False
    assert result.cli is None
    assert result.device_writes_enabled is False
    for device in result.devices:
        assert device.deployability.intent_gate == "invalid"
        assert device.deployability.evidence_gate == "intent-invalid"
        assert device.deployability.deployable is False
        for config_item in device.config_items:
            assert config_item.deployability.evidence_gate == "intent-invalid"
            assert config_item.deployability.deployable is False
            assert "structured-intent-invalid" in config_item.deployability.blockers


def test_cross_event_and_unknown_revision_are_rejected(client: TestClient) -> None:
    first_event = event(client, "Preview isolation A")
    second_event = event(client, "Preview isolation B")
    plan = make_plan(
        first_event,
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
    )
    saved = save(client, first_event, plan)
    assignment_id = plan["assignments"][0]["id"]
    for path in (
        f"{API}/events/{second_event}/plan-revisions/{saved['id']}",
        f"{API}/events/{second_event}/plan-revisions/{saved['id']}"
        "/layer2-config-preview",
        f"{API}/events/{second_event}/plan-revisions/{saved['id']}"
        f"/layer2-config-preview/devices/{assignment_id}",
        f"{API}/events/{first_event}/plan-revisions/{new_id()}"
        "/layer2-config-preview",
    ):
        assert client.get(path).status_code == 404
    assert preview(client, first_event, saved["id"])["devices"]
