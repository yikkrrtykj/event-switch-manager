from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_event_plans import API, ORIGIN, uid

from event_switch_manager.app import create_app
from event_switch_manager.settings import Settings


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "preview.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}) as session:
        yield session


def event(client: TestClient, name: str = "Synthetic draft evidence") -> str:
    response = client.post(f"{API}/events", json={"name": name})
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def save(client: TestClient, event_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = client.post(f"{API}/events/{event_id}/plan-revisions", json=payload)
    assert response.status_code == 200, response.text
    record: dict[str, Any] = response.json()
    return record


def draft_plan(
    event_id: str, *,
    pid: str | None = "C9300L-24P-4X",
    image: str | None = "17.12.4",
    license_name: str | None = "Network Advantage",
    name: str = "Gi1/0/1",
    serial: str | None = "SYN-CISCO-01",
    member: tuple[int, str, str] | None = None,
    claimed: bool = False,
) -> dict[str, Any]:
    software = None if image is None else {
        "image": image, "license": license_name,
        "capabilities": ([{"capability": "poe", "support": "supported"}] if claimed else []),
    }
    port: dict[str, Any] = {
        "id": uid(3), "assignment_id": uid(2), "physical_device_id": uid(1), "name": name,
        "settings": {"mode": "access", "access_vlan": 10},
        "capability_status": "verified" if claimed else "unknown",
    }
    data: dict[str, Any] = {
        "schema_version": 1, "event_id": event_id, "management_vlan": 10,
        "vlans": [{"id": 10, "name": "Management", "purpose": "management"}],
        "physical_devices": [{
            "id": uid(1), "vendor": "cisco", "model": pid, "verified_serial": serial,
        }],
        "assignments": [{
            "id": uid(2), "hostname": "lab-access", "role": "access",
            "physical_device_id": uid(1), "software": software,
        }],
        "physical_interfaces": [port],
    }
    if member:
        number, member_pid, state = member
        port["stack_member"] = 1
        data["physical_devices"].append({
            "id": uid(4), "vendor": "cisco", "model": member_pid,
            "verified_serial": "SYN-CISCO-02",
        })
        data["physical_interfaces"].append({
            **port, "id": uid(5), "physical_device_id": uid(4),
            "name": f"Gi{number}/0/1", "stack_member": number,
        })
        data["stacks"] = [{
            "assignment_id": uid(2),
            "members": [
                {"number": 1, "physical_device_id": uid(1), "state": "ready"},
                {"number": number, "physical_device_id": uid(4), "state": state},
            ],
        }]
    return data


def channel_plan(
    event_id: str, *, lacp: str = "active", member_ids: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    members = member_ids or (uid(10), uid(11))
    return {
        "schema_version": 1, "event_id": event_id, "management_vlan": 10,
        "vlans": [{"id": 10, "name": "Management", "purpose": "management"},
                  {"id": 20, "name": "Players"}],
        "physical_devices": [{
            "id": uid(1), "vendor": "cisco", "model": "C9300L-24P-4X",
            "verified_serial": "SYN-CHANNEL-01",
        }],
        "assignments": [{
            "id": uid(2), "hostname": "channel-access", "role": "access",
            "family": "catalyst-9300", "physical_device_id": uid(1),
            "software": {"image": "17.12.4", "license": "Network Advantage"},
        }],
        "physical_interfaces": [
            {"id": uid(10), "assignment_id": uid(2), "physical_device_id": uid(1),
             "name": "Gi1/0/1", "settings": trunk},
            {"id": uid(11), "assignment_id": uid(2), "physical_device_id": uid(1),
             "name": "Gi1/0/2", "settings": trunk},
        ],
        "logical_interfaces": [{
            "id": uid(12), "assignment_id": uid(2), "name": "Port-channel1",
            "kind": "port-channel",
        }],
        "port_channels": [{
            "interface_id": uid(12), "number": 1, "member_ids": list(members),
            "settings": trunk, "lacp": lacp,
        }],
    }


def preview(
    client: TestClient, event_id: str, plan: dict[str, Any],
    capabilities: tuple[str, ...] = ("poe",), **options: Any,
) -> dict[str, Any]:
    response = client.post(
        f"{API}/events/{event_id}/plan/capability-preview",
        json={
            "plan": plan, "assignment_id": uid(2), "capabilities": list(capabilities),
            **options,
        },
    )
    assert response.status_code == 200, response.text
    result: dict[str, Any] = response.json()
    assert result["source"] == "unsaved-draft"
    assert len(result["draft_fingerprint"]) == 64
    assert len(result["input_fingerprint"]) == 64
    assert len(result["decisions"]) == len(capabilities)
    assert [decision["capability_id"] for decision in result["decisions"]] == list(capabilities)
    for decision in result["decisions"]:
        assert decision["verification"] == "not-verified"
        assert decision["deployment_status"] == "blocked"
        assert decision["blocks_deployment"] is True
        assert {"deployment-generation-disabled", "hardware-not-verified",
                "draft-not-persisted"}.issubset(decision["deployment_blockers"])
        assert "revision_id" not in decision["affected"]
        assert "revision_hash" not in decision["affected"]
    return result


def by_capability(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {decision["capability_id"]: decision for decision in result["decisions"]}


def test_draft_matches_saved_evidence_without_persisting(client: TestClient) -> None:
    event_id = event(client)
    plan = draft_plan(event_id)
    saved = save(client, event_id, plan)
    revision_url = f"{API}/events/{event_id}/plan-revisions/{saved['id']}"
    saved_decision = client.get(
        f"{revision_url}/assignments/{uid(2)}/cisco-capability",
        params={"capability": "poe", "interface_id": uid(3)},
    ).json()
    assert "source" not in saved_decision
    assert saved_decision["affected"]["revision_id"] == saved["id"]

    before = client.get(f"{revision_url}/export")
    result = preview(client, event_id, plan, ("poe",), interface_id=uid(3))
    decision = result["decisions"][0]
    assert decision["verdict"] == saved_decision["verdict"] == "supported"
    assert decision["reason_code"] == saved_decision["reason_code"] == "poe-documented"
    assert decision["evidence"] == saved_decision["evidence"]
    assert result["draft_fingerprint"] == saved["content_hash"]
    assert result["input_fingerprint"] != result["draft_fingerprint"]

    revisions = client.get(f"{API}/events/{event_id}/plan-revisions").json()
    assert len(revisions) == 1 and revisions[0]["id"] == saved["id"]
    after = client.get(f"{revision_url}/export")
    assert after.content == before.content
    assert sha256(after.content).hexdigest() == saved["content_hash"]
    assert after.headers["etag"] == f'"{saved["content_hash"]}"'
    assert "revision_id" not in str(result)
    saved_missing = client.get(
        f"{revision_url}/assignments/{uid(99)}/cisco-capability",
        params={"capability": "poe"},
    )
    assert saved_missing.status_code == 404
    assert saved_missing.json()["detail"] == "Assignment not found in revision"
    draft_missing = client.post(
        f"{API}/events/{event_id}/plan/capability-preview",
        json={"plan": plan, "assignment_id": uid(99), "capabilities": ["poe"]},
    )
    assert draft_missing.status_code == 404
    assert draft_missing.json()["detail"] == "Assignment not found in plan"


def test_draft_identity_and_fingerprints_change_with_inputs(client: TestClient) -> None:
    event_id = event(client)
    base = draft_plan(event_id)
    first = preview(client, event_id, base, ("poe", "dhcp-relay"), interface_id=uid(3))
    again = preview(client, event_id, base, ("poe", "dhcp-relay"), interface_id=uid(3))
    assert first["draft_fingerprint"] == again["draft_fingerprint"]
    assert first["input_fingerprint"] == again["input_fingerprint"]

    changed = draft_plan(event_id, pid="C9300L-24T-4G")
    second = preview(client, event_id, changed, ("poe", "dhcp-relay"), interface_id=uid(3))
    assert second["draft_fingerprint"] != first["draft_fingerprint"]
    assert second["input_fingerprint"] != first["input_fingerprint"]
    assert by_capability(second)["poe"]["verdict"] == "unsupported"

    same_plan_new_query = preview(
        client, event_id, base, ("poe", "dhcp-relay"), interface_id=uid(3), speed=100,
    )
    assert same_plan_new_query["draft_fingerprint"] == first["draft_fingerprint"]
    assert same_plan_new_query["input_fingerprint"] != first["input_fingerprint"]


@pytest.mark.parametrize(("image", "license_name", "capability", "reason"), [
    ("17.12.2r", "Network Advantage", "dhcp-relay", "software-is-rommon"),
    ("17.12.99", "Network Advantage", "dhcp-relay", "release-unmatched"),
    ("17.9.4", "Network Advantage", "dhcp-relay", "release-unmatched"),
    ("17.12.5", "Network Advantage", "dhcp-relay", "release-evidence-missing"),
    (None, "Network Advantage", "dhcp-relay", "software-missing"),
    ("17.12.4", "Network Essentials", "dhcp-relay", "feature-license-unverified"),
    ("17.12.4", "LAN Base", "speed", "license-unmatched"),
])
def test_draft_software_and_license_are_fail_closed(
    client: TestClient, image: str | None, license_name: str | None,
    capability: str, reason: str,
) -> None:
    event_id = event(client)
    plan = draft_plan(event_id, image=image, license_name=license_name)
    result = preview(
        client, event_id, plan, (capability,), interface_id=uid(3),
        speed=1000 if capability == "speed" else None,
    )
    decision = result["decisions"][0]
    assert (decision["verdict"], decision["reason_code"], decision["evidence"]) == (
        "unknown", reason, [],
    )
    assert reason in decision["deployment_blockers"]


def test_draft_hardware_facts_survive_unknown_software(client: TestClient) -> None:
    event_id = event(client)
    plan = draft_plan(event_id, image="17.12.2r")
    result = preview(
        client, event_id, plan, ("identity", "port-media", "poe", "speed"),
        interface_id=uid(3), speed=1000,
    )
    decisions = by_capability(result)
    for capability in ("identity", "port-media", "poe"):
        assert decisions[capability]["verdict"] == "supported"
        assert all(row["version_scope"] is None for row in decisions[capability]["evidence"])
    assert decisions["speed"]["verdict"] == "unknown"
    assert decisions["speed"]["reason_code"] == "software-is-rommon"


def test_draft_interface_change_uses_new_medium_and_rates(client: TestClient) -> None:
    event_id = event(client)
    plan = draft_plan(event_id)
    copper = preview(client, event_id, plan, ("port-media", "speed", "poe"),
                     interface_id=uid(3), speed=1000)
    assert by_capability(copper)["port-media"]["port_groups"][0]["medium"] == "copper-rj45"

    plan["physical_interfaces"][0]["name"] = "Te1/1/4"
    fiber = preview(client, event_id, plan, ("port-media", "speed", "poe"),
                    interface_id=uid(3), speed=1000)
    decisions = by_capability(fiber)
    assert decisions["port-media"]["port_groups"][0]["medium"] == "sfp-plus"
    assert decisions["speed"]["verdict"] == "unknown"
    assert decisions["speed"]["reason_code"] == "optic-unknown"
    assert decisions["poe"]["verdict"] == "unsupported"

    plan["physical_interfaces"][0]["name"] = "Gi1/0/1"
    plan["physical_interfaces"][0]["physical_device_id"] = uid(9)
    wrong_chassis = preview(client, event_id, plan, ("poe",), interface_id=uid(3))
    assert wrong_chassis["decisions"][0]["verdict"] == "unknown"
    assert wrong_chassis["decisions"][0]["reason_code"] == "target-binding-unknown"
    plan["physical_interfaces"][0]["assignment_id"] = uid(9)
    missing = client.post(
        f"{API}/events/{event_id}/plan/capability-preview",
        json={
            "plan": plan, "assignment_id": uid(2), "capabilities": ["poe"],
            "interface_id": uid(3),
        },
    )
    assert missing.status_code == 404


@pytest.mark.parametrize(("pid", "name", "medium", "rates"), [
    ("C9300L-24P-4X", "Gi1/0/1", "copper-rj45", [10, 100, 1000]),
    ("C9300L-24T-4G", "GigabitEthernet1/1/4", "sfp", [1000]),
    ("C9300L-24P-4X", "Te1/1/4", "sfp-plus", [1000, 10000]),
    ("C9300X-24Y", "TwentyFiveGigE1/0/24", "sfp28", [1000, 10000, 25000]),
])
def test_draft_medium_and_rate_differences(
    client: TestClient, pid: str, name: str, medium: str, rates: list[int],
) -> None:
    event_id = event(client)
    plan = draft_plan(event_id, pid=pid, name=name)
    result = preview(client, event_id, plan, ("port-media",), interface_id=uid(3))
    group = result["decisions"][0]["port_groups"][0]
    assert (group["medium"], group["rates"]) == (medium, rates)


def test_draft_candidates_keep_documented_port_groups(client: TestClient) -> None:
    """The Port Editor candidate policy relies on the documented range for every target."""
    event_id = event(client)
    plan = draft_plan(event_id, pid="C9300L-24T-4G")
    copper = by_capability(preview(
        client, event_id, plan, ("speed", "duplex", "poe"), interface_id=uid(3),
    ))
    assert (copper["speed"]["verdict"], copper["speed"]["reason_code"]) == (
        "unknown", "speed-required",
    )
    assert copper["speed"]["port_groups"][0]["medium"] == "copper-rj45"
    assert copper["speed"]["port_groups"][0]["rates"] == [10, 100, 1000]
    assert copper["duplex"]["port_groups"][0]["rates"] == [10, 100, 1000]
    assert copper["poe"]["verdict"] == "unsupported"
    assert copper["poe"]["port_groups"][0]["poe_plus"] is False

    plan["physical_interfaces"][0]["name"] = "GigabitEthernet1/1/4"
    fiber_speed = preview(client, event_id, plan, ("speed",), interface_id=uid(3), speed=1000)
    assert (fiber_speed["decisions"][0]["verdict"], fiber_speed["decisions"][0]["reason_code"]) == (
        "unknown", "optic-unknown",
    )
    assert fiber_speed["decisions"][0]["port_groups"][0]["medium"] == "sfp"
    assert fiber_speed["decisions"][0]["port_groups"][0]["rates"] == [1000]

    plan["physical_interfaces"][0]["name"] = "Gi1/0/1"
    outside = preview(client, event_id, plan, ("speed",), interface_id=uid(3), speed=2500)
    assert outside["decisions"][0]["verdict"] == "unsupported"
    assert outside["decisions"][0]["reason_code"] == "speed-outside-port-range"
    assert outside["decisions"][0]["port_groups"][0]["rates"] == [10, 100, 1000]

    licensed = draft_plan(event_id, pid="C9300L-24T-4G", license_name="LAN Base")
    unknown = by_capability(preview(
        client, event_id, licensed, ("speed", "duplex"), interface_id=uid(3),
    ))
    for capability in ("speed", "duplex"):
        assert unknown[capability]["reason_code"] == "license-unmatched"
        assert unknown[capability]["port_groups"] == []


def test_draft_speed_and_duplex_options(client: TestClient) -> None:
    event_id = event(client)
    plan = draft_plan(event_id)
    cases: list[tuple[dict[str, int | str], str, str]] = [
        ({"speed": 100}, "speed", "supported"),
        ({"speed": 2500}, "speed", "unsupported"),
        ({"speed": 100, "duplex": "half"}, "duplex", "supported"),
        ({"speed": 1000, "duplex": "half"}, "duplex", "unsupported"),
        ({"speed": "auto", "duplex": "half"}, "duplex", "unknown"),
    ]
    for options, capability, verdict in cases:
        result = preview(client, event_id, plan, (capability,), interface_id=uid(3), **options)
        assert result["decisions"][0]["verdict"] == verdict


def test_draft_stack_member_and_interface_ownership(client: TestClient) -> None:
    event_id = event(client)
    plan = draft_plan(event_id, member=(2, "C9300L-24P-4X", "ready"))
    result = preview(client, event_id, plan, ("stack", "port-media"), interface_id=uid(5))
    decisions = by_capability(result)
    assert decisions["stack"]["verdict"] == "supported"
    assert decisions["port-media"]["affected"]["stack_member"] == 2
    assert decisions["port-media"]["affected"]["physical_device_id"] == uid(4)

    unsupported = preview(client, event_id, plan, ("stack",), stack_member=9)
    assert unsupported["decisions"][0]["verdict"] == "unknown"
    assert unsupported["decisions"][0]["reason_code"] == "target-binding-unknown"

    wrong = client.post(
        f"{API}/events/{event_id}/plan/capability-preview",
        json={
            "plan": plan, "assignment_id": uid(2), "capabilities": ["port-media"],
            "interface_id": uid(7),
        },
    )
    assert wrong.status_code == 404


def test_draft_rejects_cross_event_identity_and_mismatched_event(client: TestClient) -> None:
    first, second = event(client), event(client, "Other synthetic event")
    other_plan = draft_plan(second)
    save(client, second, other_plan)
    plan = draft_plan(first)
    response = client.post(
        f"{API}/events/{first}/plan/capability-preview",
        json={"plan": plan, "assignment_id": uid(2), "capabilities": ["poe"]},
    )
    assert response.status_code == 422
    assert any(issue["code"] == "assignment_event" for issue in response.json()["detail"])

    wrong_event = client.post(
        f"{API}/events/{first}/plan/capability-preview",
        json={
            "plan": {**plan, "event_id": second}, "assignment_id": uid(2),
            "capabilities": ["poe"],
        },
    )
    assert wrong_event.status_code == 422
    assert wrong_event.json()["detail"][0]["code"] == "event_mismatch"


def test_draft_channel_changes_are_in_fingerprints_without_persisting(client: TestClient) -> None:
    event_id = event(client)
    capabilities = ("lacp", "port-channel", "access")
    active = preview(
        client, event_id, channel_plan(event_id), capabilities, interface_id=uid(10),
    )
    passive = preview(
        client, event_id, channel_plan(event_id, lacp="passive"), capabilities,
        interface_id=uid(10),
    )
    one_member = preview(
        client, event_id, channel_plan(event_id, member_ids=(uid(10),)), capabilities,
        interface_id=uid(10),
    )
    assert active["draft_fingerprint"] != passive["draft_fingerprint"]
    assert active["input_fingerprint"] != passive["input_fingerprint"]
    assert passive["draft_fingerprint"] != one_member["draft_fingerprint"]
    assert passive["input_fingerprint"] != one_member["input_fingerprint"]
    for result in (active, passive, one_member):
        assert len(result["decisions"]) == 3
        assert result["decisions"][0]["verdict"] == "supported"
        assert result["decisions"][0]["affected"]["interface_id"] == uid(10)
        assert result["decisions"][0]["affected"]["interface_name"] == "Gi1/0/1"
        assert "revision_id" not in result["decisions"][0]["affected"]
    assert client.get(f"{API}/events/{event_id}/plan-revisions").json() == []


def test_draft_imported_claims_cannot_promote_evidence(client: TestClient) -> None:
    event_id = event(client)
    plan = draft_plan(event_id, pid=None, claimed=True)
    result = preview(client, event_id, plan, ("poe",), interface_id=uid(3))
    decision = result["decisions"][0]
    assert (decision["verdict"], decision["reason_code"], decision["evidence"]) == (
        "unknown", "identity-incomplete", [],
    )
    assert plan["physical_interfaces"][0]["capability_status"] == "verified"


def test_draft_invalid_plan_stays_blocked(client: TestClient) -> None:
    event_id = event(client)
    plan = draft_plan(event_id)
    plan["physical_interfaces"][0]["settings"]["native_vlan"] = 10
    result = preview(client, event_id, plan, ("poe",), interface_id=uid(3))
    decision = result["decisions"][0]
    assert decision["verdict"] == "supported"
    assert "plan-invalid" in decision["deployment_blockers"]


def test_draft_preview_validates_request_and_origin(client: TestClient) -> None:
    event_id = event(client)
    plan = draft_plan(event_id)
    body = {"plan": plan, "assignment_id": uid(2), "capabilities": ["poe"]}
    assert client.post(f"{API}/events/{event_id}/plan/capability-preview", json={
        **body, "capabilities": [],
    }).status_code == 422
    assert client.post(f"{API}/events/{event_id}/plan/capability-preview", json={
        **body, "capabilities": ["not-a-capability"],
    }).status_code == 422
    assert client.post(f"{API}/events/{event_id}/plan/capability-preview", json={
        **body, "capabilities": ["poe", "poe"],
    }).status_code == 422
    assert client.post(f"{API}/events/{event_id}/plan/capability-preview", json={
        **body, "capabilities": ["poe"] * 33,
    }).status_code == 422
    assert client.post(f"{API}/events/{event_id}/plan/capability-preview", json={
        **body, "stack_member": 0,
    }).status_code == 422
    assert client.post(f"{API}/events/{event_id}/plan/capability-preview", json={
        **body, "speed": "fast",
    }).status_code == 422
    assert client.post(f"{API}/events/{event_id}/plan/capability-preview", json={
        **body, "duplex": "both",
    }).status_code == 422

    origin = client.headers.pop("origin")
    try:
        assert client.post(
            f"{API}/events/{event_id}/plan/capability-preview", json=body,
        ).status_code == 403
    finally:
        client.headers["origin"] = origin


def test_draft_multiple_capabilities_and_batch_limits(client: TestClient) -> None:
    event_id = event(client)
    plan = draft_plan(event_id)
    capabilities = (
        "port-layout", "port-media", "poe", "speed", "duplex", "access", "trunk",
        "routed-port", "lacp", "port-channel", "portfast", "bpdu-guard", "stack",
        "svi", "ipv4-routing", "dhcp-relay",
    )
    result = preview(client, event_id, plan, capabilities, interface_id=uid(3))
    decisions = by_capability(result)
    assert set(decisions) == set(capabilities)
    assert decisions["stack"]["verdict"] == "supported"
    assert decisions["dhcp-relay"]["verdict"] == "supported"
    assert decisions["svi"]["verdict"] == "supported"
    assert all(len(decision["deployment_blockers"]) >= 3 for decision in decisions.values())
