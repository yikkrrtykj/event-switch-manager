from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_event_plans import API, ORIGIN, synthetic_plan, uid

from event_switch_manager.app import create_app
from event_switch_manager.settings import Settings


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "capabilities.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}) as session:
        yield session


def event(client: TestClient, name: str = "Synthetic Cisco evidence") -> str:
    response = client.post(f"{API}/events", json={"name": name})
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def save(client: TestClient, event_id: str, payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    collection = f"{API}/events/{event_id}/plan-revisions"
    response = client.post(collection, json=payload)
    assert response.status_code == 200, response.text
    record: dict[str, Any] = response.json()
    return f"{collection}/{record['id']}", record


def fixture_plan(
    client: TestClient, pid: str | None, *, image: str = "17.12.4",
    license_name: str | None = "Network Advantage", interface: str = "Gi1/0/1",
    serial: str | None = "SYN-CISCO-01", member: tuple[int, str, str] | None = None,
) -> tuple[str, dict[str, Any]]:
    event_id = event(client)
    asset = {"id": uid(1), "vendor": "cisco", "model": pid, "verified_serial": serial}
    assignment = {
        "id": uid(2), "hostname": "lab-access", "role": "access", "physical_device_id": uid(1),
        "software": {"image": image, "license": license_name,
                     "capabilities": [{"capability": "poe", "support": "supported"}]},
    }
    port: dict[str, Any] = {
        "id": uid(3), "assignment_id": uid(2), "physical_device_id": uid(1), "name": interface,
        "settings": {"mode": "access", "access_vlan": 10}, "capability_status": "verified",
    }
    data: dict[str, Any] = {
        "schema_version": 1, "event_id": event_id, "physical_devices": [asset],
        "assignments": [assignment], "physical_interfaces": [port],
        "vlans": [{"id": 10, "name": "Management", "purpose": "management"}],
    }
    if member:
        number, member_pid, state = member
        port["stack_member"] = 1
        data["physical_devices"].append({
            "id": uid(4), "vendor": "cisco", "model": member_pid, "verified_serial": "SYN-CISCO-02",
        })
        data["physical_interfaces"].append({
            **port, "id": uid(5), "physical_device_id": uid(4),
            "name": f"Gi{number}/0/1", "stack_member": number,
        })
        data["stacks"] = [{"assignment_id": uid(2), "members": [
            {"number": 1, "physical_device_id": uid(1), "state": "ready"},
            {"number": number, "physical_device_id": uid(4), "state": state},
        ]}]
    return save(client, event_id, data)


def lookup(
    client: TestClient, url: str, capability: str, *, port: bool = False, **options: int | str,
) -> dict[str, Any]:
    if port:
        options["interface_id"] = uid(3)
    response = client.get(f"{url}/assignments/{uid(2)}/cisco-capability",
                          params={"capability": capability, **options})
    assert response.status_code == 200, response.text
    result: dict[str, Any] = response.json()
    assert result["capability_id"] == capability
    assert result["verification"] == "not-verified"
    assert result["deployment_status"] == "blocked"
    assert result["blocks_deployment"] is True
    assert {"deployment-generation-disabled", "hardware-not-verified"}.issubset(
        result["deployment_blockers"]
    )
    if result["verdict"] != "supported":
        assert result["reason_code"] in result["deployment_blockers"]
    for evidence in result["evidence"]:
        assert evidence["sku"] == result["affected"]["sku"]
        assert evidence["url"].startswith("https://www.cisco.com/")
        assert evidence["section"] and evidence["conditions"]
    return result


@pytest.mark.parametrize(("pid", "version", "tier", "verdict"), [
    ("WS-C2960X-24TS-L", "15.2(7)E7", "LAN Base", "unsupported"),
    ("WS-C2960X-24PS-L", "15.2(7)E7", "LAN Base", "supported"),
    ("WS-C3850-24T", "16.12.12", "IP Base", "unsupported"),
    ("WS-C3850-24P", "16.12.12", "IP Base", "supported"),
    ("C9200L-24T-4G", "17.12.4", "Network Essentials", "unsupported"),
    ("C9200L-24P-4X", "17.12.4", "Network Essentials", "supported"),
    ("C9300L-24T-4G", "17.12.4", "Network Advantage", "unsupported"),
    ("C9300L-24P-4X", "17.12.4", "Network Advantage", "supported"),
    ("C1000-24T-4G-L", "15.2(7)E", None, "unsupported"),
    ("C1000-24P-4G-L", "15.2(7)E", None, "supported"),
])
def test_poe_varies_by_pid(
    client: TestClient, pid: str, version: str, tier: str | None, verdict: str,
) -> None:
    url, _ = fixture_plan(client, pid, image=version, license_name=tier)
    decision = lookup(client, url, "poe", port=True)
    assert decision["verdict"] == verdict
    assert decision["port_groups"][0]["poe_plus"] is (verdict == "supported")


@pytest.mark.parametrize(("version", "tier", "verdict", "reason"), [
    ("17.12.4a", "Network Advantage", "supported", "feature-documented"),
    ("17.9.4", "Network Advantage", "unknown", "release-unmatched"),
    ("17.120.4", "Network Advantage", "unknown", "release-unmatched"),
    ("17.12.4", None, "unknown", "license-unmatched"),
    ("17.12.4", "LAN Base", "unknown", "license-unmatched"),
    ("17.12.4", "Network Essentials", "unknown", "feature-license-unverified"),
])
def test_dhcp_relay_release_and_license(
    client: TestClient, version: str, tier: str | None, verdict: str, reason: str,
) -> None:
    url, _ = fixture_plan(client, "C9300L-24P-4X", image=version, license_name=tier)
    decision = lookup(client, url, "dhcp-relay")
    assert (decision["verdict"], decision["reason_code"]) == (verdict, reason)
    if verdict == "unknown":
        assert decision["evidence"] == []
    else:
        assert decision["evidence"][0]["licenses"] == ["Network Advantage"]
        assert decision["evidence"][0]["version_scope"] == "IOS XE 17.12.x"


@pytest.mark.parametrize(("pid", "name", "media", "rates"), [
    ("C9300L-24T-4G", "Gi1/0/1", "copper-rj45", [10, 100, 1000]),
    ("C9300L-24T-4G", "GigabitEthernet1/1/4", "sfp", [1000]),
    ("C9300L-24P-4X", "Te1/1/4", "sfp-plus", [1000, 10000]),
    ("C9300X-24Y", "TwentyFiveGigE1/0/24", "sfp28", [1000, 10000, 25000]),
])
def test_medium_and_rate_bounds(
    client: TestClient, pid: str, name: str, media: str, rates: list[int],
) -> None:
    url, _ = fixture_plan(client, pid, interface=name)
    result = lookup(client, url, "port-media", port=True)
    assert result["verdict"] == "supported"
    group = result["port_groups"][0]
    assert group["medium"] == media and group["rates"] == rates
    if media != "copper-rj45":
        assert lookup(client, url, "speed", port=True, speed=rates[-1])["verdict"] == "unknown"
        assert lookup(client, url, "speed", port=True, speed=40000)["verdict"] == "unsupported"
        assert lookup(client, url, "poe-plus", port=True)["verdict"] == "unsupported"


def test_copper_options_do_not_change_revision(client: TestClient) -> None:
    url, saved = fixture_plan(client, "C9300L-24P-4X")
    cases: list[tuple[str, dict[str, int | str], str]] = [
        ("speed", {"speed": 100}, "supported"),
        ("speed", {"speed": 2500}, "unsupported"),
        ("duplex", {"speed": 100, "duplex": "half"}, "supported"),
        ("duplex", {"speed": 1000, "duplex": "half"}, "unsupported"),
        ("duplex", {"speed": "auto", "duplex": "half"}, "unknown"),
    ]
    for capability, options, verdict in cases:
        result = lookup(client, url, capability, port=True, **options)
        assert result["verdict"] == verdict
        assert result["affected"]["revision_hash"] == saved["content_hash"]
    assert client.get(url).json() == saved


@pytest.mark.parametrize(("pid", "version", "tier", "verdict"), [
    ("WS-C2960X-24TS-L", "15.2(7)E", "LAN Base", "supported"),
    ("WS-C2960X-24TS-LL", "15.2(7)E", "LAN Lite", "unsupported"),
    ("C1000-24P-4G-L", "15.2(7)E", None, "unknown"),
])
def test_standalone_stacking_capability(
    client: TestClient, pid: str, version: str, tier: str | None, verdict: str,
) -> None:
    url, _ = fixture_plan(client, pid, image=version, license_name=tier)
    assert lookup(client, url, "stack")["verdict"] == verdict


@pytest.mark.parametrize(("number", "state", "verdict"), [
    (2, "ready", "supported"), (9, "ready", "unsupported"), (2, "unknown", "unknown"),
])
def test_stack_binds_the_physical_member(
    client: TestClient, number: int, state: str, verdict: str,
) -> None:
    pid = "C9300L-24P-4X"
    url, _ = fixture_plan(client, pid, member=(number, pid, state))
    assert lookup(client, url, "stack")["verdict"] == verdict
    port = lookup(client, url, "port-media", interface_id=uid(5))
    assert port["affected"]["stack_member"] == number
    assert port["affected"]["physical_device_id"] == uid(4)
    if number == 9:
        assert port["verdict"] == "unknown"
    assert lookup(client, url, "poe", port=True, stack_member=number)["verdict"] == "unknown"


def test_mixed_stack_each_port_uses_its_own_pid(client: TestClient) -> None:
    url, _ = fixture_plan(client, "C9300L-24T-4G", member=(2, "C9300L-24P-4X", "ready"))
    assert lookup(client, url, "stack")["verdict"] == "unknown"
    assert lookup(client, url, "poe", port=True)["verdict"] == "unsupported"
    assert lookup(client, url, "poe", interface_id=uid(5))["verdict"] == "supported"


@pytest.mark.parametrize(("pid", "serial", "reason"), [
    (None, "SYN-1", "identity-incomplete"),
    ("C9300L-24P-4X", None, "identity-incomplete"),
    ("C9300L", "SYN-1", "pid-unlisted"),
    ("C9300L-48T-4G", "SYN-1", "pid-unlisted"),
])
def test_imported_claim_cannot_upgrade_unknown(
    client: TestClient, pid: str | None, serial: str | None, reason: str,
) -> None:
    url, saved = fixture_plan(client, pid, serial=serial)
    assert saved["plan"]["physical_interfaces"][0]["capability_status"] == "verified"
    result = lookup(client, url, "poe", port=True)
    assert (result["verdict"], result["reason_code"], result["evidence"]) == ("unknown", reason, [])


def test_routing_and_operational_prerequisites(client: TestClient) -> None:
    url, _ = fixture_plan(client, "C9300L-24P-4X")
    for item in ("svi", "ipv4-routing", "routed-port", "static-route", "default-route"):
        assert lookup(client, url, item)["verdict"] == "supported"
    for item in ("ssh-v2", "boot", "storage"):
        result = lookup(client, url, item)
        assert result["verdict"] == "unknown" and result["evidence"]


def test_modular_layout_requires_installed_module(client: TestClient) -> None:
    url, _ = fixture_plan(client, "WS-C3850-24T", image="16.12.12", license_name="IP Base",
                          interface="Te1/1/1")
    layout = lookup(client, url, "port-layout")
    assert layout["verdict"] == "unknown"
    assert layout["port_groups"][0]["count"] == 24
    assert lookup(client, url, "poe", port=True)["reason_code"] == "port-layout-unknown"


def test_legacy_revision_and_event_isolation(client: TestClient) -> None:
    first, second = event(client), event(client, "Other synthetic event")
    raw = synthetic_plan(first)
    url, saved = save(client, first, raw)
    before = client.get(f"{url}/export")
    endpoint = f"{url}/assignments/{uid(4)}/cisco-capability"
    result = client.get(endpoint, params={"capability": "poe", "interface_id": uid(6)})
    assert result.status_code == 200 and result.json()["verdict"] == "unknown"
    outside = client.get(endpoint.replace(first, second), params={"capability": "poe"})
    wrong_port = client.get(endpoint, params={"capability": "poe", "interface_id": uid(7)})
    assert outside.status_code == wrong_port.status_code == 404
    _, again = save(client, first, raw)
    after = client.get(f"{url}/export")
    assert again == saved
    assert after.content == before.content
    assert sha256(after.content).hexdigest() == saved["content_hash"]
    assert before.headers["etag"] == after.headers["etag"] == f'"{saved["content_hash"]}"'
    assert client.post(endpoint, json={"capability": "poe"}).status_code == 405
    assert client.get(f"{API}/health").json()["device_writes_enabled"] is False
