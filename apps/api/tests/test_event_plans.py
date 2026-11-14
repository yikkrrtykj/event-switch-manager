from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from event_switch_manager.app import create_app
from event_switch_manager.database import create_database_engine
from event_switch_manager.planning.checks import validate_plan
from event_switch_manager.planning.plan import EventPlan, canonical_plan, plan_hash
from event_switch_manager.settings import Settings

ORIGIN = "http://127.0.0.1:8765"
API = "/api/v1"


def uid(n: int) -> str:
    return str(UUID(int=n))


def synthetic_plan(event_id: str) -> dict[str, object]:
    access = {"mode": "access", "access_vlan": 9}
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    return {
        "schema_version": 1,
        "event_id": event_id,
        "physical_devices": [
            {"id": uid(1), "vendor": "cisco", "verified_serial": "SYN-CORE-A"},
            {"id": uid(2), "vendor": "cisco", "verified_serial": "SYN-CORE-B"},
            {"id": uid(3), "vendor": "hillstone", "verified_serial": "SYN-FW"},
        ],
        "assignments": [
            {"id": uid(4), "hostname": "Lab-Core", "role": "core", "physical_device_id": uid(1)},
            {"id": uid(5), "hostname": "Lab-FW", "role": "access", "physical_device_id": uid(3)},
        ],
        "stacks": [{"assignment_id": uid(4), "members": [
            {"number": 1, "physical_device_id": uid(1)},
            {"number": 2, "physical_device_id": uid(2)},
        ]}],
        "physical_interfaces": [
            {"id": uid(6), "assignment_id": uid(4), "physical_device_id": uid(1),
             "name": "Gi1/0/1", "stack_member": 1, "settings": access},
            {"id": uid(7), "assignment_id": uid(5), "physical_device_id": uid(3),
             "name": "ethernet0/0", "settings": access},
            {"id": uid(8), "assignment_id": uid(4), "physical_device_id": uid(1),
             "name": "Gi1/0/2", "stack_member": 1, "settings": trunk},
            {"id": uid(9), "assignment_id": uid(4), "physical_device_id": uid(2),
             "name": "Gi2/0/2", "stack_member": 2, "settings": trunk},
            {"id": uid(10), "assignment_id": uid(5), "physical_device_id": uid(3),
             "name": "ethernet0/1", "settings": {"mode": "routed", "address": "192.0.2.2/30"}},
            {"id": uid(11), "assignment_id": uid(5), "physical_device_id": uid(3),
             "name": "ethernet0/2", "settings": {"mode": "routed", "address": "198.51.100.2/30"}},
        ],
        "logical_interfaces": [
            {"id": uid(12), "assignment_id": uid(4), "name": "Vlan9",
             "kind": "svi", "vlan": 9, "address": "10.0.0.1/30"},
            {"id": uid(13), "assignment_id": uid(4), "name": "Vlan10",
             "kind": "svi", "vlan": 10, "address": "192.168.10.1/24"},
            {"id": uid(14), "assignment_id": uid(4), "name": "Port-channel1",
             "kind": "port-channel"},
        ],
        "port_channels": [{"interface_id": uid(14), "number": 1,
                           "member_ids": [uid(8), uid(9)], "settings": trunk}],
        "links": [{"id": uid(15), "endpoints": [uid(6), uid(7)]}],
        "vlans": [{"id": 9, "name": "Transit", "purpose": "transit"},
                  {"id": 10, "name": "Management", "purpose": "management"},
                  {"id": 20, "name": "Players"}],
        "subnets": [{"id": uid(16), "vlan": 10, "network": "192.168.10.0/24"}],
        "gateways": [{"subnet_id": uid(16), "address": "192.168.10.1", "svi_id": uid(13)}],
        "dhcp_pools": [{"id": uid(17), "subnet_id": uid(16),
                        "start": "192.168.10.20", "end": "192.168.10.40"}],
        "dhcp_reservations": [{"id": uid(18), "subnet_id": uid(16),
                               "address": "192.168.10.10", "client_mac": "02:00:00:00:00:01"}],
        "dhcp_relays": [{"subnet_id": uid(16), "svi_id": uid(13), "servers": ["192.168.10.5"]}],
        "vlan_access_policies": [{"id": uid(19), "priority": 10, "source_vlan": 20,
                                  "destination_vlan": 10, "action": "deny"}],
        "transit": {"core_assignment_id": uid(4), "hillstone_assignment_id": uid(5),
                    "core_port_id": uid(6), "hillstone_port_id": uid(7), "core_svi_id": uid(12),
                    "network": "10.0.0.0/30", "core_ip": "10.0.0.1", "hillstone_ip": "10.0.0.2"},
        "tracks": [{"id": uid(20), "target": "192.0.2.1"},
                   {"id": uid(21), "target": "198.51.100.1"},
                   {"id": uid(22), "target": "10.0.1.2"}],
        "isps": [
            {"id": uid(23), "name": "Primary", "assignment_id": uid(5), "interface_id": uid(10),
             "address": "192.0.2.2/30", "gateway": "192.0.2.1", "track_id": uid(20)},
            {"id": uid(24), "name": "Secondary", "assignment_id": uid(5), "interface_id": uid(11),
             "address": "198.51.100.2/30", "gateway": "198.51.100.1", "track_id": uid(21)},
        ],
        "ipsec_tunnels": [
            {"id": uid(25), "name": "Lab VPN", "assignment_id": uid(5), "isp_id": uid(23),
             "peer": "203.0.113.2", "inside": "10.0.1.1/30", "remote_gateway": "10.0.1.2",
             "track_id": uid(22)},
        ],
        "vpn_remote_prefixes": [{"tunnel_id": uid(25), "network": "172.16.20.0/24"}],
        "static_routes": [
            {"id": uid(26), "assignment_id": uid(5), "destination": "192.168.0.0/16",
             "next_hop": {"kind": "ip", "address": "10.0.0.1"}},
            {"id": uid(27), "assignment_id": uid(5), "destination": "172.16.20.0/24",
             "next_hop": {"kind": "tunnel", "tunnel_id": uid(25)}},
            {"id": uid(28), "assignment_id": uid(5), "destination": "172.16.20.0/24",
             "next_hop": {"kind": "discard"}, "preference": 200},
        ],
        "default_routes": [{"id": uid(29), "assignment_id": uid(4),
                            "next_hop": {"kind": "ip", "address": "10.0.0.2"}}],
        "source_routes": [{"id": uid(30), "assignment_id": uid(5), "source_vlan": 20,
                           "isp_priority": [uid(23), uid(24)]}],
        "policy_routes": [{"id": uid(31), "assignment_id": uid(5), "priority": 10,
                           "source_vlan": 20, "destination": "172.16.20.0/24",
                           "tunnel_id": uid(25)}],
        "snat": [{"id": uid(32), "assignment_id": uid(5), "source_vlan": 20,
                  "isp_id": uid(23), "translated_ip": "192.0.2.2"}],
        "nat_exemptions": [{"id": uid(33), "assignment_id": uid(5), "source_vlan": 20,
                            "destination": "172.16.20.0/24", "tunnel_id": uid(25)}],
    }


def plan_model() -> EventPlan:
    return EventPlan.model_validate(synthetic_plan(uid(99)))


def test_canonical_hash_keeps_isp_priority_and_normalizes_sets() -> None:
    plan = plan_model()
    assert validate_plan(plan) == ()
    canonical = canonical_plan(plan)
    assert canonical_plan(EventPlan.model_validate_json(canonical)) == canonical
    reversed_plan = plan.model_copy(update={"vlans": plan.vlans[::-1], "links": (
        plan.links[0].model_copy(update={"endpoints": plan.links[0].endpoints[::-1]}),
    )})
    assert plan_hash(canonical_plan(reversed_plan)) == plan_hash(canonical)
    swapped = plan.source_routes[0].model_copy(update={
        "isp_priority": plan.source_routes[0].isp_priority[::-1],
    })
    assert plan_hash(canonical_plan(plan.model_copy(update={"source_routes": (swapped,)}))) != (
        plan_hash(canonical)
    )


@pytest.mark.parametrize(("group", "index", "field", "value", "code"), [
    ("vlans", 2, "id", 10, "duplicate"),
    ("vlans", 2, "name", "management", "duplicate"),
    ("subnets", 0, "vlan", 42, "vlan_reference"),
    ("gateways", 0, "address", "192.168.10.255", "gateway_address"),
    ("dhcp_pools", 0, "start", "192.168.10.1", "dhcp_gateway"),
    ("dhcp_pools", 0, "end", "192.168.11.3", "dhcp_bounds"),
    ("dhcp_reservations", 0, "address", "192.168.10.21", "dhcp_reservation_pool"),
    ("dhcp_relays", 0, "servers", ["127.0.0.1"], "dhcp_relay_server"),
    ("physical_interfaces", 3, "name", "Gi1/0/2", "stack_port"),
    ("port_channels", 0, "member_ids", [uid(7)], "port_channel_member"),
    ("links", 0, "endpoints", [uid(6), uid(90)], "topology_endpoints"),
    ("isps", 0, "gateway", "203.0.113.1", "next_hop"),
    ("static_routes", 0, "next_hop", {"kind": "ip", "address": "10.90.0.1"}, "next_hop"),
    ("source_routes", 0, "isp_priority", [uid(24), uid(24)], "isp_priority"),
    ("policy_routes", 0, "destination", "172.16.30.0/24", "vpn_policy"),
    ("vpn_remote_prefixes", 0, "network", "192.168.140.0/24", "vpn_return_overlap"),
    ("static_routes", 2, "destination", "172.16.30.0/24", "vpn_down_route"),
    ("static_routes", 2, "preference", 1, "duplicate"),
])
def test_network_conflicts_are_locatable(
    group: str, index: int, field: str, value: object, code: str
) -> None:
    raw = plan_model().model_dump(mode="json")
    raw[group][index][field] = value
    issues = validate_plan(EventPlan.model_validate(raw))
    expected_path = "vpn_remote_prefixes.0" if code == "vpn_down_route" else f"{group}.{index}"
    assert any(issue.path.startswith(expected_path) and issue.code == code for issue in issues)


def test_more_specific_route_cannot_bypass_vpn() -> None:
    raw = plan_model().model_dump(mode="json")
    raw["static_routes"].append({
        "id": uid(40), "assignment_id": uid(5), "destination": "172.16.20.0/25",
        "next_hop": {"kind": "ip", "address": "10.0.0.1"},
    })
    issues = validate_plan(EventPlan.model_validate(raw))
    assert {issue.code for issue in issues} >= {"vpn_tunnel_route", "vpn_down_route"}


def test_transit_rejects_shadowed_forward_and_return_routes() -> None:
    raw = plan_model().model_dump(mode="json")
    raw["default_routes"][0]["preference"] = 100
    raw["default_routes"].append({
        "id": uid(41), "assignment_id": uid(4),
        "next_hop": {"kind": "ip", "address": "192.168.10.2"},
    })
    raw["static_routes"].append({
        "id": uid(42), "assignment_id": uid(5), "destination": "192.168.10.0/25",
        "next_hop": {"kind": "discard"},
    })
    issues = validate_plan(EventPlan.model_validate(raw))
    assert {(issue.path, issue.code) for issue in issues} >= {
        ("transit", "core_default"), ("static_routes.3", "return_route"),
    }


def test_nested_subnets_and_duplicate_gateway_are_rejected() -> None:
    raw = plan_model().model_dump(mode="json")
    raw["subnets"].append({"id": uid(40), "vlan": 20, "network": "192.168.10.0/25"})
    raw["gateways"].append({
        "subnet_id": uid(40), "address": "192.168.10.1", "svi_id": uid(13),
    })
    issues = validate_plan(EventPlan.model_validate(raw))
    assert {issue.code for issue in issues} >= {"subnet_overlap", "duplicate", "gateway_svi"}


def test_import_export_is_atomic_immutable_and_event_scoped(tmp_path: Path) -> None:
    database = tmp_path / "revision.sqlite3"
    settings = Settings(database_path=database)
    with TestClient(create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        first = client.post(f"{API}/events", json={"name": "Lab one"}).json()["id"]
        second = client.post(f"{API}/events", json={"name": "Lab two"}).json()["id"]
        first_url = f"{API}/events/{first}"
        second_url = f"{API}/events/{second}"
        revs = first_url + "/plan-revisions"
        plan = synthetic_plan(first)
        assert client.post(first_url + "/plan/validate", json=plan).json() == []
        assert client.post(revs, json={**plan, "schema_version": 2}).status_code == 422
        assert client.post(revs, json={**plan, "event_id": second}).status_code == 422
        assert client.post(revs, json={**plan, "management_vlan": 4095}).status_code == 422
        assert client.post(revs, json={**plan, "vlans": []}).status_code == 422
        assert client.get(revs).json() == []
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: client.post(revs, json=plan), range(2)))
        assert [response.status_code for response in responses] == [200, 200]
        revision = responses[0].json()
        assert responses[1].json()["id"] == revision["id"]
        rev_url = f"{revs}/{revision['id']}"
        exported = client.get(rev_url + "/export")
        assert exported.headers["etag"] == f'"{revision["content_hash"]}"'
        assert plan_hash(exported.text) == revision["content_hash"]
        assert client.post(revs, json=exported.json()).json() == revision
        foreign = client.post(revs, json=plan, headers={"Origin": "https://example.com"})
        assert foreign.status_code == 403
        assert client.get(second_url + f"/plan-revisions/{revision['id']}").status_code == 404
        reused: Any = {"schema_version": 1, "event_id": second,
                  "physical_devices": plan["physical_devices"],
                  "assignments": [{"id": uid(4), "hostname": "Lab-Access",
                                   "physical_device_id": uid(1), "role": "access"}]}
        rejected = client.post(second_url + "/plan-revisions", json=reused)
        assert rejected.status_code == 422
        assert rejected.json()["detail"][0]["code"] == "assignment_event"
        reused["assignments"][0]["id"] = uid(41)
        assert client.post(second_url + "/plan-revisions", json=reused).status_code == 200
        assert client.get(f"{API}/health").json()["device_writes_enabled"] is False
    with TestClient(create_app(settings), base_url=ORIGIN) as client:
        assert client.get(rev_url).json() == revision
    engine = create_database_engine(database)
    try:
        with engine.begin() as connection, pytest.raises(IntegrityError, match="immutable"):
            connection.execute(text("UPDATE event_plan_revisions SET number = 99"))
    finally:
        engine.dispose()


def test_upgrade_preserves_foundation_events_and_assignment_uuid(tmp_path: Path) -> None:
    database = tmp_path / "foundation.sqlite3"
    event, device = uuid4(), uuid4()
    engine = create_database_engine(database)
    try:
        with engine.begin() as connection:
            config = Config()
            config.set_main_option("script_location", "event_switch_manager:migrations")
            config.attributes["connection"] = connection
            command.upgrade(config, "0001_event_inventory")
            connection.execute(text(
                "INSERT INTO events (id, name, management_vlan) VALUES (:id, 'Legacy', 120)"
            ), {"id": event.hex})
            connection.execute(text(
                "INSERT INTO devices (id, event_id, hostname, family, role, serial_number) "
                "VALUES (:id, :event, 'Old-Core', 'catalyst-9300', 'core', 'SYN-LEGACY')"
            ), {"id": device.hex, "event": event.hex})
        with TestClient(create_app(Settings(database_path=database)), base_url=ORIGIN) as client:
            event_url = f"{API}/events/{event}"
            assert client.get(event_url).json()["management_vlan"] == 120
            inventory = client.get(event_url + "/devices").json()
            assert inventory[0]["id"] == str(device)
            assert inventory[0]["serial_number"] == "SYN-LEGACY"
            seed = client.get(event_url + "/plan/seed").json()
            assert seed["assignments"][0]["id"] == str(device)
            assert seed["assignments"][0]["physical_device_id"] is None
            assert seed["physical_devices"] == []
        with engine.connect() as connection:
            assert connection.execute(
                text("SELECT event_id FROM assignment_identities WHERE id = :id"),
                {"id": device.hex},
            ).scalar_one() == event.hex
    finally:
        engine.dispose()
