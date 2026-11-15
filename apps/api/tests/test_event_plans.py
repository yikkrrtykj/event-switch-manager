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


def synthetic_plan(event_id: str) -> dict[str, Any]:
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
                   {"id": uid(22), "target": "10.0.1.2", "tunnel_id": uid(25)}],
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
             "next_hop": {"kind": "tunnel", "tunnel_id": uid(25)},
             "activation": {"kind": "track", "track_id": uid(22), "state": "up"}},
            {"id": uid(28), "assignment_id": uid(5), "destination": "172.16.20.0/24",
             "next_hop": {"kind": "discard"}, "preference": 200,
             "activation": {"kind": "always"}},
        ],
        "default_routes": [{"id": uid(29), "assignment_id": uid(4),
                            "next_hop": {"kind": "ip", "address": "10.0.0.2"}}],
        "source_routes": [{"id": uid(30), "assignment_id": uid(5), "source_vlan": 20,
                           "isp_priority": [uid(23), uid(24)]}],
        "policy_routes": [{"id": uid(31), "assignment_id": uid(5), "priority": 10,
                           "source_vlan": 20, "destination": "172.16.20.0/24",
                           "tunnel_id": uid(25)}],
        "snat": [
            {"id": uid(32), "assignment_id": uid(5), "source_vlan": 20,
             "isp_id": uid(23), "translated_ip": "192.0.2.2"},
            {"id": uid(34), "assignment_id": uid(5), "source_vlan": 20,
             "isp_id": uid(24), "translated_ip": "198.51.100.2"},
        ],
        "nat_exemptions": [{"id": uid(33), "assignment_id": uid(5), "source_vlan": 20,
                            "destination": "172.16.20.0/24", "tunnel_id": uid(25)}],
    }


def plan_model() -> EventPlan:
    return EventPlan.model_validate(synthetic_plan(uid(99)))


def test_canonical_hash_keeps_isp_priority_and_normalizes_sets() -> None:
    plan = plan_model()
    assert {issue.severity for issue in validate_plan(plan)} == {"WARNING"}
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
    ("vpn_remote_prefixes", 0, "network", "192.168.140.0/24", "vpn_return_overlap_risk"),
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
        issues = client.post(first_url + "/plan/validate", json=plan).json()
        assert {issue["severity"] for issue in issues} == {"WARNING"}
        assert client.post(revs, json={**plan, "schema_version": 2}).status_code == 422
        assert client.post(revs, json={**plan, "event_id": second}).status_code == 422
        assert client.post(revs, json={**plan, "management_vlan": 4095}).status_code == 422
        assert client.post(revs, json={**plan, "vlans": []}).status_code == 422
        assert client.get(revs).json() == []
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: client.post(revs, json=plan), range(2)))
        assert [response.status_code for response in responses] == [200, 200]
        revision = responses[0].json()
        assert {
            (issue["code"], issue["severity"]) for issue in revision["warnings"]
        } == {(issue["code"], issue["severity"]) for issue in issues}
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


def overlap_plan(event_id: str = uid(99)) -> dict[str, Any]:
    raw = synthetic_plan(event_id)
    remote = "192.168.141.0/24"
    raw["vpn_remote_prefixes"][0]["network"] = remote
    for route in raw["static_routes"][1:]:
        route["destination"] = remote
    for group in ("policy_routes", "nat_exemptions"):
        raw[group][0]["destination"] = remote
    return raw


def problem_codes(raw: dict[str, Any], severity: str = "ERROR") -> set[str]:
    return {
        issue.code for issue in validate_plan(EventPlan.model_validate(raw))
        if issue.severity == severity
    }


@pytest.mark.parametrize("pbr_action", ["discard", "route-table"])
@pytest.mark.parametrize("fallback", ["always", "track-down"])
def test_planned_overlap_prefers_vpn_when_up_and_discards_when_down(
    pbr_action: str, fallback: str
) -> None:
    raw = overlap_plan()
    raw["policy_routes"][0]["on_tunnel_down"] = pbr_action
    # A current tunnel state never skips the other scenario.
    raw["ipsec_tunnels"][0]["state"] = "down"
    if fallback == "track-down":
        raw["static_routes"][2]["activation"] = {
            "kind": "track", "track_id": uid(22), "state": "down",
        }
    assert not problem_codes(raw)
    assert problem_codes(raw, "WARNING") >= {"vpn_return_overlap", "vpn_failover_not_verified"}


@pytest.mark.parametrize("missing", ["route-activation", "track-binding", "pbr"])
def test_overlap_with_incomplete_failover_intent_remains_unverified(missing: str) -> None:
    raw = overlap_plan()
    if missing == "route-activation":
        for route in raw["static_routes"][1:]:
            route.pop("activation")
    elif missing == "track-binding":
        raw["tracks"][2].pop("tunnel_id")
    else:
        raw["policy_routes"][0]["on_tunnel_down"] = "unknown"
    assert not problem_codes(raw)
    warnings = problem_codes(raw, "WARNING")
    assert "vpn_return_overlap_unverified" in warnings
    assert "vpn_return_overlap" not in warnings


@pytest.mark.parametrize(("hazard", "expected"), [
    ("no-discard", "vpn_down_route"),
    ("retained-tunnel", "vpn_down_route"),
    ("discard-only-up", "vpn_down_route"),
    ("discard-loses-to-core", "vpn_down_route"),
    ("foreign-track", "tunnel_route_track"),
    ("pbr-falls-through-to-sbr", "vpn_pbr_down_unsafe"),
])
def test_unsafe_overlap_is_an_error(hazard: str, expected: str) -> None:
    raw = overlap_plan()
    if hazard == "no-discard":
        raw["static_routes"].pop()
    elif hazard == "retained-tunnel":
        raw["static_routes"][1]["activation"] = {"kind": "always"}
    elif hazard == "discard-only-up":
        raw["static_routes"][2]["activation"] = {
            "kind": "track", "track_id": uid(22), "state": "up",
        }
    elif hazard == "discard-loses-to-core":
        raw["static_routes"].append({
            "id": uid(40), "assignment_id": uid(5), "preference": 100,
            "destination": "192.168.141.128/25",
            "next_hop": {"kind": "ip", "address": "10.0.0.1"},
            "activation": {"kind": "track", "track_id": uid(22), "state": "down"},
        })
    elif hazard == "foreign-track":
        raw["static_routes"][1]["activation"]["track_id"] = uid(20)
    else:
        raw["policy_routes"][0]["on_tunnel_down"] = "use-sbr"
    errors = problem_codes(raw)
    assert expected in errors
    if hazard != "foreign-track":
        assert "vpn_return_overlap_risk" in errors


def test_more_specific_discard_only_when_down_can_protect_part_of_remote_prefix() -> None:
    raw = overlap_plan()
    raw["static_routes"].append({
        "id": uid(40), "assignment_id": uid(5), "destination": "192.168.141.128/25",
        "next_hop": {"kind": "discard"},
        "activation": {"kind": "track", "track_id": uid(22), "state": "down"},
    })
    assert not problem_codes(raw)
    assert "vpn_return_overlap" in problem_codes(raw, "WARNING")


def test_complementary_wrong_routes_leave_no_discard_path() -> None:
    raw = overlap_plan()
    for state, preference in (("up", 100), ("down", 101)):
        raw["static_routes"].append({
            "id": uid(40 + preference), "assignment_id": uid(5),
            "destination": "192.168.141.0/24", "preference": preference,
            "next_hop": {"kind": "ip", "address": "10.0.0.1"},
            "activation": {"kind": "track", "track_id": uid(20), "state": state},
        })
    assert problem_codes(raw) >= {"vpn_down_route", "vpn_return_overlap_risk"}


def test_real_local_subnet_overlap_remains_an_error() -> None:
    raw = overlap_plan()
    raw["subnets"].append({"id": uid(40), "vlan": 20, "network": "192.168.141.128/25"})
    assert "vpn_local_overlap" in problem_codes(raw)


def add_third_isp(raw: dict[str, Any]) -> None:
    raw["tracks"].append({"id": uid(40), "target": "203.0.113.5"})
    raw["physical_interfaces"].append({
        "id": uid(41), "assignment_id": uid(5), "physical_device_id": uid(3),
        "name": "ethernet0/3", "settings": {"mode": "routed", "address": "203.0.113.6/30"},
    })
    raw["isps"].append({
        "id": uid(42), "name": "Tertiary", "assignment_id": uid(5), "interface_id": uid(41),
        "address": "203.0.113.6/30", "gateway": "203.0.113.5", "track_id": uid(40),
    })
    raw["source_routes"][0]["isp_priority"].append(uid(42))
    raw["snat"].append({
        "id": uid(43), "assignment_id": uid(5), "source_vlan": 20,
        "isp_id": uid(42), "translated_ip": "203.0.113.6",
    })


@pytest.mark.parametrize(("isp_count", "missing_position"), [(2, 1), (3, 1), (3, 2)])
def test_sbr_has_snat_on_each_reachable_failover_egress(
    isp_count: int, missing_position: int
) -> None:
    raw = overlap_plan()
    if isp_count == 3:
        add_third_isp(raw)
    assert not problem_codes(raw)
    raw["snat"].pop(missing_position)
    issues = validate_plan(EventPlan.model_validate(raw))
    missing = [issue for issue in issues if issue.code == "missing_sbr_snat"]
    assert len(missing) == 1
    assert missing[0].path == f"source_routes.0.isp_priority.{missing_position}"
    assert f"Backup #{missing_position} ISP {raw['isps'][missing_position]['name']}" in (
        missing[0].message
    )
    assert missing[0].severity == "ERROR"


@pytest.mark.parametrize(("fault", "expected"), [
    ("unknown-reference", "sbr_isp_reference"),
    ("foreign-owner", "sbr_isp_reference"),
    ("shared-track", "isp_track"),
    ("wrong-translation", "snat_egress_address"),
    ("wrong-binding", "missing_sbr_snat"),
    ("unlisted-exception", "sbr_no_nat_reference"),
    ("conflicting-exception", "sbr_nat_conflict"),
])
def test_sbr_rejects_bad_egress_references_and_snat(
    fault: str, expected: str
) -> None:
    raw = overlap_plan()
    if fault == "unknown-reference":
        raw["source_routes"][0]["isp_priority"][1] = uid(90)
    elif fault == "foreign-owner":
        raw["isps"][1]["assignment_id"] = uid(4)
    elif fault == "shared-track":
        raw["isps"][1]["track_id"] = uid(20)
    elif fault == "wrong-translation":
        raw["snat"][1]["translated_ip"] = "192.0.2.2"
    elif fault == "wrong-binding":
        raw["snat"][1]["isp_id"] = uid(23)
    else:
        raw["source_routes"][0]["no_nat"] = [{
            "isp_id": uid(90) if fault == "unlisted-exception" else uid(24),
            "reason": "The upstream routes the source subnet",
        }]
    assert expected in problem_codes(raw)


def test_sbr_accepts_an_isp_routed_snat_block_and_documented_no_nat() -> None:
    raw = overlap_plan()
    add_third_isp(raw)
    raw["snat"][1]["translated_ip"] = "203.0.113.18"
    raw["isps"][1]["routed_public_blocks"] = [{
        "network": "203.0.113.16/29", "reason": "Secondary routes this block to the WAN address",
    }]
    raw["snat"].pop(2)
    raw["source_routes"][0]["no_nat"] = [{
        "isp_id": uid(42), "reason": "Private circuit has a return route for VLAN 20",
    }]
    assert not problem_codes(raw)
    raw["isps"][2]["routed_public_blocks"] = raw["isps"][1].pop("routed_public_blocks")
    assert "snat_egress_address" in problem_codes(raw)


def test_plan_import_without_hardware_and_enrichment_preserve_uuids(tmp_path: Path) -> None:
    database = tmp_path / "planned-hardware.sqlite3"
    settings = Settings(database_path=database)
    with TestClient(create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        event_id = client.post(f"{API}/events", json={"name": "Before delivery"}).json()["id"]
        url = f"{API}/events/{event_id}/plan-revisions"
        raw = overlap_plan(event_id)
        serials = [asset.pop("verified_serial") for asset in raw["physical_devices"]]
        for asset, model in zip(
            raw["physical_devices"], ("Catalyst 9300", "Catalyst 9300", "SG6000-A3800"),
            strict=True,
        ):
            asset["model"] = model
        raw["assignments"][0].pop("physical_device_id")
        raw["physical_interfaces"][0]["capability_status"] = "unverified"

        imported = client.post(url, json=raw)
        assert imported.status_code == 200, imported.text
        revision = imported.json()
        assert {warning["code"] for warning in revision["warnings"]} >= {
            "hardware_identity_unknown", "port_capability_unverified", "vpn_return_overlap",
            "vpn_failover_not_verified",
        }
        old_rev_url = f"{url}/{revision['id']}"
        exported = client.get(old_rev_url + "/export")
        assert plan_hash(exported.text) == revision["content_hash"]
        assert client.post(url, json=exported.json()).json() == revision
        engine = create_database_engine(database)
        try:
            with engine.connect() as connection:
                assert connection.execute(
                    text("SELECT count(*) FROM physical_assets")
                ).scalar() == 0
                assert connection.execute(
                    text("SELECT count(*) FROM assignment_identities")
                ).scalar() == 2

            for asset, serial in zip(raw["physical_devices"], serials, strict=True):
                asset["verified_serial"] = serial.lower()
            updated = client.post(url, json=raw)
            assert updated.status_code == 200, updated.text
            assert updated.json()["number"] == 2
            with engine.connect() as connection:
                assert set(connection.execute(
                    text("SELECT id, verified_serial FROM physical_assets")
                )) == {
                    (UUID(asset["id"]).hex, serial)
                    for asset, serial in zip(raw["physical_devices"], serials, strict=True)
                }
            raw["physical_devices"][0]["verified_serial"] = "DIFFERENT-CHASSIS"
            conflict = client.post(url, json=raw)
            assert conflict.status_code == 422
            assert "physical_identity" in {issue["code"] for issue in conflict.json()["detail"]}
        finally:
            engine.dispose()
        assert client.get(old_rev_url + "/export").text == exported.text
        assert client.get(f"{API}/health").json()["device_writes_enabled"] is False


def test_unverified_overlap_can_append_with_warnings(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "unverified.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        event_id = client.post(f"{API}/events", json={"name": "Unverified plan"}).json()["id"]
        url = f"{API}/events/{event_id}/plan-revisions"
        raw = overlap_plan(event_id)
        raw["static_routes"][1].pop("activation")
        imported = client.post(url, json=raw)
        assert imported.status_code == 200, imported.text
        assert {warning["code"] for warning in imported.json()["warnings"]} >= {
            "vpn_return_overlap_unverified", "vpn_failover_not_verified",
        }


def test_unsafe_vpn_import_cannot_append_a_revision(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "rejected.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        event_id = client.post(f"{API}/events", json={"name": "Unsafe plan"}).json()["id"]
        url = f"{API}/events/{event_id}/plan-revisions"
        raw = overlap_plan(event_id)
        raw["static_routes"].pop()
        rejected = client.post(url, json=raw)
        assert rejected.status_code == 422
        assert any(issue["code"] == "vpn_return_overlap_risk" and issue["severity"] == "ERROR"
                   for issue in rejected.json()["detail"])
        assert client.get(url).json() == []


def test_legacy_revision_hash_and_reimport_are_stable_under_stricter_checks(tmp_path: Path) -> None:
    raw = synthetic_plan(uid(99))
    raw["snat"].pop()
    raw["tracks"][2].pop("tunnel_id")
    for route in raw["static_routes"][1:]:
        route.pop("activation")
    old_content = canonical_plan(EventPlan.model_validate(raw))
    old_hash = "082de4acef4442528cdecd079df58c0de74c63986b7abdd8f78001a6a51cd285"
    assert plan_hash(old_content) == old_hash
    settings = Settings(database_path=tmp_path / "legacy-plan.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        engine = create_database_engine(settings.database_path)
        try:
            with engine.begin() as connection:
                connection.execute(text(
                    "INSERT INTO events (id, name, management_vlan) VALUES (:id, 'Legacy', 10)"
                ), {"id": UUID(uid(99)).hex})
                connection.execute(text(
                    "INSERT INTO event_plan_revisions "
                    "(id, event_id, number, schema_version, created_at, content_hash, "
                    "canonical_json) "
                    "VALUES (:id, :event, 1, 1, '2026-11-14 00:00:00', :hash, :content)"
                ), {"id": UUID(uid(98)).hex, "event": UUID(uid(99)).hex,
                    "hash": old_hash, "content": old_content})
        finally:
            engine.dispose()
        url = f"{API}/events/{uid(99)}/plan-revisions"
        exported = client.get(f"{url}/{uid(98)}/export")
        assert exported.text == old_content
        assert exported.headers["etag"] == f'"{old_hash}"'
        same = client.post(url, json=exported.json())
        assert same.status_code == 200
        assert same.json()["id"] == uid(98)
        raw["vlans"][2]["name"] = "Updated Players"
        assert client.post(url, json=raw).status_code == 422
        assert len(client.get(url).json()) == 1
