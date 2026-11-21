"""Shared builders for CIS-03-02A L3 intent tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from event_switch_manager.planning.layer3_command_evidence import (
    ROWS,
    CommandEvidenceRegistry,
    EvidenceReview,
    EvidenceReviewState,
)
from event_switch_manager.planning.plan import (
    EventPlan,
    PlanRevision,
    canonical_plan,
    plan_hash,
)

TEST_REVIEWER = "TEST-ONLY-NOT-A-PRODUCTION-EVIDENCE-REVIEW"
TEST_REGISTRY_ID = "cis-03-test-only-command-evidence-v1"


def test_only_evidence_registry() -> CommandEvidenceRegistry:
    """Explicitly test-only reviewed rows; never used by production code."""
    rows = tuple(
        replace(row, review=EvidenceReview(
            state=EvidenceReviewState.REVIEWED,
            reviewer=TEST_REVIEWER,
            reviewed_at="2026-11-21",
            findings=("test-only fixture; not a production evidence review",),
            content_digest=row.content_digest(),
        ))
        for row in ROWS
    )
    return CommandEvidenceRegistry(
        rows, registry_id=TEST_REGISTRY_ID, production=False,
    )


def make_l3_plan(
    event_id: str,
    *,
    core_pid: str = "C9300L-24P-4X",
    core_family: str = "catalyst-9300",
    core_image: str = "17.12.4",
    core_license: str | None = "Network Advantage",
    core_vendor: str = "cisco",
    core_role: str = "core",
    routing_enabled: bool | None = None,
    deny_policy: bool = False,
    with_transit: bool = True,
    with_default: bool = True,
    with_relay: bool = True,
    with_pool: bool = True,
    second_subnet: bool = False,
    duplicate_svi: bool = False,
    no_carrier: bool = False,
    default_distance: int = 1,
    access_management_ip: bool = True,
    static_route_count: int = 0,
    static_route_distance: int = 1,
) -> dict[str, Any]:
    core_assignment = str(uuid4())
    access_assignment = str(uuid4())
    firewall_assignment = str(uuid4())
    core_device = str(uuid4())
    access_device = str(uuid4())
    firewall_device = str(uuid4())
    core_transit_port = str(uuid4())
    core_trunk_port = str(uuid4())
    access_port = str(uuid4())
    firewall_transit_port = str(uuid4())
    firewall_routed_port = str(uuid4())
    vlan9_svi = str(uuid4())
    vlan10_svi = str(uuid4())
    vlan20_svi = str(uuid4())
    subnet10 = str(uuid4())
    subnet20 = str(uuid4())
    pool20 = str(uuid4())
    default_route = str(uuid4())
    return_gateway = str(uuid4())
    return_players = str(uuid4())
    link = str(uuid4())
    core_settings = {"mode": "access", "access_vlan": 9, "admin_state": "up"}
    core_trunk = (
        {"mode": "trunk", "allowed_vlans": [9, 10, 20], "admin_state": "down"}
        if no_carrier
        else {"mode": "trunk", "allowed_vlans": [9, 10, 20], "admin_state": "up"}
    )
    logical: list[dict[str, Any]] = [
        {"id": vlan9_svi, "assignment_id": core_assignment, "name": "Vlan9",
         "kind": "svi", "vlan": 9, "address": "10.0.0.1/30"},
        {"id": vlan10_svi, "assignment_id": core_assignment, "name": "Vlan10",
         "kind": "svi", "vlan": 10, "address": "192.168.10.1/24"},
        {"id": vlan20_svi, "assignment_id": core_assignment, "name": "Vlan20",
         "kind": "svi", "vlan": 20, "address": "192.168.20.1/24"},
    ]
    subnets: list[dict[str, Any]] = [
        {"id": subnet10, "vlan": 10, "network": "192.168.10.0/24"},
        {"id": subnet20, "vlan": 20, "network": "192.168.20.0/24"},
    ]
    gateways: list[dict[str, Any]] = [
        {"subnet_id": subnet10, "address": "192.168.10.1", "svi_id": vlan10_svi},
        {"subnet_id": subnet20, "address": "192.168.20.1", "svi_id": vlan20_svi},
    ]
    if second_subnet:
        second_id = str(uuid4())
        second_svi = str(uuid4())
        subnets.append({"id": second_id, "vlan": 20, "network": "192.168.21.0/24"})
        logical.append({
            "id": second_svi, "assignment_id": core_assignment, "name": "Vlan20b",
            "kind": "svi", "vlan": 20, "address": "192.168.21.1/24",
        })
        gateways.append({
            "subnet_id": second_id, "address": "192.168.21.1", "svi_id": second_svi,
        })
    if duplicate_svi:
        duplicate_id = str(uuid4())
        logical.append({
            "id": duplicate_id, "assignment_id": core_assignment,
            "name": "Vlan20-dup", "kind": "svi", "vlan": 20,
            "address": "192.168.22.1/24",
        })
    pools: list[dict[str, Any]] = []
    if with_pool:
        pools.append({
            "id": pool20, "subnet_id": subnet20,
            "start": "192.168.20.100", "end": "192.168.20.150",
        })
    relays: list[dict[str, Any]] = []
    if with_relay:
        relays.append({
            "subnet_id": subnet20, "svi_id": vlan20_svi,
            "servers": ["192.168.10.5"],
        })
    policies: list[dict[str, Any]] = []
    if deny_policy:
        policies.append({
            "id": str(uuid4()), "priority": 10, "source_vlan": 20,
            "destination_vlan": 10, "action": "deny",
        })
    plan: dict[str, Any] = {
        "schema_version": 1,
        "event_id": event_id,
        "management_vlan": 10,
        "physical_devices": [
            {"id": core_device, "vendor": core_vendor, "model": core_pid,
             "verified_serial": "SYN-CORE-001"},
            {"id": access_device, "vendor": "cisco", "model": "C9300L-24T-4G",
             "verified_serial": "SYN-ACCESS-001"},
            {"id": firewall_device, "vendor": "hillstone", "model": "SG6000",
             "verified_serial": "SYN-FW-001"},
        ],
        "assignments": [
            {
                "id": core_assignment, "hostname": "L3-Core", "role": core_role,
                "family": core_family, "physical_device_id": core_device,
                "software": (
                    None if core_image is None else {
                        "image": core_image, "license": core_license,
                    }
                ),
                "routing_enabled": routing_enabled,
            },
            {
                "id": access_assignment, "hostname": "L3-Access", "role": "access",
                "family": "catalyst-9300", "physical_device_id": access_device,
                "software": {"image": "17.12.4", "license": "Network Advantage"},
                "management_ip": "192.168.10.2" if access_management_ip else None,
            },
            {
                "id": firewall_assignment, "hostname": "L3-FW",
                "role": "external-distribution",
                "physical_device_id": firewall_device,
            },
        ],
        "physical_interfaces": [
            {
                "id": core_transit_port, "assignment_id": core_assignment,
                "physical_device_id": core_device, "name": "Gi1/0/1",
                "settings": core_settings,
            },
            {
                "id": core_trunk_port, "assignment_id": core_assignment,
                "physical_device_id": core_device, "name": "Gi1/0/2",
                "settings": core_trunk,
            },
            {
                "id": access_port, "assignment_id": access_assignment,
                "physical_device_id": access_device, "name": "Gi1/0/1",
                "settings": {"mode": "access", "access_vlan": 20, "admin_state": "up"},
            },
            {
                "id": firewall_transit_port, "assignment_id": firewall_assignment,
                "physical_device_id": firewall_device, "name": "ethernet0/0",
                "settings": {"mode": "access", "access_vlan": 9, "admin_state": "up"},
            },
            {
                "id": firewall_routed_port, "assignment_id": firewall_assignment,
                "physical_device_id": firewall_device, "name": "ethernet0/1",
                "settings": {"mode": "routed", "address": "198.51.100.2/30"},
            },
        ],
        "logical_interfaces": logical,
        "vlans": [
            {"id": 9, "name": "Transit", "purpose": "transit"},
            {"id": 10, "name": "Management", "purpose": "management"},
            {"id": 20, "name": "Players"},
        ],
        "subnets": subnets,
        "gateways": gateways,
        "dhcp_pools": pools,
        "dhcp_relays": relays,
        "vlan_access_policies": policies,
        "links": [{"id": link, "endpoints": [core_transit_port, firewall_transit_port]}],
        "static_routes": [
            {
                "id": return_gateway, "assignment_id": firewall_assignment,
                "destination": "192.168.10.0/24",
                "next_hop": {"kind": "ip", "address": "10.0.0.1"},
            },
            {
                "id": return_players, "assignment_id": firewall_assignment,
                "destination": "192.168.20.0/24",
                "next_hop": {"kind": "ip", "address": "10.0.0.1"},
            },
        ],
        "default_routes": [],
    }
    if with_transit:
        plan["transit"] = {
            "core_assignment_id": core_assignment,
            "hillstone_assignment_id": firewall_assignment,
            "core_port_id": core_transit_port,
            "hillstone_port_id": firewall_transit_port,
            "core_svi_id": vlan9_svi,
            "vlan": 9,
            "network": "10.0.0.0/30",
            "core_ip": "10.0.0.1",
            "hillstone_ip": "10.0.0.2",
        }
        if with_default:
            plan["default_routes"] = [{
                "id": default_route, "assignment_id": core_assignment,
                "next_hop": {"kind": "ip", "address": "10.0.0.2"},
                "preference": default_distance,
            }]
    for index in range(static_route_count):
        plan["static_routes"].append({
            "id": str(uuid4()),
            "assignment_id": core_assignment,
            "destination": f"10.200.{index}.0/24",
            "next_hop": {"kind": "ip", "address": "10.0.0.2"},
            "preference": static_route_distance,
        })
    return plan


def make_stack_plan(
    event_id: str,
    *,
    second_pid: str | None = "C9300L-24P-4X",
    second_serial: str | None = "SYN-CORE-002",
    second_state: str = "ready",
    include_second_device: bool = True,
    reference_missing_device: bool = False,
    assignment_outside_stack: bool = False,
) -> dict[str, Any]:
    payload = make_l3_plan(event_id)
    core_assignment = next(
        item for item in payload["assignments"] if item["hostname"] == "L3-Core"
    )
    core_device = core_assignment["physical_device_id"]
    second_device = str(uuid4())
    member_device = (
        str(uuid4()) if reference_missing_device else second_device
    )
    if include_second_device:
        payload["physical_devices"].append({
            "id": second_device,
            "vendor": "cisco",
            "model": second_pid,
            "verified_serial": second_serial,
        })
    if assignment_outside_stack:
        outside = str(uuid4())
        payload["physical_devices"].append({
            "id": outside,
            "vendor": "cisco",
            "model": "C9300L-24P-4X",
            "verified_serial": "SYN-OUTSIDE-001",
        })
        core_assignment["physical_device_id"] = outside
    payload["stacks"] = [{
        "assignment_id": core_assignment["id"],
        "members": [
            {"number": 1, "physical_device_id": core_device, "state": "ready"},
            {"number": 2, "physical_device_id": member_device, "state": second_state},
        ],
    }]
    for port in payload["physical_interfaces"]:
        if port["assignment_id"] == core_assignment["id"]:
            port["stack_member"] = 1
    return payload


def plan_model(payload: dict[str, Any]) -> EventPlan:
    return EventPlan.model_validate(payload)


def revision_for(
    payload: dict[str, Any],
    *,
    number: int = 1,
    revision_id: UUID | None = None,
) -> PlanRevision:
    plan = plan_model(payload)
    content = canonical_plan(plan)
    return PlanRevision(
        id=revision_id or uuid4(),
        number=number,
        created_at=datetime.now(UTC),
        content_hash=plan_hash(content),
        schema_version=plan.schema_version,
        plan=plan,
        warnings=(),
        validation_errors=(),
        validation_status="VALID",
    )


def assignment_id(payload: dict[str, Any], hostname: str) -> str:
    return str(next(
        item["id"] for item in payload["assignments"]
        if item["hostname"] == hostname
    ))
