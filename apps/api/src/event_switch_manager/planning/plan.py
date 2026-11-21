import hashlib
import json
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from .addressing import (
    DhcpPool,
    DhcpRelay,
    DhcpReservation,
    Gateway,
    Subnet,
    Vlan,
    VlanAccessPolicy,
)
from .inventory import (
    EventDeviceAssignment,
    LogicalInterface,
    PhysicalDevice,
    PhysicalInterface,
    PortChannel,
    StackSnapshot,
    TopologyLink,
)
from .routing import (
    CiscoHillstoneTransit,
    DefaultRoute,
    IpsecTunnel,
    Isp,
    NatExemption,
    PolicyBasedRoute,
    SourceBasedRoute,
    SourceNat,
    StaticRoute,
    Track,
    VpnRemotePrefix,
)
from .types import PositiveInt, Record, VlanId
from .validation import PlanIssue


class EventPlan(Record):
    schema_version: Literal[1]
    event_id: UUID
    management_vlan: VlanId = 10
    physical_devices: tuple[PhysicalDevice, ...] = ()
    assignments: tuple[EventDeviceAssignment, ...] = ()
    stacks: tuple[StackSnapshot, ...] = ()
    physical_interfaces: tuple[PhysicalInterface, ...] = ()
    logical_interfaces: tuple[LogicalInterface, ...] = ()
    port_channels: tuple[PortChannel, ...] = ()
    links: tuple[TopologyLink, ...] = ()
    vlans: tuple[Vlan, ...] = ()
    subnets: tuple[Subnet, ...] = ()
    gateways: tuple[Gateway, ...] = ()
    dhcp_pools: tuple[DhcpPool, ...] = ()
    dhcp_reservations: tuple[DhcpReservation, ...] = ()
    dhcp_relays: tuple[DhcpRelay, ...] = ()
    vlan_access_policies: tuple[VlanAccessPolicy, ...] = ()
    transit: CiscoHillstoneTransit | None = None
    tracks: tuple[Track, ...] = ()
    isps: tuple[Isp, ...] = ()
    ipsec_tunnels: tuple[IpsecTunnel, ...] = ()
    vpn_remote_prefixes: tuple[VpnRemotePrefix, ...] = ()
    static_routes: tuple[StaticRoute, ...] = ()
    default_routes: tuple[DefaultRoute, ...] = ()
    source_routes: tuple[SourceBasedRoute, ...] = ()
    policy_routes: tuple[PolicyBasedRoute, ...] = ()
    snat: tuple[SourceNat, ...] = ()
    nat_exemptions: tuple[NatExemption, ...] = ()


class PlanRevisionSummary(Record):
    id: UUID
    number: PositiveInt
    created_at: datetime
    content_hash: str
    schema_version: int


class PlanRevision(PlanRevisionSummary):
    plan: EventPlan
    warnings: tuple[PlanIssue, ...] = ()
    validation_errors: tuple[PlanIssue, ...]
    validation_status: Literal["VALID", "VALID_WITH_WARNINGS", "INVALID"]


def _json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _canonical(value: JsonValue, field: str = "") -> JsonValue:
    if isinstance(value, dict):
        return {key: _canonical(item, key) for key, item in value.items()}
    if isinstance(value, list):
        items = [_canonical(item) for item in value]
        # All other arrays represent sets. ISP order represents failover priority.
        return items if field == "isp_priority" else sorted(items, key=_json)
    return value


def canonical_plan(plan: EventPlan) -> str:
    document = plan.model_dump(mode="json")
    # Omit only newly added defaults, preserving hashes of existing v1 documents.
    for collection, field, default in (
        ("physical_interfaces", "capability_status", "unknown"),
        ("tracks", "tunnel_id", None),
        ("isps", "routed_public_blocks", []),
        ("ipsec_tunnels", "state", "unknown"),
        ("static_routes", "activation", None),
        ("source_routes", "no_nat", []),
    ):
        for record in document[collection]:
            if record[field] == default:
                del record[field]
    for collection in ("physical_interfaces", "port_channels"):
        for record in document[collection]:
            settings = record["settings"]
            for field in (
                "description", "admin_state", "speed", "duplex", "poe_mode", "portfast",
                "bpdu_guard",
            ):
                if settings[field] is None:
                    del settings[field]
    for record in document["assignments"]:
        if record["routing_enabled"] is None:
            del record["routing_enabled"]
    return _json(_canonical(document))


def plan_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
