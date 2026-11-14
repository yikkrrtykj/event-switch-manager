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
    return _json(_canonical(plan.model_dump(mode="json")))


def plan_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
