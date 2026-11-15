from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Literal
from uuid import UUID

from pydantic import Field

from .types import Name, PositiveInt, Record, VlanId


class CiscoHillstoneTransit(Record):
    core_assignment_id: UUID
    hillstone_assignment_id: UUID
    core_port_id: UUID
    hillstone_port_id: UUID
    core_svi_id: UUID
    vlan: VlanId = 9
    network: IPv4Network
    core_ip: IPv4Address
    hillstone_ip: IPv4Address


class Track(Record):
    id: UUID
    target: IPv4Address
    interval_seconds: PositiveInt = 5
    failure_threshold: PositiveInt = 3
    tunnel_id: UUID | None = None


class RoutedPublicBlock(Record):
    network: IPv4Network
    reason: Name


class Isp(Record):
    id: UUID
    name: Name
    assignment_id: UUID
    interface_id: UUID
    address: IPv4Interface
    gateway: IPv4Address
    track_id: UUID | None = None
    routed_public_blocks: tuple[RoutedPublicBlock, ...] = ()


class IpsecTunnel(Record):
    id: UUID
    name: Name
    assignment_id: UUID
    isp_id: UUID
    peer: IPv4Address
    inside: IPv4Interface
    remote_gateway: IPv4Address
    track_id: UUID
    state: Literal["unknown", "up", "down"] = "unknown"


class VpnRemotePrefix(Record):
    tunnel_id: UUID
    network: IPv4Network


class IpNextHop(Record):
    kind: Literal["ip"] = "ip"
    address: IPv4Address


class TunnelNextHop(Record):
    kind: Literal["tunnel"] = "tunnel"
    tunnel_id: UUID


class DropNextHop(Record):
    kind: Literal["discard"] = "discard"


class AlwaysActive(Record):
    kind: Literal["always"] = "always"


class TrackActive(Record):
    kind: Literal["track"] = "track"
    track_id: UUID
    state: Literal["up", "down"]


class StaticRoute(Record):
    id: UUID
    assignment_id: UUID
    destination: IPv4Network
    next_hop: IpNextHop | TunnelNextHop | DropNextHop = Field(discriminator="kind")
    preference: PositiveInt = 1
    activation: AlwaysActive | TrackActive | None = Field(default=None, discriminator="kind")


class DefaultRoute(Record):
    id: UUID
    assignment_id: UUID
    next_hop: IpNextHop
    preference: PositiveInt = 1


class NoNatEgress(Record):
    isp_id: UUID
    reason: Name


class SourceBasedRoute(Record):
    id: UUID
    assignment_id: UUID
    source_vlan: VlanId
    isp_priority: tuple[UUID, ...]
    no_nat: tuple[NoNatEgress, ...] = ()


class PolicyBasedRoute(Record):
    id: UUID
    assignment_id: UUID
    priority: PositiveInt
    source_vlan: VlanId
    destination: IPv4Network
    tunnel_id: UUID
    on_tunnel_down: Literal["discard", "route-table", "unknown", "use-sbr"] = "discard"


class SourceNat(Record):
    id: UUID
    assignment_id: UUID
    source_vlan: VlanId
    isp_id: UUID
    translated_ip: IPv4Address


class NatExemption(Record):
    id: UUID
    assignment_id: UUID
    source_vlan: VlanId
    destination: IPv4Network
    tunnel_id: UUID
