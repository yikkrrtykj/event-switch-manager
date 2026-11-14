from ipaddress import IPv4Address, IPv4Network
from typing import Literal
from uuid import UUID

from pydantic import field_validator

from .types import Name, PositiveInt, Record, VlanId


class Vlan(Record):
    id: VlanId
    name: Name
    purpose: Literal["ordinary", "management", "guest", "sensitive", "transit"] = "ordinary"


class Subnet(Record):
    id: UUID
    vlan: VlanId
    network: IPv4Network


class Gateway(Record):
    subnet_id: UUID
    address: IPv4Address
    svi_id: UUID


class DhcpPool(Record):
    id: UUID
    subnet_id: UUID
    start: IPv4Address
    end: IPv4Address
    lease_seconds: PositiveInt = 43200


class DhcpReservation(Record):
    id: UUID
    subnet_id: UUID
    address: IPv4Address
    client_mac: Name

    @field_validator("client_mac")
    @classmethod
    def normalize_mac(cls, value: str) -> str:
        return value.lower()


class DhcpRelay(Record):
    subnet_id: UUID
    svi_id: UUID
    servers: tuple[IPv4Address, ...]


class VlanAccessPolicy(Record):
    id: UUID
    priority: PositiveInt
    source_vlan: VlanId
    destination_vlan: VlanId
    action: Literal["allow", "deny"]
