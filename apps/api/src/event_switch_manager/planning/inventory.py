from ipaddress import IPv4Address, IPv4Interface
from typing import Literal
from uuid import UUID

from pydantic import field_validator

from event_switch_manager.domain import DeviceFamily, DeviceRole
from event_switch_manager.integrations import Capability, Support
from event_switch_manager.schemas import Hostname, LocationText, SerialNumber

from .types import Name, PortName, PositiveInt, Record, VlanId


class PhysicalDevice(Record):
    id: UUID
    vendor: Literal["cisco", "hillstone", "other"]
    verified_serial: SerialNumber
    model: Name | None = None

    @field_validator("verified_serial")
    @classmethod
    def normalize_serial(cls, value: str) -> str:
        return value.upper()


class CapabilityObservation(Record):
    capability: Capability
    support: Support


class SoftwareProfile(Record):
    image: Name
    license: Name | None = None
    capabilities: tuple[CapabilityObservation, ...] = ()


class EventDeviceAssignment(Record):
    id: UUID
    hostname: Hostname
    role: DeviceRole
    family: DeviceFamily | None = None
    physical_device_id: UUID | None = None
    software: SoftwareProfile | None = None
    management_ip: IPv4Address | None = None
    location: LocationText | None = None


class StackMember(Record):
    number: PositiveInt
    physical_device_id: UUID
    state: Literal["ready", "missing", "unknown"] = "unknown"


class StackSnapshot(Record):
    assignment_id: UUID
    members: tuple[StackMember, ...]


class PortSettings(Record):
    mode: Literal["access", "trunk", "routed"]
    access_vlan: VlanId | None = None
    native_vlan: VlanId | None = None
    allowed_vlans: tuple[VlanId, ...] = ()
    address: IPv4Interface | None = None


class PhysicalInterface(Record):
    id: UUID
    assignment_id: UUID
    physical_device_id: UUID
    name: PortName
    stack_member: PositiveInt | None = None
    settings: PortSettings


class LogicalInterface(Record):
    id: UUID
    assignment_id: UUID
    name: PortName
    kind: Literal["svi", "port-channel", "loopback"]
    vlan: VlanId | None = None
    address: IPv4Interface | None = None


class PortChannel(Record):
    interface_id: UUID
    number: PositiveInt
    member_ids: tuple[UUID, ...]
    settings: PortSettings
    lacp: Literal["active", "passive", "static"] = "active"


class TopologyLink(Record):
    id: UUID
    endpoints: tuple[UUID, UUID]
