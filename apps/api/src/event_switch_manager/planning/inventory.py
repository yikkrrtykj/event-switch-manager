import re
from ipaddress import IPv4Address, IPv4Interface
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BeforeValidator, StringConstraints, field_validator

from event_switch_manager.domain import DeviceFamily, DeviceRole
from event_switch_manager.integrations import Capability, Support
from event_switch_manager.schemas import Hostname, LocationText, SerialNumber

from .types import Name, PortName, PositiveInt, Record, VlanId


class PhysicalDevice(Record):
    id: UUID
    vendor: Literal["cisco", "hillstone", "other"]
    verified_serial: SerialNumber | None = None
    model: Name | None = None

    @field_validator("verified_serial")
    @classmethod
    def normalize_serial(cls, value: str | None) -> str | None:
        return value.upper() if value is not None else None


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


def _description_text(value: object) -> object:
    if isinstance(value, str) and re.search(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]", value):
        raise ValueError("Port descriptions must be a single line without control characters")
    return value


def _integer_speed(value: object) -> object:
    if type(value) is not int:
        raise ValueError("Fixed Ethernet speed must be an integer in Mbps")
    return value


PortDescription = Annotated[
    str, StringConstraints(strict=True, max_length=240), BeforeValidator(_description_text)
]
FixedPortSpeed = Annotated[
    Literal[10, 100, 1000, 2500, 5000, 10000, 25000, 40000, 50000, 100000, 200000, 400000, 800000],
    BeforeValidator(_integer_speed),
]


class PortSettings(Record):
    mode: Literal["access", "trunk", "routed"]
    access_vlan: VlanId | None = None
    native_vlan: VlanId | None = None
    allowed_vlans: tuple[VlanId, ...] = ()
    address: IPv4Interface | None = None
    description: PortDescription | None = None
    admin_state: Literal["up", "down"] | None = None
    speed: FixedPortSpeed | Literal["auto"] | None = None
    duplex: Literal["auto", "full", "half"] | None = None
    poe_mode: Literal["auto", "static", "never"] | None = None
    portfast: Literal["edge", "edge-trunk", "disabled"] | None = None
    bpdu_guard: Literal["enabled", "disabled"] | None = None


class PhysicalInterface(Record):
    id: UUID
    assignment_id: UUID
    physical_device_id: UUID
    name: PortName
    stack_member: PositiveInt | None = None
    settings: PortSettings
    capability_status: Literal["unknown", "unverified", "verified"] = "unknown"


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
