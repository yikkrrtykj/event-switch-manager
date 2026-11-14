"""Read-only contracts for future integrations.

Planning records and observations are separate. An observation can describe hardware
capabilities without changing an event plan or granting deployment permission.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .domain import DeviceFamily


class Capability(StrEnum):
    VLAN = "vlan"
    LACP = "lacp"
    RAPID_PVST = "rapid-pvst"
    POE = "poe"
    SVI = "svi"
    ROUTED_PORT = "routed-port"
    IPV4_ROUTING = "ipv4-routing"
    DHCP_SERVER = "dhcp-server"
    DHCP_RELAY = "dhcp-relay"
    DHCP_CLIENT = "dhcp-client"


class Support(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class ConsoleQuery(StrEnum):
    VERSION = "version"
    INVENTORY = "inventory"
    LICENSE = "license"
    INTERFACES = "interfaces"
    STACK = "stack"
    BOOT = "boot"
    STORAGE = "storage"


@dataclass(frozen=True, slots=True)
class StackMember:
    number: int
    model: str
    serial_number: str
    state: str


@dataclass(frozen=True, slots=True)
class SwitchObservation:
    family: DeviceFamily | None
    model: str
    serial_number: str
    software_version: str
    license: str | None
    interfaces: tuple[str, ...]
    stack: tuple[StackMember, ...]
    boot_state: str | None
    config_storage: tuple[str, ...]
    capabilities: tuple[tuple[Capability, Support], ...]


class ConsoleEngine(Protocol):
    """Interface for an already-open, exclusively owned console session."""

    def query(self, query: ConsoleQuery) -> str: ...


class DeviceAdapter(Protocol):
    def discover(self, console: ConsoleEngine) -> SwitchObservation: ...


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    passed: bool
    detail: str


class KeaAdapter(Protocol):
    def inspect_services(self) -> tuple[Check, ...]: ...


class HillstoneReadOnlyAdapter(Protocol):
    def inspect(self) -> tuple[Check, ...]: ...


@dataclass(frozen=True, slots=True)
class HypervisorObservation:
    platform: str
    version: str
    checks: tuple[Check, ...]


class HypervisorAdapter(Protocol):
    def preflight(self) -> HypervisorObservation: ...
