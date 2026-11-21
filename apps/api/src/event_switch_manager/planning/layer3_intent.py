"""CIS-03-02A read-only Layer 3 intent.

The intent is built only from an immutable saved revision and its previous
saved revision.  It never renders CLI, never opens a device session and never
writes plan data.  Every L3 conclusion is split into four independent facts:

* structured intent validity;
* vendor documentation status;
* runtime prerequisite status;
* hardware verification (always false in this phase).

Only a Cisco Core can receive a forwarding intent.  Access devices with a
management IP alone never become a router.  A deny VLAN policy blocks the whole
Core forwarding readiness until ACL generation exists; it is never silently
ignored.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from ..domain import DeviceFamily, DeviceRole
from .addressing import DhcpPool, Gateway, Subnet, Vlan
from .inventory import EventDeviceAssignment, LogicalInterface, PhysicalDevice
from .layer3_capability import (
    L3Capability,
    L3CapabilityDecision,
    L3Verdict,
    resolve_l3_capability,
    target_for,
)
from .plan import EventPlan, PlanRevision
from .routing import CiscoHillstoneTransit, IpNextHop
from .types import Record
from .validation import PlanIssue

INTENT_SCHEMA_VERSION: Literal[1] = 1
CONTRACT_ID: Literal["cis-03-cisco-l3-intent-v1"] = "cis-03-cisco-l3-intent-v1"
BASE_BLOCKERS: tuple[str, ...] = (
    "l3-intent-read-only",
    "no-cli-generated",
    "hardware-not-verified",
    "device-state-unknown",
    "deployment-generation-disabled",
)


class L3InterfaceRole(StrEnum):
    GATEWAY = "gateway"
    TRANSIT = "transit"
    ROUTED = "routed"
    OTHER = "other"


class L3Carrier(StrEnum):
    PLANNED_UP = "planned-up"
    PLANNED_MISSING = "planned-missing"
    NOT_APPLICABLE = "not-applicable"


class L3RoutingIntent(StrEnum):
    ENABLE = "enable"
    BLOCKED = "blocked"
    NOT_APPLICABLE = "not-applicable"


class L3DocumentationVerdict(StrEnum):
    SUPPORTED = "supported"
    CONDITIONAL = "conditional"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"
    NOT_APPLICABLE = "not-applicable"


class L3RuntimeVerdict(StrEnum):
    SATISFIED = "satisfied"
    UNOBSERVED = "unobserved"
    MISSING = "missing"
    NOT_APPLICABLE = "not-applicable"


DependencyKind = Literal[
    "vlan-definition",
    "svi-interface",
    "svi-address",
    "transit-svi",
    "default-route",
    "dhcp-relay",
    "acl-policy",
]


class L3BaselineInfo(Record):
    source: Literal["previous-saved-revision", "planning-baseline-unavailable"]
    revision_id: UUID | None
    revision_hash: str | None
    device_state: Literal["unknown"] = "unknown"


class L3StackMember(Record):
    number: int
    exact_pid: str | None
    state: str


class L3Identity(Record):
    assignment_id: UUID
    hostname: str
    role: DeviceRole
    family: DeviceFamily | None
    vendor: str | None
    physical_device_id: UUID | None
    exact_pid: str | None
    pid_evidence: Literal["exact-verified-pid", "model-only", "missing"]
    serial_verified: bool
    software_image: str | None
    software_license: str | None
    stack_identity: Literal["standalone", "resolved", "unresolved"]
    stack_members: tuple[L3StackMember, ...] = ()


class L3InterfaceIntent(Record):
    interface_id: UUID
    kind: Literal["svi", "routed-port", "port-channel"]
    name: str
    vlan: int | None
    address: IPv4Interface | None
    role: L3InterfaceRole
    subnet_id: UUID | None = None
    gateway_address: IPv4Address | None = None
    carrier: L3Carrier
    line_protocol: Literal["unknown-not-read"] = "unknown-not-read"


class L3RouteIntent(Record):
    route_id: UUID
    kind: Literal["static", "default"]
    destination: IPv4Network
    next_hop: IPv4Address
    distance: int
    owner_assignment_id: UUID
    transit_bound: bool


class L3TransitRelation(Record):
    transit_vlan: int
    network: IPv4Network
    core_ip: IPv4Address
    hillstone_ip: IPv4Address
    core_svi_id: UUID
    core_port_id: UUID
    hillstone_assignment_id: UUID
    vlan_declared: bool
    default_route_id: UUID | None


class L3DhcpRelayIntent(Record):
    subnet_id: UUID
    svi_id: UUID
    vlan: int
    servers: tuple[IPv4Address, ...]
    associated_pool_ids: tuple[UUID, ...] = ()
    server_ownership: Literal["external-unspecified"] = "external-unspecified"
    cisco_server_intent: Literal[False] = False
    capability: L3Verdict = L3Verdict.UNKNOWN
    allowed: bool = False
    blockers: tuple[str, ...] = ()


class L3DhcpServerObservation(Record):
    subnet_id: UUID
    pool_ids: tuple[UUID, ...]
    server_ownership: Literal["unspecified"] = "unspecified"
    cisco_server_intent: Literal[False] = False
    blocker: Literal["cisco-dhcp-server-ownership-unresolved"] = (
        "cisco-dhcp-server-ownership-unresolved"
    )


class L3Dependency(Record):
    dependency_id: str
    kind: Literal[
        "vlan-definition",
        "svi-interface",
        "svi-address",
        "transit-svi",
        "default-route",
        "dhcp-relay",
        "acl-policy",
    ]
    target: str
    detail: str


class L3Conflict(Record):
    code: str
    message: str
    severity: Literal["ERROR", "WARNING"]
    target: str


class L3BlockedOperation(Record):
    operation: Literal[
        "routed-port-transition",
        "cleanup",
        "svi-removal",
        "ip-routing",
        "policy-acl",
    ]
    target: str
    reason_code: str
    reason: str


class L3ForwardingReadiness(Record):
    allowed: bool
    ip_routing: L3RoutingIntent
    documentation: L3DocumentationVerdict
    runtime_prerequisite: L3RuntimeVerdict
    hardware_verified: Literal[False] = False
    deployment_allowed: Literal[False] = False
    blockers: tuple[str, ...] = ()


class L3EventReadiness(Record):
    forwarding_ready: bool
    core_devices: int
    blocked_core_devices: int
    documentation: L3DocumentationVerdict
    runtime_prerequisite: L3RuntimeVerdict
    hardware_verified: Literal[False] = False
    deployment_allowed: Literal[False] = False
    blockers: tuple[str, ...] = ()


class L3DeviceIntent(Record):
    identity: L3Identity
    transit: L3TransitRelation | None = None
    interfaces: tuple[L3InterfaceIntent, ...] = ()
    routes: tuple[L3RouteIntent, ...] = ()
    dhcp_relays: tuple[L3DhcpRelayIntent, ...] = ()
    dhcp_server_observations: tuple[L3DhcpServerObservation, ...] = ()
    service_blockers: tuple[str, ...] = ()
    capability_checks: tuple[L3CapabilityDecision, ...] = ()
    dependencies: tuple[L3Dependency, ...] = ()
    conflicts: tuple[L3Conflict, ...] = ()
    blocked_operations: tuple[L3BlockedOperation, ...] = ()
    removed_svi_ids: tuple[UUID, ...] = ()
    readiness: L3ForwardingReadiness
    blockers: tuple[str, ...] = ()


class L3TransitIntent(Record):
    core_assignment_id: UUID
    firewall_assignment_id: UUID
    vlan: int
    network: IPv4Network
    core_ip: IPv4Address
    hillstone_ip: IPv4Address
    core_svi_id: UUID
    core_port_id: UUID
    firewall_port_id: UUID
    vlan_declared: bool


class Layer3Intent(Record):
    l3_intent_schema_version: Literal[1] = INTENT_SCHEMA_VERSION
    contract_id: Literal["cis-03-cisco-l3-intent-v1"] = CONTRACT_ID
    source: Literal["saved-revision"] = "saved-revision"
    event_id: UUID
    revision_id: UUID
    revision_hash: str
    baseline: L3BaselineInfo
    device_state: Literal["unknown"] = "unknown"
    before_state_evidence: Literal["planning-baseline", "planning-baseline-unavailable"]
    transit: L3TransitIntent | None = None
    devices: tuple[L3DeviceIntent, ...] = ()
    validation_findings: tuple[PlanIssue, ...] = ()
    readiness: L3EventReadiness
    deployment_blockers: tuple[str, ...]
    intent_fingerprint: str
    verification: Literal["not-verified"] = "not-verified"
    deployment_status: Literal["blocked"] = "blocked"
    executable: Literal[False] = False
    cli: None = None
    device_writes_enabled: Literal[False] = False


def _json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: JsonValue) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _dep(
    assignment_id: UUID, kind: DependencyKind, target: str, detail: str,
) -> L3Dependency:
    digest = hashlib.sha256(f"{assignment_id}|{kind}|{target}".encode()).hexdigest()[:16]
    return L3Dependency(
        dependency_id=f"l3dep-{digest}", kind=kind, target=target, detail=detail,
    )


def _physical_device(plan: EventPlan, assignment: EventDeviceAssignment) -> PhysicalDevice | None:
    return next(
        (item for item in plan.physical_devices if item.id == assignment.physical_device_id),
        None,
    )


def _member_pid(devices: dict[UUID, PhysicalDevice], member_id: UUID) -> str | None:
    device = devices.get(member_id)
    if device is None or not device.model or not device.verified_serial:
        return None
    return device.model.upper()


def _identity(plan: EventPlan, assignment: EventDeviceAssignment) -> L3Identity:
    device = _physical_device(plan, assignment)
    target = target_for(plan, assignment)
    serial = bool(device and device.verified_serial)
    if target.exact_pid:
        evidence: Literal["exact-verified-pid", "model-only", "missing"] = "exact-verified-pid"
    elif device and device.model:
        evidence = "model-only"
    else:
        evidence = "missing"
    stack_members: tuple[L3StackMember, ...] = ()
    stack = next((item for item in plan.stacks if item.assignment_id == assignment.id), None)
    if stack is not None:
        devices = {item.id: item for item in plan.physical_devices}
        stack_members = tuple(
            L3StackMember(
                number=member.number,
                exact_pid=_member_pid(devices, member.physical_device_id),
                state=member.state,
            )
            for member in stack.members
        )
    return L3Identity(
        assignment_id=assignment.id,
        hostname=assignment.hostname,
        role=assignment.role,
        family=assignment.family,
        vendor=device.vendor if device else None,
        physical_device_id=assignment.physical_device_id,
        exact_pid=target.exact_pid,
        pid_evidence=evidence,
        serial_verified=serial,
        software_image=target.software_image,
        software_license=target.license,
        stack_identity=target.stack_identity,
        stack_members=stack_members,
    )


def _vlans(plan: EventPlan) -> dict[int, Vlan]:
    return {vlan.id: vlan for vlan in plan.vlans}


def _subnets(plan: EventPlan) -> dict[UUID, Subnet]:
    return {subnet.id: subnet for subnet in plan.subnets}


def _gateways(plan: EventPlan) -> dict[UUID, Gateway]:
    return {gateway.svi_id: gateway for gateway in plan.gateways}


def _vlan_carrier(plan: EventPlan, assignment_id: UUID, vlan: int) -> L3Carrier:
    """Planned carrier only; never a claim about real SVI line protocol."""
    ports = tuple(
        port for port in plan.physical_interfaces if port.assignment_id == assignment_id
    )
    for port in ports:
        if port.settings.admin_state == "down":
            continue
        if port.settings.mode == "access" and port.settings.access_vlan == vlan:
            return L3Carrier.PLANNED_UP
        if (
            port.settings.mode == "trunk"
            and vlan in port.settings.allowed_vlans
        ):
            return L3Carrier.PLANNED_UP
    aggregates = tuple(
        channel for channel in plan.port_channels
        if any(port.id in channel.member_ids for port in ports)
        and any(
            item.id == channel.interface_id
            and item.assignment_id == assignment_id
            for item in plan.logical_interfaces
        )
    )
    for channel in aggregates:
        if channel.settings.admin_state == "down":
            continue
        if channel.settings.mode == "access" and channel.settings.access_vlan == vlan:
            return L3Carrier.PLANNED_UP
        if channel.settings.mode == "trunk" and vlan in channel.settings.allowed_vlans:
            return L3Carrier.PLANNED_UP
    return L3Carrier.PLANNED_MISSING


def _svis(plan: EventPlan, assignment_id: UUID) -> tuple[LogicalInterface, ...]:
    return tuple(
        interface for interface in plan.logical_interfaces
        if interface.kind == "svi" and interface.assignment_id == assignment_id
    )


def _has_l3_records(plan: EventPlan, assignment_id: UUID) -> bool:
    if any(interface.assignment_id == assignment_id for interface in _svis(plan, assignment_id)):
        return True
    if plan.transit and assignment_id in {
        plan.transit.core_assignment_id,
        plan.transit.hillstone_assignment_id,
    }:
        return True
    if any(
        port.assignment_id == assignment_id and port.settings.mode == "routed"
        for port in plan.physical_interfaces
    ):
        return True
    if any(
        route.assignment_id == assignment_id
        for route in plan.static_routes
    ):
        return True
    if any(
        route.assignment_id == assignment_id
        for route in plan.default_routes
    ):
        return True
    if any(
        relay.svi_id in {interface.id for interface in _svis(plan, assignment_id)}
        for relay in plan.dhcp_relays
    ):
        return True
    return False


def _on_link(address: IPv4Address, interfaces: tuple[IPv4Interface, ...]) -> bool:
    return any(
        address != interface.ip and address in interface.network
        for interface in interfaces
    )


def _connected(plan: EventPlan, assignment_id: UUID) -> tuple[IPv4Interface, ...]:
    values: list[IPv4Interface] = []
    for port in plan.physical_interfaces:
        if port.assignment_id == assignment_id and port.settings.address is not None:
            values.append(port.settings.address)
    for interface in plan.logical_interfaces:
        if interface.assignment_id == assignment_id and interface.address is not None:
            values.append(interface.address)
    for channel in plan.port_channels:
        aggregate = next(
            (item for item in plan.logical_interfaces if item.id == channel.interface_id),
            None,
        )
        if (
            aggregate is not None
            and aggregate.assignment_id == assignment_id
            and channel.settings.address is not None
        ):
            values.append(channel.settings.address)
    if plan.transit and assignment_id == plan.transit.core_assignment_id:
        values.append(
            IPv4Interface((plan.transit.core_ip, plan.transit.network.prefixlen))
        )
    if plan.transit and assignment_id == plan.transit.hillstone_assignment_id:
        values.append(
            IPv4Interface((plan.transit.hillstone_ip, plan.transit.network.prefixlen))
        )
    return tuple(values)


def _capability_checks(
    plan: EventPlan,
    assignment: EventDeviceAssignment,
    *,
    svi_count: int,
    routed_ports: int,
    static_routes: int,
    default_routes: int,
    dhcp_relays: int,
    routing_enabled: bool,
) -> tuple[L3CapabilityDecision, ...]:
    capabilities: set[L3Capability] = set()
    if routing_enabled:
        capabilities.add(L3Capability.IPV4_ROUTING)
    if svi_count:
        capabilities.add(L3Capability.SVI)
    if routed_ports:
        capabilities.add(L3Capability.ROUTED_PORT)
    if static_routes:
        capabilities.add(L3Capability.STATIC_ROUTE)
    if default_routes:
        capabilities.add(L3Capability.DEFAULT_ROUTE)
    if dhcp_relays:
        capabilities.add(L3Capability.DHCP_RELAY)
    return tuple(
        resolve_l3_capability(plan, assignment.id, capability)
        for capability in sorted(capabilities, key=lambda item: item.value)
    )


def _documentation(checks: tuple[L3CapabilityDecision, ...]) -> L3DocumentationVerdict:
    if not checks:
        return L3DocumentationVerdict.NOT_APPLICABLE
    if any(check.verdict is L3Verdict.UNSUPPORTED for check in checks):
        return L3DocumentationVerdict.UNSUPPORTED
    if any(check.verdict is L3Verdict.UNKNOWN for check in checks):
        return L3DocumentationVerdict.UNKNOWN
    if any(check.verdict is L3Verdict.CONDITIONAL for check in checks):
        return L3DocumentationVerdict.CONDITIONAL
    return L3DocumentationVerdict.SUPPORTED


def _runtime(checks: tuple[L3CapabilityDecision, ...]) -> L3RuntimeVerdict:
    if not checks:
        return L3RuntimeVerdict.NOT_APPLICABLE
    if any(check.prerequisite.value == "missing" for check in checks):
        return L3RuntimeVerdict.MISSING
    if any(check.prerequisite.value == "unobserved" for check in checks):
        return L3RuntimeVerdict.UNOBSERVED
    return L3RuntimeVerdict.SATISFIED


def _transit_intent(plan: EventPlan) -> L3TransitIntent | None:
    transit = plan.transit
    if transit is None:
        return None
    return L3TransitIntent(
        core_assignment_id=transit.core_assignment_id,
        firewall_assignment_id=transit.hillstone_assignment_id,
        vlan=transit.vlan,
        network=transit.network,
        core_ip=transit.core_ip,
        hillstone_ip=transit.hillstone_ip,
        core_svi_id=transit.core_svi_id,
        core_port_id=transit.core_port_id,
        firewall_port_id=transit.hillstone_port_id,
        vlan_declared=transit.vlan in _vlans(plan),
    )


def _transit_relation(
    plan: EventPlan,
    assignment: EventDeviceAssignment,
    transit: CiscoHillstoneTransit,
) -> L3TransitRelation | None:
    if transit.core_assignment_id != assignment.id:
        return None
    default = min(
        (route for route in plan.default_routes if route.assignment_id == assignment.id),
        key=lambda route: route.preference,
        default=None,
    )
    return L3TransitRelation(
        transit_vlan=transit.vlan,
        network=transit.network,
        core_ip=transit.core_ip,
        hillstone_ip=transit.hillstone_ip,
        core_svi_id=transit.core_svi_id,
        core_port_id=transit.core_port_id,
        hillstone_assignment_id=transit.hillstone_assignment_id,
        vlan_declared=transit.vlan in _vlans(plan),
        default_route_id=default.id if default else None,
    )


def _interface_intents(
    plan: EventPlan,
    assignment: EventDeviceAssignment,
    conflicts: list[L3Conflict],
    dependencies: list[L3Dependency],
) -> tuple[L3InterfaceIntent, ...]:
    svis = _svis(plan, assignment.id)
    gateways = _gateways(plan)
    subnets = _subnets(plan)
    transit = plan.transit
    values: list[L3InterfaceIntent] = []
    seen_vlans: dict[int, UUID] = {}
    for svi in svis:
        if svi.vlan is None or svi.address is None:
            conflicts.append(L3Conflict(
                code="l3-svi-incomplete",
                message="An SVI requires a VLAN and an IPv4 interface address.",
                severity="ERROR",
                target=str(svi.id),
            ))
            continue
        if svi.vlan in seen_vlans:
            conflicts.append(L3Conflict(
                code="l3-duplicate-svi-vlan",
                message=(
                    f"Assignment {assignment.hostname} has more than one "
                    f"SVI for VLAN {svi.vlan}."
                ),
                severity="ERROR",
                target=f"vlan:{svi.vlan}",
            ))
        seen_vlans[svi.vlan] = svi.id
        if svi.name != f"Vlan{svi.vlan}":
            conflicts.append(L3Conflict(
                code="l3-svi-name-vlan-mismatch",
                message=(
                    f"SVI for VLAN {svi.vlan} must be named exactly "
                    f"Vlan{svi.vlan}; saved name {svi.name!r} is not normalized."
                ),
                severity="ERROR",
                target=str(svi.id),
            ))
        gateway = gateways.get(svi.id)
        subnet = subnets.get(gateway.subnet_id) if gateway else None
        role = L3InterfaceRole.TRANSIT if transit and transit.core_svi_id == svi.id else (
            L3InterfaceRole.GATEWAY if gateway else L3InterfaceRole.OTHER
        )
        if gateway and subnet:
            if (
                svi.vlan != subnet.vlan
                or svi.address.ip != gateway.address
                or svi.address.network != subnet.network
            ):
                conflicts.append(L3Conflict(
                    code="l3-svi-gateway-mismatch",
                    message="SVI VLAN/address/prefix must match its gateway and subnet.",
                    severity="ERROR",
                    target=str(svi.id),
                ))
        values.append(L3InterfaceIntent(
            interface_id=svi.id,
            kind="svi",
            name=svi.name,
            vlan=svi.vlan,
            address=svi.address,
            role=role,
            subnet_id=subnet.id if subnet else None,
            gateway_address=gateway.address if gateway else None,
            carrier=_vlan_carrier(plan, assignment.id, svi.vlan),
        ))
        dependencies.append(_dep(
            assignment.id, "vlan-definition", f"vlan:{svi.vlan}",
            f"VLAN {svi.vlan} must exist before the SVI.",
        ))
        dependencies.append(_dep(
            assignment.id, "svi-interface", f"svi:{svi.id}",
            f"SVI {svi.name} creation.",
        ))
        if gateway:
            dependencies.append(_dep(
                assignment.id, "svi-address", f"svi:{svi.id}",
                "SVI address must match the gateway and subnet.",
            ))
        if role is L3InterfaceRole.TRANSIT:
            dependencies.append(_dep(
                assignment.id, "transit-svi", f"svi:{svi.id}",
                "Transit SVI must match the Core-H Hillstone transit network.",
            ))
    for port in plan.physical_interfaces:
        if port.assignment_id != assignment.id or port.settings.mode != "routed":
            continue
        values.append(L3InterfaceIntent(
            interface_id=port.id,
            kind="routed-port",
            name=port.name,
            vlan=None,
            address=port.settings.address,
            role=L3InterfaceRole.ROUTED,
            carrier=L3Carrier.NOT_APPLICABLE,
        ))
    for channel in plan.port_channels:
        aggregate = next(
            (item for item in plan.logical_interfaces if item.id == channel.interface_id),
            None,
        )
        if (
            aggregate is None
            or aggregate.assignment_id != assignment.id
            or channel.settings.mode != "routed"
        ):
            continue
        values.append(L3InterfaceIntent(
            interface_id=aggregate.id,
            kind="port-channel",
            name=aggregate.name,
            vlan=None,
            address=channel.settings.address,
            role=L3InterfaceRole.ROUTED,
            carrier=L3Carrier.NOT_APPLICABLE,
        ))
    return tuple(sorted(values, key=lambda item: (item.kind, item.name, str(item.interface_id))))


def _route_intents(
    plan: EventPlan,
    assignment: EventDeviceAssignment,
    conflicts: list[L3Conflict],
) -> tuple[L3RouteIntent, ...]:
    connected = _connected(plan, assignment.id)
    values: list[L3RouteIntent] = []
    for route in plan.static_routes:
        if route.assignment_id != assignment.id:
            continue
        if route.destination.prefixlen == 0:
            conflicts.append(L3Conflict(
                code="l3-static-route-default-destination",
                message="A static route with a default destination is not supported here.",
                severity="ERROR",
                target=str(route.id),
            ))
            continue
        if route.activation is not None:
            conflicts.append(L3Conflict(
                code="l3-static-route-activation-unsupported",
                message="Tracked or conditional static-route activation is not supported.",
                severity="ERROR",
                target=str(route.id),
            ))
            continue
        if not isinstance(route.next_hop, IpNextHop):
            conflicts.append(L3Conflict(
                code="l3-unsupported-static-next-hop",
                message="Only an IPv4 next hop is supported for a Cisco Core static route.",
                severity="ERROR",
                target=str(route.id),
            ))
            continue
        if route.preference > 255:
            conflicts.append(L3Conflict(
                code="l3-route-distance-out-of-range",
                message="Static route distance must be 1-255.",
                severity="ERROR",
                target=str(route.id),
            ))
            continue
        if not _on_link(route.next_hop.address, connected):
            conflicts.append(L3Conflict(
                code="l3-route-next-hop-not-on-link",
                message="Static route next hop must be an on-link peer.",
                severity="ERROR",
                target=str(route.id),
            ))
            continue
        values.append(L3RouteIntent(
            route_id=route.id,
            kind="static",
            destination=route.destination,
            next_hop=route.next_hop.address,
            distance=route.preference,
            owner_assignment_id=route.assignment_id,
            transit_bound=False,
        ))
    transit = plan.transit
    for default_route in plan.default_routes:
        if default_route.assignment_id != assignment.id:
            continue
        if default_route.preference > 255:
            conflicts.append(L3Conflict(
                code="l3-route-distance-out-of-range",
                message="Default route distance must be 1-255.",
                severity="ERROR",
                target=str(default_route.id),
            ))
            continue
        if transit is None:
            conflicts.append(L3Conflict(
                code="l3-default-route-requires-transit",
                message="A Core default route requires a declared Core-H Hillstone transit.",
                severity="ERROR",
                target=str(default_route.id),
            ))
            continue
        if default_route.next_hop.address != transit.hillstone_ip:
            conflicts.append(L3Conflict(
                code="l3-default-route-not-transit",
                message="Core default route next hop must equal the transit Hillstone IP.",
                severity="ERROR",
                target=str(default_route.id),
            ))
            continue
        values.append(L3RouteIntent(
            route_id=default_route.id,
            kind="default",
            destination=IPv4Network("0.0.0.0/0"),
            next_hop=default_route.next_hop.address,
            distance=default_route.preference,
            owner_assignment_id=default_route.assignment_id,
            transit_bound=True,
        ))
    return tuple(sorted(
        values,
        key=lambda item: (item.kind, str(item.destination), str(item.route_id)),
    ))


def _dhcp_intents(
    plan: EventPlan,
    assignment: EventDeviceAssignment,
    conflicts: list[L3Conflict],
    dependencies: list[L3Dependency],
) -> tuple[tuple[L3DhcpRelayIntent, ...], tuple[L3DhcpServerObservation, ...]]:
    svi_ids = {svi.id for svi in _svis(plan, assignment.id)}
    gateways = _gateways(plan)
    subnets = _subnets(plan)
    owned_subnets = {
        gateway.subnet_id for gateway in plan.gateways
        if gateway.svi_id in svi_ids
    }
    pools_by_subnet: dict[UUID, list[DhcpPool]] = {}
    for pool in plan.dhcp_pools:
        pools_by_subnet.setdefault(pool.subnet_id, []).append(pool)
    relays: list[L3DhcpRelayIntent] = []
    observed_subnets: set[UUID] = set()
    for relay in plan.dhcp_relays:
        if relay.svi_id not in svi_ids:
            continue
        gateway = gateways.get(relay.svi_id)
        if gateway is None:
            conflicts.append(L3Conflict(
                code="l3-dhcp-relay-without-gateway",
                message="DHCP relay must reference the subnet gateway SVI.",
                severity="ERROR",
                target=str(relay.svi_id),
            ))
            continue
        subnet = subnets.get(gateway.subnet_id)
        if subnet is None:
            conflicts.append(L3Conflict(
                code="l3-dhcp-relay-without-subnet",
                message="DHCP relay subnet is missing.",
                severity="ERROR",
                target=str(relay.svi_id),
            ))
            continue
        observed_subnets.add(subnet.id)
        pool_ids = tuple(sorted(pool.id for pool in pools_by_subnet.get(subnet.id, [])))
        relays.append(L3DhcpRelayIntent(
            subnet_id=subnet.id,
            svi_id=relay.svi_id,
            vlan=subnet.vlan,
            servers=relay.servers,
            associated_pool_ids=pool_ids,
        ))
        dependencies.append(_dep(
            assignment.id, "dhcp-relay", f"subnet:{subnet.id}",
            "External DHCP relay target; the server is not generated by CIS-03.",
        ))
    observations: list[L3DhcpServerObservation] = []
    for subnet_id, subnet_pools in sorted(
        pools_by_subnet.items(), key=lambda item: str(item[0]),
    ):
        if subnet_id not in owned_subnets or subnet_id in observed_subnets:
            continue
        observations.append(L3DhcpServerObservation(
            subnet_id=subnet_id,
            pool_ids=tuple(sorted(pool.id for pool in subnet_pools)),
        ))
    return (
        tuple(sorted(relays, key=lambda item: (str(item.subnet_id), str(item.svi_id)))),
        tuple(observations),
    )


def _policy_block(plan: EventPlan) -> bool:
    return any(policy.action == "deny" for policy in plan.vlan_access_policies)


def _device_intent(
    plan: EventPlan,
    baseline_plan: EventPlan | None,
    assignment: EventDeviceAssignment,
    transit_intent: L3TransitIntent | None,
    *,
    plan_valid: bool,
) -> L3DeviceIntent:
    identity = _identity(plan, assignment)
    conflicts: list[L3Conflict] = []
    dependencies: list[L3Dependency] = []
    blockers: list[str] = []
    has_records = _has_l3_records(plan, assignment.id)
    explicit = assignment.routing_enabled
    routing_enabled = explicit if explicit is not None else assignment.role is DeviceRole.CORE
    if explicit is False and has_records:
        conflicts.append(L3Conflict(
            code="l3-routing-disabled-conflict",
            message="routing_enabled=false conflicts with existing L3 interfaces or routes.",
            severity="ERROR",
            target=assignment.hostname,
        ))
        blockers.append("l3-routing-disabled-conflict")
    if explicit is True and assignment.role is not DeviceRole.CORE and identity.vendor == "cisco":
        conflicts.append(L3Conflict(
            code="l3-routing-enabled-on-non-core",
            message="Only a Cisco Core may receive a default L3 forwarding intent.",
            severity="ERROR",
            target=assignment.hostname,
        ))
        blockers.append("l3-routing-enabled-on-non-core")
        routing_enabled = False
    if (
        assignment.role is not DeviceRole.CORE
        and has_records
        and identity.vendor == "cisco"
    ):
        conflicts.append(L3Conflict(
            code="l3-l3-records-on-non-core",
            message="L3 interfaces, routes or relay records must belong to a Core.",
            severity="ERROR",
            target=assignment.hostname,
        ))
        blockers.append("l3-forwarding-core-only")
    if assignment.role is DeviceRole.CORE and identity.vendor != "cisco":
        conflicts.append(L3Conflict(
            code="l3-core-not-cisco",
            message="A default L3 forwarding intent requires a Cisco Core.",
            severity="ERROR",
            target=assignment.hostname,
        ))
        blockers.append("l3-core-not-cisco")
        routing_enabled = False
    if assignment.role is DeviceRole.CORE and not plan_valid:
        conflicts.append(L3Conflict(
            code="l3-plan-invalid",
            message="The saved revision has plan validation errors.",
            severity="ERROR",
            target=assignment.hostname,
        ))
        blockers.append("l3-plan-invalid")
    if (
        assignment.role is DeviceRole.CORE
        and transit_intent is not None
        and not transit_intent.vlan_declared
    ):
        conflicts.append(L3Conflict(
            code="l3-transit-vlan-undefined",
            message="The transit VLAN must be declared in the event VLAN database.",
            severity="ERROR",
            target=f"vlan:{transit_intent.vlan}",
        ))
        blockers.append("l3-transit-vlan-undefined")
    if assignment.role is DeviceRole.CORE and plan.transit is not None:
        if plan.transit.core_assignment_id == assignment.id:
            transit_svi = next(
                (item for item in plan.logical_interfaces
                 if item.id == plan.transit.core_svi_id),
                None,
            )
            expected = IPv4Interface(
                (plan.transit.core_ip, plan.transit.network.prefixlen),
            )
            if (
                transit_svi is None
                or transit_svi.kind != "svi"
                or transit_svi.assignment_id != assignment.id
                or transit_svi.vlan != plan.transit.vlan
                or transit_svi.address != expected
            ):
                conflicts.append(L3Conflict(
                    code="l3-transit-svi-mismatch",
                    message="Transit SVI must match the transit VLAN, IP and prefix.",
                    severity="ERROR",
                    target=str(plan.transit.core_svi_id),
                ))
                blockers.append("l3-transit-svi-mismatch")
            transit_port = next(
                (item for item in plan.physical_interfaces
                 if item.id == plan.transit.core_port_id),
                None,
            )
            if (
                transit_port is None
                or transit_port.assignment_id != assignment.id
                or transit_port.settings.mode != "access"
                or transit_port.settings.access_vlan != plan.transit.vlan
                or transit_port.settings.admin_state == "down"
            ):
                conflicts.append(L3Conflict(
                    code="l3-transit-port-invalid",
                    message="Transit Core port must be an enabled access port on the transit VLAN.",
                    severity="ERROR",
                    target=str(plan.transit.core_port_id),
                ))
                blockers.append("l3-transit-port-invalid")
            preferred = min(
                (route for route in plan.default_routes if route.assignment_id == assignment.id),
                key=lambda route: route.preference,
                default=None,
            )
            if preferred is None or preferred.next_hop.address != plan.transit.hillstone_ip:
                conflicts.append(L3Conflict(
                    code="l3-core-default-route-mismatch",
                    message="Preferred Core default route must use the transit Hillstone IP.",
                    severity="ERROR",
                    target=assignment.hostname,
                ))
                blockers.append("l3-core-default-route-mismatch")
    policy_blocked = _policy_block(plan)
    if assignment.role is DeviceRole.CORE and policy_blocked:
        conflicts.append(L3Conflict(
            code="l3-vlan-access-policy-not-implemented",
            message="A deny VLAN policy exists but ACL generation is not implemented.",
            severity="ERROR",
            target="vlan-access-policy",
        ))
        blockers.append("l3-policy-acl-not-implemented")

    interfaces = (
        _interface_intents(plan, assignment, conflicts, dependencies)
        if assignment.role is DeviceRole.CORE else ()
    )
    routes = (
        _route_intents(plan, assignment, conflicts)
        if assignment.role is DeviceRole.CORE else ()
    )
    dhcp_relays, dhcp_observations = (
        _dhcp_intents(plan, assignment, conflicts, dependencies)
        if assignment.role is DeviceRole.CORE else ((), ())
    )
    svis = tuple(
        item for item in interfaces if item.kind == "svi"
    )
    for svi in svis:
        if svi.carrier is L3Carrier.PLANNED_MISSING:
            conflicts.append(L3Conflict(
                code="l3-svi-no-planned-carrier",
                message="The SVI VLAN is not carried by a planned up access or trunk port.",
                severity="ERROR",
                target=str(svi.interface_id),
            ))
            blockers.append("l3-svi-no-planned-carrier")
    if any(item.kind in {"routed-port", "port-channel"} for item in interfaces):
        blockers.append("routed-port-transition-requires-field-verification")
    gateway_vlans: dict[int, list[Subnet]] = {}
    for gateway in plan.gateways:
        subnet = next((item for item in plan.subnets if item.id == gateway.subnet_id), None)
        gateway_svi = next(
            (item for item in plan.logical_interfaces if item.id == gateway.svi_id), None,
        )
        if (
            subnet is None
            or gateway_svi is None
            or gateway_svi.assignment_id != assignment.id
        ):
            continue
        gateway_vlans.setdefault(subnet.vlan, []).append(subnet)
    for vlan, subnets in gateway_vlans.items():
        if len(subnets) > 1:
            conflicts.append(L3Conflict(
                code="l3-multiple-subnets-per-vlan",
                message="Multiple subnets on one VLAN (secondary IP) are not supported.",
                severity="ERROR",
                target=f"vlan:{vlan}",
            ))
            blockers.append("l3-multiple-subnets-per-vlan")
    raw_static_count = (
        sum(1 for route in plan.static_routes if route.assignment_id == assignment.id)
        if assignment.role is DeviceRole.CORE else 0
    )
    raw_default_count = (
        sum(1 for route in plan.default_routes if route.assignment_id == assignment.id)
        if assignment.role is DeviceRole.CORE else 0
    )
    checks = _capability_checks(
        plan,
        assignment,
        svi_count=len(svis) if assignment.role is DeviceRole.CORE else 0,
        routed_ports=sum(1 for item in interfaces if item.kind in {"routed-port", "port-channel"}),
        static_routes=raw_static_count,
        default_routes=raw_default_count,
        dhcp_relays=len(dhcp_relays),
        routing_enabled=routing_enabled and assignment.role is DeviceRole.CORE,
    )
    limit_check = next(
        (
            check for check in checks
            if check.max_routes is not None
            and check.capability in {L3Capability.STATIC_ROUTE, L3Capability.DEFAULT_ROUTE}
        ),
        None,
    )
    if limit_check is not None:
        max_routes = limit_check.max_routes
        assert max_routes is not None
        counted = (
            raw_static_count + raw_default_count
            if limit_check.route_limit_scope == "static-and-default"
            else raw_static_count
        )
        if counted > max_routes:
            conflicts.append(L3Conflict(
                code="l3-route-limit-exceeded",
                message=(
                    f"{counted} static/default routes exceed the documented "
                    f"limit of {max_routes} for this exact profile."
                ),
                severity="ERROR",
                target=assignment.hostname,
            ))
    for conflict in conflicts:
        if conflict.severity == "ERROR":
            blockers.append(conflict.code)

    service_blockers: list[str] = []
    relay_check = next(
        (check for check in checks if check.capability is L3Capability.DHCP_RELAY),
        None,
    )
    if dhcp_relays and relay_check is not None:
        relay_allowed = relay_check.verdict is L3Verdict.DOCUMENTED
        if not relay_allowed:
            service_blockers.append(relay_check.reason_code)
        dhcp_relays = tuple(
            relay.model_copy(update={
                "capability": relay_check.verdict,
                "allowed": relay_allowed,
                "blockers": () if relay_allowed else (relay_check.reason_code,),
            })
            for relay in dhcp_relays
        )
    for observation in dhcp_observations:
        service_blockers.append(observation.blocker)
    for check in checks:
        if check.affects_forwarding and check.verdict is not L3Verdict.DOCUMENTED:
            blockers.append(check.reason_code)
    documentation = _documentation(tuple(
        check for check in checks if check.affects_forwarding
    ))
    runtime = _runtime(tuple(
        check for check in checks if check.affects_forwarding
    ))
    allowed = (
        assignment.role is DeviceRole.CORE
        and identity.vendor == "cisco"
        and routing_enabled
        and documentation is L3DocumentationVerdict.SUPPORTED
        and runtime is L3RuntimeVerdict.SATISFIED
        and not blockers
        and not any(conflict.severity == "ERROR" for conflict in conflicts)
    )
    if not allowed and assignment.role is DeviceRole.CORE:
        if documentation is L3DocumentationVerdict.UNSUPPORTED:
            blockers.append("l3-documentation-unsupported")
        elif documentation is L3DocumentationVerdict.UNKNOWN:
            blockers.append("l3-documentation-unknown")
        elif documentation is L3DocumentationVerdict.CONDITIONAL:
            blockers.append("l3-documentation-conditional")
        if runtime is L3RuntimeVerdict.UNOBSERVED:
            blockers.append("l3-runtime-prerequisite-unobserved")
        elif runtime is L3RuntimeVerdict.MISSING:
            blockers.append("l3-runtime-prerequisite-missing")
    blockers_tuple = _dedupe(tuple(blockers))
    blocked_operations: list[L3BlockedOperation] = []
    if any(item.kind in {"routed-port", "port-channel"} for item in interfaces):
        blocked_operations.append(L3BlockedOperation(
            operation="routed-port-transition",
            target=assignment.hostname,
            reason_code="routed-port-conversion-requires-field-verification",
            reason="L2-to-L3 conversion may reset the interface and lose L2 settings.",
        ))
    if policy_blocked and assignment.role is DeviceRole.CORE:
        blocked_operations.append(L3BlockedOperation(
            operation="policy-acl",
            target="vlan-access-policy",
            reason_code="acl-generation-not-implemented",
            reason="Deny VLAN policies cannot be honoured without generated ACLs.",
        ))
    if assignment.role is DeviceRole.CORE and not allowed:
        blocked_operations.append(L3BlockedOperation(
            operation="ip-routing",
            target=assignment.hostname,
            reason_code="l3-forwarding-readiness-blocked",
            reason="L3 forwarding readiness is not satisfied.",
        ))
    if baseline_plan is not None:
        blocked_operations.append(L3BlockedOperation(
            operation="cleanup",
            target=assignment.hostname,
            reason_code="cleanup-requires-field-verification",
            reason="Removing old L3 configuration is not authorised by a planning difference.",
        ))
    removed_svi_ids: tuple[UUID, ...] = ()
    if baseline_plan is not None:
        current_ids = {svi.id for svi in _svis(plan, assignment.id)}
        removed_svi_ids = tuple(sorted(
            (svi.id for svi in _svis(baseline_plan, assignment.id) if svi.id not in current_ids),
            key=str,
        ))
        if removed_svi_ids:
            blocked_operations.append(L3BlockedOperation(
                operation="svi-removal",
                target=assignment.hostname,
                reason_code="svi-removal-not-rendered",
                reason="Removing a gateway SVI is destructive and is never auto-generated.",
            ))
    readiness = L3ForwardingReadiness(
        allowed=allowed,
        ip_routing=(
            L3RoutingIntent.ENABLE if allowed
            else L3RoutingIntent.BLOCKED if assignment.role is DeviceRole.CORE
            else L3RoutingIntent.NOT_APPLICABLE
        ),
        documentation=documentation,
        runtime_prerequisite=runtime,
        blockers=blockers_tuple,
    )
    return L3DeviceIntent(
        identity=identity,
        transit=(
            _transit_relation(plan, assignment, plan.transit)
            if plan.transit is not None and assignment.role is DeviceRole.CORE
            else None
        ),
        interfaces=interfaces,
        routes=routes,
        dhcp_relays=dhcp_relays,
        dhcp_server_observations=dhcp_observations,
        service_blockers=tuple(dict.fromkeys(service_blockers)),
        capability_checks=checks,
        dependencies=tuple(sorted(dependencies, key=lambda item: item.dependency_id)),
        conflicts=tuple(sorted(conflicts, key=lambda item: (item.code, item.target))),
        blocked_operations=tuple(blocked_operations),
        removed_svi_ids=removed_svi_ids,
        readiness=readiness,
        blockers=blockers_tuple,
    )


def _event_readiness(devices: tuple[L3DeviceIntent, ...]) -> L3EventReadiness:
    core = tuple(device for device in devices if device.identity.role is DeviceRole.CORE)
    if not core:
        return L3EventReadiness(
            forwarding_ready=False,
            core_devices=0,
            blocked_core_devices=0,
            documentation=L3DocumentationVerdict.NOT_APPLICABLE,
            runtime_prerequisite=L3RuntimeVerdict.NOT_APPLICABLE,
            blockers=("l3-no-cisco-core",),
        )
    documentation = _documentation(tuple(
        check for device in core for check in device.capability_checks
        if check.affects_forwarding
    ))
    runtime = _runtime(tuple(
        check for device in core for check in device.capability_checks
        if check.affects_forwarding
    ))
    blockers = _dedupe(tuple(
        blocker for device in core
        for blocker in (*device.readiness.blockers, *device.service_blockers)
    ))
    blocked = sum(1 for device in core if not device.readiness.allowed)
    return L3EventReadiness(
        forwarding_ready=blocked == 0,
        core_devices=len(core),
        blocked_core_devices=blocked,
        documentation=documentation,
        runtime_prerequisite=runtime,
        blockers=blockers,
    )


def build_layer3_intent(
    revision: PlanRevision,
    baseline: PlanRevision | None = None,
) -> Layer3Intent:
    """Build deterministic read-only L3 intent for one saved revision."""
    plan = revision.plan
    baseline_plan = baseline.plan if baseline is not None else None
    transit_intent = _transit_intent(plan)
    assignments = sorted(
        plan.assignments, key=lambda item: (item.hostname.casefold(), str(item.id)),
    )
    devices = tuple(
        _device_intent(
            plan, baseline_plan, assignment, transit_intent,
            plan_valid=revision.validation_status != "INVALID",
        )
        for assignment in assignments
    )
    readiness = _event_readiness(devices)
    blockers = _dedupe((
        *BASE_BLOCKERS,
        *(blocker for device in devices for blocker in device.blockers),
        *(blocker for device in devices for blocker in device.service_blockers),
    ))
    draft = Layer3Intent(
        event_id=plan.event_id,
        revision_id=revision.id,
        revision_hash=revision.content_hash,
        baseline=L3BaselineInfo(
            source=(
                "previous-saved-revision"
                if baseline is not None
                else "planning-baseline-unavailable"
            ),
            revision_id=baseline.id if baseline is not None else None,
            revision_hash=baseline.content_hash if baseline is not None else None,
        ),
        before_state_evidence=(
            "planning-baseline" if baseline is not None else "planning-baseline-unavailable"
        ),
        transit=transit_intent,
        devices=devices,
        validation_findings=(*revision.validation_errors, *revision.warnings),
        readiness=readiness,
        deployment_blockers=blockers,
        intent_fingerprint="",
    )
    document = draft.model_dump(mode="json")
    document.pop("intent_fingerprint")
    fingerprint = _sha256_json(document)
    return draft.model_copy(update={"intent_fingerprint": fingerprint})
