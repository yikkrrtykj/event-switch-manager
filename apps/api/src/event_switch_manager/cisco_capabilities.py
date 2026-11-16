"""Resolve documentation against a saved revision without granting deployment permission."""

import re
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from .cisco_catalog import (
    ADVANTAGE,
    FEATURES,
    PROFILES,
    CapabilityId,
    CiscoCapability,
    Medium,
    PortGroup,
    Profile,
    Source,
)
from .domain import DeviceFamily
from .integrations import Capability, Support
from .planning.inventory import (
    EventDeviceAssignment,
    PhysicalDevice,
    PhysicalInterface,
    SoftwareProfile,
    StackSnapshot,
)
from .planning.plan import PlanRevision
from .planning.types import Record

type Speed = int | Literal["auto"]
type Duplex = Literal["auto", "full", "half"]
type Finding = tuple[Support, str, str]

ETHERNET = re.compile(
    r"(gi(?:gabitethernet)?|te(?:ngigabitethernet)?|twe(?:ntyfivegige)?)"
    r"([1-9]\d*)/(\d+)/([1-9]\d*)", re.IGNORECASE,
)
PORT_FEATURES = {
    Capability.POE, CiscoCapability.POE_PLUS, CiscoCapability.PORT_MEDIA,
    CiscoCapability.SPEED, CiscoCapability.DUPLEX,
}
DHCP_FEATURES = {Capability.DHCP_SERVER, Capability.DHCP_RELAY, Capability.DHCP_CLIENT}
PREREQUISITES: dict[CapabilityId, str] = {
    CiscoCapability.SSH_V2: "Crypto-enabled image and device keys",
    CiscoCapability.BOOT: "Boot mode, variables and installed image or packages",
    CiscoCapability.STORAGE: "Flash layout, free space and configuration storage",
}


class Target(Record):
    event_id: UUID
    revision_id: UUID
    revision_hash: str
    assignment_id: UUID
    physical_device_id: UUID | None
    interface_id: UUID | None
    interface_name: str | None
    stack_member: int | None
    sku: str | None
    software: str | None
    license: str | None


class Evidence(Record):
    url: str
    section: str
    family: DeviceFamily
    sku: str
    version_scope: str | None
    licenses: tuple[str, ...]
    conditions: str
    status: Literal["vendor-documentation"] = "vendor-documentation"


class CapabilityDecision(Record):
    capability_id: CapabilityId
    verdict: Support
    reason_code: str
    reason: str
    evidence: tuple[Evidence, ...]
    affected: Target
    port_groups: tuple[PortGroup, ...]
    verification: Literal["not-verified"] = "not-verified"
    deployment_status: Literal["blocked"] = "blocked"
    blocks_deployment: Literal[True] = True
    deployment_blockers: tuple[str, ...]


class TargetNotFound(LookupError):
    """The requested assignment or interface is outside this revision scope."""


@dataclass(frozen=True, slots=True)
class Binding:
    assignment: EventDeviceAssignment
    asset: PhysicalDevice | None
    port: PhysicalInterface | None
    stack: StackSnapshot | None
    member: int | None
    members: tuple[PhysicalDevice | None, ...]
    problem: str | None = None


def exact_pid(asset: PhysicalDevice | None) -> str | None:
    if asset and asset.vendor == "cisco" and asset.model and asset.verified_serial:
        return asset.model.upper()
    return None


def bind(
    revision: PlanRevision, assignment_id: UUID, interface_id: UUID | None, member: int | None,
) -> Binding:
    plan = revision.plan
    assignment = next((a for a in plan.assignments if a.id == assignment_id), None)
    if assignment is None:
        raise TargetNotFound("Assignment not found in revision")
    port = None
    if interface_id is not None:
        port = next((p for p in plan.physical_interfaces
                     if p.id == interface_id and p.assignment_id == assignment_id), None)
        if port is None:
            raise TargetNotFound("Physical interface not found in assignment")
    stack = next((s for s in plan.stacks if s.assignment_id == assignment_id), None)
    devices = {device.id: device for device in plan.physical_devices}
    asset = devices.get(assignment.physical_device_id) if assignment.physical_device_id else None
    if stack is None:
        problem = None
        if member is not None or (port and (
            port.stack_member is not None
            or port.physical_device_id != assignment.physical_device_id
        )):
            problem = "Interface or member does not belong to the standalone chassis."
        return Binding(assignment, asset, port, None, None, (), problem)
    members = tuple(devices.get(m.physical_device_id) for m in stack.members)
    if port and member is not None and member != port.stack_member:
        return Binding(assignment, None, port, stack, member, members,
                       "Requested member does not own the interface.")
    number = port.stack_member if port else member
    if number is not None:
        matches = [m for m in stack.members if m.number == number]
        if len(matches) == 1 and (
            not port or port.physical_device_id == matches[0].physical_device_id
        ):
            return Binding(assignment, devices.get(matches[0].physical_device_id), port, stack,
                           number, members)
        return Binding(assignment, None, port, stack, number, members,
                       "Stack port or member binding is missing or ambiguous.")
    pids = {exact_pid(asset) for asset in members}
    if port or not pids or None in pids or len(pids) != 1:
        return Binding(assignment, None, port, stack, None, members,
                       "Supply a member or a homogeneous Stack with known PIDs.")
    return Binding(assignment, members[0], None, stack, None, members)


def software_problem(profile: Profile, software: SoftwareProfile | None) -> Finding | None:
    if not software or not re.fullmatch(profile.version_pattern, software.image, re.IGNORECASE):
        return Support.UNKNOWN, "release-unmatched", f"Specify a release in {profile.train}."
    license_name = software.license.casefold() if software.license else None
    accepted = {label.casefold() for label in profile.licenses}
    if (accepted and license_name not in accepted) or (not accepted and license_name is not None):
        scope = ", ".join(profile.licenses) or "the stock feature set with no explicit license"
        return Support.UNKNOWN, "license-unmatched", f"Documented license scope: {scope}."
    return None


def stack_finding(binding: Binding, profile: Profile) -> Finding:
    limit = profile.stack_limit
    if limit is None:
        return Support.UNKNOWN, "stack-evidence-missing", profile.stack_conditions
    if limit == 0:
        return Support.UNSUPPORTED, "stack-unsupported", profile.stack_conditions
    if binding.stack is None:
        return Support.SUPPORTED, "stack-capable", f"Stack hardware supports up to {limit} members."
    members = binding.stack.members
    if len(members) > limit or any(m.number > limit for m in members):
        return Support.UNSUPPORTED, "stack-member-limit", f"Member range is 1 to {limit}."
    pids = {exact_pid(asset) for asset in binding.members}
    if len(pids) != 1 or None in pids:
        return Support.UNKNOWN, "stack-identities-unresolved", "Member PIDs must match."
    if (
        len({m.number for m in members}) != len(members)
        or len({m.physical_device_id for m in members}) != len(members)
        or any(m.state != "ready" for m in members)
    ):
        return Support.UNKNOWN, "stack-layout-unresolved", "Unique, ready members are required."
    problem = software_problem(profile, binding.assignment.software)
    if problem:
        return problem
    return Support.SUPPORTED, "stack-layout-documented", "Declared member layout fits the catalog."


def find_group(profile: Profile, binding: Binding) -> PortGroup | None:
    if binding.port is None:
        return None
    match = ETHERNET.fullmatch(binding.port.name)
    if not match or int(match[2]) != (binding.member or 1):
        return None
    name, slot, port = match[1].casefold(), int(match[3]), int(match[4])
    return next(
        (group for group in profile.ports
         if name.startswith(group.prefix) and slot == group.slot
         and group.first <= port < group.first + group.count),
        None,
    )


def port_finding(
    capability: CapabilityId, group: PortGroup, speed: Speed | None, duplex: Duplex | None,
) -> Finding:
    if capability in {Capability.POE, CiscoCapability.POE_PLUS}:
        if group.poe_plus:
            return Support.SUPPORTED, "poe-documented", "The port supports PoE and PoE+."
        return Support.UNSUPPORTED, "poe-unsupported", "The port does not provide PoE."
    if capability in {CiscoCapability.SPEED, CiscoCapability.DUPLEX}:
        if isinstance(speed, int) and speed > max(group.rates):
            return Support.UNSUPPORTED, "speed-outside-port-range", "Speed exceeds the port rating."
        if group.medium != Medium.COPPER:
            return Support.UNKNOWN, "optic-unknown", "The installed transceiver is required."
        if isinstance(speed, int) and speed not in group.rates:
            return Support.UNSUPPORTED, "speed-unsupported", "Speed is outside copper port limits."
    if capability == CiscoCapability.SPEED:
        if speed is None:
            return Support.UNKNOWN, "speed-required", "Select a speed or auto negotiation."
        return Support.SUPPORTED, "speed-documented", "Copper supports this speed setting."
    if capability == CiscoCapability.DUPLEX:
        if duplex is None:
            return Support.UNKNOWN, "duplex-required", "Select a duplex setting."
        if duplex == "half" and speed == 1000:
            return Support.UNSUPPORTED, "duplex-unsupported", "1 Gbps requires full duplex."
        if duplex == "half" and speed not in {10, 100}:
            return Support.UNKNOWN, "duplex-speed-required", "Half duplex requires 10/100 Mbps."
        return Support.SUPPORTED, "duplex-documented", "Copper supports this duplex setting."
    return Support.SUPPORTED, "port-documented", "The physical port matches the documented map."


def resolve_capability(
    revision: PlanRevision,
    assignment_id: UUID,
    capability: CapabilityId,
    *,
    interface_id: UUID | None = None,
    stack_member: int | None = None,
    speed: Speed | None = None,
    duplex: Duplex | None = None,
) -> CapabilityDecision:
    """Evaluate only applicable vendor evidence. Device verification is independent."""
    binding = bind(revision, assignment_id, interface_id, stack_member)
    asset, port, software = binding.asset, binding.port, binding.assignment.software
    pid = exact_pid(asset)
    target = Target(
        event_id=revision.plan.event_id, revision_id=revision.id,
        revision_hash=revision.content_hash, assignment_id=assignment_id,
        physical_device_id=asset.id if asset and (not binding.stack or binding.member) else None,
        interface_id=interface_id, interface_name=port.name if port else None,
        stack_member=binding.member, sku=asset.model if asset else None,
        software=software.image if software else None,
        license=software.license if software else None,
    )

    def decide(
        finding: Finding, evidence: tuple[Evidence, ...] = (), groups: tuple[PortGroup, ...] = (),
    ) -> CapabilityDecision:
        verdict, code, reason = finding
        blockers = ["deployment-generation-disabled", "hardware-not-verified"]
        if verdict != Support.SUPPORTED:
            blockers.append(code)
        if revision.validation_status == "INVALID":
            blockers.append("plan-invalid")
        return CapabilityDecision(
            capability_id=capability, verdict=verdict, reason_code=code, reason=reason,
            evidence=evidence, affected=target, port_groups=groups,
            deployment_blockers=tuple(blockers),
        )

    if binding.problem:
        return decide((Support.UNKNOWN, "target-binding-unknown", binding.problem))
    if pid is None:
        return decide((Support.UNKNOWN, "identity-incomplete", "Supply a Cisco PID and serial."))
    profile = PROFILES.get(pid)
    if profile is None:
        return decide((Support.UNKNOWN, "pid-unlisted", "No evidence row for this exact PID."))
    if binding.assignment.family not in {None, profile.family}:
        return decide((Support.UNKNOWN, "family-mismatch", "Assignment family conflicts with PID."))

    def cite(
        source: Source, conditions: str, *, versioned: bool = False,
        licenses: tuple[str, ...] = (),
    ) -> Evidence:
        return Evidence(
            url=source.url, section=source.section, family=profile.family, sku=pid,
            version_scope=profile.train if versioned else None,
            licenses=licenses, conditions=conditions,
        )

    hardware = cite(profile.hardware, "Documented chassis characteristics for the exact PID.")
    if capability == CiscoCapability.IDENTITY:
        return decide((Support.SUPPORTED, "pid-documented", "The PID is listed."), (hardware,))
    if capability == CiscoCapability.STACK:
        finding = stack_finding(binding, profile)
        scoped = finding[1] == "stack-layout-documented"
        return decide(finding, (
            cite(profile.hardware, profile.stack_conditions, versioned=scoped,
                 licenses=profile.licenses if scoped else ()),
        ))
    if binding.member is not None and not (
        profile.stack_limit and binding.member <= profile.stack_limit
    ):
        return decide((Support.UNKNOWN, "stack-binding-unknown", "Member exceeds known limits."),
                      (hardware,))
    if capability == CiscoCapability.PORT_LAYOUT and port is None:
        finding = (Support.SUPPORTED, "layout-documented", "Fixed chassis groups are known.")
        if profile.modular:
            finding = (Support.UNKNOWN, "uplink-module-unknown", "Uplink module is required.")
        return decide(finding, (hardware,), profile.ports)

    problem = software_problem(profile, software)
    if problem:
        return decide(problem)
    group = find_group(profile, binding)
    if port and group is None:
        return decide((Support.UNKNOWN, "port-layout-unknown", "Unknown interface map."),
                      (hardware,))
    if capability in PORT_FEATURES or capability == CiscoCapability.PORT_LAYOUT:
        if not port or not group:
            return decide((Support.UNKNOWN, "port-required", "Select a physical interface."))
        interface_evidence = cite(
            Source(profile.interfaces, "Interface identification and speed/duplex guidelines"),
            f"{group.medium.value}, slot {group.slot}, indexes {group.first} through "
            f"{group.first + group.count - 1}. Optic and PoE budget require field verification.",
            versioned=True, licenses=profile.licenses,
        )
        finding = port_finding(
            capability, group, speed if speed is not None else port.settings.speed,
            duplex if duplex is not None else port.settings.duplex,
        )
        return decide(finding, (hardware, interface_evidence), (group,))

    feature = FEATURES.get(profile.family, {}).get(capability)
    if feature is None:
        return decide((Support.UNKNOWN, "feature-evidence-missing", "Feature evidence missing."))
    licenses = profile.licenses
    if capability in DHCP_FEATURES:
        if software is None or (software.license or "").casefold() != ADVANTAGE.casefold():
            return decide((
                Support.UNKNOWN, "feature-license-unverified",
                "The reviewed DHCP profile requires Network Advantage.",
            ))
        licenses = (ADVANTAGE,)
    prerequisite = PREREQUISITES.get(capability)
    if prerequisite:
        return decide((Support.UNKNOWN, "prerequisites-unobserved", prerequisite + " required."),
                      (cite(feature, prerequisite, versioned=True, licenses=licenses),))
    return decide(
        (Support.SUPPORTED, "feature-documented", "Vendor evidence applies to this profile."),
        (cite(feature, "Feature availability. Operational prerequisites still apply.",
              versioned=True, licenses=licenses),),
    )
