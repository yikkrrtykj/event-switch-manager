"""Resolve documentation for a saved revision or draft without granting deployment."""

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal
from uuid import UUID

from .cisco_catalog import (
    ADVANTAGE,
    FEATURES,
    GUIDE_SCOPES,
    PROFILES,
    R84_CONSOLE_ONLY_PIDS,
    RELEASES,
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
from .planning.plan import EventPlan, PlanRevision
from .planning.types import Record

type Speed = int | Literal["auto"]
type Duplex = Literal["auto", "full", "half"]
type Finding = tuple[Support, str, str]

ETHERNET = re.compile(
    r"(gi(?:gabitethernet)?|te(?:ngigabitethernet)?|twe(?:ntyfivegige)?)"
    r"([1-9]\d*)/(\d+)/([1-9]\d*)", re.IGNORECASE,
)
HARDWARE_PORT_FEATURES = {
    Capability.POE, CiscoCapability.POE_PLUS, CiscoCapability.PORT_MEDIA,
    CiscoCapability.PORT_LAYOUT,
}
INTERFACE_SETTINGS = {CiscoCapability.SPEED, CiscoCapability.DUPLEX}
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


class DraftTarget(Record):
    """Draft target identity. It deliberately has no persisted revision identifiers."""

    event_id: UUID
    assignment_id: UUID
    physical_device_id: UUID | None
    interface_id: UUID | None
    interface_name: str | None
    stack_member: int | None
    sku: str | None
    software: str | None
    license: str | None


class DraftCapabilityDecision(Record):
    capability_id: CapabilityId
    verdict: Support
    reason_code: str
    reason: str
    evidence: tuple[Evidence, ...]
    affected: DraftTarget
    port_groups: tuple[PortGroup, ...]
    verification: Literal["not-verified"] = "not-verified"
    deployment_status: Literal["blocked"] = "blocked"
    blocks_deployment: Literal[True] = True
    deployment_blockers: tuple[str, ...]


class DraftCapabilityPreview(Record):
    source: Literal["unsaved-draft"] = "unsaved-draft"
    draft_fingerprint: str
    input_fingerprint: str
    decisions: tuple[DraftCapabilityDecision, ...]


class TargetNotFound(LookupError):
    """The requested assignment or interface is outside this plan scope."""


@dataclass(frozen=True, slots=True)
class TargetFields:
    event_id: UUID
    assignment_id: UUID
    physical_device_id: UUID | None
    interface_id: UUID | None
    interface_name: str | None
    stack_member: int | None
    sku: str | None
    software: str | None
    license: str | None


@dataclass(frozen=True, slots=True)
class CapabilityContext:
    plan: EventPlan
    validation_status: Literal["VALID", "VALID_WITH_WARNINGS", "INVALID"]
    source: Literal["saved-revision", "unsaved-draft"]


@dataclass(frozen=True, slots=True)
class ResolvedCapability:
    verdict: Support
    reason_code: str
    reason: str
    evidence: tuple[Evidence, ...]
    port_groups: tuple[PortGroup, ...]
    target: TargetFields
    deployment_blockers: tuple[str, ...]


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
    plan: EventPlan, assignment_id: UUID, interface_id: UUID | None, member: int | None,
    source: Literal["saved-revision", "unsaved-draft"] = "saved-revision",
) -> Binding:
    assignment = next((a for a in plan.assignments if a.id == assignment_id), None)
    if assignment is None:
        raise TargetNotFound(
            "Assignment not found in revision" if source == "saved-revision"
            else "Assignment not found in plan"
        )
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


@dataclass(frozen=True, slots=True)
class Release:
    version: str
    label: str
    source: Source


def identify_release(profile: Profile, software: SoftwareProfile | None) -> Release | Finding:
    if software is None:
        return Support.UNKNOWN, "software-missing", "Supply the operating software release."
    inventory = RELEASES[profile.family]
    identifier = software.image.casefold()
    if identifier in inventory.bootloaders:
        return Support.UNKNOWN, "software-is-rommon", "Supply the running IOS or IOS XE release."
    for version in inventory.releases:
        if identifier == version.casefold():
            return Release(version, f"{inventory.operating_system} {version}", inventory.source)
    return Support.UNKNOWN, "release-unmatched", "No reviewed release identity for this platform."


def software_evidence_scope(
    profile: Profile, software: SoftwareProfile | None, guide_releases: tuple[str, ...] | None,
) -> Release | Finding:
    release = identify_release(profile, software)
    if not isinstance(release, Release):
        return release
    if guide_releases is None:
        return Support.UNKNOWN, "feature-evidence-missing", "Feature evidence missing."
    if release.version not in guide_releases:
        return Support.UNKNOWN, "release-evidence-missing", "No guide scope for this exact release."
    license_name = software.license.casefold() if software and software.license else None
    accepted = {label.casefold() for label in profile.licenses}
    if (accepted and license_name not in accepted) or (not accepted and license_name is not None):
        scope = ", ".join(profile.licenses) or "the stock feature set with no explicit license"
        return Support.UNKNOWN, "license-unmatched", f"Documented license scope: {scope}."
    return release


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


def port_hardware_finding(capability: CapabilityId, group: PortGroup) -> Finding:
    if capability in {Capability.POE, CiscoCapability.POE_PLUS}:
        if group.poe_plus:
            return Support.SUPPORTED, "poe-documented", "The port is rated for PoE and PoE+."
        return Support.UNSUPPORTED, "poe-unsupported", "The port does not provide PoE."
    return Support.SUPPORTED, "port-documented", "The physical port matches the documented map."


def port_setting_finding(
    capability: CapabilityId, group: PortGroup, speed: Speed | None, duplex: Duplex | None,
) -> Finding:
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
    if duplex is None:
        return Support.UNKNOWN, "duplex-required", "Select a duplex setting."
    if duplex == "half" and speed == 1000:
        return Support.UNSUPPORTED, "duplex-unsupported", "1 Gbps requires full duplex."
    if duplex == "half" and speed not in {10, 100}:
        return Support.UNKNOWN, "duplex-speed-required", "Half duplex requires 10/100 Mbps."
    return Support.SUPPORTED, "duplex-documented", "Copper supports this duplex setting."


def _resolve(
    context: CapabilityContext,
    assignment_id: UUID,
    capability: CapabilityId,
    *,
    interface_id: UUID | None = None,
    stack_member: int | None = None,
    speed: Speed | None = None,
    duplex: Duplex | None = None,
) -> ResolvedCapability:
    """Evaluate only applicable vendor evidence. Device verification is independent."""
    binding = bind(context.plan, assignment_id, interface_id, stack_member, context.source)
    asset, port, software = binding.asset, binding.port, binding.assignment.software
    pid = exact_pid(asset)
    target = TargetFields(
        event_id=context.plan.event_id, assignment_id=assignment_id,
        physical_device_id=asset.id if asset and (not binding.stack or binding.member) else None,
        interface_id=interface_id, interface_name=port.name if port else None,
        stack_member=binding.member, sku=asset.model if asset else None,
        software=software.image if software else None,
        license=software.license if software else None,
    )

    def decide(
        finding: Finding, evidence: tuple[Evidence, ...] = (), groups: tuple[PortGroup, ...] = (),
    ) -> ResolvedCapability:
        verdict, code, reason = finding
        blockers = ["deployment-generation-disabled", "hardware-not-verified"]
        if context.source == "unsaved-draft":
            blockers.append("draft-not-persisted")
        if verdict != Support.SUPPORTED:
            blockers.append(code)
        if context.validation_status == "INVALID":
            blockers.append("plan-invalid")
        return ResolvedCapability(
            verdict=verdict, reason_code=code, reason=reason,
            evidence=evidence, port_groups=groups, target=target,
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
        source: Source, conditions: str, *, release: Release | None = None,
        licenses: tuple[str, ...] = (),
    ) -> Evidence:
        return Evidence(
            url=source.url, section=source.section, family=profile.family, sku=pid,
            version_scope=release.label if release else None,
            licenses=licenses, conditions=conditions,
        )

    def cite_release(release: Release) -> Evidence:
        return cite(release.source, "Operating release identity for this PID.", release=release)

    hardware = cite(profile.hardware, "Documented chassis characteristics for the exact PID.")
    guides = GUIDE_SCOPES[profile.family]
    if capability == CiscoCapability.IDENTITY:
        return decide((Support.SUPPORTED, "pid-documented", "The PID is listed."), (hardware,))
    if pid in R84_CONSOLE_ONLY_PIDS:
        # R84 adds only a console read-only identity/query profile.  Production
        # capability evidence for this exact PID remains unreviewed.
        return decide(
            (
                Support.UNKNOWN,
                "console-only-evidence",
                "R84 reviewed a console read-only profile only; "
                "production capability evidence is not reviewed.",
            ),
            (hardware,),
        )
    if capability == CiscoCapability.STACK:
        finding = stack_finding(binding, profile)
        stack_hardware = cite(profile.hardware, profile.stack_conditions)
        if finding[1] != "stack-layout-documented":
            return decide(finding, (stack_hardware,))
        stack_release = software_evidence_scope(profile, software, guides.interfaces)
        if not isinstance(stack_release, Release):
            return decide(stack_release)
        if guides.stacks is None:
            return decide((Support.UNKNOWN, "stack-evidence-missing", profile.stack_conditions))
        return decide(finding, (
            stack_hardware,
            cite(guides.stacks, profile.stack_conditions,
                 release=stack_release, licenses=profile.licenses),
            cite_release(stack_release),
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

    group = find_group(profile, binding)
    if port and group is None:
        return decide((Support.UNKNOWN, "port-layout-unknown", "Unknown interface map."),
                      (hardware,))
    if capability in HARDWARE_PORT_FEATURES:
        if group is None:
            return decide((Support.UNKNOWN, "port-required", "Select a physical interface."))
        return decide(port_hardware_finding(capability, group), (hardware,), (group,))

    if capability in INTERFACE_SETTINGS:
        interface_release = software_evidence_scope(profile, software, guides.interfaces)
        if not isinstance(interface_release, Release):
            return decide(interface_release)
        if port is None or group is None:
            return decide((Support.UNKNOWN, "port-required", "Select a physical interface."))
        interface_evidence = cite(
            Source(profile.interfaces, "Interface identification and speed/duplex guidelines"),
            f"{group.medium.value}, slot {group.slot}, indexes {group.first} through "
            f"{group.first + group.count - 1}. Optic and PoE budget require field verification.",
            release=interface_release, licenses=profile.licenses,
        )
        finding = port_setting_finding(
            capability, group, speed if speed is not None else port.settings.speed,
            duplex if duplex is not None else port.settings.duplex,
        )
        return decide(finding, (hardware, interface_evidence, cite_release(interface_release)),
                      (group,))

    feature = FEATURES.get(profile.family, {}).get(capability)
    release = software_evidence_scope(profile, software, feature.releases if feature else None)
    if not isinstance(release, Release):
        return decide(release)
    assert feature is not None
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
                      (cite(feature.source, prerequisite, release=release, licenses=licenses),
                       cite_release(release)))
    return decide(
        (Support.SUPPORTED, "feature-documented", "Vendor evidence applies to this profile."),
        (cite(feature.source, "Feature availability. Operational prerequisites still apply.",
              release=release, licenses=licenses), cite_release(release)),
    )


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
    """Read one capability for a persisted revision without changing its identity."""
    resolved = _resolve(
        CapabilityContext(revision.plan, revision.validation_status, "saved-revision"),
        assignment_id, capability, interface_id=interface_id, stack_member=stack_member,
        speed=speed, duplex=duplex,
    )
    target = resolved.target
    return CapabilityDecision(
        capability_id=capability, verdict=resolved.verdict, reason_code=resolved.reason_code,
        reason=resolved.reason, evidence=resolved.evidence,
        affected=Target(
            event_id=target.event_id, revision_id=revision.id,
            revision_hash=revision.content_hash, assignment_id=target.assignment_id,
            physical_device_id=target.physical_device_id, interface_id=target.interface_id,
            interface_name=target.interface_name, stack_member=target.stack_member,
            sku=target.sku, software=target.software, license=target.license,
        ),
        port_groups=resolved.port_groups, deployment_blockers=resolved.deployment_blockers,
    )


def resolve_draft_capability(
    plan: EventPlan,
    validation_status: Literal["VALID", "VALID_WITH_WARNINGS", "INVALID"],
    assignment_id: UUID,
    capability: CapabilityId,
    *,
    interface_id: UUID | None = None,
    stack_member: int | None = None,
    speed: Speed | None = None,
    duplex: Duplex | None = None,
) -> DraftCapabilityDecision:
    """Evaluate an unsaved draft. It never receives or returns a revision identifier."""
    resolved = _resolve(
        CapabilityContext(plan, validation_status, "unsaved-draft"),
        assignment_id, capability, interface_id=interface_id, stack_member=stack_member,
        speed=speed, duplex=duplex,
    )
    target = resolved.target
    return DraftCapabilityDecision(
        capability_id=capability, verdict=resolved.verdict, reason_code=resolved.reason_code,
        reason=resolved.reason, evidence=resolved.evidence,
        affected=DraftTarget(
            event_id=target.event_id, assignment_id=target.assignment_id,
            physical_device_id=target.physical_device_id, interface_id=target.interface_id,
            interface_name=target.interface_name, stack_member=target.stack_member,
            sku=target.sku, software=target.software, license=target.license,
        ),
        port_groups=resolved.port_groups, deployment_blockers=resolved.deployment_blockers,
    )


def preview_fingerprint(
    content_hash: str,
    assignment_id: UUID,
    capabilities: tuple[CapabilityId, ...],
    *,
    interface_id: UUID | None,
    stack_member: int | None,
    speed: Speed | None,
    duplex: Duplex | None,
) -> str:
    """Fingerprint the exact draft and query inputs so stale previews are detectable."""
    payload = {
        "draft": content_hash,
        "assignment_id": str(assignment_id),
        "capabilities": [capability.value for capability in capabilities],
        "interface_id": str(interface_id) if interface_id else None,
        "stack_member": stack_member,
        "speed": speed,
        "duplex": duplex,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()
