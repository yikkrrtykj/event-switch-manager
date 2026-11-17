"""CIS-02A Layer 2 configuration intent engine.

Read-only planning layer between an immutable EventPlan revision/CIS-01A
capability evidence and a future CLI renderer. It produces structured desired
state, a deterministic ChangeSet, dependencies, conflicts and diagnostics.

It deliberately never renders Cisco CLI, never claims the device running-config
is known, never marks anything deployment-ready and never writes a device.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast
from uuid import UUID

from pydantic import JsonValue

from ..cisco_capabilities import CapabilityDecision, TargetNotFound, exact_pid, resolve_capability
from ..cisco_catalog import CapabilityId, CiscoCapability
from ..domain import DeviceFamily, DeviceRole
from ..integrations import Capability, Support
from .inventory import (
    EventDeviceAssignment,
    PhysicalDevice,
    PhysicalInterface,
    PortChannel,
    PortSettings,
    StackMember,
    StackSnapshot,
)
from .plan import EventPlan, PlanRevision
from .types import Record
from .validation import PlanIssue

DEFAULT_POLICY_ID = "cis-02a-reviewed-defaults-v1"
DEFAULT_SPANNING_TREE_MODE: Literal["rapid-pvst"] = "rapid-pvst"
DEFAULT_VTP_MODE: Literal["transparent"] = "transparent"
REVIEWED_DEFAULT_POLICY: Literal["reviewed-default-policy"] = "reviewed-default-policy"
EVENT_PLAN_SOURCE: Literal["event-plan"] = "event-plan"
PLANNING_BASELINE: Literal["planning-baseline"] = "planning-baseline"
PLANNING_BASELINE_UNAVAILABLE: Literal["planning-baseline-unavailable"] = (
    "planning-baseline-unavailable"
)
NOT_IN_BASELINE = "not-in-baseline"

ROOT_PRIORITY_BY_ROLE: Mapping[DeviceRole, int] = {
    DeviceRole.CORE: 4096,
    DeviceRole.EXTERNAL_DISTRIBUTION: 8192,
    DeviceRole.ACCESS: 32768,
}

INTENT_BASE_BLOCKERS: tuple[str, ...] = (
    "deployment-generation-disabled",
    "hardware-not-verified",
    "device-state-unknown",
    "intent-not-deployment-ready",
)

DEVICE_CAPABILITIES: tuple[CapabilityId, ...] = (
    CiscoCapability.IDENTITY,
    CiscoCapability.PORT_LAYOUT,
    Capability.VLAN,
    Capability.RAPID_PVST,
    CiscoCapability.VTP_TRANSPARENT,
)


class BeforeSource(StrEnum):
    PLANNING_BASELINE = PLANNING_BASELINE
    PLANNING_BASELINE_UNAVAILABLE = PLANNING_BASELINE_UNAVAILABLE
    NOT_IN_BASELINE = NOT_IN_BASELINE


class ChangeTarget(StrEnum):
    DEVICE = "device"
    INTERFACE = "interface"
    PORT_CHANNEL = "port-channel"
    VLAN = "vlan"


class DependencyKind(StrEnum):
    VLAN_DEFINITION = "vlan-definition"
    PORT_CHANNEL_INTERFACE = "port-channel-interface"
    PORT_CHANNEL_MEMBERSHIP = "port-channel-membership"
    MEMBER_DETACH = "member-detach"
    MODE_CLEANUP = "mode-cleanup"
    ROUTED_BOUNDARY = "routed-boundary"
    UNUSED_PORT_POLICY = "unused-port-policy"
    STACK_MEMBER_BINDING = "stack-member-binding"
    PHYSICAL_DEVICE_BINDING = "physical-device-binding"
    PORT_CHANNEL_REMOVAL = "port-channel-removal"


class DocumentationVerdict(StrEnum):
    SUPPORTED = "supported"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"


class EvidenceSummary(Record):
    url: str
    section: str
    version_scope: str | None
    licenses: tuple[str, ...]
    conditions: str


class CapabilityCheck(Record):
    scope: Literal["device", "interface"]
    subject: str
    capability: CapabilityId
    verdict: Support
    reason_code: str
    reason: str
    evidence: tuple[EvidenceSummary, ...]


class StackMemberIntent(Record):
    number: int
    physical_device_id: UUID
    pid: str | None
    state: Literal["ready", "missing", "unknown"]


class DeviceIdentity(Record):
    assignment_id: UUID
    hostname: str
    role: DeviceRole
    family: DeviceFamily | None
    physical_device_id: UUID | None
    pid: str | None
    pid_evidence: Literal["exact-verified-pid", "model-only", "missing"]
    serial_verified: bool
    software_image: str | None
    software_license: str | None
    stack_identity: Literal["standalone", "resolved", "unresolved"]
    stack_members: tuple[StackMemberIntent, ...]


class VlanIntent(Record):
    vlan_id: int
    name: str | None
    source: Literal["event-plan", "management-vlan"]


class SpanningTreeIntent(Record):
    mode: Literal["rapid-pvst"]
    source: Literal["reviewed-default-policy"]


class VtpIntent(Record):
    mode: Literal["transparent"]
    source: Literal["reviewed-default-policy"]


class RootPriorityIntent(Record):
    priority: int
    source: Literal["reviewed-default-policy"]
    policy: Literal["role-priority-v1"]


class UnusedPortPolicy(Record):
    shutdown: bool
    source: Literal["reviewed-default-policy"]
    scope: str
    semantics: Literal["no-links-port-channels-isps-or-transit"]
    requires_field_verification: Literal[True]


class PortChannelSettingsIntent(Record):
    mode: Literal["access", "trunk", "routed"]
    access_vlan: int | None
    native_vlan: int | None
    allowed_vlans: tuple[int, ...]
    routed_address: str | None
    description: str | None
    admin_state: Literal["up", "down"] | None
    portfast: Literal["edge", "edge-trunk", "disabled"] | None
    bpdu_guard: Literal["enabled", "disabled"] | None


class PhysicalPortIntent(Record):
    interface_id: UUID
    name: str
    physical_device_id: UUID | None
    stack_member: int | None
    mode: Literal["access", "trunk", "routed"]
    switchport: bool
    access_vlan: int | None
    native_vlan: int | None
    allowed_vlans: tuple[int, ...]
    routed_address: str | None
    description: str | None
    admin_state: Literal["up", "down"] | None
    shutdown_intent: Literal["shutdown", "no-shutdown", "platform-default"]
    shutdown_intent_source: Literal["event-plan", "reviewed-default-policy"] | None
    speed: int | Literal["auto"] | None
    duplex: Literal["auto", "full", "half"] | None
    poe_mode: Literal["auto", "static", "never"] | None
    portfast: Literal["edge", "edge-trunk", "disabled"] | None
    bpdu_guard: Literal["enabled", "disabled"] | None
    port_channel: int | None
    unused: bool


class PortChannelIntent(Record):
    interface_id: UUID
    name: str | None
    number: int
    member_ids: tuple[UUID, ...]
    member_names: tuple[str, ...]
    lacp: Literal["active", "passive", "static"]
    settings: PortChannelSettingsIntent


class DeviceDesiredState(Record):
    vlans: tuple[VlanIntent, ...]
    spanning_tree: SpanningTreeIntent
    vtp: VtpIntent
    root_priority: RootPriorityIntent
    unused_port_policy: UnusedPortPolicy
    physical_ports: tuple[PhysicalPortIntent, ...]
    port_channels: tuple[PortChannelIntent, ...]


class PlannedBeforeState(Record):
    source: BeforeSource
    baseline_revision_id: UUID | None
    baseline_revision_hash: str | None
    device_state: Literal["unknown"]
    state: DeviceDesiredState | None


class PlannedChange(Record):
    change_id: str
    target_kind: ChangeTarget
    target_id: str
    target_name: str
    field: str
    before: JsonValue | None
    after: JsonValue | None
    transition: str | None
    before_source: BeforeSource
    after_source: Literal["event-plan", "reviewed-default-policy"]
    dependencies: tuple[str, ...]
    cleanup: tuple[str, ...]


class IntentDependency(Record):
    dependency_id: str
    kind: DependencyKind
    target: str
    required_by: tuple[str, ...]


class IntentConflict(Record):
    code: str
    message: str
    target: str
    severity: Literal["ERROR", "WARNING"]


class IntentReadiness(Record):
    structured_intent_valid: bool
    vendor_documentation: DocumentationVerdict
    hardware_verified: Literal[False] = False
    deployment_allowed: Literal[False] = False


class DeviceLayer2Intent(Record):
    identity: DeviceIdentity
    desired: DeviceDesiredState
    before: PlannedBeforeState
    changes: tuple[PlannedChange, ...]
    dependencies: tuple[IntentDependency, ...]
    conflicts: tuple[IntentConflict, ...]
    capability_checks: tuple[CapabilityCheck, ...]
    readiness: IntentReadiness


class BaselineInfo(Record):
    source: Literal["previous-saved-revision", "none"]
    revision_id: UUID | None
    revision_hash: str | None
    device_state: Literal["unknown"]


class Layer2Intent(Record):
    intent_schema_version: Literal[1] = 1
    source: Literal["saved-revision"] = "saved-revision"
    event_id: UUID
    revision_id: UUID
    revision_hash: str
    baseline: BaselineInfo
    device_state: Literal["unknown"] = "unknown"
    before_state_evidence: Literal["planning-baseline", "planning-baseline-unavailable"]
    default_policy_id: Literal["cis-02a-reviewed-defaults-v1"] = "cis-02a-reviewed-defaults-v1"
    vlans: tuple[VlanIntent, ...]
    vlan_changes: tuple[PlannedChange, ...]
    vlan_dependencies: tuple[IntentDependency, ...]
    devices: tuple[DeviceLayer2Intent, ...]
    conflicts: tuple[IntentConflict, ...]
    validation_findings: tuple[PlanIssue, ...]
    deployment_blockers: tuple[str, ...]
    readiness: IntentReadiness
    intent_fingerprint: str
    verification: Literal["not-verified"] = "not-verified"
    deployment_status: Literal["blocked"] = "blocked"
    executable: Literal[False] = False
    cli: None = None
    device_writes_enabled: Literal[False] = False


def _json(value: object) -> JsonValue:
    return cast(JsonValue, value)


def _sha256_json(value: JsonValue) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _change_id(device_id: str, target_kind: ChangeTarget, target_id: str, field: str) -> str:
    digest = hashlib.sha256(
        f"{device_id}|{target_kind.value}|{target_id}|{field}".encode()
    ).hexdigest()
    return "chg-" + digest[:12]


def _dependency_id(kind: DependencyKind, target: str) -> str:
    digest = hashlib.sha256(f"{kind.value}|{target}".encode()).hexdigest()
    return "dep-" + digest[:12]


def _device_ports(plan: EventPlan, assignment_id: UUID) -> tuple[PhysicalInterface, ...]:
    return tuple(sorted(
        (port for port in plan.physical_interfaces if port.assignment_id == assignment_id),
        key=lambda port: (port.stack_member or 0, port.name, str(port.id)),
    ))


def _logical_interfaces(plan: EventPlan, assignment_id: UUID) -> Iterable[tuple[UUID, str]]:
    for logical in plan.logical_interfaces:
        if logical.assignment_id == assignment_id:
            yield logical.id, logical.name


def _device_port_channels(plan: EventPlan, assignment_id: UUID) -> tuple[PortChannel, ...]:
    logical_names = dict(_logical_interfaces(plan, assignment_id))
    channels = (
        channel for channel in plan.port_channels if channel.interface_id in logical_names
    )
    return tuple(sorted(channels, key=lambda channel: (channel.number, str(channel.interface_id))))


def _logical_name(plan: EventPlan, interface_id: UUID) -> str | None:
    return next(
        (logical.name for logical in plan.logical_interfaces if logical.id == interface_id),
        None,
    )


def _physical_device(plan: EventPlan, physical_device_id: UUID | None) -> PhysicalDevice | None:
    if physical_device_id is None:
        return None
    return next(
        (device for device in plan.physical_devices if device.id == physical_device_id), None,
    )


def _exact_pid(device: PhysicalDevice | None) -> str | None:
    return exact_pid(device)


def _stack_members(plan: EventPlan, assignment: EventDeviceAssignment) -> tuple[StackMember, ...]:
    stack: StackSnapshot | None = next(
        (item for item in plan.stacks if item.assignment_id == assignment.id), None,
    )
    if stack is None:
        return ()
    return tuple(sorted(stack.members, key=lambda member: member.number))


def _referenced_port_ids(plan: EventPlan) -> frozenset[UUID]:
    referenced: set[UUID] = set()
    for link in plan.links:
        referenced.update(link.endpoints)
    for channel in plan.port_channels:
        referenced.update(channel.member_ids)
    for isp in plan.isps:
        referenced.add(isp.interface_id)
    if plan.transit is not None:
        referenced.update((plan.transit.core_port_id, plan.transit.hillstone_port_id))
    return frozenset(referenced)


def _channel_for_members(plan: EventPlan, assignment_id: UUID) -> dict[UUID, PortChannel]:
    mapping: dict[UUID, PortChannel] = {}
    for channel in _device_port_channels(plan, assignment_id):
        for member_id in channel.member_ids:
            mapping[member_id] = channel
    return mapping


def _vlan_refs(
    plan: EventPlan, ports: Iterable[PhysicalInterface], channels: Iterable[PortChannel],
) -> tuple[int, ...]:
    refs: set[int] = set()
    for settings in [port.settings for port in ports]:
        if settings.access_vlan is not None:
            refs.add(settings.access_vlan)
        if settings.native_vlan is not None:
            refs.add(settings.native_vlan)
        refs.update(settings.allowed_vlans)
    for channel in channels:
        settings = channel.settings
        if settings.access_vlan is not None:
            refs.add(settings.access_vlan)
        if settings.native_vlan is not None:
            refs.add(settings.native_vlan)
        refs.update(settings.allowed_vlans)
    return tuple(sorted(refs))


def _vlan_intents(plan: EventPlan, vlan_ids: Iterable[int]) -> tuple[VlanIntent, ...]:
    names = {vlan.id: vlan.name for vlan in plan.vlans}
    intents: list[VlanIntent] = []
    for vlan_id in sorted(set(vlan_ids)):
        if vlan_id in names:
            intents.append(VlanIntent(vlan_id=vlan_id, name=names[vlan_id], source="event-plan"))
        elif vlan_id == plan.management_vlan:
            intents.append(VlanIntent(vlan_id=vlan_id, name=None, source="management-vlan"))
        else:
            intents.append(VlanIntent(vlan_id=vlan_id, name=None, source="event-plan"))
    return tuple(intents)


def _shutdown_intent(
    settings: PortSettings, unused: bool,
) -> Literal["shutdown", "no-shutdown", "platform-default"]:
    if settings.admin_state == "down":
        return "shutdown"
    if settings.admin_state == "up":
        return "no-shutdown"
    if unused:
        return "shutdown"
    return "platform-default"


def _shutdown_intent_source(
    settings: PortSettings, unused: bool,
) -> Literal["event-plan", "reviewed-default-policy"] | None:
    if settings.admin_state is not None:
        return "event-plan"
    if unused:
        return "reviewed-default-policy"
    return None


def _event_vlan_intents(plan: EventPlan) -> tuple[VlanIntent, ...]:
    """Event-wide VLAN declarations, including declared-but-not-yet-used VLANs."""
    intents = [
        VlanIntent(vlan_id=vlan.id, name=vlan.name, source="event-plan")
        for vlan in sorted(plan.vlans, key=lambda vlan: vlan.id)
    ]
    if plan.management_vlan not in {vlan.vlan_id for vlan in intents}:
        intents.append(VlanIntent(
            vlan_id=plan.management_vlan, name=None, source="management-vlan",
        ))
    return tuple(sorted(intents, key=lambda vlan: vlan.vlan_id))


def _channel_settings(settings: PortSettings) -> PortChannelSettingsIntent:
    return PortChannelSettingsIntent(
        mode=settings.mode,
        access_vlan=settings.access_vlan,
        native_vlan=settings.native_vlan,
        allowed_vlans=settings.allowed_vlans,
        routed_address=(
            str(settings.address) if settings.address is not None else None
        ),
        description=settings.description,
        admin_state=settings.admin_state,
        portfast=settings.portfast,
        bpdu_guard=settings.bpdu_guard,
    )


def _desired_device(
    plan: EventPlan, assignment: EventDeviceAssignment,
) -> DeviceDesiredState:
    ports = _device_ports(plan, assignment.id)
    channels = _device_port_channels(plan, assignment.id)
    member_channel = _channel_for_members(plan, assignment.id)
    referenced = _referenced_port_ids(plan)
    port_names = {port.id: port.name for port in plan.physical_interfaces}
    vlan_refs = _vlan_refs(plan, ports, channels)

    physical_ports = tuple(
        PhysicalPortIntent(
            interface_id=port.id,
            name=port.name,
            physical_device_id=port.physical_device_id,
            stack_member=port.stack_member,
            mode=port.settings.mode,
            switchport=port.settings.mode != "routed",
            access_vlan=port.settings.access_vlan,
            native_vlan=port.settings.native_vlan,
            allowed_vlans=port.settings.allowed_vlans,
            routed_address=(
                str(port.settings.address) if port.settings.address is not None else None
            ),
            description=port.settings.description,
            admin_state=port.settings.admin_state,
            shutdown_intent=_shutdown_intent(port.settings, port.id not in referenced),
            shutdown_intent_source=_shutdown_intent_source(
                port.settings, port.id not in referenced,
            ),
            speed=port.settings.speed,
            duplex=port.settings.duplex,
            poe_mode=port.settings.poe_mode,
            portfast=port.settings.portfast,
            bpdu_guard=port.settings.bpdu_guard,
            port_channel=(
                member_channel[port.id].number if port.id in member_channel else None
            ),
            unused=port.id not in referenced,
        )
        for port in ports
    )
    port_channels = tuple(
        PortChannelIntent(
            interface_id=channel.interface_id,
            name=_logical_name(plan, channel.interface_id),
            number=channel.number,
            member_ids=channel.member_ids,
            member_names=tuple(
                port_names.get(member_id, str(member_id)) for member_id in channel.member_ids
            ),
            lacp=channel.lacp,
            settings=_channel_settings(channel.settings),
        )
        for channel in channels
    )
    return DeviceDesiredState(
        vlans=_vlan_intents(plan, vlan_refs),
        spanning_tree=SpanningTreeIntent(
            mode=DEFAULT_SPANNING_TREE_MODE, source=REVIEWED_DEFAULT_POLICY,
        ),
        vtp=VtpIntent(mode=DEFAULT_VTP_MODE, source=REVIEWED_DEFAULT_POLICY),
        root_priority=RootPriorityIntent(
            priority=ROOT_PRIORITY_BY_ROLE[assignment.role],
            source=REVIEWED_DEFAULT_POLICY,
            policy="role-priority-v1",
        ),
        unused_port_policy=UnusedPortPolicy(
            shutdown=True,
            source=REVIEWED_DEFAULT_POLICY,
            scope="ports-not-referenced-by-links-port-channels-isps-or-transit",
            semantics="no-links-port-channels-isps-or-transit",
            requires_field_verification=True,
        ),
        physical_ports=physical_ports,
        port_channels=port_channels,
    )


def _identity(
    plan: EventPlan, assignment: EventDeviceAssignment,
) -> DeviceIdentity:
    asset = _physical_device(plan, assignment.physical_device_id)
    pid = _exact_pid(asset)
    members = _stack_members(plan, assignment)
    if not members:
        stack_identity: Literal["standalone", "resolved", "unresolved"] = "standalone"
    elif all(_exact_pid(_physical_device(plan, member.physical_device_id)) for member in members):
        stack_identity = "resolved"
    else:
        stack_identity = "unresolved"
    stack_intents = tuple(
        StackMemberIntent(
            number=member.number,
            physical_device_id=member.physical_device_id,
            pid=_exact_pid(_physical_device(plan, member.physical_device_id)),
            state=member.state,
        )
        for member in members
    )
    software = assignment.software
    return DeviceIdentity(
        assignment_id=assignment.id,
        hostname=assignment.hostname,
        role=assignment.role,
        family=assignment.family,
        physical_device_id=asset.id if asset is not None else None,
        pid=pid,
        pid_evidence=(
            "exact-verified-pid" if pid is not None
            else "model-only" if asset is not None and asset.model is not None
            else "missing"
        ),
        serial_verified=asset is not None and asset.verified_serial is not None,
        software_image=software.image if software is not None else None,
        software_license=software.license if software is not None else None,
        stack_identity=stack_identity,
        stack_members=stack_intents,
    )


def _evidence_summary(decision: CapabilityDecision) -> tuple[EvidenceSummary, ...]:
    evidence = decision.evidence
    return tuple(
        EvidenceSummary(
            url=row.url,
            section=row.section,
            version_scope=row.version_scope,
            licenses=row.licenses,
            conditions=row.conditions,
        )
        for row in evidence
    )


def _capability_check(
    revision: PlanRevision,
    assignment: EventDeviceAssignment,
    capability: CapabilityId,
    *,
    interface: PhysicalInterface | None,
    scope: Literal["device", "interface"],
    subject: str,
) -> CapabilityCheck:
    try:
        decision = resolve_capability(
            revision,
            assignment.id,
            capability,
            interface_id=interface.id if interface is not None else None,
            stack_member=interface.stack_member if interface is not None else None,
        )
    except TargetNotFound as error:
        return CapabilityCheck(
            scope=scope,
            subject=subject,
            capability=capability,
            verdict=Support.UNKNOWN,
            reason_code="target-binding-unknown",
            reason=str(error),
            evidence=(),
        )
    return CapabilityCheck(
        scope=scope,
        subject=subject,
        capability=capability,
        verdict=decision.verdict,
        reason_code=decision.reason_code,
        reason=decision.reason,
        evidence=_evidence_summary(decision),
    )


def _capability_checks(
    revision: PlanRevision,
    plan: EventPlan,
    assignment: EventDeviceAssignment,
    desired: DeviceDesiredState,
) -> tuple[CapabilityCheck, ...]:
    checks: list[CapabilityCheck] = []
    device_capabilities: list[CapabilityId] = list(DEVICE_CAPABILITIES)
    modes = {port.mode for port in desired.physical_ports}
    if "access" in modes:
        device_capabilities.append(CiscoCapability.ACCESS)
    if "trunk" in modes:
        device_capabilities.append(CiscoCapability.TRUNK)
    if "routed" in modes:
        device_capabilities.append(Capability.ROUTED_PORT)
    if desired.port_channels:
        device_capabilities.extend((Capability.LACP, CiscoCapability.PORT_CHANNEL))
    if any(port.portfast is not None for port in desired.physical_ports) or any(
        channel.settings.portfast is not None for channel in desired.port_channels
    ):
        device_capabilities.append(CiscoCapability.PORTFAST)
    if any(port.bpdu_guard is not None for port in desired.physical_ports) or any(
        channel.settings.bpdu_guard is not None for channel in desired.port_channels
    ):
        device_capabilities.append(CiscoCapability.BPDU_GUARD)
    if desired.vlans:
        device_capabilities.append(Capability.VLAN)
    if _stack_members(plan, assignment):
        device_capabilities.append(CiscoCapability.STACK)
    seen: set[CapabilityId] = set()
    for capability in device_capabilities:
        if capability in seen:
            continue
        seen.add(capability)
        checks.append(_capability_check(
            revision, assignment, capability, interface=None, scope="device",
            subject=assignment.hostname,
        ))
    for port in desired.physical_ports:
        physical = next(item for item in plan.physical_interfaces if item.id == port.interface_id)
        checks.append(_capability_check(
            revision, assignment, CiscoCapability.PORT_MEDIA, interface=physical,
            scope="interface", subject=port.name,
        ))
        for capability, present in (
            # Disabling PoE is a safe intent and does not require PoE hardware.
            (Capability.POE, port.poe_mode in {"auto", "static"}),
            (CiscoCapability.SPEED, port.speed is not None),
            (CiscoCapability.DUPLEX, port.duplex is not None),
        ):
            if present:
                checks.append(_capability_check(
                    revision, assignment, capability, interface=physical,
                    scope="interface", subject=port.name,
                ))
    return tuple(sorted(checks, key=lambda check: (
        check.scope, check.subject, str(check.capability.value),
    )))


def _documentation_verdict(checks: Iterable[CapabilityCheck]) -> DocumentationVerdict:
    verdicts = {check.verdict for check in checks}
    if Support.UNSUPPORTED in verdicts:
        return DocumentationVerdict.UNSUPPORTED
    if Support.UNKNOWN in verdicts:
        return DocumentationVerdict.UNKNOWN
    return DocumentationVerdict.SUPPORTED


def _readiness(
    checks: Iterable[CapabilityCheck], structured_valid: bool,
) -> IntentReadiness:
    return IntentReadiness(
        structured_intent_valid=structured_valid,
        vendor_documentation=_documentation_verdict(checks),
        hardware_verified=False,
        deployment_allowed=False,
    )


def _conflicts(
    plan: EventPlan,
    assignment: EventDeviceAssignment,
    desired: DeviceDesiredState,
) -> tuple[IntentConflict, ...]:
    conflicts: list[IntentConflict] = []
    ports = {port.interface_id: port for port in desired.physical_ports}
    valid_vlans = {vlan.id for vlan in plan.vlans}
    referenced_by_channels: dict[UUID, list[PortChannelIntent]] = {}
    for channel in desired.port_channels:
        for member_id in channel.member_ids:
            referenced_by_channels.setdefault(member_id, []).append(channel)
    for member_id, channels in referenced_by_channels.items():
        if len(channels) > 1:
            conflicts.append(IntentConflict(
                code="port-channel-member-conflict",
                message="A physical interface is a member of more than one Port-Channel",
                target=(
                    ports[member_id].name if member_id in ports else str(member_id)
                ),
                severity="ERROR",
            ))
        if member_id not in ports:
            conflicts.append(IntentConflict(
                code="port-channel-member-outside-plan",
                message="Port-Channel member is not a physical interface in this device",
                target=str(member_id),
                severity="ERROR",
            ))
    numbers = [channel.number for channel in desired.port_channels]
    for number in sorted({value for value in numbers if numbers.count(value) > 1}):
        conflicts.append(IntentConflict(
            code="duplicate-port-channel-number",
            message=f"Port-Channel number {number} is used more than once",
            target=str(number),
            severity="ERROR",
        ))
    for channel in desired.port_channels:
        if channel.name is None:
            conflicts.append(IntentConflict(
                code="port-channel-logical-interface-missing",
                message="Port-Channel record has no matching logical interface",
                target=str(channel.interface_id),
                severity="ERROR",
            ))
        if len(set(channel.member_ids)) != len(channel.member_ids):
            conflicts.append(IntentConflict(
                code="duplicate-port-channel-member",
                message="A physical interface is listed more than once in the same Port-Channel",
                target=channel.name or str(channel.interface_id),
                severity="ERROR",
            ))
    stack_members = {
        member.number: member for member in _stack_members(plan, assignment)
    }
    if len(stack_members) != len(_stack_members(plan, assignment)):
        for number in sorted({
            member.number for member in _stack_members(plan, assignment)
            if sum(
                other.number == member.number
                for other in _stack_members(plan, assignment)
            ) > 1
        }):
            conflicts.append(IntentConflict(
                code="duplicate-stack-member-number",
                message=f"Stack member number {number} is declared more than once",
                target=assignment.hostname,
                severity="ERROR",
            ))
    for port in desired.physical_ports:
        if port.stack_member is None:
            continue
        member = stack_members.get(port.stack_member)
        if not stack_members:
            conflicts.append(IntentConflict(
                code="stack-member-without-stack",
                message="A physical interface declares Stack membership but no Stack exists",
                target=port.name,
                severity="ERROR",
            ))
        elif member is None:
            conflicts.append(IntentConflict(
                code="stack-member-not-in-stack",
                message="A physical interface points at a Stack member that is not declared",
                target=port.name,
                severity="ERROR",
            ))
        elif port.physical_device_id != member.physical_device_id:
            conflicts.append(IntentConflict(
                code="stack-interface-ownership-mismatch",
                message=(
                    "A physical interface belongs to a different chassis than its "
                    "declared Stack member; field inventory must be corrected"
                ),
                target=port.name,
                severity="ERROR",
            ))
    for port in desired.physical_ports:
        settings = next(
            item.settings for item in plan.physical_interfaces if item.id == port.interface_id
        )
        if port.mode == "access" and (settings.native_vlan is not None or settings.allowed_vlans):
            conflicts.append(IntentConflict(
                code="access-vlan-conflict",
                message="An access port must not carry Native or Allowed VLAN intent",
                target=port.name,
                severity="ERROR",
            ))
        if port.mode == "trunk" and not settings.allowed_vlans:
            conflicts.append(IntentConflict(
                code="trunk-allowed-vlans-missing",
                message="A trunk port has no Allowed VLAN intent",
                target=port.name,
                severity="WARNING",
            ))
        if port.mode == "routed" and (
            settings.access_vlan is not None or settings.native_vlan is not None
            or bool(settings.allowed_vlans)
        ):
            conflicts.append(IntentConflict(
                code="routed-switchport-conflict",
                message="A routed port must not carry switchport VLAN intent",
                target=port.name,
                severity="ERROR",
            ))
        if port.mode == "routed" and (
            port.portfast is not None or port.bpdu_guard is not None
        ):
            conflicts.append(IntentConflict(
                code="routed-spanning-tree-conflict",
                message="Spanning-tree intent requires a Layer 2 switchport",
                target=port.name,
                severity="ERROR",
            ))
        if port.unused and settings.admin_state == "up":
            conflicts.append(IntentConflict(
                code="unused-port-explicitly-enabled",
                message=(
                    "An unused port is explicitly enabled; "
                    "review the unused-port shutdown policy"
                ),
                target=port.name,
                severity="WARNING",
            ))
        if port.unused and (
            settings.access_vlan is not None
            or settings.native_vlan is not None
            or bool(settings.allowed_vlans)
        ):
            conflicts.append(IntentConflict(
                code="unused-port-policy-inference",
                message=(
                    "The reviewed unused-port shutdown policy treats this port as "
                    "unused because it has no topology link, even though business "
                    "VLAN intent is present; field confirmation is required before "
                    "deployment."
                ),
                target=port.name,
                severity="WARNING",
            ))
        for vlan_id in (
            [settings.access_vlan, settings.native_vlan, *settings.allowed_vlans]
        ):
            if vlan_id is not None and vlan_id not in valid_vlans:
                conflicts.append(IntentConflict(
                    code="unknown-vlan-reference",
                    message=f"VLAN {vlan_id} is referenced but not defined in the plan",
                    target=port.name,
                    severity="ERROR",
                ))
    for channel in desired.port_channels:
        channel_settings = channel.settings
        channel_name = channel.name or str(channel.interface_id)
        if channel_settings.mode == "access" and (
            channel_settings.native_vlan is not None or channel_settings.allowed_vlans
        ):
            conflicts.append(IntentConflict(
                code="access-vlan-conflict",
                message="An access Port-Channel must not carry Native or Allowed VLAN intent",
                target=channel_name,
                severity="ERROR",
            ))
        if channel_settings.mode == "trunk" and not channel_settings.allowed_vlans:
            conflicts.append(IntentConflict(
                code="trunk-allowed-vlans-missing",
                message="A trunk Port-Channel has no Allowed VLAN intent",
                target=channel_name,
                severity="WARNING",
            ))
        if channel_settings.mode == "routed" and (
            channel_settings.access_vlan is not None
            or channel_settings.native_vlan is not None
            or bool(channel_settings.allowed_vlans)
        ):
            conflicts.append(IntentConflict(
                code="routed-switchport-conflict",
                message="A routed Port-Channel must not carry switchport VLAN intent",
                target=channel_name,
                severity="ERROR",
            ))
        for vlan_id in (
            [channel_settings.access_vlan, channel_settings.native_vlan,
             *channel_settings.allowed_vlans]
        ):
            if vlan_id is not None and vlan_id not in valid_vlans:
                conflicts.append(IntentConflict(
                    code="unknown-vlan-reference",
                    message=f"VLAN {vlan_id} is referenced but not defined in the plan",
                    target=channel_name,
                    severity="ERROR",
                ))
    return tuple(conflicts)


@dataclass(frozen=True, slots=True)
class _ChangeContext:
    device_id: str
    device_name: str
    before_source: BeforeSource
    baseline_revision_id: UUID | None
    baseline_revision_hash: str | None


def _interface_change(
    context: _ChangeContext,
    port: PhysicalPortIntent,
    field: str,
    before: JsonValue | None,
    after: JsonValue | None,
    *,
    transition: str | None = None,
    after_source: Literal["event-plan", "reviewed-default-policy"] = EVENT_PLAN_SOURCE,
    cleanup: tuple[str, ...] = (),
) -> PlannedChange:
    return PlannedChange(
        change_id=_change_id(
            context.device_id, ChangeTarget.INTERFACE, str(port.interface_id), field,
        ),
        target_kind=ChangeTarget.INTERFACE,
        target_id=str(port.interface_id),
        target_name=port.name,
        field=field,
        before=before,
        after=after,
        transition=transition,
        before_source=context.before_source,
        after_source=after_source,
        dependencies=(),
        cleanup=cleanup,
    )


def _channel_change(
    context: _ChangeContext,
    channel: PortChannelIntent,
    field: str,
    before: JsonValue | None,
    after: JsonValue | None,
    *,
    transition: str | None = None,
    cleanup: tuple[str, ...] = (),
) -> PlannedChange:
    return PlannedChange(
        change_id=_change_id(
            context.device_id, ChangeTarget.PORT_CHANNEL, str(channel.interface_id), field,
        ),
        target_kind=ChangeTarget.PORT_CHANNEL,
        target_id=str(channel.interface_id),
        target_name=channel.name or str(channel.interface_id),
        field=field,
        before=before,
        after=after,
        transition=transition,
        before_source=context.before_source,
        after_source=EVENT_PLAN_SOURCE,
        dependencies=(),
        cleanup=cleanup,
    )


def _device_change(
    context: _ChangeContext,
    field: str,
    before: JsonValue | None,
    after: JsonValue | None,
    *,
    transition: str | None = None,
    after_source: Literal["event-plan", "reviewed-default-policy"] = REVIEWED_DEFAULT_POLICY,
) -> PlannedChange:
    return PlannedChange(
        change_id=_change_id(context.device_id, ChangeTarget.DEVICE, context.device_id, field),
        target_kind=ChangeTarget.DEVICE,
        target_id=context.device_id,
        target_name=context.device_name,
        field=field,
        before=before,
        after=after,
        transition=transition,
        before_source=context.before_source,
        after_source=after_source,
        dependencies=(),
        cleanup=(),
    )


def _mode_transition(before: str, after: str) -> str:
    if before == "access" and after == "trunk":
        return "access-to-trunk"
    if before == "trunk" and after == "access":
        return "trunk-to-access"
    if before in {"access", "trunk"} and after == "routed":
        return "switchport-to-routed"
    if before == "routed" and after in {"access", "trunk"}:
        return "routed-to-switchport"
    return "mode-change"


def _mode_cleanup(before: str, after: str) -> tuple[str, ...]:
    if before == after:
        return ()
    cleanup: list[str] = []
    if before == "access":
        cleanup.append("access_vlan")
    if before == "trunk":
        cleanup.extend(("native_vlan", "allowed_vlans"))
    if before == "routed":
        cleanup.append("routed_address")
    if after == "routed":
        cleanup.extend(("access_vlan", "native_vlan", "allowed_vlans"))
    if after in {"access", "trunk"}:
        cleanup.append("routed_address")
    return tuple(dict.fromkeys(cleanup))


def _port_fields(port: PhysicalPortIntent) -> dict[str, JsonValue | None]:
    return {
        "name": port.name,
        "mode": port.mode,
        "physical_device_id": (
            str(port.physical_device_id) if port.physical_device_id is not None else None
        ),
        "switchport": port.switchport,
        "access_vlan": port.access_vlan,
        "native_vlan": port.native_vlan,
        "allowed_vlans": _json(list(port.allowed_vlans)),
        "routed_address": port.routed_address,
        "description": port.description,
        "admin_state": port.admin_state,
        "shutdown_intent": port.shutdown_intent,
        "speed": port.speed,
        "duplex": port.duplex,
        "poe_mode": port.poe_mode,
        "portfast": port.portfast,
        "bpdu_guard": port.bpdu_guard,
        "port_channel": port.port_channel,
        "stack_member": port.stack_member,
    }


def _physical_changes(
    context: _ChangeContext, port: PhysicalPortIntent, before: PhysicalPortIntent | None,
) -> list[PlannedChange]:
    if before is None:
        initial_changes = [_interface_change(
            context, port, "presence", None, _json("present"), transition="interface-added",
        )]
        for field, value in _port_fields(port).items():
            if value is None or value == "platform-default":
                continue
            if field in {"access_vlan", "native_vlan", "allowed_vlans"} and not value:
                continue
            initial_changes.append(_interface_change(
                context, port, field, None, value, transition="initial-plan",
                after_source=(
                    REVIEWED_DEFAULT_POLICY
                    if field == "shutdown_intent" else EVENT_PLAN_SOURCE
                ),
            ))
        return initial_changes
    changes: list[PlannedChange] = []
    for field, after_value in _port_fields(port).items():
        before_value = _port_value(before, field)
        if before_value == after_value:
            continue
        transition: str | None = None
        cleanup: tuple[str, ...] = ()
        if field == "mode":
            transition = _mode_transition(before.mode, port.mode)
            cleanup = _mode_cleanup(before.mode, port.mode)
        elif field == "port_channel":
            if before.port_channel is None and port.port_channel is not None:
                transition = "independent-to-port-channel-member"
            elif before.port_channel is not None and port.port_channel is None:
                transition = "port-channel-member-to-independent"
            else:
                transition = "port-channel-member-change"
        elif field == "shutdown_intent":
            transition = "shutdown-intent-change"
        elif field == "portfast":
            transition = "spanning-tree-edge-change"
        elif field == "bpdu_guard":
            transition = "bpdu-guard-change"
        elif field == "poe_mode":
            transition = "poe-mode-change"
        elif field == "speed":
            transition = "speed-change"
        elif field == "duplex":
            transition = "duplex-change"
        elif field == "physical_device_id":
            transition = "physical-device-change"
        elif field == "access_vlan":
            transition = "access-vlan-change"
        elif field == "native_vlan":
            transition = "native-vlan-change"
        elif field == "allowed_vlans":
            transition = "allowed-vlans-change"
        elif field == "routed_address":
            transition = "routed-boundary-change"
        elif field == "stack_member":
            transition = "stack-member-change"
        elif field == "name":
            transition = "interface-name-change"
        changes.append(_interface_change(
            context, port, field, before_value, after_value,
            transition=transition,
            after_source=(
                REVIEWED_DEFAULT_POLICY
                if field == "shutdown_intent" else EVENT_PLAN_SOURCE
            ),
            cleanup=cleanup,
        ))
    return changes

def _port_value(port: PhysicalPortIntent, field: str) -> JsonValue | None:
    if field == "allowed_vlans":
        return _json(list(port.allowed_vlans))
    if field == "physical_device_id":
        return _json(
            str(port.physical_device_id) if port.physical_device_id is not None else None
        )
    return _json(getattr(port, field))


def _channel_fields(channel: PortChannelIntent) -> dict[str, JsonValue | None]:
    return {
        "mode": channel.settings.mode,
        "access_vlan": channel.settings.access_vlan,
        "native_vlan": channel.settings.native_vlan,
        "allowed_vlans": _json(list(channel.settings.allowed_vlans)),
        "routed_address": channel.settings.routed_address,
        "description": channel.settings.description,
        "admin_state": channel.settings.admin_state,
        "portfast": channel.settings.portfast,
        "bpdu_guard": channel.settings.bpdu_guard,
    }


def _channel_field_value(channel: PortChannelIntent, field: str) -> JsonValue | None:
    if field == "allowed_vlans":
        return _json(list(channel.settings.allowed_vlans))
    return _json(getattr(channel.settings, field))


def _channel_changes(
    context: _ChangeContext, channel: PortChannelIntent, before: PortChannelIntent | None,
) -> list[PlannedChange]:
    changes: list[PlannedChange] = []
    if before is None:
        changes.append(_channel_change(
            context, channel, "presence", None, _json("present"), transition="initial-plan",
        ))
        for field in ("number", "lacp", "member_ids"):
            changes.append(_channel_change(
                context, channel, field, None, _channel_value(channel, field),
            ))
        for field, value in _channel_fields(channel).items():
            if value is None or value == "platform-default":
                continue
            if field == "allowed_vlans" and not value:
                continue
            changes.append(_channel_change(
                context, channel, field, None, value, transition="initial-plan",
            ))
        return changes
    for field in ("number", "lacp", "member_ids"):
        before_value = _channel_value(before, field)
        after_value = _channel_value(channel, field)
        if before_value == after_value:
            continue
        base_transition = None
        if field == "lacp":
            base_transition = f"lacp-{before.lacp}-to-{channel.lacp}"
        elif field == "member_ids":
            base_transition = "port-channel-members-change"
        changes.append(_channel_change(
            context, channel, field, before_value, after_value,
            transition=base_transition,
        ))
    for field, after_value in _channel_fields(channel).items():
        before_value = _channel_field_value(before, field)
        if before_value == after_value:
            continue
        transition: str | None = None
        cleanup: tuple[str, ...] = ()
        if field == "mode":
            transition = _mode_transition(before.settings.mode, channel.settings.mode)
            cleanup = _mode_cleanup(before.settings.mode, channel.settings.mode)
        elif field == "access_vlan":
            transition = "access-vlan-change"
        elif field == "native_vlan":
            transition = "native-vlan-change"
        elif field == "allowed_vlans":
            transition = "allowed-vlans-change"
        elif field == "routed_address":
            transition = "routed-boundary-change"
        elif field == "portfast":
            transition = "spanning-tree-edge-change"
        elif field == "bpdu_guard":
            transition = "bpdu-guard-change"
        elif field == "description":
            transition = "description-change"
        elif field == "admin_state":
            transition = "admin-state-change"
        changes.append(_channel_change(
            context, channel, field, before_value, after_value,
            transition=transition, cleanup=cleanup,
        ))
    return changes


def _channel_value(channel: PortChannelIntent, field: str) -> JsonValue | None:
    if field == "member_ids":
        return _json([str(member) for member in channel.member_ids])
    return _json(getattr(channel, field))


def _dependencies(
    changes: Iterable[PlannedChange],
    desired: DeviceDesiredState,
) -> tuple[IntentDependency, ...]:
    change_list = tuple(changes)
    required: dict[tuple[DependencyKind, str], set[str]] = {}
    for change in change_list:
        if change.transition is None:
            continue
        if change.transition in {
            "access-to-trunk", "trunk-to-access", "switchport-to-routed",
            "routed-to-switchport", "mode-change",
        } and change.cleanup:
            required.setdefault(
                (DependencyKind.MODE_CLEANUP, change.target_name), set(),
            ).add(change.change_id)
        if change.transition == "independent-to-port-channel-member":
            channel = next(
                (channel for channel in desired.port_channels
                 if channel.number == change.after),
                None,
            )
            target = channel.name if channel is not None and channel.name else "Port-Channel"
            required.setdefault(
                (DependencyKind.PORT_CHANNEL_INTERFACE, target), set(),
            ).add(change.change_id)
            required.setdefault(
                (DependencyKind.PORT_CHANNEL_MEMBERSHIP, target), set(),
            ).add(change.change_id)
        if change.transition == "port-channel-member-to-independent":
            required.setdefault(
                (DependencyKind.MEMBER_DETACH, change.target_name), set(),
            ).add(change.change_id)
        if change.transition == "port-channel-members-change":
            required.setdefault(
                (DependencyKind.PORT_CHANNEL_MEMBERSHIP, change.target_name), set(),
            ).add(change.change_id)
        if change.target_kind == ChangeTarget.PORT_CHANNEL and change.field == "lacp":
            required.setdefault(
                (DependencyKind.PORT_CHANNEL_MEMBERSHIP, change.target_name), set(),
            ).add(change.change_id)
        if change.field == "routed_address" or change.transition == "routed-boundary-change":
            required.setdefault(
                (DependencyKind.ROUTED_BOUNDARY, change.target_name), set(),
            ).add(change.change_id)
        if change.field == "physical_device_id":
            required.setdefault(
                (DependencyKind.PHYSICAL_DEVICE_BINDING, change.target_name), set(),
            ).add(change.change_id)
        if change.field == "physical-device-id":
            required.setdefault(
                (DependencyKind.PHYSICAL_DEVICE_BINDING, change.target_name), set(),
            ).add(change.change_id)
        if change.field == "stack-identity" or change.field.startswith("stack-member:"):
            required.setdefault(
                (DependencyKind.STACK_MEMBER_BINDING, change.target_name), set(),
            ).add(change.change_id)
        if change.field == "stack_member":
            required.setdefault(
                (DependencyKind.STACK_MEMBER_BINDING, change.target_name), set(),
            ).add(change.change_id)
        if (
            change.field == "shutdown_intent"
            and change.before_source is BeforeSource.PLANNING_BASELINE
            and change.after_source == REVIEWED_DEFAULT_POLICY
        ):
            required.setdefault(
                (DependencyKind.UNUSED_PORT_POLICY, change.target_name), set(),
            ).add(change.change_id)
    removals = [
        change for change in change_list
        if change.transition == "port-channel-removed"
    ]
    detaches = [
        change for change in change_list
        if change.transition == "port-channel-member-to-independent"
    ]
    for removal in removals:
        required.setdefault(
            (DependencyKind.PORT_CHANNEL_REMOVAL, removal.target_name), set(),
        ).add(removal.change_id)
        for detach in detaches:
            required[(DependencyKind.PORT_CHANNEL_REMOVAL, removal.target_name)].add(
                detach.change_id
            )
    dependencies = [
        IntentDependency(
            dependency_id=_dependency_id(kind, target),
            kind=kind,
            target=target,
            required_by=tuple(sorted(change_ids)),
        )
        for (kind, target), change_ids in sorted(
            required.items(), key=lambda item: (item[0][0].value, item[0][1]),
        )
    ]
    return tuple(dependencies)


def _device_changes(
    before: DeviceDesiredState | None,
    after: DeviceDesiredState,
    context: _ChangeContext,
) -> tuple[PlannedChange, ...]:
    changes: list[PlannedChange] = []
    if before is None:
        changes.append(_device_change(
            context, "vlans",
            None, _json([vlan.vlan_id for vlan in after.vlans]),
            transition="initial-plan", after_source=EVENT_PLAN_SOURCE,
        ))
        changes.extend((
            _device_change(context, "spanning-tree-mode", None, after.spanning_tree.mode),
            _device_change(context, "vtp-mode", None, after.vtp.mode),
            _device_change(context, "root-priority", None, after.root_priority.priority),
            _device_change(
                context, "unused-port-shutdown", None, after.unused_port_policy.shutdown,
            ),
        ))
        for port in after.physical_ports:
            changes.extend(_physical_changes(context, port, None))
        for channel in after.port_channels:
            changes.extend(_channel_changes(context, channel, None))
    else:
        before_vlans = [vlan.vlan_id for vlan in before.vlans]
        after_vlans = [vlan.vlan_id for vlan in after.vlans]
        if before_vlans != after_vlans:
            changes.append(_device_change(
                context, "vlans", _json(before_vlans), _json(after_vlans),
                transition="vlan-set-change", after_source=EVENT_PLAN_SOURCE,
            ))
        if before.spanning_tree.mode != after.spanning_tree.mode:
            changes.append(_device_change(
                context, "spanning-tree-mode",
                before.spanning_tree.mode, after.spanning_tree.mode,
            ))
        if before.vtp.mode != after.vtp.mode:
            changes.append(_device_change(
                context, "vtp-mode", before.vtp.mode, after.vtp.mode,
            ))
        if before.root_priority.priority != after.root_priority.priority:
            changes.append(_device_change(
                context, "root-priority",
                before.root_priority.priority, after.root_priority.priority,
            ))
        if before.unused_port_policy.shutdown != after.unused_port_policy.shutdown:
            changes.append(_device_change(
                context, "unused-port-shutdown",
                before.unused_port_policy.shutdown, after.unused_port_policy.shutdown,
            ))
        before_ports = {port.interface_id: port for port in before.physical_ports}
        before_channels = {channel.interface_id: channel for channel in before.port_channels}
        for port in after.physical_ports:
            changes.extend(_physical_changes(context, port, before_ports.get(port.interface_id)))
        for interface_id, port in before_ports.items():
            if interface_id not in {item.interface_id for item in after.physical_ports}:
                changes.append(_interface_change(
                    context, port, "presence", _json("present"), None,
                    transition="interface-removed", cleanup=("remove-interface-intent",),
                ))
        for channel in after.port_channels:
            changes.extend(_channel_changes(
                context, channel, before_channels.get(channel.interface_id),
            ))
        for interface_id, channel in before_channels.items():
            if interface_id not in {item.interface_id for item in after.port_channels}:
                changes.append(_channel_change(
                    context, channel, "presence", _json("present"), None,
                    transition="port-channel-removed",
                ))
    return tuple(changes)


def _flatten_devices(plan: EventPlan) -> tuple[EventDeviceAssignment, ...]:
    return tuple(sorted(plan.assignments, key=lambda assignment: (
        assignment.hostname, str(assignment.id),
    )))


def _baseline_info(baseline: PlanRevision | None) -> BaselineInfo:
    if baseline is None:
        return BaselineInfo(
            source="none", revision_id=None, revision_hash=None, device_state="unknown",
        )
    return BaselineInfo(
        source="previous-saved-revision",
        revision_id=baseline.id,
        revision_hash=baseline.content_hash,
        device_state="unknown",
    )




def _identity_changes(
    context: _ChangeContext,
    before: DeviceIdentity | None,
    after: DeviceIdentity,
) -> tuple[tuple[PlannedChange, ...], tuple[IntentConflict, ...]]:
    """Record planning chassis/Stack identity changes without claiming field state."""
    if before is None:
        return (), ()
    changes: list[PlannedChange] = []
    conflicts: list[IntentConflict] = []
    before_physical = (
        str(before.physical_device_id) if before.physical_device_id is not None else None
    )
    after_physical = (
        str(after.physical_device_id) if after.physical_device_id is not None else None
    )
    if before_physical != after_physical:
        changes.append(_device_change(
            context, "physical-device-id", _json(before_physical), _json(after_physical),
            transition="assignment-physical-device-change",
            after_source=EVENT_PLAN_SOURCE,
        ))
        conflicts.append(IntentConflict(
            code="device-identity-change-requires-field-verification",
            message=(
                "The planning assignment is bound to a different physical device in "
                "this revision; field confirmation is required and no hardware "
                "identity is assumed."
            ),
            target=after.hostname,
            severity="WARNING",
        ))
    if before.stack_identity != after.stack_identity:
        changes.append(_device_change(
            context, "stack-identity",
            _json(before.stack_identity), _json(after.stack_identity),
            transition="stack-identity-change", after_source=EVENT_PLAN_SOURCE,
        ))
    before_members = {member.number: member for member in before.stack_members}
    after_members = {member.number: member for member in after.stack_members}
    for number in sorted(set(before_members) | set(after_members)):
        previous = before_members.get(number)
        current = after_members.get(number)
        if previous is None and current is not None:
            changes.append(_device_change(
                context, f"stack-member:{number}:definition", None,
                _json({
                    "number": number,
                    "physical_device_id": str(current.physical_device_id),
                    "pid": current.pid,
                }),
                transition="stack-member-added", after_source=EVENT_PLAN_SOURCE,
            ))
        elif previous is not None and current is None:
            changes.append(_device_change(
                context, f"stack-member:{number}:definition",
                _json({
                    "number": number,
                    "physical_device_id": str(previous.physical_device_id),
                    "pid": previous.pid,
                }),
                None, transition="stack-member-removed", after_source=EVENT_PLAN_SOURCE,
            ))
        elif previous is not None and current is not None:
            if previous.physical_device_id != current.physical_device_id:
                changes.append(_device_change(
                    context, f"stack-member:{number}:physical-device-id",
                    _json(str(previous.physical_device_id)),
                    _json(str(current.physical_device_id)),
                    transition="stack-member-device-change",
                    after_source=EVENT_PLAN_SOURCE,
                ))
            if previous.pid != current.pid:
                changes.append(_device_change(
                    context, f"stack-member:{number}:pid",
                    _json(previous.pid), _json(current.pid),
                    transition="stack-member-pid-change",
                    after_source=EVENT_PLAN_SOURCE,
                ))
    if any(
        change.field == "stack-identity" or change.field.startswith("stack-member:")
        for change in changes
    ):
        conflicts.append(IntentConflict(
            code="stack-identity-change-requires-field-verification",
            message=(
                "The planning Stack member/chassis map changed; this is not proof "
                "that a real Stack replacement, merge, split or renumbering happened. "
                "Field verification and capability evidence collection are required."
            ),
            target=after.hostname,
            severity="WARNING",
        ))
    return tuple(changes), tuple(conflicts)


def _build_device_intent(
    revision: PlanRevision,
    plan: EventPlan,
    baseline_plan: EventPlan | None,
    assignment: EventDeviceAssignment,
    baseline_revision: PlanRevision | None,
    plan_valid: bool,
) -> DeviceLayer2Intent:
    desired = _desired_device(plan, assignment)
    baseline_assignment = None
    if baseline_plan is not None:
        baseline_assignment = next(
            (item for item in baseline_plan.assignments if item.id == assignment.id), None,
        )
    if baseline_plan is None:
        before_source = BeforeSource.PLANNING_BASELINE_UNAVAILABLE
        before_state = None
    elif baseline_assignment is None:
        before_source = BeforeSource.NOT_IN_BASELINE
        before_state = None
    else:
        before_source = BeforeSource.PLANNING_BASELINE
        before_state = _desired_device(baseline_plan, baseline_assignment)
    context = _ChangeContext(
        device_id=str(assignment.id),
        device_name=assignment.hostname,
        before_source=before_source,
        baseline_revision_id=baseline_revision.id if baseline_revision is not None else None,
        baseline_revision_hash=(
            baseline_revision.content_hash if baseline_revision is not None else None
        ),
    )
    before_identity = (
        _identity(baseline_plan, baseline_assignment)
        if baseline_plan is not None and baseline_assignment is not None
        else None
    )
    identity_changes, identity_conflicts = _identity_changes(
        context, before_identity, _identity(plan, assignment),
    )
    changes = (*_device_changes(before_state, desired, context), *identity_changes)
    dependencies = _dependencies(changes, desired)
    dependency_ids: dict[str, list[str]] = {}
    for dependency in dependencies:
        for change_id in dependency.required_by:
            dependency_ids.setdefault(change_id, []).append(dependency.dependency_id)
    changes = tuple(
        change.model_copy(update={
            "dependencies": tuple(dependency_ids.get(change.change_id, ())),
        })
        for change in changes
    )
    ownership_conflicts = [
        IntentConflict(
            code="interface-ownership-change-requires-field-verification",
            message=(
                "A physical interface is mapped to a different chassis in this "
                "revision; field inventory confirmation is required."
            ),
            target=change.target_name,
            severity="WARNING",
        )
        for change in changes
        if change.target_kind == ChangeTarget.INTERFACE
        and change.field == "physical_device_id"
    ]
    conflicts = (
        *_conflicts(plan, assignment, desired),
        *identity_conflicts,
        *ownership_conflicts,
    )
    checks = _capability_checks(revision, plan, assignment, desired)
    structured_valid = plan_valid and not any(
        conflict.severity == "ERROR" for conflict in conflicts
    )
    return DeviceLayer2Intent(
        identity=_identity(plan, assignment),
        desired=desired,
        before=PlannedBeforeState(
            source=before_source,
            baseline_revision_id=context.baseline_revision_id,
            baseline_revision_hash=context.baseline_revision_hash,
            device_state="unknown",
            state=before_state,
        ),
        changes=changes,
        dependencies=dependencies,
        conflicts=conflicts,
        capability_checks=checks,
        readiness=_readiness(checks, structured_valid),
    )




def _vlan_change(
    context: _ChangeContext,
    vlan_id: int,
    field: str,
    before: JsonValue | None,
    after: JsonValue | None,
    transition: str,
) -> PlannedChange:
    return PlannedChange(
        change_id=_change_id(
            context.device_id, ChangeTarget.VLAN, str(vlan_id), field,
        ),
        target_kind=ChangeTarget.VLAN,
        target_id=str(vlan_id),
        target_name=f"VLAN {vlan_id}",
        field=field,
        before=before,
        after=after,
        transition=transition,
        before_source=context.before_source,
        after_source=EVENT_PLAN_SOURCE,
        dependencies=(),
        cleanup=(),
    )


def _vlan_state(vlan: VlanIntent) -> JsonValue:
    return _json({
        "vlan_id": vlan.vlan_id,
        "name": vlan.name,
        "source": vlan.source,
    })


def _event_vlan_changes(
    before_vlans: tuple[VlanIntent, ...] | None,
    after_vlans: tuple[VlanIntent, ...],
    context: _ChangeContext,
) -> tuple[PlannedChange, ...]:
    changes: list[PlannedChange] = []
    if before_vlans is None:
        for vlan in after_vlans:
            changes.append(_vlan_change(
                context, vlan.vlan_id, "definition", None, _vlan_state(vlan),
                "initial-plan",
            ))
        return tuple(changes)
    before_map = {vlan.vlan_id: vlan for vlan in before_vlans}
    after_map = {vlan.vlan_id: vlan for vlan in after_vlans}
    for vlan_id in sorted(set(before_map) | set(after_map)):
        previous = before_map.get(vlan_id)
        current = after_map.get(vlan_id)
        if previous is None and current is not None:
            changes.append(_vlan_change(
                context, vlan_id, "definition", None, _vlan_state(current),
                "vlan-created",
            ))
        elif previous is not None and current is None:
            changes.append(_vlan_change(
                context, vlan_id, "definition", _vlan_state(previous), None,
                "vlan-removed",
            ))
        elif previous is not None and current is not None and (
            previous.name != current.name
        ):
            changes.append(_vlan_change(
                context, vlan_id, "name", _json(previous.name), _json(current.name),
                "vlan-renamed",
            ))
    return tuple(changes)


def _vlan_references(value: JsonValue | None) -> frozenset[int]:
    references: set[int] = set()
    if isinstance(value, int) and not isinstance(value, bool):
        references.add(value)
    if isinstance(value, list):
        references.update(
            item for item in value
            if isinstance(item, int) and not isinstance(item, bool)
        )
    return frozenset(references)


def _change_vlan_references(
    change: PlannedChange, *, before: bool = False,
) -> frozenset[int]:
    if change.field in {"access_vlan", "native_vlan"}:
        return _vlan_references(change.before if before else change.after)
    if change.field in {"allowed_vlans", "vlans"}:
        return _vlan_references(change.before if before else change.after)
    return frozenset()


def _vlan_dependencies(
    vlan_changes: Iterable[PlannedChange],
    device_changes: Iterable[PlannedChange],
) -> tuple[IntentDependency, ...]:
    required: dict[int, set[str]] = {}
    for change in vlan_changes:
        if change.transition in {"vlan-created", "vlan-renamed", "vlan-removed"}:
            required.setdefault(int(change.target_id), set()).add(change.change_id)
    if not required:
        return ()
    for change in device_changes:
        references = _change_vlan_references(change)
        previous_references = _change_vlan_references(change, before=True)
        for vlan_id in required.keys() & (references | previous_references):
            required[vlan_id].add(change.change_id)
    dependencies = [
        IntentDependency(
            dependency_id=_dependency_id(
                DependencyKind.VLAN_DEFINITION, f"vlan:{vlan_id}",
            ),
            kind=DependencyKind.VLAN_DEFINITION,
            target=f"vlan:{vlan_id}",
            required_by=tuple(sorted(change_ids)),
        )
        for vlan_id, change_ids in sorted(required.items())
    ]
    return tuple(dependencies)


def _cross_device_conflicts(plan: EventPlan) -> tuple[IntentConflict, ...]:
    conflicts: list[IntentConflict] = []
    assignment_by_channel: dict[UUID, UUID] = {}
    for logical in plan.logical_interfaces:
        assignment_by_channel[logical.id] = logical.assignment_id
    owners: dict[UUID, set[UUID]] = {}
    for channel in plan.port_channels:
        owner = assignment_by_channel.get(channel.interface_id)
        if owner is None:
            conflicts.append(IntentConflict(
                code="port-channel-logical-interface-missing",
                message="Port-Channel record has no matching logical interface",
                target=str(channel.interface_id),
                severity="ERROR",
            ))
            continue
        for member_id in channel.member_ids:
            port = next((item for item in plan.physical_interfaces if item.id == member_id), None)
            if port is None:
                conflicts.append(IntentConflict(
                    code="port-channel-member-outside-plan",
                    message="Port-Channel member is not a physical interface in this plan",
                    target=str(member_id),
                    severity="ERROR",
                ))
                continue
            owners.setdefault(member_id, set()).add(port.assignment_id)
            if port.assignment_id != owner:
                conflicts.append(IntentConflict(
                    code="port-channel-member-assignment-mismatch",
                    message="Port-Channel member belongs to a different assignment",
                    target=port.name,
                    severity="ERROR",
                ))
    for member_id, assignment_ids in owners.items():
        if len(assignment_ids) > 1:
            port = next(item for item in plan.physical_interfaces if item.id == member_id)
            conflicts.append(IntentConflict(
                code="port-channel-member-conflict",
                message="A physical interface is a member of more than one Port-Channel",
                target=port.name,
                severity="ERROR",
            ))
    return tuple(conflicts)


def _blockers(
    checks: Iterable[CapabilityCheck],
    conflicts: Iterable[IntentConflict],
    plan_valid: bool,
) -> tuple[str, ...]:
    blockers = list(INTENT_BASE_BLOCKERS)
    if not plan_valid:
        blockers.append("plan-invalid")
    if any(conflict.severity == "ERROR" for conflict in conflicts):
        blockers.append("structured-intent-invalid")
    conflict_codes = {conflict.code for conflict in conflicts}
    if (
        "device-identity-change-requires-field-verification" in conflict_codes
        or "interface-ownership-change-requires-field-verification" in conflict_codes
    ):
        blockers.append("field-verification-required:device-identity")
    if "stack-identity-change-requires-field-verification" in conflict_codes:
        blockers.append("field-verification-required:stack-identity")
    for check in checks:
        identifier = f"{check.capability.value}:{check.subject}"
        if check.verdict == Support.UNSUPPORTED:
            blockers.append(f"capability-unsupported:{identifier}")
        elif check.verdict == Support.UNKNOWN:
            blockers.append(f"capability-unknown:{identifier}")
    return tuple(dict.fromkeys(blockers))


def build_layer2_intent(
    revision: PlanRevision, baseline: PlanRevision | None = None,
) -> Layer2Intent:
    """Build deterministic diagnostic L2 intent for one saved revision."""
    plan = revision.plan
    baseline_info = _baseline_info(baseline)
    baseline_plan = baseline.plan if baseline is not None else None
    plan_valid = revision.validation_status != "INVALID"
    baseline_vlans = (
        _event_vlan_intents(baseline_plan) if baseline_plan is not None else None
    )
    event_vlans = _event_vlan_intents(plan)
    event_context = _ChangeContext(
        device_id="event-vlan-database",
        device_name="Event VLAN database",
        before_source=(
            BeforeSource.PLANNING_BASELINE if baseline_plan is not None
            else BeforeSource.PLANNING_BASELINE_UNAVAILABLE
        ),
        baseline_revision_id=baseline.id if baseline is not None else None,
        baseline_revision_hash=baseline.content_hash if baseline is not None else None,
    )
    vlan_changes = _event_vlan_changes(baseline_vlans, event_vlans, event_context)
    devices = tuple(
        _build_device_intent(
            revision, plan, baseline_plan, assignment, baseline, plan_valid,
        )
        for assignment in _flatten_devices(plan)
    )
    conflicts = (
        *_cross_device_conflicts(plan),
        *(conflict for device in devices for conflict in device.conflicts),
    )
    checks = tuple(check for device in devices for check in device.capability_checks)
    device_changes = tuple(change for device in devices for change in device.changes)
    vlan_dependencies = _vlan_dependencies(vlan_changes, device_changes)
    structured_valid = plan_valid and not any(
        conflict.severity == "ERROR" for conflict in conflicts
    )
    readiness = _readiness(checks, structured_valid)
    draft = Layer2Intent(
        event_id=plan.event_id,
        revision_id=revision.id,
        revision_hash=revision.content_hash,
        baseline=baseline_info,
        before_state_evidence=(
            PLANNING_BASELINE if baseline is not None else PLANNING_BASELINE_UNAVAILABLE
        ),
        vlans=event_vlans,
        vlan_changes=vlan_changes,
        vlan_dependencies=vlan_dependencies,
        devices=devices,
        conflicts=conflicts,
        validation_findings=(
            *revision.validation_errors,
            *revision.warnings,
        ),
        deployment_blockers=_blockers(checks, conflicts, plan_valid),
        readiness=readiness,
        intent_fingerprint="",
    )
    document = draft.model_dump(mode="json")
    document.pop("intent_fingerprint")
    fingerprint = _sha256_json(_json(document))
    return draft.model_copy(update={"intent_fingerprint": fingerprint})
