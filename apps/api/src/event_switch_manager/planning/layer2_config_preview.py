"""CIS-02B1 read-only Layer 2 configuration preview contract.

The preview is derived from one immutable CIS-02A Layer 2 intent document. It
renders structured, per-device configuration intent with explicit provenance,
planning-baseline values, planned differences, capability evidence and risk.

It is a review artifact only:

* no Cisco CLI command sequence is generated;
* no device is contacted and no running-config is claimed;
* ``executable`` is always ``False`` and ``cli`` is always ``None``;
* every configuration item is non-deployable and keeps its evidence gate;
* CIS-02A dependencies are association metadata, never an execution order.
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

from ..cisco_catalog import CapabilityId, CiscoCapability
from ..integrations import Capability
from .layer2_intent import (
    BaselineInfo,
    CapabilityCheck,
    DeviceDesiredState,
    DeviceIdentity,
    DeviceLayer2Intent,
    DocumentationVerdict,
    EvidenceSummary,
    IntentConflict,
    IntentDependency,
    IntentReadiness,
    Layer2Intent,
    PhysicalPortIntent,
    PlannedChange,
    PortChannelIntent,
    RemovedAssignment,
)
from .plan import PlanRevision
from .types import Record

PREVIEW_SCHEMA_VERSION: Literal[1] = 1
PREVIEW_CONTRACT_ID: Literal["cis-02b1-layer2-config-preview-v1"] = (
    "cis-02b1-layer2-config-preview-v1"
)
SUPPORTED_INTENT_SCHEMA_VERSION: Literal[1] = 1
DEPENDENCY_SEMANTICS: Literal["association-only-not-an-execution-order"] = (
    "association-only-not-an-execution-order"
)

#: Preview-level blockers that apply to every document and every item.
PREVIEW_BASE_BLOCKERS: tuple[str, ...] = (
    "preview-only-no-execution",
    "deployment-generation-disabled",
    "hardware-not-verified",
    "device-state-unknown",
    "intent-not-deployment-ready",
)

type PlannedValueSource = Literal[
    "event-plan",
    "management-vlan",
    "reviewed-default-policy",
    "platform-default",
    "not-in-plan",
]
type BaselineState = Literal[
    "planning-baseline", "planning-baseline-unavailable", "not-in-baseline",
]
type EvidenceGate = Literal[
    "pass", "unknown", "unsupported", "identity-incomplete", "intent-invalid",
]
type CapabilityVerdict = Literal["supported", "unsupported", "unknown", "not-required"]
type RiskLevel = Literal[
    "none", "field-verification", "unknown", "unsupported",
    "identity-incomplete", "intent-invalid",
]
type TargetKind = Literal["device", "vlan", "interface", "port-channel"]
type CheckScope = Literal["device", "interface"]


class PreviewInputError(ValueError):
    """The supplied CIS-02A intent does not bind to the supplied revision."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class PreviewTargetNotFound(LookupError):
    """The requested Assignment is not part of this intent revision."""


class PreviewCategory(StrEnum):
    VLAN = "vlan"
    STP = "stp"
    VTP = "vtp"
    ROOT_PRIORITY = "root-priority"
    ACCESS = "access"
    TRUNK = "trunk"
    ROUTED_BOUNDARY = "routed-boundary"
    PORT_CHANNEL = "port-channel"
    LACP = "lacp"
    PORTFAST = "portfast"
    BPDU_GUARD = "bpdu-guard"
    POE = "poe"
    SPEED = "speed"
    DUPLEX = "duplex"
    DESCRIPTION = "description"
    SHUTDOWN = "shutdown"
    UNUSED_PORT_POLICY = "unused-port-policy"


class PlannedValue(Record):
    value: JsonValue | None
    present: bool
    source: PlannedValueSource


class BaselineValue(Record):
    state: BaselineState
    value: JsonValue | None
    revision_id: UUID | None
    revision_hash: str | None


class DiffState(Record):
    changed: bool
    transition: str | None
    cleanup: tuple[str, ...]
    change_id: str | None
    before_source: BaselineState | None
    after_source: Literal["event-plan", "reviewed-default-policy", "platform-default"] | None


class CapabilityAssessment(Record):
    capability: CapabilityId | None
    verdict: CapabilityVerdict
    reason_code: str
    reason: str
    check_id: str | None
    evidence: tuple[EvidenceSummary, ...]


class PreviewRisk(Record):
    level: RiskLevel
    codes: tuple[str, ...]
    requires_field_verification: bool


class ItemDeployability(Record):
    deployable: Literal[False] = False
    evidence_gate: EvidenceGate
    blockers: tuple[str, ...]


class ConfigItem(Record):
    item_id: str
    category: PreviewCategory
    target_kind: TargetKind
    target_id: str
    target_name: str
    field: str
    planned: PlannedValue
    baseline: BaselineValue
    diff: DiffState
    capability: CapabilityAssessment
    risk: PreviewRisk
    deployability: ItemDeployability


class IdentityGate(Record):
    status: Literal["pass", "incomplete"]
    codes: tuple[str, ...]
    stack_identity: Literal["standalone", "resolved", "unresolved"]
    stack_member_count: int
    stack_ready_member_count: int


class CapabilityGate(Record):
    verdict: Literal["supported", "unknown", "unsupported"]
    unknown: tuple[str, ...]
    unsupported: tuple[str, ...]


class DeviceDeployability(Record):
    deployable: Literal[False] = False
    deployment_allowed: Literal[False] = False
    evidence_gate: EvidenceGate
    identity_gate: IdentityGate
    capability_gate: CapabilityGate
    intent_gate: Literal["valid", "invalid"]
    blockers: tuple[str, ...]


class PreviewSummary(Record):
    config_items: int
    changed_items: int
    deployable_items: int
    evidence_pass_items: int
    evidence_unknown_items: int
    evidence_unsupported_items: int
    evidence_identity_incomplete_items: int
    evidence_intent_invalid_items: int
    planned_changes: int
    dependencies: int


class HumanReadablePreview(Record):
    display_only: Literal[True] = True
    executable: Literal[False] = False
    headline: str
    statements: tuple[str, ...]


class DeviceConfigPreview(Record):
    preview_schema_version: Literal[1] = PREVIEW_SCHEMA_VERSION
    contract_id: Literal["cis-02b1-layer2-config-preview-v1"] = PREVIEW_CONTRACT_ID
    assignment_id: UUID
    hostname: str
    identity: DeviceIdentity
    intent_readiness: IntentReadiness
    deployability: DeviceDeployability
    config_items: tuple[ConfigItem, ...]
    planned_diff: tuple[PlannedChange, ...]
    dependencies: tuple[IntentDependency, ...]
    conflicts: tuple[IntentConflict, ...]
    capability_checks: tuple[CapabilityCheck, ...]
    summary: PreviewSummary
    human_readable: HumanReadablePreview
    preview_fingerprint: str


class PlanningScope(Record):
    planned_configuration: Literal["cis-02a-desired-state"] = "cis-02a-desired-state"
    planned_difference: Literal["planning-baseline-changeset"] = (
        "planning-baseline-changeset"
    )
    device_running_state: Literal["unknown-not-read"] = "unknown-not-read"


class PreviewReadiness(Record):
    preview_contract_valid: Literal[True] = True
    intent_contract_valid: Literal[True] = True
    structured_intent_valid: bool
    vendor_documentation: DocumentationVerdict
    hardware_verified: Literal[False] = False
    deployment_allowed: Literal[False] = False


class PreviewHeader(Record):
    preview_schema_version: Literal[1] = PREVIEW_SCHEMA_VERSION
    contract_id: Literal["cis-02b1-layer2-config-preview-v1"] = PREVIEW_CONTRACT_ID
    source: Literal["cis-02a-layer2-intent"] = "cis-02a-layer2-intent"
    event_id: UUID
    revision_id: UUID
    revision_number: int
    revision_hash: str
    intent_schema_version: Literal[1] = SUPPORTED_INTENT_SCHEMA_VERSION
    intent_fingerprint: str
    default_policy_id: Literal["cis-02a-reviewed-defaults-v1"] = (
        "cis-02a-reviewed-defaults-v1"
    )
    baseline: BaselineInfo
    device_state: Literal["unknown"] = "unknown"
    before_state_evidence: Literal["planning-baseline", "planning-baseline-unavailable"]
    running_config_read: Literal[False] = False
    observed_device_state: Literal["not-read"] = "not-read"
    dependency_semantics: Literal["association-only-not-an-execution-order"] = (
        DEPENDENCY_SEMANTICS
    )
    planning_scope: PlanningScope
    readiness: PreviewReadiness
    verification: Literal["not-verified"] = "not-verified"
    deployment_status: Literal["blocked"] = "blocked"
    executable: Literal[False] = False
    cli: None = None
    device_writes_enabled: Literal[False] = False


class VlanDefinitionReference(Record):
    vlan_id: int
    name: str | None
    source: Literal["event-plan", "management-vlan"]
    change_id: str | None
    transition: str | None


class VlanScopePreview(Record):
    scope: Literal["event-plan"] = "event-plan"
    semantics: Literal["event-wide-vlan-definitions-not-per-device-intent"] = (
        "event-wide-vlan-definitions-not-per-device-intent"
    )
    fingerprint: str
    definitions: tuple[VlanDefinitionReference, ...]
    changes: tuple[PlannedChange, ...]
    dependencies: tuple[IntentDependency, ...]


class Layer2ConfigPreview(PreviewHeader):
    vlan_scope: VlanScopePreview
    devices: tuple[DeviceConfigPreview, ...]
    removed_assignments: tuple[RemovedAssignment, ...]
    conflicts: tuple[IntentConflict, ...]
    deployment_blockers: tuple[str, ...]
    preview_fingerprint: str


class Layer2DeviceConfigPreview(PreviewHeader):
    vlan_scope: VlanScopePreview
    device: DeviceConfigPreview
    deployment_blockers: tuple[str, ...]
    preview_fingerprint: str


_RISK_RANK: Mapping[RiskLevel, int] = {
    "none": 0,
    "field-verification": 1,
    "unknown": 2,
    "unsupported": 3,
    "identity-incomplete": 4,
    "intent-invalid": 5,
}

_TARGET_RANK: Mapping[TargetKind, int] = {
    "device": 0,
    "vlan": 1,
    "port-channel": 2,
    "interface": 3,
}

_PORT_CATEGORY: Mapping[str, PreviewCategory] = {
    "access": PreviewCategory.ACCESS,
    "trunk": PreviewCategory.TRUNK,
    "routed": PreviewCategory.ROUTED_BOUNDARY,
}

_PORT_CAPABILITY: Mapping[str, CapabilityId] = {
    "access": CiscoCapability.ACCESS,
    "trunk": CiscoCapability.TRUNK,
    "routed": Capability.ROUTED_PORT,
}

_IDENTITY_REASON_CODES: Mapping[str, str] = {
    "identity-incomplete": "pid-missing",
    "license-unmatched": "license-unverified",
    "release-unmatched": "software-release-unverified",
    "software-is-rommon": "software-release-unverified",
    "software-missing": "software-image-missing",
    "pid-unlisted": "pid-unlisted",
    "family-mismatch": "family-mismatch",
    "target-binding-unknown": "target-binding-unknown",
    "stack-identities-unresolved": "stack-identity-unresolved",
    "stack-layout-unresolved": "stack-identity-unresolved",
    "stack-binding-unknown": "stack-identity-unresolved",
    "stack-evidence-missing": "stack-identity-unresolved",
}


def _sha256(value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _fingerprint(document: Record) -> str:
    value = document.model_dump(mode="json")
    value.pop("preview_fingerprint", None)
    return _sha256(value)


def intent_fingerprint(intent: Layer2Intent) -> str:
    """Recompute the CIS-02A fingerprint so a tampered intent fails closed."""
    document = intent.model_dump(mode="json")
    document.pop("intent_fingerprint")
    return _sha256(document)


def verify_intent_binding(revision: PlanRevision, intent: Layer2Intent) -> None:
    """Bind the intent to exactly one saved revision before previewing it."""
    if intent.intent_schema_version != SUPPORTED_INTENT_SCHEMA_VERSION:
        raise PreviewInputError("unsupported-intent-schema-version")
    if intent.event_id != revision.plan.event_id:
        raise PreviewInputError("intent-event-mismatch")
    if intent.revision_id != revision.id:
        raise PreviewInputError("intent-revision-mismatch")
    if intent.revision_hash != revision.content_hash:
        raise PreviewInputError("intent-revision-hash-mismatch")
    if intent.intent_fingerprint != intent_fingerprint(intent):
        raise PreviewInputError("intent-fingerprint-mismatch")


def _item_id(
    assignment_id: UUID, category: PreviewCategory, target_kind: TargetKind,
    target_id: str, field: str,
) -> str:
    digest = hashlib.sha256(
        f"{assignment_id}|{category.value}|{target_kind}|{target_id}|{field}".encode()
    ).hexdigest()
    return "cfg-" + digest[:12]


def _check_id(assignment_id: UUID, check: CapabilityCheck) -> str:
    digest = hashlib.sha256(
        f"{assignment_id}|{check.scope}|{check.subject}|{check.capability.value}".encode()
    ).hexdigest()
    return "cap-" + digest[:12]


@dataclass(frozen=True, slots=True)
class _Draft:
    category: PreviewCategory
    target_kind: TargetKind
    target_id: str
    target_name: str
    field: str
    value: JsonValue | None
    source: PlannedValueSource
    capability: CapabilityId | None
    scope: CheckScope
    requires_field_verification: bool = False
    risk_codes: tuple[str, ...] = ()
    not_required_reason: str | None = None


def _draft(
    category: PreviewCategory, target_kind: TargetKind, target_id: str, target_name: str,
    field: str, value: JsonValue | None, source: PlannedValueSource,
    capability: CapabilityId | None, scope: CheckScope, *,
    requires_field_verification: bool = False,
    risk_codes: tuple[str, ...] = (),
    not_required_reason: str | None = None,
) -> _Draft:
    return _Draft(
        category=category, target_kind=target_kind, target_id=target_id,
        target_name=target_name, field=field, value=value, source=source,
        capability=capability, scope=scope,
        requires_field_verification=requires_field_verification,
        risk_codes=risk_codes, not_required_reason=not_required_reason,
    )


def _port_drafts(port: PhysicalPortIntent) -> tuple[_Draft, ...]:
    target_id = str(port.interface_id)
    drafts: list[_Draft] = [
        _draft(
            _PORT_CATEGORY[port.mode], "interface", target_id, port.name, "mode",
            port.mode, "event-plan", _PORT_CAPABILITY[port.mode], "device",
        ),
        _draft(
            PreviewCategory.SHUTDOWN, "interface", target_id, port.name,
            "shutdown_intent",
            {
                "intent": port.shutdown_intent,
                "source": port.shutdown_intent_source,
                "admin_state": port.admin_state,
            },
            port.shutdown_intent_source or "platform-default",
            CiscoCapability.PORT_MEDIA, "interface",
            requires_field_verification=(
                port.shutdown_intent_source == "reviewed-default-policy"
            ),
            risk_codes=(
                ("reviewed-unused-port-shutdown",)
                if port.shutdown_intent_source == "reviewed-default-policy" else ()
            ),
        ),
    ]
    optional: tuple[tuple[PreviewCategory, str, JsonValue | None, CapabilityId | None,
                          CheckScope, str | None], ...] = (
        (PreviewCategory.ACCESS, "access_vlan", port.access_vlan,
         CiscoCapability.ACCESS, "device", None),
        (PreviewCategory.TRUNK, "native_vlan", port.native_vlan,
         CiscoCapability.TRUNK, "device", None),
        (PreviewCategory.TRUNK, "allowed_vlans",
         [vlan for vlan in port.allowed_vlans] or None,
         CiscoCapability.TRUNK, "device", None),
        (PreviewCategory.ROUTED_BOUNDARY, "routed_address", port.routed_address,
         Capability.ROUTED_PORT, "device", None),
        (PreviewCategory.DESCRIPTION, "description", port.description,
         CiscoCapability.PORT_MEDIA, "interface", None),
        (PreviewCategory.SHUTDOWN, "admin_state", port.admin_state,
         CiscoCapability.PORT_MEDIA, "interface", None),
        (PreviewCategory.SPEED, "speed", port.speed, CiscoCapability.SPEED,
         "interface", None),
        (PreviewCategory.DUPLEX, "duplex", port.duplex, CiscoCapability.DUPLEX,
         "interface", None),
        (PreviewCategory.POE, "poe_mode", port.poe_mode,
         Capability.POE if port.poe_mode in {"auto", "static"} else None,
         "interface", "poe-disable-requires-no-poe-hardware"),
        (PreviewCategory.PORTFAST, "portfast", port.portfast,
         CiscoCapability.PORTFAST, "device", None),
        (PreviewCategory.BPDU_GUARD, "bpdu_guard", port.bpdu_guard,
         CiscoCapability.BPDU_GUARD, "device", None),
        (PreviewCategory.PORT_CHANNEL, "port_channel", port.port_channel,
         CiscoCapability.PORT_CHANNEL, "device", None),
    )
    for category, field, value, capability, scope, not_required in optional:
        if value is None:
            continue
        drafts.append(_draft(
            category, "interface", target_id, port.name, field, cast(JsonValue, value),
            "event-plan", capability, scope, not_required_reason=not_required,
        ))
    return tuple(drafts)


def _channel_drafts(channel: PortChannelIntent) -> tuple[_Draft, ...]:
    target_id = str(channel.interface_id)
    name = channel.name or f"Port-Channel {channel.number}"
    lacp_capability = (
        Capability.LACP if channel.lacp in {"active", "passive"} else None
    )
    drafts: list[_Draft] = [
        _draft(
            PreviewCategory.PORT_CHANNEL, "port-channel", target_id, name, "number",
            channel.number, "event-plan", CiscoCapability.PORT_CHANNEL, "device",
        ),
        _draft(
            PreviewCategory.LACP, "port-channel", target_id, name, "lacp",
            channel.lacp, "event-plan", lacp_capability, "device",
            not_required_reason="static-channel-requires-no-lacp-evidence",
        ),
        _draft(
            PreviewCategory.PORT_CHANNEL, "port-channel", target_id, name,
            "member_ids",
            {
                "member_ids": [str(member) for member in channel.member_ids],
                "member_names": list(channel.member_names),
            },
            "event-plan", CiscoCapability.PORT_CHANNEL, "device",
        ),
        _draft(
            _PORT_CATEGORY[channel.settings.mode], "port-channel", target_id, name,
            "mode", channel.settings.mode, "event-plan",
            _PORT_CAPABILITY[channel.settings.mode], "device",
        ),
    ]
    optional: tuple[tuple[PreviewCategory, str, JsonValue | None, CapabilityId, CheckScope],
                    ...] = (
        (PreviewCategory.ACCESS, "access_vlan", channel.settings.access_vlan,
         CiscoCapability.ACCESS, "device"),
        (PreviewCategory.TRUNK, "native_vlan", channel.settings.native_vlan,
         CiscoCapability.TRUNK, "device"),
        (PreviewCategory.TRUNK, "allowed_vlans",
         [vlan for vlan in channel.settings.allowed_vlans] or None,
         CiscoCapability.TRUNK, "device"),
        (PreviewCategory.ROUTED_BOUNDARY, "routed_address",
         channel.settings.routed_address, Capability.ROUTED_PORT, "device"),
        (PreviewCategory.DESCRIPTION, "description", channel.settings.description,
         CiscoCapability.PORT_CHANNEL, "device"),
        (PreviewCategory.SHUTDOWN, "admin_state", channel.settings.admin_state,
         CiscoCapability.PORT_CHANNEL, "device"),
        (PreviewCategory.PORTFAST, "portfast", channel.settings.portfast,
         CiscoCapability.PORTFAST, "device"),
        (PreviewCategory.BPDU_GUARD, "bpdu_guard", channel.settings.bpdu_guard,
         CiscoCapability.BPDU_GUARD, "device"),
    )
    for category, field, value, capability, scope in optional:
        if value is None:
            continue
        drafts.append(_draft(
            category, "port-channel", target_id, name, field, cast(JsonValue, value),
            "event-plan", capability, scope,
        ))
    return tuple(drafts)


def _state_drafts(
    desired: DeviceDesiredState, assignment_id: UUID, hostname: str,
) -> tuple[_Draft, ...]:
    device_id = str(assignment_id)
    drafts: list[_Draft] = [
        _draft(
            PreviewCategory.STP, "device", device_id, hostname, "spanning-tree-mode",
            desired.spanning_tree.mode, "reviewed-default-policy",
            Capability.RAPID_PVST, "device",
        ),
        _draft(
            PreviewCategory.VTP, "device", device_id, hostname, "vtp-mode",
            desired.vtp.mode, "reviewed-default-policy",
            CiscoCapability.VTP_TRANSPARENT, "device",
        ),
        _draft(
            PreviewCategory.ROOT_PRIORITY, "device", device_id, hostname,
            "root-priority",
            {
                "priority": desired.root_priority.priority,
                "policy": desired.root_priority.policy,
            },
            "reviewed-default-policy", Capability.RAPID_PVST, "device",
        ),
        _draft(
            PreviewCategory.UNUSED_PORT_POLICY, "device", device_id, hostname,
            "unused-port-shutdown",
            {
                "shutdown": desired.unused_port_policy.shutdown,
                "semantics": desired.unused_port_policy.semantics,
                "scope": desired.unused_port_policy.scope,
                "requires_field_verification": (
                    desired.unused_port_policy.requires_field_verification
                ),
            },
            "reviewed-default-policy", CiscoCapability.PORT_LAYOUT, "device",
            requires_field_verification=True,
            risk_codes=("unused-port-policy-requires-field-verification",),
        ),
    ]
    for vlan in desired.vlans:
        drafts.append(_draft(
            PreviewCategory.VLAN, "vlan", str(vlan.vlan_id),
            vlan.name or f"VLAN {vlan.vlan_id}", "definition",
            {"vlan_id": vlan.vlan_id, "name": vlan.name},
            vlan.source, Capability.VLAN, "device",
        ))
    for channel in desired.port_channels:
        drafts.extend(_channel_drafts(channel))
    for port in desired.physical_ports:
        drafts.extend(_port_drafts(port))
    return tuple(drafts)


@dataclass(frozen=True, slots=True)
class _DeviceContext:
    device: DeviceLayer2Intent
    checks: Mapping[tuple[CheckScope, str, str], CapabilityCheck]
    changes: Mapping[tuple[TargetKind, str, str], PlannedChange]
    identity_gate: IdentityGate
    capability_gate: CapabilityGate
    structured_valid: bool


def _draft_key(draft: _Draft) -> tuple[TargetKind, str, str]:
    return (draft.target_kind, draft.target_id, draft.field)


def _check_index(device: DeviceLayer2Intent) -> Mapping[tuple[CheckScope, str, str],
                                                        CapabilityCheck]:
    return {
        (check.scope, check.subject, check.capability.value): check
        for check in device.capability_checks
    }


def _change_index(
    device: DeviceLayer2Intent, vlan_changes: tuple[PlannedChange, ...],
) -> Mapping[tuple[TargetKind, str, str], PlannedChange]:
    index: dict[tuple[TargetKind, str, str], PlannedChange] = {}
    for change in (*vlan_changes, *device.changes):
        index[(
            change.target_kind.value, change.target_id, change.field,
        )] = change
    return index


def _identity_gate(device: DeviceLayer2Intent) -> IdentityGate:
    identity = device.identity
    codes: list[str] = []
    if identity.pid_evidence == "missing":
        codes.append("pid-missing")
    elif identity.pid_evidence == "model-only":
        codes.append("pid-not-verified")
    if identity.software_image is None:
        codes.append("software-image-missing")
    if identity.stack_identity == "unresolved":
        codes.append("stack-identity-unresolved")
    numbers = [member.number for member in identity.stack_members]
    if len(set(numbers)) != len(numbers):
        codes.append("stack-member-number-duplicate")
    chassis = [member.physical_device_id for member in identity.stack_members]
    if len(set(chassis)) != len(chassis):
        codes.append("stack-member-chassis-duplicate")
    for member in identity.stack_members:
        if member.pid is None:
            codes.append(f"stack-member-pid-missing:{member.number}")
        if member.state != "ready":
            codes.append(f"stack-member-not-ready:{member.number}:{member.state}")
    for check in device.capability_checks:
        code = _IDENTITY_REASON_CODES.get(check.reason_code)
        if code is not None:
            codes.append(code)
    if not identity.serial_verified:
        codes.append("serial-not-verified")
    deduplicated = tuple(dict.fromkeys(codes))
    return IdentityGate(
        status="incomplete" if deduplicated else "pass",
        codes=deduplicated,
        stack_identity=identity.stack_identity,
        stack_member_count=len(identity.stack_members),
        stack_ready_member_count=sum(
            1 for member in identity.stack_members if member.state == "ready"
        ),
    )


def _capability_gate(device: DeviceLayer2Intent) -> CapabilityGate:
    unknown: list[str] = []
    unsupported: list[str] = []
    for check in device.capability_checks:
        identifier = f"{check.capability.value}:{check.subject}"
        if check.verdict == "unknown":
            unknown.append(identifier)
        elif check.verdict == "unsupported":
            unsupported.append(identifier)
    verdict: Literal["supported", "unknown", "unsupported"] = (
        "unsupported" if unsupported else "unknown" if unknown else "supported"
    )
    return CapabilityGate(
        verdict=verdict, unknown=tuple(dict.fromkeys(unknown)),
        unsupported=tuple(dict.fromkeys(unsupported)),
    )


def _gate_precedence(
    *, structured_valid: bool, identity: IdentityGate, capability: CapabilityGate,
) -> EvidenceGate:
    if not structured_valid:
        return "intent-invalid"
    if identity.status != "pass":
        return "identity-incomplete"
    if capability.verdict == "unsupported":
        return "unsupported"
    if capability.verdict == "unknown":
        return "unknown"
    return "pass"


def _assess_capability(
    context: _DeviceContext, planned: _Draft | None,
) -> CapabilityAssessment:
    if planned is None:
        return CapabilityAssessment(
            capability=None,
            verdict="not-required",
            reason_code="capability-not-required",
            reason=(
                "The current revision expresses no intent for this field, so no "
                "capability requirement applies."
            ),
            check_id=None,
            evidence=(),
        )
    if planned.capability is None:
        return CapabilityAssessment(
            capability=None,
            verdict="not-required",
            reason_code="capability-not-required",
            reason=planned.not_required_reason
            or "This intent deliberately requires no capability evidence.",
            check_id=None,
            evidence=(),
        )
    check_subject = (
        planned.target_name if planned.scope == "interface"
        else context.device.identity.hostname
    )
    check = context.checks.get(
        (planned.scope, check_subject, planned.capability.value)
    )
    if check is None:
        return CapabilityAssessment(
            capability=planned.capability,
            verdict="unknown",
            reason_code="preview-capability-check-missing",
            reason=(
                "CIS-02A reported no capability check for this planned intent; the "
                "preview fails closed instead of assuming documentation support."
            ),
            check_id=None,
            evidence=(),
        )
    return CapabilityAssessment(
        capability=planned.capability,
        verdict=check.verdict.value,
        reason_code=check.reason_code,
        reason=check.reason,
        check_id=_check_id(context.device.identity.assignment_id, check),
        evidence=check.evidence,
    )


def _raised(current: RiskLevel, candidate: RiskLevel) -> RiskLevel:
    return candidate if _RISK_RANK[candidate] > _RISK_RANK[current] else current


def _matching_conflicts(
    conflicts: Iterable[IntentConflict], draft: _Draft,
) -> tuple[IntentConflict, ...]:
    return tuple(
        conflict for conflict in conflicts
        if conflict.target in {draft.target_name, draft.target_id}
    )


def _risk(
    context: _DeviceContext,
    planned: _Draft | None,
    baseline: _Draft | None,
    capability: CapabilityAssessment,
    change: PlannedChange | None,
    conflicts: tuple[IntentConflict, ...],
) -> PreviewRisk:
    level: RiskLevel = "none"
    codes: list[str] = ["execution-not-generated"]
    requires_field_verification = False
    if planned is not None:
        code_prefix = "planned"
        if planned.requires_field_verification:
            requires_field_verification = True
            level = _raised(level, "field-verification")
            codes.append(f"{code_prefix}-field-verification")
        codes.extend(planned.risk_codes)
    if change is not None:
        codes.append("planned-difference")
        if change.transition is not None:
            codes.append(f"transition:{change.transition}")
        if change.cleanup:
            codes.append("planned-cleanup")
    if baseline is not None and planned is None:
        codes.append("no-current-plan-intent")
    if capability.verdict == "unknown":
        level = _raised(level, "unknown")
        codes.append(f"capability-unknown:{capability.reason_code}")
    elif capability.verdict == "unsupported":
        level = _raised(level, "unsupported")
        codes.append(f"capability-unsupported:{capability.reason_code}")
    for conflict in conflicts:
        codes.append(f"intent-conflict:{conflict.code}")
        if "requires-field-verification" in conflict.code:
            requires_field_verification = True
            level = _raised(level, "field-verification")
        if conflict.severity == "ERROR":
            level = _raised(level, "intent-invalid")
    if context.identity_gate.status != "pass":
        level = _raised(level, "identity-incomplete")
        codes.extend(
            f"identity-incomplete:{code}" for code in context.identity_gate.codes
        )
    if not context.structured_valid:
        level = _raised(level, "intent-invalid")
        codes.append("structured-intent-invalid")
    if requires_field_verification:
        codes.append("requires-field-verification")
    return PreviewRisk(
        level=level,
        codes=tuple(dict.fromkeys(codes)),
        requires_field_verification=requires_field_verification,
    )


def _item_blockers(
    planned: _Draft | None,
    capability: CapabilityAssessment,
    risk: PreviewRisk,
    gate: EvidenceGate,
) -> tuple[str, ...]:
    blockers: list[str] = []
    if planned is None:
        blockers.append("no-planned-intent")
    if capability.verdict in {"unknown", "unsupported"} and planned is not None:
        capability_id = (
            planned.capability.value if planned.capability is not None else "unknown"
        )
        blockers.append(
            f"capability-{capability.verdict}:{capability_id}:{planned.target_name}"
        )
    if gate == "identity-incomplete":
        blockers.extend(
            f"identity-incomplete:{code}" for code in risk.codes
            if code.startswith("identity-incomplete:")
        )
    if gate == "intent-invalid":
        blockers.append("structured-intent-invalid")
    if risk.requires_field_verification:
        blockers.append("field-verification-required")
    return tuple(dict.fromkeys(blockers))


def _gate_from_risk(risk: PreviewRisk) -> EvidenceGate:
    match risk.level:
        case "intent-invalid":
            return "intent-invalid"
        case "identity-incomplete":
            return "identity-incomplete"
        case "unsupported":
            return "unsupported"
        case "unknown":
            return "unknown"
        case _:
            return "pass"


def _baseline_value(
    context: _DeviceContext, baseline: _Draft | None,
) -> BaselineValue:
    before = context.device.before
    revision_id = before.baseline_revision_id
    revision_hash = before.baseline_revision_hash
    if before.state is None:
        state: BaselineState = (
            "planning-baseline-unavailable"
            if before.source.value == "planning-baseline-unavailable"
            else "not-in-baseline"
        )
        return BaselineValue(
            state=state, value=None, revision_id=revision_id,
            revision_hash=revision_hash,
        )
    if baseline is None:
        return BaselineValue(
            state="not-in-baseline", value=None, revision_id=None,
            revision_hash=None,
        )
    return BaselineValue(
        state="planning-baseline", value=baseline.value,
        revision_id=revision_id, revision_hash=revision_hash,
    )


def _matching_change(
    context: _DeviceContext, draft: _Draft,
) -> PlannedChange | None:
    change = context.changes.get(_draft_key(draft))
    if change is None and draft.target_kind == "vlan":
        # CIS-02A records a rename under the ``name`` field of the same VLAN.
        change = context.changes.get((draft.target_kind, draft.target_id, "name"))
    return change


def _config_item(
    context: _DeviceContext,
    planned: _Draft | None,
    baseline: _Draft | None,
) -> ConfigItem:
    draft = planned if planned is not None else baseline
    assert draft is not None
    capability = _assess_capability(context, planned)
    change = _matching_change(context, draft)
    conflicts = _matching_conflicts(context.device.conflicts, draft)
    risk = _risk(context, planned, baseline, capability, change, conflicts)
    gate = _gate_from_risk(risk)
    # A VLAN can stop being referenced without any event-level definition change;
    # the CIS-02A device VLAN-set change still records the planning difference.
    changed_without_change_row = (
        change is None and planned is None and baseline is not None
        and draft.target_kind == "vlan"
    )
    return ConfigItem(
        item_id=_item_id(
            context.device.identity.assignment_id, draft.category,
            draft.target_kind, draft.target_id, draft.field,
        ),
        category=draft.category,
        target_kind=draft.target_kind,
        target_id=draft.target_id,
        target_name=draft.target_name,
        field=draft.field,
        planned=PlannedValue(
            value=planned.value if planned is not None else None,
            present=planned is not None,
            source=planned.source if planned is not None else "not-in-plan",
        ),
        baseline=_baseline_value(context, baseline),
        diff=DiffState(
            changed=change is not None or changed_without_change_row,
            transition=change.transition if change is not None else (
                "vlan-unreferenced" if changed_without_change_row else None
            ),
            cleanup=change.cleanup if change is not None else (),
            change_id=change.change_id if change is not None else None,
            before_source=(
                cast(BaselineState, change.before_source.value)
                if change is not None else None
            ),
            after_source=change.after_source if change is not None else None,
        ),
        capability=capability,
        risk=risk,
        deployability=ItemDeployability(
            evidence_gate=gate,
            blockers=_item_blockers(planned, capability, risk, gate),
        ),
    )


def _sorted_keys(
    planned: Mapping[tuple[TargetKind, str, str], _Draft],
    baseline: Mapping[tuple[TargetKind, str, str], _Draft],
) -> tuple[tuple[TargetKind, str, str], ...]:
    def name(key: tuple[TargetKind, str, str]) -> str:
        draft = planned.get(key) or baseline[key]
        return draft.target_name

    return tuple(sorted(
        set(planned) | set(baseline),
        key=lambda key: (_TARGET_RANK[key[0]], name(key), key[2], key[1]),
    ))


def _config_items(context: _DeviceContext) -> tuple[ConfigItem, ...]:
    assignment_id = context.device.identity.assignment_id
    hostname = context.device.identity.hostname
    planned = {
        _draft_key(draft): draft
        for draft in _state_drafts(context.device.desired, assignment_id, hostname)
    }
    before = context.device.before.state
    baseline = (
        {
            _draft_key(draft): draft
            for draft in _state_drafts(before, assignment_id, hostname)
        }
        if before is not None else {}
    )
    return tuple(
        _config_item(context, planned.get(key), baseline.get(key))
        for key in _sorted_keys(planned, baseline)
    )


def _summary(
    items: tuple[ConfigItem, ...], device: DeviceLayer2Intent,
) -> PreviewSummary:
    gates = [item.deployability.evidence_gate for item in items]
    return PreviewSummary(
        config_items=len(items),
        changed_items=sum(1 for item in items if item.diff.changed),
        deployable_items=sum(1 for item in items if item.deployability.deployable),
        evidence_pass_items=gates.count("pass"),
        evidence_unknown_items=gates.count("unknown"),
        evidence_unsupported_items=gates.count("unsupported"),
        evidence_identity_incomplete_items=gates.count("identity-incomplete"),
        evidence_intent_invalid_items=gates.count("intent-invalid"),
        planned_changes=len(device.changes),
        dependencies=len(device.dependencies),
    )


def _human_readable(
    device: DeviceLayer2Intent,
    items: tuple[ConfigItem, ...],
    summary: PreviewSummary,
    gate: EvidenceGate,
) -> HumanReadablePreview:
    identity = device.identity
    pitch = (
        f"Review-only Layer 2 configuration preview for {identity.hostname}: "
        f"{identity.pid or 'Cisco PID not verified'}, "
        f"image {identity.software_image or 'not supplied'}, "
        f"license {identity.software_license or 'not supplied'}, "
        f"Stack identity {identity.stack_identity}."
    )
    statements = [
        pitch,
        "This preview generates no Cisco command sequence, contacts no device and "
        "claims no running-config; every intent is review information only.",
        (
            "Planned reviewed defaults: Rapid PVST+ spanning tree, VTP transparent, "
            f"root priority {device.desired.root_priority.priority} from "
            "role-priority-v1, and unreferenced ports administratively disabled."
        ),
        (
            f"{summary.config_items} configuration intents are reported; "
            f"{summary.changed_items} differ from the previous saved revision; "
            f"{summary.config_items - summary.evidence_pass_items} do not pass the "
            f"evidence gate (device gate: {gate})."
        ),
    ]
    for item in items:
        if item.category not in {
            PreviewCategory.ACCESS, PreviewCategory.TRUNK,
            PreviewCategory.ROUTED_BOUNDARY,
        } or item.field != "mode":
            continue
        if item.diff.changed:
            baseline_text = (
                "no earlier planning baseline"
                if item.baseline.state == "planning-baseline-unavailable"
                else f"previous planning baseline {item.baseline.value}"
            )
            statements.append(
                f"{item.target_name}: planned {item.planned.value} boundary, "
                f"{baseline_text}, "
                f"transition {item.diff.transition or 'mode change'}."
            )
        else:
            statements.append(
                f"{item.target_name}: planned {item.planned.value} boundary, "
                "unchanged from the planning baseline or first planned revision."
            )
    for item in items:
        if item.category is PreviewCategory.LACP and item.diff.changed:
            statements.append(
                f"{item.target_name}: planned LACP mode {item.planned.value}, "
                f"previous planning baseline {item.baseline.value}."
            )
    for item in items:
        if item.category is PreviewCategory.VLAN and item.diff.changed:
            statements.append(
                f"VLAN {item.target_id}: {item.diff.transition or 'planned change'}, "
                f"planned name {item.planned.value}, baseline {item.baseline.value}."
            )
    statements.append(
        "CIS-02A dependency IDs below are association metadata only and are not an "
        "execution order; no command sequence is authorised by this preview."
    )
    return HumanReadablePreview(
        headline=(
            f"{identity.hostname}: {summary.config_items} L2 intents, "
            f"{summary.changed_items} planned differences, review-only"
        ),
        statements=tuple(_single_line(statement) for statement in statements),
    )


def _single_line(value: str) -> str:
    return " ".join(value.split())


def _device_blockers(
    identity_gate: IdentityGate,
    capability_gate: CapabilityGate,
    identity: DeviceIdentity,
    structured_valid: bool,
) -> tuple[str, ...]:
    blockers: list[str] = list(PREVIEW_BASE_BLOCKERS)
    blockers.extend(f"identity-incomplete:{code}" for code in identity_gate.codes)
    if identity.pid_evidence != "exact-verified-pid":
        blockers.append(f"pid-evidence:{identity.pid_evidence}")
    blockers.extend(f"capability-unknown:{item}" for item in capability_gate.unknown)
    blockers.extend(
        f"capability-unsupported:{item}" for item in capability_gate.unsupported
    )
    if not structured_valid:
        blockers.append("structured-intent-invalid")
    return tuple(dict.fromkeys(blockers))


def _deployability(
    context: _DeviceContext,
) -> DeviceDeployability:
    gate = _gate_precedence(
        structured_valid=context.structured_valid,
        identity=context.identity_gate,
        capability=context.capability_gate,
    )
    return DeviceDeployability(
        evidence_gate=gate,
        identity_gate=context.identity_gate,
        capability_gate=context.capability_gate,
        intent_gate="valid" if context.structured_valid else "invalid",
        blockers=_device_blockers(
            context.identity_gate, context.capability_gate, context.device.identity,
            context.structured_valid,
        ),
    )


def _device_preview(
    intent: Layer2Intent, device: DeviceLayer2Intent,
) -> DeviceConfigPreview:
    structured_valid = device.readiness.structured_intent_valid
    context = _DeviceContext(
        device=device,
        checks=_check_index(device),
        changes=_change_index(device, intent.vlan_changes),
        identity_gate=_identity_gate(device),
        capability_gate=_capability_gate(device),
        structured_valid=structured_valid,
    )
    items = _config_items(context)
    summary = _summary(items, device)
    deployability = _deployability(context)
    draft = DeviceConfigPreview(
        assignment_id=device.identity.assignment_id,
        hostname=device.identity.hostname,
        identity=device.identity,
        intent_readiness=device.readiness,
        deployability=deployability,
        config_items=items,
        planned_diff=device.changes,
        dependencies=device.dependencies,
        conflicts=device.conflicts,
        capability_checks=device.capability_checks,
        summary=summary,
        human_readable=_human_readable(
            device, items, summary, deployability.evidence_gate,
        ),
        preview_fingerprint="",
    )
    return draft.model_copy(update={"preview_fingerprint": _fingerprint(draft)})


def _vlan_scope(intent: Layer2Intent) -> VlanScopePreview:
    changes = {change.target_id: change for change in intent.vlan_changes}
    definitions = tuple(
        VlanDefinitionReference(
            vlan_id=vlan.vlan_id,
            name=vlan.name,
            source=vlan.source,
            change_id=(
                changes[str(vlan.vlan_id)].change_id
                if str(vlan.vlan_id) in changes else None
            ),
            transition=(
                changes[str(vlan.vlan_id)].transition
                if str(vlan.vlan_id) in changes else None
            ),
        )
        for vlan in intent.vlans
    )
    without_fingerprint = {
        "scope": "event-plan",
        "semantics": "event-wide-vlan-definitions-not-per-device-intent",
        "definitions": [definition.model_dump(mode="json") for definition in definitions],
        "changes": [change.model_dump(mode="json") for change in intent.vlan_changes],
        "dependencies": [
            dependency.model_dump(mode="json") for dependency in intent.vlan_dependencies
        ],
    }
    return VlanScopePreview(
        fingerprint=_sha256(without_fingerprint),
        definitions=definitions,
        changes=intent.vlan_changes,
        dependencies=intent.vlan_dependencies,
    )


def _preview_blockers(intent: Layer2Intent) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*PREVIEW_BASE_BLOCKERS, *intent.deployment_blockers)))


def _header(
    revision: PlanRevision, intent: Layer2Intent,
) -> tuple[PreviewHeader, VlanScopePreview]:
    header = PreviewHeader(
        event_id=intent.event_id,
        revision_id=revision.id,
        revision_number=revision.number,
        revision_hash=revision.content_hash,
        intent_fingerprint=intent.intent_fingerprint,
        baseline=intent.baseline,
        before_state_evidence=intent.before_state_evidence,
        planning_scope=PlanningScope(),
        readiness=PreviewReadiness(
            structured_intent_valid=intent.readiness.structured_intent_valid,
            vendor_documentation=intent.readiness.vendor_documentation,
        ),
    )
    return header, _vlan_scope(intent)


def build_layer2_config_preview(
    revision: PlanRevision, intent: Layer2Intent,
) -> Layer2ConfigPreview:
    """Build one deterministic review-only preview for every device."""
    verify_intent_binding(revision, intent)
    header, vlan_scope = _header(revision, intent)
    devices = tuple(_device_preview(intent, device) for device in intent.devices)
    draft = Layer2ConfigPreview.model_validate({
        **header.model_dump(),
        "vlan_scope": vlan_scope,
        "devices": devices,
        "removed_assignments": intent.removed_assignments,
        "conflicts": intent.conflicts,
        "deployment_blockers": _preview_blockers(intent),
        "preview_fingerprint": "",
    })
    return draft.model_copy(update={"preview_fingerprint": _fingerprint(draft)})


def build_device_layer2_config_preview(
    revision: PlanRevision, intent: Layer2Intent, assignment_id: UUID,
) -> Layer2DeviceConfigPreview:
    """Build one self-contained preview for exactly one Assignment."""
    verify_intent_binding(revision, intent)
    device = next(
        (item for item in intent.devices
         if item.identity.assignment_id == assignment_id),
        None,
    )
    if device is None:
        raise PreviewTargetNotFound(
            "Assignment not found in this saved revision intent"
        )
    header, vlan_scope = _header(revision, intent)
    preview = _device_preview(intent, device)
    draft = Layer2DeviceConfigPreview.model_validate({
        **header.model_dump(),
        "vlan_scope": vlan_scope,
        "device": preview,
        "deployment_blockers": tuple(dict.fromkeys(
            (*PREVIEW_BASE_BLOCKERS, *preview.deployability.blockers)
        )),
        "preview_fingerprint": "",
    })
    return draft.model_copy(update={"preview_fingerprint": _fingerprint(draft)})


def config_preview_json_schema() -> dict[str, object]:
    """Return the versioned JSON Schema for both preview documents."""
    return {
        "contract_id": PREVIEW_CONTRACT_ID,
        "preview_schema_version": PREVIEW_SCHEMA_VERSION,
        "intent_schema_version": SUPPORTED_INTENT_SCHEMA_VERSION,
        "aggregate": Layer2ConfigPreview.model_json_schema(),
        "device": Layer2DeviceConfigPreview.model_json_schema(),
    }


def preview_contract_fingerprint() -> str:
    """Stable hash of the published contract schema for traceability."""
    return _sha256(config_preview_json_schema())


__all__ = [
    "PREVIEW_BASE_BLOCKERS",
    "PREVIEW_CONTRACT_ID",
    "PREVIEW_SCHEMA_VERSION",
    "SUPPORTED_INTENT_SCHEMA_VERSION",
    "BaselineValue",
    "CapabilityAssessment",
    "CapabilityGate",
    "ConfigItem",
    "DeviceConfigPreview",
    "DeviceDeployability",
    "DiffState",
    "EvidenceGate",
    "HumanReadablePreview",
    "IdentityGate",
    "ItemDeployability",
    "Layer2ConfigPreview",
    "Layer2DeviceConfigPreview",
    "PlannedValue",
    "PlanningScope",
    "PreviewCategory",
    "PreviewHeader",
    "PreviewInputError",
    "PreviewReadiness",
    "PreviewRisk",
    "PreviewSummary",
    "PreviewTargetNotFound",
    "VlanDefinitionReference",
    "VlanScopePreview",
    "build_device_layer2_config_preview",
    "build_layer2_config_preview",
    "config_preview_json_schema",
    "intent_fingerprint",
    "preview_contract_fingerprint",
    "verify_intent_binding",
]
