"""CIS-02B2 offline Cisco Layer 2 candidate renderer.

Given one immutable saved revision, its rebuilt CIS-02A intent and the rebuilt
CIS-02B1 single-device preview, this module renders *candidate* command objects
for human review. Each candidate is one command in one explicit configuration
context, backed by one reviewed L1 command-evidence row.

It is deliberately not a deployment feature:

* no full configuration file, paste-ready script or execution order is produced;
* ``candidate_only`` is ``True`` and every deployment flag is ``False``;
* no device is contacted, no running-config is read and no state is written;
* ``syntax_validation`` never exceeds ``dictionary-only``;
* a category renders text only when the CIS-01A capability is supported *and*
  the exact PID/release/license command evidence passed independent review.

Everything else returns a deterministic blocker. CIS-02B1 ``cli`` stays ``None``;
candidate text is a separate field on a separate document.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from ..cisco_capabilities import ETHERNET
from ..cisco_catalog import PROFILES, CiscoCapability, Medium, PortGroup, Profile
from ..domain import DeviceFamily
from ..integrations import Capability
from .command_evidence import (
    BLOCKING_REQUIREMENT_CODES,
    DEFAULT_REGISTRY,
    EVIDENCE_REGISTRY_ID,
    CommandEvidence,
    CommandEvidenceRegistry,
    CommandMode,
    CommandTopic,
    ParameterRule,
    RequirementKind,
    evidence_reference,
)
from .layer2_config_preview import (
    CapabilityAssessment,
    ConfigItem,
    Layer2DeviceConfigPreview,
    intent_fingerprint,
)
from .layer2_intent import (
    CapabilityCheck,
    DeviceDesiredState,
    DeviceIdentity,
    DeviceLayer2Intent,
    IntentConflict,
    Layer2Intent,
    PhysicalPortIntent,
    PortChannelIntent,
)
from .plan import PlanRevision, canonical_plan, plan_hash

RENDER_SCHEMA_VERSION: Literal[1] = 1
CONTRACT_ID: Literal["cis-02b2-cisco-l2-cli-candidate-v1"] = (
    "cis-02b2-cisco-l2-cli-candidate-v1"
)
SUPPORTED_INTENT_SCHEMA_VERSION: Literal[1] = 1
SUPPORTED_PREVIEW_SCHEMA_VERSION: Literal[1] = 1
SUPPORTED_PREVIEW_CONTRACT_ID: Literal["cis-02b1-layer2-config-preview-v1"] = (
    "cis-02b1-layer2-config-preview-v1"
)
DICTIONARY_ID: Literal["cis-02b2-l1-command-dictionary-v1"] = (
    "cis-02b2-l1-command-dictionary-v1"
)
RENDER_BASE_BLOCKERS: tuple[str, ...] = (
    "candidate-only-no-execution",
    "deployment-generation-disabled",
    "hardware-not-verified",
    "device-state-unknown",
    "syntax-dictionary-only",
    "no-execution-order-produced",
)
MAX_TRUNK_VLAN_IDS = 64
#: Renderer safety subset: the per-platform EtherChannel member limit is not
#: independently bound for every reviewed release, so no channel above this
#: planned member count may render. This is a renderer restriction, not a vendor
#: claim.
MAX_CHANNEL_MEMBERS = 8
#: Mode transitions whose associated VLAN configuration must not render on its own.
BLOCKED_MODE_TRANSITIONS = frozenset({
    "access-to-trunk", "trunk-to-access", "routed-to-switchport",
    "switchport-to-routed",
})

_ASCII = "ascii"

VLAN_NAME_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
DESCRIPTION_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9 .,:/_+%@-]{0,239}\Z")
PORT_CHANNEL_NAME_PATTERN = re.compile(r"\APort-[Cc]hannel([1-9]\d{0,3})\Z")


class RenderBindingError(ValueError):
    """Rebuilt revision, intent and preview do not bind to each other."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class RenderTargetNotFound(LookupError):
    """The requested Assignment is not part of this revision."""


class RenderRecord(BaseModel):
    """Frozen record that never rewrites a caller's text.

    ``planning.types.Record`` strips whitespace; a renderer must never normalise
    or trim candidate-bearing text, so B2 uses its own base model.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


class CandidateCategory(StrEnum):
    VLAN_DEFINITION = "vlan-definition"
    ACCESS_MODE = "access-mode"
    ACCESS_VLAN = "access-vlan"
    TRUNK_MODE = "trunk-mode"
    NATIVE_VLAN = "native-vlan"
    ALLOWED_VLANS = "allowed-vlans"
    PORT_CHANNEL = "port-channel"
    LACP_MODE = "lacp-mode"
    RAPID_PVST = "rapid-pvst"
    VTP_TRANSPARENT = "vtp-transparent"
    ROOT_PRIORITY = "root-priority"
    PORTFAST = "portfast"
    BPDU_GUARD = "bpdu-guard"
    POE_MODE = "poe-mode"
    SPEED = "speed"
    DUPLEX = "duplex"
    DESCRIPTION = "description"
    ADMIN_SHUTDOWN = "admin-shutdown"
    UNUSED_SHUTDOWN = "unused-shutdown"


#: R1 operations that can still interrupt a live link, so their connectivity
#: impact must never be advertised as absent.
CONNECTIVITY_RISK_CATEGORIES = frozenset({
    CandidateCategory.ADMIN_SHUTDOWN,
    CandidateCategory.UNUSED_SHUTDOWN,
    CandidateCategory.SPEED,
    CandidateCategory.DUPLEX,
    CandidateCategory.POE_MODE,
})


class CandidateStatus(StrEnum):
    CANDIDATE = "candidate"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"


class RenderState(StrEnum):
    BLOCKED = "blocked"
    NO_SUPPORTED_CANDIDATES = "no-supported-candidates"
    REVIEW_CANDIDATES = "review-candidates"


class RiskClass(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"
    R5 = "R5"
    R6 = "R6"


class TargetKind(StrEnum):
    DEVICE = "device"
    VLAN = "vlan"
    INTERFACE = "interface"
    PORT_CHANNEL = "port-channel"


class SyntaxValidationLevel(StrEnum):
    NOT_RUN = "not-run"
    DICTIONARY_ONLY = "dictionary-only"


_RISK_RANK: Mapping[RiskClass, int] = {
    RiskClass.R0: 0,
    RiskClass.R1: 1,
    RiskClass.R2: 2,
    RiskClass.R3: 3,
    RiskClass.R4: 4,
    RiskClass.R5: 5,
    RiskClass.R6: 6,
}
_CONNECTIVITY_RISK = {RiskClass.R2, RiskClass.R3, RiskClass.R4, RiskClass.R5}
_CAPABILITY_RANK: Mapping[str, int] = {
    "not-required": 0, "supported": 1, "unknown": 2, "unsupported": 3,
}
_CAPABILITY_IDS: Mapping[str, Capability] = {item.value: item for item in Capability}


# --------------------------------------------------------------------------- #
# Text and parameter policy
# --------------------------------------------------------------------------- #


def _is_ascii(value: str) -> bool:
    try:
        value.encode(_ASCII)
    except UnicodeEncodeError:
        return False
    return True


def vlan_name_reason(value: object, maximum: int) -> str | None:
    """Return a deterministic reason code when a VLAN name is not renderable."""
    if not isinstance(value, str) or not value:
        return "unsafe-text-class:empty-vlan-name"
    if len(value) > maximum:
        return "unsafe-text-class:vlan-name-too-long"
    if not _is_ascii(value):
        return "unsafe-text-class:non-ascii-vlan-name"
    if not VLAN_NAME_PATTERN.fullmatch(value):
        return "unsafe-text-class:forbidden-character"
    return None


def description_reason(value: object, maximum: int) -> str | None:
    """Return a deterministic reason code when a description is not renderable."""
    if not isinstance(value, str) or not value:
        return "unsafe-text-class:empty-description"
    if len(value) > maximum:
        return "unsafe-text-class:description-too-long"
    if not _is_ascii(value):
        return "unsafe-text-class:non-ascii-description"
    if value != value.strip() or "  " in value:
        return "unsafe-text-class:unsafe-whitespace"
    if not DESCRIPTION_PATTERN.fullmatch(value):
        return "unsafe-text-class:forbidden-character"
    return None


def interface_name_reason(
    value: object, profile: Profile | None, member: int | None,
) -> str | None:
    """Reject any interface name that is not the exact documented physical port."""
    if not isinstance(value, str) or not value:
        return "unsafe-text-class:empty-interface-name"
    if not _is_ascii(value) or "\n" in value or "\r" in value:
        return "unsafe-text-class:forbidden-interface-name"
    match = ETHERNET.fullmatch(value)
    if match is None or profile is None:
        return "unsafe-text-class:forbidden-interface-name"
    member_slot, module, port = int(match[2]), int(match[3]), int(match[4])
    name = match[1].casefold()
    if member_slot != (member or 1):
        return "interface-not-in-documented-layout"
    for group in profile.ports:
        if (
            name.startswith(group.prefix)
            and module == group.slot
            and group.first <= port < group.first + group.count
        ):
            return None
    return "interface-not-in-documented-layout"


def port_channel_name_reason(value: object, number: int) -> str | None:
    """The logical name must be a Port-Channel name that matches its number."""
    if not isinstance(value, str) or not value:
        return "unsafe-text-class:empty-port-channel-name"
    if not _is_ascii(value):
        return "unsafe-text-class:forbidden-port-channel-name"
    match = PORT_CHANNEL_NAME_PATTERN.fullmatch(value)
    if match is None:
        return "unsafe-text-class:forbidden-port-channel-name"
    if int(match[1]) != number:
        return "port-channel-name-number-mismatch"
    return None


def _rule_violation(rule: ParameterRule, value: object) -> str | None:
    if rule.kind == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return f"parameter-not-integer:{rule.name}"
        if rule.minimum is not None and value < rule.minimum:
            return f"parameter-out-of-range:{rule.name}"
        if rule.maximum is not None and value > rule.maximum:
            return f"parameter-out-of-range:{rule.name}"
        if rule.step is not None and value % rule.step != 0:
            return f"parameter-step-violation:{rule.name}"
        if value in rule.reserved:
            return f"parameter-reserved-value:{rule.name}"
        return None
    if rule.kind == "enum":
        return None if str(value) in rule.values else f"parameter-not-allowed:{rule.name}"
    if rule.kind == "text":
        if not isinstance(value, str):
            return f"parameter-not-text:{rule.name}"
        if rule.maximum is not None and len(value) > rule.maximum:
            return f"unsafe-text-class:{rule.name}-too-long"
        if rule.pattern is not None and not re.fullmatch(rule.pattern, value):
            return "unsafe-text-class:forbidden-character"
        return None
    if rule.kind == "vlan-list":
        if not isinstance(value, tuple) or not value:
            return f"parameter-not-allowed:{rule.name}"
        if len(value) > MAX_TRUNK_VLAN_IDS:
            return f"parameter-list-too-long:{rule.name}"
        if len(set(value)) != len(value):
            return f"parameter-duplicate-value:{rule.name}"
        for item in value:
            if not isinstance(item, int) or isinstance(item, bool):
                return f"parameter-not-integer:{rule.name}"
            if rule.minimum is not None and item < rule.minimum:
                return f"parameter-out-of-range:{rule.name}"
            if rule.maximum is not None and item > rule.maximum:
                return f"parameter-out-of-range:{rule.name}"
            if item in rule.reserved:
                return f"parameter-reserved-value:{rule.name}"
        return None
    return f"parameter-rule-unusable:{rule.name}"


def _text_policy_violations(
    evidence: CommandEvidence | None, values: Mapping[str, object],
) -> tuple[str, ...]:
    """Apply the stricter renderer text policy on top of the generic pattern."""
    if evidence is None:
        return ()
    reasons: list[str] = []
    for rule in evidence.parameters:
        maximum = rule.maximum or 0
        if rule.name == "description" and "description" in values:
            reason = description_reason(values["description"], maximum)
            if reason is not None:
                reasons.append(reason)
        elif rule.name == "vlan-name" and "vlan-name" in values:
            reason = vlan_name_reason(values["vlan-name"], maximum)
            if reason is not None:
                reasons.append(reason)
    return tuple(dict.fromkeys(reasons))


def validate_parameters(
    evidence: CommandEvidence | None, values: Mapping[str, object], *,
    require_all: bool = True,
) -> tuple[str, ...]:
    """Check every argument against the reviewed row's parameter rules.

    With ``require_all=False`` an argument the renderer deliberately does not
    supply (a command the risk model blocks anyway) is skipped instead of being
    reported as missing.
    """
    if evidence is None:
        return ()
    reasons: list[str] = []
    for rule in evidence.parameters:
        if rule.name not in values:
            if require_all:
                reasons.append(f"parameter-missing:{rule.name}")
            continue
        violation = _rule_violation(rule, values[rule.name])
        if violation is not None:
            reasons.append(violation)
    return tuple(dict.fromkeys(reasons))


# --------------------------------------------------------------------------- #
# Document schema
# --------------------------------------------------------------------------- #


class RenderTarget(RenderRecord):
    kind: TargetKind
    stable_id: str
    name: str


class CommandContext(RenderRecord):
    mode: CommandMode
    mode_header: str
    target_name: str


class CandidateProvenance(RenderRecord):
    preview_item_id: str
    b1_category: str
    b1_field: str
    change_id: str | None
    transition: str | None
    planned_source: str
    baseline_state: str
    diff_changed: bool
    cleanup: tuple[str, ...]
    #: Further B1 items that produced the exact same candidate. Safety is merged
    #: conservatively across all of them; this list keeps every source visible.
    additional_preview_item_ids: tuple[str, ...] = ()


class CapabilityEvidence(RenderRecord):
    capability: str | None
    verdict: str
    reason_code: str
    check_id: str | None


class SyntaxEvidence(RenderRecord):
    evidence_id: str
    topic: str
    release: str
    command: str
    grammar: str
    review_state: str
    source_url: str
    source_section: str
    limits: tuple[str, ...]
    exclusions: tuple[str, ...]


class SyntaxValidation(RenderRecord):
    level: SyntaxValidationLevel = SyntaxValidationLevel.DICTIONARY_ONLY
    dictionary_id: str = DICTIONARY_ID
    parser_verified: Literal[False] = False


class Candidate(RenderRecord):
    candidate_id: str = Field(pattern=r"^cand-[0-9a-f]{16}$")
    assignment_id: UUID
    target: RenderTarget
    category: CandidateCategory
    command_context: CommandContext
    status: CandidateStatus
    candidate_text: str | None
    parameters: dict[str, JsonValue]
    provenance: CandidateProvenance
    capability_evidence: tuple[CapabilityEvidence, ...]
    syntax_evidence: tuple[SyntaxEvidence, ...]
    syntax_validation: SyntaxValidation
    risk_class: RiskClass
    potential_connectivity_impact: bool
    requires_field_verification: bool
    prerequisites: tuple[str, ...]
    blocking_reasons: tuple[str, ...]
    candidate_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class RenderSafety(RenderRecord):
    candidate_only: Literal[True] = True
    executable: Literal[False] = False
    deployable: Literal[False] = False
    deployment_allowed: Literal[False] = False
    device_connection: Literal["none"] = "none"
    running_config_read: Literal[False] = False
    device_writes_enabled: Literal[False] = False
    cli: None = None
    deployment_artifact: None = None
    device_runtime_state: Literal["unknown-not-read"] = "unknown-not-read"
    hardware_verified: Literal[False] = False


class RenderSource(RenderRecord):
    saved_revision_uuid: UUID
    revision_number: int
    revision_canonical_hash: str
    intent_schema_version: Literal[1] = SUPPORTED_INTENT_SCHEMA_VERSION
    intent_fingerprint: str
    preview_schema_version: Literal[1] = SUPPORTED_PREVIEW_SCHEMA_VERSION
    preview_contract_id: Literal["cis-02b1-layer2-config-preview-v1"] = (
        SUPPORTED_PREVIEW_CONTRACT_ID
    )
    preview_fingerprint: str
    command_evidence_registry_id: str = EVIDENCE_REGISTRY_ID
    command_evidence_fingerprint: str


class RenderStackMember(RenderRecord):
    number: int
    exact_pid: str | None
    state: str


class RenderDevice(RenderRecord):
    hostname: str
    family: str | None
    exact_pid: str | None
    release: str | None
    license: str | None
    role: str
    stack_identity: str
    stack_members: tuple[RenderStackMember, ...]


class EvidenceReference(RenderRecord):
    kind: Literal["capability", "syntax"]
    reference_id: str
    detail: str


class RenderSummary(RenderRecord):
    total: int
    candidates: int
    blocked: int
    unsupported: int
    categories_rendered: tuple[str, ...]


class L2CliCandidateDocument(RenderRecord):
    render_schema_version: Literal[1] = RENDER_SCHEMA_VERSION
    contract_id: Literal["cis-02b2-cisco-l2-cli-candidate-v1"] = CONTRACT_ID
    source: RenderSource
    assignment_id: UUID
    device: RenderDevice
    render_state: RenderState
    candidates: tuple[Candidate, ...]
    unresolved_prerequisites: tuple[str, ...]
    evidence: tuple[EvidenceReference, ...]
    device_runtime_state: Literal["unknown-not-read"]
    safety: RenderSafety
    summary: RenderSummary
    deployment_blockers: tuple[str, ...]
    render_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------- #
# Deterministic fingerprints
# --------------------------------------------------------------------------- #


def _sha256(value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def candidate_fingerprint(candidate: Candidate) -> str:
    document = candidate.model_dump(mode="json")
    document.pop("candidate_fingerprint", None)
    return _sha256(document)


def render_fingerprint(document: L2CliCandidateDocument) -> str:
    value = document.model_dump(mode="json")
    value.pop("render_fingerprint", None)
    return _sha256(value)


def evidence_fingerprint(registry: CommandEvidenceRegistry) -> str:
    return _sha256(evidence_reference(registry))


def _document_fingerprint(model: BaseModel) -> str:
    """Recompute a CIS-02B1 document fingerprint to catch a tampered rebuild."""
    value = model.model_dump(mode="json")
    value.pop("preview_fingerprint", None)
    return _sha256(value)


def _candidate_id(
    assignment_id: UUID, category: CandidateCategory, target_kind: TargetKind,
    target_id: str, field: str,
) -> str:
    digest = hashlib.sha256(
        f"{assignment_id}|{category.value}|{target_kind.value}|{target_id}|{field}".encode()
    ).hexdigest()
    return "cand-" + digest[:16]


# --------------------------------------------------------------------------- #
# Server-side binding verification
# --------------------------------------------------------------------------- #


def verify_render_binding(
    revision: PlanRevision, intent: Layer2Intent, preview: Layer2DeviceConfigPreview,
    *, registry: CommandEvidenceRegistry = DEFAULT_REGISTRY,
) -> None:
    """Fail closed unless revision, intent, preview and dictionary all bind."""
    if plan_hash(canonical_plan(revision.plan)) != revision.content_hash:
        raise RenderBindingError("stored-revision-integrity-failure")
    if intent.intent_schema_version != SUPPORTED_INTENT_SCHEMA_VERSION:
        raise RenderBindingError("intent-rebuild-mismatch")
    if intent.revision_id != revision.id or intent.revision_hash != revision.content_hash:
        raise RenderBindingError("intent-rebuild-mismatch")
    if intent.intent_fingerprint != intent_fingerprint(intent):
        raise RenderBindingError("intent-rebuild-mismatch")
    if preview.preview_schema_version != SUPPORTED_PREVIEW_SCHEMA_VERSION:
        raise RenderBindingError("preview-rebuild-mismatch")
    if preview.contract_id != SUPPORTED_PREVIEW_CONTRACT_ID:
        raise RenderBindingError("preview-rebuild-mismatch")
    if preview.revision_id != revision.id or preview.revision_hash != revision.content_hash:
        raise RenderBindingError("preview-rebuild-mismatch")
    if preview.intent_fingerprint != intent.intent_fingerprint:
        raise RenderBindingError("preview-rebuild-mismatch")
    if preview.preview_fingerprint != _document_fingerprint(preview):
        raise RenderBindingError("preview-rebuild-mismatch")
    if preview.event_id != intent.event_id:
        raise RenderBindingError("preview-rebuild-mismatch")
    if not registry.rows:
        raise RenderBindingError("command-evidence-registry-empty")


# --------------------------------------------------------------------------- #
# Internal render context
# --------------------------------------------------------------------------- #

CheckKey = tuple[str, str, str]


@dataclass(frozen=True, slots=True)
class _ChannelRef:
    """Identity of the aggregate a member belongs to in one revision."""

    number: int
    interface_id: str
    lacp: str


@dataclass(frozen=True, slots=True)
class _Membership:
    """Current and previous channel membership, keyed by physical interface UUID.

    A channel number alone never proves object identity: the logical-interface
    UUID and the aggregation protocol are tracked with it so a replaced object or
    a static/LACP protocol switch cannot look like an unchanged membership.
    """

    current: Mapping[str, _ChannelRef]
    previous: Mapping[str, _ChannelRef]
    current_sets: Mapping[int, tuple[str, ...]]

    def transition(self, member_id: str) -> str:
        current = self.current.get(member_id)
        previous = self.previous.get(member_id)
        if current is not None and previous is None:
            return "added"
        if current is not None and previous is not None:
            if current.number != previous.number:
                return "migrated"
            if current.interface_id != previous.interface_id:
                return "replaced"
            return "unchanged"
        if current is None and previous is not None:
            return "removed"
        return "unknown"

    def protocol_transition(self, member_id: str) -> str:
        current = self.current.get(member_id)
        previous = self.previous.get(member_id)
        if current is None or previous is None:
            return "not-comparable"
        if current.number != previous.number or (
            current.interface_id != previous.interface_id
        ):
            return "not-comparable"
        if current.lacp == previous.lacp:
            return "unchanged"
        if "static" in {current.lacp, previous.lacp}:
            return "protocol-switch"
        return "lacp-mode-change"


def _channel_refs(state: DeviceDesiredState | None) -> Mapping[str, _ChannelRef]:
    refs: dict[str, _ChannelRef] = {}
    for channel in (state.port_channels if state is not None else ()):
        ref = _ChannelRef(
            number=channel.number,
            interface_id=str(channel.interface_id),
            lacp=channel.lacp,
        )
        for member in channel.member_ids:
            refs[str(member)] = ref
    return refs


def _build_membership(device_intent: DeviceLayer2Intent) -> _Membership:
    current = _channel_refs(device_intent.desired)
    previous = _channel_refs(device_intent.before.state)
    current_sets = {
        channel.number: tuple(str(member) for member in channel.member_ids)
        for channel in device_intent.desired.port_channels
    }
    return _Membership(current, previous, current_sets)


def _build_mode_transitions(
    device_intent: DeviceLayer2Intent,
) -> Mapping[tuple[str, str], str]:
    transitions: dict[tuple[str, str], str] = {}
    for change in device_intent.changes:
        if change.field == "mode" and change.transition is not None:
            transitions[(change.target_kind.value, change.target_id)] = change.transition
    return transitions


@dataclass(frozen=True, slots=True)
class _Context:
    revision: PlanRevision
    intent: Layer2Intent
    device_intent: DeviceLayer2Intent
    preview: Layer2DeviceConfigPreview
    registry: CommandEvidenceRegistry
    profile: Profile | None
    pid: str
    release: str | None
    license: str | None
    checks: Mapping[CheckKey, CapabilityCheck]
    vlan_scope: frozenset[int]
    hard_block: tuple[str, ...]
    membership: _Membership
    mode_transitions: Mapping[tuple[str, str], str]

    @property
    def identity(self) -> DeviceIdentity:
        return self.preview.device.identity

    @property
    def assignment_id(self) -> UUID:
        return self.preview.device.assignment_id

    @property
    def hostname(self) -> str:
        return self.preview.device.hostname

    @property
    def family(self) -> DeviceFamily | None:
        return self.identity.family

    def port(self, name: str) -> PhysicalPortIntent | None:
        return next(
            (item for item in self.device_intent.desired.physical_ports
             if item.name == name),
            None,
        )

    def channel(self, number: int) -> PortChannelIntent | None:
        return next(
            (item for item in self.device_intent.desired.port_channels
             if item.number == number),
            None,
        )

    def channel_for_interface(self, stable_id: str) -> PortChannelIntent | None:
        return next(
            (item for item in self.device_intent.desired.port_channels
             if str(item.interface_id) == stable_id),
            None,
        )

    def device_check(self, capability: str) -> CapabilityCheck | None:
        return self.checks.get(("device", self.hostname, capability))

    def member_transition(self, member_id: str) -> str:
        return self.membership.transition(member_id)

    def member_protocol_transition(self, member_id: str) -> str:
        return self.membership.protocol_transition(member_id)

    def mode_transition(self, target: TargetKind, stable_id: str) -> str | None:
        return self.mode_transitions.get((target.value, stable_id))

    def target_mode(
        self, target: TargetKind, stable_id: str, name: str,
    ) -> str | None:
        if target is TargetKind.INTERFACE:
            port = self.port(name)
            return port.mode if port is not None else None
        if target is TargetKind.PORT_CHANNEL:
            channel = self.channel_for_interface(stable_id)
            return channel.settings.mode if channel is not None else None
        return None

    def port_group(self, name: str) -> PortGroup | None:
        if self.profile is None:
            return None
        match = ETHERNET.fullmatch(name)
        if match is None:
            return None
        module, port = int(match[3]), int(match[4])
        prefix = match[1].casefold()
        return next(
            (group for group in self.profile.ports
             if prefix.startswith(group.prefix) and module == group.slot
             and group.first <= port < group.first + group.count),
            None,
        )

    def port_roles(self, name: str) -> frozenset[str]:
        port = self.port(name)
        if port is None:
            return frozenset({"unknown"})
        roles: set[str] = set()
        interface_id = port.interface_id
        if any(interface_id in link.endpoints for link in self.revision.plan.links):
            roles.add("link")
        if interface_id in {
            member for channel in self.device_intent.desired.port_channels
            for member in channel.member_ids
        }:
            roles.add("channel-member")
        if any(isp.interface_id == interface_id for isp in self.revision.plan.isps):
            roles.add("isp")
        transit = self.revision.plan.transit
        if transit is not None and interface_id in {
            transit.core_port_id, transit.hillstone_port_id,
        }:
            roles.add("transit")
        return frozenset(roles) if roles else frozenset({"unreferenced"})

    def evidence(
        self, topic: CommandTopic,
    ) -> tuple[CommandEvidence | None, tuple[str, ...]]:
        """Return the single reviewed row for this exact scope, or blocker codes.

        The diagnosis distinguishes missing, unreviewed, rejected and
        content-mismatched evidence by delegating to the registry blocker, so a
        stale review digest can never be reported as merely "not reviewed".
        """
        if self.family is None or self.release is None:
            return None, ("syntax-evidence-scope-unknown",)
        rows = self.registry.applicable(
            self.family, self.pid, self.release, self.license, topic,
        )
        reviewed = tuple(row for row in rows if row.renderable)
        if len(reviewed) == 1:
            return reviewed[0], ()
        if len(reviewed) > 1:
            return None, (f"syntax-evidence-ambiguous:{topic.value}",)
        if not rows:
            return None, (f"syntax-evidence-missing:{topic.value}",)
        return None, (self.registry.blocker(
            self.family, self.pid, self.release, self.license, topic,
        ),)


@dataclass(frozen=True, slots=True)
class _Spec:
    category: CandidateCategory
    topic: CommandTopic | None
    target_kind: TargetKind
    target_id: str
    target_name: str
    field: str
    base_risk: RiskClass
    compose: Callable[[], str]
    mode: CommandMode | None = None
    header_name: str | None = None
    parameters: Mapping[str, object] | None = None
    prerequisites: tuple[str, ...] = ()
    force_block: tuple[str, ...] = ()
    force_unsupported: tuple[str, ...] = ()
    capability_ids: tuple[str, ...] = ()
    risk_floor: RiskClass | None = None


@dataclass(frozen=True, slots=True)
class _Entry:
    spec: _Spec
    capabilities: tuple[CapabilityAssessment, ...]
    extra_block: tuple[str, ...] = ()
    extra_unsupported: tuple[str, ...] = ()


_RequirementFinding = tuple[str, RiskClass]


def _no_requirement(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    return ()


def _require_channel_membership(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    number = _as_int((spec.parameters or {}).get("port-channel-number"))
    if spec.target_kind is TargetKind.PORT_CHANNEL:
        if number is None:
            return ((f"channel-number-unresolved:{spec.target_name}", RiskClass.R5),)
        # Channel count, channel number and member count are three independent
        # constraints. The reviewed number maximum is a conservative count bound
        # because every Port-Channel has a unique number inside that range.
        reviewed_maximum = next(
            (
                rule.maximum for rule in (row.parameters if row is not None else ())
                if rule.name == "port-channel-number" and rule.maximum is not None
            ),
            None,
        )
        channel_count = len(context.membership.current_sets)
        if reviewed_maximum is not None and channel_count > reviewed_maximum:
            return ((
                f"channel-count-exceeds-reviewed-limit:{channel_count}",
                RiskClass.R3,
            ),)
        members = context.membership.current_sets.get(number, ())
        if not members:
            return ((f"channel-membership-empty:{spec.target_name}", RiskClass.R5),)
        for member in members:
            ref = context.membership.current.get(member)
            if ref is None or ref.number != number:
                return ((
                    f"channel-membership-inconsistent:{spec.target_name}",
                    RiskClass.R5,
                ),)
        return ()
    transition = context.member_transition(spec.target_id)
    if transition in {"added", "unchanged"}:
        ref = context.membership.current.get(spec.target_id)
        if number is None or ref is None or ref.number != number:
            return ((
                f"channel-membership-inconsistent:{spec.target_name}",
                RiskClass.R5,
            ),)
        return ()
    if transition == "migrated":
        return ((
            f"channel-migration-requires-source-channel-evidence:{spec.target_name}",
            RiskClass.R4,
        ),)
    if transition == "removed":
        return ((
            f"channel-member-detach-requires-field-evidence:{spec.target_name}",
            RiskClass.R4,
        ),)
    return ((f"channel-membership-unresolved:{spec.target_name}", RiskClass.R5),)


def _require_channel_member_count(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    number = _as_int((spec.parameters or {}).get("port-channel-number"))
    if number is None:
        return ((f"channel-number-unresolved:{spec.target_name}", RiskClass.R5),)
    members = context.membership.current_sets.get(number, ())
    if not members:
        return ((f"channel-membership-empty:{spec.target_name}", RiskClass.R5),)
    if len(members) > MAX_CHANNEL_MEMBERS:
        return ((
            f"channel-member-count-exceeds-renderer-limit:{len(members)}",
            RiskClass.R3,
        ),)
    return ()


def _require_poe_capable(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    group = context.port_group(spec.target_name)
    if group is None or not group.poe_plus:
        return ((
            f"platform-unsupported:poe-capable-port:{spec.target_name}",
            RiskClass.R1,
        ),)
    return ()


def _require_poe_static(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    if (spec.parameters or {}).get("poe-mode") == "static":
        return ((
            "safety-precondition-unknown:poe-static-budget",
            RiskClass.R1,
        ),)
    return ()


def _require_copper_port(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    group = context.port_group(spec.target_name)
    if group is None or group.medium is not Medium.COPPER:
        return ((
            f"safety-precondition-unknown:copper-port-required:{spec.target_name}",
            RiskClass.R1,
        ),)
    return ()


def _require_portfast_mode(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    value = (spec.parameters or {}).get("portfast")
    mode = context.target_mode(spec.target_kind, spec.target_id, spec.target_name)
    if value == "edge" and mode != "access":
        return ((
            f"platform-unsupported:portfast-mode-match:{spec.target_name}",
            RiskClass.R2,
        ),)
    if value == "edge-trunk" and mode != "trunk":
        return ((
            f"platform-unsupported:portfast-mode-match:{spec.target_name}",
            RiskClass.R2,
        ),)
    return ()


def _edge_role_findings(
    context: _Context, spec: _Spec, prefix: str,
) -> tuple[_RequirementFinding, ...]:
    """Block a known or unverifiable non-edge role for PortFast and BPDU Guard.

    A planning link, ISP/transit port, aggregate member, Port-Channel or a
    core-role device is a known topology conflict: it may not be presented as an
    ordinary edge candidate. Only an unreferenced physical port keeps the ordinary
    candidate, and even then the field notes keep the real device state unverified.
    """
    if spec.target_kind is TargetKind.PORT_CHANNEL:
        return ((
            f"{prefix}-aggregate-role-unverified:{spec.target_name}",
            RiskClass.R3,
        ),)
    roles = context.port_roles(spec.target_name)
    known = roles & {"link", "isp", "transit"}
    if known:
        role = sorted(known)[0]
        return ((
            f"{prefix}-non-edge-topology:{role}:{spec.target_name}",
            RiskClass.R5,
        ),)
    if "channel-member" in roles:
        return ((
            f"{prefix}-aggregate-member-role-unverified:{spec.target_name}",
            RiskClass.R3,
        ),)
    if context.identity.role in {"core", "external-distribution"}:
        return ((
            f"{prefix}-core-role-unverified:{spec.target_name}",
            RiskClass.R5,
        ),)
    if roles == frozenset({"unreferenced"}):
        # No planned topology says this is an edge port; the field note keeps the
        # candidate honest instead of claiming the real device was verified.
        return ()
    return ((f"{prefix}-role-unverified:{spec.target_name}", RiskClass.R5),)


def _require_portfast_edge_role(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    return _edge_role_findings(context, spec, "portfast")


def _require_bpdu_guard_edge_role(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    return _edge_role_findings(context, spec, "bpdu-guard")


def _require_topology_wide(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    return (("safety-precondition-unknown:topology-wide-evidence", RiskClass.R5),)


def _require_mode_transition(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    transition = context.mode_transition(spec.target_kind, spec.target_id)
    if transition not in BLOCKED_MODE_TRANSITIONS:
        return ()
    risk = (
        RiskClass.R5
        if transition in {"trunk-to-access", "routed-to-switchport",
                          "switchport-to-routed"}
        else RiskClass.R4
    )
    return ((
        f"mode-transition-inherited:{transition}:{spec.target_name}",
        risk,
    ),)


def _require_admin_state(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    value = (spec.parameters or {}).get("admin-state")
    if value not in {"up", "down"}:
        return ()
    if spec.target_kind is TargetKind.PORT_CHANNEL:
        reason = (
            "port-channel-shutdown-requires-topology-evidence"
            if value == "down"
            else "port-channel-no-shutdown-requires-topology-evidence"
        )
        return ((reason, RiskClass.R5), ("aggregate-member-impact-unverified", RiskClass.R5))
    roles = context.port_roles(spec.target_name)
    if "channel-member" in roles:
        return ((
            f"channel-member-admin-state-requires-topology-evidence:{spec.target_name}",
            RiskClass.R5,
        ),)
    if value == "down":
        if roles & {"isp", "transit"}:
            return ((
                f"wan-or-transit-port-shutdown-requires-topology-evidence:"
                f"{spec.target_name}",
                RiskClass.R5,
            ),)
        if "link" in roles:
            return ((
                f"link-uplink-port-shutdown-requires-topology-evidence:"
                f"{spec.target_name}",
                RiskClass.R5,
            ),)
    return ()


_REQUIREMENT_EVALUATORS: Mapping[
    str, Callable[[_Context, _Spec, CommandEvidence | None], tuple[_RequirementFinding, ...]]
] = {
    "vlan-id-platform-range": _no_requirement,
    "vlan-name-platform-policy": _no_requirement,
    "channel-number-platform-range": _no_requirement,
    "channel-membership-consistent": _require_channel_membership,
    "channel-member-count-limit": _require_channel_member_count,
    "poe-capable-port": _require_poe_capable,
    "poe-static-budget": _require_poe_static,
    "copper-port-required": _require_copper_port,
    "portfast-mode-match": _require_portfast_mode,
    "portfast-edge-role": _require_portfast_edge_role,
    "bpdu-guard-edge-role": _require_bpdu_guard_edge_role,
    "topology-wide-evidence": _require_topology_wide,
    "mode-transition-consistency": _require_mode_transition,
    "admin-state-topology": _require_admin_state,
}


def _requirement_findings(
    context: _Context, spec: _Spec, row: CommandEvidence | None,
) -> tuple[_RequirementFinding, ...]:
    """Evaluate every blocking requirement the gate contract attaches to a topic."""
    topic = spec.topic
    if topic is None:
        return ()
    expected = BLOCKING_REQUIREMENT_CODES.get(topic, ())
    findings: list[_RequirementFinding] = []
    if row is not None:
        actual = tuple(
            requirement.code for requirement in row.requirements
            if requirement.kind is not RequirementKind.FIELD_NOTE
        )
        if actual != expected:
            findings.append((f"requirement-contract-mismatch:{topic.value}", RiskClass.R5))
    for code in expected:
        evaluator = _REQUIREMENT_EVALUATORS.get(code)
        if evaluator is None:
            findings.append((f"requirement-evaluator-missing:{code}", RiskClass.R5))
            continue
        findings.extend(evaluator(context, spec, row))
    return tuple(findings)


def _field_note_prerequisites(row: CommandEvidence | None) -> tuple[str, ...]:
    if row is None:
        return ()
    return tuple(
        f"field-note:{requirement.code}"
        for requirement in row.requirements
        if requirement.kind is RequirementKind.FIELD_NOTE
    )


def _mode_for(target: TargetKind) -> CommandMode:
    match target:
        case TargetKind.INTERFACE:
            return CommandMode.INTERFACE
        case TargetKind.PORT_CHANNEL:
            return CommandMode.PORT_CHANNEL
        case TargetKind.VLAN:
            return CommandMode.VLAN
        case TargetKind.DEVICE:
            return CommandMode.GLOBAL


def _mode_header(mode: CommandMode, name: str | None) -> str:
    match mode:
        case CommandMode.GLOBAL:
            return "global configuration"
        case CommandMode.VLAN:
            return f"vlan {name or ''}".strip()
        case CommandMode.INTERFACE | CommandMode.PORT_CHANNEL:
            return f"interface {name or ''}".strip()


def _check_id(assignment_id: UUID, check: CapabilityCheck) -> str:
    digest = hashlib.sha256(
        f"{assignment_id}|{check.scope}|{check.subject}|{check.capability.value}".encode()
    ).hexdigest()
    return "cap-" + digest[:12]


def _assessment_from_check(
    context: _Context, check: CapabilityCheck,
) -> CapabilityAssessment:
    return CapabilityAssessment(
        capability=check.capability,
        verdict=check.verdict.value,
        reason_code=check.reason_code,
        reason=check.reason,
        check_id=_check_id(context.assignment_id, check),
        evidence=check.evidence,
    )


def _unknown_assessment(identifier: str) -> CapabilityAssessment:
    return CapabilityAssessment(
        capability=_CAPABILITY_IDS.get(identifier),
        verdict="unknown",
        reason_code="preview-capability-check-missing",
        reason="CIS-02A reported no capability check for this intended command.",
        check_id=None,
        evidence=(),
    )


def _entry_capabilities(
    context: _Context, item: ConfigItem, spec: _Spec,
) -> tuple[CapabilityAssessment, ...]:
    identifiers = spec.capability_ids
    if not identifiers:
        return (item.capability,)
    assessments: list[CapabilityAssessment] = []
    own = item.capability.capability.value if item.capability.capability else ""
    for identifier in identifiers:
        if identifier == own:
            assessments.append(item.capability)
            continue
        check = context.device_check(identifier)
        assessments.append(
            _assessment_from_check(context, check) if check is not None
            else _unknown_assessment(identifier)
        )
    return tuple(assessments)


# --------------------------------------------------------------------------- #
# Per-item spec builders
# --------------------------------------------------------------------------- #


def _vlan_item(context: _Context, item: ConfigItem) -> tuple[_Entry, ...]:
    vlan_id = int(item.target_id)
    target_name = f"VLAN {vlan_id}"
    planned = item.planned.value if item.planned.present else None
    name = planned.get("name") if isinstance(planned, dict) else None
    if not item.planned.present:
        return (_Entry(_Spec(
            category=CandidateCategory.VLAN_DEFINITION, topic=None,
            target_kind=TargetKind.VLAN, target_id=str(vlan_id),
            target_name=target_name, field="definition",
            base_risk=RiskClass.R5,
            compose=lambda: "",
            force_block=(
                "vlan-removal-not-rendered",
                "baseline-only-cleanup-requires-field-verification",
            ),
        ), (item.capability,)),)
    transition = item.diff.transition
    risk = RiskClass.R0 if transition == "vlan-renamed" else RiskClass.R2
    entries: list[_Entry] = [
        _Entry(_Spec(
            category=CandidateCategory.VLAN_DEFINITION,
            topic=CommandTopic.VLAN,
            target_kind=TargetKind.VLAN, target_id=str(vlan_id),
            target_name=target_name, field="definition",
            base_risk=RiskClass.R2,
            mode=CommandMode.GLOBAL,
            parameters={"vlan-id": vlan_id},
            compose=lambda: f"vlan {vlan_id}",
        ), (item.capability,)),
    ]
    if isinstance(name, str):
        entries.append(_Entry(_Spec(
            category=CandidateCategory.VLAN_DEFINITION,
            topic=CommandTopic.VLAN_NAME,
            target_kind=TargetKind.VLAN, target_id=str(vlan_id),
            target_name=target_name, field="name",
            base_risk=risk,
            mode=CommandMode.VLAN,
            header_name=str(vlan_id),
            parameters={"vlan-name": name},
            compose=lambda: f"name {name}",
        ), (item.capability,)))
    return tuple(entries)


def _vlan_id_guard(
    context: _Context, value: int, *, allow_one: bool,
) -> tuple[str, ...]:
    if value == 1 and not allow_one:
        return ("vlan-1-is-default",)
    if value == 1:
        return ()
    if str(value) not in {str(item.vlan_id) for item in context.preview.vlan_scope.definitions}:
        return (f"vlan-not-defined-in-event-plan:{value}",)
    return ()


def _mode_transition_block(
    context: _Context, target: TargetKind, stable_id: str, item: ConfigItem,
) -> tuple[str, ...]:
    transition = context.mode_transition(target, stable_id) or item.diff.transition
    if transition == "access-to-trunk":
        return ("topology-role-unverified:access-to-trunk",)
    if transition == "trunk-to-access":
        return ("topology-role-unverified:trunk-to-access",)
    if transition == "routed-to-switchport":
        return ("routed-boundary-transition-unverified",)
    if transition == "switchport-to-routed":
        return ("routed-boundary-transition-unverified",)
    return ()


def _access_trunk_item(
    context: _Context, item: ConfigItem, *, target: TargetKind,
) -> tuple[_Entry, ...]:
    field = item.field
    name = item.target_name
    target_id = item.target_id
    transition_block = _mode_transition_block(context, target, target_id, item)
    transition_risk = RiskClass.R4 if transition_block else None
    if field == "mode":
        mode = item.planned.value
        if target is TargetKind.INTERFACE and mode == "access":
            return (_Entry(_Spec(
                category=CandidateCategory.ACCESS_MODE,
                topic=CommandTopic.ACCESS_MODE,
                target_kind=TargetKind.INTERFACE, target_id=target_id,
                target_name=name, field="mode",
                base_risk=RiskClass.R2,
                mode=_mode_for(target),
                compose=lambda: "switchport mode access",
                force_block=transition_block,
            ), (item.capability,)),)
        if target is TargetKind.INTERFACE and mode == "trunk":
            return (_Entry(_Spec(
                category=CandidateCategory.TRUNK_MODE,
                topic=CommandTopic.TRUNK_MODE,
                target_kind=TargetKind.INTERFACE, target_id=target_id,
                target_name=name, field="mode",
                base_risk=RiskClass.R2,
                mode=_mode_for(target),
                compose=lambda: "switchport mode trunk",
                force_block=transition_block,
            ), (item.capability,)),)
        if mode == "access":
            return (_Entry(_Spec(
                category=CandidateCategory.ACCESS_MODE,
                topic=CommandTopic.ACCESS_MODE,
                target_kind=TargetKind.PORT_CHANNEL, target_id=target_id,
                target_name=name, field="mode",
                base_risk=RiskClass.R2,
                mode=CommandMode.PORT_CHANNEL,
                compose=lambda: "switchport mode access",
                force_block=transition_block,
            ), (item.capability,)),)
        return (_Entry(_Spec(
            category=CandidateCategory.TRUNK_MODE,
            topic=CommandTopic.TRUNK_MODE,
            target_kind=TargetKind.PORT_CHANNEL, target_id=target_id,
            target_name=name, field="mode",
            base_risk=RiskClass.R2,
            mode=CommandMode.PORT_CHANNEL,
            compose=lambda: "switchport mode trunk",
            force_block=transition_block,
        ), (item.capability,)),)
    if field == "access_vlan":
        value = item.planned.value
        if not isinstance(value, int):
            return ()
        return (_Entry(_Spec(
            category=CandidateCategory.ACCESS_VLAN,
            topic=CommandTopic.ACCESS_VLAN,
            target_kind=target, target_id=target_id, target_name=name,
            field="access_vlan",
            base_risk=RiskClass.R2,
            mode=_mode_for(target),
            parameters={"vlan-id": value},
            compose=lambda: f"switchport access vlan {value}",
            force_block=(
                *transition_block,
                *_vlan_id_guard(context, value, allow_one=False),
            ),
            risk_floor=transition_risk,
        ), (item.capability,)),)
    if field == "native_vlan":
        value = item.planned.value
        if not isinstance(value, int):
            return ()
        return (_Entry(_Spec(
            category=CandidateCategory.NATIVE_VLAN,
            topic=CommandTopic.NATIVE_VLAN,
            target_kind=target, target_id=target_id, target_name=name,
            field="native_vlan",
            base_risk=RiskClass.R5,
            mode=_mode_for(target),
            parameters={"vlan-id": value},
            compose=lambda: f"switchport trunk native vlan {value}",
            prerequisites=(
                "field-topology-evidence-required",
                "management-or-uplink-role-unverified",
            ),
            force_block=(
                *transition_block,
                "r5-requires-field-topology-evidence",
                *_vlan_id_guard(context, value, allow_one=True),
            ),
        ), (item.capability,)),)
    if field == "allowed_vlans":
        raw = item.planned.value
        if not isinstance(raw, list):
            return ()
        values = tuple(sorted({item_ for item_ in raw if isinstance(item_, int)}))
        if not values:
            return ()
        missing = tuple(
            f"vlan-not-defined-in-event-plan:{value}" for value in values
            if str(value) not in {
                str(item_.vlan_id) for item_ in context.preview.vlan_scope.definitions
            }
        )
        joined = ",".join(str(value) for value in values)
        return (_Entry(_Spec(
            category=CandidateCategory.ALLOWED_VLANS,
            topic=CommandTopic.ALLOWED_VLANS,
            target_kind=target, target_id=target_id, target_name=name,
            field="allowed_vlans",
            base_risk=RiskClass.R2,
            mode=_mode_for(target),
            parameters={"vlan-list": values, "operation": "replace"},
            compose=lambda: f"switchport trunk allowed vlan {joined}",
            force_block=(*transition_block, *missing),
            risk_floor=transition_risk,
        ), (item.capability,)),)
    return ()


def _port_channel_item(context: _Context, item: ConfigItem) -> tuple[_Entry, ...]:
    number = _as_int(item.planned.value)
    if number is None:
        return (_Entry(_Spec(
            category=CandidateCategory.PORT_CHANNEL, topic=None,
            target_kind=TargetKind.PORT_CHANNEL, target_id=item.target_id,
            target_name=item.target_name, field="interface",
            base_risk=RiskClass.R3, compose=lambda: "",
            force_block=("port-channel-number-not-integer",),
        ), (item.capability,)),)
    channel = context.channel_for_interface(item.target_id)
    if channel is None:
        return (_Entry(_Spec(
            category=CandidateCategory.PORT_CHANNEL, topic=None,
            target_kind=TargetKind.PORT_CHANNEL, target_id=item.target_id,
            target_name=item.target_name, field="interface",
            base_risk=RiskClass.R3, compose=lambda: "",
            force_block=("port-channel-record-missing",),
        ), (item.capability,)),)
    name = channel.name or f"Port-Channel{number}"
    block: list[str] = [reason for reason in (
        port_channel_name_reason(channel.name, number),
    ) if reason]
    if not channel.member_ids:
        block.append("port-channel-without-members")
    return (_Entry(_Spec(
        category=CandidateCategory.PORT_CHANNEL,
        topic=CommandTopic.PORT_CHANNEL_INTERFACE,
        target_kind=TargetKind.PORT_CHANNEL, target_id=item.target_id,
        target_name=name, field="interface",
        base_risk=RiskClass.R3,
        mode=CommandMode.GLOBAL,
        parameters={"port-channel-number": number},
        compose=lambda: f"interface Port-Channel{number}",
        force_block=tuple(block),
    ), (item.capability,)),)


def _member_item(context: _Context, item: ConfigItem) -> tuple[_Entry, ...]:
    number = _as_int(item.planned.value)
    if number is None:
        transition = context.member_transition(item.target_id)
        reason = (
            f"channel-member-detach-requires-field-evidence:{item.target_name}"
            if transition == "removed"
            else f"channel-membership-unresolved:{item.target_name}"
        )
        return (_Entry(_Spec(
            category=CandidateCategory.PORT_CHANNEL, topic=None,
            target_kind=TargetKind.INTERFACE, target_id=item.target_id,
            target_name=item.target_name, field="member",
            base_risk=RiskClass.R4, compose=lambda: "",
            force_block=(
                reason,
                "cleanup-requires-field-verification",
            ),
        ), (item.capability,)),)
    channel = context.channel(number)
    if channel is None:
        return (_Entry(_Spec(
            category=CandidateCategory.PORT_CHANNEL, topic=None,
            target_kind=TargetKind.INTERFACE, target_id=item.target_id,
            target_name=item.target_name, field="member",
            base_risk=RiskClass.R3, compose=lambda: "",
            force_block=("channel-group-record-missing",),
        ), (item.capability,)),)
    spec = _channel_group_spec(context, item, channel, item.target_id, item.target_name)
    return (_Entry(spec, _entry_capabilities(context, item, spec)),)


def _channel_group_spec(
    context: _Context, item: ConfigItem, channel: PortChannelIntent,
    target_id: str, target_name: str,
) -> _Spec:
    number = channel.number
    transition = context.member_transition(target_id)
    protocol = context.member_protocol_transition(target_id)
    membership_block: tuple[str, ...] = ()
    membership_risk: RiskClass | None = None
    prerequisites: tuple[str, ...] = ()
    if transition == "migrated":
        membership_block = (
            f"channel-migration-requires-source-channel-evidence:{target_name}",
        )
        membership_risk = RiskClass.R4
    elif transition == "removed":
        membership_block = (
            f"channel-member-detach-requires-field-evidence:{target_name}",
        )
        membership_risk = RiskClass.R4
    elif transition == "replaced":
        # The same channel number can name a different logical object.
        membership_block = (
            f"channel-object-identity-changed:{target_name}:{number}",
            "cleanup-requires-field-verification",
        )
        membership_risk = RiskClass.R4
    elif transition == "unknown":
        membership_block = (f"channel-membership-unresolved:{target_name}",)
        membership_risk = RiskClass.R5
    else:
        ref = context.membership.current.get(target_id)
        if ref is None or ref.number != number:
            membership_block = (f"channel-membership-inconsistent:{target_name}",)
            membership_risk = RiskClass.R5
    if protocol == "protocol-switch":
        # static and LACP are different aggregation protocols: switching between
        # them needs the old configuration cleaned up, peer compatibility and
        # field evidence, so no channel-group candidate is rendered.
        membership_block = (
            *membership_block,
            f"aggregation-protocol-change-requires-field-evidence:{target_name}",
            "cleanup-requires-field-verification",
        )
        membership_risk = _raise_risk(
            membership_risk or RiskClass.R3, RiskClass.R4,
        )
    elif protocol == "lacp-mode-change":
        # active <-> passive is not a protocol switch, but it changes negotiation
        # behavior and needs the peer precondition confirmed; it is never claimed
        # to be safe without field evidence.
        prerequisites = ("lacp-negotiation-change-requires-peer-evidence",)
    if channel.lacp == "static":
        return _Spec(
            category=CandidateCategory.PORT_CHANNEL,
            topic=CommandTopic.CHANNEL_GROUP_STATIC,
            target_kind=TargetKind.INTERFACE, target_id=target_id,
            target_name=target_name, field="member",
            base_risk=RiskClass.R3,
            mode=CommandMode.INTERFACE,
            parameters={"port-channel-number": number, "mode": "on"},
            compose=lambda: f"channel-group {number} mode on",
            capability_ids=(CiscoCapability.PORT_CHANNEL.value,),
            prerequisites=prerequisites,
            force_block=membership_block,
            risk_floor=membership_risk,
        )
    mode = channel.lacp
    return _Spec(
        category=CandidateCategory.LACP_MODE,
        topic=CommandTopic.CHANNEL_GROUP_LACP,
        target_kind=TargetKind.INTERFACE, target_id=target_id,
        target_name=target_name, field="member",
        base_risk=RiskClass.R3,
        mode=CommandMode.INTERFACE,
        parameters={"port-channel-number": number, "mode": mode},
        compose=lambda: f"channel-group {number} mode {mode}",
        capability_ids=(CiscoCapability.PORT_CHANNEL.value, Capability.LACP.value),
        prerequisites=prerequisites,
        force_block=membership_block,
        risk_floor=membership_risk,
    )


def _as_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _channel_membership_item(context: _Context, item: ConfigItem) -> tuple[_Entry, ...]:
    """A changed channel LACP mode or member set re-issues channel-group."""
    channel = context.channel_for_interface(item.target_id)
    if channel is None:
        return (_Entry(_Spec(
            category=CandidateCategory.PORT_CHANNEL, topic=None,
            target_kind=TargetKind.PORT_CHANNEL, target_id=item.target_id,
            target_name=item.target_name, field=item.field,
            base_risk=RiskClass.R3, compose=lambda: "",
            force_block=("channel-group-record-missing",),
        ), (item.capability,)),)
    entries: list[_Entry] = []
    for member_id, member_name in zip(channel.member_ids, channel.member_names, strict=False):
        spec = _channel_group_spec(
            context, item, channel, str(member_id), str(member_name),
        )
        entries.append(_Entry(spec, _entry_capabilities(context, item, spec)))
    if item.field == "member_ids" and item.baseline.state == "planning-baseline":
        entries.append(_Entry(_Spec(
            category=CandidateCategory.PORT_CHANNEL, topic=None,
            target_kind=TargetKind.PORT_CHANNEL, target_id=item.target_id,
            target_name=item.target_name, field="member-removal",
            base_risk=RiskClass.R4, compose=lambda: "",
            force_block=(
                "channel-member-removal-requires-field-evidence",
                "cleanup-requires-field-verification",
            ),
        ), (item.capability,)))
    return tuple(entries)


def _interface_setting_item(
    context: _Context, item: ConfigItem,
) -> tuple[_Entry, ...]:
    target_id = item.target_id
    name = item.target_name
    field = item.field
    if field == "description":
        value = item.planned.value
        if not isinstance(value, str):
            return ()
        return (_Entry(_Spec(
            category=CandidateCategory.DESCRIPTION,
            topic=CommandTopic.DESCRIPTION,
            target_kind=TargetKind.INTERFACE, target_id=target_id,
            target_name=name, field="description",
            base_risk=RiskClass.R0,
            mode=CommandMode.INTERFACE,
            parameters={"description": value},
            compose=lambda: f"description {value}",
        ), (item.capability,)),)
    if field == "speed":
        value = item.planned.value
        if not isinstance(value, (int, str)):
            return ()
        text = "auto" if value == "auto" else str(value)
        return (_Entry(_Spec(
            category=CandidateCategory.SPEED, topic=CommandTopic.SPEED,
            target_kind=TargetKind.INTERFACE, target_id=target_id,
            target_name=name, field="speed",
            base_risk=RiskClass.R1,
            mode=CommandMode.INTERFACE,
            parameters={"speed": text},
            compose=lambda: f"speed {text}",
        ), (item.capability,)),)
    if field == "duplex":
        value = item.planned.value
        if not isinstance(value, str):
            return ()
        return (_Entry(_Spec(
            category=CandidateCategory.DUPLEX, topic=CommandTopic.DUPLEX,
            target_kind=TargetKind.INTERFACE, target_id=target_id,
            target_name=name, field="duplex",
            base_risk=RiskClass.R1,
            mode=CommandMode.INTERFACE,
            parameters={"duplex": value},
            compose=lambda: f"duplex {value}",
        ), (item.capability,)),)
    if field == "poe_mode":
        value = item.planned.value
        if not isinstance(value, str):
            return ()
        return (_Entry(_Spec(
            category=CandidateCategory.POE_MODE, topic=CommandTopic.POE_MODE,
            target_kind=TargetKind.INTERFACE, target_id=target_id,
            target_name=name, field="poe_mode",
            base_risk=RiskClass.R1,
            mode=CommandMode.INTERFACE,
            parameters={"poe-mode": value},
            compose=lambda: f"power inline {value}",
        ), (item.capability,)),)
    if field == "portfast":
        value = item.planned.value
        if not isinstance(value, str):
            return ()
        portfast_text = {
            "edge": "spanning-tree portfast",
            "edge-trunk": "spanning-tree portfast trunk",
            "disabled": "spanning-tree portfast disable",
        }.get(value)
        if portfast_text is None:
            return ()
        return (_Entry(_Spec(
            category=CandidateCategory.PORTFAST, topic=CommandTopic.PORTFAST,
            target_kind=TargetKind.INTERFACE, target_id=target_id,
            target_name=name, field="portfast",
            base_risk=RiskClass.R2,
            mode=CommandMode.INTERFACE,
            parameters={"portfast": value},
            compose=lambda: portfast_text,
        ), (item.capability,)),)
    if field == "bpdu_guard":
        value = item.planned.value
        if value not in {"enabled", "disabled"}:
            return ()
        guard = "enable" if value == "enabled" else "disable"
        return (_Entry(_Spec(
            category=CandidateCategory.BPDU_GUARD, topic=CommandTopic.BPDU_GUARD,
            target_kind=TargetKind.INTERFACE, target_id=target_id,
            target_name=name, field="bpdu_guard",
            base_risk=RiskClass.R2,
            mode=CommandMode.INTERFACE,
            parameters={"bpdu-guard": guard},
            compose=lambda: f"spanning-tree bpduguard {guard}",
        ), (item.capability,)),)
    if field == "admin_state":
        value = item.planned.value
        if value not in {"up", "down"}:
            return ()
        admin_text = "shutdown" if value == "down" else "no shutdown"
        return (_Entry(_Spec(
            category=CandidateCategory.ADMIN_SHUTDOWN,
            topic=CommandTopic.ADMIN_SHUTDOWN,
            target_kind=TargetKind.INTERFACE, target_id=target_id,
            target_name=name, field="admin_state",
            base_risk=RiskClass.R1,
            mode=CommandMode.INTERFACE,
            parameters={"admin-state": value},
            compose=lambda: admin_text,
        ), (item.capability,)),)
    if field == "shutdown_intent":
        value = item.planned.value
        source = value.get("source") if isinstance(value, dict) else None
        if source != "reviewed-default-policy":
            return ()
        return (_Entry(_Spec(
            category=CandidateCategory.UNUSED_SHUTDOWN, topic=None,
            target_kind=TargetKind.INTERFACE, target_id=target_id,
            target_name=name, field="shutdown_intent",
            base_risk=RiskClass.R1, compose=lambda: "",
            prerequisites=("unused-port-policy-requires-field-verification",),
            force_block=(
                "unused-port-policy-requires-field-verification",
                "policy-does-not-prove-the-port-is-unused",
            ),
        ), (item.capability,)),)
    return ()


def _device_state_item(context: _Context, item: ConfigItem) -> tuple[_Entry, ...]:
    field = item.field
    device_id = str(context.assignment_id)
    if field == "spanning-tree-mode":
        return (_Entry(_Spec(
            category=CandidateCategory.RAPID_PVST,
            topic=CommandTopic.RAPID_PVST,
            target_kind=TargetKind.DEVICE, target_id=device_id,
            target_name=context.hostname, field="spanning-tree-mode",
            base_risk=RiskClass.R5,
            mode=CommandMode.GLOBAL,
            compose=lambda: "spanning-tree mode rapid-pvst",
            prerequisites=("field-topology-evidence-required",),
            force_block=(
                "topology-wide-change-requires-field-evidence",
                "current-stp-state-not-read",
            ),
        ), (item.capability,)),)
    if field == "vtp-mode":
        return (_Entry(_Spec(
            category=CandidateCategory.VTP_TRANSPARENT,
            topic=CommandTopic.VTP_TRANSPARENT,
            target_kind=TargetKind.DEVICE, target_id=device_id,
            target_name=context.hostname, field="vtp-mode",
            base_risk=RiskClass.R5,
            mode=CommandMode.GLOBAL,
            compose=lambda: "vtp mode transparent",
            prerequisites=("field-topology-evidence-required",),
            force_block=(
                "topology-wide-change-requires-field-evidence",
                "current-vtp-mode-and-domain-not-read",
            ),
        ), (item.capability,)),)
    if field == "root-priority":
        value = item.planned.value
        priority = value.get("priority") if isinstance(value, dict) else None
        parameters: dict[str, object] = (
            {"priority": priority} if isinstance(priority, int) else {}
        )
        return (_Entry(_Spec(
            category=CandidateCategory.ROOT_PRIORITY,
            topic=CommandTopic.ROOT_PRIORITY,
            target_kind=TargetKind.DEVICE, target_id=device_id,
            target_name=context.hostname, field="root-priority",
            base_risk=RiskClass.R5,
            mode=CommandMode.GLOBAL,
            parameters=parameters,
            compose=lambda: "",
            prerequisites=("field-topology-evidence-required",),
            force_block=(
                "root-priority-requires-explicit-vlan-scope",
                "topology-wide-change-requires-field-evidence",
                "current-root-and-priority-not-read",
            ),
        ), (item.capability,)),)
    if field == "unused-port-shutdown":
        return (_Entry(_Spec(
            category=CandidateCategory.UNUSED_SHUTDOWN, topic=None,
            target_kind=TargetKind.DEVICE, target_id=device_id,
            target_name=context.hostname, field="unused-port-shutdown",
            base_risk=RiskClass.R1, compose=lambda: "",
            prerequisites=("unused-port-policy-requires-field-verification",),
            force_block=(
                "unused-port-policy-requires-field-verification",
                "policy-does-not-prove-the-port-is-unused",
            ),
        ), (item.capability,)),)
    return ()


def _routed_item(context: _Context, item: ConfigItem) -> tuple[_Entry, ...]:
    category = (
        CandidateCategory.PORT_CHANNEL
        if item.target_kind == "port-channel"
        else CandidateCategory.ACCESS_MODE
    )
    reason = (
        "routed-port-channel-not-l2"
        if item.target_kind == "port-channel" else "routed-port-not-l2"
    )
    return (_Entry(_Spec(
        category=category, topic=None,
        target_kind=TargetKind(item.target_kind), target_id=item.target_id,
        target_name=item.target_name, field=item.field,
        base_risk=RiskClass.R2, compose=lambda: "",
        force_unsupported=(reason,),
    ), (item.capability,)),)


def _removal_item(context: _Context, item: ConfigItem) -> tuple[_Entry, ...]:
    category = _REMOVAL_CATEGORY.get(item.category, CandidateCategory.ADMIN_SHUTDOWN)
    reasons = [
        "removal-not-rendered",
        "baseline-only-cleanup-requires-field-verification",
    ]
    if category is CandidateCategory.VLAN_DEFINITION:
        reasons.insert(0, "vlan-removal-not-rendered")
        # An unreferenced VLAN is not evidence that the real device may delete it.
        reasons.append("vlan-unreferenced-does-not-authorise-delete")
    return (_Entry(_Spec(
        category=category, topic=None,
        target_kind=TargetKind(item.target_kind), target_id=item.target_id,
        target_name=item.target_name, field=item.field,
        base_risk=RiskClass.R4, compose=lambda: "",
        prerequisites=("cleanup-requires-field-verification",),
        force_block=tuple(reasons),
    ), (item.capability,)),)


_REMOVAL_CATEGORY: Mapping[object, CandidateCategory] = {
    "vlan": CandidateCategory.VLAN_DEFINITION,
    "access": CandidateCategory.ACCESS_MODE,
    "trunk": CandidateCategory.TRUNK_MODE,
    "port-channel": CandidateCategory.PORT_CHANNEL,
    "lacp": CandidateCategory.LACP_MODE,
    "description": CandidateCategory.DESCRIPTION,
    "shutdown": CandidateCategory.ADMIN_SHUTDOWN,
    "speed": CandidateCategory.SPEED,
    "duplex": CandidateCategory.DUPLEX,
    "poe": CandidateCategory.POE_MODE,
    "portfast": CandidateCategory.PORTFAST,
    "bpdu-guard": CandidateCategory.BPDU_GUARD,
    "root-priority": CandidateCategory.ROOT_PRIORITY,
    "stp": CandidateCategory.RAPID_PVST,
    "vtp": CandidateCategory.VTP_TRANSPARENT,
    "unused-port-policy": CandidateCategory.UNUSED_SHUTDOWN,
    "routed-boundary": CandidateCategory.ACCESS_MODE,
}


def _item_entries(context: _Context, item: ConfigItem) -> tuple[_Entry, ...]:
    if not item.planned.present:
        return _removal_item(context, item)
    if not item.diff.changed:
        return ()
    category = item.category.value
    target_kind = item.target_kind
    if category == "vlan":
        return _vlan_item(context, item)
    if category in {"access", "trunk"}:
        return _access_trunk_item(
            context, item,
            target=TargetKind.PORT_CHANNEL if target_kind == "port-channel"
            else TargetKind.INTERFACE,
        )
    if category == "port-channel":
        if item.field == "number" and target_kind == "port-channel":
            return _port_channel_item(context, item)
        if item.field == "port_channel":
            return _member_item(context, item)
        if item.field in {"member_ids", "lacp"}:
            return _channel_membership_item(context, item)
        if target_kind == "port-channel":
            return _channel_setting_item(context, item)
        return ()
    if category == "lacp":
        return _channel_membership_item(context, item)
    if category in {"stp", "vtp", "root-priority", "unused-port-policy"}:
        return _device_state_item(context, item)
    if category == "routed-boundary":
        return _routed_item(context, item)
    if category in {"speed", "duplex", "description", "shutdown", "poe", "portfast",
                    "bpdu-guard"}:
        if target_kind == "port-channel":
            return _channel_setting_item(context, item)
        return _interface_setting_item(context, item)
    return ()


def _channel_setting_item(context: _Context, item: ConfigItem) -> tuple[_Entry, ...]:
    field = item.field
    name = item.target_name
    target_id = item.target_id
    if field == "description":
        value = item.planned.value
        if not isinstance(value, str):
            return ()
        return (_Entry(_Spec(
            category=CandidateCategory.DESCRIPTION, topic=CommandTopic.DESCRIPTION,
            target_kind=TargetKind.PORT_CHANNEL, target_id=target_id,
            target_name=name, field="description",
            base_risk=RiskClass.R0, mode=CommandMode.PORT_CHANNEL,
            parameters={"description": value},
            compose=lambda: f"description {value}",
        ), (item.capability,)),)
    if field == "admin_state":
        value = item.planned.value
        if value not in {"up", "down"}:
            return ()
        admin_text = "shutdown" if value == "down" else "no shutdown"
        return (_Entry(_Spec(
            category=CandidateCategory.ADMIN_SHUTDOWN,
            topic=CommandTopic.ADMIN_SHUTDOWN,
            target_kind=TargetKind.PORT_CHANNEL, target_id=target_id,
            target_name=name, field="admin_state",
            base_risk=RiskClass.R1, mode=CommandMode.PORT_CHANNEL,
            parameters={"admin-state": value},
            compose=lambda: admin_text,
        ), (item.capability,)),)
    if field == "portfast":
        value = item.planned.value
        if not isinstance(value, str):
            return ()
        portfast_text = {
            "edge": "spanning-tree portfast",
            "edge-trunk": "spanning-tree portfast trunk",
            "disabled": "spanning-tree portfast disable",
        }.get(value)
        if portfast_text is None:
            return ()
        return (_Entry(_Spec(
            category=CandidateCategory.PORTFAST, topic=CommandTopic.PORTFAST,
            target_kind=TargetKind.PORT_CHANNEL, target_id=target_id,
            target_name=name, field="portfast",
            base_risk=RiskClass.R2, mode=CommandMode.PORT_CHANNEL,
            parameters={"portfast": value},
            compose=lambda: portfast_text,
        ), (item.capability,)),)
    if field == "bpdu_guard":
        value = item.planned.value
        if value not in {"enabled", "disabled"}:
            return ()
        guard = "enable" if value == "enabled" else "disable"
        return (_Entry(_Spec(
            category=CandidateCategory.BPDU_GUARD, topic=CommandTopic.BPDU_GUARD,
            target_kind=TargetKind.PORT_CHANNEL, target_id=target_id,
            target_name=name, field="bpdu_guard",
            base_risk=RiskClass.R2, mode=CommandMode.PORT_CHANNEL,
            parameters={"bpdu-guard": guard},
            compose=lambda: f"spanning-tree bpduguard {guard}",
        ), (item.capability,)),)
    return ()


# --------------------------------------------------------------------------- #
# Candidate construction
# --------------------------------------------------------------------------- #


def _raise_risk(current: RiskClass, candidate: RiskClass) -> RiskClass:
    return (
        candidate if _RISK_RANK[candidate] > _RISK_RANK[current] else current
    )


def _risk_for(context: _Context, item: ConfigItem, spec: _Spec) -> RiskClass:
    risk = spec.base_risk
    if spec.risk_floor is not None:
        risk = _raise_risk(risk, spec.risk_floor)
    if item.diff.cleanup:
        risk = _raise_risk(risk, RiskClass.R4)
    if item.diff.transition in {
        "access-to-trunk", "trunk-to-access", "routed-to-switchport",
        "switchport-to-routed", "port-channel-member-to-independent",
        "port-channel-member-migrate", "vlan-removed", "assignment-removed",
    }:
        risk = _raise_risk(risk, RiskClass.R4)
    if item.risk.level == "intent-invalid":
        risk = _raise_risk(risk, RiskClass.R5)
    if context.identity.role in {"core", "external-distribution"} and (
        spec.category
        in {
            CandidateCategory.RAPID_PVST,
            CandidateCategory.VTP_TRANSPARENT,
            CandidateCategory.ROOT_PRIORITY,
            CandidateCategory.NATIVE_VLAN,
        }
    ):
        risk = _raise_risk(risk, RiskClass.R5)
    return risk


def _provenance(item: ConfigItem) -> CandidateProvenance:
    return CandidateProvenance(
        preview_item_id=item.item_id,
        b1_category=item.category.value,
        b1_field=item.field,
        change_id=item.diff.change_id,
        transition=item.diff.transition,
        planned_source=item.planned.source,
        baseline_state=item.baseline.state,
        diff_changed=item.diff.changed,
        cleanup=item.diff.cleanup,
    )


def _syntax_evidence(evidence: CommandEvidence) -> SyntaxEvidence:
    return SyntaxEvidence(
        evidence_id=evidence.evidence_id,
        topic=evidence.topic.value,
        release=evidence.release_label,
        command=evidence.command,
        grammar=evidence.grammar,
        review_state=evidence.review.state.value,
        source_url=evidence.source_url,
        source_section=evidence.source_section,
        limits=evidence.limits,
        exclusions=evidence.exclusions,
    )


def _capability_evidence(
    assessments: tuple[CapabilityAssessment, ...],
) -> tuple[CapabilityEvidence, ...]:
    return tuple(
        CapabilityEvidence(
            capability=(
                assessment.capability.value if assessment.capability is not None else None
            ),
            verdict=assessment.verdict,
            reason_code=assessment.reason_code,
            check_id=assessment.check_id,
        )
        for assessment in assessments
    )


def _blocked_conflicts(item: ConfigItem, conflicts: tuple[IntentConflict, ...]) -> tuple[str, ...]:
    return tuple(
        f"intent-conflict:{conflict.code}"
        for conflict in conflicts
        if conflict.target in {item.target_name, item.target_id}
        and conflict.severity == "ERROR"
    )


def _port_channel_number_maximum(context: _Context) -> int | None:
    """Reviewed Port-Channel number bound for this exact scope, if available."""
    if context.family is None or context.release is None:
        return None
    rows = context.registry.applicable(
        context.family, context.pid, context.release, context.license,
        CommandTopic.PORT_CHANNEL_INTERFACE,
    )
    for row in rows:
        for rule in row.parameters:
            if rule.name == "port-channel-number" and rule.maximum is not None:
                return rule.maximum
    return None


def _vlan_target_reasons(vlan_id: int) -> tuple[str, ...]:
    if vlan_id in {1002, 1003, 1004, 1005}:
        return (f"target-invalid:vlan-reserved:{vlan_id}",)
    if vlan_id == 1:
        # VLAN 1 exists by default; creating or renaming it is a change to the
        # default VLAN and stays blocked rather than being silently allowed.
        return ("target-invalid:vlan-default:1",)
    if not 1 <= vlan_id <= 4094:
        return (f"target-invalid:vlan-range:{vlan_id}",)
    return ()


def _target_reasons(context: _Context, spec: _Spec) -> tuple[str, ...]:
    """Validate the configuration target itself, not only the command line.

    A command that enters a VLAN or Port-Channel configuration mode is only
    legitimate when that target object is legitimate, so every candidate for the
    same target inherits the same target-level block.
    """
    reasons: list[str] = []
    if spec.target_kind is TargetKind.INTERFACE:
        port = context.port(spec.target_name)
        name_reason = interface_name_reason(
            spec.target_name, context.profile, port.stack_member if port else None,
        )
        if name_reason is not None:
            reasons.append(name_reason)
    elif spec.target_kind is TargetKind.PORT_CHANNEL:
        channel = context.channel_for_interface(spec.target_id)
        if channel is None:
            reasons.append("target-invalid:port-channel-record-missing")
        else:
            name_reason = port_channel_name_reason(spec.target_name, channel.number)
            if name_reason is not None:
                reasons.append(name_reason)
            maximum = _port_channel_number_maximum(context)
            if maximum is None:
                reasons.append(
                    f"target-invalid:port-channel-range-unknown:{channel.number}"
                )
            elif not 1 <= channel.number <= maximum:
                reasons.append(
                    f"target-invalid:port-channel-number:{channel.number}:{maximum}"
                )
    elif spec.target_kind is TargetKind.VLAN:
        raw = spec.target_id
        vlan_id = int(raw) if isinstance(raw, str) and raw.isdigit() else None
        if vlan_id is None:
            reasons.append(f"target-invalid:vlan-id:{spec.target_id}")
        else:
            reasons.extend(_vlan_target_reasons(vlan_id))
    return tuple(dict.fromkeys(reasons))


def _build_candidate(
    context: _Context, item: ConfigItem, entry: _Entry,
) -> Candidate:
    spec = entry.spec
    evidence: CommandEvidence | None = None
    evidence_blockers: tuple[str, ...] = ()
    if spec.topic is not None:
        evidence, evidence_blockers = context.evidence(spec.topic)

    verdict = "not-required"
    for assessment in entry.capabilities:
        if _CAPABILITY_RANK[assessment.verdict] > _CAPABILITY_RANK[verdict]:
            verdict = assessment.verdict
    capability_reason = (
        entry.capabilities[0].reason_code if entry.capabilities else "unknown"
    )

    risk = _risk_for(context, item, spec)
    requirement_findings = _requirement_findings(context, spec, evidence)
    for _reason, floor in requirement_findings:
        risk = _raise_risk(risk, floor)
    reasons: list[str] = []
    unsupported: list[str] = list(entry.extra_unsupported)
    unsupported.extend(spec.force_unsupported)
    if verdict == "unsupported":
        unsupported.append(
            f"capability-unsupported:{capability_reason}:{spec.target_name}"
        )
    if risk is RiskClass.R6:
        unsupported.append("dangerous-operation-denied")

    if context.hard_block:
        status = CandidateStatus.BLOCKED
        reasons = [
            f"device-identity-incomplete:{code}" for code in context.hard_block
        ]
    elif unsupported:
        status = CandidateStatus.UNSUPPORTED
        reasons = unsupported
    elif verdict == "unknown":
        status = CandidateStatus.BLOCKED
        reasons = [f"capability-unknown:{capability_reason}:{spec.target_name}"]
    elif spec.force_block or entry.extra_block or requirement_findings:
        status = CandidateStatus.BLOCKED
        reasons = [
            *entry.extra_block,
            *spec.force_block,
            *(reason for reason, _floor in requirement_findings),
        ]
    elif risk is RiskClass.R5:
        status = CandidateStatus.BLOCKED
        reasons = ["r5-requires-field-topology-evidence"]
    elif risk is RiskClass.R4:
        status = CandidateStatus.BLOCKED
        reasons = ["cleanup-requires-field-verification"]
    elif evidence_blockers:
        status = CandidateStatus.BLOCKED
        reasons = list(evidence_blockers)
    else:
        status = CandidateStatus.CANDIDATE

    reasons.extend(_blocked_conflicts(item, context.preview.device.conflicts))
    reasons.extend(reason for reason, _floor in requirement_findings)

    target_reasons = _target_reasons(context, spec) if spec.topic is not None else ()
    if target_reasons:
        if status is CandidateStatus.CANDIDATE:
            status = CandidateStatus.BLOCKED
        reasons.extend(target_reasons)
        reasons.append(f"unsafe-target:{spec.field}:{spec.target_name}")

    parameters = dict(spec.parameters or {})
    text_violations = _text_policy_violations(evidence, parameters)
    if status is CandidateStatus.CANDIDATE:
        violations = (*validate_parameters(evidence, parameters), *text_violations)
        if violations:
            status = CandidateStatus.BLOCKED
            reasons = list(dict.fromkeys(violations))
            if any(value.startswith("unsafe-text-class:") for value in violations):
                reasons.append(f"unsafe-text:{spec.field}:{spec.target_name}")
    else:
        # A blocked candidate still reports a structurally invalid argument.
        reasons.extend(
            validate_parameters(evidence, parameters, require_all=False)
        )
        reasons.extend(text_violations)

    candidate_text: str | None = None
    if status is CandidateStatus.CANDIDATE:
        candidate_text = spec.compose()
        if not _single_line(candidate_text):
            status = CandidateStatus.BLOCKED
            reasons.append(f"unsafe-text:{spec.field}:{spec.target_name}")
            reasons.append("unsafe-text-class:not-a-single-line")
            candidate_text = None

    field_notes = _field_note_prerequisites(evidence)
    field_verification = (
        item.risk.requires_field_verification
        or bool(item.diff.cleanup)
        or risk in {RiskClass.R4, RiskClass.R5}
        or bool(requirement_findings)
        or bool(field_notes)
        or "field-topology-evidence-required" in spec.prerequisites
        or "lacp-negotiation-change-requires-peer-evidence" in spec.prerequisites
    )
    draft = Candidate(
        candidate_id=_candidate_id(
            context.assignment_id, spec.category, spec.target_kind,
            spec.target_id, spec.field,
        ),
        assignment_id=context.assignment_id,
        target=RenderTarget(
            kind=spec.target_kind, stable_id=spec.target_id, name=spec.target_name,
        ),
        category=spec.category,
        command_context=CommandContext(
            mode=spec.mode or _mode_for(spec.target_kind),
            mode_header=_mode_header(
                spec.mode or _mode_for(spec.target_kind),
                spec.header_name or spec.target_name,
            ),
            target_name=spec.target_name,
        ),
        status=status,
        candidate_text=candidate_text,
        parameters={
            key: _json_value(value)
            for key, value in (spec.parameters or {}).items()
        },
        provenance=_provenance(item),
        capability_evidence=_capability_evidence(entry.capabilities),
        syntax_evidence=(
            (_syntax_evidence(evidence),) if evidence is not None else ()
        ),
        syntax_validation=SyntaxValidation(
            level=(
                SyntaxValidationLevel.DICTIONARY_ONLY
                if status is CandidateStatus.CANDIDATE
                else SyntaxValidationLevel.NOT_RUN
            ),
        ),
        risk_class=risk,
        potential_connectivity_impact=(
            risk in _CONNECTIVITY_RISK
            or spec.category in CONNECTIVITY_RISK_CATEGORIES
        ),
        requires_field_verification=field_verification,
        prerequisites=tuple(dict.fromkeys(
            (*spec.prerequisites, *field_notes, *(
                ("field-verification-required",)
                if item.risk.requires_field_verification or requirement_findings
                else ()
            ), *(
                ("cleanup-requires-field-verification",)
                if item.diff.cleanup else ()
            ))
        )),
        blocking_reasons=tuple(dict.fromkeys(reasons)),
        candidate_fingerprint="0" * 64,
    )
    return draft.model_copy(update={"candidate_fingerprint": candidate_fingerprint(draft)})


def _single_line(text: str) -> bool:
    if not text or len(text) > 512:
        return False
    if any(character in text for character in ("\n", "\r", "\x00", "\x1b")):
        return False
    return text == text.strip()


def _json_value(value: object) -> JsonValue:
    """Convert validated parameters into a JSON value without changing text."""
    if isinstance(value, tuple):
        return [_json_value(entry) for entry in value]
    if isinstance(value, list):
        return [_json_value(entry) for entry in value]
    if isinstance(value, dict):
        return {str(key): _json_value(entry) for key, entry in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return cast(JsonValue, value)
    return cast(JsonValue, str(value))


# --------------------------------------------------------------------------- #
# Context construction
# --------------------------------------------------------------------------- #


def _context(
    revision: PlanRevision,
    intent: Layer2Intent,
    preview: Layer2DeviceConfigPreview,
    registry: CommandEvidenceRegistry,
) -> _Context:
    identity = preview.device.identity
    device_intent = next(
        (item for item in intent.devices if item.identity.assignment_id == identity.assignment_id),
        None,
    )
    if device_intent is None:
        raise RenderTargetNotFound("Assignment not found in this saved revision intent")
    for attribute in (
        "hostname", "pid", "software_image", "software_license", "stack_identity",
    ):
        if getattr(device_intent.identity, attribute) != getattr(identity, attribute):
            raise RenderBindingError("preview-rebuild-mismatch")

    pid = (identity.pid or "").upper()
    profile = PROFILES.get(pid) if pid else None
    release = identity.software_image
    checks: dict[CheckKey, CapabilityCheck] = {
        (check.scope, check.subject, check.capability.value): check
        for check in preview.device.capability_checks
    }
    vlan_scope = frozenset(
        definition.vlan_id for definition in preview.vlan_scope.definitions
    )
    hard: list[str] = []
    if identity.pid_evidence != "exact-verified-pid" or profile is None:
        hard.append("pid-not-verified")
    if release is None:
        hard.append("release-unmatched")
    if preview.device.deployability.identity_gate.status != "pass":
        hard.extend(preview.device.deployability.identity_gate.codes)
    if identity.stack_identity == "unresolved":
        hard.append("stack-identity-unresolved")
    if profile is not None and identity.family is not None and (
        identity.family != profile.family
    ):
        hard.append("family-mismatch")
    if identity.stack_members:
        member_pids = {member.pid for member in identity.stack_members}
        if len(member_pids) != 1 or None in member_pids:
            hard.append("stack-identity-unresolved")
        if any(member.state != "ready" for member in identity.stack_members):
            hard.append("stack-member-not-ready")
    if preview.device.deployability.intent_gate != "valid":
        hard.append("intent-not-valid")
    return _Context(
        revision=revision,
        intent=intent,
        device_intent=device_intent,
        preview=preview,
        registry=registry,
        profile=profile,
        pid=pid,
        release=release,
        license=identity.software_license,
        checks=checks,
        vlan_scope=vlan_scope,
        hard_block=tuple(dict.fromkeys(hard)),
        membership=_build_membership(device_intent),
        mode_transitions=_build_mode_transitions(device_intent),
    )


def _document(
    context: _Context, candidates: tuple[Candidate, ...],
) -> L2CliCandidateDocument:
    identity = context.identity
    rendered = tuple(
        candidate.category.value for candidate in candidates
        if candidate.status is CandidateStatus.CANDIDATE
    )
    summary = RenderSummary(
        total=len(candidates),
        candidates=sum(
            1 for item in candidates if item.status is CandidateStatus.CANDIDATE
        ),
        blocked=sum(1 for item in candidates if item.status is CandidateStatus.BLOCKED),
        unsupported=sum(
            1 for item in candidates if item.status is CandidateStatus.UNSUPPORTED
        ),
        categories_rendered=tuple(dict.fromkeys(rendered)),
    )
    if context.hard_block:
        state = RenderState.BLOCKED
    elif summary.candidates:
        state = RenderState.REVIEW_CANDIDATES
    else:
        state = RenderState.NO_SUPPORTED_CANDIDATES
    prerequisites = tuple(dict.fromkeys(
        reason for candidate in candidates for reason in candidate.prerequisites
    ))
    evidence_refs: list[EvidenceReference] = []
    for candidate in candidates:
        for capability in candidate.capability_evidence:
            evidence_refs.append(EvidenceReference(
                kind="capability",
                reference_id=capability.check_id or capability.reason_code,
                detail=(
                    f"{capability.capability or 'none'}:{capability.verdict}:"
                    f"{capability.reason_code}"
                ),
            ))
        for syntax in candidate.syntax_evidence:
            evidence_refs.append(EvidenceReference(
                kind="syntax",
                reference_id=syntax.evidence_id,
                detail=(
                    f"{syntax.topic}:{syntax.release}:{syntax.review_state}:"
                    f"{syntax.source_section}"
                ),
            ))
    unique_evidence = tuple({
        (reference.kind, reference.reference_id, reference.detail): reference
        for reference in evidence_refs
    }.values())
    deployment_blockers = tuple(dict.fromkeys(
        (*RENDER_BASE_BLOCKERS, *(f"device-identity-incomplete:{code}"
                                  for code in context.hard_block))
    ))
    document = L2CliCandidateDocument(
        source=RenderSource(
            saved_revision_uuid=context.revision.id,
            revision_number=context.revision.number,
            revision_canonical_hash=context.revision.content_hash,
            intent_fingerprint=context.intent.intent_fingerprint,
            preview_fingerprint=context.preview.preview_fingerprint,
            command_evidence_fingerprint=evidence_fingerprint(context.registry),
        ),
        assignment_id=context.assignment_id,
        device=RenderDevice(
            hostname=identity.hostname,
            family=identity.family.value if identity.family is not None else None,
            exact_pid=identity.pid,
            release=identity.software_image,
            license=identity.software_license,
            role=identity.role.value,
            stack_identity=identity.stack_identity,
            stack_members=tuple(
                RenderStackMember(number=member.number, exact_pid=member.pid,
                                  state=member.state)
                for member in identity.stack_members
            ),
        ),
        render_state=state,
        candidates=candidates,
        unresolved_prerequisites=prerequisites,
        evidence=unique_evidence,
        device_runtime_state="unknown-not-read",
        safety=RenderSafety(),
        summary=summary,
        deployment_blockers=deployment_blockers,
        render_fingerprint="0" * 64,
    )
    return document.model_copy(update={"render_fingerprint": render_fingerprint(document)})


_STATUS_SEVERITY: Mapping[CandidateStatus, int] = {
    CandidateStatus.CANDIDATE: 0,
    CandidateStatus.BLOCKED: 1,
    CandidateStatus.UNSUPPORTED: 2,
}


def _merge_group(group: list[Candidate]) -> Candidate:
    """Conservatively merge candidates that share one deterministic candidate ID.

    The merged record keeps every source item, takes the worst status and risk,
    unions blockers and prerequisites, and fails closed when two sources disagree
    about the target, the parameters or the command text. A blocked path can
    therefore never be hidden behind a rendered one.
    """
    if len(group) == 1:
        return group[0]
    base = group[0]
    status = max(
        (candidate.status for candidate in group),
        key=lambda value: _STATUS_SEVERITY[value],
    )
    risk = max((candidate.risk_class for candidate in group), key=lambda value: _RISK_RANK[value])
    targets = {(item.target.kind, item.target.stable_id, item.target.name) for item in group}
    parameter_sets = {
        json.dumps(item.parameters, ensure_ascii=False, sort_keys=True) for item in group
    }
    texts = {item.candidate_text for item in group if item.candidate_text is not None}
    conflicts: list[str] = []
    if len(targets) > 1:
        conflicts.append("merged-candidate-conflict:target")
    if len(parameter_sets) > 1:
        conflicts.append("merged-candidate-conflict:parameters")
    if status is CandidateStatus.CANDIDATE and len(texts) > 1:
        conflicts.append("merged-candidate-conflict:text")
    if conflicts:
        status = CandidateStatus.BLOCKED
    candidate_text = (
        next(iter(texts))
        if status is CandidateStatus.CANDIDATE and len(texts) == 1
        else None
    )
    reasons: list[str] = []
    prerequisites: list[str] = []
    syntax_evidence: dict[str, SyntaxEvidence] = {}
    capability_evidence: dict[tuple[str | None, str, str], CapabilityEvidence] = {}
    for candidate in group:
        reasons.extend(candidate.blocking_reasons)
        prerequisites.extend(candidate.prerequisites)
        for evidence in candidate.syntax_evidence:
            syntax_evidence.setdefault(evidence.evidence_id, evidence)
        for capability in candidate.capability_evidence:
            capability_evidence.setdefault(
                (capability.capability, capability.verdict, capability.reason_code),
                capability,
            )
    reasons.extend(conflicts)
    merged = base.model_copy(update={
        "status": status,
        "candidate_text": candidate_text,
        "risk_class": risk,
        "blocking_reasons": tuple(dict.fromkeys(reasons)),
        "prerequisites": tuple(dict.fromkeys(prerequisites)),
        "potential_connectivity_impact": any(
            candidate.potential_connectivity_impact for candidate in group
        ),
        "requires_field_verification": any(
            candidate.requires_field_verification for candidate in group
        ),
        "syntax_evidence": tuple(syntax_evidence.values()),
        "capability_evidence": tuple(capability_evidence.values()),
        "syntax_validation": SyntaxValidation(
            level=(
                SyntaxValidationLevel.DICTIONARY_ONLY
                if status is CandidateStatus.CANDIDATE
                else SyntaxValidationLevel.NOT_RUN
            ),
        ),
        "provenance": base.provenance.model_copy(update={
            "additional_preview_item_ids": tuple(sorted(
                item.provenance.preview_item_id for item in group[1:]
            )),
        }),
    })
    return merged.model_copy(update={"candidate_fingerprint": candidate_fingerprint(merged)})


def _merge_candidates(candidates: Iterable[Candidate]) -> tuple[Candidate, ...]:
    grouped: dict[str, list[Candidate]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate.candidate_id, []).append(candidate)
    return tuple(_merge_group(group) for group in grouped.values())


def _filter_categories(
    candidates: Iterable[Candidate], categories: tuple[CandidateCategory, ...] | None,
) -> tuple[Candidate, ...]:
    if not categories:
        return tuple(candidates)
    allowed = {category.value for category in categories}
    return tuple(
        candidate for candidate in candidates if candidate.category.value in allowed
    )


def build_l2_cli_candidates(
    revision: PlanRevision,
    intent: Layer2Intent,
    preview: Layer2DeviceConfigPreview,
    *,
    categories: tuple[CandidateCategory, ...] | None = None,
    registry: CommandEvidenceRegistry = DEFAULT_REGISTRY,
) -> L2CliCandidateDocument:
    """Render review-only candidate commands for exactly one Assignment."""
    verify_render_binding(revision, intent, preview, registry=registry)
    context = _context(revision, intent, preview, registry)
    candidates: list[Candidate] = []
    for item in preview.device.config_items:
        for entry in _item_entries(context, item):
            candidates.append(_build_candidate(context, item, entry))
    # Merge before the category filter so a filter can never drop a blocker that
    # another source contributed to the same candidate.
    merged = _merge_candidates(candidates)
    filtered = _filter_categories(merged, categories)
    return _document(context, filtered)


# --------------------------------------------------------------------------- #
# Published schema
# --------------------------------------------------------------------------- #

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"


def candidate_document_json_schema() -> dict[str, object]:
    """Return the Draft 2020-12 JSON Schema for one candidate document.

    The returned object is itself a JSON Schema: it can be handed directly to a
    standard validator. It is not a catalog wrapper.

    Two cross-field invariants that Pydantic cannot express are added as
    ``if/then`` clauses on the ``Candidate`` definition: candidate text exists
    exactly when the status is ``candidate``.
    """
    schema: dict[str, object] = L2CliCandidateDocument.model_json_schema()
    definitions = cast(dict[str, dict[str, object]], schema["$defs"])
    definitions["Candidate"]["allOf"] = [
        {
            "if": {
                "properties": {"status": {"const": "candidate"}},
                "required": ["status"],
            },
            "then": {
                "properties": {"candidate_text": {"type": "string", "minLength": 1}},
                "required": ["candidate_text"],
            },
        },
        {
            "if": {
                "properties": {"status": {"enum": ["blocked", "unsupported"]}},
                "required": ["status"],
            },
            "then": {
                "properties": {"candidate_text": {"type": "null"}},
                "required": ["candidate_text"],
            },
        },
    ]
    return {**schema, "$schema": JSON_SCHEMA_DIALECT}


def candidate_catalog_json_schema() -> dict[str, object]:
    """Versioned Schema Catalog for the B2 contract.

    This object is a directory, not a document validator. Use
    :func:`candidate_document_json_schema` for validation.
    """
    return {
        "contract_id": CONTRACT_ID,
        "render_schema_version": RENDER_SCHEMA_VERSION,
        "intent_schema_version": SUPPORTED_INTENT_SCHEMA_VERSION,
        "preview_schema_version": SUPPORTED_PREVIEW_SCHEMA_VERSION,
        "preview_contract_id": SUPPORTED_PREVIEW_CONTRACT_ID,
        "command_evidence_registry_id": EVIDENCE_REGISTRY_ID,
        "document": candidate_document_json_schema(),
    }


def render_contract_fingerprint() -> str:
    return _sha256(candidate_catalog_json_schema())


__all__ = [
    "CONTRACT_ID",
    "DICTIONARY_ID",
    "JSON_SCHEMA_DIALECT",
    "MAX_TRUNK_VLAN_IDS",
    "RENDER_BASE_BLOCKERS",
    "RENDER_SCHEMA_VERSION",
    "SUPPORTED_INTENT_SCHEMA_VERSION",
    "SUPPORTED_PREVIEW_CONTRACT_ID",
    "SUPPORTED_PREVIEW_SCHEMA_VERSION",
    "Candidate",
    "CandidateCategory",
    "CandidateProvenance",
    "CandidateStatus",
    "CapabilityEvidence",
    "CommandContext",
    "EvidenceReference",
    "L2CliCandidateDocument",
    "RenderBindingError",
    "RenderDevice",
    "RenderRecord",
    "RenderSafety",
    "RenderSource",
    "RenderStackMember",
    "RenderState",
    "RenderSummary",
    "RenderTarget",
    "RenderTargetNotFound",
    "RiskClass",
    "SyntaxEvidence",
    "SyntaxValidation",
    "SyntaxValidationLevel",
    "TargetKind",
    "build_l2_cli_candidates",
    "candidate_catalog_json_schema",
    "candidate_document_json_schema",
    "candidate_fingerprint",
    "description_reason",
    "evidence_fingerprint",
    "interface_name_reason",
    "port_channel_name_reason",
    "render_contract_fingerprint",
    "render_fingerprint",
    "validate_parameters",
    "verify_render_binding",
    "vlan_name_reason",
]
