"""CIS-02B2-03 independent scope validator, risk review and report adapter.

The adapter is the only part of B2-03 that reads frozen B2-02 renderer output.
It consumes the typed candidate document read-only and never lets the renderer's
own validation conclusion decide whether the independent parse passed:

1. the grammar/lexer/parser verdict comes from the independent modules;
2. scope applicability is computed from the frozen L1 evidence registry rows
   (review state, exact PID/release/license binding, reviewed parameter limits);
3. text safety and prohibited-operation checks are applied independently;
4. semantic equality between the parsed command and the rendered candidate is
   checked field by field;
5. the renderer's risk classification is independently challenged against the
   B2-01 minimum classes, never raised by a parser PASS.

The output is an internal, deterministic validation report. It is not exposed
through the public API, it adds no order/sequence/execution field, it never
changes a candidate's ``syntax_validation`` level and it never claims hardware
verification or deployment permission. A report-level PASS means only "the
independently authored parser and safety/scope review accepted this exact
document"; it is not execution authorization.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from ..cisco_catalog import PROFILES
from ..domain import DeviceFamily
from .command_evidence import (
    DEFAULT_REGISTRY,
    EVIDENCE_REGISTRY_ID,
    ROWS,
    CommandEvidence,
    CommandMode,
    CommandTopic,
    EvidenceReviewState,
    ParameterRule,
    evidence_reference,
)
from .layer2_cli_candidates import (
    Candidate,
    CandidateStatus,
    L2CliCandidateDocument,
    RenderDevice,
    RiskClass,
    SyntaxValidationLevel,
    TargetKind,
)
from .layer2_cli_grammar import (
    COVERAGE_COMMAND_BY_TOPIC,
    DESCRIPTION_ALLOWED,
    DESCRIPTION_MAXIMUM,
    FORM_BY_ID,
    VLAN_NAME_ALLOWED,
    VLAN_NAME_MAXIMUM,
    TargetClass,
)
from .layer2_cli_lexer import lex_command
from .layer2_cli_parser import (
    FailureKind,
    ParsedCommand,
    ParseResult,
    parse_command,
    scan_for_dangerous_command,
)

VALIDATION_SCHEMA_VERSION: Literal[1] = 1
VALIDATION_CONTRACT_ID: Literal["cis-02b2-03-independent-cli-validation-v1"] = (
    "cis-02b2-03-independent-cli-validation-v1"
)

#: Independent copy of the B2 safety-invariant vocabulary. The report asserts
#: these values; it never accepts them from a client.
REQUIRED_DEPLOYMENT_BLOCKERS: tuple[str, ...] = (
    "candidate-only-no-execution",
    "deployment-generation-disabled",
    "hardware-not-verified",
    "device-state-unknown",
    "syntax-dictionary-only",
    "no-execution-order-produced",
)

FORBIDDEN_DOCUMENT_KEYS: frozenset[str] = frozenset({
    "commands",
    "cli_commands",
    "cli_lines",
    "command_lines",
    "command_sequence",
    "configuration",
    "config",
    "config_snippet",
    "paste_ready",
    "script",
    "execution_plan",
    "execution_order",
    "deployment_script",
    "order",
    "sequence",
})

#: Reviewed per-family Stack envelope from the B2-01 contract. C1000 has no
#: reviewed Stack; 2960X LAN Lite has no reviewed Stack.
_STACK_LIMITS: Mapping[str, Mapping[str | None, int]] = {
    "catalyst-2960x": {"lan base": 8, "lan lite": 0},
    "catalyst-3850": {None: 9},
    "catalyst-9200": {None: 8},
    "catalyst-9300": {None: 8},
    "catalyst-c1000": {None: 0},
}

#: Independent B2 category vocabulary per reviewed command topic. The adapter
#: binds the renderer's declared category to the parsed topic/evidence topic so
#: a forged document cannot relabel a topology-wide command into an inert one.
TOPIC_CATEGORY: Mapping[CommandTopic, str] = {
    CommandTopic.VLAN: "vlan-definition",
    CommandTopic.VLAN_NAME: "vlan-definition",
    CommandTopic.ACCESS_MODE: "access-mode",
    CommandTopic.ACCESS_VLAN: "access-vlan",
    CommandTopic.TRUNK_MODE: "trunk-mode",
    CommandTopic.NATIVE_VLAN: "native-vlan",
    CommandTopic.ALLOWED_VLANS: "allowed-vlans",
    CommandTopic.PORT_CHANNEL_INTERFACE: "port-channel",
    CommandTopic.CHANNEL_GROUP_STATIC: "port-channel",
    CommandTopic.CHANNEL_GROUP_LACP: "lacp-mode",
    CommandTopic.RAPID_PVST: "rapid-pvst",
    CommandTopic.VTP_TRANSPARENT: "vtp-transparent",
    CommandTopic.ROOT_PRIORITY: "root-priority",
    CommandTopic.PORTFAST: "portfast",
    CommandTopic.BPDU_GUARD: "bpdu-guard",
    CommandTopic.POE_MODE: "poe-mode",
    CommandTopic.SPEED: "speed",
    CommandTopic.DUPLEX: "duplex",
    CommandTopic.DESCRIPTION: "description",
    CommandTopic.ADMIN_SHUTDOWN: "admin-shutdown",
}

#: Categories that carry no reviewed command evidence and stay blocked.
_NON_SYNTAX_CATEGORIES: frozenset[str] = frozenset({"unused-shutdown"})

_ASCII_LETTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
_INTERFACE_NAME_CHARACTERS = _ASCII_LETTERS | frozenset(
    "0123456789/.-_"
)
_INTERFACE_PREFIXES: frozenset[str] = frozenset({
    "gi", "gigabitethernet", "te", "tengigabitethernet", "twe",
    "twentyfivegige",
})


class ReportModel(BaseModel):
    """Frozen report base model: no extra fields, never normalized."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Verdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_RUN = "not-run"


class ScopeOutcome(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    NOT_RUN = "not-run"


@dataclass(frozen=True, slots=True)
class DeviceScope:
    """Independent, exact device identity used for scope decisions."""

    family: DeviceFamily | None
    pid: str | None
    release: str | None
    license: str | None
    stack_identity: str
    stack_members: tuple[tuple[int, str | None, str], ...]


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    outcome: ScopeOutcome
    evidence_id: str | None
    evidence_review_state: str | None
    reason_code: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ExpectedSource:
    """Optional externally expected binding values for integrity checking."""

    saved_revision_uuid: UUID | None = None
    revision_number: int | None = None
    revision_canonical_hash: str | None = None
    intent_fingerprint: str | None = None
    preview_fingerprint: str | None = None
    render_fingerprint: str | None = None
    assignment_id: UUID | None = None


# --------------------------------------------------------------------------- #
# Report model
# --------------------------------------------------------------------------- #


class FailureReport(ReportModel):
    kind: str
    code: str
    detail: str = ""


class ParseReport(ReportModel):
    status: Verdict
    topic: str | None = None
    form: str | None = None
    mode: str | None = None
    modes: tuple[str, ...] = ()
    target_class: str | None = None
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    failures: tuple[FailureReport, ...] = ()


class ScopeReport(ReportModel):
    status: ScopeOutcome
    evidence_id: str | None = None
    evidence_review_state: str | None = None
    reason_code: str
    detail: str = ""


class SecurityReport(ReportModel):
    status: Verdict
    reason_codes: tuple[str, ...] = ()


class SemanticReport(ReportModel):
    status: Verdict
    mismatches: tuple[str, ...] = ()


class RiskReport(ReportModel):
    status: Verdict
    renderer_risk_class: str
    independent_floor: str
    findings: tuple[str, ...] = ()


class PortGroupBinding(ReportModel):
    prefix: str
    slot: int
    first: int
    count: int
    medium: str
    rates: tuple[int, ...]
    poe_plus: bool


class ContextBindingReport(ReportModel):
    status: Verdict
    topic: str | None = None
    candidate_mode: str | None = None
    candidate_target_class: str | None = None
    reviewed_command_mode: str | None = None
    reviewed_modes: tuple[str, ...] = ()
    port_channel_exception_applied: bool = False
    reasons: tuple[str, ...] = ()


class TargetCapabilityReport(ReportModel):
    status: Verdict
    applicable: bool = False
    exact_pid: str | None = None
    interface_name: str | None = None
    port_group: PortGroupBinding | None = None
    reasons: tuple[str, ...] = ()


class CandidateValidation(ReportModel):
    candidate_id: str
    category: str
    renderer_status: str
    candidate_text_present: bool
    syntax_validation_level: str
    parser_verified: bool
    candidate_fingerprint: str
    candidate_fingerprint_recomputed: str
    candidate_fingerprint_match: bool
    parse: ParseReport
    scope: ScopeReport
    context_binding: ContextBindingReport
    target_capability: TargetCapabilityReport
    security: SecurityReport
    semantics: SemanticReport
    risk: RiskReport
    independent_verdict: Verdict
    fail_closed_action: str | None = None


class SourceBinding(ReportModel):
    render_schema_version: int
    render_contract_id: str
    saved_revision_uuid: UUID
    revision_number: int
    revision_canonical_hash: str
    intent_schema_version: int
    intent_fingerprint: str
    preview_schema_version: int
    preview_contract_id: str
    preview_fingerprint: str
    command_evidence_registry_id: str
    command_evidence_fingerprint: str
    render_fingerprint: str
    assignment_id: UUID


class StackMemberBinding(ReportModel):
    number: int
    exact_pid: str | None
    state: str


class DeviceBinding(ReportModel):
    hostname: str
    family: str | None
    exact_pid: str | None
    release: str | None
    license: str | None
    role: str
    stack_identity: str
    stack_members: tuple[StackMemberBinding, ...]
    identity_verdict: Verdict
    identity_reasons: tuple[str, ...] = ()


class IntegrityReport(ReportModel):
    status: Verdict
    render_fingerprint_recomputed: str
    render_fingerprint_match: bool
    candidate_fingerprints_match: bool
    candidate_ids_unique: bool
    source_binding_format_ok: bool
    evidence_content_digests_ok: bool
    assignment_binding_ok: bool
    expected_source_match: bool
    failures: tuple[str, ...] = ()


class RegistryCoverageRecord(ReportModel):
    evidence_id: str
    topic: str
    family: str
    pids: tuple[str, ...]
    releases: tuple[str, ...]
    licenses: tuple[str, ...]
    review_state: str
    renderable: bool
    canonical_parse_status: Verdict
    independent_scope_verdict: ScopeOutcome
    evidence_id_resolved: str | None = None
    reason_code: str | None = None


class TopologyCheck(ReportModel):
    name: str
    status: Verdict
    findings: tuple[str, ...] = ()


class TopologyReview(ReportModel):
    status: Verdict
    checks: tuple[TopologyCheck, ...]
    findings: tuple[str, ...] = ()


class ValidationSummary(ReportModel):
    total_candidates: int
    parsed_candidates: int
    parse_pass: int
    parse_fail: int
    not_run: int
    scope_blocked: int
    context_fail: int
    capability_fail: int
    capability_not_run: int
    security_fail: int
    semantic_mismatch: int
    risk_fail: int
    failed_candidates: int
    topics_parsed: tuple[str, ...]
    registry_rows: int
    registry_reviewed: int
    registry_rejected: int
    registry_unreviewed: int
    overall_status: Verdict


class ValidationSafety(ReportModel):
    candidate_only: Literal[True] = True
    executable: Literal[False] = False
    deployable: Literal[False] = False
    deployment_allowed: Literal[False] = False
    hardware_verified: Literal[False] = False
    device_connection: Literal["none"] = "none"
    running_config_read: Literal[False] = False
    device_writes_enabled: Literal[False] = False
    device_runtime_state: Literal["unknown-not-read"] = "unknown-not-read"
    cli: None = None
    deployment_artifact: None = None
    independent_validation_is_not_execution_authorization: Literal[True] = True
    public_candidate_schema_unchanged: Literal[True] = True
    parser_verified_public_field_unchanged: Literal[True] = True


class ValidationReport(ReportModel):
    validation_schema_version: Literal[1] = VALIDATION_SCHEMA_VERSION
    validation_contract_id: Literal[
        "cis-02b2-03-independent-cli-validation-v1"
    ] = VALIDATION_CONTRACT_ID
    source: SourceBinding
    device: DeviceBinding
    assignment_id: UUID
    integrity: IntegrityReport
    candidates: tuple[CandidateValidation, ...]
    registry_coverage: tuple[RegistryCoverageRecord, ...]
    topology_review: TopologyReview
    summary: ValidationSummary
    safety: ValidationSafety
    report_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------- #
# Canonical hashing and integrity helpers
# --------------------------------------------------------------------------- #


def canonical_sha256(value: object) -> str:
    """SHA-256 of the canonical JSON encoding, independent of key order."""
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def recompute_render_fingerprint(document: L2CliCandidateDocument) -> str:
    payload = document.model_dump(mode="json")
    payload.pop("render_fingerprint", None)
    return canonical_sha256(payload)


def recompute_candidate_fingerprint(candidate: Candidate) -> str:
    payload = candidate.model_dump(mode="json")
    payload.pop("candidate_fingerprint", None)
    return canonical_sha256(payload)


def _is_sha256_hex(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _is_candidate_id(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 21:
        return False
    return (
        value.startswith("cand-")
        and all(character in "0123456789abcdef" for character in value[5:])
    )


def _iter_keys(value: object) -> Sequence[str]:
    keys: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            keys.append(str(key))
            keys.extend(_iter_keys(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            keys.extend(_iter_keys(item))
    return tuple(keys)


# --------------------------------------------------------------------------- #
# Independent device-identity and scope validation
# --------------------------------------------------------------------------- #


def _family_of(value: str | None) -> DeviceFamily | None:
    if value is None:
        return None
    try:
        return DeviceFamily(value)
    except ValueError:
        return None


def device_scope_of(device: RenderDevice) -> DeviceScope:
    """Build the independent exact device scope from the rendered device block."""
    return DeviceScope(
        family=_family_of(device.family),
        pid=device.exact_pid,
        release=device.release,
        license=device.license,
        stack_identity=device.stack_identity,
        stack_members=tuple(
            (member.number, member.exact_pid, member.state)
            for member in device.stack_members
        ),
    )


def _family_rows(family: DeviceFamily) -> tuple[CommandEvidence, ...]:
    return tuple(row for row in ROWS if row.family is family)


def _family_licensed(family: DeviceFamily) -> bool:
    return any(row.licenses for row in _family_rows(family))


def _family_pids(family: DeviceFamily) -> frozenset[str]:
    return frozenset(
        pid.upper() for row in _family_rows(family) for pid in row.pids
    )


def _family_licenses(family: DeviceFamily) -> frozenset[str]:
    return frozenset(
        license_name.casefold()
        for row in _family_rows(family)
        for license_name in row.licenses
    )


def _stack_limit(family: DeviceFamily, license_name: str | None) -> int | None:
    limits = _STACK_LIMITS.get(family.value, {})
    if not limits:
        return None
    if None in limits:
        return limits[None]
    return limits.get((license_name or "").casefold())


def device_identity_findings(device: DeviceScope) -> tuple[str, ...]:
    """Fail-closed device identity checks independent of the renderer gates."""
    findings: list[str] = []
    if device.family is None:
        findings.append("device-family-unknown")
    if not device.pid:
        findings.append("device-pid-missing")
    elif device.family is not None and device.pid.upper() not in _family_pids(
        device.family
    ):
        findings.append("pid-not-verified")
    if not device.release:
        findings.append("release-unmatched")
    if device.family is not None:
        if _family_licensed(device.family):
            if not device.license:
                findings.append("license-unmatched")
            elif device.license.casefold() not in _family_licenses(device.family):
                findings.append("license-unmatched")
        limit = _stack_limit(device.family, device.license)
        if device.stack_identity == "standalone":
            if device.stack_members:
                findings.append("stack-identity-inconsistent")
        elif device.stack_identity == "resolved":
            if not device.stack_members:
                findings.append("stack-identity-unresolved")
            else:
                numbers = [number for number, _pid, _state in device.stack_members]
                if any(number < 1 for number in numbers) or len(set(numbers)) != len(
                    numbers
                ):
                    findings.append("stack-member-numbers-invalid")
                member_pids = {
                    (pid or "").upper() for _number, pid, _state in device.stack_members
                }
                if len(member_pids) != 1 or "" in member_pids:
                    findings.append("stack-identity-unresolved")
                if member_pids and member_pids <= _family_pids(device.family):
                    pass
                else:
                    findings.append("stack-member-pid-not-verified")
                if any(
                    state != "ready" for _number, _pid, state in device.stack_members
                ):
                    findings.append("stack-member-not-ready")
                if limit is not None and len(device.stack_members) > limit:
                    findings.append(
                        f"stack-limit-exceeded:{len(device.stack_members)}:{limit}"
                    )
        else:
            findings.append("stack-identity-unresolved")
    return tuple(dict.fromkeys(findings))


def _rows_for(
    family: DeviceFamily,
    pid: str,
    release: str,
    license_name: str | None,
    topic: CommandTopic,
    rows: Sequence[CommandEvidence],
) -> tuple[CommandEvidence, ...]:
    normalized_pid = pid.upper()
    normalized_release = release.casefold()
    normalized_license = (license_name or "").casefold()
    return tuple(
        row for row in rows
        if row.family is family
        and normalized_pid in {value.upper() for value in row.pids}
        and normalized_release in {value.casefold() for value in row.releases}
        and normalized_license in {
            value.casefold() for value in (row.licenses or ("",))
        }
        and row.topic is topic
    )


def _integer_violation(
    rule: ParameterRule, value: object,
) -> str | None:
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


def _text_violation(rule: ParameterRule, value: object) -> str | None:
    if not isinstance(value, str):
        return f"parameter-not-text:{rule.name}"
    maximum = rule.maximum if rule.maximum is not None else 0
    if len(value) > maximum:
        return f"unsafe-text-class:{rule.name}-too-long"
    if rule.name == "vlan-name":
        allowed = VLAN_NAME_ALLOWED
        if not value or value[0] not in _ASCII_LETTERS and not value[0].isdigit():
            return "unsafe-text-class:forbidden-character"
        if any(character not in allowed for character in value):
            return "unsafe-text-class:forbidden-character"
        if len(value) > VLAN_NAME_MAXIMUM:
            return "unsafe-text-class:vlan-name-too-long"
        return None
    if rule.name == "description":
        if not value or not (value[0].isalnum() and value[0].isascii()):
            return "unsafe-text-class:forbidden-character"
        if value != value.strip() or "  " in value:
            return "unsafe-text-class:unsafe-whitespace"
        if any(character not in DESCRIPTION_ALLOWED for character in value):
            return "unsafe-text-class:forbidden-character"
        if len(value) > DESCRIPTION_MAXIMUM:
            return "unsafe-text-class:description-too-long"
        return None
    return "unsafe-text-class:unsupported-text-rule"


def _vlan_list_violation(rule: ParameterRule, value: object) -> str | None:
    if not isinstance(value, (tuple, list)) or not value:
        return f"parameter-not-allowed:{rule.name}"
    values = list(value)
    if len(values) > 64:
        return f"parameter-list-too-long:{rule.name}"
    if len(set(values)) != len(values):
        return f"parameter-duplicate-value:{rule.name}"
    for item in values:
        if not isinstance(item, int) or isinstance(item, bool):
            return f"parameter-not-integer:{rule.name}"
        if rule.minimum is not None and item < rule.minimum:
            return f"parameter-out-of-range:{rule.name}"
        if rule.maximum is not None and item > rule.maximum:
            return f"parameter-out-of-range:{rule.name}"
        if item in rule.reserved:
            return f"parameter-reserved-value:{rule.name}"
    if values != sorted(values):
        return f"parameter-not-allowed:{rule.name}"
    return None


def _row_parameter_violation(
    row: CommandEvidence, parameters: Mapping[str, object],
) -> str | None:
    for rule in row.parameters:
        if rule.name not in parameters:
            continue
        value = parameters[rule.name]
        if rule.kind == "integer":
            violation = _integer_violation(rule, value)
        elif rule.kind == "enum":
            violation = (
                None if str(value) in rule.values
                else f"parameter-not-allowed:{rule.name}"
            )
        elif rule.kind == "text":
            violation = _text_violation(rule, value)
        elif rule.kind == "vlan-list":
            violation = _vlan_list_violation(rule, value)
        else:  # pragma: no cover - closed registry vocabulary
            violation = f"parameter-rule-unusable:{rule.name}"
        if violation is not None:
            return violation
    return None


def classify_scope(
    parsed: ParsedCommand,
    device: DeviceScope,
    *,
    rows: Sequence[CommandEvidence] = ROWS,
) -> ScopeDecision:
    """Independently decide whether reviewed evidence covers this command/device."""
    identity = device_identity_findings(device)
    if identity:
        return ScopeDecision(
            ScopeOutcome.BLOCKED, None, None, identity[0],
            "device identity fails closed",
        )
    assert device.family is not None  # narrowed by the identity check
    assert device.pid is not None
    assert device.release is not None
    applicable = _rows_for(
        device.family, device.pid, device.release, device.license,
        parsed.topic, rows,
    )
    topic = parsed.topic.value
    if not applicable:
        return ScopeDecision(
            ScopeOutcome.BLOCKED, None, None,
            f"syntax-evidence-missing:{topic}", "no reviewed row for this scope",
        )
    rejected = tuple(
        row for row in applicable
        if row.review.state is EvidenceReviewState.REJECTED
    )
    if rejected:
        return ScopeDecision(
            ScopeOutcome.BLOCKED, rejected[0].evidence_id,
            rejected[0].review.state.value,
            f"syntax-evidence-rejected:{topic}",
            "the exact-scope evidence row is independently rejected",
        )
    reviewed = tuple(
        row for row in applicable
        if row.review.state is EvidenceReviewState.REVIEWED
    )
    if not reviewed:
        return ScopeDecision(
            ScopeOutcome.BLOCKED, applicable[0].evidence_id,
            applicable[0].review.state.value,
            f"syntax-evidence-not-reviewed:{topic}",
            "the exact-scope evidence row is not independently reviewed",
        )
    renderable = tuple(row for row in reviewed if row.renderable)
    if not renderable:
        return ScopeDecision(
            ScopeOutcome.BLOCKED, reviewed[0].evidence_id,
            reviewed[0].review.state.value,
            f"syntax-evidence-content-mismatch:{topic}",
            "review attestation does not match the evidence content digest",
        )
    if len(renderable) > 1:
        return ScopeDecision(
            ScopeOutcome.BLOCKED, None, None,
            f"syntax-evidence-ambiguous:{topic}",
            "more than one reviewed row matches this exact scope",
        )
    row = renderable[0]
    violation = _row_parameter_violation(row, parsed.parameters)
    if violation is not None:
        return ScopeDecision(
            ScopeOutcome.BLOCKED, row.evidence_id, row.review.state.value,
            violation, "the parsed argument is outside the reviewed row limits",
        )
    return ScopeDecision(
        ScopeOutcome.ALLOWED, row.evidence_id, row.review.state.value,
        "syntax-evidence-reviewed", f"independent syntax evidence: {row.evidence_id}",
    )


# --------------------------------------------------------------------------- #
# Independent risk review
# --------------------------------------------------------------------------- #

_RISK_RANK: Mapping[RiskClass, int] = {
    RiskClass.R0: 0,
    RiskClass.R1: 1,
    RiskClass.R2: 2,
    RiskClass.R3: 3,
    RiskClass.R4: 4,
    RiskClass.R5: 5,
    RiskClass.R6: 6,
}

#: B2-01 minimum risk class per candidate category, independent of the renderer.
_MINIMUM_RISK: Mapping[str, RiskClass] = {
    "vlan-definition": RiskClass.R0,
    "access-mode": RiskClass.R2,
    "access-vlan": RiskClass.R2,
    "trunk-mode": RiskClass.R2,
    "native-vlan": RiskClass.R5,
    "allowed-vlans": RiskClass.R2,
    "port-channel": RiskClass.R3,
    "lacp-mode": RiskClass.R3,
    "rapid-pvst": RiskClass.R2,
    "vtp-transparent": RiskClass.R2,
    "root-priority": RiskClass.R2,
    "portfast": RiskClass.R2,
    "bpdu-guard": RiskClass.R2,
    "poe-mode": RiskClass.R1,
    "speed": RiskClass.R1,
    "duplex": RiskClass.R1,
    "description": RiskClass.R0,
    "admin-shutdown": RiskClass.R1,
    "unused-shutdown": RiskClass.R1,
}

_TOPOLOGY_WIDE_CATEGORIES: frozenset[str] = frozenset({
    "rapid-pvst", "vtp-transparent", "root-priority",
})
_EDGE_ROLE_CATEGORIES: frozenset[str] = frozenset({"portfast", "bpdu-guard"})
_CONNECTIVITY_RISK_CATEGORIES: frozenset[str] = frozenset({
    "admin-shutdown", "unused-shutdown", "speed", "duplex", "poe-mode",
})
_VLAN_RENAME_TRANSITIONS: frozenset[str] = frozenset({"vlan-renamed", "no-change"})

#: Independent reviewed context policy. The Grammar already narrows the
#: physical-interface forms; this table is the second, adapter-independent
#: judgement so a forged context cannot rely on Grammar alone. The frozen
#: Renderer emits the switchport/description/admin/PortFast/BPDU-Guard forms on
#: a logical Port-Channel target, so the reviewed INTERFACE command mode is
#: explicitly widened only for that known Renderer target semantics.
_CONTEXT_MODES: Mapping[CommandTopic, frozenset[CommandMode]] = {
    CommandTopic.VLAN: frozenset({CommandMode.GLOBAL}),
    CommandTopic.VLAN_NAME: frozenset({CommandMode.VLAN}),
    CommandTopic.ACCESS_MODE: frozenset({
        CommandMode.INTERFACE, CommandMode.PORT_CHANNEL,
    }),
    CommandTopic.ACCESS_VLAN: frozenset({
        CommandMode.INTERFACE, CommandMode.PORT_CHANNEL,
    }),
    CommandTopic.TRUNK_MODE: frozenset({
        CommandMode.INTERFACE, CommandMode.PORT_CHANNEL,
    }),
    CommandTopic.NATIVE_VLAN: frozenset({
        CommandMode.INTERFACE, CommandMode.PORT_CHANNEL,
    }),
    CommandTopic.ALLOWED_VLANS: frozenset({
        CommandMode.INTERFACE, CommandMode.PORT_CHANNEL,
    }),
    CommandTopic.PORT_CHANNEL_INTERFACE: frozenset({CommandMode.GLOBAL}),
    CommandTopic.CHANNEL_GROUP_STATIC: frozenset({CommandMode.INTERFACE}),
    CommandTopic.CHANNEL_GROUP_LACP: frozenset({CommandMode.INTERFACE}),
    CommandTopic.RAPID_PVST: frozenset({CommandMode.GLOBAL}),
    CommandTopic.VTP_TRANSPARENT: frozenset({CommandMode.GLOBAL}),
    CommandTopic.ROOT_PRIORITY: frozenset({CommandMode.GLOBAL}),
    CommandTopic.PORTFAST: frozenset({
        CommandMode.INTERFACE, CommandMode.PORT_CHANNEL,
    }),
    CommandTopic.BPDU_GUARD: frozenset({
        CommandMode.INTERFACE, CommandMode.PORT_CHANNEL,
    }),
    CommandTopic.POE_MODE: frozenset({CommandMode.INTERFACE}),
    CommandTopic.SPEED: frozenset({CommandMode.INTERFACE}),
    CommandTopic.DUPLEX: frozenset({CommandMode.INTERFACE}),
    CommandTopic.DESCRIPTION: frozenset({
        CommandMode.INTERFACE, CommandMode.PORT_CHANNEL,
    }),
    CommandTopic.ADMIN_SHUTDOWN: frozenset({
        CommandMode.INTERFACE, CommandMode.PORT_CHANNEL,
    }),
}

_CONTEXT_TARGET_CLASSES: Mapping[CommandTopic, frozenset[TargetClass]] = {
    CommandTopic.VLAN: frozenset({TargetClass.VLAN}),
    CommandTopic.VLAN_NAME: frozenset({TargetClass.VLAN}),
    CommandTopic.ACCESS_MODE: frozenset({
        TargetClass.INTERFACE, TargetClass.PORT_CHANNEL,
    }),
    CommandTopic.ACCESS_VLAN: frozenset({
        TargetClass.INTERFACE, TargetClass.PORT_CHANNEL,
    }),
    CommandTopic.TRUNK_MODE: frozenset({
        TargetClass.INTERFACE, TargetClass.PORT_CHANNEL,
    }),
    CommandTopic.NATIVE_VLAN: frozenset({
        TargetClass.INTERFACE, TargetClass.PORT_CHANNEL,
    }),
    CommandTopic.ALLOWED_VLANS: frozenset({
        TargetClass.INTERFACE, TargetClass.PORT_CHANNEL,
    }),
    CommandTopic.PORT_CHANNEL_INTERFACE: frozenset({TargetClass.PORT_CHANNEL}),
    CommandTopic.CHANNEL_GROUP_STATIC: frozenset({TargetClass.INTERFACE}),
    CommandTopic.CHANNEL_GROUP_LACP: frozenset({TargetClass.INTERFACE}),
    CommandTopic.RAPID_PVST: frozenset({TargetClass.DEVICE}),
    CommandTopic.VTP_TRANSPARENT: frozenset({TargetClass.DEVICE}),
    CommandTopic.ROOT_PRIORITY: frozenset({TargetClass.DEVICE}),
    CommandTopic.PORTFAST: frozenset({
        TargetClass.INTERFACE, TargetClass.PORT_CHANNEL,
    }),
    CommandTopic.BPDU_GUARD: frozenset({
        TargetClass.INTERFACE, TargetClass.PORT_CHANNEL,
    }),
    CommandTopic.POE_MODE: frozenset({TargetClass.INTERFACE}),
    CommandTopic.SPEED: frozenset({TargetClass.INTERFACE}),
    CommandTopic.DUPLEX: frozenset({TargetClass.INTERFACE}),
    CommandTopic.DESCRIPTION: frozenset({
        TargetClass.INTERFACE, TargetClass.PORT_CHANNEL,
    }),
    CommandTopic.ADMIN_SHUTDOWN: frozenset({
        TargetClass.INTERFACE, TargetClass.PORT_CHANNEL,
    }),
}

#: Reviewed topics the frozen Renderer emits on a logical Port-Channel target.
#: Their evidence row command_mode is INTERFACE (Cisco's general interface
#: configuration mode), which must not be read as excluding every Port-Channel
#: sub-command. Physical-member/port-attribute topics are deliberately absent.
_PORT_CHANNEL_REVIEWED_TOPICS: frozenset[CommandTopic] = frozenset({
    CommandTopic.ACCESS_MODE,
    CommandTopic.ACCESS_VLAN,
    CommandTopic.TRUNK_MODE,
    CommandTopic.NATIVE_VLAN,
    CommandTopic.ALLOWED_VLANS,
    CommandTopic.PORTFAST,
    CommandTopic.BPDU_GUARD,
    CommandTopic.DESCRIPTION,
    CommandTopic.ADMIN_SHUTDOWN,
})

_PHYSICAL_ONLY_TOPICS: frozenset[CommandTopic] = frozenset({
    CommandTopic.CHANNEL_GROUP_STATIC,
    CommandTopic.CHANNEL_GROUP_LACP,
    CommandTopic.POE_MODE,
    CommandTopic.SPEED,
    CommandTopic.DUPLEX,
})

_CAPABILITY_TOPICS: frozenset[CommandTopic] = frozenset({
    CommandTopic.POE_MODE, CommandTopic.SPEED, CommandTopic.DUPLEX,
})
_COPPER_MEDIUM = "copper-rj45"


def _context_binding_report(
    candidate: Candidate,
    parsed: ParsedCommand | None,
    topic: CommandTopic | None,
    evidence_row: CommandEvidence | None,
) -> ContextBindingReport:
    """Independently check context/target and the reviewed command mode."""
    context_mode = candidate.command_context.mode
    target_class = _TARGET_CLASS_MAP.get(candidate.target.kind)
    candidate_mode = context_mode.value
    candidate_target_class = target_class.value if target_class else None
    reviewed_command_mode = (
        evidence_row.command_mode.value if evidence_row else None
    )
    if candidate.status is not CandidateStatus.CANDIDATE:
        return ContextBindingReport(
            status=Verdict.NOT_RUN,
            topic=topic.value if topic else None,
            candidate_mode=candidate_mode,
            candidate_target_class=candidate_target_class,
            reviewed_command_mode=reviewed_command_mode,
            reasons=(f"renderer-{candidate.status.value}-no-context-binding",),
        )
    if parsed is None or topic is None:
        return ContextBindingReport(
            status=Verdict.NOT_RUN,
            topic=topic.value if topic else None,
            candidate_mode=candidate_mode,
            candidate_target_class=candidate_target_class,
            reviewed_command_mode=reviewed_command_mode,
            reasons=("parse-failed-or-not-run",),
        )
    reasons: list[str] = []
    expected_modes = _CONTEXT_MODES.get(topic)
    expected_targets = _CONTEXT_TARGET_CLASSES.get(topic)
    if expected_modes is not None and context_mode not in expected_modes:
        reasons.append(
            f"context-mode-not-reviewed:{topic.value}:{context_mode.value}:"
            + ",".join(sorted(mode.value for mode in expected_modes))
        )
    if expected_targets is not None and (
        target_class is None or target_class not in expected_targets
    ):
        reasons.append(
            f"context-target-not-reviewed:{topic.value}:"
            f"{target_class.value if target_class else 'none'}"
        )
    port_channel_exception = False
    if evidence_row is not None:
        reviewed_mode = evidence_row.command_mode
        allowed_modes: set[CommandMode] = set()
        if reviewed_mode is CommandMode.INTERFACE:
            allowed_modes.add(CommandMode.INTERFACE)
            if topic in _PORT_CHANNEL_REVIEWED_TOPICS:
                allowed_modes.add(CommandMode.PORT_CHANNEL)
                port_channel_exception = context_mode is CommandMode.PORT_CHANNEL
        elif reviewed_mode is CommandMode.GLOBAL:
            allowed_modes.add(CommandMode.GLOBAL)
        elif reviewed_mode is CommandMode.VLAN:
            allowed_modes.add(CommandMode.VLAN)
        else:
            allowed_modes.add(CommandMode.PORT_CHANNEL)
        if context_mode not in allowed_modes:
            reasons.append(
                "evidence-command-mode-context-mismatch:"
                f"{evidence_row.evidence_id}:{reviewed_mode.value}:"
                f"{context_mode.value}"
            )
    else:
        reasons.append("no-reviewed-evidence-row-for-context")
    return ContextBindingReport(
        status=Verdict.FAIL if reasons else Verdict.PASS,
        topic=topic.value,
        candidate_mode=candidate_mode,
        candidate_target_class=candidate_target_class,
        reviewed_command_mode=reviewed_command_mode,
        reviewed_modes=tuple(sorted(
            mode.value for mode in (expected_modes or frozenset())
        )),
        port_channel_exception_applied=port_channel_exception,
        reasons=tuple(dict.fromkeys(reasons)),
    )


def _port_group_binding(
    device: RenderDevice, interface_name: str,
) -> tuple[PortGroupBinding | None, tuple[str, ...]]:
    """Resolve the exact-PID reviewed PortGroup for a physical interface."""
    if not device.exact_pid:
        return None, ("target-capability-pid-missing",)
    profile = PROFILES.get(device.exact_pid.upper())
    if profile is None:
        return None, (
            f"target-capability-pid-unknown:{device.exact_pid}",
        )
    components = _interface_components(interface_name)
    if components is None:
        return None, ("target-capability-interface-unresolvable",)
    prefix, member, module, port = components
    if device.stack_identity == "standalone":
        if member != 1:
            return None, ("target-capability-member-slot-invalid",)
    elif device.stack_identity == "resolved":
        if member not in {item.number for item in device.stack_members}:
            return None, ("target-capability-member-slot-invalid",)
    else:
        return None, ("target-capability-stack-unresolved",)
    for group in profile.ports:
        if not prefix.startswith(group.prefix):
            continue
        if module == group.slot and group.first <= port < group.first + group.count:
            return (
                PortGroupBinding(
                    prefix=group.prefix,
                    slot=group.slot,
                    first=group.first,
                    count=group.count,
                    medium=group.medium.value,
                    rates=group.rates,
                    poe_plus=group.poe_plus,
                ),
                (),
            )
    return None, ("target-capability-port-group-unknown",)


def _target_capability_report(
    candidate: Candidate,
    parsed: ParsedCommand | None,
    topic: CommandTopic | None,
    device: RenderDevice,
) -> TargetCapabilityReport:
    """Independently validate physical port PoE/medium/rate capability."""
    applicable_topic = topic if topic in _CAPABILITY_TOPICS else None
    if candidate.status is not CandidateStatus.CANDIDATE:
        return TargetCapabilityReport(
            status=Verdict.NOT_RUN,
            reasons=(f"renderer-{candidate.status.value}-no-target-capability",),
        )
    if parsed is None or applicable_topic is None or topic is None:
        return TargetCapabilityReport(
            status=Verdict.NOT_RUN,
            reasons=("no-target-capability-rule",),
        )
    if candidate.target.kind is not TargetKind.INTERFACE:
        return TargetCapabilityReport(
            status=Verdict.FAIL,
            applicable=True,
            exact_pid=device.exact_pid,
            interface_name=candidate.target.name,
            reasons=(
                "target-capability-requires-physical-interface:"
                f"{candidate.target.kind.value}",
            ),
        )
    binding, binding_reasons = _port_group_binding(device, candidate.target.name)
    if binding is None:
        return TargetCapabilityReport(
            status=Verdict.FAIL,
            applicable=True,
            exact_pid=device.exact_pid,
            interface_name=candidate.target.name,
            reasons=binding_reasons or ("target-capability-port-group-unknown",),
        )
    reasons: list[str] = []
    if topic is CommandTopic.POE_MODE:
        mode_value = parsed.parameter("poe-mode")
        if not binding.poe_plus:
            reasons.append(
                f"target-port-not-poe-capable:{candidate.target.name}:"
                f"{binding.medium}"
            )
        if mode_value == "static":
            reasons.append("poe-static-budget-evidence-required")
    elif topic is CommandTopic.SPEED:
        if binding.medium != _COPPER_MEDIUM:
            reasons.append(
                f"target-port-not-copper:{candidate.target.name}:{binding.medium}"
            )
        else:
            speed_value = str(parsed.parameter("speed"))
            if speed_value != "auto":
                speed_number = _canonical_integer_text(speed_value)
                if speed_number is None or speed_number not in binding.rates:
                    reasons.append(
                        f"speed-not-in-port-rates:{speed_value}:"
                        + ",".join(str(rate) for rate in binding.rates)
                    )
    elif topic is CommandTopic.DUPLEX:
        if binding.medium != _COPPER_MEDIUM:
            reasons.append(
                f"target-port-not-copper:{candidate.target.name}:{binding.medium}"
            )
    return TargetCapabilityReport(
        status=Verdict.FAIL if reasons else Verdict.PASS,
        applicable=True,
        exact_pid=device.exact_pid,
        interface_name=candidate.target.name,
        port_group=binding,
        reasons=tuple(dict.fromkeys(reasons)),
    )


def review_candidate_risk(
    candidate: Candidate,
    *,
    device: RenderDevice,
    effective_topic: CommandTopic | None = None,
) -> RiskReport:
    """Challenge the renderer's risk class against B2-01 minimum classes.

    The category is taken from the independently parsed topic or the evidence
    row topic when available. The renderer's self-declared ``category`` cannot
    relabel a topology-wide command as an inert one.
    """
    declared_category = candidate.category.value
    category = (
        TOPIC_CATEGORY[effective_topic]
        if effective_topic is not None
        else declared_category
    )
    risk = candidate.risk_class
    floor = _MINIMUM_RISK.get(category, RiskClass.R5)
    findings: list[str] = []
    rank = _RISK_RANK[risk]
    floor_rank = _RISK_RANK[floor]
    visible = candidate.status is CandidateStatus.CANDIDATE
    cleanup_record = bool(candidate.provenance.cleanup) or any(
        "cleanup" in reason or "removal" in reason
        for reason in candidate.blocking_reasons
    )
    if effective_topic is not None and category != declared_category:
        findings.append(
            f"category-topic-mismatch:{declared_category}:{category}"
        )
    if visible:
        if rank < floor_rank:
            if not (
                category == "vlan-definition"
                and candidate.provenance.transition in _VLAN_RENAME_TRANSITIONS
            ):
                findings.append(
                    f"risk-class-below-independent-floor:{category}:"
                    f"{risk.value}:{floor.value}"
                )
    elif cleanup_record and rank < _RISK_RANK[RiskClass.R4]:
        findings.append(f"cleanup-risk-below-r4:{risk.value}")
    if category == "native-vlan" and rank < _RISK_RANK[RiskClass.R5]:
        findings.append(f"native-vlan-risk-below-r5:{risk.value}")
    if category in _TOPOLOGY_WIDE_CATEGORIES:
        if candidate.status is CandidateStatus.CANDIDATE:
            findings.append(
                f"topology-wide-command-visible-without-field-evidence:{category}"
            )
        elif rank < _RISK_RANK[RiskClass.R5]:
            findings.append(
                f"topology-wide-block-not-escalated-to-r5:{category}:{risk.value}"
            )
    if category in _EDGE_ROLE_CATEGORIES and (
        candidate.status is CandidateStatus.CANDIDATE and device.role != "access"
    ):
        findings.append(f"edge-role-unverified:candidate-visible:{device.role}")
    if candidate.status is CandidateStatus.CANDIDATE:
        if candidate.risk_class in {RiskClass.R5, RiskClass.R6}:
            findings.append(f"visible-high-risk-candidate:{risk.value}")
        if candidate.blocking_reasons:
            findings.append("visible-candidate-carries-blocking-reasons")
        if candidate.candidate_text is None:
            findings.append("visible-candidate-without-text")
        if candidate.syntax_validation.level is not (
            SyntaxValidationLevel.DICTIONARY_ONLY
        ):
            findings.append("visible-candidate-syntax-level-not-dictionary-only")
        if not candidate.syntax_evidence:
            findings.append("visible-candidate-without-syntax-evidence")
        if any(
            evidence.verdict in {"unknown", "unsupported"}
            for evidence in candidate.capability_evidence
        ):
            findings.append("visible-candidate-with-unresolved-capability")
    else:
        if candidate.candidate_text is not None:
            findings.append("blocked-candidate-carries-text")
        if candidate.syntax_validation.level is not SyntaxValidationLevel.NOT_RUN:
            findings.append("blocked-candidate-syntax-level-not-not-run")
    if candidate.syntax_validation.parser_verified:
        findings.append("frozen-v1-parser-verified-must-stay-false")
    if rank >= _RISK_RANK[RiskClass.R2] or category in _CONNECTIVITY_RISK_CATEGORIES:
        if not candidate.potential_connectivity_impact:
            findings.append("connectivity-impact-understated")
    if rank >= _RISK_RANK[RiskClass.R4] and not candidate.requires_field_verification:
        findings.append("field-verification-understated-for-r4-r5")
    if risk is RiskClass.R6:
        findings.append("dangerous-operation-classified-r6")
    unique = tuple(dict.fromkeys(findings))
    return RiskReport(
        status=Verdict.FAIL if unique else Verdict.PASS,
        renderer_risk_class=risk.value,
        independent_floor=floor.value,
        findings=unique,
    )


# --------------------------------------------------------------------------- #
# Independent text safety and semantic comparison
# --------------------------------------------------------------------------- #


def _security_report(
    candidate: Candidate, *, parse: ParseResult,
) -> SecurityReport:
    reasons: list[str] = []
    if candidate.candidate_text is not None:
        lexed = lex_command(candidate.candidate_text)
        reasons.extend(issue.code.value for issue in lexed.issues)
        reasons.extend(scan_for_dangerous_command(candidate.candidate_text))
        if len(candidate.candidate_text) > 512:
            reasons.append("text-too-long")
    reasons.extend(
        failure.code for failure in parse.failures
        if failure.kind is FailureKind.SAFETY
    )
    unique = tuple(dict.fromkeys(reasons))
    return SecurityReport(
        status=Verdict.FAIL if unique else Verdict.PASS,
        reason_codes=unique,
    )


_TARGET_CLASS_MAP: Mapping[TargetKind, TargetClass] = {
    TargetKind.DEVICE: TargetClass.DEVICE,
    TargetKind.VLAN: TargetClass.VLAN,
    TargetKind.INTERFACE: TargetClass.INTERFACE,
    TargetKind.PORT_CHANNEL: TargetClass.PORT_CHANNEL,
}


def _canonical_integer_text(value: str) -> int | None:
    if not value or not value.isascii() or not value.isdigit():
        return None
    if len(value) > 1 and value.startswith("0"):
        return None
    return int(value)


def _port_channel_target_number(value: str) -> int | None:
    for prefix in ("Port-Channel", "Port-channel"):
        if value.startswith(prefix):
            number = _canonical_integer_text(value[len(prefix):])
            return number if number is not None and 1 <= number <= 9999 else None
    return None


def _interface_components(value: str) -> tuple[str, int, int, int] | None:
    """Split a documented interface name without reusing a renderer regex.

    The reviewed renderer envelope allows a bare decimal module component
    (leading zeros accepted, because the module number is compared
    numerically), while member and port numbers are canonical positive
    integers.
    """
    prefix_end = 0
    while prefix_end < len(value) and value[prefix_end] in _ASCII_LETTERS:
        prefix_end += 1
    prefix = value[:prefix_end].casefold()
    if prefix not in _INTERFACE_PREFIXES:
        return None
    remainder = value[prefix_end:]
    parts = remainder.split("/")
    if len(parts) != 3:
        return None
    member = _canonical_integer_text(parts[0])
    port = _canonical_integer_text(parts[2])
    if member is None or port is None:
        return None
    if not parts[1] or not parts[1].isascii() or not parts[1].isdigit():
        return None
    module = int(parts[1])
    if member < 1 or port < 1:
        return None
    return prefix, member, module, port


def _interface_name_format_reason(value: str) -> str | None:
    if not value:
        return "target-interface-name-empty"
    if len(value) > 64:
        return "target-interface-name-too-long"
    if not value.isascii():
        return "target-interface-name-non-ascii"
    if value[0] not in _ASCII_LETTERS:
        return "target-interface-name-invalid"
    if any(character not in _INTERFACE_NAME_CHARACTERS for character in value):
        return "target-interface-name-invalid"
    folded = value.casefold()
    if folded.startswith("port-channel") or folded.startswith("vlan"):
        return "target-kind-name-mismatch"
    return None


def _interface_target_reason(value: str, device: RenderDevice) -> str | None:
    """Validate the interface target against the frozen reviewed layout."""
    reason = _interface_name_format_reason(value)
    if reason is not None:
        return reason
    components = _interface_components(value)
    if components is None:
        return "target-interface-name-invalid"
    prefix, member, module, port = components
    if device.exact_pid is None:
        return "target-interface-pid-unknown"
    profile = PROFILES.get(device.exact_pid.upper())
    if profile is None:
        return "target-interface-pid-unknown"
    if device.stack_identity == "standalone":
        if member != 1:
            return "target-interface-member-slot-invalid"
    elif device.stack_identity == "resolved":
        if member not in {item.number for item in device.stack_members}:
            return "target-interface-member-slot-invalid"
    else:
        return "target-interface-stack-unresolved"
    for group in profile.ports:
        if not prefix.startswith(group.prefix):
            continue
        if module == group.slot and group.first <= port < group.first + group.count:
            return None
    return "target-interface-not-in-reviewed-layout"


def _is_uuid_text(value: str) -> bool:
    try:
        UUID(value)
    except (ValueError, AttributeError):
        return False
    return True


def _vlan_target_number(value: str) -> int | None:
    prefix = "VLAN "
    if not value.startswith(prefix):
        return None
    number = _canonical_integer_text(value[len(prefix):])
    return number if number is not None and 1 <= number <= 4094 else None


def _mode_header_mismatch(
    parsed: ParsedCommand, candidate: Candidate,
) -> str | None:
    target = candidate.target
    context = candidate.command_context
    match parsed.mode:
        case CommandMode.GLOBAL:
            expected = "global configuration"
        case CommandMode.VLAN:
            vlan_number = _vlan_target_number(target.name)
            if vlan_number is None:
                return "target-vlan-name-invalid"
            expected = f"vlan {vlan_number}"
        case CommandMode.INTERFACE | CommandMode.PORT_CHANNEL:
            expected = f"interface {target.name}"
    if context.mode_header != expected:
        return f"mode-header-mismatch:{context.mode_header}"
    return None


def _target_mismatches(
    parsed: ParsedCommand, candidate: Candidate, document: L2CliCandidateDocument,
) -> list[str]:
    mismatches: list[str] = []
    target = candidate.target
    context = candidate.command_context
    form = FORM_BY_ID.get(parsed.form_id)
    if form is None:  # pragma: no cover - parser only emits known forms
        return ["parser-form-not-in-grammar"]
    target_class = _TARGET_CLASS_MAP.get(target.kind)
    if target_class is None:
        return [f"target-kind-unknown:{target.kind.value}"]
    if target_class not in form.target_classes:
        mismatches.append(f"target-kind-not-legal-for-form:{target.kind.value}")
    mode = candidate.command_context.mode
    if mode not in form.modes:
        mismatches.append(f"context-mode-not-legal-for-form:{mode.value}")
    modes_for_target = {
        CommandMode.INTERFACE: TargetKind.INTERFACE,
        CommandMode.PORT_CHANNEL: TargetKind.PORT_CHANNEL,
    }
    expected_kind = modes_for_target.get(mode)
    if expected_kind is not None and target.kind is not expected_kind:
        mismatches.append(f"context-mode-target-mismatch:{mode.value}:{target.kind.value}")
    if context.target_name != target.name:
        mismatches.append("context-target-name-mismatch")
    header_mismatch = _mode_header_mismatch(parsed, candidate)
    if header_mismatch is not None:
        mismatches.append(header_mismatch)
    if target.kind is TargetKind.VLAN:
        vlan_number = _vlan_target_number(target.name)
        if vlan_number is None:
            mismatches.append("target-vlan-name-invalid")
        else:
            if target.stable_id != str(vlan_number):
                mismatches.append("target-vlan-stable-id-mismatch")
            if parsed.topic is CommandTopic.VLAN and (
                parsed.parameter("vlan-id") != vlan_number
            ):
                mismatches.append("target-vlan-number-mismatch")
            if parsed.topic is CommandTopic.VLAN_NAME:
                mode_number = context.mode_header.removeprefix("vlan ")
                if _canonical_integer_text(mode_number) != vlan_number:
                    mismatches.append("target-vlan-mode-header-mismatch")
    elif target.kind is TargetKind.PORT_CHANNEL:
        number = _port_channel_target_number(target.name)
        if number is None:
            mismatches.append("target-port-channel-name-invalid")
        elif parsed.topic is CommandTopic.PORT_CHANNEL_INTERFACE and (
            parsed.parameter("port-channel-number") != number
        ):
            mismatches.append("target-port-channel-number-mismatch")
        if not target.stable_id or not _is_uuid_text(target.stable_id):
            mismatches.append("target-port-channel-stable-id-invalid")
    elif target.kind is TargetKind.INTERFACE:
        reason = _interface_target_reason(target.name, document.device)
        if reason is not None:
            mismatches.append(reason)
        if not target.stable_id or not _is_uuid_text(target.stable_id):
            mismatches.append("target-interface-stable-id-invalid")
    else:
        if target.name != document.device.hostname:
            mismatches.append("target-device-hostname-mismatch")
        if target.stable_id != str(document.assignment_id):
            mismatches.append("target-device-stable-id-mismatch")
    return mismatches


def _expected_parameters(parsed: ParsedCommand) -> dict[str, object]:
    topic = parsed.topic
    if topic is CommandTopic.VLAN or topic in {
        CommandTopic.ACCESS_VLAN, CommandTopic.NATIVE_VLAN,
    }:
        return {"vlan-id": parsed.parameter("vlan-id")}
    if topic is CommandTopic.VLAN_NAME:
        return {"vlan-name": parsed.parameter("vlan-name")}
    if topic is CommandTopic.ALLOWED_VLANS:
        raw = parsed.parameter("vlan-list")
        values = list(raw) if isinstance(raw, tuple) else []
        return {"vlan-list": values, "operation": "replace"}
    if topic is CommandTopic.PORT_CHANNEL_INTERFACE:
        return {"port-channel-number": parsed.parameter("port-channel-number")}
    if topic is CommandTopic.CHANNEL_GROUP_STATIC:
        return {
            "port-channel-number": parsed.parameter("port-channel-number"),
            "mode": "on",
        }
    if topic is CommandTopic.CHANNEL_GROUP_LACP:
        return {
            "port-channel-number": parsed.parameter("port-channel-number"),
            "mode": parsed.parameter("mode"),
        }
    if topic is CommandTopic.ROOT_PRIORITY:
        return {"priority": parsed.parameter("priority")}
    if topic is CommandTopic.PORTFAST:
        return {"portfast": parsed.parameter("portfast")}
    if topic is CommandTopic.BPDU_GUARD:
        return {"bpdu-guard": parsed.parameter("bpdu-guard")}
    if topic is CommandTopic.POE_MODE:
        return {"poe-mode": parsed.parameter("poe-mode")}
    if topic is CommandTopic.SPEED:
        return {"speed": parsed.parameter("speed")}
    if topic is CommandTopic.DUPLEX:
        return {"duplex": parsed.parameter("duplex")}
    if topic is CommandTopic.DESCRIPTION:
        return {"description": parsed.parameter("description")}
    if topic is CommandTopic.ADMIN_SHUTDOWN:
        return {"admin-state": parsed.parameter("admin-state")}
    return {}


def _parameter_mismatches(
    parsed: ParsedCommand, candidate: Candidate,
) -> list[str]:
    expected = _expected_parameters(parsed)
    actual = dict(candidate.parameters)
    mismatches: list[str] = []
    for key in sorted(set(expected) | set(actual)):
        if key not in actual:
            mismatches.append(f"parameter-missing-from-candidate:{key}")
            continue
        if key not in expected:
            mismatches.append(f"parameter-not-in-parsed-command:{key}")
            continue
        if expected[key] != actual[key]:
            mismatches.append(f"parameter-mismatch:{key}")
    return mismatches


def _evidence_row(evidence_id: str) -> CommandEvidence | None:
    return next((row for row in ROWS if row.evidence_id == evidence_id), None)


def _syntax_evidence_mismatches(
    candidate: Candidate, scope: ScopeDecision, document: L2CliCandidateDocument,
) -> list[str]:
    if scope.outcome is not ScopeOutcome.ALLOWED:
        return []
    mismatches: list[str] = []
    evidence = candidate.syntax_evidence
    if not evidence:
        return ["syntax-evidence-missing"]
    if scope.evidence_id not in {entry.evidence_id for entry in evidence}:
        mismatches.append("syntax-evidence-binding-mismatch")
    for entry in evidence:
        row = _evidence_row(entry.evidence_id)
        if row is None:
            mismatches.append(f"syntax-evidence-unknown:{entry.evidence_id}")
            continue
        if entry.topic != row.topic.value:
            mismatches.append(f"syntax-evidence-topic-mismatch:{entry.evidence_id}")
        if entry.command != row.command:
            mismatches.append(f"syntax-evidence-command-mismatch:{entry.evidence_id}")
        if entry.grammar != row.grammar:
            mismatches.append(f"syntax-evidence-grammar-mismatch:{entry.evidence_id}")
        if entry.release != row.release_label:
            mismatches.append(f"syntax-evidence-release-mismatch:{entry.evidence_id}")
        if (document.device.release or "").casefold() not in {
            release.casefold() for release in row.releases
        }:
            mismatches.append(
                f"syntax-evidence-device-release-mismatch:{entry.evidence_id}"
            )
        if entry.review_state != EvidenceReviewState.REVIEWED.value:
            mismatches.append(f"syntax-evidence-review-state:{entry.evidence_id}")
        if entry.source_url != row.source_url or entry.source_section != row.source_section:
            mismatches.append(f"syntax-evidence-source-mismatch:{entry.evidence_id}")
        if entry.limits != row.limits:
            mismatches.append(f"syntax-evidence-limits-mismatch:{entry.evidence_id}")
        if entry.exclusions != row.exclusions:
            mismatches.append(
                f"syntax-evidence-exclusions-mismatch:{entry.evidence_id}"
            )
        if row.family.value != (document.device.family or ""):
            mismatches.append(f"syntax-evidence-family-mismatch:{entry.evidence_id}")
    return mismatches


def _effective_topic(
    candidate: Candidate, parsed: ParsedCommand | None,
) -> tuple[CommandTopic | None, tuple[str, ...]]:
    """Independent topic for a candidate: parsed text first, then evidence."""
    mismatches: list[str] = []
    if parsed is not None:
        return parsed.topic, ()
    for entry in candidate.syntax_evidence:
        try:
            topic = CommandTopic(entry.topic)
        except ValueError:
            mismatches.append(
                f"syntax-evidence-topic-unknown:{entry.evidence_id}"
            )
            continue
        return topic, tuple(mismatches)
    return None, tuple(mismatches)


def _category_binding_mismatches(
    candidate: Candidate,
    parsed: ParsedCommand | None,
    effective_topic: CommandTopic | None,
) -> list[str]:
    """Bind the renderer's category to the parsed/evidence topic."""
    mismatches: list[str] = []
    if effective_topic is not None:
        expected = TOPIC_CATEGORY.get(effective_topic)
        if expected is not None and candidate.category.value != expected:
            mismatches.append(
                f"category-topic-mismatch:{candidate.category.value}:{expected}"
            )
    for entry in candidate.syntax_evidence:
        row = _evidence_row(entry.evidence_id)
        if row is None:
            continue
        expected = TOPIC_CATEGORY.get(row.topic)
        if expected is not None and candidate.category.value != expected:
            mismatches.append(
                f"category-evidence-topic-mismatch:{entry.evidence_id}"
            )
        if parsed is not None and row.topic is not parsed.topic:
            mismatches.append(
                f"parsed-evidence-topic-mismatch:{entry.evidence_id}"
            )
    if candidate.category.value in _NON_SYNTAX_CATEGORIES:
        if candidate.syntax_evidence:
            mismatches.append("non-syntax-category-carries-evidence")
        if parsed is not None:
            mismatches.append("non-syntax-category-carries-parsed-command")
    if (
        candidate.status is CandidateStatus.CANDIDATE
        and effective_topic is None
    ):
        mismatches.append("visible-candidate-without-topic-binding")
    return list(dict.fromkeys(mismatches))


def _semantic_mismatches(
    parsed: ParsedCommand,
    candidate: Candidate,
    document: L2CliCandidateDocument,
    scope: ScopeDecision,
    effective_topic: CommandTopic | None,
) -> list[str]:
    mismatches = _target_mismatches(parsed, candidate, document)
    mismatches.extend(_parameter_mismatches(parsed, candidate))
    mismatches.extend(_syntax_evidence_mismatches(candidate, scope, document))
    mismatches.extend(
        _category_binding_mismatches(candidate, parsed, effective_topic)
    )
    if candidate.assignment_id != document.assignment_id:
        mismatches.append("candidate-assignment-mismatch")
    return list(dict.fromkeys(mismatches))


# --------------------------------------------------------------------------- #
# Report construction
# --------------------------------------------------------------------------- #


def _integrity_report(
    document: L2CliCandidateDocument,
    *,
    expected: ExpectedSource | None,
) -> IntegrityReport:
    failures: list[str] = []
    recomputed = recompute_render_fingerprint(document)
    render_match = recomputed == document.render_fingerprint
    if not render_match:
        failures.append("render-fingerprint-mismatch")

    candidate_fingerprints_match = True
    for candidate in document.candidates:
        if recompute_candidate_fingerprint(candidate) != candidate.candidate_fingerprint:
            candidate_fingerprints_match = False
            failures.append(
                f"candidate-fingerprint-mismatch:{candidate.candidate_id}"
            )

    ids = [candidate.candidate_id for candidate in document.candidates]
    ids_unique = len(set(ids)) == len(ids) and all(
        _is_candidate_id(value) for value in ids
    )
    if not ids_unique:
        failures.append("candidate-id-not-unique-or-malformed")

    source = document.source
    source_format_ok = (
        document.render_schema_version == 1
        and document.contract_id == "cis-02b2-cisco-l2-cli-candidate-v1"
        and source.intent_schema_version == 1
        and source.preview_schema_version == 1
        and source.preview_contract_id == "cis-02b1-layer2-config-preview-v1"
        and _is_sha256_hex(source.revision_canonical_hash)
        and _is_sha256_hex(source.intent_fingerprint)
        and _is_sha256_hex(source.preview_fingerprint)
        and _is_sha256_hex(source.command_evidence_fingerprint)
    )
    if not source_format_ok:
        failures.append("source-binding-format-invalid")

    expected_registry_fingerprint = canonical_sha256(
        evidence_reference(DEFAULT_REGISTRY)
    )
    registry_binding_ok = (
        source.command_evidence_registry_id == EVIDENCE_REGISTRY_ID
        and source.command_evidence_fingerprint == expected_registry_fingerprint
    )
    if not registry_binding_ok:
        failures.append("command-evidence-registry-binding-mismatch")

    digest_ok = True
    for candidate in document.candidates:
        for evidence in candidate.syntax_evidence:
            row = _evidence_row(evidence.evidence_id)
            if row is None:
                digest_ok = False
                failures.append(
                    f"syntax-evidence-unknown:{evidence.evidence_id}"
                )
                continue
            if row.review.state is EvidenceReviewState.REVIEWED and (
                row.review.content_digest != row.content_digest
            ):
                digest_ok = False
                failures.append(
                    f"evidence-content-digest-mismatch:{evidence.evidence_id}"
                )

    assignment_ok = all(
        candidate.assignment_id == document.assignment_id
        for candidate in document.candidates
    )
    if not assignment_ok:
        failures.append("assignment-binding-mismatch")

    expected_ok = True
    if expected is not None:
        checks: tuple[tuple[str, object, object], ...] = (
            ("saved_revision_uuid", expected.saved_revision_uuid, source.saved_revision_uuid),
            ("revision_number", expected.revision_number, source.revision_number),
            (
                "revision_canonical_hash",
                expected.revision_canonical_hash, source.revision_canonical_hash,
            ),
            ("intent_fingerprint", expected.intent_fingerprint, source.intent_fingerprint),
            ("preview_fingerprint", expected.preview_fingerprint, source.preview_fingerprint),
            ("render_fingerprint", expected.render_fingerprint, document.render_fingerprint),
            ("assignment_id", expected.assignment_id, document.assignment_id),
        )
        for name, expected_value, actual in checks:
            if expected_value is not None and expected_value != actual:
                expected_ok = False
                failures.append(f"expected-source-mismatch:{name}")

    return IntegrityReport(
        status=Verdict.FAIL if failures else Verdict.PASS,
        render_fingerprint_recomputed=recomputed,
        render_fingerprint_match=render_match,
        candidate_fingerprints_match=candidate_fingerprints_match,
        candidate_ids_unique=ids_unique,
        source_binding_format_ok=source_format_ok,
        evidence_content_digests_ok=digest_ok,
        assignment_binding_ok=assignment_ok,
        expected_source_match=expected_ok,
        failures=tuple(dict.fromkeys(failures)),
    )


def _candidate_validation(
    document: L2CliCandidateDocument,
    candidate: Candidate,
    *,
    device: DeviceScope,
    integrity: IntegrityReport,
) -> CandidateValidation:
    recomputed = recompute_candidate_fingerprint(candidate)
    fingerprint_match = recomputed == candidate.candidate_fingerprint

    if candidate.status is CandidateStatus.CANDIDATE:
        parse = parse_command(
            candidate.candidate_text, expected_mode=candidate.command_context.mode,
        )
    else:
        parse = parse_command(candidate.candidate_text) if (
            candidate.candidate_text is not None
        ) else ParseResult("", (), None, (), ())

    parse_report = ParseReport(
        status=(
            Verdict.PASS if parse.ok
            else Verdict.FAIL if parse.failures
            else Verdict.NOT_RUN
        ),
        failures=tuple(
            FailureReport(kind=failure.kind.value, code=failure.code, detail=failure.detail)
            for failure in parse.failures
        ),
    )
    scope: ScopeDecision
    if parse.command is not None:
        scope = classify_scope(parse.command, device)
        parse_report = parse_report.model_copy(update={
            "topic": parse.command.topic.value,
            "form": parse.command.form_id,
            "mode": parse.command.mode.value,
            "modes": tuple(
                sorted(mode.value for mode in FORM_BY_ID[parse.command.form_id].modes)
            ),
            "target_class": parse.command.target_class.value,
            "parameters": _json_parameters(parse.command),
        })
    else:
        scope = ScopeDecision(
            ScopeOutcome.NOT_RUN, None, None,
            "parse-failed-or-not-run",
            "scope validation requires a parsed command",
        )
    if candidate.status is not CandidateStatus.CANDIDATE:
        scope = ScopeDecision(
            ScopeOutcome.NOT_RUN, None, None,
            f"renderer-{candidate.status.value}-no-text-parsed",
            "the frozen renderer did not expose a text candidate; no promotion",
        )
    scope_report = ScopeReport(
        status=scope.outcome,
        evidence_id=scope.evidence_id,
        evidence_review_state=scope.evidence_review_state,
        reason_code=scope.reason_code,
        detail=scope.detail,
    )

    security = _security_report(candidate, parse=parse)
    if candidate.status is not CandidateStatus.CANDIDATE and candidate.candidate_text is None:
        security = SecurityReport(status=Verdict.NOT_RUN)

    semantic = SemanticReport(status=Verdict.NOT_RUN)
    effective_topic, topic_failures = _effective_topic(candidate, parse.command)
    binding_mismatches = list(topic_failures)
    binding_mismatches.extend(_category_binding_mismatches(
        candidate, parse.command, effective_topic,
    ))
    context_row = (
        _evidence_row(scope.evidence_id) if scope.evidence_id is not None else None
    )
    if context_row is None and candidate.syntax_evidence:
        context_row = _evidence_row(candidate.syntax_evidence[0].evidence_id)
    context_binding = _context_binding_report(
        candidate, parse.command, effective_topic, context_row,
    )
    target_capability = _target_capability_report(
        candidate, parse.command, effective_topic, document.device,
    )
    if parse.command is not None and candidate.status is CandidateStatus.CANDIDATE:
        mismatches = _semantic_mismatches(
            parse.command, candidate, document, scope, effective_topic,
        )
        semantic = SemanticReport(
            status=Verdict.FAIL if mismatches else Verdict.PASS,
            mismatches=tuple(mismatches),
        )
    elif binding_mismatches:
        semantic = SemanticReport(
            status=Verdict.FAIL,
            mismatches=tuple(dict.fromkeys(binding_mismatches)),
        )

    risk = review_candidate_risk(
        candidate, device=document.device, effective_topic=effective_topic,
    )

    failures: list[str] = []
    if not fingerprint_match:
        failures.append("candidate-fingerprint-mismatch")
    if binding_mismatches:
        failures.append("category-topic-binding-mismatch")
    if candidate.status is CandidateStatus.CANDIDATE:
        if parse_report.status is not Verdict.PASS:
            failures.append("independent-parse-failed")
        if scope_report.status is not ScopeOutcome.ALLOWED:
            failures.append("independent-scope-not-allowed")
        if security.status is not Verdict.PASS:
            failures.append("independent-security-failed")
        if semantic.status is not Verdict.PASS:
            failures.append("independent-semantics-mismatch")
        if context_binding.status is not Verdict.PASS:
            failures.append("independent-context-binding-failed")
        if target_capability.status is Verdict.FAIL:
            failures.append("independent-target-capability-failed")
    if risk.status is Verdict.FAIL:
        failures.append("independent-risk-review-failed")

    if candidate.status is CandidateStatus.CANDIDATE:
        verdict = Verdict.FAIL if failures else Verdict.PASS
        fail_closed_action = (
            "block-visible-candidate-until-independent-validation-passes"
            if verdict is Verdict.FAIL else None
        )
    else:
        verdict = Verdict.FAIL if failures else Verdict.NOT_RUN
        fail_closed_action = None
    if integrity.status is Verdict.FAIL:
        verdict = Verdict.FAIL
        fail_closed_action = "reject-document-until-source-integrity-passes"

    return CandidateValidation(
        candidate_id=candidate.candidate_id,
        category=candidate.category.value,
        renderer_status=candidate.status.value,
        candidate_text_present=candidate.candidate_text is not None,
        syntax_validation_level=candidate.syntax_validation.level.value,
        parser_verified=candidate.syntax_validation.parser_verified,
        candidate_fingerprint=candidate.candidate_fingerprint,
        candidate_fingerprint_recomputed=recomputed,
        candidate_fingerprint_match=fingerprint_match,
        parse=parse_report,
        scope=scope_report,
        context_binding=context_binding,
        target_capability=target_capability,
        security=security,
        semantics=semantic,
        risk=risk,
        independent_verdict=verdict,
        fail_closed_action=fail_closed_action,
    )


def _json_parameters(parsed: ParsedCommand) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = {}
    for key, value in sorted(parsed.json_parameters().items()):
        if isinstance(value, list):
            payload[key] = [item for item in value if isinstance(item, (int, str))]
        elif isinstance(value, (int, str, bool)):
            payload[key] = value
        elif value is None:
            payload[key] = None
        else:  # pragma: no cover - closed parser output vocabulary
            payload[key] = str(value)
    return payload


def _registry_coverage() -> tuple[RegistryCoverageRecord, ...]:
    records: list[RegistryCoverageRecord] = []
    for row in ROWS:
        device = DeviceScope(
            family=row.family,
            pid=row.pids[0] if row.pids else None,
            release=row.releases[0] if row.releases else None,
            license=row.licenses[0] if row.licenses else None,
            stack_identity="standalone",
            stack_members=(),
        )
        canonical = parse_command(COVERAGE_COMMAND_BY_TOPIC[row.topic])
        if canonical.ok and canonical.command is not None:
            decision = classify_scope(canonical.command, device)
            parse_status = Verdict.PASS
        else:
            decision = ScopeDecision(
                ScopeOutcome.NOT_RUN, None, None, "coverage-command-parse-failed",
                "the hand-authored coverage command did not parse",
            )
            parse_status = Verdict.FAIL
        records.append(RegistryCoverageRecord(
            evidence_id=row.evidence_id,
            topic=row.topic.value,
            family=row.family.value,
            pids=row.pids,
            releases=row.releases,
            licenses=row.licenses,
            review_state=row.review.state.value,
            renderable=row.renderable,
            canonical_parse_status=parse_status,
            independent_scope_verdict=decision.outcome,
            evidence_id_resolved=decision.evidence_id,
            reason_code=decision.reason_code,
        ))
    return tuple(records)


def _topology_review(
    document: L2CliCandidateDocument,
    candidate_reports: tuple[CandidateValidation, ...],
    *,
    device: DeviceBinding,
    integrity: IntegrityReport,
) -> TopologyReview:
    checks: list[TopologyCheck] = []
    findings: list[str] = []

    dangerous: list[str] = []
    for candidate in document.candidates:
        if candidate.candidate_text is None:
            continue
        codes = scan_for_dangerous_command(candidate.candidate_text)
        dangerous.extend(
            f"dangerous-command-text:{candidate.candidate_id}:{code}" for code in codes
        )
    findings.extend(dangerous)
    checks.append(TopologyCheck(
        name="no-dangerous-command-text",
        status=Verdict.FAIL if dangerous else Verdict.PASS,
        findings=tuple(dangerous),
    ))

    cleanup_texts = tuple(
        f"cleanup-candidate-text:{candidate.candidate_id}"
        for candidate in document.candidates
        if candidate.provenance.cleanup and candidate.candidate_text is not None
    )
    findings.extend(cleanup_texts)
    checks.append(TopologyCheck(
        name="no-cleanup-command-text",
        status=Verdict.FAIL if cleanup_texts else Verdict.PASS,
        findings=cleanup_texts,
    ))

    document_keys = _iter_keys(document.model_dump(mode="json"))
    forbidden_keys = tuple(
        f"forbidden-document-key:{key}"
        for key in sorted(set(document_keys) & FORBIDDEN_DOCUMENT_KEYS)
    )
    findings.extend(forbidden_keys)
    checks.append(TopologyCheck(
        name="no-execution-order-fields",
        status=Verdict.FAIL if forbidden_keys else Verdict.PASS,
        findings=forbidden_keys,
    ))

    r6_visible = tuple(
        f"r6-operation-visible:{candidate.candidate_id}"
        for candidate in document.candidates
        if candidate.risk_class is RiskClass.R6
        and (
            candidate.status is CandidateStatus.CANDIDATE
            or candidate.candidate_text is not None
        )
    )
    findings.extend(r6_visible)
    checks.append(TopologyCheck(
        name="no-r6-visible-command",
        status=Verdict.FAIL if r6_visible else Verdict.PASS,
        findings=r6_visible,
    ))

    topology_topic_values = {
        topic.value for topic in CommandTopic
        if TOPIC_CATEGORY[topic] in _TOPOLOGY_WIDE_CATEGORIES
    }
    promoted = tuple(
        f"topology-wide-command-visible:{report.candidate_id}"
        for report in candidate_reports
        if report.renderer_status == CandidateStatus.CANDIDATE.value and (
            (report.parse.topic or "") in topology_topic_values
            or any(
                finding.startswith("topology-wide-command-visible")
                for finding in report.risk.findings
            )
        )
    )
    findings.extend(promoted)
    checks.append(TopologyCheck(
        name="topology-wide-commands-not-promoted",
        status=Verdict.FAIL if promoted else Verdict.PASS,
        findings=promoted,
    ))

    visible_r5 = tuple(
        f"r5-candidate-visible:{candidate.candidate_id}"
        for candidate in document.candidates
        if candidate.status is CandidateStatus.CANDIDATE
        and candidate.risk_class in {RiskClass.R5, RiskClass.R6}
    )
    findings.extend(visible_r5)
    checks.append(TopologyCheck(
        name="no-visible-r5-r6-candidate",
        status=Verdict.FAIL if visible_r5 else Verdict.PASS,
        findings=visible_r5,
    ))

    safety_findings: list[str] = []
    safety = document.safety
    expected_safety: tuple[tuple[str, object], ...] = (
        ("candidate_only", True),
        ("executable", False),
        ("deployable", False),
        ("deployment_allowed", False),
        ("device_connection", "none"),
        ("running_config_read", False),
        ("device_writes_enabled", False),
        ("cli", None),
        ("deployment_artifact", None),
        ("device_runtime_state", "unknown-not-read"),
        ("hardware_verified", False),
    )
    for name, expected in expected_safety:
        actual = getattr(safety, name)
        if actual != expected:
            safety_findings.append(f"renderer-safety-invariant-violated:{name}")
    if document.device_runtime_state != "unknown-not-read":
        safety_findings.append("renderer-safety-invariant-violated:device_runtime_state")
    missing_blockers = tuple(
        f"deployment-blocker-missing:{blocker}"
        for blocker in REQUIRED_DEPLOYMENT_BLOCKERS
        if blocker not in document.deployment_blockers
    )
    safety_findings.extend(missing_blockers)
    findings.extend(safety_findings)
    checks.append(TopologyCheck(
        name="renderer-safety-invariants-preserved",
        status=Verdict.FAIL if safety_findings else Verdict.PASS,
        findings=tuple(safety_findings),
    ))

    summary = document.summary
    statuses = [candidate.status for candidate in document.candidates]
    summary_findings: list[str] = []
    if summary.total != len(document.candidates):
        summary_findings.append("renderer-summary-total-mismatch")
    if summary.candidates != statuses.count(CandidateStatus.CANDIDATE):
        summary_findings.append("renderer-summary-candidate-count-mismatch")
    if summary.blocked != statuses.count(CandidateStatus.BLOCKED):
        summary_findings.append("renderer-summary-blocked-count-mismatch")
    if summary.unsupported != statuses.count(CandidateStatus.UNSUPPORTED):
        summary_findings.append("renderer-summary-unsupported-count-mismatch")
    rendered_categories = tuple(dict.fromkeys(
        candidate.category.value for candidate in document.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    ))
    if summary.categories_rendered != rendered_categories:
        summary_findings.append("renderer-summary-categories-mismatch")
    if summary.candidates and document.render_state.value != "review-candidates":
        summary_findings.append("renderer-render-state-mismatch")
    if not summary.candidates and not any(
        blocker.startswith("device-identity-incomplete:")
        for blocker in document.deployment_blockers
    ) and document.render_state.value != "no-supported-candidates":
        summary_findings.append("renderer-render-state-mismatch")
    findings.extend(summary_findings)
    checks.append(TopologyCheck(
        name="renderer-status-preserved",
        status=Verdict.FAIL if summary_findings else Verdict.PASS,
        findings=tuple(summary_findings),
    ))

    visible_candidates = any(
        candidate.status is CandidateStatus.CANDIDATE
        for candidate in document.candidates
    )
    identity_findings: list[str] = []
    if device.identity_verdict is Verdict.FAIL:
        if visible_candidates:
            identity_findings.extend(
                f"device-identity-failed-with-visible-candidate:{reason}"
                for reason in device.identity_reasons
            )
        if any(
            blocker.startswith("device-identity-incomplete:")
            for blocker in document.deployment_blockers
        ) and visible_candidates:
            identity_findings.append(
                "hard-blocked-document-exposes-visible-candidate"
            )
    findings.extend(identity_findings)
    checks.append(TopologyCheck(
        name="device-identity-gate-respected",
        status=Verdict.FAIL if identity_findings else Verdict.PASS,
        findings=tuple(identity_findings),
    ))

    if integrity.status is Verdict.FAIL:
        findings.extend(f"integrity:{failure}" for failure in integrity.failures)
    return TopologyReview(
        status=Verdict.FAIL if findings else Verdict.PASS,
        checks=tuple(checks),
        findings=tuple(dict.fromkeys(findings)),
    )


def _device_binding(device: RenderDevice, scope: DeviceScope) -> DeviceBinding:
    reasons = device_identity_findings(scope)
    return DeviceBinding(
        hostname=device.hostname,
        family=device.family,
        exact_pid=device.exact_pid,
        release=device.release,
        license=device.license,
        role=device.role,
        stack_identity=device.stack_identity,
        stack_members=tuple(
            StackMemberBinding(
                number=member.number,
                exact_pid=member.exact_pid,
                state=member.state,
            )
            for member in device.stack_members
        ),
        identity_verdict=Verdict.FAIL if reasons else Verdict.PASS,
        identity_reasons=reasons,
    )


def _report_fingerprint(report: ValidationReport) -> str:
    payload = report.model_dump(mode="json")
    payload.pop("report_fingerprint", None)
    return canonical_sha256(payload)


def validate_candidate_document(
    document: L2CliCandidateDocument,
    *,
    expected: ExpectedSource | None = None,
) -> ValidationReport:
    """Independently validate the frozen renderer document for one Assignment."""
    device_scope = device_scope_of(document.device)
    device = _device_binding(document.device, device_scope)
    integrity = _integrity_report(document, expected=expected)
    candidates = tuple(
        _candidate_validation(
            document, candidate, device=device_scope, integrity=integrity,
        )
        for candidate in document.candidates
    )
    registry_coverage = _registry_coverage()
    topology_review = _topology_review(
        document, candidates, device=device, integrity=integrity,
    )

    summary_candidates = [item for item in candidates]
    parse_pass = sum(
        1 for item in summary_candidates if item.parse.status is Verdict.PASS
    )
    parse_fail = sum(
        1 for item in summary_candidates if item.parse.status is Verdict.FAIL
    )
    not_run = sum(
        1 for item in summary_candidates if item.parse.status is Verdict.NOT_RUN
    )
    scope_blocked = sum(
        1 for item in summary_candidates if item.scope.status is ScopeOutcome.BLOCKED
    )
    context_fail = sum(
        1 for item in summary_candidates if item.context_binding.status is Verdict.FAIL
    )
    capability_fail = sum(
        1 for item in summary_candidates
        if item.target_capability.status is Verdict.FAIL
    )
    capability_not_run = sum(
        1 for item in summary_candidates
        if item.target_capability.status is Verdict.NOT_RUN
    )
    security_fail = sum(
        1 for item in summary_candidates if item.security.status is Verdict.FAIL
    )
    semantic_mismatch = sum(
        1 for item in summary_candidates if item.semantics.status is Verdict.FAIL
    )
    risk_fail = sum(
        1 for item in summary_candidates if item.risk.status is Verdict.FAIL
    )
    failed = sum(
        1 for item in summary_candidates if item.independent_verdict is Verdict.FAIL
    )
    topics = tuple(sorted({
        item.parse.topic for item in summary_candidates
        if item.parse.status is Verdict.PASS and item.parse.topic is not None
    }))
    reviewed = sum(1 for row in ROWS if row.renderable)
    rejected = sum(
        1 for row in ROWS
        if row.review.state is EvidenceReviewState.REJECTED
    )
    unreviewed = len(ROWS) - reviewed - rejected
    overall = (
        Verdict.PASS
        if not failed
        and integrity.status is Verdict.PASS
        and topology_review.status is Verdict.PASS
        else Verdict.FAIL
    )

    summary = ValidationSummary(
        total_candidates=len(candidates),
        parsed_candidates=parse_pass,
        parse_pass=parse_pass,
        parse_fail=parse_fail,
        not_run=not_run,
        scope_blocked=scope_blocked,
        context_fail=context_fail,
        capability_fail=capability_fail,
        capability_not_run=capability_not_run,
        security_fail=security_fail,
        semantic_mismatch=semantic_mismatch,
        risk_fail=risk_fail,
        failed_candidates=failed,
        topics_parsed=topics,
        registry_rows=len(ROWS),
        registry_reviewed=reviewed,
        registry_rejected=rejected,
        registry_unreviewed=unreviewed,
        overall_status=overall,
    )

    report = ValidationReport(
        source=SourceBinding(
            render_schema_version=document.render_schema_version,
            render_contract_id=document.contract_id,
            saved_revision_uuid=document.source.saved_revision_uuid,
            revision_number=document.source.revision_number,
            revision_canonical_hash=document.source.revision_canonical_hash,
            intent_schema_version=document.source.intent_schema_version,
            intent_fingerprint=document.source.intent_fingerprint,
            preview_schema_version=document.source.preview_schema_version,
            preview_contract_id=document.source.preview_contract_id,
            preview_fingerprint=document.source.preview_fingerprint,
            command_evidence_registry_id=document.source.command_evidence_registry_id,
            command_evidence_fingerprint=document.source.command_evidence_fingerprint,
            render_fingerprint=document.render_fingerprint,
            assignment_id=document.assignment_id,
        ),
        device=device,
        assignment_id=document.assignment_id,
        integrity=integrity,
        candidates=candidates,
        registry_coverage=registry_coverage,
        topology_review=topology_review,
        summary=summary,
        safety=ValidationSafety(),
        report_fingerprint="0" * 64,
    )
    return report.model_copy(
        update={"report_fingerprint": _report_fingerprint(report)},
    )
