"""CIS-03-03B independent L3 candidate validator.

The validator consumes a trusted saved revision, its rebuilt ``Layer3Intent``,
an immutable L3 candidate document and an explicit ``ExpectedSource``.  It
recomputes every fingerprint itself, parses every non-empty candidate with the
independent parser, and re-derives evidence, capability, context and route/SVI
semantics from the trusted intent and production evidence registry.

It intentionally does not import or call renderer construction/check helpers.
A report is returned only after all integrity checks pass; candidate-level
semantic or evidence failures are reported as fail-closed verdicts, never as
deployment authorization.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from enum import StrEnum
from ipaddress import IPv4Address
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from ..domain import DeviceRole
from .layer3_capability import (
    DocumentationStatus,
    L3Capability,
    L3Verdict,
    PrerequisiteStatus,
)
from .layer3_cli_candidates import (
    Candidate,
    CandidateCategory,
    CandidateStatus,
    L3CandidateDocument,
)
from .layer3_cli_grammar import (
    SAFE_DISTANCE_MAX,
    SVI_PREFIX_MAX,
    SVI_PREFIX_MIN,
    L3Form,
    L3RiskFloor,
    is_reserved_vlan,
)
from .layer3_cli_parser import (
    ParsedCommand,
    parse_l3_command,
)
from .layer3_command_evidence import (
    DEFAULT_REGISTRY,
    REVIEW_LIFECYCLE_GAP,
    CommandEvidenceRegistry,
    CommandEvidenceRow,
    EvidenceReviewState,
    L3CommandMode,
    L3CommandTopic,
)
from .layer3_intent import (
    L3DeviceIntent,
    L3DocumentationVerdict,
    L3InterfaceIntent,
    L3RouteIntent,
    L3RuntimeVerdict,
    Layer3Intent,
    build_layer3_intent,
)
from .layer3_registry_selection import (
    RegistrySelectionError,
    assert_production_registry,
)
from .plan import PlanRevision, canonical_plan, plan_hash
from .types import Record

VALIDATION_CONTRACT_ID: Literal["cis-03-03-independent-cli-validation-v1"] = (
    "cis-03-03-independent-cli-validation-v1"
)
VALIDATION_SCHEMA_VERSION: Literal[1] = 1
CANDIDATE_CONTRACT_ID: Literal["cis-03-cisco-l3-cli-candidate-v1"] = (
    "cis-03-cisco-l3-cli-candidate-v1"
)
CANDIDATE_SCHEMA_VERSION: Literal[1] = 1

_BASE_CATEGORIES = frozenset({
    CandidateCategory.IP_ROUTING,
    CandidateCategory.SVI_INTERFACE,
    CandidateCategory.SVI_ADDRESS,
    CandidateCategory.STATIC_ROUTE,
    CandidateCategory.DEFAULT_ROUTE,
})
_CATEGORY_TOPIC = {
    CandidateCategory.IP_ROUTING: L3CommandTopic.IP_ROUTING,
    CandidateCategory.SVI_INTERFACE: L3CommandTopic.SVI_INTERFACE,
    CandidateCategory.SVI_ADDRESS: L3CommandTopic.SVI_ADDRESS,
    CandidateCategory.STATIC_ROUTE: L3CommandTopic.STATIC_ROUTE,
    CandidateCategory.DEFAULT_ROUTE: L3CommandTopic.DEFAULT_ROUTE,
    CandidateCategory.DHCP_HELPER_ADDRESS: L3CommandTopic.DHCP_HELPER_ADDRESS,
}
_CATEGORY_CAPABILITY = {
    CandidateCategory.IP_ROUTING: L3Capability.IPV4_ROUTING,
    CandidateCategory.SVI_INTERFACE: L3Capability.SVI,
    CandidateCategory.SVI_ADDRESS: L3Capability.SVI,
    CandidateCategory.STATIC_ROUTE: L3Capability.STATIC_ROUTE,
    CandidateCategory.DEFAULT_ROUTE: L3Capability.DEFAULT_ROUTE,
    CandidateCategory.DHCP_HELPER_ADDRESS: L3Capability.DHCP_RELAY,
}
_CATEGORY_FORM = {
    CandidateCategory.IP_ROUTING: L3Form.IP_ROUTING,
    CandidateCategory.SVI_INTERFACE: L3Form.SVI_INTERFACE,
    CandidateCategory.SVI_ADDRESS: L3Form.SVI_ADDRESS,
    CandidateCategory.STATIC_ROUTE: L3Form.STATIC_ROUTE,
    CandidateCategory.DEFAULT_ROUTE: L3Form.DEFAULT_ROUTE,
    CandidateCategory.DHCP_HELPER_ADDRESS: L3Form.DHCP_HELPER_ADDRESS,
}
_CATEGORY_RISK_FLOOR = {
    CandidateCategory.IP_ROUTING: L3RiskFloor.R2,
    CandidateCategory.SVI_INTERFACE: L3RiskFloor.R2,
    CandidateCategory.SVI_ADDRESS: L3RiskFloor.R2,
    CandidateCategory.STATIC_ROUTE: L3RiskFloor.R2,
    CandidateCategory.DEFAULT_ROUTE: L3RiskFloor.R3,
    CandidateCategory.DHCP_HELPER_ADDRESS: L3RiskFloor.R2,
}


class IndependentVerdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    BLOCKED = "blocked"
    NOT_RUN = "not-run"


class ReportOverall(StrEnum):
    PASS = "pass"
    PARTIAL = "partial"
    FAIL = "fail"


class ValidationIntegrityError(ValueError):
    """Integrity failure: no trustworthy report may be returned."""

    def __init__(self, reason_code: str, reasons: tuple[str, ...] = ()) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.reasons = reasons


class ExpectedSource(Record):
    event_id: UUID
    saved_revision_uuid: UUID
    revision_number: int
    revision_canonical_hash: str
    l3_intent_schema_version: int
    l3_intent_fingerprint: str
    l3_render_contract_id: str
    l3_render_contract_version: int
    l3_render_fingerprint: str
    command_evidence_registry_id: str
    command_evidence_registry_fingerprint: str
    assignment_id: UUID
    baseline_revision_uuid: UUID | None = None
    baseline_revision_hash: str | None = None


class ActualSource(Record):
    event_id: UUID
    saved_revision_uuid: UUID
    revision_number: int
    revision_canonical_hash: str
    l3_intent_schema_version: int
    l3_intent_fingerprint: str
    l3_render_contract_id: str
    l3_render_contract_version: int
    l3_render_fingerprint: str
    command_evidence_registry_id: str
    command_evidence_registry_fingerprint: str
    assignment_id: UUID
    baseline_revision_uuid: UUID | None = None
    baseline_revision_hash: str | None = None


class ValidationDevice(Record):
    assignment_id: UUID
    hostname: str
    role: str
    family: str | None
    exact_pid: str | None
    software_image: str | None
    software_license: str | None
    stack_identity: str
    hardware_verified: Literal[False] = False


class ValidationParameter(Record):
    name: str
    value: str | int


class ValidationParse(Record):
    status: str
    form: str | None = None
    mode: str | None = None
    target_class: str | None = None
    parameters: tuple[ValidationParameter, ...] = ()
    failures: tuple[str, ...] = ()


class ValidationEvidence(Record):
    evidence_id: str | None = None
    topic: str | None = None
    review_state: str | None = None
    content_digest: str | None = None
    source_url: str | None = None
    source_section: str | None = None
    scope_ok: bool = False
    reason_codes: tuple[str, ...] = ()


class ValidationContext(Record):
    expected_mode: str
    actual_mode: str | None
    header_bound: bool
    target_kind: str
    target_stable_id: UUID
    target_name: str
    bound: bool = False
    reason_codes: tuple[str, ...] = ()


class ValidationCapability(Record):
    capability: str
    verdict: str | None = None
    documented: bool = False
    reason_codes: tuple[str, ...] = ()


class ValidationSecurity(Record):
    text_safe: bool
    reason_codes: tuple[str, ...] = ()


class ValidationSemantics(Record):
    status: str
    reason_codes: tuple[str, ...] = ()


class ValidationRisk(Record):
    renderer_risk: str
    independent_floor: str
    non_degraded: bool
    reason_codes: tuple[str, ...] = ()


class CandidateValidation(Record):
    candidate_id: str
    category: str
    target_kind: str
    target_stable_id: UUID
    target_name: str
    parse: ValidationParse
    evidence: ValidationEvidence
    context_binding: ValidationContext
    target_capability: ValidationCapability
    security: ValidationSecurity
    semantics: ValidationSemantics
    risk: ValidationRisk
    independent_verdict: IndependentVerdict
    fail_closed_action: str


class ValidationSummary(Record):
    total: int
    passed: int
    failed: int
    blocked: int
    not_run: int
    base_categories_passed: int
    base_categories_failed: int
    base_candidates_passed: int
    base_candidates_failed: int
    dhcp_helper_blocked: bool


class ValidationIntegrity(Record):
    revision_canonical_hash: bool
    baseline_canonical_hash: bool
    intent_rebuilt: bool
    intent_fingerprint: bool
    expected_source: bool
    document_source: bool
    document_fingerprint: bool
    candidate_fingerprints: bool
    candidate_ids_unique: bool
    candidate_set: bool
    summary: bool
    safety: bool


class ValidationSafety(Record):
    candidate_only: Literal[True] = True
    executable: Literal[False] = False
    deployable: Literal[False] = False
    deployment_allowed: Literal[False] = False
    hardware_verified: Literal[False] = False
    device_connection: Literal["none"] = "none"
    running_config_read: Literal[False] = False
    device_writes_enabled: Literal[False] = False
    cli: None = None
    deployment_artifact: None = None
    independent_parser: Literal["cis-03-03b"] = "cis-03-03b"
    parser_verified: Literal[True] = True
    deployment_authorized: Literal[False] = False


class L3ValidationReport(Record):
    validation_contract_id: Literal[
        "cis-03-03-independent-cli-validation-v1"
    ] = VALIDATION_CONTRACT_ID
    validation_schema_version: Literal[1] = VALIDATION_SCHEMA_VERSION
    validation_scope: Literal["production", "test-only"] = "production"
    expected_source: ExpectedSource
    source: ActualSource
    assignment_id: UUID
    device: ValidationDevice
    integrity: ValidationIntegrity
    candidates: tuple[CandidateValidation, ...] = ()
    summary: ValidationSummary
    overall_status: ReportOverall
    safety: ValidationSafety = ValidationSafety()
    report_fingerprint: str


def _json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: JsonValue) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def independent_intent_fingerprint(intent: Layer3Intent) -> str:
    payload = intent.model_dump(mode="json")
    payload.pop("intent_fingerprint")
    return _sha256_json(payload)


def independent_candidate_fingerprint(candidate: Candidate) -> str:
    payload = candidate.model_dump(mode="json")
    payload.pop("candidate_fingerprint")
    return _sha256_json(payload)


def independent_render_fingerprint(document: L3CandidateDocument) -> str:
    payload = document.model_dump(mode="json")
    payload.pop("l3_render_fingerprint")
    return _sha256_json(payload)


def independent_report_fingerprint(report: L3ValidationReport) -> str:
    payload = report.model_dump(mode="json")
    payload.pop("report_fingerprint")
    return _sha256_json(payload)


def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _risk_rank(value: str) -> int:
    return {"R2": 2, "R3": 3}.get(value, 0)


def _evidence_topic(category: CandidateCategory) -> L3CommandTopic:
    return _CATEGORY_TOPIC[category]


def _candidate_key(candidate: Candidate) -> tuple[str, str, str, str]:
    extra = ""
    if candidate.category is CandidateCategory.DHCP_HELPER_ADDRESS:
        if candidate.candidate_text is not None:
            parsed = parse_l3_command(candidate.candidate_text)
            if parsed.ok:
                extra = str(parsed.parameter("server") or "")
        if not extra and " -> " in candidate.target.name:
            extra = candidate.target.name.rsplit(" -> ", 1)[1]
    return (
        candidate.category.value,
        candidate.target.kind,
        str(candidate.target.stable_id),
        extra,
    )


def _expected_candidate_keys(device: L3DeviceIntent) -> tuple[tuple[str, str, str, str], ...]:
    keys: list[tuple[str, str, str, str]] = []
    if device.identity.role is not DeviceRole.CORE or device.identity.vendor != "cisco":
        return ()
    keys.append((
        CandidateCategory.IP_ROUTING.value,
        "device",
        str(device.identity.assignment_id),
        "",
    ))
    for interface in device.interfaces:
        if interface.kind != "svi":
            continue
        for category in (
            CandidateCategory.SVI_INTERFACE,
            CandidateCategory.SVI_ADDRESS,
        ):
            keys.append((category.value, "svi", str(interface.interface_id), ""))
    for route in device.routes:
        category = (
            CandidateCategory.DEFAULT_ROUTE
            if route.kind == "default"
            else CandidateCategory.STATIC_ROUTE
        )
        keys.append((category.value, "route", str(route.route_id), ""))
    for relay in device.dhcp_relays:
        for server in relay.servers:
            keys.append((
                CandidateCategory.DHCP_HELPER_ADDRESS.value,
                "svi",
                str(relay.svi_id),
                str(server),
            ))
    return tuple(keys)


def _trusted_target_name(
    device: L3DeviceIntent,
    candidate: Candidate,
) -> tuple[str, UUID, str] | None:
    category = candidate.category
    if category is CandidateCategory.IP_ROUTING:
        return "device", device.identity.assignment_id, device.identity.hostname
    if category in {
        CandidateCategory.SVI_INTERFACE,
        CandidateCategory.SVI_ADDRESS,
    }:
        interface = next(
            (item for item in device.interfaces
             if item.interface_id == candidate.target.stable_id),
            None,
        )
        if interface is None:
            return None
        return "svi", interface.interface_id, interface.name
    if category in {
        CandidateCategory.STATIC_ROUTE,
        CandidateCategory.DEFAULT_ROUTE,
    }:
        route = next(
            (item for item in device.routes
             if item.route_id == candidate.target.stable_id),
            None,
        )
        if route is None:
            return None
        return "route", route.route_id, str(route.destination)
    if category is CandidateCategory.DHCP_HELPER_ADDRESS:
        relay = next(
            (item for item in device.dhcp_relays
             if item.svi_id == candidate.target.stable_id),
            None,
        )
        if relay is None:
            return None
        interface = next(
            (item for item in device.interfaces
             if item.interface_id == relay.svi_id),
            None,
        )
        if interface is None:
            return None
        server = _candidate_server(candidate)
        if server is None:
            return None
        if server not in {str(item) for item in relay.servers}:
            return None
        return "svi", relay.svi_id, f"{interface.name} -> {server}"
    return None


def _candidate_server(candidate: Candidate) -> str | None:
    if candidate.candidate_text is not None:
        parsed = parse_l3_command(candidate.candidate_text)
        if parsed.ok and parsed.parameter("server") is not None:
            return str(parsed.parameter("server"))
    if " -> " in candidate.target.name:
        return candidate.target.name.rsplit(" -> ", 1)[1]
    return None


def _trusted_candidate_metadata(
    device: L3DeviceIntent,
    candidate: Candidate,
) -> tuple[
    dict[str, JsonValue],
    tuple[tuple[str, str, str], ...],
    tuple[UUID | None, UUID | None, UUID | None],
] | None:
    category = candidate.category
    capability = _CATEGORY_CAPABILITY[category]
    check = next(
        (item for item in device.capability_checks
         if item.capability is capability),
        None,
    )
    expected_capability: tuple[tuple[str, str, str], ...] = (
        ((check.capability.value, check.verdict.value, check.reason_code),)
        if check is not None else ()
    )
    if category is CandidateCategory.IP_ROUTING:
        return {}, expected_capability, (None, None, None)
    if category in {
        CandidateCategory.SVI_INTERFACE,
        CandidateCategory.SVI_ADDRESS,
    }:
        interface = next(
            (item for item in device.interfaces
             if item.interface_id == candidate.target.stable_id),
            None,
        )
        if interface is None:
            return None
        if category is CandidateCategory.SVI_INTERFACE:
            parameters: dict[str, JsonValue] = {"vlan_id": interface.vlan}
        else:
            if interface.address is None:
                return None
            parameters = {
                "address": str(interface.address.ip),
                "mask": str(interface.address.netmask),
            }
        return (
            parameters,
            expected_capability,
            (interface.interface_id, None, interface.subnet_id),
        )
    if category in {
        CandidateCategory.STATIC_ROUTE,
        CandidateCategory.DEFAULT_ROUTE,
    }:
        route = next(
            (item for item in device.routes
             if item.route_id == candidate.target.stable_id),
            None,
        )
        if route is None:
            return None
        return (
            {
                "destination": str(route.destination),
                "next_hop": str(route.next_hop),
                "distance": route.distance,
            },
            expected_capability,
            (None, route.route_id, None),
        )
    if category is CandidateCategory.DHCP_HELPER_ADDRESS:
        relay = next(
            (item for item in device.dhcp_relays
             if item.svi_id == candidate.target.stable_id),
            None,
        )
        if relay is None:
            return None
        server = _candidate_server(candidate)
        if server is None or server not in {str(item) for item in relay.servers}:
            return None
        return (
            {"server": server, "subnet_id": str(relay.subnet_id)},
            expected_capability,
            (None, None, relay.subnet_id),
        )
    return None


def _planned_metadata_mismatches(
    device: L3DeviceIntent,
    candidate: Candidate,
    intent_fingerprint: str,
) -> tuple[str, ...]:
    expected = _trusted_candidate_metadata(device, candidate)
    if expected is None:
        return ("metadata-target-not-found",)
    expected_parameters, expected_capability, expected_provenance = expected
    reasons: list[str] = []
    if {
        key: value for key, value in candidate.parameters.items()
    } != expected_parameters:
        reasons.append("candidate-parameters-mismatch")
    actual_capability = tuple(
        (item.capability, item.verdict, item.reason_code)
        for item in candidate.capability_evidence
    )
    if actual_capability != expected_capability:
        reasons.append("candidate-capability-evidence-mismatch")
    provenance = candidate.provenance
    expected_interface_id, expected_route_id, expected_subnet_id = expected_provenance
    if (
        provenance.intent_interface_id != expected_interface_id
        or provenance.intent_route_id != expected_route_id
        or provenance.intent_subnet_id != expected_subnet_id
    ):
        reasons.append("candidate-provenance-mismatch")
    if provenance.intent_fingerprint != intent_fingerprint:
        reasons.append("candidate-provenance-intent-mismatch")
    return _dedupe(tuple(reasons))

    if candidate.candidate_text is not None:
        parsed = parse_l3_command(candidate.candidate_text)
        if parsed.ok and parsed.parameter("server") is not None:
            return str(parsed.parameter("server"))
    if " -> " in candidate.target.name:
        return candidate.target.name.rsplit(" -> ", 1)[1]
    return None


def _candidate_id(
    assignment_id: UUID,
    category: CandidateCategory,
    target_kind: str,
    target_stable_id: UUID,
    target_name: str,
) -> str:
    digest = hashlib.sha256(
        f"{assignment_id}|{category.value}|"
        f"{target_kind}:{target_stable_id}|{target_name}".encode(),
    ).hexdigest()[:16]
    return f"l3cand-{digest}"


def _trusted_device_ref(device: L3DeviceIntent) -> ValidationDevice:
    identity = device.identity
    return ValidationDevice(
        assignment_id=identity.assignment_id,
        hostname=identity.hostname,
        role=identity.role.value,
        family=identity.family.value if identity.family else None,
        exact_pid=identity.exact_pid,
        software_image=identity.software_image,
        software_license=identity.software_license,
        stack_identity=identity.stack_identity,
    )


def _actual_candidate_keys(document: L3CandidateDocument) -> tuple[tuple[str, str, str, str], ...]:
    return tuple(_candidate_key(candidate) for candidate in document.candidates)


def _source_mismatches(
    expected: ExpectedSource,
    revision: PlanRevision,
    intent: Layer3Intent,
    document: L3CandidateDocument,
    assignment_id: UUID,
    registry: CommandEvidenceRegistry,
) -> tuple[str, ...]:
    reasons: list[str] = []
    expected_values: dict[str, object] = {
        "event_id": revision.plan.event_id,
        "saved_revision_uuid": revision.id,
        "revision_number": revision.number,
        "revision_canonical_hash": revision.content_hash,
        "l3_intent_schema_version": intent.l3_intent_schema_version,
        "l3_intent_fingerprint": intent.intent_fingerprint,
        "l3_render_contract_id": document.contract_id,
        "l3_render_contract_version": document.l3_render_schema_version,
        "l3_render_fingerprint": document.l3_render_fingerprint,
        "command_evidence_registry_id": registry.registry_id,
        "command_evidence_registry_fingerprint": registry.fingerprint,
        "assignment_id": assignment_id,
        "baseline_revision_uuid": intent.baseline.revision_id,
        "baseline_revision_hash": intent.baseline.revision_hash,
    }
    for name, actual in expected_values.items():
        if getattr(expected, name) != actual:
            reasons.append(f"expected-source-{name.replace('_', '-')}")
    source_values: dict[str, object] = {
        "revision_uuid": revision.id,
        "revision_number": revision.number,
        "revision_hash": revision.content_hash,
        "l3_intent_schema_version": intent.l3_intent_schema_version,
        "l3_intent_fingerprint": intent.intent_fingerprint,
        "command_evidence_registry_id": registry.registry_id,
        "command_evidence_registry_fingerprint": registry.fingerprint,
    }
    for name, actual in source_values.items():
        if getattr(document.source, name) != actual:
            reasons.append(f"document-source-{name.replace('_', '-')}")
    if document.assignment_id != assignment_id:
        reasons.append("document-assignment-mismatch")
    return tuple(reasons)


def _assert_integrity(
    revision: PlanRevision,
    intent: Layer3Intent,
    document: L3CandidateDocument,
    expected: ExpectedSource,
    assignment_id: UUID,
    registry: CommandEvidenceRegistry,
    baseline: PlanRevision | None,
    *,
    test_only_registry: bool,
) -> Layer3Intent:
    reasons: list[str] = []
    if plan_hash(canonical_plan(revision.plan)) != revision.content_hash:
        raise ValidationIntegrityError("revision-canonical-hash-mismatch")
    if baseline is not None:
        if plan_hash(canonical_plan(baseline.plan)) != baseline.content_hash:
            raise ValidationIntegrityError("baseline-canonical-hash-mismatch")
        if baseline.plan.event_id != revision.plan.event_id:
            raise ValidationIntegrityError("baseline-event-mismatch")
    if baseline is None and intent.baseline.revision_id is not None:
        raise ValidationIntegrityError("baseline-required-but-missing")
    trusted = build_layer3_intent(revision, baseline)
    if trusted.intent_fingerprint != independent_intent_fingerprint(trusted):
        raise ValidationIntegrityError("trusted-intent-fingerprint-invalid")
    if (
        intent.revision_id != revision.id
        or intent.revision_hash != revision.content_hash
        or intent.event_id != revision.plan.event_id
    ):
        raise ValidationIntegrityError("intent-revision-mismatch")
    if (
        intent.intent_fingerprint != independent_intent_fingerprint(intent)
        or intent.intent_fingerprint != trusted.intent_fingerprint
    ):
        raise ValidationIntegrityError("intent-fingerprint-mismatch")
    if (
        intent.baseline.revision_id
        != (baseline.id if baseline is not None else None)
        or intent.baseline.revision_hash
        != (baseline.content_hash if baseline is not None else None)
    ):
        raise ValidationIntegrityError("intent-baseline-mismatch")
    if (
        document.contract_id != CANDIDATE_CONTRACT_ID
        or document.l3_render_schema_version != CANDIDATE_SCHEMA_VERSION
    ):
        raise ValidationIntegrityError("candidate-contract-mismatch")
    candidate_ids = [candidate.candidate_id for candidate in document.candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValidationIntegrityError("duplicate-candidate-id")
    for candidate in document.candidates:
        if candidate.candidate_fingerprint != independent_candidate_fingerprint(candidate):
            raise ValidationIntegrityError("candidate-fingerprint-mismatch")
        if candidate.status is CandidateStatus.CANDIDATE:
            if candidate.candidate_text is None:
                raise ValidationIntegrityError("candidate-text-missing")
        elif candidate.candidate_text is not None:
            raise ValidationIntegrityError("blocked-candidate-carries-text")
    if document.l3_render_fingerprint != independent_render_fingerprint(document):
        raise ValidationIntegrityError("document-fingerprint-mismatch")
    if test_only_registry and registry.production:
        raise ValidationIntegrityError("test-only-path-rejects-production-registry")
    device = next(
        (item for item in trusted.devices if item.identity.assignment_id == assignment_id),
        None,
    )
    if device is None:
        raise ValidationIntegrityError("assignment-not-in-intent")
    if not test_only_registry:
        try:
            assert_production_registry(registry, device.identity)
        except RegistrySelectionError as exc:
            raise ValidationIntegrityError(exc.reason_code) from None
    expected_device = _trusted_device_ref(device)
    if (
        document.device.assignment_id != expected_device.assignment_id
        or document.device.hostname != expected_device.hostname
        or document.device.role != expected_device.role
        or document.device.family != expected_device.family
        or document.device.exact_pid != expected_device.exact_pid
        or document.device.software_image != expected_device.software_image
        or document.device.software_license != expected_device.software_license
        or document.device.stack_identity != expected_device.stack_identity
    ):
        raise ValidationIntegrityError("device-identity-mismatch")
    for candidate in document.candidates:
        identity = _trusted_target_name(device, candidate)
        if identity is None:
            raise ValidationIntegrityError("candidate-id-mismatch")
        target_kind, target_stable_id, target_name = identity
        if (
            candidate.target.kind != target_kind
            or candidate.target.stable_id != target_stable_id
            or candidate.target.name != target_name
        ):
            raise ValidationIntegrityError("candidate-id-mismatch")
        expected_candidate_id = _candidate_id(
            assignment_id,
            candidate.category,
            target_kind,
            target_stable_id,
            target_name,
        )
        if candidate.candidate_id != expected_candidate_id:
            raise ValidationIntegrityError("candidate-id-mismatch")
        metadata_mismatches = _planned_metadata_mismatches(
            device, candidate, trusted.intent_fingerprint,
        )
        if metadata_mismatches:
            raise ValidationIntegrityError(
                "candidate-metadata-mismatch", metadata_mismatches,
            )
    reasons.extend(_source_mismatches(
        expected, revision, intent, document, assignment_id, registry,
    ))
    if reasons:
        raise ValidationIntegrityError("expected-source-mismatch", tuple(reasons))
    expected_keys = Counter(_expected_candidate_keys(device))
    actual_keys = Counter(_actual_candidate_keys(document))
    if expected_keys != actual_keys:
        raise ValidationIntegrityError("candidate-set-mismatch")
    expected_categories = tuple(sorted({
        category for category, _, _, _ in expected_keys
    }))
    if document.summary.categories != expected_categories:
        raise ValidationIntegrityError("summary-category-mismatch")
    statuses = Counter(candidate.status for candidate in document.candidates)
    expected_total = sum(expected_keys.values())
    expected_candidates = statuses[CandidateStatus.CANDIDATE]
    expected_blocked = statuses[CandidateStatus.BLOCKED]
    expected_unsupported = statuses[CandidateStatus.UNSUPPORTED]
    if (
        document.summary.total != expected_total
        or document.summary.candidates != expected_candidates
        or document.summary.blocked != expected_blocked
        or document.summary.unsupported != expected_unsupported
    ):
        raise ValidationIntegrityError("summary-count-mismatch")
    expected_render_state = (
        "review-candidates"
        if expected_candidates
        else "not-applicable"
        if expected_total == 0
        else "blocked"
    )
    if document.render_state.value != expected_render_state:
        raise ValidationIntegrityError("render-state-mismatch")
    if (
        not document.safety.candidate_only
        or document.safety.executable
        or document.safety.deployable
        or document.safety.deployment_allowed
        or document.safety.device_connection != "none"
        or document.safety.running_config_read
        or document.safety.device_writes_enabled
        or document.safety.cli is not None
        or document.safety.deployment_artifact is not None
        or document.safety.hardware_verified
        or document.safety.parser_verified
        or document.verification != "not-verified"
        or document.deployment_status != "blocked"
        or document.executable
        or document.cli is not None
        or document.device_writes_enabled
    ):
        raise ValidationIntegrityError("unsafe-document-flags")
    if document.device.assignment_id != assignment_id:
        raise ValidationIntegrityError("device-assignment-mismatch")
    return trusted


def _check_evidence(
    candidate: Candidate,
    device: L3DeviceIntent,
    registry: CommandEvidenceRegistry,
) -> ValidationEvidence:
    references = candidate.syntax_evidence
    reasons: list[str] = []
    if len(references) != 1:
        reasons.append("evidence-reference-count")
        return ValidationEvidence(reason_codes=tuple(reasons))
    ref = references[0]
    row = registry.get(ref.evidence_id)
    if row is None:
        return ValidationEvidence(
            evidence_id=ref.evidence_id, reason_codes=("evidence-missing",),
        )
    expected_topic = _evidence_topic(candidate.category)
    reasons.extend(_row_scope_reasons(row, device, expected_topic))
    if row.topic is not expected_topic:
        reasons.append("evidence-topic-mismatch")
    if row.mode is not _expected_evidence_mode(candidate.category):
        reasons.append("evidence-mode-mismatch")
    if row.content_digest() != ref.content_digest:
        reasons.append("evidence-digest-mismatch")
    if row.review.state is not EvidenceReviewState.REVIEWED:
        reasons.append("evidence-review-pending")
    if not row.renderable:
        reasons.append("evidence-not-renderable")
    if row.source_url != ref.source_url or row.source_section != ref.source_section:
        reasons.append("evidence-source-mismatch")
    for field_name, expected in (
        ("topic", expected_topic.value),
        ("release", row.releases[0]),
        ("review_state", row.review.state.value),
        ("content_digest", row.content_digest()),
        ("source_url", row.source_url),
        ("source_section", row.source_section),
    ):
        if getattr(ref, field_name) != expected:
            reasons.append(f"candidate-{field_name}-mismatch")
    return ValidationEvidence(
        evidence_id=row.evidence_id,
        topic=row.topic.value,
        review_state=row.review.state.value,
        content_digest=row.content_digest(),
        source_url=row.source_url,
        source_section=row.source_section,
        scope_ok=not reasons,
        reason_codes=_dedupe(tuple(reasons)),
    )


def _expected_evidence_mode(category: CandidateCategory) -> L3CommandMode:
    return (
        L3CommandMode.INTERFACE
        if category in {
            CandidateCategory.SVI_ADDRESS,
            CandidateCategory.DHCP_HELPER_ADDRESS,
        }
        else L3CommandMode.GLOBAL
    )


def _row_scope_reasons(
    row: CommandEvidenceRow,
    device: L3DeviceIntent,
    topic: L3CommandTopic,
) -> tuple[str, ...]:
    """Independently re-check row scope; do not call registry matches."""
    reasons: list[str] = []
    identity = device.identity
    classification = row.classification
    if row.topic is not topic:
        reasons.append("evidence-topic-mismatch")
    if identity.exact_pid is None:
        reasons.append("exact-pid-missing")
    elif identity.exact_pid.upper() not in {
        item.upper()
        for item in (
            classification.verified_pids
            if classification is not None else row.pids
        )
    }:
        reasons.append("exact-pid-not-in-evidence")
    if identity.software_image is None:
        reasons.append("release-missing")
    elif identity.software_image.casefold() not in {
        item.casefold() for item in row.releases
    }:
        reasons.append("release-not-in-evidence")
    if identity.software_license is None:
        reasons.append("license-missing")
    elif identity.software_license.casefold() not in {
        item.casefold() for item in row.licenses
    }:
        reasons.append("license-not-in-evidence")
    if classification is None:
        reasons.append("classification-missing")
        return _dedupe(tuple(reasons))
    if not classification.platform_documented:
        reasons.append("platform-not-documented")
    if classification.license_evidence.value != "verified":
        reasons.append(f"license-{classification.license_evidence.value}")
    elif not (
        classification.license_source_url
        and classification.license_source_section
    ):
        reasons.append("license-source-missing")
    verified = {item.upper() for item in classification.verified_pids}
    hardware = {item.upper() for item in classification.hardware_pids}
    ordering = {item.upper() for item in classification.ordering_skus}
    row_pids = {item.upper() for item in row.pids}
    if not verified:
        reasons.append("pid-scope-empty")
    if not verified <= row_pids:
        reasons.append("pid-scope-outside-row")
    if hardware & ordering or hardware | ordering != verified:
        reasons.append("pid-scope-inconsistent")
    reasons.extend(
        f"scope-gap-{gap}"
        for gap in classification.blocking_evidence_gaps
        if not (gap == REVIEW_LIFECYCLE_GAP and row.renderable)
    )
    return _dedupe(tuple(reasons))


def _expected_context(
    category: CandidateCategory,
    target_id: UUID,
    target_name: str,
    device: L3DeviceIntent,
) -> tuple[str, str | None, str]:
    if category is CandidateCategory.IP_ROUTING:
        return "global", "configure terminal", device.identity.hostname
    if category in {CandidateCategory.SVI_INTERFACE}:
        return "global", "configure terminal", target_name
    if category in {
        CandidateCategory.SVI_ADDRESS,
        CandidateCategory.DHCP_HELPER_ADDRESS,
    }:
        return "interface", f"interface {target_name}", target_name
    return "global", "configure terminal", target_name


def _check_context(
    candidate: Candidate,
    device: L3DeviceIntent,
) -> ValidationContext:
    target_name = candidate.target.name
    if candidate.category is CandidateCategory.DHCP_HELPER_ADDRESS:
        interface = next(
            (item for item in device.interfaces
             if item.interface_id == candidate.target.stable_id),
            None,
        )
        if interface is not None:
            target_name = interface.name
    expected_mode, expected_header, expected_name = _expected_context(
        candidate.category, candidate.target.stable_id,
        target_name, device,
    )
    reasons: list[str] = []
    if candidate.command_context.mode != expected_mode:
        reasons.append("context-mode-mismatch")
    if candidate.command_context.mode_header != expected_header:
        reasons.append("context-header-mismatch")
    if candidate.command_context.target_name != expected_name:
        reasons.append("context-target-mismatch")
    if candidate.target.kind != {
        CandidateCategory.IP_ROUTING: "device",
        CandidateCategory.SVI_INTERFACE: "svi",
        CandidateCategory.SVI_ADDRESS: "svi",
        CandidateCategory.STATIC_ROUTE: "route",
        CandidateCategory.DEFAULT_ROUTE: "route",
        CandidateCategory.DHCP_HELPER_ADDRESS: "svi",
    }[candidate.category]:
        reasons.append("target-kind-mismatch")
    return ValidationContext(
        expected_mode=expected_mode,
        actual_mode=candidate.command_context.mode,
        header_bound=candidate.command_context.mode_header == expected_header,
        target_kind=candidate.target.kind,
        target_stable_id=candidate.target.stable_id,
        target_name=candidate.target.name,
        bound=not reasons,
        reason_codes=_dedupe(tuple(reasons)),
    )


def _check_capability(
    candidate: Candidate,
    device: L3DeviceIntent,
) -> ValidationCapability:
    capability = _CATEGORY_CAPABILITY[candidate.category]
    check = next(
        (item for item in device.capability_checks
         if item.capability is capability),
        None,
    )
    if check is None:
        return ValidationCapability(
            capability=capability.value,
            reason_codes=("capability-missing",),
        )
    reasons: list[str] = []
    if check.verdict is not L3Verdict.DOCUMENTED:
        reasons.append(f"capability-{check.verdict.value}")
    if check.documentation is not DocumentationStatus.SUPPORTED:
        reasons.append(f"documentation-{check.documentation.value}")
    if check.prerequisite is not PrerequisiteStatus.NOT_REQUIRED:
        reasons.append(f"prerequisite-{check.prerequisite.value}")
    return ValidationCapability(
        capability=capability.value,
        verdict=check.verdict.value,
        documented=check.verdict is L3Verdict.DOCUMENTED,
        reason_codes=_dedupe(tuple(reasons)),
    )


def _check_device(
    device: L3DeviceIntent,
    registry: CommandEvidenceRegistry,
) -> tuple[str, ...]:
    identity = device.identity
    reasons: list[str] = []
    if identity.role is not DeviceRole.CORE:
        reasons.append("device-not-core")
    if identity.vendor != "cisco":
        reasons.append("device-not-cisco")
    families = {row.family for row in registry.rows}
    if identity.family is None or identity.family not in families:
        reasons.append("device-family-not-in-registry")
    if identity.exact_pid is None:
        reasons.append("exact-pid-missing")
    elif identity.pid_evidence != "exact-verified-pid":
        reasons.append("exact-pid-not-verified")
    if identity.stack_identity == "unresolved":
        reasons.append("stack-unresolved")
    if not identity.serial_verified:
        reasons.append("serial-not-verified-planning")
    if not device.readiness.allowed:
        reasons.append("readiness-blocked")
    if device.readiness.ip_routing.value != "enable":
        reasons.append("ip-routing-not-enabled")
    if device.readiness.documentation is not L3DocumentationVerdict.SUPPORTED:
        reasons.append("documentation-not-supported")
    if device.readiness.runtime_prerequisite is not L3RuntimeVerdict.SATISFIED:
        reasons.append("runtime-prerequisite-not-met")
    if any(conflict.severity == "ERROR" for conflict in device.conflicts):
        reasons.append("intent-error-conflict")
    blocked = {operation.operation for operation in device.blocked_operations}
    if blocked & {
        "policy-acl", "ip-routing", "routed-port-transition", "cleanup",
        "svi-removal",
    }:
        reasons.append("blocked-operation")
    # DHCP service blockers are category-specific and are evaluated by the
    # Relay semantics below.  They must not become a global forwarding block.
    return _dedupe(tuple(reasons))


def _check_svi(interface: L3InterfaceIntent, device: L3DeviceIntent) -> tuple[str, ...]:
    reasons: list[str] = []
    if interface.kind != "svi":
        reasons.append("svi-kind-unsupported")
    if interface.role.value not in {"gateway", "transit"}:
        reasons.append("svi-role-not-forwarding")
    if interface.vlan is None:
        reasons.append("svi-vlan-missing")
    else:
        if not 1 <= interface.vlan <= 4094:
            reasons.append("vlan-out-of-range")
        if is_reserved_vlan(interface.vlan):
            reasons.append("vlan-reserved")
        if interface.name != f"Vlan{interface.vlan}":
            reasons.append("svi-name-mismatch")
    if interface.address is None:
        reasons.append("svi-address-missing")
    else:
        prefix = interface.address.network.prefixlen
        if not SVI_PREFIX_MIN <= prefix <= SVI_PREFIX_MAX:
            reasons.append("svi-prefix-not-first-batch")
        if (
            interface.address.ip == interface.address.network.network_address
            or interface.address.ip == interface.address.network.broadcast_address
        ):
            reasons.append("svi-address-not-usable")
    if interface.carrier.value != "planned-up":
        reasons.append("svi-carrier-not-planned")
    if interface.role.value == "gateway":
        if interface.gateway_address is None or interface.subnet_id is None:
            reasons.append("svi-gateway-binding-missing")
        if (
            interface.gateway_address is not None
            and interface.address is not None
            and interface.address.ip != interface.gateway_address
        ):
            reasons.append("svi-gateway-mismatch")
    if interface.role.value == "transit":
        if device.transit is None or interface.interface_id != device.transit.core_svi_id:
            reasons.append("svi-transit-binding-missing")
    return _dedupe(tuple(reasons))


def _on_link_svis(
    device: L3DeviceIntent, next_hop: IPv4Address,
) -> tuple[L3InterfaceIntent, ...]:
    return tuple(
        item for item in device.interfaces
        if item.kind == "svi"
        and item.address is not None
        and next_hop in item.address.network
    )


def _check_route(
    candidate: Candidate,
    route: L3RouteIntent,
    device: L3DeviceIntent,
    parsed: ParsedCommand,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if route.owner_assignment_id != device.identity.assignment_id:
        reasons.append("route-owner-mismatch")
    if candidate.category is CandidateCategory.DEFAULT_ROUTE:
        if route.kind != "default":
            reasons.append("default-route-kind-mismatch")
        if device.transit is None:
            reasons.append("transit-missing")
        else:
            if route.route_id != device.transit.default_route_id:
                reasons.append("default-route-not-preferred")
            if route.next_hop != device.transit.hillstone_ip:
                reasons.append("default-route-next-hop-mismatch")
            if route.next_hop not in device.transit.network:
                reasons.append("default-route-next-hop-not-in-transit")
            if parsed.parameter("next_hop") != str(device.transit.hillstone_ip):
                reasons.append("parsed-default-next-hop-mismatch")
            transit_interface = next(
                (
                    item for item in device.interfaces
                    if item.interface_id == device.transit.core_svi_id
                ),
                None,
            )
            if transit_interface is None:
                reasons.append("transit-svi-missing")
            else:
                reasons.extend(_check_svi(transit_interface, device))
                if transit_interface.vlan != device.transit.transit_vlan:
                    reasons.append("transit-vlan-mismatch")
                if (
                    transit_interface.address is not None
                    and transit_interface.address.ip != device.transit.core_ip
                ):
                    reasons.append("transit-core-ip-mismatch")
    else:
        if route.kind != "static":
            reasons.append("static-route-kind-mismatch")
        if route.destination.prefixlen == 0:
            reasons.append("static-route-default-destination")
    if route.distance > SAFE_DISTANCE_MAX:
        reasons.append("route-distance-not-installed")
    dependencies = _on_link_svis(device, route.next_hop)
    if not dependencies:
        reasons.append("route-next-hop-not-on-link")
    elif len(dependencies) != 1:
        reasons.append("route-next-hop-ambiguous")
    else:
        reasons.extend(_check_svi(dependencies[0], device))
    if parsed.parameter("destination") != str(route.destination):
        reasons.append("parsed-destination-mismatch")
    if parsed.parameter("next_hop") != str(route.next_hop):
        reasons.append("parsed-next-hop-mismatch")
    if parsed.parameter("distance") != route.distance:
        reasons.append("parsed-distance-mismatch")
    return _dedupe(tuple(reasons))


def _check_svi_candidate_semantics(
    candidate: Candidate,
    device: L3DeviceIntent,
    interface: L3InterfaceIntent,
    parsed: ParsedCommand,
) -> tuple[str, ...]:
    reasons = list(_check_svi(interface, device))
    if candidate.category is CandidateCategory.SVI_INTERFACE:
        if parsed.parameter("vlan_id") != interface.vlan:
            reasons.append("parsed-vlan-mismatch")
    if candidate.target.kind != "svi":
        reasons.append("target-kind-mismatch")
    if candidate.target.stable_id != interface.interface_id:
        reasons.append("target-interface-mismatch")
    if candidate.target.name != interface.name:
        reasons.append("target-name-mismatch")
    provenance = candidate.provenance
    if provenance.intent_interface_id != interface.interface_id:
        reasons.append("provenance-interface-mismatch")
    if candidate.category is CandidateCategory.SVI_ADDRESS:
        if interface.address is None:
            reasons.append("svi-address-missing")
        else:
            if parsed.parameter("address") != str(interface.address.ip):
                reasons.append("parsed-address-mismatch")
            if parsed.parameter("mask") != str(interface.address.netmask):
                reasons.append("parsed-mask-mismatch")
            if parsed.parameter("prefix_length") != interface.address.network.prefixlen:
                reasons.append("parsed-prefix-mismatch")
            if (
                interface.gateway_address is not None
                and interface.address.ip != interface.gateway_address
            ):
                reasons.append("gateway-address-mismatch")
    if candidate.category is CandidateCategory.SVI_INTERFACE:
        if candidate.target.name != interface.name:
            reasons.append("target-name-mismatch")
    return _dedupe(tuple(reasons))


def _check_dhcp_semantics(
    candidate: Candidate,
    device: L3DeviceIntent,
    parsed: ParsedCommand,
) -> tuple[str, ...]:
    reasons: list[str] = []
    relay = next(
        (
            item for item in device.dhcp_relays
            if item.svi_id == candidate.target.stable_id
            and str(parsed.parameter("server")) in {str(server) for server in item.servers}
        ),
        None,
    )
    if relay is None:
        reasons.append("dhcp-relay-binding-mismatch")
        return _dedupe(tuple(reasons))
    if not relay.allowed:
        reasons.append("dhcp-relay-not-allowed")
    if relay.capability is not L3Verdict.DOCUMENTED:
        reasons.append(f"dhcp-relay-capability-{relay.capability.value}")
    if relay.blockers:
        reasons.append("dhcp-relay-blocked")
    interface = next(
        (item for item in device.interfaces if item.interface_id == relay.svi_id),
        None,
    )
    if interface is None:
        reasons.append("dhcp-relay-svi-missing")
    else:
        reasons.extend(_check_svi(interface, device))
        if interface.vlan != relay.vlan:
            reasons.append("dhcp-relay-vlan-mismatch")
        if interface.subnet_id != relay.subnet_id:
            reasons.append("dhcp-relay-subnet-mismatch")
    if parsed.parameter("server") not in {
        str(server) for server in relay.servers
    }:
        reasons.append("dhcp-server-not-planned")
    # The production evidence is permitted to be PENDING; the independent
    # validator records that as a blocker, never as a pass.
    return _dedupe(tuple(reasons))


def _check_risk(candidate: Candidate) -> ValidationRisk:
    floor = _CATEGORY_RISK_FLOOR[candidate.category]
    non_degraded = _risk_rank(candidate.risk_class.value) >= _risk_rank(floor.value)
    reasons: list[str] = []
    if not non_degraded:
        reasons.append("risk-class-below-floor")
    if not candidate.potential_connectivity_impact:
        reasons.append("connectivity-impact-not-declared")
    if not candidate.requires_field_verification:
        reasons.append("field-verification-not-required")
    return ValidationRisk(
        renderer_risk=candidate.risk_class.value,
        independent_floor=floor.value,
        non_degraded=non_degraded,
        reason_codes=tuple(reasons),
    )


def _expected_candidate_parameters(
    candidate: Candidate,
    device: L3DeviceIntent,
    parsed: ParsedCommand,
) -> dict[str, JsonValue] | None:
    category = candidate.category
    if category is CandidateCategory.IP_ROUTING:
        return {}
    if category is CandidateCategory.SVI_INTERFACE:
        return {"vlan_id": parsed.parameter("vlan_id")}
    if category is CandidateCategory.SVI_ADDRESS:
        return {
            "address": parsed.parameter("address"),
            "mask": parsed.parameter("mask"),
        }
    if category in {
        CandidateCategory.STATIC_ROUTE,
        CandidateCategory.DEFAULT_ROUTE,
    }:
        return {
            "destination": parsed.parameter("destination"),
            "next_hop": parsed.parameter("next_hop"),
            "distance": parsed.parameter("distance"),
        }
    if category is CandidateCategory.DHCP_HELPER_ADDRESS:
        relay = next(
            (
                item for item in device.dhcp_relays
                if item.svi_id == candidate.target.stable_id
            ),
            None,
        )
        if relay is None:
            return None
        return {
            "server": parsed.parameter("server"),
            "subnet_id": str(relay.subnet_id),
        }
    return None


def _check_candidate_metadata(
    candidate: Candidate,
    device: L3DeviceIntent,
    parsed: ParsedCommand,
    intent_fingerprint: str,
) -> tuple[str, ...]:
    reasons: list[str] = []
    expected_parameters = _expected_candidate_parameters(candidate, device, parsed)
    if expected_parameters is not None:
        if {
            key: value for key, value in candidate.parameters.items()
        } != expected_parameters:
            reasons.append("candidate-parameters-mismatch")
    expected_capability = _CATEGORY_CAPABILITY[candidate.category]
    actual_capabilities = {
        (item.capability, item.verdict) for item in candidate.capability_evidence
    }
    if actual_capabilities != {
        (expected_capability.value, L3Verdict.DOCUMENTED.value),
    }:
        reasons.append("candidate-capability-evidence-mismatch")
    provenance = candidate.provenance
    if provenance.intent_fingerprint != intent_fingerprint:
        reasons.append("provenance-intent-mismatch")
    if candidate.category is CandidateCategory.IP_ROUTING:
        if (
            provenance.intent_interface_id is not None
            or provenance.intent_route_id is not None
            or provenance.intent_subnet_id is not None
        ):
            reasons.append("provenance-device-mismatch")
    elif candidate.category in {
        CandidateCategory.SVI_INTERFACE,
        CandidateCategory.SVI_ADDRESS,
    }:
        interface = next(
            (item for item in device.interfaces
             if item.interface_id == candidate.target.stable_id),
            None,
        )
        if interface is None:
            reasons.append("provenance-interface-missing")
        else:
            if provenance.intent_interface_id != interface.interface_id:
                reasons.append("provenance-interface-mismatch")
            if provenance.intent_subnet_id != interface.subnet_id:
                reasons.append("provenance-subnet-mismatch")
            if provenance.intent_route_id is not None:
                reasons.append("provenance-route-mismatch")
    elif candidate.category in {
        CandidateCategory.STATIC_ROUTE,
        CandidateCategory.DEFAULT_ROUTE,
    }:
        if provenance.intent_route_id != candidate.target.stable_id:
            reasons.append("provenance-route-mismatch")
        if provenance.intent_interface_id is not None:
            reasons.append("provenance-interface-mismatch")
        if provenance.intent_subnet_id is not None:
            reasons.append("provenance-subnet-mismatch")
    elif candidate.category is CandidateCategory.DHCP_HELPER_ADDRESS:
        relay = next(
            (item for item in device.dhcp_relays
             if item.svi_id == candidate.target.stable_id),
            None,
        )
        if relay is None:
            reasons.append("provenance-relay-missing")
        elif provenance.intent_subnet_id != relay.subnet_id:
            reasons.append("provenance-subnet-mismatch")
        if provenance.intent_interface_id is not None:
            reasons.append("provenance-interface-mismatch")
        if provenance.intent_route_id is not None:
            reasons.append("provenance-route-mismatch")
    return _dedupe(tuple(reasons))

    if candidate.candidate_text is None:
        return ValidationParse(status="not-run")
    parsed = parse_l3_command(candidate.candidate_text)
    return ValidationParse(
        status=parsed.status.value,
        form=parsed.form.value if parsed.form else None,
        mode=parsed.mode.value if parsed.mode else None,
        target_class=parsed.target_class.value if parsed.target_class else None,
        parameters=tuple(
            ValidationParameter(name=item.name, value=item.value)
            for item in parsed.parameters
        ),
        failures=parsed.failure_codes,
    )


_LEGIT_EVIDENCE_REASONS = frozenset({
    "evidence-review-pending",
    "evidence-not-renderable",
    "license-unresolved",
    "license-partial",
})
_LEGIT_SEMANTIC_PREFIXES = (
    "no-svi-",
    "route-",
    "svi-",
    "transit-",
    "dhcp-",
    "default-",
    "l3-evidence-",
    "l3-license-",
)


def _semantic_blocker_is_legitimate(code: str) -> bool:
    return code.startswith(_LEGIT_SEMANTIC_PREFIXES)


def _is_legitimate_evidence_reason(code: str) -> bool:
    return code in _LEGIT_EVIDENCE_REASONS or code.startswith("scope-gap-")


def _is_legitimate_blocked(
    *,
    evidence: ValidationEvidence,
    evidence_reference_count: int,
    capability: ValidationCapability,
    device_reasons: tuple[str, ...],
    context_reasons: tuple[str, ...],
    semantics_reasons: tuple[str, ...],
    risk_reasons: tuple[str, ...],
) -> bool:
    if context_reasons or risk_reasons:
        return False
    if any(not _semantic_blocker_is_legitimate(item) for item in semantics_reasons):
        return False
    if evidence_reference_count:
        if any(
            not _is_legitimate_evidence_reason(item)
            for item in evidence.reason_codes
        ):
            return False
    if device_reasons:
        return True
    if not capability.documented or capability.reason_codes:
        return True
    if evidence.evidence_id is not None and evidence.reason_codes:
        if all(
            _is_legitimate_evidence_reason(item)
            for item in evidence.reason_codes
        ):
            return True
    return any(
        _semantic_blocker_is_legitimate(item) for item in semantics_reasons
    )


def _planned_semantic_blockers(
    candidate: Candidate,
    device: L3DeviceIntent,
) -> tuple[str, ...]:
    """Independent blockers that exist even when no command text was emitted."""
    reasons: list[str] = []
    if candidate.category is CandidateCategory.IP_ROUTING:
        if not any(item.kind == "svi" for item in device.interfaces):
            reasons.append("no-svi-for-ip-routing")
        return _dedupe(tuple(reasons))
    if candidate.category in {
        CandidateCategory.SVI_INTERFACE,
        CandidateCategory.SVI_ADDRESS,
    }:
        interface = next(
            (item for item in device.interfaces
             if item.interface_id == candidate.target.stable_id),
            None,
        )
        if interface is None:
            return ("target-interface-missing",)
        return _check_svi(interface, device)
    if candidate.category in {
        CandidateCategory.STATIC_ROUTE,
        CandidateCategory.DEFAULT_ROUTE,
    }:
        route = next(
            (item for item in device.routes
             if item.route_id == candidate.target.stable_id),
            None,
        )
        if route is None:
            return ("target-route-missing",)
        if route.owner_assignment_id != device.identity.assignment_id:
            reasons.append("route-owner-mismatch")
        if route.distance > SAFE_DISTANCE_MAX:
            reasons.append("route-distance-not-installed")
        dependencies = _on_link_svis(device, route.next_hop)
        if not dependencies:
            reasons.append("route-next-hop-not-on-link")
        elif len(dependencies) != 1:
            reasons.append("route-next-hop-ambiguous")
        else:
            reasons.extend(_check_svi(dependencies[0], device))
        if candidate.category is CandidateCategory.STATIC_ROUTE:
            if route.kind != "static":
                reasons.append("static-route-kind-mismatch")
            if route.destination.prefixlen == 0:
                reasons.append("static-route-default-destination")
        else:
            if route.kind != "default":
                reasons.append("default-route-kind-mismatch")
            if device.transit is None:
                reasons.append("transit-missing")
            else:
                if route.route_id != device.transit.default_route_id:
                    reasons.append("default-route-not-preferred")
                if route.next_hop != device.transit.hillstone_ip:
                    reasons.append("default-route-next-hop-mismatch")
                if route.next_hop not in device.transit.network:
                    reasons.append("default-route-next-hop-not-in-transit")
                transit_interface = next(
                    (item for item in device.interfaces
                     if item.interface_id == device.transit.core_svi_id),
                    None,
                )
                if transit_interface is None:
                    reasons.append("transit-svi-missing")
                else:
                    reasons.extend(_check_svi(transit_interface, device))
        return _dedupe(tuple(reasons))
    if candidate.category is CandidateCategory.DHCP_HELPER_ADDRESS:
        relay = next(
            (item for item in device.dhcp_relays
             if item.svi_id == candidate.target.stable_id),
            None,
        )
        if relay is None:
            return ("dhcp-relay-binding-mismatch",)
        if not relay.allowed:
            reasons.append("dhcp-relay-not-allowed")
        if relay.capability is not L3Verdict.DOCUMENTED:
            reasons.append(f"dhcp-relay-capability-{relay.capability.value}")
        reasons.extend(relay.blockers)
        interface = next(
            (item for item in device.interfaces if item.interface_id == relay.svi_id),
            None,
        )
        if interface is None:
            reasons.append("dhcp-relay-svi-missing")
        else:
            reasons.extend(_check_svi(interface, device))
        return _dedupe(tuple(reasons))
    return ()


def _parse_candidate(candidate: Candidate) -> ValidationParse:
    if candidate.candidate_text is None:
        return ValidationParse(status="not-run")
    parsed = parse_l3_command(candidate.candidate_text)
    return ValidationParse(
        status=parsed.status.value,
        form=parsed.form.value if parsed.form else None,
        mode=parsed.mode.value if parsed.mode else None,
        target_class=parsed.target_class.value if parsed.target_class else None,
        parameters=tuple(
            ValidationParameter(name=item.name, value=item.value)
            for item in parsed.parameters
        ),
        failures=parsed.failure_codes,
    )


def _validate_candidate(
    candidate: Candidate,
    device: L3DeviceIntent,
    registry: CommandEvidenceRegistry,
    intent_fingerprint: str,
) -> CandidateValidation:
    reasons: list[str] = []
    parsed = (
        parse_l3_command(candidate.candidate_text)
        if candidate.candidate_text is not None
        else None
    )
    if parsed is not None and not parsed.ok:
        reasons.extend(parsed.failure_codes)
    expected_form = _CATEGORY_FORM[candidate.category]
    if parsed is not None and parsed.ok and parsed.form is not expected_form:
        reasons.append("parsed-form-category-mismatch")
    evidence = _check_evidence(candidate, device, registry)
    context = _check_context(candidate, device)
    capability = _check_capability(candidate, device)
    security = ValidationSecurity(
        text_safe=parsed is None or parsed.ok,
        reason_codes=() if parsed is None or parsed.ok else parsed.failure_codes,
    )
    reasons.extend(evidence.reason_codes)
    reasons.extend(context.reason_codes)
    reasons.extend(capability.reason_codes)
    device_reasons = _check_device(device, registry)
    reasons.extend(device_reasons)
    semantics_reasons: list[str] = []
    if parsed is not None and parsed.ok:
        semantics_reasons.extend(_semantic_for_candidate(candidate, device, parsed))
        semantics_reasons.extend(
            _check_candidate_metadata(
                candidate, device, parsed, intent_fingerprint,
            ),
        )
    elif parsed is not None:
        semantics_reasons.extend(parsed.failure_codes)
    else:
        semantics_reasons.extend(_planned_semantic_blockers(candidate, device))
    reasons.extend(semantics_reasons)
    if candidate.status is CandidateStatus.CANDIDATE:
        if candidate.candidate_text is None:
            reasons.append("candidate-text-missing")
        if candidate.command_context.mode not in {"global", "interface"}:
            reasons.append("invalid-context-mode")
        if candidate.syntax_validation.parser_verified:
            semantics_reasons.append("renderer-parser-verified-must-be-false")
            reasons.append("renderer-parser-verified-must-be-false")
    elif candidate.candidate_text is not None:
        reasons.append("blocked-candidate-carries-text")
    if candidate.status is CandidateStatus.BLOCKED:
        if not semantics_reasons and not evidence.reason_codes:
            reasons.append("blocked-without-independent-reason")
    risk = _check_risk(candidate)
    reasons.extend(risk.reason_codes)
    blocked_legitimate = False
    if candidate.status in {CandidateStatus.BLOCKED, CandidateStatus.UNSUPPORTED}:
        blocked_legitimate = _is_legitimate_blocked(
            evidence=evidence,
            evidence_reference_count=len(candidate.syntax_evidence),
            capability=capability,
            device_reasons=device_reasons,
            context_reasons=context.reason_codes,
            semantics_reasons=tuple(semantics_reasons),
            risk_reasons=risk.reason_codes,
        )
        if not blocked_legitimate:
            semantics_reasons.append("blocked-verdict-not-supported")
            reasons.append("blocked-verdict-not-supported")
    reasons = list(_dedupe(tuple(reasons)))
    semantics_reasons = list(_dedupe(tuple(semantics_reasons)))
    verdict: IndependentVerdict
    if candidate.status is CandidateStatus.CANDIDATE:
        verdict = (
            IndependentVerdict.PASS if not reasons else IndependentVerdict.FAIL
        )
    elif candidate.status in {CandidateStatus.BLOCKED, CandidateStatus.UNSUPPORTED}:
        verdict = (
            IndependentVerdict.BLOCKED
            if blocked_legitimate
            else IndependentVerdict.FAIL
        )
    else:
        verdict = IndependentVerdict.FAIL
    fail_closed_action = {
        IndependentVerdict.PASS: "offline-review-only",
        IndependentVerdict.FAIL: "reject-candidate",
        IndependentVerdict.BLOCKED: "suppress-and-defer",
        IndependentVerdict.NOT_RUN: "not-run",
    }[verdict]
    return CandidateValidation(
        candidate_id=candidate.candidate_id,
        category=candidate.category.value,
        target_kind=candidate.target.kind,
        target_stable_id=candidate.target.stable_id,
        target_name=candidate.target.name,
        parse=_parse_candidate(candidate),
        evidence=evidence,
        context_binding=context,
        target_capability=capability,
        security=security,
        semantics=ValidationSemantics(
            status="pass" if not semantics_reasons else "fail",
            reason_codes=_dedupe(tuple(semantics_reasons)),
        ),
        risk=risk,
        independent_verdict=verdict,
        fail_closed_action=fail_closed_action,
    )


def _semantic_for_candidate(
    candidate: Candidate,
    device: L3DeviceIntent,
    parsed: ParsedCommand,
) -> tuple[str, ...]:
    category = candidate.category
    if category is CandidateCategory.IP_ROUTING:
        reasons: list[str] = []
        if candidate.target.kind != "device":
            reasons.append("target-kind-mismatch")
        if candidate.target.stable_id != device.identity.assignment_id:
            reasons.append("target-device-mismatch")
        if candidate.target.name != device.identity.hostname:
            reasons.append("target-name-mismatch")
        if not any(item.kind == "svi" for item in device.interfaces):
            reasons.append("no-svi-for-ip-routing")
        if parsed.parameter_dict():
            reasons.append("ip-routing-parameters-present")
        return tuple(reasons)
    if category in {
        CandidateCategory.SVI_INTERFACE,
        CandidateCategory.SVI_ADDRESS,
    }:
        interface = next(
            (item for item in device.interfaces
             if item.interface_id == candidate.target.stable_id),
            None,
        )
        if interface is None:
            return ("target-interface-missing",)
        return _check_svi_candidate_semantics(candidate, device, interface, parsed)
    if category in {
        CandidateCategory.STATIC_ROUTE,
        CandidateCategory.DEFAULT_ROUTE,
    }:
        route = next(
            (item for item in device.routes
             if item.route_id == candidate.target.stable_id),
            None,
        )
        if route is None:
            return ("target-route-missing",)
        if candidate.target.name != str(route.destination):
            return ("target-route-name-mismatch",)
        return _check_route(candidate, route, device, parsed)
    if category is CandidateCategory.DHCP_HELPER_ADDRESS:
        return _check_dhcp_semantics(candidate, device, parsed)
    return ("unknown-category",)


def _summary(
    candidates: tuple[CandidateValidation, ...],
) -> tuple[ValidationSummary, ReportOverall]:
    passed = sum(1 for c in candidates if c.independent_verdict is IndependentVerdict.PASS)
    failed = sum(1 for c in candidates if c.independent_verdict is IndependentVerdict.FAIL)
    blocked = sum(1 for c in candidates if c.independent_verdict is IndependentVerdict.BLOCKED)
    not_run = sum(
        1 for c in candidates if c.independent_verdict is IndependentVerdict.NOT_RUN
    )
    base = [
        c for c in candidates
        if c.category in {item.value for item in _BASE_CATEGORIES}
    ]
    base_candidates_passed = sum(
        1 for c in base if c.independent_verdict is IndependentVerdict.PASS
    )
    base_candidates_failed = sum(
        1 for c in base if c.independent_verdict is IndependentVerdict.FAIL
    )
    base_groups: dict[str, list[CandidateValidation]] = {}
    for candidate in base:
        base_groups.setdefault(candidate.category, []).append(candidate)
    base_categories_passed = sum(
        1 for group in base_groups.values()
        if group and all(
            item.independent_verdict is IndependentVerdict.PASS for item in group
        )
    )
    base_categories_failed = sum(
        1 for group in base_groups.values()
        if any(item.independent_verdict is IndependentVerdict.FAIL for item in group)
    )
    dhcp = [
        c for c in candidates
        if c.category == CandidateCategory.DHCP_HELPER_ADDRESS.value
    ]
    dhcp_blocked = bool(dhcp) and all(
        c.independent_verdict is IndependentVerdict.BLOCKED for c in dhcp
    )
    overall: ReportOverall = (
        ReportOverall.FAIL
        if failed
        else ReportOverall.PARTIAL
        if blocked or dhcp_blocked
        else ReportOverall.PASS
    )
    return (
        ValidationSummary(
            total=len(candidates),
            passed=passed,
            failed=failed,
            blocked=blocked,
            not_run=not_run,
            base_categories_passed=base_categories_passed,
            base_categories_failed=base_categories_failed,
            base_candidates_passed=base_candidates_passed,
            base_candidates_failed=base_candidates_failed,
            dhcp_helper_blocked=dhcp_blocked,
        ),
        overall,
    )


def validate_l3_candidates(
    revision: PlanRevision,
    intent: Layer3Intent,
    document: L3CandidateDocument,
    expected_source: ExpectedSource,
    assignment_id: UUID,
    registry: CommandEvidenceRegistry = DEFAULT_REGISTRY,
    *,
    baseline: PlanRevision | None = None,
    test_only_registry: bool = False,
) -> L3ValidationReport:
    """Validate an L3 candidate document and return an independent report."""
    trusted = _assert_integrity(
        revision, intent, document, expected_source, assignment_id,
        registry, baseline, test_only_registry=test_only_registry,
    )
    device = next(
        (item for item in trusted.devices
         if item.identity.assignment_id == assignment_id),
    )
    candidate_reports = tuple(
        _validate_candidate(
            candidate, device, registry, trusted.intent_fingerprint,
        )
        for candidate in document.candidates
    )
    summary, overall = _summary(candidate_reports)
    source = ActualSource(
        event_id=revision.plan.event_id,
        saved_revision_uuid=revision.id,
        revision_number=revision.number,
        revision_canonical_hash=revision.content_hash,
        l3_intent_schema_version=trusted.l3_intent_schema_version,
        l3_intent_fingerprint=trusted.intent_fingerprint,
        l3_render_contract_id=document.contract_id,
        l3_render_contract_version=document.l3_render_schema_version,
        l3_render_fingerprint=document.l3_render_fingerprint,
        command_evidence_registry_id=registry.registry_id,
        command_evidence_registry_fingerprint=registry.fingerprint,
        assignment_id=assignment_id,
        baseline_revision_uuid=trusted.baseline.revision_id,
        baseline_revision_hash=trusted.baseline.revision_hash,
    )
    draft = L3ValidationReport(
        validation_scope="test-only" if test_only_registry else "production",
        expected_source=expected_source,
        source=source,
        assignment_id=assignment_id,
        device=_trusted_device_ref(device),
        integrity=ValidationIntegrity(
            revision_canonical_hash=True,
            baseline_canonical_hash=True,
            intent_rebuilt=True,
            intent_fingerprint=True,
            expected_source=True,
            document_source=True,
            document_fingerprint=True,
            candidate_fingerprints=True,
            candidate_ids_unique=True,
            candidate_set=True,
            summary=True,
            safety=True,
        ),
        candidates=candidate_reports,
        summary=summary,
        overall_status=overall,
        report_fingerprint="",
    )
    return draft.model_copy(update={
        "report_fingerprint": independent_report_fingerprint(draft),
    })


__all__ = [
    "ActualSource",
    "CandidateValidation",
    "ExpectedSource",
    "IndependentVerdict",
    "L3ValidationReport",
    "ReportOverall",
    "VALIDATION_CONTRACT_ID",
    "VALIDATION_SCHEMA_VERSION",
    "ValidationIntegrityError",
    "independent_candidate_fingerprint",
    "independent_intent_fingerprint",
    "independent_render_fingerprint",
    "independent_report_fingerprint",
    "validate_l3_candidates",
]
