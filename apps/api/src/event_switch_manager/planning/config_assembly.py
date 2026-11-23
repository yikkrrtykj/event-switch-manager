"""CIS-04 read-only device configuration assembly contract.

The assembly is a review artifact for exactly one Cisco Assignment of one
immutable Saved Revision.  It binds the already-frozen L2 and L3 intent,
preview, candidate and independent validation objects.  It does not render a
deployment script, order commands, contact a device, read a running
configuration or write hardware.

Every chapter reports its own completeness.  A device is never COMPLETE while a
required chapter is missing, blocked or not implemented.  Recommended next
steps remain operator decisions; this module emits no executable artifact.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from enum import StrEnum
from ipaddress import IPv4Address
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from ..domain import DeviceRole
from .inventory import PhysicalInterface
from .layer2_cli_candidates import (
    Candidate as L2Candidate,
)
from .layer2_cli_candidates import (
    CandidateStatus as L2CandidateStatus,
)
from .layer2_cli_candidates import (
    L2CliCandidateDocument,
)
from .layer2_cli_validation import (
    ValidationReport as L2ValidationReport,
)
from .layer2_cli_validation import (
    Verdict as L2Verdict,
)
from .layer2_config_preview import (
    Layer2DeviceConfigPreview,
)
from .layer2_intent import (
    DeviceLayer2Intent,
    Layer2Intent,
    PhysicalPortIntent,
    PortChannelIntent,
)
from .layer3_cli_candidates import (
    Candidate as L3Candidate,
)
from .layer3_cli_candidates import (
    CandidateStatus as L3CandidateStatus,
)
from .layer3_cli_candidates import (
    L3CandidateDocument,
)
from .layer3_cli_validation import (
    IndependentVerdict as L3Verdict,
)
from .layer3_cli_validation import (
    L3ValidationReport,
)
from .layer3_intent import (
    L3DeviceIntent,
    Layer3Intent,
)
from .plan import EventPlan, PlanRevision
from .types import Record

ASSEMBLY_SCHEMA_VERSION: Literal[1] = 1
ASSEMBLY_CONTRACT_ID: Literal["cis-04-device-config-assembly-v1"] = (
    "cis-04-device-config-assembly-v1"
)
DEPENDENCY_SEMANTICS: Literal["association-only-not-an-execution-order"] = (
    "association-only-not-an-execution-order"
)

SECTION_IDS: tuple[str, ...] = (
    "vlan-definitions",
    "stp-vtp",
    "physical-interfaces",
    "access-trunk-vlans",
    "port-channels-lacp",
    "portfast-bpdu-poe",
    "ip-routing",
    "svi",
    "routes",
    "dhcp",
    "management-auth-ssh",
    "snmp-syslog-ntp",
)

L2_SECTION_CATEGORIES: Mapping[str, tuple[str, ...]] = {
    "vlan-definitions": ("vlan-definition",),
    "stp-vtp": ("rapid-pvst", "vtp-transparent", "root-priority"),
    "physical-interfaces": (
        "speed", "duplex", "description", "admin-shutdown", "unused-shutdown",
    ),
    "access-trunk-vlans": (
        "access-mode", "access-vlan", "trunk-mode", "native-vlan",
        "allowed-vlans",
    ),
    "port-channels-lacp": ("port-channel", "lacp-mode"),
    "portfast-bpdu-poe": ("portfast", "bpdu-guard", "poe-mode"),
}

L3_SECTION_CATEGORIES: Mapping[str, tuple[str, ...]] = {
    "ip-routing": ("ip-routing",),
    "svi": ("svi-interface", "svi-address"),
    "routes": ("static-route", "default-route"),
    "dhcp": ("dhcp-helper-address",),
}

#: CIS-01/02/03 requirement-to-chapter matrix.  This is not documentation
#: only: ``_applicability`` and the completeness gate consume it so a chapter
#: without an implemented path cannot silently satisfy a device.
SECTION_CAPABILITY_MATRIX: Mapping[str, tuple[str, bool]] = {
    "vlan-definitions": ("CIS-02", True),
    "stp-vtp": ("CIS-02", True),
    "physical-interfaces": ("CIS-01/CIS-02", True),
    "access-trunk-vlans": ("CIS-02", True),
    "port-channels-lacp": ("CIS-02", True),
    "portfast-bpdu-poe": ("CIS-01/CIS-02", True),
    "ip-routing": ("CIS-03", True),
    "svi": ("CIS-03", True),
    "routes": ("CIS-03", True),
    "dhcp": ("CIS-01/CIS-03", True),
    "management-auth-ssh": ("CIS-03", False),
    "snmp-syslog-ntp": ("CIS-03", False),
}

L2_PREVIEW_CATEGORIES: Mapping[str, tuple[str, ...]] = {
    "vlan-definitions": ("vlan",),
    "stp-vtp": ("stp", "vtp", "root-priority"),
    "physical-interfaces": (
        "speed", "duplex", "description", "shutdown", "unused-port-policy",
    ),
    "access-trunk-vlans": ("access", "trunk", "routed-boundary"),
    "port-channels-lacp": ("port-channel", "lacp"),
    "portfast-bpdu-poe": ("portfast", "bpdu-guard", "poe"),
}


class AssemblyInputError(ValueError):
    """The trusted objects cannot be assembled without ambiguity."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class AssemblySectionStatus(StrEnum):
    VALIDATED_SECTION = "VALIDATED_SECTION"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


class AssemblyApplicability(StrEnum):
    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


class CrossLayerStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class AssemblySafety(Record):
    read_only: Literal[True] = True
    candidate_only: Literal[True] = True
    executable: Literal[False] = False
    deployable: Literal[False] = False
    deployment_allowed: Literal[False] = False
    device_connection: Literal["none"] = "none"
    running_config_read: Literal[False] = False
    device_writes_enabled: Literal[False] = False
    device_runtime_state: Literal["unknown-not-read"] = "unknown-not-read"
    full_config_generated: Literal[False] = False
    deployment_artifact: None = None
    cli: None = None
    hardware_verified: Literal[False] = False
    assembly_is_not_execution_authorization: Literal[True] = True


class AssemblyStackMember(Record):
    number: int
    physical_device_id: UUID
    exact_pid: str | None
    state: str


class AssemblyPhysicalIdentity(Record):
    assignment_id: UUID
    hostname: str
    role: str
    family: str | None
    physical_device_id: UUID | None
    physical_vendor: str | None
    physical_model: str | None
    verified_serial_present: bool
    exact_pid: str | None
    pid_evidence: str
    serial_verified: bool
    software_image: str | None
    software_license: str | None
    stack_identity: str
    stack_members: tuple[AssemblyStackMember, ...]
    management_ip: str | None


class AssemblySource(Record):
    event_id: UUID
    revision_id: UUID
    revision_number: int
    revision_canonical_hash: str
    assignment_id: UUID
    l2_intent_fingerprint: str
    l2_preview_fingerprint: str
    l2_render_fingerprint: str
    l2_validation_fingerprint: str
    l2_candidate_fingerprints: tuple[str, ...]
    l2_command_evidence_registry_id: str
    l2_command_evidence_registry_fingerprint: str
    l3_intent_fingerprint: str
    l3_render_fingerprint: str
    l3_validation_fingerprint: str
    l3_candidate_fingerprints: tuple[str, ...]
    l3_command_evidence_registry_id: str
    l3_command_evidence_registry_fingerprint: str
    dependency_semantics: Literal[
        "association-only-not-an-execution-order"
    ] = DEPENDENCY_SEMANTICS


class AssemblyCandidate(Record):
    candidate_id: str
    source_layer: Literal["l2", "l3"]
    category: str
    target_kind: str
    target_name: str
    status: Literal["candidate", "blocked", "unsupported"]
    verdict: Literal["pass", "fail", "blocked", "not-run"]
    candidate_text: str | None
    risk_class: str
    requires_field_verification: bool
    blocking_reasons: tuple[str, ...]
    candidate_fingerprint: str


class SectionFingerprints(Record):
    l2_intent: str | None = None
    l2_preview: str | None = None
    l2_render: str | None = None
    l2_validation: str | None = None
    l3_intent: str | None = None
    l3_render: str | None = None
    l3_validation: str | None = None


class SectionEvidenceReference(Record):
    kind: Literal["syntax", "capability", "registry", "preview"]
    reference_id: str
    detail: str


class AssemblySection(Record):
    section_id: str
    required: bool
    applicability: AssemblyApplicability
    status: AssemblySectionStatus
    candidate_count: int
    passed_count: int
    failed_count: int
    blocked_count: int
    missing_count: int
    reason_codes: tuple[str, ...]
    evidence_references: tuple[SectionEvidenceReference, ...]
    source_fingerprints: SectionFingerprints
    candidates: tuple[AssemblyCandidate, ...]


class CrossLayerCheck(Record):
    check_id: str
    status: CrossLayerStatus
    reason_codes: tuple[str, ...]
    detail: str


class AssemblyCompleteness(Record):
    status: AssemblySectionStatus
    complete: bool
    required_sections: int
    validated_sections: int
    partial_sections: int
    blocked_sections: int
    not_applicable_sections: int
    not_implemented_sections: int
    missing_sections: tuple[str, ...]
    missing_features: tuple[str, ...]
    blockers: tuple[str, ...]


class ConfigurationAssembly(Record):
    assembly_schema_version: Literal[1] = ASSEMBLY_SCHEMA_VERSION
    contract_id: Literal["cis-04-device-config-assembly-v1"] = (
        ASSEMBLY_CONTRACT_ID
    )
    source: AssemblySource
    identity: AssemblyPhysicalIdentity
    sections: tuple[AssemblySection, ...]
    cross_layer_checks: tuple[CrossLayerCheck, ...]
    completeness: AssemblyCompleteness
    safety: AssemblySafety = AssemblySafety()
    device_runtime_state: Literal["unknown-not-read"] = "unknown-not-read"
    verification: Literal["not-verified"] = "not-verified"
    deployment_status: Literal["blocked"] = "blocked"
    executable: Literal[False] = False
    cli: None = None
    device_writes_enabled: Literal[False] = False
    full_config_generated: Literal[False] = False
    assembly_fingerprint: str


# --------------------------------------------------------------------------- #
# Deterministic helpers
# --------------------------------------------------------------------------- #


def _json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: JsonValue) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def assembly_fingerprint(document: ConfigurationAssembly) -> str:
    payload = document.model_dump(mode="json")
    payload.pop("assembly_fingerprint", None)
    return _sha256(payload)


def _section_fingerprints(
    l2_preview: Layer2DeviceConfigPreview,
    l2_document: L2CliCandidateDocument,
    l2_report: L2ValidationReport,
    l3_intent: Layer3Intent,
    l3_document: L3CandidateDocument,
    l3_report: L3ValidationReport,
) -> SectionFingerprints:
    return SectionFingerprints(
        l2_intent=l2_preview.intent_fingerprint,
        l2_preview=l2_preview.preview_fingerprint,
        l2_render=l2_document.render_fingerprint,
        l2_validation=l2_report.report_fingerprint,
        l3_intent=l3_intent.intent_fingerprint,
        l3_render=l3_document.l3_render_fingerprint,
        l3_validation=l3_report.report_fingerprint,
    )


# --------------------------------------------------------------------------- #
# Candidate projection
# --------------------------------------------------------------------------- #


def _l2_verdict(
    candidate: L2Candidate, report: L2ValidationReport,
) -> Literal["pass", "fail", "blocked", "not-run"]:
    if candidate.status is not L2CandidateStatus.CANDIDATE:
        return "blocked"
    row = next(
        (item for item in report.candidates
         if item.candidate_id == candidate.candidate_id),
        None,
    )
    if row is None or row.independent_verdict is L2Verdict.NOT_RUN:
        return "not-run"
    return "pass" if row.independent_verdict is L2Verdict.PASS else "fail"


def _l3_verdict(
    candidate: L3Candidate, report: L3ValidationReport,
) -> Literal["pass", "fail", "blocked", "not-run"]:
    if candidate.status is not L3CandidateStatus.CANDIDATE:
        return "blocked"
    row = next(
        (item for item in report.candidates
         if item.candidate_id == candidate.candidate_id),
        None,
    )
    if row is None:
        return "not-run"
    if row.independent_verdict is L3Verdict.PASS:
        return "pass"
    if row.independent_verdict is L3Verdict.FAIL:
        return "fail"
    if row.independent_verdict is L3Verdict.BLOCKED:
        return "blocked"
    return "not-run"


def _l2_blocking_reasons(
    candidate: L2Candidate, report: L2ValidationReport,
) -> tuple[str, ...]:
    values = list(candidate.blocking_reasons)
    row = next(
        (item for item in report.candidates
         if item.candidate_id == candidate.candidate_id),
        None,
    )
    if row is not None:
        values.extend(failure.code for failure in row.parse.failures)
        if row.scope.reason_code:
            values.append(row.scope.reason_code)
        values.extend(row.context_binding.reasons)
        values.extend(row.semantics.mismatches)
        values.extend(row.risk.findings)
    return _dedupe(values)


def _l3_blocking_reasons(
    candidate: L3Candidate, report: L3ValidationReport,
) -> tuple[str, ...]:
    values = list(candidate.blocking_reasons)
    row = next(
        (item for item in report.candidates
         if item.candidate_id == candidate.candidate_id),
        None,
    )
    if row is not None:
        values.extend(row.evidence.reason_codes)
        values.extend(row.context_binding.reason_codes)
        values.extend(row.target_capability.reason_codes)
        values.extend(row.semantics.reason_codes)
        values.extend(row.risk.reason_codes)
    return _dedupe(values)


def _project_l2(
    candidate: L2Candidate,
    report: L2ValidationReport,
    *,
    trusted: bool,
) -> AssemblyCandidate:
    verdict = _l2_verdict(candidate, report)
    if not trusted:
        verdict = "blocked"
    return AssemblyCandidate(
        candidate_id=candidate.candidate_id,
        source_layer="l2",
        category=candidate.category.value,
        target_kind=candidate.target.kind.value,
        target_name=candidate.target.name,
        status=candidate.status.value,
        verdict=verdict,
        candidate_text=(
            candidate.candidate_text
            if candidate.status is L2CandidateStatus.CANDIDATE
            and verdict == "pass" else None
        ),
        risk_class=candidate.risk_class.value,
        requires_field_verification=candidate.requires_field_verification,
        blocking_reasons=(
            () if verdict == "pass" else (
                *(_l2_blocking_reasons(candidate, report)
                  if trusted else ("l2-device-evidence-gate-not-pass",)),
            )
        ),
        candidate_fingerprint=candidate.candidate_fingerprint,
    )


def _project_l3(
    candidate: L3Candidate, report: L3ValidationReport,
) -> AssemblyCandidate:
    verdict = _l3_verdict(candidate, report)
    return AssemblyCandidate(
        candidate_id=candidate.candidate_id,
        source_layer="l3",
        category=candidate.category.value,
        target_kind=candidate.target.kind,
        target_name=candidate.target.name,
        status=candidate.status.value,
        verdict=verdict,
        candidate_text=(
            candidate.candidate_text
            if candidate.status is L3CandidateStatus.CANDIDATE
            and verdict == "pass" else None
        ),
        risk_class=candidate.risk_class.value,
        requires_field_verification=candidate.requires_field_verification,
        blocking_reasons=(
            () if verdict == "pass" else _l3_blocking_reasons(candidate, report)
        ),
        candidate_fingerprint=candidate.candidate_fingerprint,
    )


# --------------------------------------------------------------------------- #
# Chapter composition and completeness
# --------------------------------------------------------------------------- #


def _applicability(
    section_id: str,
    l2_device: DeviceLayer2Intent,
    l3_device: L3DeviceIntent,
    l3_applicable: bool,
) -> tuple[bool, AssemblyApplicability]:
    _cis_reference, implemented = SECTION_CAPABILITY_MATRIX[section_id]
    if not implemented:
        return (
            section_id == "management-auth-ssh",
            AssemblyApplicability.NOT_IMPLEMENTED,
        )
    if section_id in L3_SECTION_CATEGORIES:
        if not l3_applicable:
            return False, AssemblyApplicability.NOT_APPLICABLE
        if section_id == "dhcp" and not l3_device.dhcp_relays:
            return False, AssemblyApplicability.NOT_APPLICABLE
        return True, AssemblyApplicability.APPLICABLE
    ports = l2_device.desired.physical_ports
    channels = l2_device.desired.port_channels
    if section_id == "port-channels-lacp":
        applicable = bool(channels)
    elif section_id == "portfast-bpdu-poe":
        applicable = any(
            port.portfast is not None
            or port.bpdu_guard is not None
            or port.poe_mode is not None
            for port in ports
        ) or any(
            channel.settings.portfast is not None
            or channel.settings.bpdu_guard is not None
            for channel in channels
        )
    else:
        applicable = bool(ports or channels)
    return applicable, (
        AssemblyApplicability.APPLICABLE if applicable
        else AssemblyApplicability.NOT_APPLICABLE
    )


def _l2_expected_items(
    section_id: str, l2_preview: Layer2DeviceConfigPreview,
) -> Mapping[str, str]:
    categories = set(L2_PREVIEW_CATEGORIES.get(section_id, ()))
    return {
        item.item_id: item.category.value
        for item in l2_preview.device.config_items
        if item.category.value in categories
    }


def _l2_candidate_item_ids(candidate: L2Candidate) -> set[str]:
    values = {candidate.provenance.preview_item_id}
    values.update(candidate.provenance.additional_preview_item_ids)
    return {value for value in values if value}


def _l3_expected_targets(
    section_id: str,
    l3_device: L3DeviceIntent,
    assignment_id: UUID,
) -> Mapping[str, str]:
    if section_id == "ip-routing":
        return (
            {str(assignment_id): l3_device.identity.hostname}
            if l3_device.identity.role is DeviceRole.CORE else {}
        )
    if section_id == "svi":
        return {
            str(item.interface_id): item.name
            for item in l3_device.interfaces if item.kind == "svi"
        }
    if section_id == "routes":
        return {
            str(item.route_id): str(item.destination)
            for item in l3_device.routes
        }
    if section_id == "dhcp":
        return {
            str(item.svi_id): str(item.vlan)
            for item in l3_device.dhcp_relays
        }
    return {}


def _section_status(
    *,
    required: bool,
    applicability: AssemblyApplicability,
    candidate_count: int,
    passed_count: int,
    failed_count: int,
    blocked_count: int,
    missing_count: int,
) -> AssemblySectionStatus:
    if applicability is AssemblyApplicability.NOT_IMPLEMENTED:
        return AssemblySectionStatus.NOT_IMPLEMENTED
    if applicability is AssemblyApplicability.NOT_APPLICABLE:
        return AssemblySectionStatus.NOT_APPLICABLE
    if failed_count:
        return AssemblySectionStatus.BLOCKED
    if candidate_count == 0:
        return (
            AssemblySectionStatus.BLOCKED
            if required else AssemblySectionStatus.NOT_APPLICABLE
        )
    if missing_count:
        return (
            AssemblySectionStatus.PARTIAL
            if passed_count else AssemblySectionStatus.BLOCKED
        )
    if passed_count == candidate_count and blocked_count == 0:
        return AssemblySectionStatus.VALIDATED_SECTION
    if passed_count:
        return AssemblySectionStatus.PARTIAL
    return AssemblySectionStatus.BLOCKED


def _evidence_references(
    candidates: tuple[AssemblyCandidate, ...],
    l2_document: L2CliCandidateDocument,
    l3_document: L3CandidateDocument,
    l2_registry_id: str,
    l2_registry_fingerprint: str,
    l3_registry_id: str,
    l3_registry_fingerprint: str,
) -> tuple[SectionEvidenceReference, ...]:
    references: list[SectionEvidenceReference] = []
    l2_by_id = {item.candidate_id: item for item in l2_document.candidates}
    l3_by_id = {item.candidate_id: item for item in l3_document.candidates}
    for candidate in candidates:
        if candidate.source_layer == "l2":
            l2_source = l2_by_id.get(candidate.candidate_id)
            if l2_source is not None:
                for l2_evidence in l2_source.syntax_evidence:
                    references.append(SectionEvidenceReference(
                        kind="syntax",
                        reference_id=l2_evidence.evidence_id,
                        detail=f"{l2_evidence.topic} · {l2_evidence.source_section}",
                    ))
                for l2_capability in l2_source.capability_evidence:
                    if l2_capability.capability:
                        references.append(SectionEvidenceReference(
                            kind="capability",
                            reference_id=l2_capability.capability,
                            detail=(
                                f"{l2_capability.verdict} · "
                                f"{l2_capability.reason_code}"
                            ),
                        ))
        else:
            l3_source = l3_by_id.get(candidate.candidate_id)
            if l3_source is not None:
                for l3_evidence in l3_source.syntax_evidence:
                    references.append(SectionEvidenceReference(
                        kind="syntax",
                        reference_id=l3_evidence.evidence_id,
                        detail=f"{l3_evidence.topic} · {l3_evidence.source_section}",
                    ))
                for l3_capability in l3_source.capability_evidence:
                    if l3_capability.capability:
                        references.append(SectionEvidenceReference(
                            kind="capability",
                            reference_id=l3_capability.capability,
                            detail=(
                                f"{l3_capability.verdict} · "
                                f"{l3_capability.reason_code}"
                            ),
                        ))
    references.extend((
        SectionEvidenceReference(
            kind="registry", reference_id=l2_registry_id,
            detail=l2_registry_fingerprint,
        ),
        SectionEvidenceReference(
            kind="registry", reference_id=l3_registry_id,
            detail=l3_registry_fingerprint,
        ),
    ))
    unique: dict[tuple[str, str, str], SectionEvidenceReference] = {}
    for reference in references:
        unique[(reference.kind, reference.reference_id, reference.detail)] = reference
    return tuple(unique[key] for key in sorted(unique))


def _build_sections(
    *,
    l2_intent: Layer2Intent,
    l2_preview: Layer2DeviceConfigPreview,
    l2_document: L2CliCandidateDocument,
    l2_report: L2ValidationReport,
    l3_intent: Layer3Intent,
    l3_device: L3DeviceIntent,
    l3_document: L3CandidateDocument,
    l3_report: L3ValidationReport,
    assignment_id: UUID,
    l3_applicable: bool,
) -> tuple[AssemblySection, ...]:
    l2_device = next(
        item for item in l2_intent.devices
        if item.identity.assignment_id == assignment_id
    )
    l2_trusted = (
        l2_preview.device.deployability.evidence_gate == "pass"
        and l2_report.summary.overall_status is L2Verdict.PASS
    )
    l2_rows = tuple(
        _project_l2(candidate, l2_report, trusted=l2_trusted)
        for candidate in l2_document.candidates
    )
    l3_rows = tuple(
        _project_l3(candidate, l3_report)
        for candidate in l3_document.candidates
    )
    l2_registry_id = l2_document.source.command_evidence_registry_id
    l2_registry_fingerprint = l2_document.source.command_evidence_fingerprint
    l3_registry_id = l3_document.source.command_evidence_registry_id
    l3_registry_fingerprint = l3_document.source.command_evidence_registry_fingerprint
    fingerprints = _section_fingerprints(
        l2_preview, l2_document, l2_report, l3_intent, l3_document, l3_report,
    )
    sections: list[AssemblySection] = []
    for section_id in SECTION_IDS:
        required, applicability = _applicability(
            section_id, l2_device, l3_device, l3_applicable,
        )
        categories = {
            *L2_SECTION_CATEGORIES.get(section_id, ()),
            *L3_SECTION_CATEGORIES.get(section_id, ()),
        }
        selected = tuple(
            row for row in (*l2_rows, *l3_rows)
            if row.category in categories
        )
        if section_id in L2_SECTION_CATEGORIES:
            expected = _l2_expected_items(section_id, l2_preview)
            covered: set[str] = set()
            for candidate in l2_document.candidates:
                if candidate.category.value in categories:
                    covered.update(_l2_candidate_item_ids(candidate))
            missing = len(set(expected) - covered)
        elif section_id in L3_SECTION_CATEGORIES:
            expected_targets = _l3_expected_targets(
                section_id, l3_device, assignment_id,
            )
            source_by_id = {
                item.candidate_id: item for item in l3_document.candidates
            }
            covered_targets = {
                str(source_by_id[row.candidate_id].target.stable_id)
                for row in selected if row.candidate_id in source_by_id
            }
            missing = len(set(expected_targets) - covered_targets)
        else:
            missing = 1 if required else 0
        candidate_count = len(selected)
        passed = sum(1 for row in selected if row.verdict == "pass")
        failed = sum(1 for row in selected if row.verdict == "fail")
        blocked = sum(
            1 for row in selected
            if row.status != "candidate" or row.verdict == "blocked"
        )
        reason_codes = [
            reason for row in selected for reason in row.blocking_reasons
        ]
        if applicability is AssemblyApplicability.NOT_IMPLEMENTED:
            reason_codes.append("section-not-implemented")
        if (
            required
            and candidate_count == 0
            and applicability is AssemblyApplicability.APPLICABLE
        ):
            reason_codes.append("no-validated-candidate")
        if missing:
            reason_codes.append("missing-configuration-target")
        sections.append(AssemblySection(
            section_id=section_id,
            required=required,
            applicability=applicability,
            status=_section_status(
                required=required,
                applicability=applicability,
                candidate_count=candidate_count,
                passed_count=passed,
                failed_count=failed,
                blocked_count=blocked,
                missing_count=missing,
            ),
            candidate_count=candidate_count,
            passed_count=passed,
            failed_count=failed,
            blocked_count=blocked,
            missing_count=missing,
            reason_codes=_dedupe(reason_codes),
            evidence_references=_evidence_references(
                selected, l2_document, l3_document,
                l2_registry_id, l2_registry_fingerprint,
                l3_registry_id, l3_registry_fingerprint,
            ),
            source_fingerprints=fingerprints,
            candidates=selected,
        ))
    return tuple(sections)


# --------------------------------------------------------------------------- #
# Independent cross-layer checks
# --------------------------------------------------------------------------- #


def _check(
    check_id: str,
    status: CrossLayerStatus,
    reason_codes: Iterable[str] = (),
    detail: str = "",
) -> CrossLayerCheck:
    return CrossLayerCheck(
        check_id=check_id,
        status=status,
        reason_codes=_dedupe(reason_codes),
        detail=detail,
    )


def _interface_vlan_references(
    ports: Iterable[PhysicalPortIntent],
    channels: Iterable[PortChannelIntent],
) -> Mapping[int, tuple[str, ...]]:
    references: dict[int, list[str]] = {}

    def add(vlan: int | None, source: str) -> None:
        if vlan is not None:
            references.setdefault(vlan, []).append(source)

    for port in ports:
        add(port.access_vlan, f"interface:{port.name}:access")
        add(port.native_vlan, f"interface:{port.name}:native")
        for vlan in port.allowed_vlans:
            add(vlan, f"interface:{port.name}:allowed")
    for channel in channels:
        settings = channel.settings
        add(settings.access_vlan, f"port-channel:{channel.number}:access")
        add(settings.native_vlan, f"port-channel:{channel.number}:native")
        for vlan in settings.allowed_vlans:
            add(vlan, f"port-channel:{channel.number}:allowed")
    return {vlan: tuple(sources) for vlan, sources in references.items()}


def _plan_interfaces(
    plan: EventPlan, assignment_id: UUID,
) -> tuple[PhysicalInterface, ...]:
    return tuple(
        item for item in plan.physical_interfaces
        if item.assignment_id == assignment_id
    )


def _cross_checks(
    *,
    revision: PlanRevision,
    l2_intent: Layer2Intent,
    l2_device: DeviceLayer2Intent,
    l3_device: L3DeviceIntent,
    l3_document: L3CandidateDocument,
    l3_report: L3ValidationReport,
    assignment_id: UUID,
) -> tuple[CrossLayerCheck, ...]:
    plan = revision.plan
    declared = {item.vlan_id for item in l2_intent.vlans}
    ports = l2_device.desired.physical_ports
    channels = l2_device.desired.port_channels
    references = _interface_vlan_references(ports, channels)
    l3_svi_vlans = {
        item.vlan for item in l3_device.interfaces
        if item.kind == "svi" and item.vlan is not None
    }
    checks: list[CrossLayerCheck] = []

    missing_vlans = sorted(
        (set(references) | l3_svi_vlans) - declared
    )
    checks.append(_check(
        "vlan-definition-exists",
        CrossLayerStatus.FAIL if missing_vlans else CrossLayerStatus.PASS,
        (f"vlan-not-declared:{vlan}" for vlan in missing_vlans),
        "All L2 references and L3 SVI VLANs must exist in the event VLAN scope.",
    ))

    svi_reasons: list[str] = []
    gateways_by_vlan: dict[int, set[IPv4Address]] = {}
    subnets_by_id = {item.id: item for item in plan.subnets}
    for gateway in plan.gateways:
        subnet = subnets_by_id.get(gateway.subnet_id)
        if subnet is not None:
            gateways_by_vlan.setdefault(subnet.vlan, set()).add(gateway.address)
    for interface in l3_device.interfaces:
        if interface.kind != "svi" or interface.vlan is None:
            continue
        if interface.name != f"Vlan{interface.vlan}":
            svi_reasons.append(f"svi-name-vlan-mismatch:{interface.interface_id}")
        expected = gateways_by_vlan.get(interface.vlan)
        if (
            expected and interface.address is not None
            and interface.address.ip not in expected
        ):
            svi_reasons.append(f"svi-gateway-mismatch:{interface.vlan}")
    checks.append(_check(
        "svi-vlan-definition-consistency",
        CrossLayerStatus.FAIL if svi_reasons else CrossLayerStatus.PASS,
        svi_reasons,
        "SVI identity and gateway addresses must agree with the L2 VLAN scope.",
    ))

    mode_reasons = [
        f"routed-port-with-switchport:{port.name}"
        for port in ports if port.mode == "routed" and port.switchport
    ]
    checks.append(_check(
        "routed-switchport-conflict",
        CrossLayerStatus.FAIL if mode_reasons else CrossLayerStatus.PASS,
        mode_reasons,
        "A routed interface cannot also retain switchport intent.",
    ))

    channel_reasons: list[str] = []
    port_by_id = {item.interface_id: item for item in ports}
    memberships: dict[UUID, list[int]] = {}
    stack_device_ids = {
        member.physical_device_id for member in l2_device.identity.stack_members
    }
    expected_physical_ids = {
        item for item in (
            l2_device.identity.physical_device_id,
            *stack_device_ids,
        ) if item is not None
    }
    for channel in channels:
        if len(channel.member_ids) != len(channel.member_names):
            channel_reasons.append(f"channel-member-count-mismatch:{channel.number}")
        for member_id in channel.member_ids:
            memberships.setdefault(member_id, []).append(channel.number)
            port = port_by_id.get(member_id)
            if port is None:
                channel_reasons.append(
                    f"channel-member-not-physical:{channel.number}:{member_id}"
                )
                continue
            if port.port_channel != channel.number:
                channel_reasons.append(
                    f"channel-member-port-number-mismatch:{channel.number}:{port.name}"
                )
            if (
                port.physical_device_id is not None
                and port.physical_device_id not in expected_physical_ids
            ):
                channel_reasons.append(
                    f"channel-member-foreign-device:{channel.number}:{port.name}"
                )
    for member_id, numbers in memberships.items():
        if len(numbers) > 1:
            channel_reasons.append(f"channel-member-in-multiple-channels:{member_id}")
    checks.append(_check(
        "port-channel-membership",
        CrossLayerStatus.FAIL if channel_reasons else CrossLayerStatus.PASS,
        channel_reasons,
        "Port-Channel members must be physical ports of this assignment, "
        "bound to exactly one aggregate.",
    ))

    native_reasons: list[str] = []
    for port in ports:
        if port.native_vlan is not None and port.native_vlan not in declared:
            native_reasons.append(f"native-vlan-not-declared:{port.name}:{port.native_vlan}")
        for vlan in port.allowed_vlans:
            if vlan not in declared:
                native_reasons.append(f"allowed-vlan-not-declared:{port.name}:{vlan}")
    for channel in channels:
        if (
            channel.settings.native_vlan is not None
            and channel.settings.native_vlan not in declared
        ):
            native_reasons.append(
                f"native-vlan-not-declared:port-channel{channel.number}:{channel.settings.native_vlan}"
            )
        for vlan in channel.settings.allowed_vlans:
            if vlan not in declared:
                native_reasons.append(
                    f"allowed-vlan-not-declared:port-channel{channel.number}:{vlan}"
                )
    checks.append(_check(
        "native-allowed-vlan-reference",
        CrossLayerStatus.FAIL if native_reasons else CrossLayerStatus.PASS,
        native_reasons,
        "Native/allowed VLAN references must exist in the event VLAN scope.",
    ))

    protected_ports: set[UUID] = set()
    if plan.transit is not None and plan.transit.core_assignment_id == assignment_id:
        protected_ports.add(plan.transit.core_port_id)
    selected_port_ids = {port.interface_id for port in ports}
    for link in plan.links:
        endpoints = set(link.endpoints)
        if endpoints & selected_port_ids:
            protected_ports.update(endpoints & selected_port_ids)
    shutdown_reasons = [
        f"uplink-shutdown-contradiction:{port.name}"
        for port in ports
        if port.interface_id in protected_ports
        and (port.admin_state == "down" or port.shutdown_intent == "shutdown")
    ]
    checks.append(_check(
        "shutdown-uplink-consistency",
        CrossLayerStatus.FAIL if shutdown_reasons else CrossLayerStatus.PASS,
        shutdown_reasons,
        "An uplink or transit port cannot be planned down while required by topology.",
    ))

    local_networks = [
        interface.address.network
        for interface in l3_device.interfaces
        if interface.address is not None
    ]
    route_reasons: list[str] = []
    for route in l3_device.routes:
        if route.owner_assignment_id != assignment_id:
            route_reasons.append(f"route-owner-mismatch:{route.route_id}")
        if not any(route.next_hop in network for network in local_networks):
            route_reasons.append(f"route-next-hop-not-on-link:{route.route_id}")
    checks.append(_check(
        "static-route-next-hop-dependency",
        CrossLayerStatus.FAIL if route_reasons else CrossLayerStatus.PASS,
        route_reasons,
        "Static/default next hops must be reachable through a planned local interface.",
    ))

    default_routes = [route for route in l3_device.routes if route.kind == "default"]
    if not default_routes:
        checks.append(_check(
            "default-route-evidence-gate",
            CrossLayerStatus.NOT_APPLICABLE,
            detail="No Default Route is planned for this device.",
        ))
    else:
        default_candidates = [
            item for item in l3_document.candidates
            if item.category.value == "default-route"
        ]
        default_verdicts = [
            _l3_verdict(item, l3_report) for item in default_candidates
        ]
        approved = bool(default_candidates) and all(
            verdict == "pass" for verdict in default_verdicts
        )
        checks.append(_check(
            "default-route-evidence-gate",
            CrossLayerStatus.PASS if approved else CrossLayerStatus.FAIL,
            () if approved else ("default-route-not-evidence-approved",),
            "Default Route requires independent evidence approval on this device.",
        ))

    if not l3_device.dhcp_relays:
        checks.append(_check(
            "dhcp-relay-issue-30",
            CrossLayerStatus.NOT_APPLICABLE,
            detail="No DHCP Relay is planned for this device.",
        ))
    else:
        dhcp_candidates = [
            item for item in l3_document.candidates
            if item.category.value == "dhcp-helper-address"
        ]
        verdicts = [_l3_verdict(item, l3_report) for item in dhcp_candidates]
        if "pass" in verdicts:
            checks.append(_check(
                "dhcp-relay-issue-30",
                CrossLayerStatus.FAIL,
                ("dhcp-helper-unexpectedly-approved",),
                "DHCP Relay must remain blocked while Issue #30 is unresolved.",
            ))
        else:
            checks.append(_check(
                "dhcp-relay-issue-30",
                CrossLayerStatus.BLOCKED,
                ("dhcp-relay-license-unresolved",)
                if dhcp_candidates else ("dhcp-helper-evidence-missing",),
                "DHCP Relay License remains UNRESOLVED under Issue #30.",
            ))

    selected_interfaces = _plan_interfaces(plan, assignment_id)
    selected_ids = {item.interface_id for item in ports}
    planned_ids = {item.id for item in selected_interfaces}
    physical_reasons: list[str] = []
    if selected_ids - planned_ids:
        physical_reasons.extend(
            f"physical-interface-not-in-plan:{item}" for item in sorted(
                selected_ids - planned_ids, key=str
            )
        )
    if planned_ids - selected_ids:
        physical_reasons.extend(
            f"planned-physical-interface-not-in-assembly:{item}" for item in sorted(
                planned_ids - selected_ids, key=str
            )
        )
    seen_interface_ids: set[UUID] = set()
    for physical_interface in plan.physical_interfaces:
        if physical_interface.id in seen_interface_ids:
            physical_reasons.append(
                f"duplicate-physical-interface-id:{physical_interface.id}"
            )
        seen_interface_ids.add(physical_interface.id)
    assignment = next(
        (item for item in plan.assignments if item.id == assignment_id), None
    )
    if assignment is None:
        physical_reasons.append("assignment-missing")
    else:
        allowed_ids = {
            assignment.physical_device_id,
            *stack_device_ids,
        }
        for selected_interface in selected_interfaces:
            if selected_interface.physical_device_id not in allowed_ids:
                physical_reasons.append(
                    f"physical-interface-wrong-device:{selected_interface.id}"
                )
        for port in ports:
            if (
                port.physical_device_id is not None
                and port.physical_device_id not in allowed_ids
            ):
                physical_reasons.append(
                    f"physical-port-wrong-device:{port.name}"
                )
    checks.append(_check(
        "physical-interface-assignment",
        CrossLayerStatus.FAIL if physical_reasons else CrossLayerStatus.PASS,
        physical_reasons,
        "Every physical interface must belong to this assignment and Stack snapshot.",
    ))

    management_reasons: list[str] = []
    if plan.management_vlan not in declared:
        management_reasons.append(
            f"management-vlan-not-declared:{plan.management_vlan}"
        )
    management_ip = assignment.management_ip if assignment is not None else None
    if management_ip is not None:
        management_subnets = [
            subnet for subnet in plan.subnets
            if subnet.vlan == plan.management_vlan
        ]
        if not management_subnets:
            management_reasons.append("management-vlan-has-no-subnet")
        elif not any(
            management_ip in subnet.network for subnet in management_subnets
        ):
            management_reasons.append("management-ip-outside-management-subnet")
    checks.append(_check(
        "management-vlan-management-ip",
        (
            CrossLayerStatus.FAIL if management_reasons
            else CrossLayerStatus.PASS if management_ip is not None
            else CrossLayerStatus.NOT_APPLICABLE
        ),
        management_reasons
        or (() if management_ip is not None else ("management-ip-not-planned",)),
        "Management VLAN and management IP must describe the same planned network.",
    ))
    return tuple(checks)


# --------------------------------------------------------------------------- #
# Builder
# --------------------------------------------------------------------------- #


def evaluate_cross_layer_checks(
    revision: PlanRevision,
    l2_intent: Layer2Intent,
    l2_device: DeviceLayer2Intent,
    l3_device: L3DeviceIntent,
    l3_document: L3CandidateDocument,
    l3_report: L3ValidationReport,
    assignment_id: UUID,
) -> tuple[CrossLayerCheck, ...]:
    """Public, independently testable L2/L3 cross-layer consistency checks."""
    return _cross_checks(
        revision=revision,
        l2_intent=l2_intent,
        l2_device=l2_device,
        l3_device=l3_device,
        l3_document=l3_document,
        l3_report=l3_report,
        assignment_id=assignment_id,
    )


def _identity(
    revision: PlanRevision,
    assignment_id: UUID,
    l2_device: DeviceLayer2Intent,
    l3_device: L3DeviceIntent,
) -> AssemblyPhysicalIdentity:
    plan = revision.plan
    assignment = next(
        (item for item in plan.assignments if item.id == assignment_id), None
    )
    if assignment is None:
        raise AssemblyInputError("assignment-not-in-saved-revision")
    physical = next(
        (item for item in plan.physical_devices
         if item.id == assignment.physical_device_id),
        None,
    )
    identity = l2_device.identity
    if identity.assignment_id != assignment_id:
        raise AssemblyInputError("l2-identity-assignment-mismatch")
    if l3_device.identity.assignment_id != assignment_id:
        raise AssemblyInputError("l3-identity-assignment-mismatch")
    members = tuple(
        AssemblyStackMember(
            number=member.number,
            physical_device_id=member.physical_device_id,
            exact_pid=member.pid,
            state=member.state,
        )
        for member in identity.stack_members
    )
    return AssemblyPhysicalIdentity(
        assignment_id=assignment_id,
        hostname=identity.hostname,
        role=identity.role.value,
        family=identity.family.value if identity.family is not None else None,
        physical_device_id=identity.physical_device_id,
        physical_vendor=physical.vendor if physical is not None else None,
        physical_model=physical.model if physical is not None else None,
        verified_serial_present=bool(
            physical.verified_serial if physical is not None else None
        ),
        exact_pid=identity.pid,
        pid_evidence=identity.pid_evidence,
        serial_verified=identity.serial_verified,
        software_image=identity.software_image,
        software_license=identity.software_license,
        stack_identity=identity.stack_identity,
        stack_members=members,
        management_ip=(
            str(assignment.management_ip)
            if assignment.management_ip is not None else None
        ),
    )


def _completeness(
    sections: tuple[AssemblySection, ...],
    cross_checks: tuple[CrossLayerCheck, ...],
) -> AssemblyCompleteness:
    required = tuple(section for section in sections if section.required)
    validated = sum(
        1 for section in sections
        if section.status is AssemblySectionStatus.VALIDATED_SECTION
    )
    partial = sum(
        1 for section in sections
        if section.status is AssemblySectionStatus.PARTIAL
    )
    blocked = sum(
        1 for section in sections
        if section.status is AssemblySectionStatus.BLOCKED
    )
    not_applicable = sum(
        1 for section in sections
        if section.status is AssemblySectionStatus.NOT_APPLICABLE
    )
    not_implemented = sum(
        1 for section in sections
        if section.status is AssemblySectionStatus.NOT_IMPLEMENTED
    )
    missing_sections = tuple(
        section.section_id for section in required
        if section.status not in {
            AssemblySectionStatus.VALIDATED_SECTION,
            AssemblySectionStatus.NOT_APPLICABLE,
        }
    )
    missing_features = tuple(
        section.section_id for section in sections
        if section.status in {
            AssemblySectionStatus.NOT_IMPLEMENTED,
            AssemblySectionStatus.BLOCKED,
            AssemblySectionStatus.PARTIAL,
        }
    )
    blockers: list[str] = []
    for section in required:
        if section.status in {
            AssemblySectionStatus.VALIDATED_SECTION,
            AssemblySectionStatus.NOT_APPLICABLE,
        }:
            continue
        blockers.append(f"{section.section_id}:{section.status.value}")
        blockers.extend(section.reason_codes)
    cross_blocked = False
    cross_failed = False
    for check in cross_checks:
        if check.status is CrossLayerStatus.FAIL:
            cross_failed = True
            blockers.extend(
                f"cross-layer:{check.check_id}:{reason}"
                for reason in check.reason_codes
            )
        elif check.status is CrossLayerStatus.BLOCKED:
            cross_blocked = True
            blockers.extend(
                f"cross-layer:{check.check_id}:{reason}"
                for reason in check.reason_codes
            )
    complete = not missing_sections and not cross_failed and not cross_blocked
    if complete:
        status = AssemblySectionStatus.VALIDATED_SECTION
    elif missing_sections or cross_failed or cross_blocked:
        status = (
            AssemblySectionStatus.BLOCKED
            if any(
                section.status is AssemblySectionStatus.BLOCKED
                for section in required
            ) or cross_failed or cross_blocked
            else AssemblySectionStatus.NOT_IMPLEMENTED
            if any(
                section.status is AssemblySectionStatus.NOT_IMPLEMENTED
                for section in required
            )
            else AssemblySectionStatus.PARTIAL
        )
    else:
        status = AssemblySectionStatus.PARTIAL
    return AssemblyCompleteness(
        status=status,
        complete=complete,
        required_sections=len(required),
        validated_sections=validated,
        partial_sections=partial,
        blocked_sections=blocked,
        not_applicable_sections=not_applicable,
        not_implemented_sections=not_implemented,
        missing_sections=missing_sections,
        missing_features=missing_features,
        blockers=_dedupe(blockers),
    )


def build_config_assembly(
    revision: PlanRevision,
    l2_intent: Layer2Intent,
    l2_preview: Layer2DeviceConfigPreview,
    l2_document: L2CliCandidateDocument,
    l2_report: L2ValidationReport,
    l3_intent: Layer3Intent,
    l3_document: L3CandidateDocument,
    l3_report: L3ValidationReport,
    assignment_id: UUID,
) -> ConfigurationAssembly:
    """Assemble one read-only device review from trusted frozen objects."""
    plan = revision.plan
    assignment = next(
        (item for item in plan.assignments if item.id == assignment_id), None
    )
    if assignment is None:
        raise AssemblyInputError("assignment-not-in-saved-revision")
    l3_device = next(
        (item for item in l3_intent.devices
         if item.identity.assignment_id == assignment_id),
        None,
    )
    if l3_device is None:
        raise AssemblyInputError("l3-device-not-in-saved-revision")
    l2_device = next(
        (item for item in l2_intent.devices
         if item.identity.assignment_id == assignment_id),
        None,
    )
    if l2_device is None:
        raise AssemblyInputError("l2-device-not-in-saved-revision")
    if l2_document.assignment_id != assignment_id:
        raise AssemblyInputError("l2-document-assignment-mismatch")
    if l3_document.assignment_id != assignment_id:
        raise AssemblyInputError("l3-document-assignment-mismatch")
    if l2_preview.device.assignment_id != assignment_id:
        raise AssemblyInputError("l2-preview-assignment-mismatch")
    if l2_report.assignment_id != assignment_id:
        raise AssemblyInputError("l2-validation-assignment-mismatch")
    if l3_report.assignment_id != assignment_id:
        raise AssemblyInputError("l3-validation-assignment-mismatch")
    if l2_intent.revision_id != revision.id or l2_intent.revision_hash != revision.content_hash:
        raise AssemblyInputError("l2-intent-revision-mismatch")
    if l3_intent.revision_id != revision.id or l3_intent.revision_hash != revision.content_hash:
        raise AssemblyInputError("l3-intent-revision-mismatch")
    l3_applicable = (
        assignment.role is DeviceRole.CORE
        and (assignment.family is not None)
    )
    sections = _build_sections(
        l2_intent=l2_intent,
        l2_preview=l2_preview,
        l2_document=l2_document,
        l2_report=l2_report,
        l3_intent=l3_intent,
        l3_device=l3_device,
        l3_document=l3_document,
        l3_report=l3_report,
        assignment_id=assignment_id,
        l3_applicable=l3_applicable,
    )
    cross_checks = _cross_checks(
        revision=revision,
        l2_intent=l2_intent,
        l2_device=l2_device,
        l3_device=l3_device,
        l3_document=l3_document,
        l3_report=l3_report,
        assignment_id=assignment_id,
    )
    source = AssemblySource(
        event_id=plan.event_id,
        revision_id=revision.id,
        revision_number=revision.number,
        revision_canonical_hash=revision.content_hash,
        assignment_id=assignment_id,
        l2_intent_fingerprint=l2_intent.intent_fingerprint,
        l2_preview_fingerprint=l2_preview.preview_fingerprint,
        l2_render_fingerprint=l2_document.render_fingerprint,
        l2_validation_fingerprint=l2_report.report_fingerprint,
        l2_candidate_fingerprints=tuple(
            candidate.candidate_fingerprint
            for candidate in l2_document.candidates
        ),
        l2_command_evidence_registry_id=(
            l2_document.source.command_evidence_registry_id
        ),
        l2_command_evidence_registry_fingerprint=(
            l2_document.source.command_evidence_fingerprint
        ),
        l3_intent_fingerprint=l3_intent.intent_fingerprint,
        l3_render_fingerprint=l3_document.l3_render_fingerprint,
        l3_validation_fingerprint=l3_report.report_fingerprint,
        l3_candidate_fingerprints=tuple(
            candidate.candidate_fingerprint
            for candidate in l3_document.candidates
        ),
        l3_command_evidence_registry_id=(
            l3_document.source.command_evidence_registry_id
        ),
        l3_command_evidence_registry_fingerprint=(
            l3_document.source.command_evidence_registry_fingerprint
        ),
    )
    draft = ConfigurationAssembly(
        source=source,
        identity=_identity(revision, assignment_id, l2_device, l3_device),
        sections=sections,
        cross_layer_checks=cross_checks,
        completeness=_completeness(sections, cross_checks),
        assembly_fingerprint="",
    )
    return draft.model_copy(update={
        "assembly_fingerprint": assembly_fingerprint(draft),
    })


__all__ = [
    "ASSEMBLY_CONTRACT_ID",
    "ASSEMBLY_SCHEMA_VERSION",
    "AssemblyApplicability",
    "AssemblyCandidate",
    "AssemblyCompleteness",
    "AssemblyInputError",
    "AssemblyPhysicalIdentity",
    "AssemblySafety",
    "AssemblySection",
    "AssemblySectionStatus",
    "AssemblySource",
    "ConfigurationAssembly",
    "CrossLayerCheck",
    "CrossLayerStatus",
    "L2_SECTION_CATEGORIES",
    "L3_SECTION_CATEGORIES",
    "SECTION_CAPABILITY_MATRIX",
    "SECTION_IDS",
    "assembly_fingerprint",
    "build_config_assembly",
    "evaluate_cross_layer_checks",
]
