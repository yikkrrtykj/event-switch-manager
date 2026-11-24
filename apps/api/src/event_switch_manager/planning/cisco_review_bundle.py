"""Cisco read-only configuration review bundle.

The bundle is a structured review artifact only.  It contains no complete
configuration, execution sequence or deployment artifact.  Every candidate
text retained here is bound to the same saved revision, assignment, production
Evidence Registry identity and independent validation verdict used by the API.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Literal, cast
from uuid import UUID

from .config_assembly import ConfigurationAssembly, assembly_fingerprint
from .layer2_cli_candidates import (
    Candidate as L2Candidate,
)
from .layer2_cli_candidates import (
    L2CliCandidateDocument,
)
from .layer2_cli_validation import (
    CandidateValidation as L2CandidateValidation,
)
from .layer2_cli_validation import (
    ValidationReport as L2ValidationReport,
)
from .layer2_cli_validation import (
    _report_fingerprint as l2_report_fingerprint,
)
from .layer2_cli_validation import (
    recompute_candidate_fingerprint as recompute_l2_candidate_fingerprint,
)
from .layer2_cli_validation import (
    recompute_render_fingerprint as recompute_l2_render_fingerprint,
)
from .layer3_cli_candidates import (
    Candidate as L3Candidate,
)
from .layer3_cli_candidates import (
    L3CandidateDocument,
)
from .layer3_cli_validation import (
    CandidateValidation as L3CandidateValidation,
)
from .layer3_cli_validation import (
    L3ValidationReport,
)
from .layer3_cli_validation import (
    independent_candidate_fingerprint as independent_l3_candidate_fingerprint,
)
from .layer3_cli_validation import (
    independent_render_fingerprint as independent_l3_render_fingerprint,
)
from .layer3_cli_validation import (
    independent_report_fingerprint as independent_l3_report_fingerprint,
)
from .management_cli_candidates import (
    ManagementCandidate,
    ManagementCandidateDocument,
    ManagementCandidateValidation,
    ManagementValidationReport,
)
from .management_cli_candidates import (
    _candidate_fingerprint as _management_candidate_fingerprint,
)
from .management_cli_candidates import (
    _document_fingerprint as _management_document_fingerprint,
)
from .management_cli_candidates import (
    _report_fingerprint as _management_report_fingerprint,
)
from .plan import PlanRevision
from .types import Record

REVIEW_BUNDLE_CONTRACT_ID: Literal[
    "cis-04b-cisco-config-review-bundle-v1"
] = "cis-04b-cisco-config-review-bundle-v1"
REVIEW_BUNDLE_SCHEMA_VERSION: Literal[1] = 1
REVIEW_BUNDLE_REPORT_TYPE: Literal[
    "cisco-configuration-review-report"
] = "cisco-configuration-review-report"
REVIEW_BUNDLE_TITLE = "CISCO CONFIGURATION REVIEW REPORT"
REVIEW_BUNDLE_BANNER = (
    REVIEW_BUNDLE_TITLE,
    "READ ONLY",
    "NON-EXECUTABLE",
    "PARTIAL CONFIGURATION CANDIDATES",
    "NOT HARDWARE VERIFIED",
    "NOT APPROVED FOR DEPLOYMENT",
)
REVIEW_BUNDLE_LIMITATIONS = (
    "PARTIAL CONFIGURATION CANDIDATES ONLY",
    "NOT A COMPLETE CISCO CONFIGURATION",
    "NO DEVICE CONNECTION OR COMMAND EXECUTION",
    "NO DEPLOYMENT ARTIFACT OR EXECUTABLE SCRIPT",
    "SOFTWARE VALIDATION IS NOT HARDWARE VERIFICATION",
)


class ReviewBundleError(ValueError):
    """A bundle integrity or traceability failure; never downgraded to BLOCKED."""

    def __init__(self, reason_code: str, details: tuple[str, ...] = ()) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.details = details


class ReviewBundleIdentity(Record):
    event_id: UUID
    event_name: str
    revision_id: UUID
    revision_number: int
    revision_canonical_hash: str
    assignment_id: UUID
    hostname: str
    role: str
    family: str
    exact_pid: str | None
    software_image: str | None
    software_license: str | None
    stack_identity: str


class ReviewBundleCandidate(Record):
    candidate_id: str
    source_layer: Literal["l2", "l3", "management"]
    category: str
    target_kind: str
    target_name: str
    status: str
    independent_verdict: str
    command_text: str | None
    command_text_included: bool
    blocking_reasons: tuple[str, ...]
    candidate_fingerprint: str
    evidence_ids: tuple[str, ...]
    risk_class: str | None
    requires_field_verification: bool
    secret_bearing: bool


class ReviewBundleSubsystem(Record):
    layer: Literal["l2", "l3", "management"]
    contract_id: str
    registry_id: str
    registry_fingerprint: str
    intent_fingerprint: str
    document_fingerprint: str
    validation_fingerprint: str
    overall_status: str
    summary: dict[str, object]
    candidates: tuple[ReviewBundleCandidate, ...]
    production_authorization: Literal["PENDING"] | None = None


class ReviewBundleSection(Record):
    section_id: str
    required: bool
    applicability: str
    status: str
    candidate_count: int
    passed_count: int
    failed_count: int
    blocked_count: int
    missing_count: int
    reason_codes: tuple[str, ...]


class ReviewBundleCrossCheck(Record):
    check_id: str
    status: str
    reason_codes: tuple[str, ...]
    detail: str


class ReviewBundleAssembly(Record):
    contract_id: str
    assembly_fingerprint: str
    completeness: dict[str, object]
    sections: tuple[ReviewBundleSection, ...]
    cross_layer_checks: tuple[ReviewBundleCrossCheck, ...]
    safety: dict[str, object]


class ReviewBundleSourceFingerprints(Record):
    l2_intent: str
    l2_preview: str
    l2_render: str
    l2_validation: str
    l3_intent: str
    l3_render: str
    l3_validation: str
    management_intent: str
    management_render: str
    management_validation: str
    assembly: str


class ReviewBundleSafety(Record):
    read_only: Literal[True] = True
    non_executable: Literal[True] = True
    partial_configuration_candidates: Literal[True] = True
    software_validation: Literal["completed"] = "completed"
    hardware_verified: Literal[False] = False
    deployment_allowed: Literal[False] = False
    full_config_generated: Literal[False] = False
    executable: Literal[False] = False
    device_connection: Literal["none"] = "none"
    device_writes_enabled: Literal[False] = False
    production_authorization: Literal["PENDING"] = "PENDING"


class ReviewBundleContent(Record):
    report_schema_version: Literal[1] = REVIEW_BUNDLE_SCHEMA_VERSION
    contract_id: Literal[
        "cis-04b-cisco-config-review-bundle-v1"
    ] = REVIEW_BUNDLE_CONTRACT_ID
    report_type: Literal["cisco-configuration-review-report"] = (
        REVIEW_BUNDLE_REPORT_TYPE
    )
    banner: tuple[str, ...] = REVIEW_BUNDLE_BANNER
    identity: ReviewBundleIdentity
    l2: ReviewBundleSubsystem
    l3: ReviewBundleSubsystem
    management: ReviewBundleSubsystem
    assembly: ReviewBundleAssembly
    source_fingerprints: ReviewBundleSourceFingerprints
    safety: ReviewBundleSafety = ReviewBundleSafety()
    limitations: tuple[str, ...] = REVIEW_BUNDLE_LIMITATIONS


class CiscoReviewBundle(Record):
    bundle_schema_version: Literal[1] = REVIEW_BUNDLE_SCHEMA_VERSION
    contract_id: Literal[
        "cis-04b-cisco-config-review-bundle-v1"
    ] = REVIEW_BUNDLE_CONTRACT_ID
    generated_at: str
    suggested_filename: str
    content_digest: str
    content: ReviewBundleContent


_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename_part(value: str, fallback: str) -> str:
    cleaned = _UNSAFE_FILENAME.sub("-", value).strip("-._")
    return (cleaned[:64] or fallback)


def review_bundle_filename(
    event_name: str, hostname: str, revision_number: int, event_id: UUID,
) -> str:
    event = _safe_filename_part(event_name, f"event-{str(event_id)[:8]}")
    device = _safe_filename_part(hostname, "device")
    return f"cisco-config-review-{event}-{device}-r{revision_number}.json"


def review_bundle_content_digest(content: ReviewBundleContent) -> str:
    """Deterministic digest of content only; generated_at is deliberately excluded."""
    payload = content.model_dump(mode="json")
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _reasons(
    *groups: str | tuple[str, ...] | None,
) -> tuple[str, ...]:
    values: list[str] = []
    for group in groups:
        if group is None:
            continue
        if isinstance(group, str):
            values.append(group)
        else:
            values.extend(str(item) for item in group if item)
    return tuple(dict.fromkeys(value for value in values if value))


def _verify_l2_current_content(
    document: L2CliCandidateDocument,
    report: L2ValidationReport,
) -> None:
    """Recompute current L2 document/candidate hashes, not just trust booleans."""
    actual_document = recompute_l2_render_fingerprint(document)
    if document.render_fingerprint != actual_document:
        raise ReviewBundleError("review-bundle-l2-document-fingerprint-mismatch")
    if report.source.render_fingerprint != actual_document:
        raise ReviewBundleError("review-bundle-l2-report-document-binding-mismatch")
    actual_report = l2_report_fingerprint(report)
    if report.report_fingerprint != actual_report:
        raise ReviewBundleError("review-bundle-l2-report-fingerprint-mismatch")
    docs = [item.candidate_id for item in document.candidates]
    reports = [item.candidate_id for item in report.candidates]
    if len(docs) != len(set(docs)) or len(reports) != len(set(reports)):
        raise ReviewBundleError("review-bundle-l2-candidate-id-duplicate")
    if set(docs) != set(reports):
        raise ReviewBundleError("review-bundle-l2-candidate-set-mismatch")
    for candidate in document.candidates:
        actual = recompute_l2_candidate_fingerprint(candidate)
        if candidate.candidate_fingerprint != actual:
            raise ReviewBundleError(
                "review-bundle-l2-candidate-fingerprint-mismatch",
            )
        validation = next(
            item for item in report.candidates
            if item.candidate_id == candidate.candidate_id
        )
        if (
            validation.candidate_fingerprint != actual
            or validation.candidate_fingerprint_recomputed != actual
            or not validation.candidate_fingerprint_match
        ):
            raise ReviewBundleError(
                "review-bundle-l2-report-candidate-binding-mismatch",
            )


def _verify_l3_current_content(
    document: L3CandidateDocument,
    report: L3ValidationReport,
) -> None:
    """Recompute current L3 document/candidate/report hashes."""
    actual_document = independent_l3_render_fingerprint(document)
    if document.l3_render_fingerprint != actual_document:
        raise ReviewBundleError("review-bundle-l3-document-fingerprint-mismatch")
    if report.source.l3_render_fingerprint != actual_document:
        raise ReviewBundleError("review-bundle-l3-report-document-binding-mismatch")
    actual_report = independent_l3_report_fingerprint(report)
    if report.report_fingerprint != actual_report:
        raise ReviewBundleError("review-bundle-l3-report-fingerprint-mismatch")
    docs = [item.candidate_id for item in document.candidates]
    reports = [item.candidate_id for item in report.candidates]
    if len(docs) != len(set(docs)) or len(reports) != len(set(reports)):
        raise ReviewBundleError("review-bundle-l3-candidate-id-duplicate")
    if set(docs) != set(reports):
        raise ReviewBundleError("review-bundle-l3-candidate-set-mismatch")
    for candidate in document.candidates:
        if candidate.candidate_fingerprint != (
            independent_l3_candidate_fingerprint(candidate)
        ):
            raise ReviewBundleError(
                "review-bundle-l3-candidate-fingerprint-mismatch",
            )


def _verify_management_current_content(
    document: ManagementCandidateDocument,
    report: ManagementValidationReport,
) -> None:
    """Recompute current Management document/candidate/report hashes."""
    actual_document = _management_document_fingerprint(document)
    if document.render_fingerprint != actual_document:
        raise ReviewBundleError(
            "review-bundle-management-document-fingerprint-mismatch",
        )
    if report.report_fingerprint != _management_report_fingerprint(report):
        raise ReviewBundleError(
            "review-bundle-management-report-fingerprint-mismatch",
        )
    docs = [item.candidate_id for item in document.candidates]
    reports = [item.candidate_id for item in report.candidates]
    if len(docs) != len(set(docs)) or len(reports) != len(set(reports)):
        raise ReviewBundleError("review-bundle-management-candidate-id-duplicate")
    if set(docs) != set(reports):
        raise ReviewBundleError("review-bundle-management-candidate-set-mismatch")
    for candidate in document.candidates:
        if candidate.candidate_fingerprint != (
            _management_candidate_fingerprint(candidate)
        ):
            raise ReviewBundleError(
                "review-bundle-management-candidate-fingerprint-mismatch",
            )


def _l2_candidate_reasons(
    candidate: L2Candidate, report: L2CandidateValidation,
) -> tuple[str, ...]:
    return _reasons(
        candidate.blocking_reasons,
        tuple(failure.code for failure in report.parse.failures),
        report.scope.reason_code,
        report.context_binding.reasons,
        report.target_capability.reasons,
        report.security.reason_codes,
        report.semantics.mismatches,
        report.risk.findings,
        report.fail_closed_action,
    )


def _l3_candidate_reasons(
    candidate: L3Candidate, report: L3CandidateValidation,
) -> tuple[str, ...]:
    return _reasons(
        candidate.blocking_reasons,
        report.parse.failures,
        report.evidence.reason_codes,
        report.context_binding.reason_codes,
        report.target_capability.reason_codes,
        report.security.reason_codes,
        report.semantics.reason_codes,
        report.risk.reason_codes,
        report.fail_closed_action,
    )


def _management_candidate_reasons(
    candidate: ManagementCandidate,
    report: ManagementCandidateValidation,
) -> tuple[str, ...]:
    return _reasons(candidate.blocking_reasons, report.blocking_reasons)


def _l2_candidates(
    document: L2CliCandidateDocument,
    report: L2ValidationReport,
) -> tuple[ReviewBundleCandidate, ...]:
    reports = {item.candidate_id: item for item in report.candidates}
    docs = {item.candidate_id: item for item in document.candidates}
    if len(reports) != len(report.candidates) or set(reports) != set(docs):
        raise ReviewBundleError("review-bundle-l2-candidate-set-mismatch")
    if report.source.render_fingerprint != document.render_fingerprint:
        raise ReviewBundleError("review-bundle-l2-render-fingerprint-mismatch")
    if not report.integrity.candidate_fingerprints_match:
        raise ReviewBundleError("review-bundle-l2-candidate-fingerprint-mismatch")
    result: list[ReviewBundleCandidate] = []
    for candidate_id, candidate in docs.items():
        validation = reports[candidate_id]
        if validation.candidate_fingerprint != candidate.candidate_fingerprint:
            raise ReviewBundleError("review-bundle-l2-candidate-fingerprint-mismatch")
        passed = validation.independent_verdict.value == "pass"
        text = candidate.candidate_text
        if passed:
            if candidate.status.value != "candidate" or not text:
                raise ReviewBundleError(
                    "review-bundle-l2-pass-text-binding-mismatch",
                )
        elif text is not None:
            raise ReviewBundleError(
                "review-bundle-l2-blocked-text-present",
            )
        reasons = _l2_candidate_reasons(candidate, validation)
        result.append(ReviewBundleCandidate(
            candidate_id=candidate.candidate_id,
            source_layer="l2",
            category=candidate.category.value,
            target_kind=candidate.target.kind.value,
            target_name=candidate.target.name,
            status=candidate.status.value,
            independent_verdict=validation.independent_verdict.value,
            command_text=text if passed else None,
            command_text_included=bool(passed and text),
            blocking_reasons=reasons,
            candidate_fingerprint=candidate.candidate_fingerprint,
            evidence_ids=tuple(dict.fromkeys(
                item.evidence_id for item in candidate.syntax_evidence
            )),
            risk_class=candidate.risk_class.value,
            requires_field_verification=(
                candidate.requires_field_verification
            ),
            secret_bearing=False,
        ))
    return tuple(result)


def _l3_candidates(
    document: L3CandidateDocument,
    report: L3ValidationReport,
) -> tuple[ReviewBundleCandidate, ...]:
    reports = {item.candidate_id: item for item in report.candidates}
    docs = {item.candidate_id: item for item in document.candidates}
    if len(reports) != len(report.candidates) or set(reports) != set(docs):
        raise ReviewBundleError("review-bundle-l3-candidate-set-mismatch")
    if report.source.l3_render_fingerprint != document.l3_render_fingerprint:
        raise ReviewBundleError("review-bundle-l3-render-fingerprint-mismatch")
    if report.report_fingerprint != independent_l3_report_fingerprint(report):
        raise ReviewBundleError("review-bundle-l3-report-fingerprint-mismatch")
    result: list[ReviewBundleCandidate] = []
    for candidate_id, candidate in docs.items():
        validation = reports[candidate_id]
        passed = validation.independent_verdict.value == "pass"
        text = candidate.candidate_text
        if passed:
            if candidate.status.value != "candidate" or not text:
                raise ReviewBundleError(
                    "review-bundle-l3-pass-text-binding-mismatch",
                )
        elif text is not None:
            raise ReviewBundleError(
                "review-bundle-l3-blocked-text-present",
            )
        result.append(ReviewBundleCandidate(
            candidate_id=candidate.candidate_id,
            source_layer="l3",
            category=candidate.category.value,
            target_kind=candidate.target.kind,
            target_name=candidate.target.name,
            status=candidate.status.value,
            independent_verdict=validation.independent_verdict.value,
            command_text=text if passed else None,
            command_text_included=bool(passed and text),
            blocking_reasons=_l3_candidate_reasons(candidate, validation),
            candidate_fingerprint=candidate.candidate_fingerprint,
            evidence_ids=tuple(dict.fromkeys(
                item.evidence_id for item in candidate.syntax_evidence
            )),
            risk_class=candidate.risk_class.value,
            requires_field_verification=(
                candidate.requires_field_verification
            ),
            secret_bearing=False,
        ))
    return tuple(result)


def _management_candidates(
    document: ManagementCandidateDocument,
    report: ManagementValidationReport,
) -> tuple[ReviewBundleCandidate, ...]:
    reports = {item.candidate_id: item for item in report.candidates}
    docs = {item.candidate_id: item for item in document.candidates}
    if len(reports) != len(report.candidates) or set(reports) != set(docs):
        raise ReviewBundleError("review-bundle-management-candidate-set-mismatch")
    if report.report_fingerprint != _management_report_fingerprint(report):
        raise ReviewBundleError(
            "review-bundle-management-report-fingerprint-mismatch",
        )
    result: list[ReviewBundleCandidate] = []
    for candidate_id, candidate in docs.items():
        validation = reports[candidate_id]
        passed = validation.independent_verdict == "pass"
        text = candidate.candidate_text
        if candidate.secret_bearing and text is not None:
            raise ReviewBundleError("review-bundle-management-secret-text-present")
        if passed:
            if candidate.status != "candidate" or not text:
                raise ReviewBundleError(
                    "review-bundle-management-pass-text-binding-mismatch",
                )
        elif text is not None:
            raise ReviewBundleError(
                "review-bundle-management-blocked-text-present",
            )
        result.append(ReviewBundleCandidate(
            candidate_id=candidate.candidate_id,
            source_layer="management",
            category=candidate.topic,
            target_kind="management-topic",
            target_name=candidate.target_name,
            status=candidate.status,
            independent_verdict=validation.independent_verdict,
            command_text=text if passed else None,
            command_text_included=bool(passed and text),
            blocking_reasons=_management_candidate_reasons(
                candidate, validation,
            ),
            candidate_fingerprint=candidate.candidate_fingerprint,
            evidence_ids=(candidate.evidence_id,) if candidate.evidence_id else (),
            risk_class=None,
            requires_field_verification=(
                candidate.requires_field_verification
            ),
            secret_bearing=candidate.secret_bearing,
        ))
    return tuple(result)


def _subsystem(
    *,
    layer: Literal["l2", "l3", "management"],
    contract_id: str,
    registry_id: str,
    registry_fingerprint: str,
    intent_fingerprint: str,
    document_fingerprint: str,
    validation_fingerprint: str,
    overall_status: str,
    summary: dict[str, object],
    candidates: tuple[ReviewBundleCandidate, ...],
    production_authorization: Literal["PENDING"] | None = None,
) -> ReviewBundleSubsystem:
    return ReviewBundleSubsystem(
        layer=layer,
        contract_id=contract_id,
        registry_id=registry_id,
        registry_fingerprint=registry_fingerprint,
        intent_fingerprint=intent_fingerprint,
        document_fingerprint=document_fingerprint,
        validation_fingerprint=validation_fingerprint,
        overall_status=overall_status,
        summary=summary,
        candidates=candidates,
        production_authorization=production_authorization,
    )


def _summary_dict(value: object) -> dict[str, object]:
    if hasattr(value, "model_dump"):
        return cast(dict[str, object], value.model_dump(mode="json"))
    return {}


def build_cisco_review_bundle(
    *,
    event_id: UUID,
    event_name: str,
    revision: PlanRevision,
    assignment_id: UUID,
    l2_document: L2CliCandidateDocument,
    l2_report: L2ValidationReport,
    l3_document: L3CandidateDocument,
    l3_report: L3ValidationReport,
    management_document: ManagementCandidateDocument,
    management_report: ManagementValidationReport,
    assembly: ConfigurationAssembly,
    generated_at: str | None = None,
) -> CiscoReviewBundle:
    """Build a deterministic-content review bundle from trusted server objects."""
    identity = ReviewBundleIdentity(
        event_id=event_id,
        event_name=event_name,
        revision_id=revision.id,
        revision_number=revision.number,
        revision_canonical_hash=revision.content_hash,
        assignment_id=assignment_id,
        hostname=l2_document.device.hostname,
        role=l3_document.device.role,
        family=l2_document.device.family or "",
        exact_pid=l2_document.device.exact_pid,
        software_image=l2_document.device.release,
        software_license=l2_document.device.license,
        stack_identity=l2_document.device.stack_identity,
    )
    if (
        l2_document.assignment_id != assignment_id
        or l2_report.assignment_id != assignment_id
        or l3_document.assignment_id != assignment_id
        or l3_report.assignment_id != assignment_id
        or management_document.assignment_id != assignment_id
        or management_report.assignment_id != assignment_id
        or assembly.identity.assignment_id != assignment_id
        or assembly.source.event_id != event_id
        or assembly.source.revision_id != revision.id
        or assembly.source.revision_canonical_hash != revision.content_hash
    ):
        raise ReviewBundleError("review-bundle-revision-assignment-binding-mismatch")
    if (
        l2_document.source.saved_revision_uuid != revision.id
        or l3_document.source.revision_uuid != revision.id
        or management_document.source.revision_uuid != revision.id
        or l2_report.source.saved_revision_uuid != revision.id
        or l3_report.expected_source.saved_revision_uuid != revision.id
        or management_report.source.revision_uuid != revision.id
    ):
        raise ReviewBundleError("review-bundle-revision-binding-mismatch")
    if (
        l2_document.source.revision_canonical_hash != revision.content_hash
        or l3_document.source.revision_hash != revision.content_hash
        or management_document.source.revision_hash != revision.content_hash
        or l2_report.source.revision_canonical_hash != revision.content_hash
        or l3_report.expected_source.revision_canonical_hash
        != revision.content_hash
        or management_report.source.revision_hash != revision.content_hash
    ):
        raise ReviewBundleError("review-bundle-revision-hash-mismatch")
    if not (
        l2_report.integrity.expected_source_match
        and l2_report.integrity.candidate_fingerprints_match
        and l2_report.integrity.status.value == "pass"
        and all(l3_report.integrity.model_dump().values())
        and all(management_report.integrity.values())
    ):
        raise ReviewBundleError("review-bundle-validation-integrity-failure")
    if (
        l2_document.source.command_evidence_registry_id
        != l2_report.source.command_evidence_registry_id
        or l2_document.source.command_evidence_fingerprint
        != l2_report.source.command_evidence_fingerprint
        or l3_document.source.command_evidence_registry_id
        != l3_report.expected_source.command_evidence_registry_id
        or l3_document.source.command_evidence_registry_fingerprint
        != l3_report.expected_source.command_evidence_registry_fingerprint
        or management_document.source.evidence_registry_id
        != management_report.source.evidence_registry_id
        or management_document.source.evidence_registry_fingerprint
        != management_report.source.evidence_registry_fingerprint
    ):
        raise ReviewBundleError("review-bundle-registry-binding-mismatch")
    if assembly.assembly_fingerprint != assembly_fingerprint(assembly):
        raise ReviewBundleError("review-bundle-assembly-fingerprint-mismatch")
    if (
        assembly.source.l2_render_fingerprint != l2_document.render_fingerprint
        or assembly.source.l2_validation_fingerprint
        != l2_report.report_fingerprint
        or assembly.source.l3_render_fingerprint
        != l3_document.l3_render_fingerprint
        or assembly.source.l3_validation_fingerprint
        != l3_report.report_fingerprint
        or assembly.source.l2_command_evidence_registry_id
        != l2_document.source.command_evidence_registry_id
        or assembly.source.l3_command_evidence_registry_id
        != l3_document.source.command_evidence_registry_id
    ):
        raise ReviewBundleError("review-bundle-assembly-binding-mismatch")

    # Recompute current object content before emitting any command text.  A
    # stale candidate/document/report fingerprint must never survive a text
    # change merely because an old integrity flag said True.
    _verify_l2_current_content(l2_document, l2_report)
    _verify_l3_current_content(l3_document, l3_report)
    _verify_management_current_content(management_document, management_report)

    l2_candidates = _l2_candidates(l2_document, l2_report)
    l3_candidates = _l3_candidates(l3_document, l3_report)
    management_candidates = _management_candidates(
        management_document, management_report,
    )

    l2 = _subsystem(
        layer="l2",
        contract_id=l2_document.contract_id,
        registry_id=l2_document.source.command_evidence_registry_id,
        registry_fingerprint=(
            l2_document.source.command_evidence_fingerprint
        ),
        intent_fingerprint=l2_document.source.intent_fingerprint,
        document_fingerprint=l2_document.render_fingerprint,
        validation_fingerprint=l2_report.report_fingerprint,
        overall_status=l2_report.summary.overall_status.value,
        summary=_summary_dict(l2_report.summary),
        candidates=l2_candidates,
    )
    l3 = _subsystem(
        layer="l3",
        contract_id=l3_document.contract_id,
        registry_id=l3_document.source.command_evidence_registry_id,
        registry_fingerprint=(
            l3_document.source.command_evidence_registry_fingerprint
        ),
        intent_fingerprint=l3_document.source.l3_intent_fingerprint,
        document_fingerprint=l3_document.l3_render_fingerprint,
        validation_fingerprint=l3_report.report_fingerprint,
        overall_status=l3_report.overall_status.value,
        summary=_summary_dict(l3_report.summary),
        candidates=l3_candidates,
    )
    management = _subsystem(
        layer="management",
        contract_id=management_document.contract_id,
        registry_id=management_document.source.evidence_registry_id,
        registry_fingerprint=(
            management_document.source.evidence_registry_fingerprint
        ),
        intent_fingerprint=(
            management_document.source.management_intent_fingerprint
        ),
        document_fingerprint=management_document.render_fingerprint,
        validation_fingerprint=management_report.report_fingerprint,
        overall_status=management_report.overall_status,
        summary=_summary_dict(management_report.summary),
        candidates=management_candidates,
        production_authorization="PENDING",
    )

    assembly_view = ReviewBundleAssembly(
        contract_id=assembly.contract_id,
        assembly_fingerprint=assembly.assembly_fingerprint,
        completeness=_summary_dict(assembly.completeness),
        sections=tuple(ReviewBundleSection(
            section_id=section.section_id,
            required=section.required,
            applicability=section.applicability.value,
            status=section.status.value,
            candidate_count=section.candidate_count,
            passed_count=section.passed_count,
            failed_count=section.failed_count,
            blocked_count=section.blocked_count,
            missing_count=section.missing_count,
            reason_codes=section.reason_codes,
        ) for section in assembly.sections),
        cross_layer_checks=tuple(ReviewBundleCrossCheck(
            check_id=check.check_id,
            status=check.status.value,
            reason_codes=check.reason_codes,
            detail=check.detail,
        ) for check in assembly.cross_layer_checks),
        safety=assembly.safety.model_dump(mode="json"),
    )
    source_fingerprints = ReviewBundleSourceFingerprints(
        l2_intent=l2_document.source.intent_fingerprint,
        l2_preview=l2_document.source.preview_fingerprint,
        l2_render=l2_document.render_fingerprint,
        l2_validation=l2_report.report_fingerprint,
        l3_intent=l3_document.source.l3_intent_fingerprint,
        l3_render=l3_document.l3_render_fingerprint,
        l3_validation=l3_report.report_fingerprint,
        management_intent=(
            management_document.source.management_intent_fingerprint
        ),
        management_render=management_document.render_fingerprint,
        management_validation=management_report.report_fingerprint,
        assembly=assembly.assembly_fingerprint,
    )
    content = ReviewBundleContent(
        identity=identity,
        l2=l2,
        l3=l3,
        management=management,
        assembly=assembly_view,
        source_fingerprints=source_fingerprints,
    )
    return CiscoReviewBundle(
        generated_at=generated_at or datetime.now(UTC).isoformat(timespec="seconds"),
        suggested_filename=review_bundle_filename(
            event_name, identity.hostname, revision.number, event_id,
        ),
        content_digest=review_bundle_content_digest(content),
        content=content,
    )


__all__ = [
    "CiscoReviewBundle",
    "REVIEW_BUNDLE_BANNER",
    "REVIEW_BUNDLE_CONTRACT_ID",
    "REVIEW_BUNDLE_LIMITATIONS",
    "REVIEW_BUNDLE_SCHEMA_VERSION",
    "ReviewBundleError",
    "build_cisco_review_bundle",
    "review_bundle_content_digest",
    "review_bundle_filename",
]
