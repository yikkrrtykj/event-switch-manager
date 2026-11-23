"""CIS-04 read-only Device Configuration Assembly API.

The client supplies only the three UUID path identifiers.  The Event, Saved
Revision, L2/L3 intents, previews, candidate documents, production Evidence
Registries, independent validation reports and the final assembly are rebuilt
from trusted server-side objects.

The route returns a structured review document only after both the L2 and L3
source/integrity gates pass.  It never accepts a Registry, candidate, verdict,
fingerprint or device identity from the client, and it exposes no executable
configuration sequence, deployment artifact or device connection.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import ValidationError
from sqlalchemy.orm import Session

from .api import DatabaseSession, find_event
from .plan_api import revision_and_baseline
from .planning.config_assembly import (
    ASSEMBLY_CONTRACT_ID,
    AssemblyInputError,
    ConfigurationAssembly,
    build_config_assembly,
)
from .planning.layer2_cli_candidates import (
    L2CliCandidateDocument,
    build_l2_cli_candidates,
)
from .planning.layer2_cli_candidates import (
    RenderBindingError as L2RenderBindingError,
)
from .planning.layer2_cli_validation import (
    ExpectedSource as L2ExpectedSource,
)
from .planning.layer2_cli_validation import (
    ValidationReport as L2ValidationReport,
)
from .planning.layer2_cli_validation import (
    Verdict as L2Verdict,
)
from .planning.layer2_cli_validation import (
    validate_candidate_document as validate_l2_candidate_document,
)
from .planning.layer2_config_preview import (
    Layer2DeviceConfigPreview,
    PreviewInputError,
    PreviewTargetNotFound,
    build_device_layer2_config_preview,
)
from .planning.layer2_intent import Layer2Intent, build_layer2_intent
from .planning.layer3_cli_candidates import (
    L3CandidateDocument,
    build_l3_cli_candidates,
)
from .planning.layer3_cli_candidates import (
    RenderBindingError as L3RenderBindingError,
)
from .planning.layer3_cli_candidates import (
    RenderTargetNotFound as L3RenderTargetNotFound,
)
from .planning.layer3_cli_validation import (
    ExpectedSource as L3ExpectedSource,
)
from .planning.layer3_cli_validation import (
    L3ValidationReport,
    ValidationIntegrityError,
    independent_report_fingerprint,
    validate_l3_candidates,
)
from .planning.layer3_intent import Layer3Intent, build_layer3_intent
from .planning.layer3_registry_selection import select_l3_registry
from .planning.plan import PlanRevision, canonical_plan, plan_hash

router = APIRouter(prefix="/api/v1/events/{event_id}")

ASSEMBLY_SCOPE_HEADER = "X-Config-Assembly-Scope"
_FULL_SCOPE = "full"
_EVENT_NOT_FOUND_DETAIL = "Event not found"
_REVISION_NOT_FOUND_DETAIL = "Plan revision not found"
_REFUSED_HEADERS = ("if-match", "if-none-match")
_L2_EXPECTED_FIELDS = (
    "saved_revision_uuid",
    "revision_number",
    "revision_canonical_hash",
    "intent_fingerprint",
    "preview_fingerprint",
    "render_fingerprint",
    "assignment_id",
)
_L3_EXPECTED_FIELDS = (
    "event_id",
    "saved_revision_uuid",
    "revision_number",
    "revision_canonical_hash",
    "l3_intent_schema_version",
    "l3_intent_fingerprint",
    "l3_render_contract_id",
    "l3_render_contract_version",
    "l3_render_fingerprint",
    "command_evidence_registry_id",
    "command_evidence_registry_fingerprint",
    "assignment_id",
)


def _error(
    status_code: int, *, reason_code: str, stage: str, **extra: object,
) -> HTTPException:
    detail: dict[str, object] = {"reason_code": reason_code, "stage": stage}
    detail.update(extra)
    return HTTPException(status_code=status_code, detail=detail)


def _not_found(reason_code: str, stage: str) -> HTTPException:
    return _error(404, reason_code=reason_code, stage=stage)


def _conflict(
    reason_code: str, stage: str, **extra: object,
) -> HTTPException:
    return _error(409, reason_code=reason_code, stage=stage, **extra)


def _reject_undeclared(request: Request, body: bytes) -> None:
    fields = sorted(request.query_params.keys())
    fields.extend(name for name in _REFUSED_HEADERS if name in request.headers)
    if body:
        fields.append("request-body")
    if fields:
        raise HTTPException(
            status_code=400,
            detail={"reason_code": "undeclared-input", "fields": fields},
        )


def _require_event(session: Session, event_id: UUID) -> None:
    try:
        find_event(session, event_id)
    except HTTPException as exc:
        if exc.status_code == 404 and exc.detail == _EVENT_NOT_FOUND_DETAIL:
            raise _not_found("event-not-found", "event") from None
        raise


def _load_revisions(
    session: Session, event_id: UUID, revision_id: UUID,
) -> tuple[PlanRevision, PlanRevision | None]:
    try:
        revision, baseline = revision_and_baseline(event_id, revision_id, session)
    except HTTPException as exc:
        if exc.status_code == 404 and exc.detail == _REVISION_NOT_FOUND_DETAIL:
            raise _not_found("saved-revision-not-found", "revision") from None
        raise
    except ValidationError:
        raise _conflict("revision-document-invalid", "revision") from None
    return revision, baseline


def _verify_revision(revision: PlanRevision, event_id: UUID, stage: str) -> None:
    if plan_hash(canonical_plan(revision.plan)) != revision.content_hash:
        raise _conflict("revision-canonical-hash-mismatch", stage)
    if revision.plan.event_id != event_id:
        raise _conflict("revision-event-mismatch", stage)


def _build_l2(
    revision: PlanRevision,
    baseline: PlanRevision | None,
    assignment_id: UUID,
) -> tuple[
    Layer2Intent,
    Layer2DeviceConfigPreview,
    L2CliCandidateDocument,
    L2ValidationReport,
]:
    try:
        intent = build_layer2_intent(revision, baseline)
    except ValidationError:
        raise _conflict("layer2-intent-build-failed", "intent") from None
    try:
        preview = build_device_layer2_config_preview(
            revision, intent, assignment_id,
        )
    except PreviewInputError as exc:
        raise _conflict(exc.reason_code, "intent") from None
    except PreviewTargetNotFound:
        raise _not_found("assignment-not-found", "preview") from None
    try:
        document = build_l2_cli_candidates(revision, intent, preview)
    except L2RenderBindingError as exc:
        raise _conflict(exc.reason_code, "renderer") from None
    expected = L2ExpectedSource(
        saved_revision_uuid=revision.id,
        revision_number=revision.number,
        revision_canonical_hash=revision.content_hash,
        intent_fingerprint=intent.intent_fingerprint,
        preview_fingerprint=preview.preview_fingerprint,
        render_fingerprint=document.render_fingerprint,
        assignment_id=assignment_id,
    )
    if any(
        getattr(expected, name) is None for name in _L2_EXPECTED_FIELDS
    ):
        raise _conflict("l2-expected-source-incomplete", "validation")
    report = validate_l2_candidate_document(document, expected=expected)
    if (
        report.integrity.status is not L2Verdict.PASS
        or not report.integrity.expected_source_match
    ):
        raise _conflict(
            "l2-validation-integrity-failure", "validation",
            failures=list(report.integrity.failures),
        )
    return intent, preview, document, report


def _build_l3(
    revision: PlanRevision,
    baseline: PlanRevision | None,
    assignment_id: UUID,
) -> tuple[Layer3Intent, L3CandidateDocument, L3ValidationReport]:
    try:
        intent = build_layer3_intent(revision, baseline)
    except ValidationError:
        raise _conflict("layer3-intent-build-failed", "intent") from None
    device = next(
        (item for item in intent.devices
         if item.identity.assignment_id == assignment_id),
        None,
    )
    if device is None:
        raise _not_found("assignment-not-found", "intent")
    selection = select_l3_registry(device.identity)
    try:
        document = build_l3_cli_candidates(
            revision, intent, assignment_id, selection.registry,
            baseline=baseline,
        )
    except L3RenderBindingError as exc:
        raise _conflict(exc.reason_code, "renderer") from None
    except L3RenderTargetNotFound:
        raise _not_found("assignment-not-found", "renderer") from None
    expected = L3ExpectedSource(
        event_id=revision.plan.event_id,
        saved_revision_uuid=revision.id,
        revision_number=revision.number,
        revision_canonical_hash=revision.content_hash,
        l3_intent_schema_version=intent.l3_intent_schema_version,
        l3_intent_fingerprint=intent.intent_fingerprint,
        l3_render_contract_id=document.contract_id,
        l3_render_contract_version=document.l3_render_schema_version,
        l3_render_fingerprint=document.l3_render_fingerprint,
        command_evidence_registry_id=selection.registry.registry_id,
        command_evidence_registry_fingerprint=selection.registry.fingerprint,
        assignment_id=assignment_id,
        baseline_revision_uuid=intent.baseline.revision_id,
        baseline_revision_hash=intent.baseline.revision_hash,
    )
    if any(getattr(expected, name) is None for name in _L3_EXPECTED_FIELDS):
        raise _conflict("l3-expected-source-incomplete", "validation")
    try:
        report = validate_l3_candidates(
            revision, intent, document, expected, assignment_id,
            selection.registry, baseline=baseline,
        )
    except ValidationIntegrityError as exc:
        raise _conflict(
            "l3-validation-integrity-failure", "validation",
            failures=[exc.reason_code, *exc.reasons],
        ) from None
    if (
        report.expected_source != expected
        or report.source.assignment_id != assignment_id
        or report.report_fingerprint != independent_report_fingerprint(report)
    ):
        raise _conflict("l3-validation-integrity-failure", "validation")
    if not all((
        report.integrity.revision_canonical_hash,
        report.integrity.baseline_canonical_hash,
        report.integrity.intent_rebuilt,
        report.integrity.intent_fingerprint,
        report.integrity.expected_source,
        report.integrity.document_source,
        report.integrity.document_fingerprint,
        report.integrity.candidate_fingerprints,
        report.integrity.candidate_ids_unique,
        report.integrity.candidate_set,
        report.integrity.summary,
        report.integrity.safety,
    )):
        raise _conflict("l3-validation-integrity-failure", "validation")
    return intent, document, report


def _require_cisco_assignment(
    revision: PlanRevision, assignment_id: UUID,
) -> None:
    assignment = next(
        (item for item in revision.plan.assignments
         if item.id == assignment_id),
        None,
    )
    if assignment is None:
        raise _not_found("assignment-not-found", "assignment")
    device = next(
        (item for item in revision.plan.physical_devices
         if item.id == assignment.physical_device_id),
        None,
    )
    if device is None or device.vendor != "cisco":
        raise _conflict(
            "assignment-is-not-cisco", "assignment",
        )


@router.get(
    "/plan-revisions/{revision_id}/assignments/{assignment_id}"
    "/config-assembly-preview",
    response_model=ConfigurationAssembly,
)
async def read_config_assembly_preview(
    event_id: UUID,
    revision_id: UUID,
    assignment_id: UUID,
    request: Request,
    response: Response,
    session: DatabaseSession,
) -> ConfigurationAssembly:
    """Return one read-only device configuration assembly, or fail closed."""
    _reject_undeclared(request, await request.body())
    _require_event(session, event_id)
    revision, baseline = _load_revisions(session, event_id, revision_id)
    _verify_revision(revision, event_id, "revision")
    if baseline is not None:
        _verify_revision(baseline, event_id, "baseline")
    _require_cisco_assignment(revision, assignment_id)
    l2_intent, l2_preview, l2_document, l2_report = _build_l2(
        revision, baseline, assignment_id,
    )
    l3_intent, l3_document, l3_report = _build_l3(
        revision, baseline, assignment_id,
    )
    try:
        assembly = build_config_assembly(
            revision, l2_intent, l2_preview, l2_document, l2_report,
            l3_intent, l3_document, l3_report, assignment_id,
        )
    except AssemblyInputError as exc:
        raise _conflict(exc.reason_code, "assembly") from None
    if assembly.contract_id != ASSEMBLY_CONTRACT_ID:
        raise _conflict("assembly-contract-mismatch", "assembly")
    response.headers[ASSEMBLY_SCOPE_HEADER] = _FULL_SCOPE
    return assembly


__all__ = [
    "ASSEMBLY_SCOPE_HEADER",
    "read_config_assembly_preview",
    "router",
]
