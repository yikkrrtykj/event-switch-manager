"""CIS-03-03C read-only L3 candidate and validation API.

Both routes use one server-side trust pipeline.  The client supplies only the
three UUID path identifiers; the Event, Saved Revision, baseline, Layer3Intent,
Candidate Document, production Evidence Registry and ExpectedSource are all
rebuilt from trusted database and frozen production objects.

The Candidate route returns a document only after the complete independent
validation has succeeded (no candidate FAIL).  The Validation route returns the
frozen ``L3ValidationReport``; an integrity-gate failure is a 409 and never a
trusted report.  Neither route reads a device, connects to one, or exposes a
deployment artefact.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from .api import DatabaseSession, find_event
from .domain import DeviceRole
from .plan_api import revision_and_baseline
from .planning import layer3_cli_candidates as _candidate_models
from .planning import layer3_cli_validation as _validation_models
from .planning.layer3_cli_candidates import (
    CandidateStatus,
    L3CandidateDocument,
    RenderBindingError,
    RenderTargetNotFound,
    build_l3_cli_candidates,
)
from .planning.layer3_cli_validation import (
    ExpectedSource,
    IndependentVerdict,
    L3ValidationReport,
    ValidationIntegrityError,
    independent_candidate_fingerprint,
    independent_render_fingerprint,
    independent_report_fingerprint,
    validate_l3_candidates,
)
from .planning.layer3_command_evidence import DEFAULT_REGISTRY
from .planning.layer3_intent import L3DeviceIntent, Layer3Intent, build_layer3_intent
from .planning.plan import PlanRevision, canonical_plan, plan_hash


def _isolate_openapi_component_names() -> None:
    """Keep L2 and L3 schemas in separate OpenAPI component namespaces.

    Several frozen L3 response model class names intentionally match existing
    L2 validation model names (for example ``ValidationSafety``). FastAPI's
    schema generator uses Python class names as component keys; when both
    documents are exposed by one app it otherwise renames the *L2* components
    and breaks the frozen L2 OpenAPI contract. Prefix only the L3 component
    classes, leaving the two L3 response roots unchanged. Model fields,
    validation and wire payloads are untouched.
    """
    response_roots = {"L3CandidateDocument", "L3ValidationReport"}
    modules = (_candidate_models, _validation_models)
    for module in modules:
        for item in tuple(vars(module).values()):
            if not isinstance(item, type):
                continue
            if item.__module__ != module.__name__:
                continue
            if item.__name__ in response_roots:
                continue
            prefixed = f"L3Cli{item.__name__}"
            item.__name__ = prefixed
            item.__qualname__ = prefixed
    for module in modules:
        for item in tuple(vars(module).values()):
            if (
                isinstance(item, type)
                and item.__module__ == module.__name__
                and issubclass(item, BaseModel)
            ):
                item.model_rebuild(force=True)


_isolate_openapi_component_names()

router = APIRouter(prefix="/api/v1/events/{event_id}")

VALIDATION_SCOPE_HEADER = "X-Validation-Scope"
_FULL_SCOPE = "full"
_EVENT_NOT_FOUND_DETAIL = "Event not found"
_REVISION_NOT_FOUND_DETAIL = "Plan revision not found"
_REFUSED_HEADERS = ("if-match", "if-none-match")


def _error(
    status_code: int,
    *,
    reason_code: str,
    stage: str,
    **extra: object,
) -> HTTPException:
    detail: dict[str, object] = {"reason_code": reason_code, "stage": stage}
    detail.update(extra)
    return HTTPException(status_code=status_code, detail=detail)


def _not_found(reason_code: str, stage: str) -> HTTPException:
    return _error(404, reason_code=reason_code, stage=stage)


def _conflict(
    reason_code: str,
    stage: str,
    **extra: object,
) -> HTTPException:
    return _error(409, reason_code=reason_code, stage=stage, **extra)


def _reject_undeclared(request: Request, body: bytes) -> None:
    fields = sorted(request.query_params.keys())
    fields.extend(
        name for name in _REFUSED_HEADERS if name in request.headers
    )
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
    session: Session,
    event_id: UUID,
    revision_id: UUID,
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


def _rebuild_intent(
    revision: PlanRevision,
    baseline: PlanRevision | None,
) -> Layer3Intent:
    try:
        return build_layer3_intent(revision, baseline)
    except ValidationError:
        raise _conflict("layer3-intent-build-failed", "intent") from None


def _eligible_device(
    intent: Layer3Intent,
    assignment_id: UUID,
) -> L3DeviceIntent:
    device = next(
        (
            item for item in intent.devices
            if item.identity.assignment_id == assignment_id
        ),
        None,
    )
    if device is None:
        raise _not_found("assignment-not-found", "assignment")
    identity = device.identity
    if identity.role is not DeviceRole.CORE or identity.vendor != "cisco":
        raise _conflict(
            "assignment-not-eligible-for-l3-cli", "assignment",
        )
    return device


def _build_document(
    revision: PlanRevision,
    intent: Layer3Intent,
    baseline: PlanRevision | None,
    assignment_id: UUID,
) -> L3CandidateDocument:
    try:
        return build_l3_cli_candidates(
            revision,
            intent,
            assignment_id,
            DEFAULT_REGISTRY,
            baseline=baseline,
        )
    except RenderBindingError as exc:
        raise _conflict(
            "renderer-binding-failure",
            "renderer",
            failures=[exc.reason_code],
        ) from None
    except RenderTargetNotFound:
        raise _not_found("assignment-not-found", "renderer") from None


def _expected_source(
    revision: PlanRevision,
    intent: Layer3Intent,
    document: L3CandidateDocument,
    assignment_id: UUID,
) -> ExpectedSource:
    return ExpectedSource(
        event_id=revision.plan.event_id,
        saved_revision_uuid=revision.id,
        revision_number=revision.number,
        revision_canonical_hash=revision.content_hash,
        l3_intent_schema_version=intent.l3_intent_schema_version,
        l3_intent_fingerprint=intent.intent_fingerprint,
        l3_render_contract_id=document.contract_id,
        l3_render_contract_version=document.l3_render_schema_version,
        l3_render_fingerprint=document.l3_render_fingerprint,
        command_evidence_registry_id=DEFAULT_REGISTRY.registry_id,
        command_evidence_registry_fingerprint=DEFAULT_REGISTRY.fingerprint,
        assignment_id=assignment_id,
        baseline_revision_uuid=intent.baseline.revision_id,
        baseline_revision_hash=intent.baseline.revision_hash,
    )


def _validate(
    revision: PlanRevision,
    intent: Layer3Intent,
    document: L3CandidateDocument,
    expected: ExpectedSource,
    baseline: PlanRevision | None,
    assignment_id: UUID,
) -> L3ValidationReport:
    try:
        report = validate_l3_candidates(
            revision,
            intent,
            document,
            expected,
            assignment_id,
            baseline=baseline,
        )
    except ValidationIntegrityError as exc:
        failures = [exc.reason_code, *exc.reasons]
        raise _conflict(
            "validation-integrity-failure",
            "validation",
            failures=failures,
        ) from None
    _require_report_integrity(report, expected, document, revision, assignment_id)
    return report


def _require_report_integrity(
    report: L3ValidationReport,
    expected: ExpectedSource,
    document: L3CandidateDocument,
    revision: PlanRevision,
    assignment_id: UUID,
) -> None:
    problems: list[str] = []
    if report.validation_scope != "production":
        problems.append("validation-scope-not-production")
    if report.expected_source != expected:
        problems.append("expected-source-mismatch")
    if report.assignment_id != assignment_id:
        problems.append("assignment-mismatch")
    expected_source_values = expected.model_dump(mode="json")
    actual_source_values = report.source.model_dump(mode="json")
    for field_name, expected_value in expected_source_values.items():
        if actual_source_values.get(field_name) != expected_value:
            problems.append(
                f"source-{field_name.replace('_', '-')}-mismatch",
            )
    if not all(
        field_name in expected_source_values
        for field_name in actual_source_values
    ):
        problems.append("source-unknown-field")
    if not all(
        field_name in actual_source_values
        for field_name in expected_source_values
    ):
        problems.append("source-missing-field")
    integrity_values = (
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
    )
    if not all(integrity_values):
        problems.append("integrity-flag-false")
    if report.report_fingerprint != independent_report_fingerprint(report):
        problems.append("report-fingerprint-mismatch")
    if document.l3_render_fingerprint != independent_render_fingerprint(document):
        problems.append("document-fingerprint-mismatch")
    for candidate in document.candidates:
        if candidate.candidate_fingerprint != independent_candidate_fingerprint(candidate):
            problems.append("candidate-fingerprint-mismatch")
            break
    if report.safety.candidate_only is not True:
        problems.append("safety-candidate-only")
    if report.safety.executable is not False:
        problems.append("safety-executable")
    if report.safety.deployable is not False:
        problems.append("safety-deployable")
    if report.safety.deployment_allowed is not False:
        problems.append("safety-deployment-allowed")
    if report.safety.hardware_verified is not False:
        problems.append("safety-hardware-verified")
    if report.safety.device_connection != "none":
        problems.append("safety-device-connection")
    if report.safety.running_config_read is not False:
        problems.append("safety-running-config-read")
    if report.safety.device_writes_enabled is not False:
        problems.append("safety-device-writes")
    if report.safety.cli is not None:
        problems.append("safety-cli")
    if report.safety.deployment_artifact is not None:
        problems.append("safety-deployment-artifact")
    if problems:
        raise _conflict(
            "validation-integrity-failure",
            "validation",
            failures=sorted(set(problems)),
        )
    document_ids = [item.candidate_id for item in document.candidates]
    report_ids = [item.candidate_id for item in report.candidates]
    if document_ids != report_ids:
        raise _conflict(
            "validation-integrity-failure",
            "validation",
            failures=["candidate-set-mismatch"],
        )


def _candidate_document_allowed(
    document: L3CandidateDocument,
    report: L3ValidationReport,
) -> None:
    if document.summary.total == 0:
        raise _conflict(
            "candidate-document-not-reviewable",
            "candidate",
            failures=["empty-candidate-document"],
        )
    by_id = {item.candidate_id: item for item in report.candidates}
    if len(by_id) != len(report.candidates):
        raise _conflict(
            "candidate-document-not-reviewable",
            "candidate",
            failures=["duplicate-report-candidate"],
        )
    for candidate in document.candidates:
        validation = by_id.get(candidate.candidate_id)
        if validation is None:
            raise _conflict(
                "candidate-document-not-reviewable",
                "candidate",
                failures=["candidate-not-in-report"],
            )
        if validation.independent_verdict is IndependentVerdict.FAIL:
            raise _conflict(
                "candidate-document-not-reviewable",
                "candidate",
                failures=[f"candidate-failed:{candidate.candidate_id}"],
            )
        if candidate.status is CandidateStatus.CANDIDATE:
            if (
                validation.independent_verdict is not IndependentVerdict.PASS
                or candidate.candidate_text is None
            ):
                raise _conflict(
                    "candidate-document-not-reviewable",
                    "candidate",
                    failures=["candidate-text-not-validated"],
                )
        elif candidate.candidate_text is not None:
            raise _conflict(
                "candidate-document-not-reviewable",
                "candidate",
                failures=["blocked-candidate-has-text"],
            )


async def _trusted_response(
    event_id: UUID,
    revision_id: UUID,
    assignment_id: UUID,
    request: Request,
    session: Session,
) -> tuple[L3CandidateDocument, L3ValidationReport]:
    _reject_undeclared(request, await request.body())
    _require_event(session, event_id)
    revision, baseline = _load_revisions(session, event_id, revision_id)
    _verify_revision(revision, event_id, "revision")
    if baseline is not None:
        _verify_revision(baseline, event_id, "baseline")
    intent = _rebuild_intent(revision, baseline)
    _eligible_device(intent, assignment_id)
    document = _build_document(revision, intent, baseline, assignment_id)
    if document.summary.total == 0:
        raise _conflict(
            "candidate-document-not-reviewable",
            "candidate",
            failures=["empty-candidate-document"],
        )
    expected = _expected_source(revision, intent, document, assignment_id)
    report = _validate(
        revision, intent, document, expected, baseline, assignment_id,
    )
    return document, report


@router.get(
    "/plan-revisions/{revision_id}/assignments/{assignment_id}/l3-cli-candidates",
    response_model=L3CandidateDocument,
)
async def read_l3_cli_candidates(
    event_id: UUID,
    revision_id: UUID,
    assignment_id: UUID,
    request: Request,
    session: DatabaseSession,
) -> L3CandidateDocument:
    """Return the complete reviewed candidate document, or fail closed."""
    document, report = await _trusted_response(
        event_id, revision_id, assignment_id, request, session,
    )
    _candidate_document_allowed(document, report)
    return document


@router.get(
    "/plan-revisions/{revision_id}/assignments/{assignment_id}/l3-cli-validation",
    response_model=L3ValidationReport,
)
async def read_l3_cli_validation(
    event_id: UUID,
    revision_id: UUID,
    assignment_id: UUID,
    request: Request,
    response: Response,
    session: DatabaseSession,
) -> L3ValidationReport:
    """Return the complete independent validation report."""
    _document, report = await _trusted_response(
        event_id, revision_id, assignment_id, request, session,
    )
    response.headers[VALIDATION_SCOPE_HEADER] = _FULL_SCOPE
    return report


__all__ = [
    "VALIDATION_SCOPE_HEADER",
    "read_l3_cli_candidates",
    "read_l3_cli_validation",
    "router",
]
