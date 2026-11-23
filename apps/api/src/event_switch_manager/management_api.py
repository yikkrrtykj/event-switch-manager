"""CIS-04B read-only management intent and candidate validation API.

The client supplies only the Event/Revision/Assignment UUID path identifiers.
The management intent, PENDING evidence registry, candidates and validation
report are rebuilt from trusted database and frozen objects. No secret is
accepted or returned, no device is contacted and no configuration is written.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import ValidationError
from sqlalchemy.orm import Session

from .api import DatabaseSession, find_event
from .plan_api import revision_and_baseline
from .planning.layer2_intent import build_layer2_intent
from .planning.management_cli_candidates import (
    MANAGEMENT_RENDER_CONTRACT_ID,
    MANAGEMENT_VALIDATION_CONTRACT_ID,
    ManagementCandidateDocument,
    ManagementRenderError,
    ManagementValidationReport,
    build_management_cli_candidates,
    validate_management_candidates,
)
from .planning.management_command_evidence import (
    MANAGEMENT_EVIDENCE_DRAFT_REGISTRY,
)
from .planning.management_intent import (
    ManagementInputError,
    ManagementIntent,
    build_management_intent,
)
from .planning.plan import PlanRevision, canonical_plan, plan_hash

router = APIRouter(prefix="/api/v1/events/{event_id}")

MANAGEMENT_SCOPE_HEADER = "X-Management-Scope"
_FULL_SCOPE = "full"
_EVENT_NOT_FOUND_DETAIL = "Event not found"
_REVISION_NOT_FOUND_DETAIL = "Plan revision not found"
_REFUSED_HEADERS = ("if-match", "if-none-match")


def _error(status_code: int, *, reason_code: str, stage: str,
           **extra: object) -> HTTPException:
    detail: dict[str, object] = {"reason_code": reason_code, "stage": stage}
    detail.update(extra)
    return HTTPException(status_code=status_code, detail=detail)


def _not_found(reason_code: str, stage: str) -> HTTPException:
    return _error(404, reason_code=reason_code, stage=stage)


def _conflict(reason_code: str, stage: str, **extra: object) -> HTTPException:
    return _error(409, reason_code=reason_code, stage=stage, **extra)


def _reject_undeclared(request: Request) -> None:
    fields = sorted(request.query_params.keys())
    fields.extend(name for name in _REFUSED_HEADERS if name in request.headers)
    content_length = request.headers.get("content-length")
    if content_length not in (None, "0"):
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


def _build(request_revision: PlanRevision, baseline: PlanRevision | None,
           assignment_id: UUID) -> tuple[
               ManagementIntent, ManagementCandidateDocument,
               ManagementValidationReport,
           ]:
    revision = request_revision
    assignment = next(
        (item for item in revision.plan.assignments if item.id == assignment_id),
        None,
    )
    if assignment is None:
        raise _not_found("assignment-not-found", "assignment")
    if assignment.family is None or assignment.family.value not in {
        "catalyst-9300", "catalyst-9200",
    }:
        raise _conflict("platform-not-supported-for-management", "assignment")
    try:
        l2_intent = build_layer2_intent(revision, baseline)
        intent = build_management_intent(
            revision, l2_intent, assignment_id,
        )
    except ManagementInputError as exc:
        raise _conflict(exc.reason_code, "intent") from None
    except ValidationError:
        raise _conflict("management-intent-build-failed", "intent") from None
    try:
        document = build_management_cli_candidates(
            revision, intent, MANAGEMENT_EVIDENCE_DRAFT_REGISTRY,
        )
    except (ManagementRenderError, ValueError) as exc:
        reason = getattr(exc, "reason_code", str(exc))
        raise _conflict(reason, "candidate") from None
    try:
        report = validate_management_candidates(
            revision, intent, document, MANAGEMENT_EVIDENCE_DRAFT_REGISTRY,
        )
    except (ManagementRenderError, ValueError) as exc:
        reason = getattr(exc, "reason_code", str(exc))
        raise _conflict(reason, "validation") from None
    if not all(report.integrity.values()):
        raise _conflict("management-validation-integrity-failure", "validation")
    if report.overall_status == "fail":
        raise _conflict("management-candidate-validation-failed", "validation")
    if document.contract_id != MANAGEMENT_RENDER_CONTRACT_ID:
        raise _conflict("management-render-contract-mismatch", "candidate")
    if report.validation_contract_id != MANAGEMENT_VALIDATION_CONTRACT_ID:
        raise _conflict("management-validation-contract-mismatch", "validation")
    if any(item.secret_text_present for item in report.candidates):
        raise _conflict("management-secret-text-present", "validation")
    return intent, document, report


def _load(
    session: Session, event_id: UUID, revision_id: UUID, assignment_id: UUID,
) -> tuple[
    ManagementIntent, ManagementCandidateDocument, ManagementValidationReport,
]:
    _require_event(session, event_id)
    revision, baseline = _load_revisions(session, event_id, revision_id)
    _verify_revision(revision, event_id, "revision")
    if baseline is not None:
        _verify_revision(baseline, event_id, "baseline")
    return _build(revision, baseline, assignment_id)


@router.get(
    "/plan-revisions/{revision_id}/assignments/{assignment_id}/management-intent",
    response_model=ManagementIntent,
)
async def read_management_intent(
    event_id: UUID, revision_id: UUID, assignment_id: UUID,
    request: Request, response: Response, session: DatabaseSession,
) -> ManagementIntent:
    _reject_undeclared(request)
    intent, _document, _report = _load(
        session, event_id, revision_id, assignment_id,
    )
    response.headers[MANAGEMENT_SCOPE_HEADER] = _FULL_SCOPE
    return intent


@router.get(
    "/plan-revisions/{revision_id}/assignments/{assignment_id}"
    "/management-cli-candidates",
    response_model=ManagementCandidateDocument,
)
async def read_management_cli_candidates(
    event_id: UUID, revision_id: UUID, assignment_id: UUID,
    request: Request, response: Response, session: DatabaseSession,
) -> ManagementCandidateDocument:
    _reject_undeclared(request)
    _intent, document, _report = _load(
        session, event_id, revision_id, assignment_id,
    )
    response.headers[MANAGEMENT_SCOPE_HEADER] = _FULL_SCOPE
    return document


@router.get(
    "/plan-revisions/{revision_id}/assignments/{assignment_id}"
    "/management-cli-validation",
    response_model=ManagementValidationReport,
)
async def read_management_cli_validation(
    event_id: UUID, revision_id: UUID, assignment_id: UUID,
    request: Request, response: Response, session: DatabaseSession,
) -> ManagementValidationReport:
    _reject_undeclared(request)
    _intent, _document, report = _load(
        session, event_id, revision_id, assignment_id,
    )
    response.headers[MANAGEMENT_SCOPE_HEADER] = _FULL_SCOPE
    return report


__all__ = [
    "MANAGEMENT_SCOPE_HEADER",
    "read_management_cli_candidates",
    "read_management_cli_validation",
    "read_management_intent",
    "router",
]
