"""CIS-02B2-03 R19 public read-only validation API.

Exposes the frozen independent validation report for exactly one Assignment of
one saved plan revision. The client supplies only the three path identifiers and
an optional repeated ``category`` filter. The server then:

1. rejects every undeclared query parameter, body and conditional-request header;
2. resolves the Event and the saved Revision (with its planning baseline);
3. re-verifies the saved revision canonical hash and Event binding;
4. rebuilds the CIS-02A Intent, the CIS-02B1 device preview and the frozen
   CIS-02B2 Candidate Document from the database;
5. constructs the complete seven-field :class:`ExpectedSource` from those
   trusted objects, and
6. runs the frozen independent validator behind an integrity gate before any
   report is returned.

The route is read-only: it opens no device connection, executes no
configuration, writes no row and exposes no candidate command text, execution
order or deployment authorisation. ``ExpectedSource`` is never accepted from the
client, and no client-supplied hash or fingerprint is used as a trust anchor.
"""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import ValidationError
from sqlalchemy.orm import Session

from .api import DatabaseSession, find_event
from .plan_api import reject_undeclared_input, revision_and_baseline
from .planning.layer2_cli_candidates import (
    CandidateCategory,
    L2CliCandidateDocument,
    RenderBindingError,
    RenderTargetNotFound,
    build_l2_cli_candidates,
)
from .planning.layer2_cli_validation import (
    ExpectedSource,
    ValidationReport,
    Verdict,
    validate_candidate_document,
)
from .planning.layer2_config_preview import (
    Layer2DeviceConfigPreview,
    PreviewInputError,
    PreviewTargetNotFound,
    build_device_layer2_config_preview,
)
from .planning.layer2_intent import Layer2Intent, build_layer2_intent
from .planning.plan import PlanRevision, canonical_plan, plan_hash

router = APIRouter(prefix="/api/v1/events/{event_id}")

#: Read-only scope marker for the response. It states which document the
#: response evaluated; it is not a signature or a trust proof.
VALIDATION_SCOPE_HEADER = "X-Validation-Scope"

#: Frozen legacy 404 payloads raised by ``api.find_event`` and
#: ``plan_api.require_revision``. The public validation API must not leak that
#: legacy bare-string error shape, so it converts exactly these payloads.
_EVENT_NOT_FOUND_DETAIL = "Event not found"
_REVISION_NOT_FOUND_DETAIL = "Plan revision not found"

#: Every field of ``ExpectedSource`` that must be bound before a report can be
#: trusted. The dataclass itself allows ``None``; the public route does not.
_EXPECTED_SOURCE_FIELDS: tuple[str, ...] = (
    "saved_revision_uuid",
    "revision_number",
    "revision_canonical_hash",
    "intent_fingerprint",
    "preview_fingerprint",
    "render_fingerprint",
    "assignment_id",
)


def _error(
    status_code: int, *, reason_code: str, stage: str, **extra: object,
) -> HTTPException:
    """Build the structured error envelope of this read-only contract."""
    detail: dict[str, object] = {"reason_code": reason_code, "stage": stage}
    detail.update(extra)
    return HTTPException(status_code=status_code, detail=detail)


def _not_found(reason_code: str, stage: str) -> HTTPException:
    return _error(404, reason_code=reason_code, stage=stage)


def _conflict(reason_code: str, stage: str, **extra: object) -> HTTPException:
    return _error(409, reason_code=reason_code, stage=stage, **extra)


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


def _verify_saved_revision(
    revision: PlanRevision,
    event_id: UUID,
    revision_scope: Literal["requested", "baseline"],
) -> None:
    """Re-verify the stored canonical hash and the Event binding."""
    if plan_hash(canonical_plan(revision.plan)) != revision.content_hash:
        raise _conflict(
            "revision-canonical-hash-mismatch",
            "revision",
            revision_scope=revision_scope,
        )
    if revision.plan.event_id != event_id:
        raise _conflict(
            "revision-event-mismatch", "revision", revision_scope=revision_scope,
        )


def _rebuild_intent(
    revision: PlanRevision, baseline: PlanRevision | None,
) -> Layer2Intent:
    try:
        return build_layer2_intent(revision, baseline)
    except ValidationError:
        raise _conflict("intent-rebuild-failed", "intent") from None


def _rebuild_device_preview(
    revision: PlanRevision, intent: Layer2Intent, assignment_id: UUID,
) -> Layer2DeviceConfigPreview:
    try:
        return build_device_layer2_config_preview(revision, intent, assignment_id)
    except PreviewInputError as exc:
        raise _conflict(exc.reason_code, "intent") from None
    except PreviewTargetNotFound:
        raise _not_found("assignment-not-found", "preview") from None


def _rebuild_candidate_document(
    revision: PlanRevision,
    intent: Layer2Intent,
    preview: Layer2DeviceConfigPreview,
    categories: tuple[CandidateCategory, ...] | None,
) -> L2CliCandidateDocument:
    try:
        return build_l2_cli_candidates(
            revision, intent, preview, categories=categories,
        )
    except RenderBindingError as exc:
        raise _conflict(exc.reason_code, "renderer") from None
    except RenderTargetNotFound:
        raise _not_found("assignment-not-found", "preview") from None


def _trusted_expected_source(
    revision: PlanRevision,
    intent: Layer2Intent,
    preview: Layer2DeviceConfigPreview,
    document: L2CliCandidateDocument,
    assignment_id: UUID,
) -> ExpectedSource:
    """Bind every ExpectedSource field to a server-rebuilt trusted object."""
    return ExpectedSource(
        saved_revision_uuid=revision.id,
        revision_number=revision.number,
        revision_canonical_hash=revision.content_hash,
        intent_fingerprint=intent.intent_fingerprint,
        preview_fingerprint=preview.preview_fingerprint,
        render_fingerprint=document.render_fingerprint,
        assignment_id=assignment_id,
    )


def _require_complete_expected_source(expected: ExpectedSource) -> None:
    """Refuse to validate with any unbound ExpectedSource field."""
    if any(getattr(expected, name) is None for name in _EXPECTED_SOURCE_FIELDS):
        raise _conflict(
            "validation-integrity-failure",
            "validation",
            failures=["expected-source-incomplete"],
        )


def _require_report_integrity(report: ValidationReport) -> None:
    """Refuse to return a report whose integrity or source binding failed."""
    if (
        report.integrity.status is not Verdict.PASS
        or not report.integrity.expected_source_match
    ):
        raise _conflict(
            "validation-integrity-failure",
            "validation",
            failures=list(report.integrity.failures),
        )


@router.get(
    "/plan-revisions/{revision_id}/assignments/{assignment_id}/l2-cli-validation",
)
async def read_l2_cli_validation(
    event_id: UUID,
    revision_id: UUID,
    assignment_id: UUID,
    request: Request,
    response: Response,
    session: DatabaseSession,
    category: Annotated[tuple[CandidateCategory, ...] | None, Query()] = None,
) -> ValidationReport:
    """Independently validate one saved Assignment of one saved revision."""
    reject_undeclared_input(request, await request.body())
    _require_event(session, event_id)
    revision, baseline = _load_revisions(session, event_id, revision_id)
    _verify_saved_revision(revision, event_id, "requested")
    if baseline is not None:
        _verify_saved_revision(baseline, event_id, "baseline")
    intent = _rebuild_intent(revision, baseline)
    preview = _rebuild_device_preview(revision, intent, assignment_id)
    document = _rebuild_candidate_document(revision, intent, preview, category)
    expected = _trusted_expected_source(
        revision, intent, preview, document, assignment_id,
    )
    _require_complete_expected_source(expected)
    report = validate_candidate_document(document, expected=expected)
    _require_report_integrity(report)
    response.headers[VALIDATION_SCOPE_HEADER] = "filtered" if category else "full"
    return report
