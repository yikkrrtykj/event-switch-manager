"""CIS-03-02A read-only Layer 3 intent API.

The route accepts only the three path identifiers.  It rejects every query
parameter, request body and conditional-request header, then loads the saved
revision server-side, re-verifies its canonical hash and Event binding, and
rebuilds the previous saved revision as the planning baseline.  The client can
never supply a hash, fingerprint or document.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.orm import Session

from .api import DatabaseSession, find_event
from .plan_api import revision_and_baseline
from .planning.layer3_intent import Layer3Intent, build_layer3_intent
from .planning.plan import PlanRevision, canonical_plan, plan_hash

router = APIRouter(prefix="/api/v1/events/{event_id}")

_EVENT_NOT_FOUND_DETAIL = "Event not found"
_REVISION_NOT_FOUND_DETAIL = "Plan revision not found"
_REFUSED_HEADERS = ("if-match", "if-none-match")


def _error(status_code: int, *, reason_code: str, stage: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"reason_code": reason_code, "stage": stage},
    )


def _not_found(reason_code: str, stage: str) -> HTTPException:
    return _error(404, reason_code=reason_code, stage=stage)


def _conflict(reason_code: str, stage: str) -> HTTPException:
    return _error(409, reason_code=reason_code, stage=stage)


def _reject_undeclared(request: Request, body: bytes) -> None:
    fields: list[str] = sorted(request.query_params.keys())
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


def _load_revision(
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


def _verify_revision(
    revision: PlanRevision, event_id: UUID, stage: str,
) -> None:
    if plan_hash(canonical_plan(revision.plan)) != revision.content_hash:
        raise _conflict("revision-canonical-hash-mismatch", stage)
    if revision.plan.event_id != event_id:
        raise _conflict("revision-event-mismatch", stage)


@router.get("/plan-revisions/{revision_id}/layer3-intent")
async def read_layer3_intent(
    event_id: UUID,
    revision_id: UUID,
    request: Request,
    session: DatabaseSession,
) -> Layer3Intent:
    """Build read-only L3 intent for one trusted saved revision."""
    _reject_undeclared(request, await request.body())
    _require_event(session, event_id)
    revision, baseline = _load_revision(session, event_id, revision_id)
    _verify_revision(revision, event_id, "revision")
    if baseline is not None:
        _verify_revision(baseline, event_id, "baseline")
    try:
        return build_layer3_intent(revision, baseline)
    except ValidationError:
        raise _conflict("layer3-intent-build-failed", "intent") from None
