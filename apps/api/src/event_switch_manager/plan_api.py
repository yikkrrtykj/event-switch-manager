from datetime import UTC
from uuid import UUID

from fastapi import APIRouter, HTTPException, Response
from sqlalchemy import select, text

from .api import DatabaseSession, find_event
from .models import Device, EventPlanRevision
from .planning.inventory import EventDeviceAssignment
from .planning.persistence import (
    current_plan_issues,
    find_existing_revision,
    get_revision,
    revision_view,
    save_revision,
)
from .planning.plan import EventPlan, PlanRevision, PlanRevisionSummary
from .planning.validation import PlanIssue
from .schemas import DeviceView

router = APIRouter(prefix="/api/v1/events/{event_id}")


def plan_issues(session: DatabaseSession, event_id: UUID, plan: EventPlan) -> tuple[PlanIssue, ...]:
    if event_id != plan.event_id:
        return (PlanIssue(path="event_id", code="event_mismatch",
                          message="Plan event UUID must match the URL"),)
    return current_plan_issues(session, plan)


@router.get("/plan/seed")
def seed_event_plan(event_id: UUID, session: DatabaseSession) -> EventPlan:
    event = find_event(session, event_id)
    assignments = []
    devices = session.scalars(select(Device).where(Device.event_id == event_id).order_by(Device.id))
    for device in devices:
        view = DeviceView.model_validate(device)
        assignments.append(EventDeviceAssignment(
            id=view.id,
            hostname=view.hostname,
            role=view.role,
            family=view.family,
            management_ip=view.management_ip,
            location=view.location,
        ))
    return EventPlan(
        schema_version=1,
        event_id=event_id,
        management_vlan=event.management_vlan,
        assignments=tuple(assignments),
    )


@router.post("/plan/validate")
def validate_event_plan(
    event_id: UUID, plan: EventPlan, session: DatabaseSession
) -> tuple[PlanIssue, ...]:
    find_event(session, event_id)
    return plan_issues(session, event_id, plan)


@router.post("/plan-revisions")
def import_plan(event_id: UUID, plan: EventPlan, session: DatabaseSession) -> PlanRevision:
    # Serialize identity checks and revision allocation with other imports.
    session.execute(text("BEGIN IMMEDIATE"))
    find_event(session, event_id)
    # Exact re-imports preserve historical revisions, even when current checks are stricter.
    revision = find_existing_revision(session, plan) if event_id == plan.event_id else None
    if revision is None:
        issues = plan_issues(session, event_id, plan)
        if any(issue.severity == "ERROR" for issue in issues):
            raise HTTPException(status_code=422, detail=[issue.model_dump() for issue in issues])
        revision = save_revision(session, plan)
    result = revision_view(session, revision)
    session.commit()
    return result


@router.get("/plan-revisions")
def list_revisions(event_id: UUID, session: DatabaseSession) -> list[PlanRevisionSummary]:
    find_event(session, event_id)
    revisions = session.scalars(select(EventPlanRevision)
                                .where(EventPlanRevision.event_id == event_id)
                                .order_by(EventPlanRevision.number))
    return [
        PlanRevisionSummary(
            id=revision.id,
            number=revision.number,
            created_at=revision.created_at.replace(tzinfo=UTC),
            content_hash=revision.content_hash,
            schema_version=revision.schema_version,
        )
        for revision in revisions
    ]


def require_revision(
    event_id: UUID, revision_id: UUID, session: DatabaseSession
) -> EventPlanRevision:
    revision = get_revision(session, event_id, revision_id)
    if revision is None:
        raise HTTPException(status_code=404, detail="Plan revision not found")
    return revision


@router.get("/plan-revisions/{revision_id}")
def read_revision(event_id: UUID, revision_id: UUID, session: DatabaseSession) -> PlanRevision:
    return revision_view(session, require_revision(event_id, revision_id, session))


@router.get("/plan-revisions/{revision_id}/export", response_class=Response)
def export_revision(event_id: UUID, revision_id: UUID, session: DatabaseSession) -> Response:
    revision = require_revision(event_id, revision_id, session)
    return Response(
        revision.canonical_json, media_type="application/json",
        headers={"ETag": f'"{revision.content_hash}"'},
    )
