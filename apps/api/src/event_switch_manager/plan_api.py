from datetime import UTC
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import Field, field_validator
from sqlalchemy import select, text

from .api import DatabaseSession, find_event
from .cisco_capabilities import (
    CapabilityDecision,
    DraftCapabilityPreview,
    Duplex,
    Speed,
    TargetNotFound,
    preview_fingerprint,
    resolve_capability,
    resolve_draft_capability,
)
from .cisco_catalog import CapabilityId
from .models import Device, EventPlanRevision
from .planning.inventory import EventDeviceAssignment
from .planning.layer2_config_preview import (
    Layer2ConfigPreview,
    Layer2DeviceConfigPreview,
    PreviewInputError,
    PreviewTargetNotFound,
    build_device_layer2_config_preview,
    build_layer2_config_preview,
)
from .planning.layer2_intent import Layer2Intent, build_layer2_intent
from .planning.persistence import (
    current_plan_issues,
    find_existing_revision,
    get_revision,
    revision_view,
    save_revision,
)
from .planning.plan import (
    EventPlan,
    PlanRevision,
    PlanRevisionSummary,
    canonical_plan,
    plan_hash,
)
from .planning.types import Record
from .planning.validation import PlanIssue
from .schemas import DeviceView

router = APIRouter(prefix="/api/v1/events/{event_id}")


class CapabilityPreviewRequest(Record):
    plan: EventPlan
    assignment_id: UUID
    capabilities: Annotated[tuple[CapabilityId, ...], Field(min_length=1, max_length=32)]
    interface_id: UUID | None = None
    stack_member: Annotated[int | None, Field(ge=1)] = None
    speed: Speed | None = None
    duplex: Duplex | None = None

    @field_validator("capabilities")
    @classmethod
    def distinct_capabilities(cls, value: tuple[CapabilityId, ...]) -> tuple[CapabilityId, ...]:
        if len(set(value)) != len(value):
            raise ValueError("Capability IDs must be distinct")
        return value


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


@router.get("/plan-revisions/{revision_id}/assignments/{assignment_id}/cisco-capability")
def read_cisco_capability(
    event_id: UUID,
    revision_id: UUID,
    assignment_id: UUID,
    session: DatabaseSession,
    capability: Annotated[CapabilityId, Query()],
    interface_id: UUID | None = None,
    stack_member: Annotated[int | None, Query(ge=1)] = None,
    speed: Annotated[Speed | None, Query()] = None,
    duplex: Annotated[Duplex | None, Query()] = None,
) -> CapabilityDecision:
    revision = revision_view(session, require_revision(event_id, revision_id, session))
    try:
        return resolve_capability(
            revision, assignment_id, capability, interface_id=interface_id,
            stack_member=stack_member, speed=speed, duplex=duplex,
        )
    except TargetNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None


@router.get("/plan-revisions/{revision_id}/layer2-intent")
def read_layer2_intent(
    event_id: UUID, revision_id: UUID, session: DatabaseSession,
) -> Layer2Intent:
    """Diagnostic CIS-02A intent for one immutable revision; read-only, no CLI."""
    revision, baseline = revision_and_baseline(event_id, revision_id, session)
    return build_layer2_intent(revision, baseline)


def revision_and_baseline(
    event_id: UUID, revision_id: UUID, session: DatabaseSession,
) -> tuple[PlanRevision, PlanRevision | None]:
    revision = revision_view(session, require_revision(event_id, revision_id, session))
    previous = session.scalar(select(EventPlanRevision).where(
        EventPlanRevision.event_id == event_id,
        EventPlanRevision.number < revision.number,
    ).order_by(EventPlanRevision.number.desc()))
    baseline = revision_view(session, previous) if previous is not None else None
    return revision, baseline


def revision_intent(
    event_id: UUID, revision_id: UUID, session: DatabaseSession,
) -> tuple[PlanRevision, Layer2Intent]:
    revision, baseline = revision_and_baseline(event_id, revision_id, session)
    return revision, build_layer2_intent(revision, baseline)


@router.get("/plan-revisions/{revision_id}/layer2-config-preview")
def read_layer2_config_preview(
    event_id: UUID, revision_id: UUID, session: DatabaseSession,
) -> Layer2ConfigPreview:
    """CIS-02B1 review-only L2 config preview; no CLI, no device operation."""
    revision, intent = revision_intent(event_id, revision_id, session)
    try:
        return build_layer2_config_preview(revision, intent)
    except PreviewInputError as exc:
        raise HTTPException(status_code=409, detail=exc.reason_code) from None


@router.get(
    "/plan-revisions/{revision_id}/layer2-config-preview/devices/{assignment_id}",
)
def read_device_layer2_config_preview(
    event_id: UUID, revision_id: UUID, assignment_id: UUID, session: DatabaseSession,
) -> Layer2DeviceConfigPreview:
    """CIS-02B1 preview for one Assignment; no other device is mixed in."""
    revision, intent = revision_intent(event_id, revision_id, session)
    try:
        return build_device_layer2_config_preview(revision, intent, assignment_id)
    except PreviewInputError as exc:
        raise HTTPException(status_code=409, detail=exc.reason_code) from None
    except PreviewTargetNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None


@router.post("/plan/capability-preview")
def preview_plan_capabilities(
    event_id: UUID, request: CapabilityPreviewRequest, session: DatabaseSession,
) -> DraftCapabilityPreview:
    """Read-only capability preview for the current, unsaved planner draft."""
    find_event(session, event_id)
    if request.plan.event_id != event_id:
        raise HTTPException(status_code=422, detail=[PlanIssue(
            path="event_id", code="event_mismatch",
            message="Plan event UUID must match the URL",
        ).model_dump()])
    issues = current_plan_issues(session, request.plan)
    identity_issues = tuple(
        issue for issue in issues if issue.code in {"assignment_event", "physical_identity"}
    )
    if identity_issues:
        raise HTTPException(
            status_code=422, detail=[issue.model_dump() for issue in identity_issues],
        )
    errors = any(issue.severity == "ERROR" for issue in issues)
    warnings = any(issue.severity == "WARNING" for issue in issues)
    status: Literal["VALID", "VALID_WITH_WARNINGS", "INVALID"]
    status = "INVALID" if errors else "VALID_WITH_WARNINGS" if warnings else "VALID"
    content_hash = plan_hash(canonical_plan(request.plan))
    try:
        decisions = tuple(
            resolve_draft_capability(
                request.plan, status, request.assignment_id, capability,
                interface_id=request.interface_id, stack_member=request.stack_member,
                speed=request.speed, duplex=request.duplex,
            )
            for capability in request.capabilities
        )
    except TargetNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    return DraftCapabilityPreview(
        draft_fingerprint=content_hash,
        input_fingerprint=preview_fingerprint(
            content_hash, request.assignment_id, request.capabilities,
            interface_id=request.interface_id, stack_member=request.stack_member,
            speed=request.speed, duplex=request.duplex,
        ),
        decisions=decisions,
    )
