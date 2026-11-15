from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from event_switch_manager.models import AssignmentIdentity, Device, EventPlanRevision, PhysicalAsset

from .checks import validate_plan
from .plan import EventPlan, PlanRevision, canonical_plan, plan_hash
from .validation import PlanIssue


def check_identities(session: Session, plan: EventPlan) -> tuple[PlanIssue, ...]:
    issues = []
    for i, assignment in enumerate(plan.assignments):
        identity = session.get(AssignmentIdentity, assignment.id)
        device = session.get(Device, assignment.id)
        if (identity and identity.event_id != plan.event_id) or (
            device and device.event_id != plan.event_id
        ):
            issues.append(PlanIssue(
                path=f"assignments.{i}.id",
                code="assignment_event",
                message="Assignment UUID belongs to another event",
            ))
    for i, asset in enumerate(plan.physical_devices):
        by_id = session.get(PhysicalAsset, asset.id)
        serial = asset.verified_serial
        by_serial = None if serial is None else session.scalar(select(PhysicalAsset).where(
            PhysicalAsset.vendor == asset.vendor,
            PhysicalAsset.verified_serial == serial,
        ))
        if (by_id and (by_id.vendor != asset.vendor or (
            serial is not None and by_id.verified_serial.upper() != serial
        ))) or (by_serial and by_serial.id != asset.id):
            issues.append(PlanIssue(
                path=f"physical_devices.{i}",
                code="physical_identity",
                message="Verified vendor and serial already map to a different chassis identity",
            ))
    return tuple(issues)


def find_existing_revision(session: Session, plan: EventPlan) -> EventPlanRevision | None:
    return session.scalar(select(EventPlanRevision).where(
        EventPlanRevision.event_id == plan.event_id,
        EventPlanRevision.content_hash == plan_hash(canonical_plan(plan)),
    ))


def save_revision(session: Session, plan: EventPlan) -> EventPlanRevision:
    """Append a validated, unique revision within the caller's SQLite write transaction."""
    content = canonical_plan(plan)
    digest = plan_hash(content)
    for assignment in plan.assignments:
        if session.get(AssignmentIdentity, assignment.id) is None:
            session.add(AssignmentIdentity(id=assignment.id, event_id=plan.event_id))
    for asset in plan.physical_devices:
        if asset.verified_serial is not None and session.get(PhysicalAsset, asset.id) is None:
            session.add(PhysicalAsset(
                id=asset.id, vendor=asset.vendor, verified_serial=asset.verified_serial
            ))
    latest = session.scalar(select(func.max(EventPlanRevision.number)).where(
        EventPlanRevision.event_id == plan.event_id
    ))
    revision = EventPlanRevision(
        event_id=plan.event_id,
        number=(latest or 0) + 1,
        schema_version=plan.schema_version,
        created_at=datetime.now(UTC).replace(tzinfo=None),
        content_hash=digest,
        canonical_json=content,
    )
    session.add(revision)
    session.flush()
    return revision


def revision_view(revision: EventPlanRevision) -> PlanRevision:
    plan = EventPlan.model_validate_json(revision.canonical_json)
    return PlanRevision(
        id=revision.id,
        number=revision.number,
        created_at=revision.created_at.replace(tzinfo=UTC),
        content_hash=revision.content_hash,
        schema_version=revision.schema_version,
        plan=plan,
        warnings=tuple(issue for issue in validate_plan(plan) if issue.severity == "WARNING"),
    )


def get_revision(session: Session, event_id: UUID, revision_id: UUID) -> EventPlanRevision | None:
    return session.scalar(select(EventPlanRevision).where(
        EventPlanRevision.event_id == event_id, EventPlanRevision.id == revision_id
    ))
