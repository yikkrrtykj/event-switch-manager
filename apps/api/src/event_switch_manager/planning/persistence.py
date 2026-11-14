from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from event_switch_manager.models import AssignmentIdentity, Device, EventPlanRevision, PhysicalAsset

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
        by_serial = session.scalar(select(PhysicalAsset).where(
            PhysicalAsset.vendor == asset.vendor,
            PhysicalAsset.verified_serial == asset.verified_serial,
        ))
        if (by_id and (by_id.vendor, by_id.verified_serial.upper())
                != (asset.vendor, asset.verified_serial.upper())) or (
            by_serial and by_serial.id != asset.id
        ):
            issues.append(PlanIssue(
                path=f"physical_devices.{i}",
                code="physical_identity",
                message="Verified vendor and serial already map to a different chassis identity",
            ))
    return tuple(issues)


def save_revision(session: Session, plan: EventPlan) -> EventPlanRevision:
    """Append within the caller's SQLite write transaction."""
    content = canonical_plan(plan)
    digest = plan_hash(content)
    existing = session.scalar(select(EventPlanRevision).where(
        EventPlanRevision.event_id == plan.event_id,
        EventPlanRevision.content_hash == digest,
    ))
    if existing is not None:
        return existing
    for assignment in plan.assignments:
        if session.get(AssignmentIdentity, assignment.id) is None:
            session.add(AssignmentIdentity(id=assignment.id, event_id=plan.event_id))
    for asset in plan.physical_devices:
        if session.get(PhysicalAsset, asset.id) is None:
            session.add(PhysicalAsset(
                id=asset.id, vendor=asset.vendor, verified_serial=asset.verified_serial.upper()
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
    return PlanRevision(
        id=revision.id,
        number=revision.number,
        created_at=revision.created_at.replace(tzinfo=UTC),
        content_hash=revision.content_hash,
        schema_version=revision.schema_version,
        plan=EventPlan.model_validate_json(revision.canonical_json),
    )


def get_revision(session: Session, event_id: UUID, revision_id: UUID) -> EventPlanRevision | None:
    return session.scalar(select(EventPlanRevision).where(
        EventPlanRevision.event_id == event_id, EventPlanRevision.id == revision_id
    ))
