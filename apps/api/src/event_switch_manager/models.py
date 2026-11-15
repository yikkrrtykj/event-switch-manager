from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy import CheckConstraint, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .domain import DeviceFamily, DeviceRole


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(120))
    management_vlan: Mapped[int]


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("event_id", "hostname", name="uq_device_event_hostname"),
        UniqueConstraint("event_id", "management_ip", name="uq_device_event_management_ip"),
        UniqueConstraint("event_id", "serial_number", name="uq_device_event_serial_number"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    event_id: Mapped[UUID] = mapped_column(ForeignKey("events.id", ondelete="RESTRICT"))
    hostname: Mapped[str] = mapped_column(String(63, collation="NOCASE"))
    family: Mapped[DeviceFamily] = mapped_column(
        sa.Enum(DeviceFamily, native_enum=False, values_callable=lambda cls: [e.value for e in cls])
    )
    role: Mapped[DeviceRole] = mapped_column(
        sa.Enum(DeviceRole, native_enum=False, values_callable=lambda cls: [e.value for e in cls])
    )
    model: Mapped[str | None] = mapped_column(String(80))
    serial_number: Mapped[str | None] = mapped_column(String(64, collation="NOCASE"))
    software_version: Mapped[str | None] = mapped_column(String(80))
    management_ip: Mapped[str | None] = mapped_column(String(15))
    location: Mapped[str | None] = mapped_column(String(120))


class PhysicalAsset(Base):
    __tablename__ = "physical_assets"
    __table_args__ = (UniqueConstraint("vendor", "verified_serial", name="uq_asset_identity"),)

    id: Mapped[UUID] = mapped_column(primary_key=True)
    vendor: Mapped[str] = mapped_column(String(24))
    verified_serial: Mapped[str] = mapped_column(String(64, collation="NOCASE"))


class AssignmentIdentity(Base):
    __tablename__ = "assignment_identities"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    event_id: Mapped[UUID] = mapped_column(ForeignKey("events.id", ondelete="RESTRICT"), index=True)


class EventPlanRevision(Base):
    __tablename__ = "event_plan_revisions"
    __table_args__ = (
        UniqueConstraint("event_id", "number", name="uq_plan_revision_number"),
        UniqueConstraint("event_id", "content_hash", name="uq_plan_revision_hash"),
        CheckConstraint("number > 0", name="ck_plan_revision_number"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    event_id: Mapped[UUID] = mapped_column(ForeignKey("events.id", ondelete="RESTRICT"))
    number: Mapped[int]
    schema_version: Mapped[int]
    created_at: Mapped[datetime]
    content_hash: Mapped[str] = mapped_column(String(64))
    canonical_json: Mapped[str] = mapped_column(Text)
