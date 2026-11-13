from collections.abc import Iterator
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from .models import Device, Event
from .schemas import DeviceInput, DeviceView, EventInput, EventView, HealthView

router = APIRouter(prefix="/api/v1")


def get_session(request: Request) -> Iterator[Session]:
    engine: Engine = request.app.state.engine
    with Session(engine) as session:
        yield session


DatabaseSession = Annotated[Session, Depends(get_session)]


@router.get("/health", response_model=HealthView)
def health(session: DatabaseSession) -> HealthView:
    try:
        session.execute(select(Event.id).limit(0))
        session.execute(select(Device.id).limit(0))
        session.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail="Planning database unavailable") from None
    return HealthView(status="ok", database="ready", device_writes_enabled=False)


@router.get("/events", response_model=list[EventView])
def list_events(session: DatabaseSession) -> list[Event]:
    return list(session.scalars(select(Event).order_by(Event.name, Event.id)))


@router.post("/events", response_model=EventView, status_code=201)
def create_event(data: EventInput, session: DatabaseSession) -> Event:
    event = Event(name=data.name, management_vlan=data.management_vlan)
    session.add(event)
    session.commit()
    session.refresh(event)
    return event


def find_event(session: Session, event_id: UUID) -> Event:
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/events/{event_id}", response_model=EventView)
def get_event(event_id: UUID, session: DatabaseSession) -> Event:
    return find_event(session, event_id)


@router.put("/events/{event_id}", response_model=EventView)
def update_event(event_id: UUID, data: EventInput, session: DatabaseSession) -> Event:
    event = find_event(session, event_id)
    event.name = data.name
    event.management_vlan = data.management_vlan
    session.commit()
    session.refresh(event)
    return event


@router.get("/events/{event_id}/devices", response_model=list[DeviceView])
def list_devices(event_id: UUID, session: DatabaseSession) -> list[Device]:
    find_event(session, event_id)
    query = select(Device).where(Device.event_id == event_id).order_by(Device.hostname)
    return list(session.scalars(query))


def save_device(session: Session, device: Device, data: DeviceInput) -> Device:
    device.hostname = data.hostname
    device.family = data.family
    device.role = data.role
    device.model = data.model
    device.serial_number = data.serial_number
    device.software_version = data.software_version
    device.management_ip = str(data.management_ip) if data.management_ip is not None else None
    device.location = data.location
    session.add(device)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=409, detail="Hostname, management IP and serial must be unique per event"
        ) from None
    session.refresh(device)
    return device


@router.post("/events/{event_id}/devices", response_model=DeviceView, status_code=201)
def create_device(event_id: UUID, data: DeviceInput, session: DatabaseSession) -> Device:
    find_event(session, event_id)
    return save_device(session, Device(event_id=event_id), data)


def find_device(session: Session, event_id: UUID, device_id: UUID) -> Device:
    device = session.scalar(
        select(Device).where(Device.event_id == event_id, Device.id == device_id)
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.get("/events/{event_id}/devices/{device_id}", response_model=DeviceView)
def get_device(event_id: UUID, device_id: UUID, session: DatabaseSession) -> Device:
    return find_device(session, event_id, device_id)


@router.put("/events/{event_id}/devices/{device_id}", response_model=DeviceView)
def update_device(
    event_id: UUID, device_id: UUID, data: DeviceInput, session: DatabaseSession
) -> Device:
    return save_device(session, find_device(session, event_id, device_id), data)
