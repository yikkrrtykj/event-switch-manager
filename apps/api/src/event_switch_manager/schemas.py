from ipaddress import IPv4Address
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .domain import DeviceFamily, DeviceRole

ShortText = Annotated[str, StringConstraints(min_length=1, max_length=80)]
LocationText = Annotated[str, StringConstraints(min_length=1, max_length=120)]
Hostname = Annotated[
    str, StringConstraints(pattern=r"^[a-zA-Z][a-zA-Z0-9-]{0,62}$", strip_whitespace=False)
]
SerialNumber = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9-]+$")
]


class PlanningRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True, str_strip_whitespace=True)


class EventInput(PlanningRecord):
    name: LocationText
    management_vlan: Annotated[int, Field(strict=True, ge=1, le=4094)] = 10


class EventView(EventInput):
    id: UUID


class DeviceInput(PlanningRecord):
    hostname: Hostname
    family: DeviceFamily
    role: DeviceRole
    model: ShortText | None = None
    serial_number: SerialNumber | None = None
    software_version: ShortText | None = None
    management_ip: IPv4Address | None = None
    location: LocationText | None = None


class DeviceView(DeviceInput):
    id: UUID
    event_id: UUID


class HealthView(BaseModel):
    status: str
    database: str
    device_writes_enabled: bool
