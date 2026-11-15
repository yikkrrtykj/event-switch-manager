from ipaddress import IPv4Address, IPv4Network
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

VlanId = Annotated[int, Field(strict=True, ge=1, le=4094)]
PositiveInt = Annotated[int, Field(strict=True, ge=1)]
Name = Annotated[
    str, StringConstraints(min_length=1, max_length=80, pattern=r"^[^\x00-\x1f\x7f]+$")
]
PortName = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9/._:-]*$")
]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


def usable(address: IPv4Address, network: IPv4Network) -> bool:
    return address in network and (
        network.prefixlen >= 31
        or address not in (network.network_address, network.broadcast_address)
    )
