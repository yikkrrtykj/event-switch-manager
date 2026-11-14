from uuid import uuid4

import pytest
from pydantic import ValidationError

from event_switch_manager.domain import DeviceFamily, DeviceRole
from event_switch_manager.schemas import DeviceInput, DeviceView, EventInput


def test_management_vlan_defaults_and_can_be_changed() -> None:
    assert EventInput(name="  Finals  ").model_dump() == {"name": "Finals", "management_vlan": 10}
    assert EventInput(name="Finals", management_vlan=4094).management_vlan == 4094


@pytest.mark.parametrize("vlan", [0, 4095, "10", True])
def test_management_vlan_rejects_invalid_values(vlan: object) -> None:
    with pytest.raises(ValidationError):
        EventInput.model_validate({"name": "Finals", "management_vlan": vlan})


@pytest.mark.parametrize("family", list(DeviceFamily))
def test_family_is_independent_of_role(family: DeviceFamily) -> None:
    for role in DeviceRole:
        device = DeviceInput(hostname="Lab-Switch", family=family, role=role)
        assert device.family == family
        assert device.role == role


@pytest.mark.parametrize(
    "values",
    [
        {"hostname": "Lab-Switch\nreload"},
        {"family": "unrecognized"},
        {"management_ip": "2001:db8::1"},
        {"serial_number": "A B"},
        {"commands": ["show version"]},
    ],
)
def test_invalid_device_data_is_rejected(values: dict[str, object]) -> None:
    data = {"hostname": "Lab-Switch", "family": "catalyst-9300", "role": "access", **values}
    with pytest.raises(ValidationError):
        DeviceInput.model_validate(data)


def test_device_output_serializes_ipv4_as_text() -> None:
    device = DeviceView.model_validate(
        {
            "id": uuid4(),
            "event_id": uuid4(),
            "hostname": "Lab-Switch",
            "family": "catalyst-9300",
            "role": "access",
            "management_ip": "192.0.2.10",
        }
    )
    assert device.model_dump(mode="json")["management_ip"] == "192.0.2.10"
