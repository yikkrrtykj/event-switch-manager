from __future__ import annotations

from uuid import uuid4

from event_switch_manager.domain import DeviceFamily, DeviceRole
from event_switch_manager.planning.command_evidence import DEFAULT_REGISTRY, CommandTopic
from event_switch_manager.planning.layer3_intent import L3Identity
from event_switch_manager.planning.layer3_registry_selection import select_l3_registry
from event_switch_manager.planning.management_command_evidence import (
    ManagementCommandTopic,
)
from event_switch_manager.planning.management_command_evidence_reviews import (
    production_management_registry,
)


def test_r85_identity_has_no_l2_command_evidence_rows() -> None:
    for topic in CommandTopic:
        assert DEFAULT_REGISTRY.applicable(
            DeviceFamily.CATALYST_C1000,
            "C1000-16T-2G-L",
            "15.2(7)E2",
            None,
            topic,
        ) == ()


def test_r85_identity_selects_no_reviewed_l3_registry() -> None:
    identity = L3Identity(
        assignment_id=uuid4(),
        hostname="r85-lab",
        role=DeviceRole.ACCESS,
        family=DeviceFamily.CATALYST_C1000,
        vendor="cisco",
        physical_device_id=uuid4(),
        exact_pid="C1000-16T-2G-L",
        pid_evidence="exact-verified-pid",
        serial_verified=True,
        software_image="15.2(7)E2",
        software_license=None,
        stack_identity="standalone",
        stack_members=(),
    )
    selection = select_l3_registry(identity)
    assert selection.evidence_approved is False
    assert selection.reason_code == "platform-evidence-unreviewed"
    assert selection.registry.rows == ()


def test_r85_identity_has_no_management_evidence() -> None:
    registry = production_management_registry()
    for row in registry.rows:
        assert "C1000-16T-2G-L" not in row.pids
    for topic in ManagementCommandTopic:
        assert registry.find(
            DeviceFamily.CATALYST_C1000,
            "C1000-16T-2G-L",
            "15.2(7)E2",
            "",
            topic,
        ) is None
