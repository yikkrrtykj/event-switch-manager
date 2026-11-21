"""CIS-03-02A exact L3 capability evidence tests."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from layer3_helpers import make_stack_plan

from event_switch_manager.domain import DeviceFamily, DeviceRole
from event_switch_manager.planning.inventory import (
    EventDeviceAssignment,
    PhysicalDevice,
    SoftwareProfile,
)
from event_switch_manager.planning.layer3_capability import (
    ROWS,
    DocumentationStatus,
    L3Capability,
    L3Verdict,
    PrerequisiteStatus,
    resolve_l3_capability,
    target_for,
)
from event_switch_manager.planning.plan import EventPlan


def _plan(
    pid: str,
    family: str,
    image: str | None,
    license_name: str | None,
    *,
    serial: str | None = "SYN-L3-001",
    assignment_family: DeviceFamily | None = None,
) -> tuple[EventPlan, UUID]:
    device_id, assignment_id = uuid4(), uuid4()
    plan = EventPlan(
        schema_version=1,
        event_id=uuid4(),
        physical_devices=(PhysicalDevice(
            id=device_id,
            vendor="cisco",
            model=pid,
            verified_serial=serial,
        ),),
        assignments=(EventDeviceAssignment(
            id=assignment_id,
            hostname="L3-Capability",
            role=DeviceRole.CORE,
            family=assignment_family or DeviceFamily(family),
            physical_device_id=device_id,
            software=(
                None if image is None
                else SoftwareProfile(image=image, license=license_name)
            ),
        ),),
    )
    return plan, assignment_id


@pytest.mark.parametrize("capability", [
    L3Capability.IPV4_ROUTING,
    L3Capability.SVI,
    L3Capability.ROUTED_PORT,
    L3Capability.STATIC_ROUTE,
    L3Capability.DEFAULT_ROUTE,
    L3Capability.DHCP_RELAY,
])
def test_9300_advantage_documented(capability: L3Capability) -> None:
    plan, aid = _plan("C9300L-24P-4X", "catalyst-9300", "17.12.4", "Network Advantage")
    decision = resolve_l3_capability(plan, aid, capability)
    assert decision.verdict is L3Verdict.DOCUMENTED
    assert decision.documentation is DocumentationStatus.SUPPORTED
    assert decision.prerequisite is PrerequisiteStatus.NOT_REQUIRED
    assert decision.reason_code == "l3-documented"
    assert decision.hardware_verified is False
    assert decision.deployment_allowed is False
    assert decision.evidence
    assert decision.evidence[0].url.startswith("https://www.cisco.com/")
    assert decision.evidence[0].section


def test_9300_dhcp_relay_requires_advantage() -> None:
    plan, aid = _plan("C9300L-24P-4X", "catalyst-9300", "17.12.4", "Network Essentials")
    decision = resolve_l3_capability(plan, aid, L3Capability.DHCP_RELAY)
    assert decision.verdict is L3Verdict.UNKNOWN
    assert decision.reason_code == "l3-license-unmatched"
    assert decision.evidence == ()
    assert decision.affects_forwarding is False


def test_9300_forwarding_capabilities_work_on_essentials() -> None:
    plan, aid = _plan("C9300L-24P-4X", "catalyst-9300", "17.12.4", "Network Essentials")
    for capability in (
        L3Capability.IPV4_ROUTING,
        L3Capability.SVI,
        L3Capability.ROUTED_PORT,
        L3Capability.STATIC_ROUTE,
        L3Capability.DEFAULT_ROUTE,
    ):
        assert resolve_l3_capability(plan, aid, capability).verdict is L3Verdict.DOCUMENTED


def test_9200_default_route_and_dhcp_remain_unknown() -> None:
    plan, aid = _plan("C9200L-24P-4X", "catalyst-9200", "17.12.4", "Network Advantage")
    for capability in (L3Capability.DEFAULT_ROUTE, L3Capability.DHCP_RELAY):
        decision = resolve_l3_capability(plan, aid, capability)
        assert decision.verdict is L3Verdict.UNKNOWN
        assert decision.reason_code == "l3-evidence-missing"
        assert decision.evidence == ()
    for capability in (
        L3Capability.IPV4_ROUTING,
        L3Capability.SVI,
        L3Capability.ROUTED_PORT,
        L3Capability.STATIC_ROUTE,
    ):
        assert resolve_l3_capability(plan, aid, capability).verdict is L3Verdict.DOCUMENTED


def test_9200_identity_only_release_is_unknown() -> None:
    plan, aid = _plan("C9200L-24P-4X", "catalyst-9200", "17.12.5", "Network Advantage")
    decision = resolve_l3_capability(plan, aid, L3Capability.SVI)
    assert decision.verdict is L3Verdict.UNKNOWN
    assert decision.reason_code == "l3-release-unmatched"


def test_2960x_lanbase_is_conditional_on_sdm() -> None:
    plan, aid = _plan("WS-C2960X-24TS-L", "catalyst-2960x", "15.2(7)E", "LAN Base")
    for capability in (
        L3Capability.IPV4_ROUTING,
        L3Capability.SVI,
        L3Capability.STATIC_ROUTE,
        L3Capability.DEFAULT_ROUTE,
    ):
        decision = resolve_l3_capability(plan, aid, capability)
        assert decision.verdict is L3Verdict.CONDITIONAL
        assert decision.prerequisite is PrerequisiteStatus.UNOBSERVED
        assert decision.reason_code == "l3-runtime-prerequisite-unobserved"
        assert any("sdm prefer lanbase-routing" in item for item in decision.evidence[0].conditions)


def test_2960x_lanlite_is_documented_unsupported() -> None:
    plan, aid = _plan("WS-C2960X-24TS-LL", "catalyst-2960x", "15.2(7)E", "LAN Lite")
    for capability in (
        L3Capability.IPV4_ROUTING,
        L3Capability.STATIC_ROUTE,
        L3Capability.DEFAULT_ROUTE,
    ):
        decision = resolve_l3_capability(plan, aid, capability)
        assert decision.verdict is L3Verdict.UNSUPPORTED
        assert decision.reason_code == "l3-documented-unsupported"
        assert decision.documentation is DocumentationStatus.UNSUPPORTED
    assert resolve_l3_capability(plan, aid, L3Capability.SVI).verdict is L3Verdict.UNKNOWN


def test_3850_license_boundaries_are_exact() -> None:
    lanbase, lanbase_aid = _plan("WS-C3850-24P", "catalyst-3850", "16.12.12", "LAN Base")
    for capability in (
        L3Capability.IPV4_ROUTING,
        L3Capability.SVI,
        L3Capability.STATIC_ROUTE,
    ):
        assert resolve_l3_capability(lanbase, lanbase_aid, capability).verdict is (
            L3Verdict.DOCUMENTED
        )
    for capability in (L3Capability.ROUTED_PORT, L3Capability.DEFAULT_ROUTE):
        assert resolve_l3_capability(lanbase, lanbase_aid, capability).verdict is (
            L3Verdict.UNKNOWN
        )
    ipbase, ipbase_aid = _plan("WS-C3850-24P", "catalyst-3850", "16.12.12", "IP Base")
    for capability in (
        L3Capability.IPV4_ROUTING,
        L3Capability.SVI,
        L3Capability.ROUTED_PORT,
        L3Capability.STATIC_ROUTE,
        L3Capability.DEFAULT_ROUTE,
    ):
        assert resolve_l3_capability(ipbase, ipbase_aid, capability).verdict is (
            L3Verdict.DOCUMENTED
        )


def test_3850_aggregation_only_release_has_no_l3_evidence() -> None:
    plan, aid = _plan("WS-C3850-24P", "catalyst-3850", "16.12.10a", "IP Base")
    decision = resolve_l3_capability(plan, aid, L3Capability.STATIC_ROUTE)
    assert decision.verdict is L3Verdict.UNKNOWN
    assert decision.reason_code == "l3-release-unmatched"


def test_c1000_documented_with_route_limit() -> None:
    plan, aid = _plan("C1000-24P-4G-L", "catalyst-c1000", "15.2(7)E1", None)
    for capability in (
        L3Capability.IPV4_ROUTING,
        L3Capability.SVI,
        L3Capability.ROUTED_PORT,
        L3Capability.STATIC_ROUTE,
        L3Capability.DEFAULT_ROUTE,
    ):
        decision = resolve_l3_capability(plan, aid, capability)
        assert decision.verdict is L3Verdict.DOCUMENTED
        assert any("16 static routes" in item for item in decision.evidence[0].limits)


def test_c1000_explicit_license_is_unmatched() -> None:
    plan, aid = _plan("C1000-24T-4G-L", "catalyst-c1000", "15.2(7)E1", "LAN Base")
    decision = resolve_l3_capability(plan, aid, L3Capability.STATIC_ROUTE)
    assert decision.verdict is L3Verdict.UNKNOWN
    assert decision.reason_code == "l3-license-unmatched"


@pytest.mark.parametrize(("pid", "family", "image", "reason"), [
    ("C9300L-24P-4X", "catalyst-9300", "17.12.5", "l3-release-unmatched"),
    ("C9300L-24P-4X", "catalyst-9300", "16.12.12", "l3-release-unmatched"),
    ("C9300L-48T-4G", "catalyst-9300", "17.12.4", "l3-pid-unlisted"),
])
def test_release_and_pid_fail_closed(pid: str, family: str, image: str, reason: str) -> None:
    plan, aid = _plan(pid, family, image, "Network Advantage")
    decision = resolve_l3_capability(plan, aid, L3Capability.SVI)
    assert decision.verdict is L3Verdict.UNKNOWN
    assert decision.reason_code == reason


def test_missing_identity_or_software_fails_closed() -> None:
    plan, aid = _plan("C9300L-24P-4X", "catalyst-9300", "17.12.4", "Network Advantage", serial=None)
    assert resolve_l3_capability(plan, aid, L3Capability.SVI).reason_code == (
        "l3-identity-incomplete"
    )
    plan2, aid2 = _plan("C9300L-24P-4X", "catalyst-9300", None, None)
    assert resolve_l3_capability(plan2, aid2, L3Capability.SVI).reason_code == (
        "l3-software-missing"
    )


def test_family_mismatch_fails_closed() -> None:
    plan, aid = _plan(
        "C9300L-24P-4X", "catalyst-9300", "17.12.4", "Network Advantage",
        assignment_family=DeviceFamily.CATALYST_9200,
    )
    decision = resolve_l3_capability(plan, aid, L3Capability.SVI)
    assert decision.verdict is L3Verdict.UNKNOWN
    assert decision.reason_code == "l3-family-mismatch"


def test_every_row_is_exact_and_versioned() -> None:
    assert ROWS
    keys = {
        (row.family, row.pids, row.releases, row.licenses, row.capability)
        for row in ROWS
    }
    assert len(keys) == len(ROWS)
    assert len({row.evidence_id for row in ROWS}) == len(ROWS)
    for row in ROWS:
        assert row.evidence_id.startswith("l3-")
        assert row.pids and all(pid.isupper() for pid in row.pids)
        assert row.releases
        assert row.source_url.startswith("https://www.cisco.com/")
        assert row.source_section
        assert row.evidence_version == 1
        if row.documentation is DocumentationStatus.SUPPORTED:
            assert row.prerequisite in {
                PrerequisiteStatus.NOT_REQUIRED,
                PrerequisiteStatus.UNOBSERVED,
            }


def test_target_for_binds_exact_pid_and_software() -> None:
    plan, aid = _plan("C9300L-24P-4X", "catalyst-9300", "17.12.4", "Network Advantage")
    assignment = next(item for item in plan.assignments if item.id == aid)
    target = target_for(plan, assignment)
    assert target.exact_pid == "C9300L-24P-4X"
    assert target.software_image == "17.12.4"
    assert target.license == "Network Advantage"
    assert target.stack_identity == "standalone"


def test_route_limits_are_machine_readable_and_scoped() -> None:
    c1000, c1000_aid = _plan("C1000-24P-4G-L", "catalyst-c1000", "15.2(7)E1", None)
    static = resolve_l3_capability(c1000, c1000_aid, L3Capability.STATIC_ROUTE)
    assert (static.max_routes, static.route_limit_scope) == (16, "static-and-default")
    default = resolve_l3_capability(c1000, c1000_aid, L3Capability.DEFAULT_ROUTE)
    assert (default.max_routes, default.route_limit_scope) == (16, "static-and-default")
    lanbase, lanbase_aid = _plan("WS-C3850-24P", "catalyst-3850", "16.12.12", "LAN Base")
    lanbase_static = resolve_l3_capability(
        lanbase, lanbase_aid, L3Capability.STATIC_ROUTE,
    )
    assert (lanbase_static.max_routes, lanbase_static.route_limit_scope) == (
        16, "static-and-default",
    )
    s2960, s2960_aid = _plan("WS-C2960X-24TS-L", "catalyst-2960x", "15.2(7)E", "LAN Base")
    assert resolve_l3_capability(
        s2960, s2960_aid, L3Capability.STATIC_ROUTE,
    ).max_routes == 16
    c9300, c9300_aid = _plan("C9300L-24P-4X", "catalyst-9300", "17.12.4", "Network Advantage")
    assert resolve_l3_capability(
        c9300, c9300_aid, L3Capability.STATIC_ROUTE,
    ).max_routes is None
    c9200, c9200_aid = _plan("C9200L-24P-4X", "catalyst-9200", "17.12.4", "Network Advantage")
    assert resolve_l3_capability(
        c9200, c9200_aid, L3Capability.STATIC_ROUTE,
    ).max_routes is None


def _stack_target(**kwargs: Any) -> tuple[EventPlan, UUID, str]:
    payload = make_stack_plan("00000000-0000-0000-0000-000000000099", **kwargs)
    plan = EventPlan.model_validate(payload)
    aid = next(
        item.id for item in plan.assignments if item.hostname == "L3-Core"
    )
    assignment = next(item for item in plan.assignments if item.id == aid)
    return plan, aid, target_for(plan, assignment).stack_identity


def test_complete_homogeneous_ready_stack_is_resolved() -> None:
    plan, aid, identity = _stack_target()
    assert identity == "resolved"
    decision = resolve_l3_capability(plan, aid, L3Capability.SVI)
    assert decision.verdict is L3Verdict.DOCUMENTED
    assert decision.hardware_verified is False


@pytest.mark.parametrize(("kwargs", "expected"), [
    ({"second_serial": None}, "unresolved"),
    ({"second_pid": None}, "unresolved"),
    ({"second_pid": "C9300L-24T-4G"}, "unresolved"),
    ({"second_state": "unknown"}, "unresolved"),
    ({"second_state": "missing"}, "unresolved"),
    ({"reference_missing_device": True}, "unresolved"),
    ({"assignment_outside_stack": True}, "unresolved"),
])
def test_incomplete_or_incompatible_stack_is_unresolved(
    kwargs: dict[str, object], expected: str,
) -> None:
    plan, aid, identity = _stack_target(**kwargs)
    assert identity == expected
    decision = resolve_l3_capability(plan, aid, L3Capability.SVI)
    assert decision.verdict is L3Verdict.UNKNOWN
    assert decision.reason_code == "l3-stack-unresolved"
