"""CIS-02B2-02 round-7 regressions: pending member cleanup + member mode.

P2-C: an interface whose previous aggregate membership still needs cleanup must
not be treated as an independent edge/admin target just because its current
planning role looks unreferenced.

P2-D: a physical member's own blocked switchport-mode transition must propagate
to its channel-group candidate for every aggregation protocol form.
"""

from __future__ import annotations

import copy
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from test_event_plans import API, ORIGIN

from event_switch_manager.app import create_app
from event_switch_manager.planning import layer2_cli_candidates as renderer
from event_switch_manager.planning.layer2_cli_candidates import (
    CandidateCategory,
    CandidateStatus,
    RiskClass,
    SyntaxValidationLevel,
    build_l2_cli_candidates,
)
from event_switch_manager.planning.layer2_config_preview import (
    build_device_layer2_config_preview,
)
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.planning.plan import (
    EventPlan,
    PlanRevision,
    canonical_plan,
    plan_hash,
)
from event_switch_manager.settings import Settings

CLEANUP = "pending-member-cleanup-unverified"
ADMIN_CLEANUP = "admin-state-pending-member-cleanup-requires-topology-evidence"
MODE = "mode-transition-inherited"
TRUNK = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
CHANNEL_GROUP = {CandidateCategory.LACP_MODE, CandidateCategory.PORT_CHANNEL}


def new_id() -> str:
    return str(uuid4())


def revision(plan: dict[str, Any], number: int = 1) -> PlanRevision:
    event_plan = EventPlan.model_validate(plan)
    return PlanRevision(
        id=UUID(new_id()), number=number, created_at=datetime.now(UTC),
        content_hash=plan_hash(canonical_plan(event_plan)), schema_version=1,
        plan=event_plan, warnings=(), validation_errors=(),
        validation_status=cast(Any, "VALID_WITH_WARNINGS"),
    )


def base_plan(count: int = 3) -> dict[str, Any]:
    device_id, assignment_id = new_id(), new_id()
    return {
        "schema_version": 1, "event_id": new_id(), "management_vlan": 10,
        "vlans": [
            {"id": 10, "name": "Management", "purpose": "management"},
            {"id": 20, "name": "Players", "purpose": "ordinary"},
            {"id": 30, "name": "Guest", "purpose": "guest"},
        ],
        "physical_devices": [{
            "id": device_id, "vendor": "cisco", "model": "C9300L-24P-4X",
            "verified_serial": "SYN-" + new_id()[:8],
        }],
        "assignments": [{
            "id": assignment_id, "hostname": "L2-R12", "role": "access",
            "family": "catalyst-9300", "physical_device_id": device_id,
            "software": {"image": "17.12.4", "license": "Network Advantage"},
        }],
        "physical_interfaces": [
            {"id": new_id(), "assignment_id": assignment_id,
             "physical_device_id": device_id, "name": f"Gi1/0/{index + 1}",
             "settings": {"mode": "access", "access_vlan": 20}}
            for index in range(count)
        ],
    }


def set_port(plan: dict[str, Any], index: int, settings: dict[str, Any]) -> None:
    plan["physical_interfaces"][index]["settings"] = settings


def add_channel(
    plan: dict[str, Any], number: int, members: list[int],
    settings: dict[str, Any], lacp: str = "active",
) -> None:
    assignment_id = plan["assignments"][0]["id"]
    logical = new_id()
    plan.setdefault("logical_interfaces", []).append({
        "id": logical, "assignment_id": assignment_id,
        "name": f"Port-channel{number}", "kind": "port-channel",
    })
    plan.setdefault("port_channels", []).append({
        "interface_id": logical, "number": number,
        "member_ids": [plan["physical_interfaces"][i]["id"] for i in members],
        "settings": settings, "lacp": lacp,
    })


def render(plans: list[dict[str, Any]]) -> Any:
    built = [revision(item, index + 1) for index, item in enumerate(plans)]
    current = built[-1]
    baseline = built[-2] if len(built) > 1 else None
    intent = build_layer2_intent(current, baseline)
    preview = build_device_layer2_config_preview(
        current, intent, current.plan.assignments[0].id,
    )
    return build_l2_cli_candidates(current, intent, preview)


def by_category(document: Any, stable_id: str, category: CandidateCategory) -> list[Any]:
    return [
        candidate for candidate in document.candidates
        if candidate.target.stable_id == stable_id
        and candidate.category is category
    ]


def member_channel_group(document: Any, member_ids: set[str]) -> list[Any]:
    return [
        candidate for candidate in document.candidates
        if candidate.target.stable_id in member_ids
        and candidate.category in CHANNEL_GROUP
        and candidate.parameters.get("port-channel-number") is not None
    ]


def has_reason(candidate: Any, prefix: str) -> bool:
    return any(reason.startswith(prefix) for reason in candidate.blocking_reasons)


def cleanup_text(document: Any) -> list[str]:
    return [
        candidate.candidate_text for candidate in document.candidates
        if candidate.candidate_text is not None
        and (
            candidate.candidate_text.casefold().startswith("no ")
            or candidate.candidate_text.casefold().startswith("ip ")
        )
    ]


def detached_case(
    extra: dict[str, Any], *, trunk: bool = False,
    prior_admin: str | None = None,
) -> tuple[Any, dict[str, Any]]:
    settings = dict(TRUNK) if trunk else {"mode": "access", "access_vlan": 20}
    first = base_plan()
    if trunk:
        set_port(first, 0, dict(settings))
        set_port(first, 1, dict(settings))
    if prior_admin is not None:
        set_port(first, 0, {**settings, "admin_state": prior_admin})
    add_channel(first, 1, [0, 1], settings)
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][1]["id"],
    ]
    set_port(second, 0, {**settings, **extra})
    return render([first, second]), second


# --------------------------------------------------------------------------- #
# P2-C: pending member cleanup blocks STP / admin commands
# --------------------------------------------------------------------------- #


def test_removed_member_portfast_is_blocked() -> None:
    document, plan = detached_case({"portfast": "edge"})
    member = plan["physical_interfaces"][0]["id"]
    records = by_category(document, member, CandidateCategory.PORTFAST)
    assert len(records) == 1
    candidate = records[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert candidate.syntax_validation.level is SyntaxValidationLevel.NOT_RUN
    assert candidate.requires_field_verification is True
    assert has_reason(candidate, f"portfast-{CLEANUP}:removed:")
    # The original membership-removal record is preserved.
    removal = [
        item for item in by_category(
            document, member, CandidateCategory.PORT_CHANNEL,
        )
        if has_reason(item, "removal-not-rendered")
    ]
    assert removal
    assert removal[0].status is CandidateStatus.BLOCKED
    assert removal[0].candidate_text is None


def test_removed_member_bpdu_guard_is_blocked() -> None:
    document, plan = detached_case({"bpdu_guard": "enabled"})
    member = plan["physical_interfaces"][0]["id"]
    records = by_category(document, member, CandidateCategory.BPDU_GUARD)
    assert len(records) == 1
    candidate = records[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert candidate.syntax_validation.level is SyntaxValidationLevel.NOT_RUN
    assert has_reason(candidate, f"bpdu-guard-{CLEANUP}:removed:")


def test_removed_member_shutdown_is_blocked() -> None:
    document, plan = detached_case({"admin_state": "down"})
    member = plan["physical_interfaces"][0]["id"]
    records = by_category(document, member, CandidateCategory.ADMIN_SHUTDOWN)
    assert len(records) == 1
    candidate = records[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R5
    assert candidate.candidate_text is None
    assert has_reason(candidate, f"{ADMIN_CLEANUP}:removed:")


def test_removed_member_no_shutdown_is_blocked() -> None:
    document, plan = detached_case({"admin_state": "up"}, prior_admin="down")
    member = plan["physical_interfaces"][0]["id"]
    records = by_category(document, member, CandidateCategory.ADMIN_SHUTDOWN)
    assert len(records) == 1
    candidate = records[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R5
    assert candidate.candidate_text is None
    assert has_reason(candidate, f"{ADMIN_CLEANUP}:removed:")


def test_removed_trunk_member_edge_trunk_is_blocked() -> None:
    document, plan = detached_case({"portfast": "edge-trunk"}, trunk=True)
    member = plan["physical_interfaces"][0]["id"]
    records = by_category(document, member, CandidateCategory.PORTFAST)
    assert len(records) == 1
    candidate = records[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert has_reason(candidate, f"portfast-{CLEANUP}:removed:")


def test_migrated_member_keeps_member_gate_and_cleanup() -> None:
    first = base_plan()
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    add_channel(first, 2, [1], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [first["physical_interfaces"][1]["id"]]
    second["port_channels"][1]["member_ids"] = [first["physical_interfaces"][0]["id"]]
    set_port(second, 0, {"mode": "access", "access_vlan": 20,
                         "portfast": "edge"})
    document = render([first, second])
    member = second["physical_interfaces"][0]["id"]
    records = by_category(document, member, CandidateCategory.PORTFAST)
    assert len(records) == 1
    candidate = records[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert has_reason(candidate, "portfast-aggregate-member-role-unverified")
    assert has_reason(candidate, f"portfast-{CLEANUP}:migrated:")


def test_replaced_object_member_keeps_identity_and_cleanup() -> None:
    first = base_plan()
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    add_channel(second, 1, [0], {"mode": "access", "access_vlan": 20})
    set_port(second, 0, {"mode": "access", "access_vlan": 20,
                         "bpdu_guard": "enabled"})
    document = render([first, second])
    member = second["physical_interfaces"][0]["id"]
    records = by_category(document, member, CandidateCategory.BPDU_GUARD)
    assert len(records) == 1
    candidate = records[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert has_reason(candidate, "bpdu-guard-aggregate-member-role-unverified")
    assert has_reason(candidate, f"bpdu-guard-{CLEANUP}:replaced:")
    # The stricter identity migration record is still present.
    identity = [
        item for item in member_channel_group(document, {member})
        if has_reason(item, "channel-object-identity-changed")
    ]
    assert identity
    assert identity[0].risk_class is RiskClass.R5


def test_current_member_gates_are_unchanged() -> None:
    first = base_plan()
    add_channel(first, 1, [0, 1], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    set_port(second, 0, {"mode": "access", "access_vlan": 20,
                         "portfast": "edge", "bpdu_guard": "enabled",
                         "admin_state": "down"})
    document = render([first, second])
    member = second["physical_interfaces"][0]["id"]
    portfast = by_category(document, member, CandidateCategory.PORTFAST)[0]
    bpdu = by_category(document, member, CandidateCategory.BPDU_GUARD)[0]
    admin = by_category(document, member, CandidateCategory.ADMIN_SHUTDOWN)[0]
    assert portfast.status is CandidateStatus.BLOCKED
    assert portfast.risk_class is RiskClass.R3
    assert has_reason(portfast, "portfast-aggregate-member-role-unverified")
    assert not has_reason(portfast, CLEANUP)
    assert bpdu.status is CandidateStatus.BLOCKED
    assert bpdu.risk_class is RiskClass.R3
    assert not has_reason(bpdu, CLEANUP)
    assert admin.status is CandidateStatus.BLOCKED
    assert admin.risk_class is RiskClass.R5
    assert has_reason(admin, "channel-member-admin-state-requires-topology-evidence")


def test_never_aggregated_interface_keeps_candidates() -> None:
    first = base_plan()
    second = copy.deepcopy(first)
    set_port(second, 2, {"mode": "access", "access_vlan": 20,
                         "portfast": "edge", "bpdu_guard": "enabled",
                         "admin_state": "down"})
    document = render([first, second])
    port = second["physical_interfaces"][2]["id"]
    portfast = by_category(document, port, CandidateCategory.PORTFAST)[0]
    bpdu = by_category(document, port, CandidateCategory.BPDU_GUARD)[0]
    admin = by_category(document, port, CandidateCategory.ADMIN_SHUTDOWN)[0]
    assert portfast.status is CandidateStatus.CANDIDATE
    assert portfast.candidate_text == "spanning-tree portfast"
    assert not has_reason(portfast, CLEANUP)
    assert bpdu.status is CandidateStatus.CANDIDATE
    assert bpdu.candidate_text == "spanning-tree bpduguard enable"
    assert not has_reason(bpdu, CLEANUP)
    assert admin.status is CandidateStatus.CANDIDATE
    assert admin.candidate_text == "shutdown"
    assert not has_reason(admin, CLEANUP)


def test_unrelated_interface_is_not_polluted() -> None:
    first = base_plan()
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [first["physical_interfaces"][1]["id"]]
    set_port(second, 0, {"mode": "access", "access_vlan": 20,
                         "portfast": "edge"})
    set_port(second, 2, {"mode": "access", "access_vlan": 20,
                         "portfast": "edge"})
    document = render([first, second])
    detached = second["physical_interfaces"][0]["id"]
    unrelated = second["physical_interfaces"][2]["id"]
    assert by_category(document, detached, CandidateCategory.PORTFAST)[0].status \
        is CandidateStatus.BLOCKED
    unrelated_record = by_category(document, unrelated, CandidateCategory.PORTFAST)
    assert len(unrelated_record) == 1
    assert unrelated_record[0].status is CandidateStatus.CANDIDATE
    assert unrelated_record[0].candidate_text == "spanning-tree portfast"
    assert not has_reason(unrelated_record[0], CLEANUP)


def test_vlan_cleanup_gate_is_preserved() -> None:
    document, plan = detached_case({"access_vlan": 10})
    member = plan["physical_interfaces"][0]["id"]
    records = by_category(document, member, CandidateCategory.ACCESS_VLAN)
    assert len(records) == 1
    candidate = records[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert has_reason(candidate, "member-cleanup-unresolved:removed:")


def test_cleanup_gate_category_filter_cannot_bypass() -> None:
    document, plan = detached_case({"portfast": "edge", "bpdu_guard": "enabled",
                                    "admin_state": "down"})
    filtered = renderer._filter_categories(  # noqa: SLF001 - targeted regression
        document.candidates,
        (CandidateCategory.PORTFAST, CandidateCategory.BPDU_GUARD,
         CandidateCategory.ADMIN_SHUTDOWN),
    )
    assert filtered
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in filtered)
    assert all(candidate.candidate_text is None for candidate in filtered)
    assert all(
        any(reason.startswith(("portfast-", "bpdu-guard-", "admin-state-"))
            and "pending-member-cleanup" in reason
            for reason in candidate.blocking_reasons)
        for candidate in filtered
    )


def test_description_speed_duplex_are_not_cleanup_gated() -> None:
    first = base_plan()
    add_channel(first, 1, [0, 1], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][1]["id"],
    ]
    set_port(second, 0, {"mode": "access", "access_vlan": 20,
                         "description": "detached-r12", "speed": 1000,
                         "duplex": "full"})
    document = render([first, second])
    member = second["physical_interfaces"][0]["id"]
    generic = [
        candidate for candidate in document.candidates
        if candidate.target.stable_id == member
        and candidate.category in {
            CandidateCategory.DESCRIPTION, CandidateCategory.SPEED,
            CandidateCategory.DUPLEX,
        }
    ]
    assert generic
    assert all(
        not any(CLEANUP in reason for reason in candidate.blocking_reasons)
        for candidate in generic
    )


# --------------------------------------------------------------------------- #
# P2-D: member's own mode transition reaches channel-group
# --------------------------------------------------------------------------- #


def join_mode_case(
    before: str, after: str, lacp: str = "active",
    channel_mode: str = "trunk", count: int = 2,
) -> tuple[Any, dict[str, Any]]:
    settings = dict(TRUNK) if channel_mode == "trunk" else {
        "mode": "access", "access_vlan": 20,
    }
    first = base_plan(count=count)
    set_port(first, 0, dict(settings))
    set_port(first, 1, (
        dict(TRUNK) if before == "trunk"
        else {"mode": "routed", "address": "192.0.2.2/24"} if before == "routed"
        else {"mode": "access", "access_vlan": 20}
    ))
    add_channel(first, 1, [0], settings, lacp=lacp)
    second = copy.deepcopy(first)
    set_port(second, 1, (
        dict(TRUNK) if after == "trunk"
        else {"mode": "routed", "address": "192.0.2.2/24"} if after == "routed"
        else {"mode": "access", "access_vlan": 20}
    ))
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    return render([first, second]), second


def test_member_access_to_trunk_blocks_channel_group() -> None:
    document, plan = join_mode_case("access", "trunk")
    first_member = plan["physical_interfaces"][0]["id"]
    second_member = plan["physical_interfaces"][1]["id"]
    records = member_channel_group(document, {first_member, second_member})
    assert {record.target.stable_id for record in records} == {
        first_member, second_member,
    }
    assert len(records) == 2
    moved = [record for record in records
             if record.target.stable_id == second_member]
    assert len(moved) == 1
    candidate = moved[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert candidate.syntax_validation.level is SyntaxValidationLevel.NOT_RUN
    assert has_reason(candidate, f"{MODE}:access-to-trunk:Gi1/0/2")
    # The member's own mode command keeps its existing block.
    trunk_mode = [
        item for item in by_category(
            document, second_member, CandidateCategory.TRUNK_MODE,
        )
        if has_reason(item, "topology-role-unverified:access-to-trunk")
    ]
    assert trunk_mode
    assert trunk_mode[0].candidate_text is None
    # The unchanged original member keeps its legitimate candidate.
    unchanged = [record for record in records
                 if record.target.stable_id == first_member]
    assert unchanged[0].status is CandidateStatus.CANDIDATE
    assert not has_reason(unchanged[0], MODE)


def test_member_trunk_to_access_blocks_channel_group_at_r5() -> None:
    document, plan = join_mode_case("trunk", "access", channel_mode="access")
    member = plan["physical_interfaces"][1]["id"]
    candidate = member_channel_group(document, {member})[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R5
    assert candidate.candidate_text is None
    assert has_reason(candidate, f"{MODE}:trunk-to-access:Gi1/0/2")


def test_member_routed_to_access_blocks_channel_group_at_r5() -> None:
    document, plan = join_mode_case("routed", "access", channel_mode="access")
    member = plan["physical_interfaces"][1]["id"]
    candidate = member_channel_group(document, {member})[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R5
    assert candidate.candidate_text is None
    assert has_reason(candidate, f"{MODE}:routed-to-switchport:Gi1/0/2")
    # Existing routed boundary block on the mode command is preserved.
    access_mode = [
        item for item in by_category(
            document, member, CandidateCategory.ACCESS_MODE,
        )
        if has_reason(item, "routed-boundary-transition-unverified")
    ]
    assert access_mode
    assert access_mode[0].candidate_text is None


@pytest.mark.parametrize(("lacp", "expected_category"), [
    ("static", CandidateCategory.PORT_CHANNEL),
    ("active", CandidateCategory.LACP_MODE),
    ("passive", CandidateCategory.LACP_MODE),
])
def test_every_aggregation_form_inherits_member_mode(
    lacp: str, expected_category: CandidateCategory,
) -> None:
    document, plan = join_mode_case("access", "trunk", lacp=lacp)
    member = plan["physical_interfaces"][1]["id"]
    records = [
        candidate for candidate in document.candidates
        if candidate.target.stable_id == member
        and candidate.category is expected_category
        and candidate.parameters.get("port-channel-number") is not None
    ]
    assert len(records) == 1
    candidate = records[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert has_reason(candidate, f"{MODE}:access-to-trunk:Gi1/0/2")


def test_new_aggregate_with_member_mode_migration_blocks() -> None:
    first = base_plan()
    set_port(first, 0, dict(TRUNK))
    second = copy.deepcopy(first)
    set_port(second, 1, dict(TRUNK))
    add_channel(second, 1, [0, 1], TRUNK)
    document = render([first, second])
    member = second["physical_interfaces"][1]["id"]
    candidate = member_channel_group(document, {member})[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert has_reason(candidate, f"{MODE}:access-to-trunk:Gi1/0/2")


def test_aggregate_and_member_mode_keep_both_reasons() -> None:
    first = base_plan()
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"][0]["settings"] = TRUNK
    set_port(second, 0, dict(TRUNK))
    set_port(second, 1, dict(TRUNK))
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    document = render([first, second])
    member = second["physical_interfaces"][1]["id"]
    candidate = member_channel_group(document, {member})[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert has_reason(candidate, f"{MODE}:access-to-trunk:Port-channel1")
    assert has_reason(candidate, f"{MODE}:access-to-trunk:Gi1/0/2")


def test_mode_and_protocol_keep_all_blockers() -> None:
    first = base_plan()
    set_port(first, 0, dict(TRUNK))
    add_channel(first, 1, [0], TRUNK, lacp="static")
    second = copy.deepcopy(first)
    set_port(second, 1, dict(TRUNK))
    second["port_channels"][0]["lacp"] = "active"
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    document = render([first, second])
    member = second["physical_interfaces"][1]["id"]
    candidate = member_channel_group(document, {member})[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert has_reason(candidate, "aggregation-protocol-change-requires-field-evidence")
    assert has_reason(candidate, f"{MODE}:access-to-trunk:Gi1/0/2")


def test_mode_and_identity_keep_both_blockers() -> None:
    first = base_plan()
    set_port(first, 0, dict(TRUNK))
    add_channel(first, 1, [0], TRUNK)
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    set_port(second, 1, dict(TRUNK))
    add_channel(second, 1, [0, 1], TRUNK)
    document = render([first, second])
    member = second["physical_interfaces"][1]["id"]
    candidate = member_channel_group(document, {member})[0]
    assert candidate.status is CandidateStatus.BLOCKED
    # Identity replacement and the member's own mode transition both apply; the
    # highest applicable risk floor is R4.
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert has_reason(candidate, "channel-object-identity-changed")
    assert has_reason(candidate, f"{MODE}:access-to-trunk:Gi1/0/2")


def test_mode_and_migration_keep_both_blockers() -> None:
    first = base_plan(count=3)
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    add_channel(first, 2, [1, 2], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"][0]["settings"] = TRUNK
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    set_port(second, 0, dict(TRUNK))
    set_port(second, 1, dict(TRUNK))
    second["port_channels"][1]["member_ids"] = [first["physical_interfaces"][2]["id"]]
    set_port(second, 2, dict(TRUNK))
    document = render([first, second])
    member = second["physical_interfaces"][1]["id"]
    candidate = member_channel_group(document, {member})[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.risk_class is RiskClass.R4
    assert candidate.candidate_text is None
    assert has_reason(candidate, "channel-migration-requires-source-channel-evidence")
    assert has_reason(candidate, f"{MODE}:access-to-trunk:Gi1/0/2")


def test_plain_member_addition_stays_candidate() -> None:
    first = base_plan()
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    document = render([first, second])
    members = {
        second["physical_interfaces"][0]["id"],
        second["physical_interfaces"][1]["id"],
    }
    records = member_channel_group(document, members)
    assert {record.target.stable_id for record in records} == members
    assert len(records) == 2
    for candidate in records:
        assert candidate.status is CandidateStatus.CANDIDATE
        assert candidate.candidate_text == "channel-group 1 mode active"
        assert not has_reason(candidate, MODE)


def test_routed_scope_gate_is_preserved() -> None:
    first = base_plan()
    for index in range(2):
        set_port(first, index, {"mode": "routed"})
    add_channel(first, 1, [0, 1], {"mode": "routed",
                                   "address": "192.0.2.254/24"})
    document = render([first])
    members = {
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    }
    records = member_channel_group(document, members)
    assert {record.target.stable_id for record in records} == members
    assert len(records) == 2
    for candidate in records:
        assert candidate.status is CandidateStatus.UNSUPPORTED
        assert candidate.candidate_text is None
        assert has_reason(candidate, "routed-port-channel-not-l2")
    assert cleanup_text(document) == []


def test_mode_transition_filter_cannot_bypass() -> None:
    document, plan = join_mode_case("access", "trunk")
    member = plan["physical_interfaces"][1]["id"]
    filtered = renderer._filter_categories(  # noqa: SLF001 - targeted regression
        document.candidates,
        (CandidateCategory.LACP_MODE, CandidateCategory.PORT_CHANNEL),
    )
    records = [
        candidate for candidate in filtered
        if candidate.target.stable_id == member
        and candidate.parameters.get("port-channel-number") is not None
    ]
    assert len(records) == 1
    assert records[0].status is CandidateStatus.BLOCKED
    assert records[0].candidate_text is None
    assert has_reason(records[0], f"{MODE}:access-to-trunk:Gi1/0/2")


def test_no_cleanup_or_l3_text_in_fixtures() -> None:
    for extra, trunk in (
        ({"portfast": "edge"}, False),
        ({"bpdu_guard": "enabled"}, False),
        ({"admin_state": "down"}, False),
        ({"portfast": "edge-trunk"}, True),
    ):
        document, _plan = detached_case(extra, trunk=trunk)
        assert cleanup_text(document) == []
    document, _plan = join_mode_case("access", "trunk")
    assert cleanup_text(document) == []


# --------------------------------------------------------------------------- #
# Real API regressions on the shipped registry
# --------------------------------------------------------------------------- #


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "round7.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as session:
        yield session


def save_revision(
    client: TestClient, event_id: str, plan: dict[str, Any],
) -> dict[str, Any]:
    payload = copy.deepcopy(plan)
    payload["event_id"] = event_id
    response = client.post(
        f"{API}/events/{event_id}/plan-revisions", json=payload,
    )
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def get_candidates(
    client: TestClient, event_id: str, revision_id: str, assignment_id: str,
) -> list[dict[str, Any]]:
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision_id}"
        f"/assignments/{assignment_id}/l2-cli-candidates"
    )
    assert response.status_code == 200, response.text
    document = cast(dict[str, Any], response.json())
    return cast(list[dict[str, Any]], document["candidates"])


def test_api_pending_cleanup_blocks_stp_and_admin(client: TestClient) -> None:
    event_id = client.post(f"{API}/events", json={"name": "r12-c"}).json()["id"]
    first = base_plan()
    add_channel(first, 1, [0, 1], {"mode": "access", "access_vlan": 20})
    assignment_id = first["assignments"][0]["id"]
    save_revision(client, event_id, first)
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][1]["id"],
    ]
    set_port(second, 0, {"mode": "access", "access_vlan": 20,
                         "portfast": "edge", "bpdu_guard": "enabled",
                         "admin_state": "down"})
    revision = save_revision(client, event_id, second)
    member = second["physical_interfaces"][0]["id"]
    candidates = get_candidates(client, event_id, revision["id"], assignment_id)
    for category, risk in (("portfast", "R4"), ("bpdu-guard", "R4"),
                           ("admin-shutdown", "R5")):
        records = [
            candidate for candidate in candidates
            if candidate["target"]["stable_id"] == member
            and candidate["category"] == category
        ]
        assert len(records) == 1, category
        record = records[0]
        assert record["status"] == "blocked"
        assert record["risk_class"] == risk
        assert record["candidate_text"] is None
        assert record["syntax_validation"]["level"] == "not-run"
        assert any("pending-member-cleanup" in reason
                   for reason in record["blocking_reasons"]), records
    removal = [
        candidate for candidate in candidates
        if candidate["target"]["stable_id"] == member
        and candidate["category"] == "port-channel"
        and any(reason.startswith("removal-not-rendered")
                for reason in candidate["blocking_reasons"])
    ]
    assert removal


def test_api_member_mode_blocks_channel_group(client: TestClient) -> None:
    event_id = client.post(f"{API}/events", json={"name": "r12-d"}).json()["id"]
    first = base_plan()
    set_port(first, 0, dict(TRUNK))
    add_channel(first, 1, [0], TRUNK)
    assignment_id = first["assignments"][0]["id"]
    save_revision(client, event_id, first)
    second = copy.deepcopy(first)
    set_port(second, 1, dict(TRUNK))
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    revision = save_revision(client, event_id, second)
    member = second["physical_interfaces"][1]["id"]
    candidates = get_candidates(client, event_id, revision["id"], assignment_id)
    records = [
        candidate for candidate in candidates
        if candidate["target"]["stable_id"] == member
        and candidate["category"] in {"lacp-mode", "port-channel"}
        and candidate["parameters"].get("port-channel-number") is not None
    ]
    assert len(records) == 1
    record = records[0]
    assert record["status"] == "blocked"
    assert record["risk_class"] == "R4"
    assert record["candidate_text"] is None
    assert record["syntax_validation"]["level"] == "not-run"
    assert "mode-transition-inherited:access-to-trunk:Gi1/0/2" in (
        record["blocking_reasons"]
    )
