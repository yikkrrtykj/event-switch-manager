"""CIS-02B2-02 round-6 regressions: member cleanup and aggregate mode transitions.

Covers the two Ready-stage findings:
  A. switchport VLAN commands must inherit an unresolved member cleanup
     (detached / migrated / replaced membership).
  B. member channel-group commands must inherit a blocked aggregate
     access/trunk mode transition, for existing and newly added members.
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

MEMBER_CLEANUP = "member-cleanup-unresolved"
MODE_TRANSITION = "mode-transition-inherited"
ACCESS_TO_TRUNK = "mode-transition-inherited:access-to-trunk:Port-channel1"
TRUNK_TO_ACCESS = "mode-transition-inherited:trunk-to-access:Port-channel1"
PROTOCOL_CHANGE = "aggregation-protocol-change-requires-field-evidence"
IDENTITY_CHANGE = "channel-object-identity-changed"
CHANNEL_CATEGORIES = {CandidateCategory.PORT_CHANNEL, CandidateCategory.LACP_MODE}


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


def base_plan(event_id: str, count: int = 4) -> dict[str, Any]:
    device_id, assignment_id = new_id(), new_id()
    return {
        "schema_version": 1, "event_id": event_id, "management_vlan": 10,
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
            "id": assignment_id, "hostname": "L2-Access", "role": "access",
            "family": "catalyst-9300", "physical_device_id": device_id,
            "software": {"image": "17.12.4", "license": "Network Advantage"},
        }],
        "physical_interfaces": [
            {
                "id": new_id(), "assignment_id": assignment_id,
                "physical_device_id": device_id, "name": f"Gi1/0/{index + 1}",
                "settings": {"mode": "access", "access_vlan": 20},
            }
            for index in range(count)
        ],
    }


def set_port(plan: dict[str, Any], index: int, settings: dict[str, Any]) -> None:
    plan["physical_interfaces"][index]["settings"] = settings


def add_channel(
    plan: dict[str, Any], number: int, members: list[int],
    settings: dict[str, Any], lacp: str = "active",
    logical_id: str | None = None,
) -> str:
    assignment_id = plan["assignments"][0]["id"]
    logical_id = logical_id or new_id()
    plan.setdefault("logical_interfaces", []).append({
        "id": logical_id, "assignment_id": assignment_id,
        "name": f"Port-channel{number}", "kind": "port-channel",
    })
    plan.setdefault("port_channels", []).append({
        "interface_id": logical_id, "number": number,
        "member_ids": [plan["physical_interfaces"][index]["id"] for index in members],
        "settings": settings, "lacp": lacp,
    })
    return logical_id


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
        and candidate.category in CHANNEL_CATEGORIES
        and candidate.parameters.get("port-channel-number") is not None
    ]


def has_reason(candidate: Any, prefix: str) -> bool:
    return any(reason.startswith(prefix) for reason in candidate.blocking_reasons)


def cleanup_text(document: Any) -> list[str]:
    return [
        candidate.candidate_text for candidate in document.candidates
        if candidate.candidate_text is not None
        and candidate.candidate_text.casefold().startswith("no ")
    ]


def assert_blocked_without_text(candidate: Any, prefix: str) -> None:
    assert candidate.status is CandidateStatus.BLOCKED, (
        candidate.category, candidate.status, candidate.blocking_reasons,
    )
    assert candidate.candidate_text is None
    assert candidate.syntax_validation.level is SyntaxValidationLevel.NOT_RUN
    assert has_reason(candidate, prefix), candidate.blocking_reasons


# --------------------------------------------------------------------------- #
# P2-A: member cleanup dependency
# --------------------------------------------------------------------------- #


def _detached_access_case() -> tuple[Any, dict[str, Any], str]:
    first = base_plan(new_id(), 2)
    logical = add_channel(
        first, 1, [0, 1], {"mode": "access", "access_vlan": 20},
    )
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [first["physical_interfaces"][1]["id"]]
    set_port(second, 0, {"mode": "access", "access_vlan": 10})
    return render([first, second]), second, logical


def test_detached_member_access_vlan_is_blocked() -> None:
    document, plan, _logical = _detached_access_case()
    detached = plan["physical_interfaces"][0]["id"]
    records = by_category(document, detached, CandidateCategory.ACCESS_VLAN)
    assert len(records) == 1
    candidate = records[0]
    assert_blocked_without_text(candidate, f"{MEMBER_CLEANUP}:removed:")
    assert candidate.risk_class is RiskClass.R4
    assert "cleanup-requires-field-verification" in candidate.blocking_reasons
    # The original removal record keeps its own semantics.
    removal = [
        item for item in by_category(document, detached, CandidateCategory.PORT_CHANNEL)
        if "removal-not-rendered" in item.blocking_reasons
    ]
    assert removal
    assert all(item.candidate_text is None for item in removal)
    assert all(
        "baseline-only-cleanup-requires-field-verification" in item.blocking_reasons
        for item in removal
    )
    # The member that stayed in the aggregate keeps its legitimate candidate.
    stay = plan["physical_interfaces"][1]["id"]
    stay_records = member_channel_group(document, {stay})
    assert {record.target.stable_id for record in stay_records} == {stay}
    assert all(record.status is CandidateStatus.CANDIDATE for record in stay_records)
    assert all(
        record.candidate_text == "channel-group 1 mode active"
        for record in stay_records
    )
    assert cleanup_text(document) == []


def test_detached_trunk_member_allowed_vlan_is_blocked() -> None:
    first = base_plan(new_id(), 2)
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    set_port(first, 0, dict(trunk))
    set_port(first, 1, dict(trunk))
    add_channel(first, 1, [0, 1], trunk)
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [first["physical_interfaces"][1]["id"]]
    set_port(second, 0, {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20, 30],
    })
    document = render([first, second])
    detached = second["physical_interfaces"][0]["id"]
    records = by_category(document, detached, CandidateCategory.ALLOWED_VLANS)
    assert len(records) == 1
    assert_blocked_without_text(records[0], f"{MEMBER_CLEANUP}:removed:")
    assert records[0].risk_class is RiskClass.R4
    assert cleanup_text(document) == []


def test_migrated_member_vlan_is_blocked() -> None:
    first = base_plan(new_id(), 2)
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    add_channel(first, 2, [1], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [first["physical_interfaces"][1]["id"]]
    second["port_channels"][1]["member_ids"] = [first["physical_interfaces"][0]["id"]]
    set_port(second, 0, {"mode": "access", "access_vlan": 10})
    document = render([first, second])
    migrated = second["physical_interfaces"][0]["id"]
    records = by_category(document, migrated, CandidateCategory.ACCESS_VLAN)
    assert len(records) == 1
    assert_blocked_without_text(records[0], f"{MEMBER_CLEANUP}:migrated:")
    assert records[0].risk_class is RiskClass.R4
    # The migration record is preserved.
    migration = [
        item for item in member_channel_group(document, {migrated})
        if has_reason(item, "channel-migration-requires-source-channel-evidence")
    ]
    assert migration
    assert migration[0].status is CandidateStatus.BLOCKED
    assert migration[0].candidate_text is None


def test_replaced_object_member_vlan_is_blocked() -> None:
    first = base_plan(new_id(), 2)
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    add_channel(second, 1, [0], {"mode": "access", "access_vlan": 20})
    set_port(second, 0, {"mode": "access", "access_vlan": 10})
    document = render([first, second])
    member = second["physical_interfaces"][0]["id"]
    records = by_category(document, member, CandidateCategory.ACCESS_VLAN)
    assert len(records) == 1
    assert_blocked_without_text(records[0], f"{MEMBER_CLEANUP}:replaced:")
    assert records[0].risk_class is RiskClass.R4
    identity = [
        item for item in member_channel_group(document, {member})
        if has_reason(item, IDENTITY_CHANGE)
    ]
    assert identity
    assert identity[0].risk_class is RiskClass.R5


def test_standalone_port_vlan_change_stays_candidate() -> None:
    first = base_plan(new_id(), 2)
    second = copy.deepcopy(first)
    set_port(second, 0, {"mode": "access", "access_vlan": 10})
    document = render([first, second])
    records = by_category(
        document, second["physical_interfaces"][0]["id"],
        CandidateCategory.ACCESS_VLAN,
    )
    assert len(records) == 1
    assert records[0].status is CandidateStatus.CANDIDATE
    assert records[0].candidate_text == "switchport access vlan 10"
    assert records[0].blocking_reasons == ()


def test_unrelated_interface_is_not_polluted() -> None:
    document, plan, _logical = _detached_access_case()
    unrelated = plan["physical_interfaces"][0]["id"]
    # A third, never-aggregated port changes its VLAN in the same revision.
    first = base_plan(new_id(), 3)
    second = copy.deepcopy(first)
    set_port(second, 2, {"mode": "access", "access_vlan": 10})
    unrelated_document = render([first, second])
    records = by_category(
        unrelated_document, second["physical_interfaces"][2]["id"],
        CandidateCategory.ACCESS_VLAN,
    )
    assert len(records) == 1
    assert records[0].status is CandidateStatus.CANDIDATE
    assert records[0].candidate_text == "switchport access vlan 10"
    assert unrelated is not None
    assert cleanup_text(document) == []


def test_member_cleanup_filter_cannot_bypass() -> None:
    document, _plan, _logical = _detached_access_case()
    filtered = renderer._filter_categories(  # noqa: SLF001 - targeted regression
        document.candidates,
        (CandidateCategory.ACCESS_VLAN, CandidateCategory.ALLOWED_VLANS),
    )
    assert filtered
    assert all(candidate.status is not CandidateStatus.CANDIDATE for candidate in filtered)
    assert all(candidate.candidate_text is None for candidate in filtered)
    assert all(
        has_reason(candidate, MEMBER_CLEANUP) for candidate in filtered
    )


def test_native_and_mode_paths_stay_fail_closed_after_detachment() -> None:
    # native VLAN on a detached trunk member is already blocked by the R5
    # topology gate; a port mode change is already blocked by the mode-transition
    # gate. Neither may render text.
    first = base_plan(new_id(), 2)
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    set_port(first, 0, dict(trunk))
    set_port(first, 1, dict(trunk))
    add_channel(first, 1, [0, 1], trunk)
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [first["physical_interfaces"][1]["id"]]
    set_port(second, 0, {"mode": "trunk", "native_vlan": 30,
                         "allowed_vlans": [10, 20]})
    document = render([first, second])
    detached = second["physical_interfaces"][0]["id"]
    native = by_category(document, detached, CandidateCategory.NATIVE_VLAN)
    assert native
    assert all(candidate.candidate_text is None for candidate in native)
    assert all(candidate.status is not CandidateStatus.CANDIDATE for candidate in native)
    # A mode change on the detached member is already blocked by the
    # mode-transition gate and must never render text.
    mode_first = base_plan(new_id(), 2)
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    set_port(mode_first, 0, dict(trunk))
    set_port(mode_first, 1, dict(trunk))
    add_channel(mode_first, 1, [0, 1], trunk)
    mode_second = copy.deepcopy(mode_first)
    mode_second["port_channels"][0]["member_ids"] = [
        mode_first["physical_interfaces"][1]["id"],
    ]
    set_port(mode_second, 0, {"mode": "access", "access_vlan": 20})
    mode_document = render([mode_first, mode_second])
    mode_member = mode_second["physical_interfaces"][0]["id"]
    modes = [
        candidate for candidate in mode_document.candidates
        if candidate.target.stable_id == mode_member
        and candidate.category in {CandidateCategory.ACCESS_MODE,
                                   CandidateCategory.TRUNK_MODE}
    ]
    assert modes
    assert all(candidate.candidate_text is None for candidate in modes)
    assert all(
        candidate.status is not CandidateStatus.CANDIDATE for candidate in modes
    )
    assert cleanup_text(mode_document) == []


def test_member_cleanup_does_not_reach_generic_attributes() -> None:
    first = base_plan(new_id(), 2)
    add_channel(first, 1, [0, 1], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [first["physical_interfaces"][1]["id"]]
    set_port(second, 0, {"mode": "access", "access_vlan": 10,
                         "description": "detached-port"})
    document = render([first, second])
    detached = second["physical_interfaces"][0]["id"]
    description = by_category(document, detached, CandidateCategory.DESCRIPTION)
    # 9300 description evidence is unverified, so it is blocked by evidence; the
    # point is that the member-cleanup gate did not claim it.
    assert description
    assert not any(has_reason(item, MEMBER_CLEANUP) for item in description)


# --------------------------------------------------------------------------- #
# P2-B: aggregate mode-transition propagation
# --------------------------------------------------------------------------- #


def _mode_case(
    before: str, after: str, lacp: str = "active", added: bool = True,
) -> tuple[Any, dict[str, Any]]:
    first = base_plan(new_id(), 2)
    before_settings = (
        {"mode": "access", "access_vlan": 20} if before == "access"
        else {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    )
    after_settings = (
        {"mode": "access", "access_vlan": 20} if after == "access"
        else {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    )
    set_port(first, 0, dict(before_settings))
    add_channel(first, 1, [0], before_settings, lacp=lacp)
    second = copy.deepcopy(first)
    second["port_channels"][0]["settings"] = after_settings
    set_port(second, 0, dict(after_settings))
    if added:
        second["port_channels"][0]["member_ids"] = [
            first["physical_interfaces"][0]["id"],
            first["physical_interfaces"][1]["id"],
        ]
        set_port(second, 1, dict(after_settings))
    return render([first, second]), second


@pytest.mark.parametrize(("lacp", "text"), [
    ("active", "channel-group 1 mode active"),
    ("passive", "channel-group 1 mode passive"),
    ("static", "channel-group 1 mode on"),
])
def test_access_to_trunk_blocks_every_member_form(lacp: str, text: str) -> None:
    document, plan = _mode_case("access", "trunk", lacp=lacp)
    members = {
        plan["physical_interfaces"][0]["id"],
        plan["physical_interfaces"][1]["id"],
    }
    records = member_channel_group(document, members)
    assert {record.target.stable_id for record in records} == members
    assert len(records) == 2
    for candidate in records:
        assert_blocked_without_text(candidate, ACCESS_TO_TRUNK)
        assert candidate.risk_class is RiskClass.R4
    assert text not in {
        candidate.candidate_text for candidate in document.candidates
    }
    assert cleanup_text(document) == []


def test_trunk_to_access_blocks_members_at_r5() -> None:
    document, plan = _mode_case("trunk", "access")
    members = {
        plan["physical_interfaces"][0]["id"],
        plan["physical_interfaces"][1]["id"],
    }
    records = member_channel_group(document, members)
    assert {record.target.stable_id for record in records} == members
    assert len(records) == 2
    for candidate in records:
        assert_blocked_without_text(candidate, TRUNK_TO_ACCESS)
        assert candidate.risk_class is RiskClass.R5


def test_full_member_replacement_with_mode_transition_blocks_new_members() -> None:
    first = base_plan(new_id(), 4)
    add_channel(first, 1, [0, 1], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    second["port_channels"][0]["settings"] = trunk
    set_port(second, 2, dict(trunk))
    set_port(second, 3, dict(trunk))
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][2]["id"],
        first["physical_interfaces"][3]["id"],
    ]
    old_members = {
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    }
    new_members = {
        first["physical_interfaces"][2]["id"],
        first["physical_interfaces"][3]["id"],
    }
    assert old_members & new_members == set()
    document = render([first, second])
    records = member_channel_group(document, new_members)
    assert {record.target.stable_id for record in records} == new_members
    assert len(records) == 2
    for candidate in records:
        assert_blocked_without_text(candidate, ACCESS_TO_TRUNK)
        assert candidate.risk_class is RiskClass.R4
    # The old members keep their blocked removal records.
    for old in old_members:
        removals = [
            candidate for candidate in document.candidates
            if candidate.target.stable_id == old
            and candidate.status is CandidateStatus.BLOCKED
            and has_reason(candidate, "removal-not-rendered")
        ]
        assert removals


def test_mode_and_protocol_transition_keep_both_blockers() -> None:
    first = base_plan(new_id(), 2)
    set_port(first, 0, {"mode": "access", "access_vlan": 20})
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20},
                lacp="static")
    second = copy.deepcopy(first)
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    second["port_channels"][0]["settings"] = trunk
    second["port_channels"][0]["lacp"] = "active"
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    set_port(second, 0, dict(trunk))
    set_port(second, 1, dict(trunk))
    document = render([first, second])
    members = {
        second["physical_interfaces"][0]["id"],
        second["physical_interfaces"][1]["id"],
    }
    records = member_channel_group(document, members)
    assert {record.target.stable_id for record in records} == members
    assert len(records) == 2
    for candidate in records:
        assert_blocked_without_text(candidate, ACCESS_TO_TRUNK)
        assert has_reason(candidate, PROTOCOL_CHANGE)
        assert candidate.risk_class is RiskClass.R4
        assert candidate.candidate_text is None


def test_mode_and_object_replacement_keeps_identity_gate() -> None:
    first = base_plan(new_id(), 2)
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    set_port(second, 0, dict(trunk))
    add_channel(second, 1, [0], trunk)
    document = render([first, second])
    member = second["physical_interfaces"][0]["id"]
    records = member_channel_group(document, {member})
    assert {record.target.stable_id for record in records} == {member}
    candidate = records[0]
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.candidate_text is None
    assert has_reason(candidate, IDENTITY_CHANGE)
    assert candidate.risk_class is RiskClass.R5
    # Replaced logical objects are not comparable, so the mode marker is not
    # fabricated; the stricter identity gate carries the block.
    assert not has_reason(candidate, MODE_TRANSITION)


def test_unaffected_second_aggregate_keeps_candidates() -> None:
    first = base_plan(new_id(), 4)
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    add_channel(first, 2, [2], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    second["port_channels"][0]["settings"] = trunk
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    set_port(second, 0, dict(trunk))
    set_port(second, 1, dict(trunk))
    # The second aggregate only gains a member; its mode does not change.
    second["port_channels"][1]["member_ids"] = [
        first["physical_interfaces"][2]["id"],
        first["physical_interfaces"][3]["id"],
    ]
    document = render([first, second])
    blocked = member_channel_group(document, {
        second["physical_interfaces"][0]["id"],
        second["physical_interfaces"][1]["id"],
    })
    assert len(blocked) == 2
    assert all(has_reason(candidate, ACCESS_TO_TRUNK) for candidate in blocked)
    unaffected = member_channel_group(document, {
        second["physical_interfaces"][2]["id"],
        second["physical_interfaces"][3]["id"],
    })
    assert {candidate.target.stable_id for candidate in unaffected} == {
        second["physical_interfaces"][2]["id"],
        second["physical_interfaces"][3]["id"],
    }
    assert len(unaffected) == 2
    for candidate in unaffected:
        assert candidate.status is CandidateStatus.CANDIDATE
        assert candidate.candidate_text == "channel-group 2 mode active"
        assert candidate.blocking_reasons == ()


def test_plain_member_addition_keeps_candidates() -> None:
    first = base_plan(new_id(), 2)
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
    assert {candidate.target.stable_id for candidate in records} == members
    assert len(records) == 2
    for candidate in records:
        assert candidate.status is CandidateStatus.CANDIDATE
        assert candidate.candidate_text == "channel-group 1 mode active"
        assert candidate.blocking_reasons == ()


def test_mode_transition_filter_cannot_bypass() -> None:
    document, plan = _mode_case("access", "trunk")
    members = {
        plan["physical_interfaces"][0]["id"],
        plan["physical_interfaces"][1]["id"],
    }
    filtered = renderer._filter_categories(  # noqa: SLF001 - targeted regression
        document.candidates,
        (CandidateCategory.LACP_MODE, CandidateCategory.PORT_CHANNEL),
    )
    filtered_members = [
        candidate for candidate in filtered
        if candidate.target.stable_id in members
        and candidate.parameters.get("port-channel-number") is not None
    ]
    assert {candidate.target.stable_id for candidate in filtered_members} == members
    assert len(filtered_members) == 2
    assert all(
        candidate.status is not CandidateStatus.CANDIDATE
        for candidate in filtered_members
    )
    assert all(candidate.candidate_text is None for candidate in filtered_members)


# --------------------------------------------------------------------------- #
# Shipped registry through the real API
# --------------------------------------------------------------------------- #


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "round6.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as session:
        yield session


def _save(client: TestClient, event_id: str, plan: dict[str, Any]) -> dict[str, Any]:
    response = client.post(f"{API}/events/{event_id}/plan-revisions", json=plan)
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def _get_candidates(
    client: TestClient, event_id: str, revision_id: str, assignment_id: str,
) -> list[dict[str, Any]]:
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision_id}"
        f"/assignments/{assignment_id}/l2-cli-candidates"
    )
    assert response.status_code == 200, response.text
    document = cast(dict[str, Any], response.json())
    return cast(list[dict[str, Any]], document["candidates"])


def test_api_member_cleanup_and_mode_transition(client: TestClient) -> None:
    event_id = client.post(f"{API}/events", json={"name": "round6"}).json()["id"]

    # P2-A through the API: rev1 member leaves the aggregate and changes VLAN.
    first = base_plan(new_id(), 2)
    first["event_id"] = event_id
    add_channel(first, 1, [0, 1], {"mode": "access", "access_vlan": 20})
    assignment_id = first["assignments"][0]["id"]
    rev1 = _save(client, event_id, first)
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [first["physical_interfaces"][1]["id"]]
    set_port(second, 0, {"mode": "access", "access_vlan": 10})
    rev2 = _save(client, event_id, second)
    detached = second["physical_interfaces"][0]["id"]
    candidates = _get_candidates(client, event_id, rev2["id"], assignment_id)
    vlan_records = [
        candidate for candidate in candidates
        if candidate["target"]["stable_id"] == detached
        and candidate["category"] == "access-vlan"
    ]
    assert len(vlan_records) == 1
    assert vlan_records[0]["status"] == "blocked"
    assert vlan_records[0]["candidate_text"] is None
    assert vlan_records[0]["syntax_validation"]["level"] == "not-run"
    assert any(
        reason.startswith("member-cleanup-unresolved:removed:")
        for reason in vlan_records[0]["blocking_reasons"]
    )
    assert rev1["id"] != rev2["id"]

    # P2-B through the API: access aggregate becomes trunk and gains a member.
    mode_event = client.post(f"{API}/events", json={"name": "round6-mode"}).json()["id"]
    first = base_plan(new_id(), 2)
    first["event_id"] = mode_event
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    mode_assignment = first["assignments"][0]["id"]
    _save(client, mode_event, first)
    second = copy.deepcopy(first)
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    second["port_channels"][0]["settings"] = trunk
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    set_port(second, 0, dict(trunk))
    set_port(second, 1, dict(trunk))
    mode_rev = _save(client, mode_event, second)
    members = {
        second["physical_interfaces"][0]["id"],
        second["physical_interfaces"][1]["id"],
    }
    candidates = _get_candidates(client, mode_event, mode_rev["id"], mode_assignment)
    records = [
        candidate for candidate in candidates
        if candidate["target"]["stable_id"] in members
        and candidate["category"] in {"lacp-mode", "port-channel"}
        and candidate["parameters"].get("port-channel-number") is not None
    ]
    assert {candidate["target"]["stable_id"] for candidate in records} == members
    assert len(records) == 2
    for candidate in records:
        assert candidate["status"] == "blocked"
        assert candidate["candidate_text"] is None
        assert candidate["syntax_validation"]["level"] == "not-run"
        assert "mode-transition-inherited:access-to-trunk:Port-channel1" in (
            candidate["blocking_reasons"]
        )
