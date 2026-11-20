"""CIS-02B2-02 round-5 regressions: routed aggregates are an L3 boundary.

The renderer must never emit Layer-2 aggregate commands (interface Port-Channel,
member channel-group, switchport settings or STP edge features) for a routed
Port-Channel object, while keeping the records (unsupported, no text), keeping
generic interface attributes available, and failing closed for mixed/unknown
aggregate modes.
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
    AGGREGATE_L2_CATEGORIES,
    CandidateCategory,
    CandidateStatus,
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

SCOPE_REASON = "routed-port-channel-not-l2"
TRANSITION_REASON = "routed-boundary-transition-unverified"
#: Aggregate-related categories that must stay silent for a routed aggregate.
SILENT_CATEGORIES = AGGREGATE_L2_CATEGORIES


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


def set_port_mode(plan: dict[str, Any], index: int, settings: dict[str, Any]) -> None:
    plan["physical_interfaces"][index]["settings"] = settings


def add_channel(
    plan: dict[str, Any],
    number: int,
    members: list[int],
    settings: dict[str, Any],
    lacp: str,
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


def routed_plan(event_id: str, *, lacp: str = "active") -> dict[str, Any]:
    plan = base_plan(event_id, 2)
    for index in range(2):
        set_port_mode(plan, index, {"mode": "routed"})
    add_channel(
        plan, 1, [0, 1],
        {"mode": "routed", "address": "192.0.2.254/24",
         "description": "routed uplink"},
        lacp=lacp,
    )
    return plan


def l2_plan(event_id: str, *, lacp: str = "active") -> dict[str, Any]:
    plan = base_plan(event_id, 2)
    add_channel(
        plan, 1, [0, 1],
        {"mode": "access", "access_vlan": 20, "description": "l2 channel"},
        lacp=lacp,
    )
    return plan


def render(plans: list[dict[str, Any]], registry: Any = None) -> Any:
    built = [revision(item, index + 1) for index, item in enumerate(plans)]
    current = built[-1]
    baseline = built[-2] if len(built) > 1 else None
    intent = build_layer2_intent(current, baseline)
    preview = build_device_layer2_config_preview(
        current, intent, current.plan.assignments[0].id,
    )
    if registry is None:
        return build_l2_cli_candidates(current, intent, preview)
    return build_l2_cli_candidates(current, intent, preview, registry=registry)


def by_target(document: Any, stable_id: str) -> list[Any]:
    return [
        candidate for candidate in document.candidates
        if candidate.target.stable_id == stable_id
    ]


def member_channel_group_records(document: Any, member_ids: set[str]) -> list[Any]:
    return [
        candidate for candidate in document.candidates
        if candidate.target.stable_id in member_ids
        and candidate.category in {CandidateCategory.LACP_MODE,
                                   CandidateCategory.PORT_CHANNEL}
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


def aggregate_texts(document: Any) -> list[str]:
    return [
        text for text in (
            candidate.candidate_text for candidate in document.candidates
        )
        if text is not None and (
            "Port-Channel" in text or "channel-group" in text
            or text.startswith(("switchport ", "spanning-tree portfast",
                                "spanning-tree bpduguard"))
        )
    ]


def routed_aggregate_texts(
    document: Any, logical_id: str, member_ids: set[str],
) -> list[str]:
    related = {logical_id} | member_ids
    return [
        candidate.candidate_text for candidate in document.candidates
        if candidate.candidate_text is not None
        and candidate.target.stable_id in related
        and candidate.category in SILENT_CATEGORIES
    ]


def assert_routed_silence(
    document: Any,
    logical_id: str,
    member_ids: set[str],
    *,
    expect_interface: bool = True,
    expect_members: bool = True,
) -> None:
    """Related aggregate objects have records, none carries L2 candidate text.

    A multi-revision change may only touch a settings item, so the interface or
    membership record is not necessarily re-emitted; ``expect_*`` states what the
    scenario must produce. Records that are present always have no text, and an
    unsupported record must carry the routed scope diagnosis. Removals stay
    blocked rather than silently disappearing.
    """
    related = {logical_id} | member_ids

    def _check(candidate: Any) -> None:
        assert candidate.candidate_text is None, (
            candidate.category, candidate.target.name,
        )
        if candidate.status is CandidateStatus.UNSUPPORTED:
            assert SCOPE_REASON in candidate.blocking_reasons, (
                candidate.category, candidate.blocking_reasons,
            )
            assert candidate.syntax_validation.level is SyntaxValidationLevel.NOT_RUN
        else:
            assert candidate.status is CandidateStatus.BLOCKED, (
                candidate.category, candidate.status,
            )

    interface_records = [
        candidate for candidate in by_target(document, logical_id)
        if candidate.category is CandidateCategory.PORT_CHANNEL
    ]
    if expect_interface:
        assert interface_records, "routed Port-Channel lost its interface record"
    for candidate in interface_records:
        _check(candidate)
    if expect_members:
        records = member_channel_group_records(document, member_ids)
        assert {record.target.stable_id for record in records} == member_ids
        for candidate in records:
            _check(candidate)
    for candidate in document.candidates:
        if candidate.target.stable_id in related and (
            candidate.category in SILENT_CATEGORIES
        ):
            _check(candidate)
    assert routed_aggregate_texts(document, logical_id, member_ids) == []


# --------------------------------------------------------------------------- #
# Routed aggregate scope gate
# --------------------------------------------------------------------------- #


def test_first_revision_routed_aggregate_renders_no_l2_commands() -> None:
    plan = routed_plan(new_id())
    logical_id = plan["logical_interfaces"][0]["id"]
    members = {item["id"] for item in plan["physical_interfaces"]}
    document = render([plan])
    assert_routed_silence(document, logical_id, members)
    # The generic description attribute is not reclassified as L3.
    descriptions = [
        candidate for candidate in by_target(document, logical_id)
        if candidate.category is CandidateCategory.DESCRIPTION
    ]
    assert descriptions
    assert not has_reason(descriptions[0], SCOPE_REASON)


@pytest.mark.parametrize("lacp", ["active", "passive", "static"])
def test_routed_aggregate_protocol_forms_are_all_unsupported(lacp: str) -> None:
    plan = routed_plan(new_id(), lacp=lacp)
    logical_id = plan["logical_interfaces"][0]["id"]
    members = {item["id"] for item in plan["physical_interfaces"]}
    document = render([plan])
    assert_routed_silence(document, logical_id, members)
    records = member_channel_group_records(document, members)
    assert all(record.status is CandidateStatus.UNSUPPORTED for record in records)


def test_every_routed_member_has_its_own_unsupported_record() -> None:
    plan = base_plan(new_id(), 3)
    for index in range(3):
        set_port_mode(plan, index, {"mode": "routed"})
    add_channel(
        plan, 1, [0, 1, 2],
        {"mode": "routed", "address": "192.0.2.254/24"}, lacp="active",
    )
    members = {item["id"] for item in plan["physical_interfaces"]}
    document = render([plan])
    records = member_channel_group_records(document, members)
    assert {record.target.stable_id for record in records} == members
    assert len(records) == 3
    assert all(record.status is CandidateStatus.UNSUPPORTED for record in records)
    assert all(record.candidate_text is None for record in records)


def test_later_revision_adding_a_routed_member_stays_unsupported() -> None:
    first = base_plan(new_id(), 3)
    for index in range(3):
        set_port_mode(first, index, {"mode": "routed"})
    logical_id = add_channel(
        first, 1, [0, 1], {"mode": "routed", "address": "192.0.2.254/24"},
        lacp="active",
    )
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][index]["id"] for index in (0, 1, 2)
    ]
    members = {item["id"] for item in first["physical_interfaces"]}
    document = render([first, second])
    assert_routed_silence(document, logical_id, members, expect_interface=False)


def test_routed_protocol_change_does_not_unlock_l2_candidates() -> None:
    first = routed_plan(new_id(), lacp="static")
    logical_id = first["logical_interfaces"][0]["id"]
    second = copy.deepcopy(first)
    second["port_channels"][0]["lacp"] = "active"
    members = {item["id"] for item in first["physical_interfaces"]}
    document = render([first, second])
    assert_routed_silence(document, logical_id, members, expect_interface=False)


def test_routed_member_set_change_does_not_unlock_l2_candidates() -> None:
    first = base_plan(new_id(), 2)
    for index in range(2):
        set_port_mode(first, index, {"mode": "routed"})
    logical_id = add_channel(
        first, 1, [0], {"mode": "routed", "address": "192.0.2.254/24"},
        lacp="active",
    )
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][1]["id"],
    ]
    document = render([first, second])
    assert_routed_silence(
        document, logical_id, {first["physical_interfaces"][1]["id"]},
        expect_interface=False,
    )
    # The detached member keeps an explicit blocked removal record.
    detached = [
        candidate for candidate in by_target(
            document, first["physical_interfaces"][0]["id"],
        )
        if candidate.status is CandidateStatus.BLOCKED
    ]
    assert detached
    assert all(candidate.candidate_text is None for candidate in detached)
    assert cleanup_text(document) == []


def test_l2_to_routed_mode_change_switches_the_scope_gate_on() -> None:
    first = l2_plan(new_id())
    logical_id = first["logical_interfaces"][0]["id"]
    second = copy.deepcopy(first)
    for index in range(2):
        second["physical_interfaces"][index]["settings"] = {"mode": "routed"}
    second["port_channels"][0]["settings"] = {
        "mode": "routed", "address": "192.0.2.254/24",
    }
    members = {item["id"] for item in first["physical_interfaces"]}
    document = render([first, second])
    assert_routed_silence(
        document, logical_id, members,
        expect_interface=False, expect_members=False,
    )
    assert cleanup_text(document) == []


def test_routed_to_l2_mode_change_keeps_the_migration_block() -> None:
    first = base_plan(new_id(), 3)
    for index in range(3):
        set_port_mode(first, index, {"mode": "routed"})
    logical_id = add_channel(
        first, 1, [0], {"mode": "routed", "address": "192.0.2.254/24"},
        lacp="active",
    )
    second = copy.deepcopy(first)
    for index in range(3):
        second["physical_interfaces"][index]["settings"] = {
            "mode": "access", "access_vlan": 20,
        }
    second["port_channels"][0]["settings"] = {
        "mode": "access", "access_vlan": 20,
    }
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    current_members = {
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    }
    document = render([first, second])
    records = member_channel_group_records(document, current_members)
    assert {record.target.stable_id for record in records} == current_members
    for candidate in records:
        assert candidate.status is CandidateStatus.BLOCKED, candidate.blocking_reasons
        assert candidate.candidate_text is None
        assert TRANSITION_REASON in candidate.blocking_reasons
    access_mode = [
        candidate for candidate in by_target(document, logical_id)
        if candidate.category is CandidateCategory.ACCESS_MODE
    ]
    assert access_mode
    for candidate in access_mode:
        assert candidate.status is CandidateStatus.BLOCKED
        assert candidate.candidate_text is None
        assert TRANSITION_REASON in candidate.blocking_reasons
    assert aggregate_texts(document) == []


def test_mixed_mode_aggregate_fails_closed() -> None:
    plan = base_plan(new_id(), 2)
    set_port_mode(plan, 0, {"mode": "routed"})
    # The second member disagrees with the aggregate even though the plan model
    # would normally be rejected before it is saved.
    logical_id = add_channel(
        plan, 1, [0, 1], {"mode": "routed", "address": "192.0.2.254/24"},
        lacp="active",
    )
    assert plan["physical_interfaces"][1]["settings"]["mode"] == "access"
    document = render([plan])
    members = {item["id"] for item in plan["physical_interfaces"]}
    interface_records = [
        candidate for candidate in by_target(document, logical_id)
        if candidate.category is CandidateCategory.PORT_CHANNEL
    ]
    assert interface_records
    for candidate in interface_records:
        # Fail closed: the scope contradiction never renders, and the routed
        # boundary record that also exists for this item stays unsupported.
        assert candidate.status is not CandidateStatus.CANDIDATE
        assert candidate.candidate_text is None
        assert any(
            reason.startswith("aggregate-scope-inconsistent")
            for reason in candidate.blocking_reasons
        )
    for candidate in document.candidates:
        if candidate.target.stable_id in {logical_id} | members and (
            candidate.category in SILENT_CATEGORIES
        ):
            assert candidate.status is not CandidateStatus.CANDIDATE
            assert candidate.candidate_text is None
    member_access = [
        candidate for candidate in document.candidates
        if candidate.target.stable_id
        == plan["physical_interfaces"][1]["id"]
        and candidate.category is CandidateCategory.ACCESS_MODE
    ]
    assert member_access
    assert all(
        candidate.status is not CandidateStatus.CANDIDATE
        for candidate in member_access
    )
    assert aggregate_texts(document) == []


def test_valid_l2_aggregate_is_unaffected_next_to_a_routed_aggregate() -> None:
    plan = base_plan(new_id(), 4)
    for index in (2, 3):
        set_port_mode(plan, index, {"mode": "routed"})
    l2_logical = add_channel(
        plan, 1, [0, 1],
        {"mode": "access", "access_vlan": 20, "description": "l2 channel"},
        lacp="active",
    )
    routed_logical = add_channel(
        plan, 2, [2, 3], {"mode": "routed", "address": "198.51.100.254/24"},
        lacp="active",
    )
    members = {item["id"] for item in plan["physical_interfaces"]}
    document = render([plan])
    l2_members = {plan["physical_interfaces"][index]["id"] for index in (0, 1)}
    routed_members = {plan["physical_interfaces"][index]["id"] for index in (2, 3)}
    l2_records = member_channel_group_records(document, l2_members)
    assert {record.target.stable_id for record in l2_records} == l2_members
    assert all(record.status is CandidateStatus.CANDIDATE for record in l2_records)
    assert all(
        record.candidate_text == "channel-group 1 mode active"
        for record in l2_records
    )
    l2_interface = [
        candidate for candidate in by_target(document, l2_logical)
        if candidate.category is CandidateCategory.PORT_CHANNEL
        and candidate.status is CandidateStatus.CANDIDATE
    ]
    assert any(candidate.candidate_text == "interface Port-Channel1"
               for candidate in l2_interface)
    assert_routed_silence(document, routed_logical, routed_members)
    assert members  # every member belongs to exactly one aggregate


def test_scope_gate_survives_category_filter_and_changed_paths() -> None:
    first = l2_plan(new_id())
    logical_id = first["logical_interfaces"][0]["id"]
    second = copy.deepcopy(first)
    for index in range(2):
        second["physical_interfaces"][index]["settings"] = {"mode": "routed"}
    second["port_channels"][0]["settings"] = {
        "mode": "routed", "address": "192.0.2.254/24",
    }
    second["port_channels"][0]["lacp"] = "active"
    members = {item["id"] for item in first["physical_interfaces"]}
    document = render([first, second])
    unfiltered = {
        (candidate.candidate_id, candidate.status)
        for candidate in document.candidates
        if candidate.target.stable_id in {logical_id} | members
    }
    filtered = renderer._filter_categories(  # noqa: SLF001 - targeted regression
        document.candidates, tuple(SILENT_CATEGORIES),
    )
    filtered_keys = {
        (candidate.candidate_id, candidate.status) for candidate in filtered
    }
    assert filtered_keys
    assert filtered_keys <= unfiltered
    assert all(
        status is not CandidateStatus.CANDIDATE for _id, status in filtered_keys
    )
    # Re-rendering with the same input is stable (no path leaks a candidate).
    again = render([first, second])
    assert {
        (candidate.candidate_id, candidate.status)
        for candidate in again.candidates
    } == {(candidate.candidate_id, candidate.status)
          for candidate in document.candidates}


def test_no_baseline_cleanup_for_routed_aggregate() -> None:
    first = l2_plan(new_id())
    second = copy.deepcopy(first)
    for index in range(2):
        second["physical_interfaces"][index]["settings"] = {"mode": "routed"}
    second["port_channels"][0]["settings"] = {
        "mode": "routed", "address": "192.0.2.254/24",
    }
    document = render([first, second])
    assert cleanup_text(document) == []


# --------------------------------------------------------------------------- #
# Shipped registry through the real API
# --------------------------------------------------------------------------- #


def routed_api_plan(event_id: str, assignment_id: str, device_id: str) -> dict[str, Any]:
    ports = [new_id(), new_id()]
    logical = new_id()
    plan = base_plan(event_id, 0)
    plan["physical_devices"][0]["id"] = device_id
    plan["assignments"][0]["id"] = assignment_id
    plan["assignments"][0]["physical_device_id"] = device_id
    plan["physical_interfaces"] = [
        {
            "id": ports[index], "assignment_id": assignment_id,
            "physical_device_id": device_id, "name": f"Gi1/0/{index + 1}",
            "settings": {"mode": "routed"},
        }
        for index in range(2)
    ]
    plan["logical_interfaces"] = [{
        "id": logical, "assignment_id": assignment_id,
        "name": "Port-channel1", "kind": "port-channel",
    }]
    plan["port_channels"] = [{
        "interface_id": logical, "number": 1, "member_ids": ports,
        "settings": {
            "mode": "routed", "address": "192.0.2.254/24",
            "description": "routed uplink",
        },
        "lacp": "active",
    }]
    return plan


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "round5.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as session:
        yield session


def test_api_reports_routed_aggregate_as_unsupported(client: TestClient) -> None:
    event_id = client.post(f"{API}/events", json={"name": "routed"}).json()["id"]
    plan = routed_api_plan(event_id, new_id(), new_id())
    response = client.post(
        f"{API}/events/{event_id}/plan-revisions", json=plan,
    )
    assert response.status_code == 200, response.text
    revision_id = response.json()["id"]
    assignment_id = plan["assignments"][0]["id"]
    result = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision_id}"
        f"/assignments/{assignment_id}/l2-cli-candidates"
    )
    assert result.status_code == 200, result.text
    document = cast(dict[str, Any], result.json())
    candidates = cast(list[dict[str, Any]], document["candidates"])
    logical_id = plan["logical_interfaces"][0]["id"]
    members = {item["id"] for item in plan["physical_interfaces"]}
    interface_records = [
        candidate for candidate in candidates
        if candidate["target"]["stable_id"] == logical_id
        and candidate["category"] == "port-channel"
    ]
    assert interface_records
    for candidate in interface_records:
        assert candidate["status"] == "unsupported"
        assert candidate["candidate_text"] is None
        assert SCOPE_REASON in candidate["blocking_reasons"]
        assert candidate["syntax_validation"]["level"] == "not-run"
    records = [
        candidate for candidate in candidates
        if candidate["target"]["stable_id"] in members
        and candidate["category"] in {"lacp-mode", "port-channel"}
        and candidate["parameters"].get("port-channel-number") is not None
    ]
    assert {candidate["target"]["stable_id"] for candidate in records} == members
    for candidate in records:
        assert candidate["status"] == "unsupported"
        assert candidate["candidate_text"] is None
        assert SCOPE_REASON in candidate["blocking_reasons"]
    rendered = [
        candidate["candidate_text"] for candidate in candidates
        if candidate["candidate_text"] is not None
    ]
    assert not any(
        "Port-Channel" in text or "channel-group" in text for text in rendered
    )


def test_api_rejects_mixed_mode_aggregate_import(client: TestClient) -> None:
    event_id = client.post(f"{API}/events", json={"name": "mixed"}).json()["id"]
    plan = routed_api_plan(event_id, new_id(), new_id())
    plan["physical_interfaces"][0]["settings"] = {"mode": "access", "access_vlan": 20}
    response = client.post(
        f"{API}/events/{event_id}/plan-revisions", json=plan,
    )
    assert response.status_code == 422
    codes = {
        item["code"] for item in cast(list[dict[str, Any]], response.json()["detail"])
    }
    assert "port_channel_member" in codes
