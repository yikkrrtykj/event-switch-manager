"""CIS-02B2-02 round-3 review regressions: target objects, edge roles, protocol.

Covers P2-06 (target-object validity reaches every sub-command), P2-07
(PortFast/BPDU Guard topology role gates), P2-08 (aggregation protocol change and
channel identity) and the evidence-diagnosis accuracy claim.
"""

from __future__ import annotations

import copy
import dataclasses
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from test_event_plans import API, ORIGIN
from test_l2_cli_candidate_review_fixes import (
    CHANNEL_CATEGORIES,
    _revision,
    add_channel,
    base_plan,
    harness_registry,
    of,
    render,
)

from event_switch_manager import plan_api
from event_switch_manager.app import create_app
from event_switch_manager.planning import layer2_cli_candidates as renderer
from event_switch_manager.planning.command_evidence import (
    ROWS,
    CommandEvidenceRegistry,
)
from event_switch_manager.planning.layer2_cli_candidates import (
    CandidateCategory,
    CandidateStatus,
    RiskClass,
    build_l2_cli_candidates,
)
from event_switch_manager.planning.layer2_config_preview import (
    build_device_layer2_config_preview,
)
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.settings import Settings


def new_id() -> str:
    return str(uuid4())


def all_candidates(document: Any, name: str) -> list[Any]:
    return [candidate for candidate in document.candidates if candidate.target.name == name]


def reasons_text(candidate: Any) -> str:
    return " ".join(candidate.blocking_reasons)


# --------------------------------------------------------------------------- #
# P2-06 target-object validity
# --------------------------------------------------------------------------- #


def _reserved_vlan_plan(event_id: str) -> dict[str, Any]:
    return base_plan(
        event_id,
        [{
            "name": "Gi1/0/1",
            "settings": {
                "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 1002],
            },
        }],
        vlans=[
            {"id": 10, "name": "Management", "purpose": "management"},
            {"id": 1002, "name": "ReservedRange", "purpose": "ordinary"},
        ],
    )


def test_reserved_vlan_blocks_definition_and_name() -> None:
    document = render([_reserved_vlan_plan(str(uuid4()))])
    target = all_candidates(document, "VLAN 1002")
    assert target
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in target)
    assert all(candidate.candidate_text is None for candidate in target)
    assert all("target-invalid:vlan-reserved:1002" in reasons_text(candidate)
               for candidate in target)
    assert {candidate.category for candidate in target} == {
        CandidateCategory.VLAN_DEFINITION
    }


def test_reserved_vlan_category_filter_cannot_bypass_target_validation() -> None:
    built = render([_reserved_vlan_plan(str(uuid4()))])
    filtered = renderer._filter_categories(  # noqa: SLF001 - targeted regression
        built.candidates, (CandidateCategory.VLAN_DEFINITION,),
    )
    target = [candidate for candidate in filtered if candidate.target.name == "VLAN 1002"]
    assert target
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in target)
    assert all(candidate.candidate_text is None for candidate in target)


def test_default_vlan_is_never_modified() -> None:
    plan = base_plan(
        str(uuid4()),
        [{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 1}}],
        vlans=[
            {"id": 1, "name": "Default", "purpose": "ordinary"},
            {"id": 10, "name": "Management", "purpose": "management"},
        ],
    )
    document = render([plan])
    target = all_candidates(document, "VLAN 1")
    assert target
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in target)
    assert all("target-invalid:vlan-default:1" in reasons_text(candidate)
               for candidate in target)
    assert all(candidate.candidate_text is None for candidate in target)


def test_valid_vlan_target_and_name_render() -> None:
    plan = base_plan(
        str(uuid4()),
        [{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
        vlans=[
            {"id": 10, "name": "Management", "purpose": "management"},
            {"id": 20, "name": "Players_2F", "purpose": "ordinary"},
        ],
    )
    document = render([plan])
    target = all_candidates(document, "VLAN 20")
    rendered = [
        candidate.candidate_text for candidate in target
        if candidate.status is CandidateStatus.CANDIDATE
    ]
    assert "vlan 20" in rendered
    assert "name Players_2F" in rendered
    assert not any("target-invalid" in reasons_text(candidate) for candidate in target)


def test_port_channel_above_reviewed_range_blocks_every_subcommand() -> None:
    plan = base_plan(
        str(uuid4()),
        [{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
    )
    add_channel(plan, 49, [0], {
        "mode": "access", "access_vlan": 20, "description": "channel 49",
        "admin_state": "up", "portfast": "edge", "bpdu_guard": "enabled",
    })
    document = render([plan])
    target = all_candidates(document, "Port-channel49")
    assert {candidate.category for candidate in target} >= {
        CandidateCategory.PORT_CHANNEL,
        CandidateCategory.ACCESS_MODE,
        CandidateCategory.ACCESS_VLAN,
        CandidateCategory.DESCRIPTION,
        CandidateCategory.PORTFAST,
        CandidateCategory.BPDU_GUARD,
        CandidateCategory.ADMIN_SHUTDOWN,
    }
    for candidate in target:
        assert candidate.status is not CandidateStatus.CANDIDATE, candidate.category
        assert candidate.candidate_text is None, candidate.category
        assert "target-invalid:port-channel-number:49:48" in reasons_text(candidate), (
            candidate.category, candidate.blocking_reasons,
        )


def test_port_channel_within_reviewed_range_renders_subcommands() -> None:
    plan = base_plan(
        str(uuid4()),
        [{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
    )
    add_channel(plan, 48, [0], {
        "mode": "access", "access_vlan": 20, "admin_state": "up",
    })
    document = render([plan])
    target = all_candidates(document, "Port-channel48")
    rendered = [
        candidate.candidate_text for candidate in target
        if candidate.status is CandidateStatus.CANDIDATE
    ]
    assert "interface Port-Channel48" in rendered
    assert "switchport mode access" in rendered
    assert "switchport access vlan 20" in rendered


def test_port_channel_number_limit_is_platform_specific() -> None:
    # Catalyst 3850 reviews a 1-128 range, so the same number is a valid target
    # and only capability evidence (not the target) decides the sub-command.
    plan = base_plan(
        str(uuid4()),
        [{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
        pid="WS-C3850-24P",
    )
    plan["assignments"][0]["family"] = "catalyst-3850"
    plan["assignments"][0]["software"] = {"image": "16.12.12", "license": "IP Base"}
    add_channel(plan, 49, [0], {
        "mode": "access", "access_vlan": 20, "description": "channel 49",
    })
    document = render([plan])
    target = all_candidates(document, "Port-channel49")
    assert target
    assert not any("target-invalid" in reasons_text(candidate) for candidate in target)
    assert any(
        candidate.status is CandidateStatus.CANDIDATE
        and candidate.category is CandidateCategory.DESCRIPTION
        for candidate in target
    )


def test_unknown_port_channel_range_fails_closed() -> None:
    rows = tuple(
        row for row in ROWS
        if not (
            row.family.value == "catalyst-9300"
            and row.topic.value == "port-channel-interface"
        )
    )
    registry = harness_registry(rows)
    plan = base_plan(
        str(uuid4()),
        [{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
    )
    add_channel(plan, 1, [0], {
        "mode": "access", "access_vlan": 20, "description": "channel 1",
    })
    document = render_with_registry([plan], registry)
    target = all_candidates(document, "Port-channel1")
    assert target
    description = [
        candidate for candidate in target
        if candidate.category is CandidateCategory.DESCRIPTION
    ]
    assert description
    assert description[0].status is CandidateStatus.BLOCKED
    # With no reviewed parent row at all, round-4 resolution reports the exact
    # missing-evidence diagnosis instead of a generic unknown-range code.
    assert "syntax-evidence-missing:port-channel-interface" in (
        description[0].blocking_reasons
    )


# --------------------------------------------------------------------------- #
# P2-07 PortFast / BPDU Guard topology roles
# --------------------------------------------------------------------------- #


def _link_plan(event_id: str) -> dict[str, Any]:
    plan = base_plan(event_id, [
        {"name": "Gi1/0/1", "settings": {
            "mode": "access", "access_vlan": 20, "portfast": "edge",
            "bpdu_guard": "enabled",
        }},
        {"name": "Gi1/0/2", "settings": {"mode": "trunk", "native_vlan": 10,
                                         "allowed_vlans": [10, 20]}},
    ])
    plan["links"] = [{
        "id": new_id(),
        "endpoints": [
            plan["physical_interfaces"][0]["id"],
            plan["physical_interfaces"][1]["id"],
        ],
    }]
    return plan


def test_planned_link_blocks_portfast_and_bpdu_guard() -> None:
    document = render([_link_plan(str(uuid4()))])
    portfast = of(document, "Gi1/0/1", {CandidateCategory.PORTFAST})
    guard = of(document, "Gi1/0/1", {CandidateCategory.BPDU_GUARD})
    assert portfast and guard
    for candidate, prefix in ((portfast[0], "portfast"), (guard[0], "bpdu-guard")):
        assert candidate.status is CandidateStatus.BLOCKED
        assert candidate.candidate_text is None
        assert candidate.risk_class is RiskClass.R5
        assert candidate.requires_field_verification is True
        assert f"{prefix}-non-edge-topology:link:Gi1/0/1" in candidate.blocking_reasons
    # Unrelated per-port configuration on the same link port is not collateral.
    assert of(document, "Gi1/0/1", {CandidateCategory.ACCESS_VLAN})[0].status in {
        CandidateStatus.CANDIDATE, CandidateStatus.BLOCKED,
    }


def test_isp_referenced_port_blocks_edge_features() -> None:
    plan = base_plan(str(uuid4()), [
        {"name": "Gi1/0/1", "settings": {
            "mode": "access", "access_vlan": 20, "portfast": "edge",
            "bpdu_guard": "enabled",
        }},
    ])
    plan["isps"] = [{
        "id": new_id(), "name": "ISP-A",
        "assignment_id": plan["assignments"][0]["id"],
        "interface_id": plan["physical_interfaces"][0]["id"],
        "address": "198.51.100.2/30", "gateway": "198.51.100.1",
    }]
    document = render([plan])
    for category, prefix in (
        (CandidateCategory.PORTFAST, "portfast"),
        (CandidateCategory.BPDU_GUARD, "bpdu-guard"),
    ):
        found = of(document, "Gi1/0/1", {category})
        assert found and found[0].status is CandidateStatus.BLOCKED
        assert f"{prefix}-non-edge-topology:isp:Gi1/0/1" in found[0].blocking_reasons


def test_transit_port_blocks_edge_features() -> None:
    plan = base_plan(str(uuid4()), [
        {"name": "Gi1/0/1", "settings": {
            "mode": "access", "access_vlan": 20, "portfast": "edge",
            "bpdu_guard": "enabled",
        }},
    ])
    assignment_id = plan["assignments"][0]["id"]
    core_svi = new_id()
    hillstone_assignment = new_id()
    plan["logical_interfaces"] = [{
        "id": core_svi, "assignment_id": assignment_id,
        "name": "Vlan9", "kind": "svi", "vlan": 9,
    }]
    plan["transit"] = {
        "core_assignment_id": assignment_id,
        "hillstone_assignment_id": hillstone_assignment,
        "core_port_id": plan["physical_interfaces"][0]["id"],
        "hillstone_port_id": new_id(),
        "core_svi_id": core_svi,
        "vlan": 9,
        "network": "192.0.2.0/30",
        "core_ip": "192.0.2.1",
        "hillstone_ip": "192.0.2.2",
    }
    document = render([plan])
    for category, prefix in (
        (CandidateCategory.PORTFAST, "portfast"),
        (CandidateCategory.BPDU_GUARD, "bpdu-guard"),
    ):
        found = of(document, "Gi1/0/1", {category})
        assert found and found[0].status is CandidateStatus.BLOCKED
        assert f"{prefix}-non-edge-topology:transit:Gi1/0/1" in found[0].blocking_reasons


def test_channel_member_and_logical_channel_block_edge_features() -> None:
    plan = base_plan(str(uuid4()), [
        {"name": "Gi1/0/1", "settings": {
            "mode": "access", "access_vlan": 20, "portfast": "edge",
            "bpdu_guard": "enabled",
        }},
    ])
    add_channel(plan, 1, [0], {
        "mode": "access", "access_vlan": 20, "portfast": "edge",
        "bpdu_guard": "enabled",
    })
    document = render([plan])
    member_portfast = of(document, "Gi1/0/1", {CandidateCategory.PORTFAST})
    member_guard = of(document, "Gi1/0/1", {CandidateCategory.BPDU_GUARD})
    channel_portfast = of(document, "Port-channel1", {CandidateCategory.PORTFAST})
    channel_guard = of(document, "Port-channel1", {CandidateCategory.BPDU_GUARD})
    assert member_portfast and member_guard
    assert channel_portfast and channel_guard
    assert member_portfast[0].status is CandidateStatus.BLOCKED
    assert "portfast-aggregate-member-role-unverified:Gi1/0/1" in (
        member_portfast[0].blocking_reasons
    )
    assert member_guard[0].status is CandidateStatus.BLOCKED
    assert "bpdu-guard-aggregate-member-role-unverified:Gi1/0/1" in (
        member_guard[0].blocking_reasons
    )
    assert channel_portfast[0].status is CandidateStatus.BLOCKED
    assert "portfast-aggregate-role-unverified:Port-channel1" in (
        channel_portfast[0].blocking_reasons
    )
    assert channel_guard[0].status is CandidateStatus.BLOCKED
    assert "bpdu-guard-aggregate-role-unverified:Port-channel1" in (
        channel_guard[0].blocking_reasons
    )


def test_core_role_device_blocks_edge_features() -> None:
    plan = base_plan(str(uuid4()), [
        {"name": "Gi1/0/1", "settings": {
            "mode": "access", "access_vlan": 20, "portfast": "edge",
            "bpdu_guard": "enabled",
        }},
    ])
    plan["assignments"][0]["role"] = "core"
    document = render([plan])
    portfast = of(document, "Gi1/0/1", {CandidateCategory.PORTFAST})
    guard = of(document, "Gi1/0/1", {CandidateCategory.BPDU_GUARD})
    assert portfast and guard
    assert portfast[0].status is CandidateStatus.BLOCKED
    assert "portfast-core-role-unverified:Gi1/0/1" in portfast[0].blocking_reasons
    assert guard[0].status is CandidateStatus.BLOCKED
    assert "bpdu-guard-core-role-unverified:Gi1/0/1" in guard[0].blocking_reasons


def test_unreferenced_access_port_keeps_an_unverified_edge_candidate() -> None:
    plan = base_plan(str(uuid4()), [
        {"name": "Gi1/0/1", "settings": {
            "mode": "access", "access_vlan": 20, "portfast": "edge",
            "bpdu_guard": "enabled",
        }},
    ])
    document = render([plan])
    portfast = of(document, "Gi1/0/1", {CandidateCategory.PORTFAST})
    guard = of(document, "Gi1/0/1", {CandidateCategory.BPDU_GUARD})
    assert portfast and guard
    assert portfast[0].status is CandidateStatus.CANDIDATE
    assert portfast[0].candidate_text == "spanning-tree portfast"
    assert portfast[0].requires_field_verification is True
    assert "field-note:portfast-topology-note" in portfast[0].prerequisites
    assert guard[0].status is CandidateStatus.CANDIDATE
    assert guard[0].candidate_text == "spanning-tree bpduguard enable"
    assert guard[0].requires_field_verification is True
    assert "field-note:bpdu-guard-topology-note" in guard[0].prerequisites


def test_unreferenced_trunk_port_keeps_edge_trunk_candidate() -> None:
    plan = base_plan(str(uuid4()), [
        {"name": "Gi1/0/1", "settings": {
            "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
            "portfast": "edge-trunk",
        }},
    ])
    document = render([plan])
    portfast = of(document, "Gi1/0/1", {CandidateCategory.PORTFAST})
    assert portfast and portfast[0].status is CandidateStatus.CANDIDATE
    assert portfast[0].candidate_text == "spanning-tree portfast trunk"


# --------------------------------------------------------------------------- #
# P2-08 aggregation protocol and channel identity
# --------------------------------------------------------------------------- #


def _channel_plan(event_id: str, lacp: str) -> dict[str, Any]:
    plan = base_plan(event_id, [
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    add_channel(plan, 1, [0], {"mode": "access", "access_vlan": 20}, lacp=lacp)
    return plan


@pytest.mark.parametrize(("before_lacp", "after_lacp"), [
    ("static", "active"),
    ("active", "static"),
    ("static", "passive"),
])
def test_protocol_switch_between_static_and_lacp_blocks(
    before_lacp: str, after_lacp: str,
) -> None:
    first = _channel_plan(str(uuid4()), before_lacp)
    second = copy.deepcopy(first)
    second["port_channels"][0]["lacp"] = after_lacp
    document = render([first, second])
    target = of(document, "Gi1/0/1", CHANNEL_CATEGORIES)
    assert target
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in target)
    assert all(candidate.candidate_text is None for candidate in target)
    assert all(
        "aggregation-protocol-change-requires-field-evidence" in reasons_text(candidate)
        for candidate in target
    )


def test_active_to_passive_requires_peer_evidence_but_is_not_claimed_safe() -> None:
    first = _channel_plan(str(uuid4()), "active")
    second = copy.deepcopy(first)
    second["port_channels"][0]["lacp"] = "passive"
    document = render([first, second])
    target = [
        candidate for candidate in of(document, "Gi1/0/1", CHANNEL_CATEGORIES)
        if candidate.candidate_text is not None
    ]
    assert [candidate.candidate_text for candidate in target] == [
        "channel-group 1 mode passive"
    ]
    assert "lacp-negotiation-change-requires-peer-evidence" in target[0].prerequisites
    assert target[0].requires_field_verification is True
    assert target[0].risk_class is RiskClass.R3
    assert "aggregation-protocol-change-requires-field-evidence" not in (
        target[0].blocking_reasons
    )


def test_unchanged_protocol_is_not_flagged() -> None:
    first = base_plan(str(uuid4()), [
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/2", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20}, lacp="active")
    second = copy.deepcopy(first)
    # Only the member set changes; the protocol of the existing member stays.
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    document = render([first, second])
    existing = [
        candidate for candidate in of(document, "Gi1/0/1", CHANNEL_CATEGORIES)
        if candidate.candidate_text is not None
    ]
    assert existing
    assert "aggregation-protocol-change-requires-field-evidence" not in (
        existing[0].blocking_reasons
    )
    added = [
        candidate for candidate in of(document, "Gi1/0/2", CHANNEL_CATEGORIES)
        if candidate.candidate_text is not None
    ]
    assert added and added[0].candidate_text == "channel-group 1 mode active"


def test_replaced_channel_object_blocks_member_channel_group() -> None:
    first = _channel_plan(str(uuid4()), "active")
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    add_channel(second, 1, [0], {"mode": "access", "access_vlan": 20}, lacp="active")
    assert first["logical_interfaces"][0]["id"] != second["logical_interfaces"][0]["id"]
    document = render([first, second])
    target = of(document, "Gi1/0/1", CHANNEL_CATEGORIES)
    assert target
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in target)
    assert all(candidate.candidate_text is None for candidate in target)
    assert all(
        "channel-object-identity-changed" in reasons_text(candidate)
        for candidate in target
    )


def test_combined_protocol_membership_and_number_change_blocks() -> None:
    first = base_plan(str(uuid4()), [
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/2", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20}, lacp="static")
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    add_channel(second, 2, [1], {"mode": "access", "access_vlan": 20}, lacp="active")
    document = render([first, second])
    # The member that leaves the old aggregate is blocked; the old channel object
    # is a baseline-only removal and never produces cleanup text.
    removed = of(document, "Gi1/0/1", CHANNEL_CATEGORIES)
    assert removed
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in removed)
    assert all(candidate.candidate_text is None for candidate in removed)
    old_channel = of(document, "Port-channel1", CHANNEL_CATEGORIES)
    assert old_channel
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in old_channel)
    # A newly added member of the new object may render: creating a new aggregate
    # is not a protocol switch of an existing one.
    added = [
        candidate for candidate in of(document, "Gi1/0/2", CHANNEL_CATEGORIES)
        if candidate.candidate_text is not None
    ]
    assert added and added[0].candidate_text == "channel-group 2 mode active"
    assert not [text for text in (
        candidate.candidate_text for candidate in document.candidates
    ) if text is not None and text.casefold().startswith("no ")]


def test_channel_group_paths_and_category_filter_agree() -> None:
    first = _channel_plan(str(uuid4()), "static")
    second = copy.deepcopy(first)
    second["port_channels"][0]["lacp"] = "active"
    built = render([first, second])
    filtered = renderer._filter_categories(  # noqa: SLF001 - targeted regression
        built.candidates, (CandidateCategory.LACP_MODE, CandidateCategory.PORT_CHANNEL),
    )
    unfiltered_member = {
        (candidate.candidate_id, candidate.status)
        for candidate in built.candidates
        if candidate.target.name == "Gi1/0/1"
        and candidate.category in CHANNEL_CATEGORIES
    }
    filtered_member = {
        (candidate.candidate_id, candidate.status)
        for candidate in filtered
        if candidate.target.name == "Gi1/0/1"
    }
    assert filtered_member
    assert filtered_member <= unfiltered_member
    assert all(status is CandidateStatus.BLOCKED for _id, status in filtered_member)


def test_no_baseline_cleanup_command_is_rendered() -> None:
    first = _channel_plan(str(uuid4()), "static")
    second = copy.deepcopy(first)
    second["port_channels"][0]["lacp"] = "active"
    document = render([first, second])
    for candidate in document.candidates:
        if candidate.candidate_text is not None:
            assert not candidate.candidate_text.casefold().startswith("no ")


# --------------------------------------------------------------------------- #
# Evidence diagnosis accuracy
# --------------------------------------------------------------------------- #


def render_with_registry(plans: list[dict[str, Any]], registry: Any) -> Any:
    built = [_revision(item, index + 1) for index, item in enumerate(plans)]
    current = built[-1]
    baseline = built[-2] if len(built) > 1 else None
    intent = build_layer2_intent(current, baseline)
    preview = build_device_layer2_config_preview(
        current, intent, current.plan.assignments[0].id,
    )
    return build_l2_cli_candidates(current, intent, preview, registry=registry)


def _stale_registry(topic: str = "vlan", family: str = "catalyst-9300") -> Any:
    registry = harness_registry()
    row = next(
        item for item in registry.rows
        if item.topic.value == topic and item.family.value == family
    )
    tampered = dataclasses.replace(row, grammar=row.grammar + " changed")
    return CommandEvidenceRegistry(tuple(
        tampered if item.evidence_id == row.evidence_id else item
        for item in registry.rows
    ))


def test_renderer_reports_content_mismatch_not_not_reviewed() -> None:
    plan = base_plan(str(uuid4()), [
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    document = render_with_registry([plan], _stale_registry())
    target = of(document, "VLAN 20", {CandidateCategory.VLAN_DEFINITION})
    assert target
    definition = [
        candidate for candidate in target
        if candidate.candidate_text is None
        and candidate.parameters.get("vlan-id") == 20
    ]
    assert definition
    reasons = reasons_text(definition[0])
    assert "syntax-evidence-content-mismatch:vlan" in reasons
    assert "syntax-evidence-not-reviewed" not in reasons


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "round3.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as session:
        yield session


def test_api_reports_content_mismatch_for_the_affected_topic(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_layer2_intent import event, save

    event_id = event(client, "round3 diagnosis")
    plan = base_plan(event_id, [
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    revision = save(client, event_id, plan)
    stale = _stale_registry()

    original = cast(Any, plan_api).build_l2_cli_candidates

    def injected(revision: Any, intent: Any, preview: Any, *,
                 categories: Any = None, registry: Any = None) -> Any:
        return original(
            revision, intent, preview, categories=categories, registry=stale,
        )

    monkeypatch.setattr(plan_api, "build_l2_cli_candidates", injected)
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{plan['assignments'][0]['id']}/l2-cli-candidates"
    )
    assert response.status_code == 200, response.text
    candidates = cast(list[dict[str, Any]], response.json()["candidates"])
    vlan = [
        candidate for candidate in candidates
        if candidate["target"]["name"] == "VLAN 20"
        and candidate["category"] == "vlan-definition"
        and candidate["parameters"].get("vlan-id") == 20
    ]
    assert vlan
    reasons = " ".join(cast(list[str], vlan[0]["blocking_reasons"]))
    assert "syntax-evidence-content-mismatch:vlan" in reasons
    assert "syntax-evidence-not-reviewed" not in reasons
