"""CIS-02B2-02 round-4 regressions: parent evidence and aggregate protocol.

Covers P2-09 (the Port-Channel parent configuration-mode evidence must be unique,
renderable and digest-valid before any child or member command renders) and
P2-10 (an aggregate-level protocol or identity change propagates to newly added
members that have no previous membership of their own).
"""

from __future__ import annotations

import copy
import dataclasses
from typing import Any

import pytest
from test_l2_cli_candidate_review_fixes import (
    CHANNEL_CATEGORIES,
    _revision,
    add_channel,
    base_plan,
    harness_registry,
    new_id,
    of,
    render,
)

from event_switch_manager.planning import layer2_cli_candidates as renderer
from event_switch_manager.planning.command_evidence import (
    PENDING_REVIEW,
    REJECTED_REVIEW,
    CommandEvidence,
    CommandEvidenceRegistry,
    EvidenceReview,
    EvidenceReviewState,
)
from event_switch_manager.planning.layer2_cli_candidates import (
    Candidate,
    CandidateCategory,
    CandidateStatus,
    RiskClass,
)
from event_switch_manager.planning.layer2_config_preview import (
    build_device_layer2_config_preview,
)
from event_switch_manager.planning.layer2_intent import build_layer2_intent

PARENT_TOPIC = "port-channel-interface"


def _parent_row(registry: CommandEvidenceRegistry) -> CommandEvidence:
    return next(
        row for row in registry.rows
        if row.family.value == "catalyst-9300" and row.topic.value == PARENT_TOPIC
    )


def _reviewed(row: CommandEvidence) -> CommandEvidence:
    return dataclasses.replace(
        row,
        review=EvidenceReview(
            EvidenceReviewState.REVIEWED, "harness", "2026-11-20",
            ("harness",), row.content_digest,
        ),
    )


def _with_parent(
    state: str, base: CommandEvidenceRegistry | None = None,
) -> CommandEvidenceRegistry:
    registry = base or harness_registry()
    parent = _parent_row(registry)
    if state == "pending":
        changed = dataclasses.replace(parent, review=PENDING_REVIEW)
    elif state == "rejected":
        changed = dataclasses.replace(parent, review=REJECTED_REVIEW)
    elif state == "mismatch":
        changed = dataclasses.replace(parent, grammar=parent.grammar + " changed")
    elif state == "missing":
        return CommandEvidenceRegistry(tuple(
            row for row in registry.rows
            if not (
                row.family.value == "catalyst-9300"
                and row.topic.value == PARENT_TOPIC
            )
        ))
    elif state == "ambiguous":
        duplicate = _reviewed(dataclasses.replace(
            parent, evidence_id=parent.evidence_id + "-dup",
        ))
        return CommandEvidenceRegistry((*registry.rows, duplicate))
    else:
        raise AssertionError(state)
    return CommandEvidenceRegistry(tuple(
        changed if row.evidence_id == parent.evidence_id else row
        for row in registry.rows
    ))


def _render_with(plan: dict[str, Any], registry: CommandEvidenceRegistry) -> Any:
    revision = _revision(plan, 1)
    intent = build_layer2_intent(revision, None)
    preview = build_device_layer2_config_preview(
        revision, intent, revision.plan.assignments[0].id,
    )
    return renderer.build_l2_cli_candidates(
        revision, intent, preview, registry=registry,
    )


def _channel_plan(event_id: str, *, number: int = 1) -> dict[str, Any]:
    plan = base_plan(event_id, [
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    add_channel(plan, number, [0], {
        "mode": "access", "access_vlan": 20, "description": "channel one",
    })
    return plan


def _has_reason(candidate: Candidate, prefix: str) -> bool:
    return any(reason.startswith(prefix) for reason in candidate.blocking_reasons)


PARENT_DIAGNOSIS = {
    "pending": "syntax-evidence-not-reviewed:port-channel-interface",
    "rejected": "syntax-evidence-rejected:port-channel-interface",
    "mismatch": "syntax-evidence-content-mismatch:port-channel-interface",
    "ambiguous": "syntax-evidence-ambiguous:port-channel-interface",
    "missing": "syntax-evidence-missing:port-channel-interface",
}


# --------------------------------------------------------------------------- #
# P2-09 parent configuration-mode evidence
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("state", list(PARENT_DIAGNOSIS))
def test_invalid_parent_evidence_blocks_every_port_channel_candidate(
    state: str,
) -> None:
    registry = _with_parent(state)
    plan = base_plan(new_id(), [
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    add_channel(plan, 1, [0], {
        "mode": "access", "access_vlan": 20, "description": "channel one",
    })
    document = _render_with(plan, registry)
    channel_candidates = [
        candidate for candidate in document.candidates
        if candidate.target.name == "Port-channel1"
    ]
    member_candidates = [
        candidate for candidate in document.candidates
        if candidate.target.name == "Gi1/0/1"
        and "channel-group" in str(candidate.candidate_text)
        or (
            candidate.target.name == "Gi1/0/1"
            and candidate.category in CHANNEL_CATEGORIES
            and candidate.parameters.get("port-channel-number") == 1
        )
    ]
    assert channel_candidates, state
    expected = PARENT_DIAGNOSIS[state]
    for candidate in (*channel_candidates, *member_candidates):
        assert candidate.status is not CandidateStatus.CANDIDATE, (
            state, candidate.category,
        )
        assert candidate.candidate_text is None, (state, candidate.category)
        assert expected in candidate.blocking_reasons, (
            state, candidate.category, candidate.blocking_reasons,
        )
    # The physical port's own, unrelated layer-2 configuration is not collateral.
    unrelated = of(document, "Gi1/0/1", {CandidateCategory.ACCESS_VLAN})
    assert unrelated and unrelated[0].status is CandidateStatus.CANDIDATE


def test_child_evidence_cannot_substitute_for_the_parent_mode() -> None:
    registry = _with_parent("pending")
    document = _render_with(_channel_plan(new_id()), registry)
    description = of(document, "Port-channel1", {CandidateCategory.DESCRIPTION})
    assert description
    candidate = description[0]
    # Its own topic evidence is reviewed and cited ...
    assert candidate.syntax_evidence
    assert candidate.syntax_evidence[0].evidence_id == "l1-catalyst-9300-description-v1"
    # ... yet the parent configuration-mode failure still blocks the command.
    assert candidate.status is CandidateStatus.BLOCKED
    assert candidate.candidate_text is None
    assert "syntax-evidence-not-reviewed:port-channel-interface" in (
        candidate.blocking_reasons
    )


def test_category_filter_cannot_bypass_parent_evidence_failure() -> None:
    registry = _with_parent("mismatch")
    document = _render_with(_channel_plan(new_id()), registry)
    filtered = renderer._filter_categories(  # noqa: SLF001 - targeted regression
        document.candidates,
        (CandidateCategory.DESCRIPTION, CandidateCategory.PORT_CHANNEL),
    )
    assert filtered
    assert all(candidate.status is not CandidateStatus.CANDIDATE for candidate in filtered)
    assert all(candidate.candidate_text is None for candidate in filtered)


def test_valid_parent_evidence_keeps_port_channel_candidates() -> None:
    registry = harness_registry()
    document = _render_with(_channel_plan(new_id()), registry)
    rendered = {
        candidate.candidate_text for candidate in document.candidates
        if candidate.target.name == "Port-channel1"
        and candidate.status is CandidateStatus.CANDIDATE
    }
    assert "interface Port-Channel1" in rendered
    assert "switchport mode access" in rendered
    assert "switchport access vlan 20" in rendered


def test_valid_parent_evidence_keeps_3850_channel_description() -> None:
    registry = harness_registry()
    plan = base_plan(
        new_id(),
        [{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
        pid="WS-C3850-24P",
    )
    plan["assignments"][0]["family"] = "catalyst-3850"
    plan["assignments"][0]["software"] = {"image": "16.12.12", "license": "IP Base"}
    add_channel(plan, 49, [0], {
        "mode": "access", "access_vlan": 20, "description": "channel 49",
    })
    document = _render_with(plan, registry)
    description = of(document, "Port-channel49", {CandidateCategory.DESCRIPTION})
    assert description
    assert description[0].status is CandidateStatus.CANDIDATE
    assert description[0].candidate_text == "description channel 49"
    assert not any(
        "target-invalid" in reason for reason in description[0].blocking_reasons
    )


# --------------------------------------------------------------------------- #
# P2-10 aggregate-level protocol and identity
# --------------------------------------------------------------------------- #


def _two_member_plan(event_id: str, lacp: str) -> dict[str, Any]:
    plan = base_plan(event_id, [
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/2", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    add_channel(plan, 1, [0], {"mode": "access", "access_vlan": 20}, lacp=lacp)
    return plan


def _member_channel_group(document: Any, names: set[str]) -> list[Candidate]:
    return [
        candidate for candidate in document.candidates
        if candidate.target.name in names
        and candidate.category in CHANNEL_CATEGORIES
        and candidate.parameters.get("port-channel-number") is not None
    ]


@pytest.mark.parametrize(("before_lacp", "after_lacp"), [
    ("static", "active"),
    ("static", "passive"),
    ("active", "static"),
    ("passive", "static"),
])
def test_aggregate_protocol_switch_reaches_a_newly_added_member(
    before_lacp: str, after_lacp: str,
) -> None:
    first = _two_member_plan(new_id(), before_lacp)
    second = copy.deepcopy(first)
    second["port_channels"][0]["lacp"] = after_lacp
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    document = render([first, second])
    members = _member_channel_group(document, {"Gi1/0/1", "Gi1/0/2"})
    assert members
    for candidate in members:
        assert candidate.status is CandidateStatus.BLOCKED, candidate.target.name
        assert candidate.candidate_text is None
        assert _has_reason(
            candidate, "aggregation-protocol-change-requires-field-evidence",
        )
    assert all(
        "no " not in str(candidate.candidate_text) for candidate in document.candidates
    )


def test_aggregate_protocol_switch_after_replacing_all_members_blocks_all() -> None:
    first = _two_member_plan(new_id(), "static")
    second = copy.deepcopy(first)
    # Keep the same logical object but replace every member and the protocol.
    second["port_channels"][0]["lacp"] = "active"
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][1]["id"],
        first["physical_interfaces"][0]["id"],
    ]
    document = render([first, second])
    members = _member_channel_group(document, {"Gi1/0/1", "Gi1/0/2"})
    assert members
    for candidate in members:
        assert candidate.status is CandidateStatus.BLOCKED
        assert candidate.candidate_text is None
        assert _has_reason(
            candidate, "aggregation-protocol-change-requires-field-evidence",
        )


def test_same_number_object_rebuild_reaches_every_member() -> None:
    first = _two_member_plan(new_id(), "active")
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    add_channel(second, 1, [1], {"mode": "access", "access_vlan": 20}, lacp="active")
    assert first["logical_interfaces"][0]["id"] != second["logical_interfaces"][0]["id"]
    document = render([first, second])
    new_member = _member_channel_group(document, {"Gi1/0/2"})
    assert new_member
    assert new_member[0].status is CandidateStatus.BLOCKED
    assert new_member[0].candidate_text is None
    assert _has_reason(new_member[0], "channel-object-identity-changed")


def test_active_to_passive_with_added_member_marks_risk_consistently() -> None:
    first = _two_member_plan(new_id(), "active")
    second = copy.deepcopy(first)
    second["port_channels"][0]["lacp"] = "passive"
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    document = render([first, second])
    members = _member_channel_group(document, {"Gi1/0/1", "Gi1/0/2"})
    assert members
    for candidate in members:
        assert candidate.status is CandidateStatus.CANDIDATE
        assert candidate.risk_class is RiskClass.R3
        assert candidate.requires_field_verification is True
        assert "lacp-negotiation-change-requires-peer-evidence" in (
            candidate.prerequisites
        )
        assert not _has_reason(
            candidate, "aggregation-protocol-change-requires-field-evidence",
        )


def test_unchanged_protocol_with_added_member_keeps_candidates() -> None:
    first = _two_member_plan(new_id(), "active")
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    document = render([first, second])
    members = _member_channel_group(document, {"Gi1/0/1", "Gi1/0/2"})
    assert members
    for candidate in members:
        assert candidate.status is CandidateStatus.CANDIDATE
        assert candidate.candidate_text == "channel-group 1 mode active"
        assert candidate.blocking_reasons == ()


def test_a_genuinely_new_aggregate_keeps_its_members() -> None:
    event_id = new_id()
    first = base_plan(event_id, [
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
        {"name": "Gi1/0/2", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    second = copy.deepcopy(first)
    add_channel(second, 5, [0, 1], {"mode": "access", "access_vlan": 20}, lacp="active")
    document = render([first, second])
    members = _member_channel_group(document, {"Gi1/0/1", "Gi1/0/2"})
    assert members
    for candidate in members:
        assert candidate.status is CandidateStatus.CANDIDATE
        assert candidate.candidate_text == "channel-group 5 mode active"
        assert candidate.blocking_reasons == ()


def test_protocol_switch_category_filter_and_paths_agree() -> None:
    first = _two_member_plan(new_id(), "static")
    second = copy.deepcopy(first)
    second["port_channels"][0]["lacp"] = "active"
    second["port_channels"][0]["member_ids"] = [
        first["physical_interfaces"][0]["id"],
        first["physical_interfaces"][1]["id"],
    ]
    document = render([first, second])
    unfiltered = {
        (candidate.candidate_id, candidate.status)
        for candidate in _member_channel_group(document, {"Gi1/0/1", "Gi1/0/2"})
    }
    assert unfiltered
    filtered = renderer._filter_categories(  # noqa: SLF001 - targeted regression
        document.candidates,
        (CandidateCategory.LACP_MODE, CandidateCategory.PORT_CHANNEL),
    )
    filtered_members = {
        (candidate.candidate_id, candidate.status)
        for candidate in filtered
        if candidate.target.name in {"Gi1/0/1", "Gi1/0/2"}
        and (candidate.candidate_id, candidate.status) in unfiltered
    }
    assert filtered_members == unfiltered
    assert all(status is CandidateStatus.BLOCKED for _id, status in filtered_members)
