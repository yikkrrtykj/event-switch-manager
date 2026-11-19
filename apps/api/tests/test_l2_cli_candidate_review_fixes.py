"""CIS-02B2-02 independent-review fix regressions.

Covers the six findings: member-migration bypass (P2-01), mode-transition
propagation (P2-02), Port-Channel admin-state protection (P2-03), evidence
content/review digest binding (P2-04), structured vendor-limit gates (P2-05) and
the syntax-validation state (P3-01). Migration scenarios build two real saved
revisions with stable interface UUIDs, so the renderer sees a planning baseline.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from event_switch_manager.domain import DeviceFamily
from event_switch_manager.planning import layer2_cli_candidates as renderer
from event_switch_manager.planning.command_evidence import (
    BLOCKING_REQUIREMENT_CODES,
    PENDING_REVIEW,
    ROWS,
    CommandEvidence,
    CommandEvidenceRegistry,
    CommandTopic,
    EvidenceReview,
    EvidenceReviewState,
    evidence_content_digest,
)
from event_switch_manager.planning.layer2_cli_candidates import (
    Candidate,
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

HarnessRows = tuple[CommandEvidence, ...]


def new_id() -> str:
    return str(uuid4())


def _revision(plan: dict[str, Any], number: int) -> PlanRevision:
    event_plan = EventPlan.model_validate(plan)
    return PlanRevision(
        id=UUID(new_id()), number=number, created_at=datetime.now(UTC),
        content_hash=plan_hash(canonical_plan(event_plan)), schema_version=1,
        plan=event_plan, warnings=(), validation_errors=(),
        validation_status="VALID_WITH_WARNINGS",
    )


def render_revisions(built: list[PlanRevision]) -> Any:
    current = built[-1]
    baseline = built[-2] if len(built) > 1 else None
    intent = build_layer2_intent(current, baseline)
    preview = build_device_layer2_config_preview(
        current, intent, current.plan.assignments[0].id,
    )
    return build_l2_cli_candidates(current, intent, preview)


def render(plans: list[dict[str, Any]]) -> Any:
    built = [_revision(item, index + 1) for index, item in enumerate(plans)]
    return render_revisions(built)


def harness_registry(rows: HarnessRows = ROWS) -> CommandEvidenceRegistry:
    """Digest-bound records for renderer mechanics tests.

    These attestations exist only inside the test process. They are not the
    shipped review record and never authorise a real render.
    """
    return CommandEvidenceRegistry(tuple(
        dataclasses.replace(
            row,
            review=EvidenceReview(
                EvidenceReviewState.REVIEWED,
                "test-harness",
                "2026-11-20",
                ("Harness attestation bound to this content digest.",),
                row.content_digest,
            ),
        )
        for row in rows
    ))


def base_plan(
    event_id: str, ports: list[dict[str, Any]], *, pid: str = "C9300L-24P-4X",
) -> dict[str, Any]:
    device_id, assignment_id = new_id(), new_id()
    return {
        "schema_version": 1, "event_id": event_id, "management_vlan": 10,
        "vlans": [
            {"id": 10, "name": "Management", "purpose": "management"},
            {"id": 20, "name": "Players", "purpose": "ordinary"},
            {"id": 30, "name": "Guest", "purpose": "guest"},
        ],
        "physical_devices": [{
            "id": device_id, "vendor": "cisco", "model": pid,
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
                "physical_device_id": device_id, "name": port["name"],
                "settings": port["settings"],
            }
            for port in ports
        ],
    }


def add_channel(
    plan: dict[str, Any], number: int, members: list[int],
    settings: dict[str, Any], lacp: str = "active",
) -> None:
    assignment_id = plan["assignments"][0]["id"]
    logical_id = new_id()
    plan.setdefault("logical_interfaces", []).append({
        "id": logical_id, "assignment_id": assignment_id,
        "name": f"Port-channel{number}", "kind": "port-channel",
    })
    plan.setdefault("port_channels", []).append({
        "interface_id": logical_id, "number": number,
        "member_ids": [plan["physical_interfaces"][index]["id"] for index in members],
        "settings": settings, "lacp": lacp,
    })


def port(name: str, **settings: Any) -> dict[str, Any]:
    return {"name": name, "settings": {"mode": "access", "access_vlan": 20, **settings}}


def of(document: Any, name: str, categories: set[CandidateCategory]) -> list[Candidate]:
    return [
        candidate for candidate in document.candidates
        if candidate.target.name == name
        and (candidate.category in categories or not categories)
    ]


CHANNEL_CATEGORIES = {CandidateCategory.PORT_CHANNEL, CandidateCategory.LACP_MODE}


# --------------------------------------------------------------------------- #
# P2-01 cross-revision membership safety
# --------------------------------------------------------------------------- #


def test_independent_to_port_channel_renders_the_member() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1")])
    second = copy.deepcopy(first)
    add_channel(second, 1, [0], {"mode": "access", "access_vlan": 20})
    document = render([first, second])
    channel_group = [
        candidate for candidate in of(document, "Gi1/0/1", CHANNEL_CATEGORIES)
        if candidate.candidate_text is not None
    ]
    assert [candidate.candidate_text for candidate in channel_group] == [
        "channel-group 1 mode active"
    ]
    assert channel_group[0].status is CandidateStatus.CANDIDATE


def test_port_channel_to_independent_blocks_the_detach() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1")])
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    document = render([first, second])
    member = of(document, "Gi1/0/1", CHANNEL_CATEGORIES)
    assert member
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in member)
    assert all(candidate.candidate_text is None for candidate in member)
    # A detach is expressed either as the member's own cleanup record or as the
    # baseline-only removal of the interface membership item.
    assert all(
        any(
            "channel-member-detach-requires-field-evidence" in reason
            or "removal-not-rendered" in reason
            or "cleanup" in reason
            for reason in candidate.blocking_reasons
        )
        for candidate in member
    )


def test_direct_channel_to_channel_migration_blocks_every_path() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1")])
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    add_channel(second, 2, [0], {"mode": "access", "access_vlan": 20})
    document = render([first, second])
    member = of(document, "Gi1/0/1", CHANNEL_CATEGORIES)
    assert member
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in member)
    assert all(candidate.candidate_text is None for candidate in member)
    assert any(
        "channel-migration-requires-source-channel-evidence"
        in " ".join(candidate.blocking_reasons)
        for candidate in member
    )


def test_old_channel_removal_with_members_moving_to_a_new_channel() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1"), port("Gi1/0/2")])
    add_channel(first, 1, [0, 1], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    add_channel(second, 2, [0], {"mode": "access", "access_vlan": 20})
    document = render([first, second])
    for name in ("Gi1/0/1", "Gi1/0/2"):
        member = of(document, name, CHANNEL_CATEGORIES)
        assert all(candidate.status is not CandidateStatus.CANDIDATE for candidate in member)
    removed = of(document, "Port-channel1", CHANNEL_CATEGORIES)
    assert removed
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in removed)
    assert any(
        "removal-not-rendered" in candidate.blocking_reasons for candidate in removed
    )


def test_two_channels_swapping_members_blocks_both_members() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1"), port("Gi1/0/2")])
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    add_channel(first, 2, [1], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [first["physical_interfaces"][1]["id"]]
    second["port_channels"][1]["member_ids"] = [first["physical_interfaces"][0]["id"]]
    document = render([first, second])
    for name in ("Gi1/0/1", "Gi1/0/2"):
        member = of(document, name, CHANNEL_CATEGORIES)
        assert member
        assert all(candidate.status is CandidateStatus.BLOCKED for candidate in member)
        assert all(candidate.candidate_text is None for candidate in member)


def test_same_revision_lacp_and_membership_change_blocks_migrating_member() -> None:
    event_id = str(uuid4())
    first = base_plan(
        event_id, [port("Gi1/0/1"), port("Gi1/0/2"), port("Gi1/0/3")],
    )
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    add_channel(first, 2, [1, 2], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    add_channel(second, 1, [1], {"mode": "access", "access_vlan": 20}, lacp="passive")
    add_channel(second, 2, [0, 2], {"mode": "access", "access_vlan": 20})
    document = render([first, second])
    migrated = of(document, "Gi1/0/2", CHANNEL_CATEGORIES)
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in migrated)
    unchanged = [
        candidate for candidate in of(document, "Gi1/0/3", CHANNEL_CATEGORIES)
        if candidate.candidate_text is not None
    ]
    assert [candidate.candidate_text for candidate in unchanged] == [
        "channel-group 2 mode active"
    ]


def test_membership_only_change_keeps_unchanged_members_renderable() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1"), port("Gi1/0/2")])
    add_channel(first, 1, [0, 1], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [first["physical_interfaces"][0]["id"]]
    document = render([first, second])
    unchanged = [
        candidate for candidate in of(document, "Gi1/0/1", CHANNEL_CATEGORIES)
        if candidate.candidate_text is not None
    ]
    assert unchanged and unchanged[0].status is CandidateStatus.CANDIDATE
    removed = of(document, "Gi1/0/2", CHANNEL_CATEGORIES)
    assert all(candidate.status is not CandidateStatus.CANDIDATE for candidate in removed)


def test_safety_result_is_identical_across_generation_paths_and_ordering() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1"), port("Gi1/0/2")])
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    add_channel(first, 2, [1], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    # Both the LACP mode and the member set change in the same revision.
    second["port_channels"][0]["member_ids"] = [first["physical_interfaces"][1]["id"]]
    second["port_channels"][0]["lacp"] = "passive"
    built = [_revision(first, 1), _revision(second, 2)]
    document = render_revisions(built)
    again = render_revisions(built)
    assert document.render_fingerprint == again.render_fingerprint
    assert [
        (candidate.candidate_id, candidate.status, candidate.candidate_text)
        for candidate in document.candidates
    ] == [
        (candidate.candidate_id, candidate.status, candidate.candidate_text)
        for candidate in again.candidates
    ]
    for name in ("Gi1/0/1", "Gi1/0/2"):
        paths = [
            candidate for candidate in of(document, name, CHANNEL_CATEGORIES)
        ]
        assert paths
        assert {candidate.status for candidate in paths} == {CandidateStatus.BLOCKED}


def test_merged_candidate_keeps_every_source_and_fails_closed() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1")])
    second = copy.deepcopy(first)
    add_channel(second, 1, [0], {"mode": "access", "access_vlan": 20}, lacp="passive")
    document = render([first, second])
    merged = [
        candidate for candidate in of(document, "Gi1/0/1", CHANNEL_CATEGORIES)
        if candidate.candidate_text == "channel-group 1 mode passive"
    ]
    assert merged
    assert merged[0].status is CandidateStatus.CANDIDATE
    assert merged[0].provenance.additional_preview_item_ids
    assert merged[0].candidate_fingerprint


def test_merge_conflict_fails_closed() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [port("Gi1/0/1")])
    document = render([plan])
    base = next(
        candidate for candidate in document.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    )
    other = base.model_copy(update={"candidate_text": "switchport mode trunk"})
    merged = renderer._merge_group([base, other])  # noqa: SLF001 - targeted regression
    assert merged.status is CandidateStatus.BLOCKED
    assert merged.candidate_text is None
    assert "merged-candidate-conflict:text" in merged.blocking_reasons
    assert merged.syntax_validation.level is SyntaxValidationLevel.NOT_RUN

    parameter_conflict = base.model_copy(update={"parameters": {"vlan-id": 99}})
    merged_parameters = renderer._merge_group([base, parameter_conflict])
    assert "merged-candidate-conflict:parameters" in merged_parameters.blocking_reasons
    assert merged_parameters.status is CandidateStatus.BLOCKED


def test_category_filter_cannot_bypass_a_membership_block() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1")])
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"] = []
    second["logical_interfaces"] = []
    add_channel(second, 2, [0], {"mode": "access", "access_vlan": 20})
    built = render([first, second])
    filtered = renderer._filter_categories(  # noqa: SLF001 - targeted regression
        built.candidates, (CandidateCategory.PORT_CHANNEL, CandidateCategory.LACP_MODE),
    )
    assert filtered
    member = [
        candidate for candidate in filtered
        if candidate.target.name == "Gi1/0/1"
    ]
    assert member
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in member)
    assert all(candidate.candidate_text is None for candidate in member)


# --------------------------------------------------------------------------- #
# P2-02 mode-transition propagation
# --------------------------------------------------------------------------- #


def test_access_to_trunk_propagates_the_block_to_associated_vlans() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1", description="metadata")])
    second = copy.deepcopy(first)
    second["physical_interfaces"][0]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
        "description": "changed metadata",
    }
    document = render([first, second])
    associated = [
        candidate for candidate in document.candidates
        if candidate.target.name == "Gi1/0/1"
        and candidate.category in {
            CandidateCategory.TRUNK_MODE,
            CandidateCategory.ALLOWED_VLANS,
            CandidateCategory.NATIVE_VLAN,
        }
    ]
    assert associated
    assert all(candidate.status is CandidateStatus.BLOCKED for candidate in associated)
    assert all(candidate.candidate_text is None for candidate in associated)
    assert any(
        "mode-transition-inherited:access-to-trunk:Gi1/0/1"
        in candidate.blocking_reasons
        for candidate in associated
    )
    metadata = [
        candidate for candidate in document.candidates
        if candidate.category is CandidateCategory.DESCRIPTION
    ]
    assert metadata
    assert metadata[0].risk_class is RiskClass.R0
    assert not any(
        "mode-transition-inherited" in reason
        for reason in metadata[0].blocking_reasons
    )


def test_trunk_to_access_propagates_r5_and_blocks_cleanup_candidates() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [{
        "name": "Gi1/0/1",
        "settings": {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]},
    }])
    second = copy.deepcopy(first)
    second["physical_interfaces"][0]["settings"] = {
        "mode": "access", "access_vlan": 20,
    }
    document = render([first, second])
    related = [
        candidate for candidate in document.candidates
        if candidate.target.name == "Gi1/0/1"
        and candidate.category in {
            CandidateCategory.ACCESS_MODE, CandidateCategory.ACCESS_VLAN,
            CandidateCategory.TRUNK_MODE, CandidateCategory.NATIVE_VLAN,
            CandidateCategory.ALLOWED_VLANS,
        }
    ]
    assert all(candidate.status is not CandidateStatus.CANDIDATE for candidate in related)
    assert all(candidate.candidate_text is None for candidate in related)
    assert any(candidate.risk_class is RiskClass.R5 for candidate in related)


def test_routed_to_switchport_transition_blocks_associated_candidates() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [{
        "name": "Gi1/0/1",
        "settings": {"mode": "routed", "address": "192.0.2.1/24"},
    }])
    second = copy.deepcopy(first)
    second["physical_interfaces"][0]["settings"] = {
        "mode": "access", "access_vlan": 20,
    }
    document = render([first, second])
    related = [
        candidate for candidate in document.candidates
        if candidate.target.name == "Gi1/0/1"
        and candidate.category in {
            CandidateCategory.ACCESS_MODE, CandidateCategory.ACCESS_VLAN,
        }
    ]
    assert related
    assert all(candidate.status is not CandidateStatus.CANDIDATE for candidate in related)
    assert any(
        "routed-boundary-transition-unverified" in candidate.blocking_reasons
        or "mode-transition-inherited" in " ".join(candidate.blocking_reasons)
        for candidate in related
    )


def test_port_channel_mode_transition_propagates() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1")])
    add_channel(first, 1, [0], {"mode": "access", "access_vlan": 20})
    second = copy.deepcopy(first)
    second["port_channels"][0]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
    }
    document = render([first, second])
    related = [
        candidate for candidate in document.candidates
        if candidate.target.name == "Port-channel1"
        and candidate.category in {
            CandidateCategory.TRUNK_MODE, CandidateCategory.ALLOWED_VLANS,
            CandidateCategory.NATIVE_VLAN,
        }
    ]
    assert related
    assert all(candidate.status is not CandidateStatus.CANDIDATE for candidate in related)
    assert any(
        "mode-transition-inherited:access-to-trunk:Port-channel1"
        in candidate.blocking_reasons
        for candidate in related
    )


def test_allowed_vlans_is_an_explicit_replacement() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [{
        "name": "Gi1/0/1",
        "settings": {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]},
    }])
    document = render([plan])
    allowed = next(
        candidate for candidate in document.candidates
        if candidate.category is CandidateCategory.ALLOWED_VLANS
    )
    assert allowed.status is CandidateStatus.CANDIDATE
    assert allowed.parameters["operation"] == "replace"
    assert allowed.candidate_text == "switchport trunk allowed vlan 10,20"
    assert "field-note:allowed-vlans-replacement-semantics" in allowed.prerequisites
    for token in ("add ", "remove ", "except "):
        assert token not in str(allowed.candidate_text)


# --------------------------------------------------------------------------- #
# P2-03 Port-Channel admin state and connectivity impact
# --------------------------------------------------------------------------- #


def test_port_channel_shutdown_and_no_shutdown_are_blocked() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [port("Gi1/0/1"), port("Gi1/0/2")])
    add_channel(plan, 1, [0], {
        "mode": "access", "access_vlan": 20, "admin_state": "down",
    })
    add_channel(plan, 2, [1], {
        "mode": "access", "access_vlan": 20, "admin_state": "up",
    })
    document = render([plan])
    down = of(document, "Port-channel1", {CandidateCategory.ADMIN_SHUTDOWN})
    up = of(document, "Port-channel2", {CandidateCategory.ADMIN_SHUTDOWN})
    assert down and up
    assert down[0].status is CandidateStatus.BLOCKED
    assert "port-channel-shutdown-requires-topology-evidence" in down[0].blocking_reasons
    assert "aggregate-member-impact-unverified" in down[0].blocking_reasons
    assert up[0].status is CandidateStatus.BLOCKED
    assert "port-channel-no-shutdown-requires-topology-evidence" in up[0].blocking_reasons
    for candidate in (down[0], up[0]):
        assert candidate.candidate_text is None
        assert candidate.risk_class is RiskClass.R5
        assert candidate.requires_field_verification is True
        assert "field-verification-required" in candidate.prerequisites


def test_channel_member_admin_state_is_blocked() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [
        port("Gi1/0/1"),
        {"name": "Gi1/0/2", "settings": {
            "mode": "access", "access_vlan": 20, "admin_state": "down",
        }},
    ])
    add_channel(plan, 1, [0, 1], {"mode": "access", "access_vlan": 20})
    document = render([plan])
    for name in ("Gi1/0/1", "Gi1/0/2"):
        members = of(document, name, {CandidateCategory.ADMIN_SHUTDOWN})
        assert all(candidate.status is CandidateStatus.BLOCKED for candidate in members)
        assert all(
            "channel-member-admin-state-requires-topology-evidence" in " ".join(
                candidate.blocking_reasons
            )
            for candidate in members
        )


def test_unreferenced_port_shutdown_renders_with_connectivity_impact() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [
        {"name": "Gi1/0/1", "settings": {
            "mode": "access", "access_vlan": 20, "admin_state": "down",
        }},
    ])
    document = render([plan])
    shutdown = [
        candidate for candidate in of(
            document, "Gi1/0/1", {CandidateCategory.ADMIN_SHUTDOWN},
        )
        if candidate.candidate_text == "shutdown"
    ]
    assert shutdown
    assert shutdown[0].status is CandidateStatus.CANDIDATE
    assert shutdown[0].potential_connectivity_impact is True


def test_r1_connectivity_operations_never_report_no_impact() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [
        port("Gi1/0/1", speed=1000, duplex="full", poe_mode="auto",
             description="metadata"),
    ])
    document = render([plan])
    impact_categories = {
        CandidateCategory.SPEED, CandidateCategory.DUPLEX,
        CandidateCategory.POE_MODE, CandidateCategory.ADMIN_SHUTDOWN,
    }
    seen: set[CandidateCategory] = set()
    for candidate in document.candidates:
        if candidate.category in impact_categories:
            seen.add(candidate.category)
            assert candidate.potential_connectivity_impact is True
    assert seen & {CandidateCategory.SPEED, CandidateCategory.DUPLEX}
    description = [
        candidate for candidate in document.candidates
        if candidate.category is CandidateCategory.DESCRIPTION
    ]
    assert description and description[0].potential_connectivity_impact is False


def test_baseline_never_implies_the_aggregate_is_already_down() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1")])
    add_channel(first, 1, [0], {
        "mode": "access", "access_vlan": 20, "admin_state": "down",
    })
    second = copy.deepcopy(first)
    second["port_channels"][0]["settings"]["admin_state"] = "up"
    document = render([first, second])
    changed = [
        candidate for candidate in of(
            document, "Port-channel1", {CandidateCategory.ADMIN_SHUTDOWN},
        )
        if candidate.parameters.get("admin-state") == "up"
    ]
    assert changed and changed[0].status is CandidateStatus.BLOCKED
    assert changed[0].candidate_text is None


# --------------------------------------------------------------------------- #
# P2-04 evidence content and review binding
# --------------------------------------------------------------------------- #


CONTENT_CLASSES = [
    ("grammar", {"grammar": "modified grammar line"}),
    ("parameter-maximum", {"parameters": (
        dataclasses.replace(ROWS[0].parameters[0], maximum=9999),
        *ROWS[0].parameters[1:],
    )}),
    ("pids", {"pids": ("WS-C2960X-24TS-LL",)}),
    ("release", {"releases": ("15.2(7)E1a",)}),
    ("license", {"licenses": ("LAN Lite",)}),
    ("source-url", {"source_url": "https://www.cisco.com/other"}),
    ("source-section", {"source_section": "Other section"}),
    ("exclusions", {"exclusions": ("Other exclusion.",)}),
    ("limits", {"limits": ("Other limit.",)}),
    ("requirements", {"requirements": ()}),
]


@pytest.mark.parametrize(
    ("label", "change"),
    CONTENT_CLASSES,
    ids=[label for label, _change in CONTENT_CLASSES],
)
def test_every_content_class_changes_the_content_digest(
    label: str, change: dict[str, Any],
) -> None:
    row = ROWS[0]
    tampered = dataclasses.replace(row, **change)
    assert tampered.content_digest != row.content_digest, label
    # The review digest itself is unchanged; only the binding breaks.
    assert tampered.review.review_digest == row.review.review_digest


def test_reviewed_row_with_changed_content_cannot_render() -> None:
    registry = harness_registry()
    row = registry.rows[0]
    assert registry.renderable(
        row.family, row.pids[0], row.releases[0],
        row.licenses[0] if row.licenses else None, row.topic,
    ) is not None
    tampered_row = dataclasses.replace(row, grammar=row.grammar + " changed")
    tampered = CommandEvidenceRegistry(tuple(
        tampered_row if item.evidence_id == row.evidence_id else item
        for item in registry.rows
    ))
    assert tampered.renderable(
        row.family, row.pids[0], row.releases[0],
        row.licenses[0] if row.licenses else None, row.topic,
    ) is None
    assert tampered.blocker(
        row.family, row.pids[0], row.releases[0],
        row.licenses[0] if row.licenses else None, row.topic,
    ) == f"syntax-evidence-content-mismatch:{row.topic.value}"


def test_reviewer_and_findings_change_the_review_digest_not_the_content() -> None:
    row = ROWS[0]
    original = EvidenceReview(
        EvidenceReviewState.REVIEWED, "reviewer-a", "2026-11-20",
        ("finding a",), row.content_digest,
    )
    other_reviewer = dataclasses.replace(original, reviewer="reviewer-b")
    other_findings = dataclasses.replace(original, findings=("finding b",))
    assert original.review_digest != other_reviewer.review_digest
    assert original.review_digest != other_findings.review_digest
    assert original.content_digest == other_reviewer.content_digest


def test_tampered_review_digest_cannot_authorise_a_render() -> None:
    row = ROWS[0]
    stale = dataclasses.replace(
        row,
        review=EvidenceReview(
            EvidenceReviewState.REVIEWED, "reviewer", "2026-11-20",
            ("finding",), "0" * 64,
        ),
    )
    registry = CommandEvidenceRegistry((stale, *ROWS[1:]))
    assert not stale.renderable
    assert registry.renderable(
        row.family, row.pids[0], row.releases[0],
        row.licenses[0] if row.licenses else None, row.topic,
    ) is None


def test_registry_fingerprint_covers_content_and_is_order_independent() -> None:
    base = harness_registry()
    reordered = CommandEvidenceRegistry(tuple(reversed(base.rows)))
    assert base.fingerprint == reordered.fingerprint
    assert all(len(item) >= 8 for item in base.fingerprint_rows)
    row = base.rows[0]
    tampered = CommandEvidenceRegistry(tuple(
        dataclasses.replace(row, grammar=row.grammar + " changed")
        if item.evidence_id == row.evidence_id else item
        for item in base.rows
    ))
    assert tampered.fingerprint != base.fingerprint
    assert tampered.fingerprint_rows != base.fingerprint_rows


def test_pending_review_cannot_render_even_with_content_digest() -> None:
    row = dataclasses.replace(
        ROWS[0],
        review=dataclasses.replace(PENDING_REVIEW, content_digest=ROWS[0].content_digest),
    )
    registry = CommandEvidenceRegistry((row, *ROWS[1:]))
    assert registry.renderable(
        row.family, row.pids[0], row.releases[0],
        row.licenses[0] if row.licenses else None, row.topic,
    ) is None


# --------------------------------------------------------------------------- #
# P2-05 structured platform and safety gates
# --------------------------------------------------------------------------- #


def test_power_inline_requires_poe_hardware_even_for_never() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [port("Gi1/0/1", poe_mode="never")], pid="C9300-24T")
    document = render([plan])
    poe = of(document, "Gi1/0/1", {CandidateCategory.POE_MODE})
    assert poe and poe[0].status is CandidateStatus.BLOCKED
    assert "platform-unsupported:poe-capable-port:Gi1/0/1" in poe[0].blocking_reasons
    assert poe[0].candidate_text is None


def test_power_inline_auto_renders_on_a_poe_port() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [port("Gi1/0/1", poe_mode="auto")])
    document = render([plan])
    poe = of(document, "Gi1/0/1", {CandidateCategory.POE_MODE})
    assert [candidate.candidate_text for candidate in poe] == ["power inline auto"]


def test_power_inline_static_requires_power_budget_evidence() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [port("Gi1/0/1", poe_mode="static")])
    document = render([plan])
    poe = of(document, "Gi1/0/1", {CandidateCategory.POE_MODE})
    assert poe and poe[0].status is CandidateStatus.BLOCKED
    assert "safety-precondition-unknown:poe-static-budget" in poe[0].blocking_reasons
    assert "field-note:poe-budget-field-note" in poe[0].prerequisites


def test_portfast_form_must_match_the_target_mode() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [
        port("Gi1/0/1", portfast="edge"),
        {"name": "Gi1/0/2", "settings": {
            "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
            "portfast": "edge",
        }},
        {"name": "Gi1/0/3", "settings": {
            "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
            "portfast": "edge-trunk",
        }},
    ])
    document = render([plan])
    access = of(document, "Gi1/0/1", {CandidateCategory.PORTFAST})
    wrong = of(document, "Gi1/0/2", {CandidateCategory.PORTFAST})
    right = of(document, "Gi1/0/3", {CandidateCategory.PORTFAST})
    assert [candidate.candidate_text for candidate in access] == [
        "spanning-tree portfast"
    ]
    assert wrong and wrong[0].status is CandidateStatus.BLOCKED
    assert "platform-unsupported:portfast-mode-match:Gi1/0/2" in wrong[0].blocking_reasons
    assert [candidate.candidate_text for candidate in right] == [
        "spanning-tree portfast trunk"
    ]


def test_channel_member_count_and_number_range_are_distinct_constraints() -> None:
    event_id = str(uuid4())
    many = base_plan(event_id, [
        port(f"Gi1/0/{index}") for index in range(1, 13)
    ])
    add_channel(many, 1, list(range(0, 12)), {"mode": "access", "access_vlan": 20})
    document = render([many])
    blocked = of(document, "Gi1/0/1", CHANNEL_CATEGORIES)
    assert blocked and blocked[0].status is CandidateStatus.BLOCKED
    assert any(
        reason.startswith("channel-member-count-exceeds-renderer-limit")
        for reason in blocked[0].blocking_reasons
    )
    eight = base_plan(event_id, [port(f"Gi1/0/{index}") for index in range(1, 10)])
    add_channel(eight, 1, list(range(0, 8)), {"mode": "access", "access_vlan": 20})
    rendered = render([eight])
    ok = [
        candidate for candidate in of(rendered, "Gi1/0/1", CHANNEL_CATEGORIES)
        if candidate.candidate_text is not None
    ]
    assert ok
    out_of_range = base_plan(event_id, [port("Gi1/0/1")])
    add_channel(out_of_range, 49, [0], {"mode": "access", "access_vlan": 20})
    numbered = render([out_of_range])
    interfaces = of(numbered, "Port-channel49", CHANNEL_CATEGORIES)
    assert interfaces and interfaces[0].status is CandidateStatus.BLOCKED
    assert any(
        reason.startswith("parameter-out-of-range:port-channel-number")
        for reason in interfaces[0].blocking_reasons
    )


def test_sfp_speed_and_duplex_require_optic_evidence() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [
        {"name": "Te1/1/1", "settings": {
            "mode": "access", "access_vlan": 20, "speed": 1000, "duplex": "full",
        }},
    ])
    document = render([plan])
    for category in (CandidateCategory.SPEED, CandidateCategory.DUPLEX):
        found = of(document, "Te1/1/1", {category})
        assert found, category
        assert found[0].status is not CandidateStatus.CANDIDATE
        assert found[0].candidate_text is None
        reasons = " ".join(found[0].blocking_reasons)
        assert "copper-port-required" in reasons or "optic-unknown" in reasons


def test_channel_count_uses_the_reviewed_number_maximum() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [port("Gi1/0/1")])
    for number in range(1, 50):
        add_channel(plan, number, [0], {"mode": "access", "access_vlan": 20})
    document = render([plan])
    interfaces = [
        candidate for candidate in document.candidates
        if candidate.category is CandidateCategory.PORT_CHANNEL
        and candidate.target.name == "Port-channel1"
    ]
    assert interfaces
    assert all(candidate.status is not CandidateStatus.CANDIDATE
               for candidate in interfaces)
    assert any(
        reason.startswith("channel-count-exceeds-reviewed-limit")
        for candidate in interfaces
        for reason in candidate.blocking_reasons
    )


def test_link_and_isp_referenced_ports_block_shutdown() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [
        {"name": "Gi1/0/1", "settings": {
            "mode": "access", "access_vlan": 20, "admin_state": "down",
        }},
        {"name": "Gi1/0/2", "settings": {
            "mode": "access", "access_vlan": 20, "admin_state": "down",
        }},
        {"name": "Gi1/0/3", "settings": {
            "mode": "access", "access_vlan": 20, "admin_state": "down",
        }},
    ])
    assignment_id = plan["assignments"][0]["id"]
    interfaces = plan["physical_interfaces"]
    plan["links"] = [{
        "id": new_id(),
        "endpoints": [interfaces[0]["id"], interfaces[1]["id"]],
    }]
    plan["isps"] = [{
        "id": new_id(), "name": "ISP-A", "assignment_id": assignment_id,
        "interface_id": interfaces[2]["id"],
        "address": "198.51.100.2/30", "gateway": "198.51.100.1",
    }]
    document = render([plan])
    link_port = of(document, "Gi1/0/1", {CandidateCategory.ADMIN_SHUTDOWN})
    isp_port = of(document, "Gi1/0/3", {CandidateCategory.ADMIN_SHUTDOWN})
    assert link_port and link_port[0].status is CandidateStatus.BLOCKED
    assert "link-uplink-port-shutdown-requires-topology-evidence:Gi1/0/1" in (
        link_port[0].blocking_reasons
    )
    assert isp_port and isp_port[0].status is CandidateStatus.BLOCKED
    assert "wan-or-transit-port-shutdown-requires-topology-evidence:Gi1/0/3" in (
        isp_port[0].blocking_reasons
    )


def test_lan_lite_poe_is_blocked() -> None:
    event_id = str(uuid4())
    plan = base_plan(
        event_id, [port("Gi1/0/1", poe_mode="auto")],
        pid="WS-C2960X-24TS-LL",
    )
    plan["assignments"][0]["family"] = "catalyst-2960x"
    plan["assignments"][0]["software"] = {
        "image": "15.2(7)E", "license": "LAN Lite",
    }
    document = render([plan])
    poe = of(document, "Gi1/0/1", {CandidateCategory.POE_MODE})
    assert poe and poe[0].status is not CandidateStatus.CANDIDATE
    assert poe[0].candidate_text is None


def test_sfp28_speed_is_blocked_without_optic_evidence() -> None:
    event_id = str(uuid4())
    plan = base_plan(
        event_id, [{
            "name": "Twe1/0/1",
            "settings": {"mode": "access", "access_vlan": 20, "speed": 25000},
        }],
        pid="C9300X-24Y",
    )
    document = render([plan])
    speed = of(document, "Twe1/0/1", {CandidateCategory.SPEED})
    assert speed and speed[0].status is not CandidateStatus.CANDIDATE
    assert speed[0].candidate_text is None


def test_bpdu_guard_carries_its_field_prerequisites() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [port("Gi1/0/1", bpdu_guard="enabled")])
    document = render([plan])
    guard = of(document, "Gi1/0/1", {CandidateCategory.BPDU_GUARD})
    assert guard and guard[0].status is CandidateStatus.CANDIDATE
    assert "field-note:bpdu-guard-topology-note" in guard[0].prerequisites
    assert guard[0].requires_field_verification is True
    assert guard[0].potential_connectivity_impact is True


def test_requirement_contract_drift_fails_closed() -> None:
    row = next(
        item for item in ROWS
        if item.topic is CommandTopic.POE_MODE
        and item.family is DeviceFamily.CATALYST_9300
    )
    drifted = dataclasses.replace(row, requirements=())
    registry = harness_registry(tuple(
        drifted if item.evidence_id == row.evidence_id else item for item in ROWS
    ))
    event_id = str(uuid4())
    plan = base_plan(event_id, [port("Gi1/0/1", poe_mode="auto")])
    built = [_revision(plan, 1)]
    intent = build_layer2_intent(built[0], None)
    preview = build_device_layer2_config_preview(
        built[0], intent, built[0].plan.assignments[0].id,
    )
    document = build_l2_cli_candidates(built[0], intent, preview, registry=registry)
    poe = [
        candidate for candidate in document.candidates
        if candidate.category is CandidateCategory.POE_MODE
    ]
    assert poe and poe[0].status is CandidateStatus.BLOCKED
    assert any(
        reason.startswith("requirement-contract-mismatch:")
        for reason in poe[0].blocking_reasons
    )


def test_unknown_requirement_code_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patched = dict(BLOCKING_REQUIREMENT_CODES)
    patched[CommandTopic.DESCRIPTION] = ("unreviewed-new-gate",)
    monkeypatch.setattr(renderer, "BLOCKING_REQUIREMENT_CODES", patched)
    event_id = str(uuid4())
    plan = base_plan(event_id, [port("Gi1/0/1", description="metadata")])
    document = render([plan])
    description = [
        candidate for candidate in document.candidates
        if candidate.category is CandidateCategory.DESCRIPTION
    ]
    assert description and description[0].status is CandidateStatus.BLOCKED
    assert "requirement-evaluator-missing:unreviewed-new-gate" in (
        description[0].blocking_reasons
    )


# --------------------------------------------------------------------------- #
# P3-01 syntax validation state
# --------------------------------------------------------------------------- #


def test_syntax_validation_state_matches_the_outcome() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [
        port("Gi1/0/1"),
        {"name": "Gi1/0/2", "settings": {"mode": "routed",
                                         "address": "192.0.2.1/24"}},
    ])
    document = render([plan])
    assert {candidate.status for candidate in document.candidates} >= {
        CandidateStatus.CANDIDATE, CandidateStatus.UNSUPPORTED,
    }
    for candidate in document.candidates:
        assert candidate.syntax_validation.parser_verified is False
        expected = (
            SyntaxValidationLevel.DICTIONARY_ONLY
            if candidate.status is CandidateStatus.CANDIDATE
            else SyntaxValidationLevel.NOT_RUN
        )
        assert candidate.syntax_validation.level is expected


def test_schema_accepts_both_levels_and_rejects_an_unknown_state() -> None:
    from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

    schema = renderer.candidate_document_json_schema()
    Draft202012Validator.check_schema(schema)
    event_id = str(uuid4())
    plan = base_plan(event_id, [port("Gi1/0/1")])
    document = render([plan]).model_dump(mode="json")
    validator = Draft202012Validator(schema)
    assert list(validator.iter_errors(document)) == []
    for candidate in document["candidates"]:
        levels = {candidate["syntax_validation"]["level"]}
        assert levels <= {"dictionary-only", "not-run"}
    tampered = copy.deepcopy(document)
    tampered["candidates"][0]["syntax_validation"]["level"] = "parser-verified"
    assert list(validator.iter_errors(tampered))


# --------------------------------------------------------------------------- #
# Planned-difference semantics (documented boundary)
# --------------------------------------------------------------------------- #


def test_renderer_emits_planned_differences_not_the_full_desired_state() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1", description="first")])
    second = copy.deepcopy(first)
    second["physical_interfaces"][0]["settings"]["description"] = "second"
    document = render([first, second])
    assert {
        candidate.category for candidate in document.candidates
    } == {CandidateCategory.DESCRIPTION}
    assert document.summary.total == 1


def test_first_revision_renders_initial_plan_candidates() -> None:
    event_id = str(uuid4())
    plan = base_plan(event_id, [port("Gi1/0/1")])
    document = render([plan])
    assert document.render_state.value == "review-candidates"
    assert {candidate.category for candidate in document.candidates} >= {
        CandidateCategory.VLAN_DEFINITION,
        CandidateCategory.ACCESS_MODE,
        CandidateCategory.ACCESS_VLAN,
        CandidateCategory.UNUSED_SHUTDOWN,
    }


def test_non_layer2_revision_change_renders_no_supported_candidates() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1")])
    second = copy.deepcopy(first)
    second["assignments"][0]["location"] = "Hall B"
    document = render([first, second])
    assert document.candidates == ()
    assert document.render_state.value == "no-supported-candidates"
    assert document.summary.total == 0


def test_new_assignment_in_a_later_revision_is_rendered_as_initial_plan() -> None:
    event_id = str(uuid4())
    first = base_plan(event_id, [port("Gi1/0/1")])
    second = copy.deepcopy(first)
    device_id, assignment_id = new_id(), new_id()
    second["physical_devices"].append({
        "id": device_id, "vendor": "cisco", "model": "C9300L-24P-4X",
        "verified_serial": "SYN-" + new_id()[:8],
    })
    second["assignments"].append({
        "id": assignment_id, "hostname": "L2-New", "role": "access",
        "family": "catalyst-9300", "physical_device_id": device_id,
        "software": {"image": "17.12.4", "license": "Network Advantage"},
    })
    second["physical_interfaces"].append({
        "id": new_id(), "assignment_id": assignment_id,
        "physical_device_id": device_id, "name": "Gi1/0/1",
        "settings": {"mode": "access", "access_vlan": 20},
    })
    built = [_revision(first, 1), _revision(second, 2)]
    intent = build_layer2_intent(built[1], built[0])
    new_assignment = next(
        device for device in intent.devices
        if device.identity.hostname == "L2-New"
    )
    preview = build_device_layer2_config_preview(
        built[1], intent, new_assignment.identity.assignment_id,
    )
    document = build_l2_cli_candidates(built[1], intent, preview)
    assert document.render_state.value == "review-candidates"
    assert {candidate.category for candidate in document.candidates} >= {
        CandidateCategory.ACCESS_MODE, CandidateCategory.ACCESS_VLAN,
    }


def test_evidence_content_digest_helper_matches_the_row() -> None:
    for row in ROWS:
        assert evidence_content_digest(row) == row.content_digest
        assert json.dumps(row.content_payload(), sort_keys=True)


def test_device_family_scope_never_borrows_another_family_content() -> None:
    for row in ROWS:
        assert row.family in set(DeviceFamily)
        digest = row.content_digest
        assert len(digest) == 64
