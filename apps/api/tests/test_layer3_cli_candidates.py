"""CIS-03-03A read-only L3 candidate renderer tests."""

from __future__ import annotations

import copy
from dataclasses import replace
from typing import Any
from uuid import UUID

import pytest
from layer3_helpers import (
    make_l3_plan,
    make_stack_plan,
    plan_model,
    revision_for,
)
from layer3_helpers import (
    synthetic_eligible_evidence_registry as _synthetic_eligible_evidence_registry,
)
from layer3_helpers import (
    test_only_evidence_registry as _test_only_evidence_registry,
)

from event_switch_manager.planning.checks import validate_plan
from event_switch_manager.planning.layer3_cli_candidates import (
    CandidateCategory,
    CandidateStatus,
    L3CandidateDocument,
    RenderBindingError,
    RenderTargetNotFound,
    build_l3_cli_candidates,
    candidate_fingerprint,
    intent_fingerprint,
    render_fingerprint,
)
from event_switch_manager.planning.layer3_command_evidence import (
    DEFAULT_REGISTRY,
    PENDING_REVIEW,
    CommandEvidenceRegistry,
    L3CommandTopic,
)
from event_switch_manager.planning.layer3_intent import build_layer3_intent
from event_switch_manager.planning.plan import PlanRevision

TEST_REGISTRY = _synthetic_eligible_evidence_registry()
ACTUAL_TEST_REGISTRY = _test_only_evidence_registry()


def _core_assignment(intent: Any) -> Any:
    return next(
        device for device in intent.devices if device.identity.hostname == "L3-Core"
    ).identity.assignment_id


def _build(
    payload: dict[str, Any], *, registry: CommandEvidenceRegistry = TEST_REGISTRY,
    baseline: PlanRevision | None = None,
) -> tuple[PlanRevision, Any, L3CandidateDocument]:
    revision = revision_for(payload)
    intent = build_layer3_intent(revision, baseline)
    document = build_l3_cli_candidates(
        revision, intent, _core_assignment(intent), registry,
        baseline=baseline, test_only_registry=True,
    )
    return revision, intent, document


def _by_category(document: L3CandidateDocument, category: CandidateCategory) -> list[Any]:
    return [item for item in document.candidates if item.category is category]


def test_positive_six_categories_with_test_only_registry() -> None:
    _, intent, document = _build(
        make_l3_plan(
            "00000000-0000-0000-0000-000000000099", static_route_count=1,
        ),
    )
    core = next(
        device for device in intent.devices if device.identity.hostname == "L3-Core"
    )
    svis = {item.name: item for item in core.interfaces if item.kind == "svi"}
    assert svis["Vlan9"].role.value == "transit"
    assert svis["Vlan10"].role.value == "gateway"
    assert svis["Vlan20"].role.value == "gateway"
    assert svis["Vlan10"].gateway_address is not None
    assert svis["Vlan10"].subnet_id is not None
    assert document.render_state.value == "review-candidates"
    assert document.source.command_evidence_registry_id == TEST_REGISTRY.registry_id
    assert TEST_REGISTRY.production is False
    assert document.summary.total == 10
    assert document.summary.candidates == 10
    assert document.summary.blocked == 0
    assert set(document.summary.categories) == {
        "ip-routing", "svi-interface", "svi-address",
        "static-route", "default-route", "dhcp-helper-address",
    }
    assert _by_category(document, CandidateCategory.IP_ROUTING)[0].candidate_text == (
        "ip routing"
    )
    assert "interface Vlan20" in {
        item.candidate_text for item in _by_category(
            document, CandidateCategory.SVI_INTERFACE,
        )
    }
    assert "ip address 192.168.20.1 255.255.255.0" in {
        item.candidate_text for item in _by_category(
            document, CandidateCategory.SVI_ADDRESS,
        )
    }
    static = _by_category(document, CandidateCategory.STATIC_ROUTE)[0]
    assert static.candidate_text == "ip route 10.200.0.0 255.255.255.0 10.0.0.2"
    default = _by_category(document, CandidateCategory.DEFAULT_ROUTE)[0]
    assert default.candidate_text == "ip route 0.0.0.0 0.0.0.0 10.0.0.2"
    helper = _by_category(document, CandidateCategory.DHCP_HELPER_ADDRESS)[0]
    assert helper.candidate_text == "ip helper-address 192.168.10.5"
    assert helper.syntax_evidence[0].review_state == "independently-reviewed"
    assert helper.syntax_evidence[0].review_state != "pending-independent-review"
    assert helper.provenance.intent_fingerprint == intent.intent_fingerprint
    assert all(item.syntax_validation.parser_verified is False for item in document.candidates)
    assert document.safety.candidate_only is True
    assert document.safety.executable is False
    assert document.safety.deployable is False
    assert document.safety.deployment_allowed is False
    assert document.safety.cli is None
    assert document.safety.hardware_verified is False
    assert document.safety.parser_verified is False
    assert all("\n" not in (item.candidate_text or "") for item in document.candidates)
    assert all(not (item.candidate_text or "").startswith("no ") for item in document.candidates)


def test_production_registry_renders_no_text() -> None:
    revision = revision_for(make_l3_plan("00000000-0000-0000-0000-000000000099"))
    intent = build_layer3_intent(revision)
    document = build_l3_cli_candidates(
        revision, intent, _core_assignment(intent),
    )
    assert document.render_state.value == "blocked"
    assert document.summary.candidates == 0
    assert all(item.candidate_text is None for item in document.candidates)
    assert all("syntax-evidence-pending" in item.blocking_reasons
               for item in document.candidates)
    assert all(item.status is CandidateStatus.BLOCKED for item in document.candidates)


def test_actual_base_evidence_generates_five_categories() -> None:
    _, _, document = _build(
        make_l3_plan(
            "00000000-0000-0000-0000-000000000099", static_route_count=1,
        ),
        registry=ACTUAL_TEST_REGISTRY,
    )
    for category in (
        CandidateCategory.IP_ROUTING,
        CandidateCategory.SVI_INTERFACE,
        CandidateCategory.SVI_ADDRESS,
        CandidateCategory.STATIC_ROUTE,
        CandidateCategory.DEFAULT_ROUTE,
    ):
        candidates = _by_category(document, category)
        assert candidates
        assert all(
            item.status is CandidateStatus.CANDIDATE
            and item.candidate_text is not None
            for item in candidates
        )
    helper = _by_category(document, CandidateCategory.DHCP_HELPER_ADDRESS)[0]
    assert helper.status is CandidateStatus.BLOCKED
    assert helper.candidate_text is None


def test_actual_scope_gaps_block_even_with_test_review() -> None:
    dhcp_row = next(
        row for row in ACTUAL_TEST_REGISTRY.rows
        if row.topic is L3CommandTopic.DHCP_HELPER_ADDRESS
    )
    assert dhcp_row.renderable is True
    assert "evidence-license-unresolved" in dhcp_row.scope_blockers()
    assert "evidence-scope-gap-dhcp-relay-license" in dhcp_row.scope_blockers()
    _, _, document = _build(
        make_l3_plan("00000000-0000-0000-0000-000000000099"),
        registry=ACTUAL_TEST_REGISTRY,
    )
    helper = _by_category(document, CandidateCategory.DHCP_HELPER_ADDRESS)[0]
    assert helper.status is CandidateStatus.BLOCKED
    assert helper.candidate_text is None
    assert "evidence-license-unresolved" in helper.blocking_reasons
    assert "evidence-scope-gap-dhcp-relay-license" in helper.blocking_reasons


def test_missing_classification_blocks_production_scope() -> None:
    base = ACTUAL_TEST_REGISTRY.get("l3-9300-dhcp-helper-address-v1")
    assert base is not None
    changed = replace(base, classification=None)
    changed = replace(changed, review=replace(
        changed.review, content_digest=changed.content_digest(),
    ))
    rows = tuple(
        changed if row.evidence_id == changed.evidence_id else row
        for row in ACTUAL_TEST_REGISTRY.rows
    )
    registry = CommandEvidenceRegistry(
        rows, registry_id="test-only-missing-classification", production=False,
    )
    _, _, document = _build(
        make_l3_plan("00000000-0000-0000-0000-000000000099"),
        registry=registry,
    )
    helper = _by_category(document, CandidateCategory.DHCP_HELPER_ADDRESS)[0]
    assert helper.status is CandidateStatus.BLOCKED
    assert "evidence-classification-missing" in helper.blocking_reasons


def test_nonblocking_excluded_scope_notes_do_not_globally_block() -> None:
    registry = _synthetic_eligible_evidence_registry()
    assert all(
        row.scope_blockers() == () for row in registry.rows
    )
    assert all(
        row.classification is not None
        and row.classification.excluded_scope_notes
        for row in registry.rows
    )
    _, _, document = _build(
        make_l3_plan("00000000-0000-0000-0000-000000000099"),
        registry=registry,
    )
    helper = _by_category(document, CandidateCategory.DHCP_HELPER_ADDRESS)[0]
    assert helper.status is CandidateStatus.CANDIDATE
    assert not any(
        reason.startswith("evidence-scope-gap-")
        for reason in helper.blocking_reasons
    )


def test_missing_or_wrong_scope_evidence_blocks() -> None:
    revision = revision_for(make_l3_plan("00000000-0000-0000-0000-000000000099"))
    intent = build_layer3_intent(revision)
    empty = CommandEvidenceRegistry(())
    document = build_l3_cli_candidates(
        revision, intent, _core_assignment(intent), empty,
    )
    assert all(item.candidate_text is None for item in document.candidates)
    assert all("syntax-evidence-missing" in item.blocking_reasons
               for item in document.candidates)

    variants: tuple[dict[str, Any], ...] = (
        {"core_pid": "C9200L-24P-4X", "core_family": "catalyst-9200"},
        {"core_image": "17.12.5"},
    )
    for kwargs in variants:
        _, _, document = _build(make_l3_plan(
            "00000000-0000-0000-0000-000000000099", **kwargs,
        ))
        assert all(item.candidate_text is None for item in document.candidates)


def test_stack_unresolved_and_deny_policy_block_everything() -> None:
    _, _, stack_doc = _build(
        make_stack_plan(
            "00000000-0000-0000-0000-000000000099", second_serial=None,
        ),
    )
    assert stack_doc.render_state.value == "blocked"
    assert all(item.candidate_text is None for item in stack_doc.candidates)
    _, _, deny_doc = _build(
        make_l3_plan("00000000-0000-0000-0000-000000000099", deny_policy=True),
    )
    assert all(item.candidate_text is None for item in deny_doc.candidates)
    assert "l3-policy-acl-not-implemented" in deny_doc.deployment_blockers


def test_relay_service_verdict_is_separate_from_forwarding() -> None:
    _, _, document = _build(make_l3_plan(
        "00000000-0000-0000-0000-000000000099",
        core_license="Network Essentials",
    ))
    helper = _by_category(document, CandidateCategory.DHCP_HELPER_ADDRESS)
    assert helper[0].status is CandidateStatus.BLOCKED
    assert "dhcp-relay-not-allowed" in helper[0].blocking_reasons
    assert _by_category(document, CandidateCategory.IP_ROUTING)[0].status is (
        CandidateStatus.CANDIDATE
    )
    assert _by_category(document, CandidateCategory.SVI_INTERFACE)[0].status is (
        CandidateStatus.CANDIDATE
    )


def test_kea_pool_and_relay_coexist_and_no_cisco_server_is_rendered() -> None:
    _, _, document = _build(make_l3_plan(
        "00000000-0000-0000-0000-000000000099", with_pool=True, with_relay=True,
    ))
    helper = _by_category(document, CandidateCategory.DHCP_HELPER_ADDRESS)[0]
    assert helper.status is CandidateStatus.CANDIDATE
    assert helper.candidate_text == "ip helper-address 192.168.10.5"
    assert not any("dhcp pool" in (item.candidate_text or "") for item in document.candidates)
    _, _, no_relay = _build(make_l3_plan(
        "00000000-0000-0000-0000-000000000099", with_pool=True, with_relay=False,
    ))
    assert _by_category(no_relay, CandidateCategory.DHCP_HELPER_ADDRESS) == []
    assert not any("dhcp" in (item.candidate_text or "").lower()
                   for item in no_relay.candidates)


def test_cleanup_blocker_does_not_block_new_candidates() -> None:
    current = make_l3_plan(
        "00000000-0000-0000-0000-000000000099", static_route_count=1,
    )
    baseline_payload = copy.deepcopy(current)
    baseline_payload["static_routes"] = [
        route for route in baseline_payload["static_routes"]
        if route["assignment_id"] != next(
            assignment["id"] for assignment in baseline_payload["assignments"]
            if assignment["hostname"] == "L3-Core"
        )
    ]
    baseline = revision_for(baseline_payload)
    _, intent, document = _build(current, baseline=baseline)
    assert "cleanup" in {
        operation.operation for operation in next(
            device for device in intent.devices
            if device.identity.hostname == "L3-Core"
        ).blocked_operations
    }
    static = _by_category(document, CandidateCategory.STATIC_ROUTE)[0]
    assert static.status is CandidateStatus.CANDIDATE
    assert static.candidate_text == "ip route 10.200.0.0 255.255.255.0 10.0.0.2"


def test_svi_removal_never_becomes_a_deletion_candidate() -> None:
    current = make_l3_plan("00000000-0000-0000-0000-000000000099")
    baseline_payload = copy.deepcopy(current)
    baseline_payload["logical_interfaces"].append({
        "id": "00000000-0000-0000-0000-0000000000aa",
        "assignment_id": next(
            assignment["id"] for assignment in baseline_payload["assignments"]
            if assignment["hostname"] == "L3-Core"
        ),
        "name": "Vlan99",
        "kind": "svi",
        "vlan": 20,
        "address": "192.168.99.1/24",
    })
    baseline = revision_for(baseline_payload)
    _, intent, document = _build(current, baseline=baseline)
    core = next(
        device for device in intent.devices if device.identity.hostname == "L3-Core"
    )
    assert core.removed_svi_ids
    assert "svi-removal" in {op.operation for op in core.blocked_operations}
    assert all("no interface" not in (item.candidate_text or "") for item in document.candidates)
    assert all(not (item.candidate_text or "").startswith("no ") for item in document.candidates)
    assert not any("Vlan99" in (item.candidate_text or "") for item in document.candidates)


@pytest.mark.parametrize(("distance", "allowed", "reason"), [
    (254, True, None),
    (255, False, "route-distance-255-not-installed"),
])
def test_default_route_distance_255_is_not_usable(
    distance: int, allowed: bool, reason: str | None,
) -> None:
    _, _, document = _build(make_l3_plan(
        "00000000-0000-0000-0000-000000000099", default_distance=distance,
    ))
    candidate = _by_category(document, CandidateCategory.DEFAULT_ROUTE)[0]
    assert (candidate.status is CandidateStatus.CANDIDATE) is allowed
    assert (candidate.candidate_text is not None) is allowed
    if reason:
        assert reason in candidate.blocking_reasons


@pytest.mark.parametrize(("distance", "allowed", "reason"), [
    (254, True, None),
    (255, False, "route-distance-255-not-installed"),
])
def test_static_route_distance_255_is_not_usable(
    distance: int, allowed: bool, reason: str | None,
) -> None:
    _, _, document = _build(make_l3_plan(
        "00000000-0000-0000-0000-000000000099",
        static_route_count=1, static_route_distance=distance,
    ))
    candidate = _by_category(document, CandidateCategory.STATIC_ROUTE)[0]
    assert (candidate.status is CandidateStatus.CANDIDATE) is allowed
    assert (candidate.candidate_text is not None) is allowed
    if reason:
        assert reason in candidate.blocking_reasons


def test_distance_256_blocks_forwarding() -> None:
    _, _, document = _build(make_l3_plan(
        "00000000-0000-0000-0000-000000000099", default_distance=256,
    ))
    assert all(item.candidate_text is None for item in document.candidates)
    assert "l3-route-distance-out-of-range" in document.deployment_blockers
    _, _, static_doc = _build(make_l3_plan(
        "00000000-0000-0000-0000-000000000099",
        static_route_count=1, static_route_distance=256,
    ))
    assert all(item.candidate_text is None for item in static_doc.candidates)
    assert "l3-route-distance-out-of-range" in static_doc.deployment_blockers


def test_svi_name_and_carrier_errors_block_text() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    next(
        item for item in payload["logical_interfaces"]
        if item["kind"] == "svi" and item["vlan"] == 20
    )["name"] = "Vlan200"
    _, _, document = _build(payload)
    assert all(item.candidate_text is None for item in document.candidates)
    _, _, no_carrier = _build(
        make_l3_plan("00000000-0000-0000-0000-000000000099", no_carrier=True),
    )
    assert all(item.candidate_text is None for item in no_carrier.candidates)


def test_svi_prefix_and_vlan_reserved_limits_block_text() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    svi = next(
        item for item in payload["logical_interfaces"]
        if item["kind"] == "svi" and item["vlan"] == 20
    )
    svi["address"] = "192.168.20.1/31"
    _, _, prefix_doc = _build(payload)
    assert all(item.candidate_text is None for item in prefix_doc.candidates)
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    svi = next(
        item for item in payload["logical_interfaces"]
        if item["kind"] == "svi" and item["vlan"] == 20
    )
    svi["name"] = "Vlan1"
    svi["vlan"] = 1
    _, _, vlan_doc = _build(payload)
    assert all(item.candidate_text is None for item in vlan_doc.candidates)


def test_svi_role_other_is_blocked() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    core_id = next(
        assignment["id"] for assignment in payload["assignments"]
        if assignment["hostname"] == "L3-Core"
    )
    for port in payload["physical_interfaces"]:
        if port["assignment_id"] == core_id and port["name"] == "Gi1/0/2":
            port["settings"]["allowed_vlans"] = [9, 10, 20, 30]
    payload["vlans"].append({"id": 30, "name": "Other"})
    payload["logical_interfaces"].append({
        "id": "00000000-0000-0000-0000-0000000000aa",
        "assignment_id": core_id,
        "name": "Vlan30",
        "kind": "svi",
        "vlan": 30,
        "address": "192.168.30.1/24",
    })
    _, _, document = _build(payload)
    other = [
        item for item in _by_category(document, CandidateCategory.SVI_INTERFACE)
        if item.target.name == "Vlan30"
    ]
    assert other
    assert other[0].status is CandidateStatus.BLOCKED
    assert "svi-role-other" in other[0].blocking_reasons
    assert other[0].candidate_text is None


def test_dhcp_helper_requires_eligible_svi() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    subnet = next(
        item for item in payload["subnets"]
        if item["network"] == "192.168.20.0/24"
    )
    subnet["network"] = "192.168.20.0/31"
    svi = next(
        item for item in payload["logical_interfaces"]
        if item["kind"] == "svi" and item["vlan"] == 20
    )
    svi["address"] = "192.168.20.1/31"
    _, _, document = _build(payload)
    helper = _by_category(document, CandidateCategory.DHCP_HELPER_ADDRESS)[0]
    assert helper.status is CandidateStatus.BLOCKED
    assert helper.candidate_text is None
    assert "svi-prefix-not-first-batch" in helper.blocking_reasons
    svi_address = [
        item for item in _by_category(document, CandidateCategory.SVI_ADDRESS)
        if item.target.name == "Vlan20"
    ][0]
    assert svi_address.status is CandidateStatus.BLOCKED


def test_dhcp_helper_requires_svi_evidence_too() -> None:
    base = _test_only_evidence_registry()
    rows = tuple(
        replace(row, review=PENDING_REVIEW)
        if row.topic is L3CommandTopic.SVI_ADDRESS
        else row
        for row in base.rows
    )
    registry = CommandEvidenceRegistry(
        rows, registry_id="test-only-svi-address-pending", production=False,
    )
    _, _, document = _build(
        make_l3_plan("00000000-0000-0000-0000-000000000099"),
        registry=registry,
    )
    helper = _by_category(document, CandidateCategory.DHCP_HELPER_ADDRESS)[0]
    assert helper.status is CandidateStatus.BLOCKED
    assert "syntax-evidence-pending" in helper.blocking_reasons


def _planner_errors(payload: dict[str, Any]) -> list[str]:
    return [
        issue.code for issue in validate_plan(plan_model(payload))
        if issue.severity == "ERROR"
    ]


def test_transit_slash31_blocks_default_route_dependency() -> None:
    payload = make_l3_plan(
        "00000000-0000-0000-0000-000000000099", transit_prefix=31,
    )
    assert _planner_errors(payload) == []
    _, intent, document = _build(payload)
    core = next(
        device for device in intent.devices if device.identity.hostname == "L3-Core"
    )
    assert core.readiness.allowed is True
    svi9 = [
        item for item in _by_category(document, CandidateCategory.SVI_INTERFACE)
        if item.target.name == "Vlan9"
    ][0]
    address9 = [
        item for item in _by_category(document, CandidateCategory.SVI_ADDRESS)
        if item.target.name == "Vlan9"
    ][0]
    assert svi9.status is CandidateStatus.BLOCKED
    assert address9.status is CandidateStatus.BLOCKED
    assert "svi-prefix-not-first-batch" in svi9.blocking_reasons
    default = _by_category(document, CandidateCategory.DEFAULT_ROUTE)[0]
    assert default.status is CandidateStatus.BLOCKED
    assert default.candidate_text is None
    assert "route-dependency-svi-prefix-not-first-batch" in default.blocking_reasons


def test_static_route_via_blocked_transit_svi_is_blocked() -> None:
    payload = make_l3_plan(
        "00000000-0000-0000-0000-000000000099",
        transit_prefix=31, static_route_count=1,
    )
    assert _planner_errors(payload) == []
    _, _, document = _build(payload)
    static = _by_category(document, CandidateCategory.STATIC_ROUTE)[0]
    assert static.status is CandidateStatus.BLOCKED
    assert static.candidate_text is None
    assert "route-dependency-svi-prefix-not-first-batch" in static.blocking_reasons


def test_route_dependency_requires_svi_evidence() -> None:
    base = _test_only_evidence_registry()
    rows = tuple(
        replace(row, review=PENDING_REVIEW)
        if row.topic in {L3CommandTopic.SVI_INTERFACE, L3CommandTopic.SVI_ADDRESS}
        else row
        for row in base.rows
    )
    registry = CommandEvidenceRegistry(
        rows, registry_id="test-only-route-svi-evidence-pending", production=False,
    )
    _, _, document = _build(
        make_l3_plan(
            "00000000-0000-0000-0000-000000000099", static_route_count=1,
        ),
        registry=registry,
    )
    default = _by_category(document, CandidateCategory.DEFAULT_ROUTE)[0]
    assert default.status is CandidateStatus.BLOCKED
    assert default.candidate_text is None
    assert "route-dependency-svi-interface-syntax-evidence-pending" in (
        default.blocking_reasons
    )
    static = _by_category(document, CandidateCategory.STATIC_ROUTE)[0]
    assert static.status is CandidateStatus.BLOCKED
    assert static.candidate_text is None
    assert "route-dependency-svi-interface-syntax-evidence-pending" in (
        static.blocking_reasons
    )


def test_transit_slash30_default_route_remains_candidate() -> None:
    _, _, document = _build(
        make_l3_plan("00000000-0000-0000-0000-000000000099", transit_prefix=30),
    )
    default = _by_category(document, CandidateCategory.DEFAULT_ROUTE)[0]
    assert default.status is CandidateStatus.CANDIDATE
    assert default.candidate_text == "ip route 0.0.0.0 0.0.0.0 10.0.0.2"


def test_static_route_via_valid_svi_remains_candidate() -> None:
    _, _, document = _build(make_l3_plan(
        "00000000-0000-0000-0000-000000000099", static_route_count=1,
    ))
    static = _by_category(document, CandidateCategory.STATIC_ROUTE)[0]
    assert static.status is CandidateStatus.CANDIDATE
    assert static.candidate_text == "ip route 10.200.0.0 255.255.255.0 10.0.0.2"


def test_blocked_unrelated_svi_does_not_block_valid_route() -> None:
    payload = make_l3_plan(
        "00000000-0000-0000-0000-000000000099",
        transit_prefix=31,
        static_route_count=1,
        static_route_next_hop="192.168.10.2",
    )
    assert _planner_errors(payload) == []
    _, _, document = _build(payload)
    default = _by_category(document, CandidateCategory.DEFAULT_ROUTE)[0]
    static = _by_category(document, CandidateCategory.STATIC_ROUTE)[0]
    assert default.status is CandidateStatus.BLOCKED
    assert static.status is CandidateStatus.CANDIDATE
    assert static.candidate_text == (
        "ip route 10.200.0.0 255.255.255.0 192.168.10.2"
    )


def test_route_next_hop_on_routed_port_is_not_a_candidate_dependency() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    core_id = next(
        item["id"] for item in payload["assignments"]
        if item["hostname"] == "L3-Core"
    )
    core_device = next(
        item["physical_device_id"] for item in payload["assignments"]
        if item["hostname"] == "L3-Core"
    )
    payload["physical_interfaces"].append({
        "id": "00000000-0000-0000-0000-0000000000cc",
        "assignment_id": core_id,
        "physical_device_id": core_device,
        "name": "Gi1/0/3",
        "settings": {"mode": "routed", "address": "10.99.0.1/30"},
    })
    payload["static_routes"].append({
        "id": "00000000-0000-0000-0000-0000000000cd",
        "assignment_id": core_id,
        "destination": "10.201.0.0/24",
        "next_hop": {"kind": "ip", "address": "10.99.0.2"},
    })
    assert _planner_errors(payload) == []
    _, _, document = _build(payload)
    target = [
        item for item in _by_category(document, CandidateCategory.STATIC_ROUTE)
        if item.target.name == "10.201.0.0/24"
    ][0]
    assert target.status is CandidateStatus.BLOCKED
    assert target.candidate_text is None
    assert "route-next-hop-not-on-link" in target.blocking_reasons


def test_extra_default_route_is_blocked() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    core_id = next(
        assignment["id"] for assignment in payload["assignments"]
        if assignment["hostname"] == "L3-Core"
    )
    payload["default_routes"].append({
        "id": "00000000-0000-0000-0000-0000000000bb",
        "assignment_id": core_id,
        "next_hop": {"kind": "ip", "address": "10.0.0.2"},
        "preference": 2,
    })
    _, _, document = _build(payload)
    defaults = _by_category(document, CandidateCategory.DEFAULT_ROUTE)
    assert len(defaults) == 2
    blocked = [item for item in defaults if item.status is CandidateStatus.BLOCKED]
    assert blocked
    assert "additional-default-route-not-first-batch" in blocked[0].blocking_reasons


def test_routed_port_transition_produces_no_text() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    core_id = next(
        assignment["id"] for assignment in payload["assignments"]
        if assignment["hostname"] == "L3-Core"
    )
    payload["physical_interfaces"].append({
        "id": "00000000-0000-0000-0000-0000000000cc",
        "assignment_id": core_id,
        "physical_device_id": payload["assignments"][0]["physical_device_id"],
        "name": "Gi1/0/3",
        "settings": {"mode": "routed", "address": "10.10.10.1/30"},
    })
    _, _, document = _build(payload)
    assert all(item.candidate_text is None for item in document.candidates)
    assert "routed-port-transition-requires-field-verification" in (
        document.deployment_blockers
    )
    assert not any("switchport" in (item.candidate_text or "") for item in document.candidates)


def test_no_svi_blocks_ip_routing() -> None:
    payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    payload["logical_interfaces"] = []
    payload["subnets"] = []
    payload["gateways"] = []
    payload["dhcp_pools"] = []
    payload["dhcp_relays"] = []
    payload["transit"] = None
    payload["default_routes"] = []
    payload["static_routes"] = []
    _, _, document = _build(payload)
    ip_routing = _by_category(document, CandidateCategory.IP_ROUTING)[0]
    assert ip_routing.status is CandidateStatus.BLOCKED
    assert "no-svi-for-ip-routing" in ip_routing.blocking_reasons


def test_binding_and_target_errors() -> None:
    revision = revision_for(make_l3_plan("00000000-0000-0000-0000-000000000099"))
    intent = build_layer3_intent(revision)
    core = _core_assignment(intent)
    with pytest.raises(RenderBindingError, match="revision-canonical-hash-mismatch"):
        build_l3_cli_candidates(
            revision.model_copy(update={"content_hash": "0" * 64}),
            intent, core, TEST_REGISTRY, test_only_registry=True,
        )
    with pytest.raises(
        RenderBindingError,
        match="intent-not-derived-from-trusted-revision",
    ):
        build_l3_cli_candidates(
            revision,
            intent.model_copy(update={"intent_fingerprint": "0" * 64}),
            core, TEST_REGISTRY, test_only_registry=True,
        )
    forged = intent.model_copy(update={
        "devices": tuple(
            device.model_copy(update={
                "routes": tuple(
                    route.model_copy(update={"distance": 254})
                    if route.kind == "default" else route
                    for route in device.routes
                ),
            })
            if device.identity.assignment_id == core
            else device
            for device in intent.devices
        ),
    })
    forged = forged.model_copy(update={
        "intent_fingerprint": intent_fingerprint(forged),
    })
    with pytest.raises(
        RenderBindingError,
        match="intent-not-derived-from-trusted-revision",
    ):
        build_l3_cli_candidates(
            revision, forged, core, TEST_REGISTRY, test_only_registry=True,
        )
    with pytest.raises(RenderTargetNotFound):
        build_l3_cli_candidates(
            revision, intent, UUID(int=0), TEST_REGISTRY,
            test_only_registry=True,
        )


def test_baseline_must_be_supplied_and_match() -> None:
    baseline_payload = make_l3_plan("00000000-0000-0000-0000-000000000099")
    baseline = revision_for(baseline_payload)
    current_payload = make_l3_plan(
        "00000000-0000-0000-0000-000000000099", static_route_count=1,
    )
    revision = revision_for(current_payload)
    intent = build_layer3_intent(revision, baseline)
    core = _core_assignment(intent)
    with pytest.raises(
        RenderBindingError,
        match="intent-not-derived-from-trusted-revision",
    ):
        build_l3_cli_candidates(
            revision, intent, core, TEST_REGISTRY, test_only_registry=True,
        )
    tampered = baseline.model_copy(update={"content_hash": "0" * 64})
    with pytest.raises(RenderBindingError, match="baseline-canonical-hash-mismatch"):
        build_l3_cli_candidates(
            revision, intent, core, TEST_REGISTRY,
            baseline=tampered, test_only_registry=True,
        )


def test_test_only_registry_requires_explicit_test_flag() -> None:
    revision = revision_for(make_l3_plan("00000000-0000-0000-0000-000000000099"))
    intent = build_layer3_intent(revision)
    with pytest.raises(
        RenderBindingError, match="non-production-registry-not-allowed",
    ):
        build_l3_cli_candidates(
            revision, intent, _core_assignment(intent), TEST_REGISTRY,
        )
    with pytest.raises(
        RenderBindingError, match="test-only-path-rejects-production-registry",
    ):
        build_l3_cli_candidates(
            revision, intent, _core_assignment(intent), DEFAULT_REGISTRY,
            test_only_registry=True,
        )


def test_document_and_candidate_fingerprints_are_deterministic() -> None:
    revision = revision_for(make_l3_plan("00000000-0000-0000-0000-000000000099"))
    intent = build_layer3_intent(revision)
    first = build_l3_cli_candidates(
        revision, intent, _core_assignment(intent), TEST_REGISTRY,
        test_only_registry=True,
    )
    second = build_l3_cli_candidates(
        revision, intent, _core_assignment(intent), TEST_REGISTRY,
        test_only_registry=True,
    )
    assert first.l3_render_fingerprint == second.l3_render_fingerprint
    assert first.model_dump() == second.model_dump()
    candidate = first.candidates[0]
    changed = candidate.model_copy(update={"candidate_text": "ip routing "})
    assert candidate_fingerprint(changed) != candidate_fingerprint(candidate)
    tampered = first.model_copy(update={"summary": first.summary.model_copy(
        update={"total": first.summary.total + 1},
    )})
    assert render_fingerprint(tampered) != first.l3_render_fingerprint


def test_no_full_config_execution_order_or_secret_fields() -> None:
    _, _, document = _build(make_l3_plan("00000000-0000-0000-0000-000000000099"))
    fields = set(L3CandidateDocument.model_fields)
    assert {
        "commands", "configuration", "config", "script", "execution_order",
        "sequence", "paste_ready", "deployment_script", "secrets",
    }.isdisjoint(fields)
    assert document.safety.cli is None
    assert document.safety.executable is False
    assert document.safety.device_writes_enabled is False
    assert all(item.candidate_text is None or len(item.candidate_text.splitlines()) == 1
               for item in document.candidates)
