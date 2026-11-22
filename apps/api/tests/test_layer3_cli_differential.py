"""CIS-03-03B renderer/parser differential tests using real production output."""

from __future__ import annotations

import json

import pytest
from layer3_helpers import make_l3_plan, revision_for
from layer3_parser_helpers import expected_source, replace_candidate_and_refresh_source

from event_switch_manager.planning.layer3_cli_candidates import (
    CandidateCategory,
    L3CandidateDocument,
    build_l3_cli_candidates,
)
from event_switch_manager.planning.layer3_cli_grammar import L3Form, L3Mode
from event_switch_manager.planning.layer3_cli_parser import parse_l3_command
from event_switch_manager.planning.layer3_cli_validation import (
    ExpectedSource,
    IndependentVerdict,
    ReportOverall,
    independent_candidate_fingerprint,
    independent_render_fingerprint,
    validate_l3_candidates,
)
from event_switch_manager.planning.layer3_intent import (
    L3DeviceIntent,
    Layer3Intent,
    build_layer3_intent,
)
from event_switch_manager.planning.plan import PlanRevision


def _fixture() -> tuple[
    PlanRevision, Layer3Intent, L3DeviceIntent, L3CandidateDocument, ExpectedSource,
]:
    revision = revision_for(make_l3_plan(
        "00000000-0000-0000-0000-000000000099", static_route_count=1,
    ))
    intent = build_layer3_intent(revision)
    core = next(item for item in intent.devices if item.identity.hostname == "L3-Core")
    document = build_l3_cli_candidates(revision, intent, core.identity.assignment_id)
    expected = expected_source(revision, intent, document)
    return revision, intent, core, document, expected


def test_real_renderer_has_ten_candidates_nine_with_text() -> None:
    _, _, _, document, _ = _fixture()
    assert len(document.candidates) == 10
    texts = [item.candidate_text for item in document.candidates]
    assert sum(text is not None for text in texts) == 9
    assert sum(text is None for text in texts) == 1
    assert document.summary.total == 10
    assert document.summary.candidates == 9
    assert document.summary.blocked == 1


def test_every_nonempty_renderer_text_is_one_independent_command() -> None:
    _, _, _, document, _ = _fixture()
    for candidate in document.candidates:
        if candidate.candidate_text is None:
            continue
        assert "\n" not in candidate.candidate_text
        assert "\r" not in candidate.candidate_text
        assert candidate.candidate_text.strip() == candidate.candidate_text
        parsed = parse_l3_command(candidate.candidate_text)
        assert parsed.ok is True, (candidate.candidate_text, parsed.failure_codes)
        assert parsed.form is not None
        assert parsed.form.value == candidate.category.value
        assert parsed.mode is (
            L3Mode.GLOBAL
            if candidate.command_context.mode == "global"
            else L3Mode.INTERFACE
        )
        assert candidate.candidate_text.split()[0] != "no"


@pytest.mark.parametrize(
    ("category", "form"),
    (
        (CandidateCategory.IP_ROUTING, L3Form.IP_ROUTING),
        (CandidateCategory.SVI_INTERFACE, L3Form.SVI_INTERFACE),
        (CandidateCategory.SVI_ADDRESS, L3Form.SVI_ADDRESS),
        (CandidateCategory.STATIC_ROUTE, L3Form.STATIC_ROUTE),
        (CandidateCategory.DEFAULT_ROUTE, L3Form.DEFAULT_ROUTE),
    ),
)
def test_renderer_parser_differential_category_parameters(
    category: CandidateCategory, form: L3Form,
) -> None:
    revision, intent, core, document, _ = _fixture()
    candidate = next(item for item in document.candidates if item.category is category)
    assert candidate.candidate_text is not None
    parsed = parse_l3_command(candidate.candidate_text)
    assert parsed.form is form
    if category is CandidateCategory.IP_ROUTING:
        assert parsed.parameter_dict() == {}
    elif category is CandidateCategory.SVI_INTERFACE:
        interface = next(
            item for item in core.interfaces
            if item.interface_id == candidate.provenance.intent_interface_id
        )
        assert parsed.parameter("vlan_id") == interface.vlan
    elif category is CandidateCategory.SVI_ADDRESS:
        interface = next(
            item for item in core.interfaces
            if item.interface_id == candidate.provenance.intent_interface_id
        )
        assert interface.address is not None
        assert parsed.parameter("address") == str(interface.address.ip)
        assert parsed.parameter("mask") == str(interface.address.netmask)
    else:
        route = next(
            item for item in core.routes
            if item.route_id == candidate.provenance.intent_route_id
        )
        assert parsed.parameter("destination") == str(route.destination)
        assert parsed.parameter("next_hop") == str(route.next_hop)
        assert parsed.parameter("distance") == route.distance


def test_real_renderer_parser_differential_full_report() -> None:
    revision, intent, core, document, expected = _fixture()
    report = validate_l3_candidates(
        revision, intent, document, expected, core.identity.assignment_id,
    )
    assert report.overall_status is ReportOverall.PARTIAL
    assert report.summary.passed == 9
    assert report.summary.failed == 0
    assert report.summary.blocked == 1
    assert report.summary.base_categories_passed == 5
    assert report.summary.base_candidates_passed == 9
    assert report.summary.dhcp_helper_blocked is True
    assert report.report_fingerprint
    helper = next(
        item for item in report.candidates
        if item.category == CandidateCategory.DHCP_HELPER_ADDRESS.value
    )
    assert helper.independent_verdict is IndependentVerdict.BLOCKED
    assert "evidence-review-pending" in helper.evidence.reason_codes


def test_document_and_candidate_fingerprints_are_recomputable() -> None:
    revision, intent, core, document, expected = _fixture()
    assert document.l3_render_fingerprint == independent_render_fingerprint(document)
    for candidate in document.candidates:
        assert candidate.candidate_fingerprint == independent_candidate_fingerprint(candidate)
    report = validate_l3_candidates(
        revision, intent, document, expected, core.identity.assignment_id,
    )
    assert report.candidates[0].candidate_id == document.candidates[0].candidate_id
    assert report.report_fingerprint


def test_renderer_output_is_deterministic_for_same_plan() -> None:
    revision, intent, core, document, _ = _fixture()
    again = build_l3_cli_candidates(revision, intent, core.identity.assignment_id)
    assert document.model_dump(mode="json") == again.model_dump(mode="json")


@pytest.mark.parametrize(
    ("category", "new_text"),
    (
        (
            CandidateCategory.STATIC_ROUTE,
            "ip route 10.200.0.0 255.255.255.0 10.0.0.1",
        ),
        (
            CandidateCategory.DEFAULT_ROUTE,
            "ip route 0.0.0.0 0.0.0.0 10.0.0.3",
        ),
        (
            CandidateCategory.SVI_ADDRESS,
            "ip address 192.168.10.9 255.255.255.0",
        ),
        (
            CandidateCategory.SVI_INTERFACE,
            "interface Vlan99",
        ),
    ),
)
def test_parser_detects_wrong_text_after_fingerprint_recompute(
    category: CandidateCategory, new_text: str,
) -> None:
    revision, intent, core, document, _ = _fixture()
    candidate = next(item for item in document.candidates if item.category is category)
    changed = candidate.model_copy(update={"candidate_text": new_text})
    new_document, new_expected = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), changed,
    )
    report = validate_l3_candidates(
        revision, intent, new_document, new_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert item.independent_verdict is IndependentVerdict.FAIL
    assert report.overall_status is ReportOverall.FAIL


def test_report_does_not_embed_renderer_text_or_commands() -> None:
    revision, intent, core, document, expected = _fixture()
    report = validate_l3_candidates(
        revision, intent, document, expected, core.identity.assignment_id,
    )
    serialized = json.dumps(report.model_dump(mode="json"), ensure_ascii=False)
    for candidate in document.candidates:
        if candidate.candidate_text:
            assert candidate.candidate_text not in serialized
    assert "configure terminal" not in serialized
    assert "ip routing" not in serialized
