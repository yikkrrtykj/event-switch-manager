"""CIS-03-03B independent validator semantic and integrity tests."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from layer3_helpers import (
    make_l3_plan,
    make_stack_plan,
    revision_for,
)
from layer3_helpers import (
    test_only_evidence_registry as _test_only_registry,
)
from layer3_parser_helpers import (
    expected_source,
    rebuild_document,
    replace_candidate_and_refresh_source,
    with_candidate_fingerprint,
)

from event_switch_manager.planning.layer3_cli_candidates import (
    Candidate,
    CandidateCategory,
    CandidateStatus,
    L3CandidateDocument,
    RiskClass,
)
from event_switch_manager.planning.layer3_cli_validation import (
    ExpectedSource,
    IndependentVerdict,
    L3ValidationReport,
    ReportOverall,
    ValidationIntegrityError,
    independent_report_fingerprint,
    validate_l3_candidates,
)
from event_switch_manager.planning.layer3_intent import (
    L3DeviceIntent,
    Layer3Intent,
    build_layer3_intent,
)
from event_switch_manager.planning.plan import PlanRevision


def _fixture(
    *,
    static_route_count: int = 1,
    plan_kwargs: dict[str, Any] | None = None,
    stack: bool = False,
) -> tuple[
    PlanRevision, Layer3Intent, L3DeviceIntent, L3CandidateDocument, ExpectedSource,
]:
    payload = (
        make_stack_plan("00000000-0000-0000-0000-000000000099")
        if stack
        else make_l3_plan(
            "00000000-0000-0000-0000-000000000099",
            static_route_count=static_route_count,
            **(plan_kwargs or {}),
        )
    )
    revision = revision_for(payload)
    intent = build_layer3_intent(revision)
    core = next(item for item in intent.devices if item.identity.hostname == "L3-Core")
    document = build_document(revision, intent, core.identity.assignment_id)
    expected = expected_source(revision, intent, document)
    return revision, intent, core, document, expected


def build_document(
    revision: PlanRevision,
    intent: Layer3Intent,
    assignment_id: UUID,
    *,
    baseline: PlanRevision | None = None,
) -> L3CandidateDocument:
    from event_switch_manager.planning.layer3_cli_candidates import (
        build_l3_cli_candidates,
    )

    return build_l3_cli_candidates(
        revision, intent, assignment_id, baseline=baseline,
    )


def _report(
    revision: PlanRevision,
    intent: Layer3Intent,
    document: L3CandidateDocument,
    expected: ExpectedSource,
    assignment_id: UUID,
    **kwargs: Any,
) -> L3ValidationReport:
    return validate_l3_candidates(
        revision, intent, document, expected, assignment_id, **kwargs,
    )


def _category(
    document: L3CandidateDocument,
    category: CandidateCategory,
) -> Candidate:
    return next(
        item for item in document.candidates if item.category is category
    )


def test_real_production_report_passes_base_and_blocks_helper() -> None:
    revision, intent, core, document, expected = _fixture()
    report = _report(revision, intent, document, expected, core.identity.assignment_id)
    assert report.overall_status is ReportOverall.PARTIAL
    assert report.summary.total == 10
    assert report.summary.passed == 9
    assert report.summary.failed == 0
    assert report.summary.blocked == 1
    assert report.summary.base_categories_passed == 5
    assert report.summary.base_categories_failed == 0
    assert report.summary.base_candidates_passed == 9
    assert report.summary.dhcp_helper_blocked is True
    base = [
        item for item in report.candidates
        if item.category != CandidateCategory.DHCP_HELPER_ADDRESS.value
    ]
    helper = next(
        item for item in report.candidates
        if item.category == CandidateCategory.DHCP_HELPER_ADDRESS.value
    )
    assert all(item.independent_verdict is IndependentVerdict.PASS for item in base)
    assert helper.independent_verdict is IndependentVerdict.BLOCKED
    assert helper.parse.status == "not-run"
    assert "license-unresolved" in helper.evidence.reason_codes
    assert "evidence-review-pending" in helper.evidence.reason_codes
    assert helper.fail_closed_action == "suppress-and-defer"
    assert report.report_fingerprint == independent_report_fingerprint(report)
    assert report.validation_scope == "production"
    assert report.safety.candidate_only is True
    assert report.safety.executable is False
    assert report.safety.deployment_allowed is False
    assert report.safety.parser_verified is True
    serialized = report.model_dump_json()
    assert "ip route 10.200.0.0" not in serialized
    assert "ip address 192.168.10.1" not in serialized
    assert all(
        candidate.syntax_validation.parser_verified is False
        for candidate in document.candidates
    )


def test_report_binds_every_candidate_to_evidence_and_intent() -> None:
    revision, intent, core, document, expected = _fixture()
    report = _report(revision, intent, document, expected, core.identity.assignment_id)
    by_id = {item.candidate_id: item for item in report.candidates}
    for candidate in document.candidates:
        item = by_id[candidate.candidate_id]
        assert item.category == candidate.category.value
        assert item.target_kind == candidate.target.kind
        assert item.target_stable_id == candidate.target.stable_id
        if candidate.candidate_text is not None:
            assert item.parse.status == "pass"
            assert item.context_binding.bound is True
            assert item.evidence.scope_ok is True
            assert item.target_capability.documented is True
            assert item.risk.non_degraded is True
            assert item.independent_verdict is IndependentVerdict.PASS
        else:
            assert item.parse.status == "not-run"
            assert item.independent_verdict is IndependentVerdict.BLOCKED


@pytest.mark.parametrize(
    "field",
    (
        "event_id",
        "saved_revision_uuid",
        "revision_number",
        "revision_canonical_hash",
        "l3_intent_schema_version",
        "l3_intent_fingerprint",
        "l3_render_contract_id",
        "l3_render_contract_version",
        "l3_render_fingerprint",
        "command_evidence_registry_id",
        "command_evidence_registry_fingerprint",
        "assignment_id",
        "baseline_revision_uuid",
        "baseline_revision_hash",
    ),
)
def test_expected_source_field_mismatch_fails_closed(field: str) -> None:
    revision, intent, core, document, expected = _fixture()
    value: object
    if field in {"event_id", "saved_revision_uuid", "assignment_id"}:
        value = uuid4()
    elif field in {"revision_number", "l3_intent_schema_version",
                   "l3_render_contract_version"}:
        value = 99
    elif field == "baseline_revision_uuid":
        value = uuid4()
    else:
        value = "0" * 64
    tampered = expected.model_copy(update={field: value})
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(revision, intent, document, tampered, core.identity.assignment_id)
    assert caught.value.reason_code == "expected-source-mismatch"
    assert any(field.replace("_", "-") in reason for reason in caught.value.reasons)


def test_document_fingerprint_and_candidate_fingerprint_tamper_fail_closed() -> None:
    revision, intent, core, document, expected = _fixture()
    bad_document = document.model_copy(update={"l3_render_fingerprint": "0" * 64})
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(revision, intent, bad_document, expected, core.identity.assignment_id)
    assert caught.value.reason_code == "document-fingerprint-mismatch"

    candidate = document.candidates[0]
    bad_candidate = candidate.model_copy(update={"candidate_fingerprint": "0" * 64})
    candidates = (bad_candidate, *document.candidates[1:])
    bad_document = document.model_copy(update={
        "candidates": candidates,
        "l3_render_fingerprint": "0" * 64,
    })
    # Recompute the document fingerprint only, leaving the candidate invalid.
    from event_switch_manager.planning.layer3_cli_validation import (
        independent_render_fingerprint,
    )

    bad_document = bad_document.model_copy(update={
        "l3_render_fingerprint": independent_render_fingerprint(bad_document),
    })
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(revision, intent, bad_document, expected, core.identity.assignment_id)
    assert caught.value.reason_code == "candidate-fingerprint-mismatch"


def test_missing_duplicate_candidate_and_summary_tamper_fail_closed() -> None:
    revision, intent, core, document, expected = _fixture()
    missing = rebuild_document(document, document.candidates[:-1])
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(revision, intent, missing, expected_source(revision, intent, missing),
                core.identity.assignment_id)
    assert caught.value.reason_code == "candidate-set-mismatch"

    duplicate = rebuild_document(document, (*document.candidates, document.candidates[0]))
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(revision, intent, duplicate, expected_source(revision, intent, duplicate),
                core.identity.assignment_id)
    assert caught.value.reason_code == "duplicate-candidate-id"

    summary = document.summary.model_copy(update={"candidates": 99})
    forged = rebuild_document(document, updates={"summary": summary})
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(revision, intent, forged, expected_source(revision, intent, forged),
                core.identity.assignment_id)
    assert caught.value.reason_code == "summary-count-mismatch"


def test_unsafe_document_flags_and_contract_fail_closed() -> None:
    revision, intent, core, document, expected = _fixture()
    unsafe = rebuild_document(document, updates={"executable": True})
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(revision, intent, unsafe, expected_source(revision, intent, unsafe),
                core.identity.assignment_id)
    assert caught.value.reason_code == "unsafe-document-flags"

    bad_contract = rebuild_document(document, updates={"contract_id": "unknown"})
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(revision, intent, bad_contract,
                expected_source(revision, intent, bad_contract),
                core.identity.assignment_id)
    assert caught.value.reason_code == "candidate-contract-mismatch"


def test_cross_event_revision_assignment_is_rejected() -> None:
    revision, intent, core, document, expected = _fixture()
    other = revision_for(make_l3_plan("00000000-0000-0000-0000-000000000100",
                                      static_route_count=1))
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(other, intent, document, expected, core.identity.assignment_id)
    assert caught.value.reason_code in {
        "intent-revision-mismatch",
        "expected-source-mismatch",
    }
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(revision, intent, document, expected, uuid4())
    assert caught.value.reason_code in {
        "assignment-not-in-intent",
        "expected-source-mismatch",
    }


def test_untrusted_production_registry_is_rejected() -> None:
    revision, intent, core, document, expected = _fixture()
    test_registry = _test_only_registry()
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(
            revision, intent, document,
            expected.model_copy(update={
                "command_evidence_registry_id": test_registry.registry_id,
                "command_evidence_registry_fingerprint": test_registry.fingerprint,
            }),
            core.identity.assignment_id,
            registry=test_registry,
        )
    assert caught.value.reason_code == "untrusted-production-registry"


def test_test_only_path_rejects_production_registry() -> None:
    revision, intent, core, document, expected = _fixture()
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(
            revision, intent, document, expected,
            core.identity.assignment_id, test_only_registry=True,
        )
    assert caught.value.reason_code == "test-only-path-rejects-production-registry"


def test_unreviewed_evidence_cannot_pass() -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, CandidateCategory.SVI_INTERFACE)
    forged_evidence = candidate.syntax_evidence[0].model_copy(update={
        "evidence_id": "l3-9300-dhcp-helper-address-v1",
        "content_digest": "0" * 64,
    })
    changed = candidate.model_copy(update={
        "syntax_evidence": (forged_evidence,),
    })
    new_document, new_expected = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), changed,
    )
    report = _report(
        revision, intent, new_document, new_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates if item.candidate_id == candidate.candidate_id
    )
    assert item.independent_verdict is IndependentVerdict.FAIL
    assert "evidence-topic-mismatch" in item.evidence.reason_codes
    assert "evidence-digest-mismatch" in item.evidence.reason_codes


def test_forged_evidence_digest_and_review_metadata_fail() -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, CandidateCategory.STATIC_ROUTE)
    ref = candidate.syntax_evidence[0]
    forged = ref.model_copy(update={
        "content_digest": "f" * 64,
        "review_state": "independently-reviewed",
    })
    changed = candidate.model_copy(update={"syntax_evidence": (forged,)})
    new_document, new_expected = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), changed,
    )
    report = _report(
        revision, intent, new_document, new_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert item.independent_verdict is IndependentVerdict.FAIL
    assert "evidence-digest-mismatch" in item.evidence.reason_codes


@pytest.mark.parametrize(
    ("category", "new_text", "expected_reason"),
    (
        (
            CandidateCategory.STATIC_ROUTE,
            "ip route 10.200.0.0 255.255.255.0 10.0.0.1",
            "parsed-next-hop-mismatch",
        ),
        (
            CandidateCategory.STATIC_ROUTE,
            "ip route 10.201.0.0 255.255.255.0 10.0.0.2",
            "parsed-destination-mismatch",
        ),
        (
            CandidateCategory.SVI_ADDRESS,
            "ip address 192.168.10.9 255.255.255.0",
            "parsed-address-mismatch",
        ),
        (
            CandidateCategory.DEFAULT_ROUTE,
            "ip route 0.0.0.0 0.0.0.0 10.0.0.3",
            "parsed-default-next-hop-mismatch",
        ),
        (
            CandidateCategory.SVI_INTERFACE,
            "interface Vlan99",
            "parsed-vlan-mismatch",
        ),
    ),
)
def test_correct_hashes_but_wrong_semantics_fail(
    category: CandidateCategory,
    new_text: str,
    expected_reason: str,
) -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, category)
    changed = candidate.model_copy(update={"candidate_text": new_text})
    new_document, new_expected = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), changed,
    )
    report = _report(
        revision, intent, new_document, new_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert item.independent_verdict is IndependentVerdict.FAIL
    assert expected_reason in item.semantics.reason_codes
    assert report.overall_status is ReportOverall.FAIL


def test_wrong_mode_context_and_parameters_fail() -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, CandidateCategory.SVI_ADDRESS)
    bad_context = candidate.command_context.model_copy(update={"mode": "global"})
    changed = candidate.model_copy(update={"command_context": bad_context})
    new_document, new_expected = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), changed,
    )
    report = _report(
        revision, intent, new_document, new_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert "context-mode-mismatch" in item.context_binding.reason_codes
    assert item.independent_verdict is IndependentVerdict.FAIL

    changed = candidate.model_copy(update={
        "parameters": {"address": "192.168.10.99", "mask": "255.255.255.0"},
    })
    new_document, new_expected = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), changed,
    )
    report = _report(
        revision, intent, new_document, new_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert "candidate-parameters-mismatch" in item.semantics.reason_codes


def test_low_risk_and_parser_verified_are_fail_closed() -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, CandidateCategory.DEFAULT_ROUTE)
    changed = candidate.model_copy(update={"risk_class": RiskClass.R2})
    new_document, new_expected = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), changed,
    )
    report = _report(
        revision, intent, new_document, new_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert "risk-class-below-floor" in item.risk.reason_codes
    assert item.independent_verdict is IndependentVerdict.FAIL

    changed = candidate.model_copy(update={
        "syntax_validation": candidate.syntax_validation.model_copy(
            update={"parser_verified": True},
        ),
    })
    new_document, new_expected = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), changed,
    )
    report = _report(
        revision, intent, new_document, new_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert "renderer-parser-verified-must-be-false" in item.semantics.reason_codes


def test_blocked_candidate_with_text_is_integrity_failure() -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, CandidateCategory.DHCP_HELPER_ADDRESS)
    assert candidate.candidate_text is None
    changed = candidate.model_copy(update={
        "candidate_text": "ip helper-address 192.168.20.5",
        "status": CandidateStatus.BLOCKED,
    })
    changed = with_candidate_fingerprint(changed)
    candidates = list(document.candidates)
    candidates[document.candidates.index(candidate)] = changed
    forged = rebuild_document(document, tuple(candidates))
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(revision, intent, forged, expected_source(revision, intent, forged),
                core.identity.assignment_id)
    assert caught.value.reason_code == "blocked-candidate-carries-text"


def test_parse_failure_of_candidate_text_fails_report() -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, CandidateCategory.STATIC_ROUTE)
    changed = candidate.model_copy(update={"candidate_text": "show running-config"})
    new_document, new_expected = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), changed,
    )
    report = _report(
        revision, intent, new_document, new_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert item.independent_verdict is IndependentVerdict.FAIL
    assert item.parse.status == "fail"
    assert any(
        failure.split("@")[0] == "unknown-command"
        for failure in item.parse.failures
    )
    assert report.overall_status is ReportOverall.FAIL


@pytest.mark.parametrize(
    ("kwargs", "expect_fail"),
    (
        ({"core_pid": "C9200L-24P-4X", "core_family": "catalyst-9200"}, True),
        ({"core_image": "17.12.5"}, True),
        ({"core_license": "Unknown License"}, True),
        ({"routing_enabled": False}, True),
        ({"with_transit": False}, True),
        ({"with_default": False}, True),
        ({"default_distance": 255}, True),
        ({"default_distance": 256}, True),
        ({"transit_prefix": 31}, True),
        ({"deny_policy": True}, True),
        ({"no_carrier": True}, True),
    ),
)
def test_unsupported_or_unsafe_plans_never_pass(
    kwargs: dict[str, Any], expect_fail: bool,
) -> None:
    revision, intent, core, document, expected = _fixture(plan_kwargs=kwargs)
    report = _report(revision, intent, document, expected, core.identity.assignment_id)
    assert report.overall_status is not ReportOverall.PASS
    if expect_fail:
        assert report.summary.failed or report.summary.blocked
        assert not all(
            item.independent_verdict is IndependentVerdict.PASS
            for item in report.candidates
            if item.category != CandidateCategory.DHCP_HELPER_ADDRESS.value
        )


def test_unresolved_stack_never_passes() -> None:
    revision, intent, core, document, expected = _fixture(stack=True)
    payload = make_stack_plan(
        "00000000-0000-0000-0000-000000000099", second_serial=None,
    )
    revision = revision_for(payload)
    intent = build_layer3_intent(revision)
    core = next(item for item in intent.devices if item.identity.hostname == "L3-Core")
    document = build_document(revision, intent, core.identity.assignment_id)
    expected = expected_source(revision, intent, document)
    report = _report(revision, intent, document, expected, core.identity.assignment_id)
    assert all(
        item.independent_verdict is not IndependentVerdict.PASS
        for item in report.candidates
    )


def test_test_only_path_is_explicitly_scoped() -> None:
    payload = make_l3_plan(
        "00000000-0000-0000-0000-000000000099", static_route_count=1,
    )
    revision = revision_for(payload)
    intent = build_layer3_intent(revision)
    core = next(item for item in intent.devices if item.identity.hostname == "L3-Core")
    registry = _test_only_registry()
    from event_switch_manager.planning.layer3_cli_candidates import (
        build_l3_cli_candidates,
    )

    document = build_l3_cli_candidates(
        revision, intent, core.identity.assignment_id, registry,
        test_only_registry=True,
    )
    expected = expected_source(revision, intent, document, registry)
    report = _report(
        revision, intent, document, expected, core.identity.assignment_id,
        registry=registry,
        test_only_registry=True,
    )
    assert report.validation_scope == "test-only"
    assert report.overall_status is not ReportOverall.PASS


def test_baseline_binding_is_independently_checked() -> None:
    baseline = revision_for(
        make_l3_plan(
            "00000000-0000-0000-0000-000000000099", static_route_count=1,
        ),
        number=1,
    )
    revision = revision_for(
        make_l3_plan(
            "00000000-0000-0000-0000-000000000099", static_route_count=1,
        ),
        number=2,
    )
    intent = build_layer3_intent(revision, baseline)
    core = next(item for item in intent.devices if item.identity.hostname == "L3-Core")
    document = build_document(
        revision, intent, core.identity.assignment_id, baseline=baseline,
    )
    expected = expected_source(revision, intent, document)
    report = _report(
        revision, intent, document, expected, core.identity.assignment_id,
        baseline=baseline,
    )
    assert report.source.baseline_revision_uuid == baseline.id
    assert report.source.baseline_revision_hash == baseline.content_hash
    bad_expected = expected.model_copy(update={"baseline_revision_hash": "0" * 64})
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(
            revision, intent, document, bad_expected, core.identity.assignment_id,
            baseline=baseline,
        )
    assert caught.value.reason_code == "expected-source-mismatch"


def test_report_is_deterministic() -> None:
    revision, intent, core, document, expected = _fixture()
    first = _report(revision, intent, document, expected, core.identity.assignment_id)
    second = _report(revision, intent, document, expected, core.identity.assignment_id)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.report_fingerprint == second.report_fingerprint


def test_rejected_evidence_never_passes() -> None:
    from dataclasses import replace as dataclass_replace

    from event_switch_manager.planning.layer3_cli_candidates import (
        build_l3_cli_candidates,
    )
    from event_switch_manager.planning.layer3_command_evidence import (
        CommandEvidenceRegistry,
        EvidenceReview,
        EvidenceReviewState,
    )

    base = _test_only_registry()
    rejected_row = next(
        item for item in base.rows if item.evidence_id == "l3-9300-static-route-v1"
    )
    rejected = dataclass_replace(
        rejected_row,
        review=EvidenceReview(
            state=EvidenceReviewState.REJECTED,
            reviewer=rejected_row.review.reviewer,
            reviewed_at=rejected_row.review.reviewed_at,
            findings=rejected_row.review.findings,
            content_digest=rejected_row.content_digest(),
        ),
    )
    rows = tuple(
        rejected if item.evidence_id == rejected.evidence_id else item
        for item in base.rows
    )
    registry = CommandEvidenceRegistry(
        rows, registry_id="cis-03-test-only-rejected-v1", production=False,
    )
    payload = make_l3_plan(
        "00000000-0000-0000-0000-000000000099", static_route_count=1,
    )
    revision = revision_for(payload)
    intent = build_layer3_intent(revision)
    core = next(item for item in intent.devices if item.identity.hostname == "L3-Core")
    document = build_l3_cli_candidates(
        revision, intent, core.identity.assignment_id, registry,
        test_only_registry=True,
    )
    expected = expected_source(revision, intent, document, registry)
    report = _report(
        revision, intent, document, expected, core.identity.assignment_id,
        registry=registry, test_only_registry=True,
    )
    static = next(
        item for item in report.candidates
        if item.category == CandidateCategory.STATIC_ROUTE.value
    )
    assert static.independent_verdict is IndependentVerdict.BLOCKED
    assert "evidence-not-renderable" in static.evidence.reason_codes
    assert report.overall_status is not ReportOverall.PASS


def test_candidate_id_is_derived_from_trusted_target() -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, CandidateCategory.STATIC_ROUTE)
    assert candidate.candidate_id.startswith("l3cand-")
    forged = candidate.model_copy(update={"candidate_id": "l3cand-0000000000000000"})
    changed, changed_expected = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), forged,
    )
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(
            revision, intent, changed, changed_expected,
            core.identity.assignment_id,
        )
    assert caught.value.reason_code == "candidate-id-mismatch"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("hostname", "FORGED-CORE"),
        ("role", "access"),
        ("family", "catalyst-9200"),
        ("exact_pid", "C9300X-24Y"),
        ("software_image", "17.12.5"),
        ("software_license", "Network Essentials"),
        ("stack_identity", "unresolved"),
    ),
)
def test_document_device_identity_is_bound_to_trusted_intent(
    field: str, value: str,
) -> None:
    revision, intent, core, document, expected = _fixture()
    bad_device = document.device.model_copy(update={field: value})
    changed = rebuild_document(document, updates={"device": bad_device})
    changed_expected = expected_source(revision, intent, changed)
    with pytest.raises(ValidationIntegrityError) as caught:
        _report(
            revision, intent, changed, changed_expected,
            core.identity.assignment_id,
        )
    assert caught.value.reason_code == "device-identity-mismatch"


def test_report_device_identity_comes_from_trusted_intent() -> None:
    revision, intent, core, document, expected = _fixture()
    report = _report(revision, intent, document, expected, core.identity.assignment_id)
    assert report.device.assignment_id == core.identity.assignment_id
    assert report.device.hostname == core.identity.hostname
    assert report.device.role == core.identity.role.value
    assert core.identity.family is not None
    assert report.device.family == core.identity.family.value
    assert report.device.exact_pid == core.identity.exact_pid
    assert report.device.software_image == core.identity.software_image
    assert report.device.software_license == core.identity.software_license
    assert report.device.stack_identity == core.identity.stack_identity


def test_resolved_stack_identity_regression() -> None:
    revision, intent, core, document, expected = _fixture(stack=True)
    report = _report(revision, intent, document, expected, core.identity.assignment_id)
    assert report.device.stack_identity == "resolved"
    base = [
        item for item in report.candidates
        if item.category != CandidateCategory.DHCP_HELPER_ADDRESS.value
    ]
    assert all(item.independent_verdict is IndependentVerdict.PASS for item in base)


def test_forged_blocked_status_without_blocker_fails() -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, CandidateCategory.STATIC_ROUTE)
    forged = candidate.model_copy(update={
        "status": CandidateStatus.BLOCKED,
        "candidate_text": None,
    })
    changed, _ = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), forged,
    )
    summary = document.summary.model_copy(update={"candidates": 8, "blocked": 2})
    changed = rebuild_document(changed, updates={"summary": summary})
    changed_expected = expected_source(revision, intent, changed)
    report = _report(
        revision, intent, changed, changed_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert item.independent_verdict is IndependentVerdict.FAIL
    assert "blocked-verdict-not-supported" in item.semantics.reason_codes
    assert report.overall_status is ReportOverall.FAIL
    assert report.summary.failed == 1


def test_forged_unsupported_status_without_unsupported_capability_fails() -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, CandidateCategory.STATIC_ROUTE)
    forged = candidate.model_copy(update={
        "status": CandidateStatus.UNSUPPORTED,
        "candidate_text": None,
    })
    changed, _ = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), forged,
    )
    summary = document.summary.model_copy(update={"candidates": 8, "unsupported": 1})
    changed = rebuild_document(changed, updates={"summary": summary})
    changed_expected = expected_source(revision, intent, changed)
    report = _report(
        revision, intent, changed, changed_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert item.independent_verdict is IndependentVerdict.FAIL
    assert "blocked-verdict-not-supported" in item.semantics.reason_codes


def test_blocked_candidate_with_invalid_context_fails() -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, CandidateCategory.STATIC_ROUTE)
    bad_context = candidate.command_context.model_copy(update={
        "mode": "interface", "mode_header": "interface Vlan10",
    })
    forged = candidate.model_copy(update={
        "status": CandidateStatus.BLOCKED,
        "candidate_text": None,
        "command_context": bad_context,
    })
    changed, _ = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), forged,
    )
    summary = document.summary.model_copy(update={"candidates": 8, "blocked": 2})
    changed = rebuild_document(changed, updates={"summary": summary})
    changed_expected = expected_source(revision, intent, changed)
    report = _report(
        revision, intent, changed, changed_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert item.independent_verdict is IndependentVerdict.FAIL


def test_blocked_candidate_with_forged_evidence_fails() -> None:
    revision, intent, core, document, expected = _fixture()
    candidate = _category(document, CandidateCategory.STATIC_ROUTE)
    forged_ref = candidate.syntax_evidence[0].model_copy(update={
        "evidence_id": "l3-9300-ip-routing-v1",
        "content_digest": "0" * 64,
    })
    forged = candidate.model_copy(update={
        "status": CandidateStatus.BLOCKED,
        "candidate_text": None,
        "syntax_evidence": (forged_ref,),
    })
    changed, _ = replace_candidate_and_refresh_source(
        revision, intent, document,
        document.candidates.index(candidate), forged,
    )
    summary = document.summary.model_copy(update={"candidates": 8, "blocked": 2})
    changed = rebuild_document(changed, updates={"summary": summary})
    changed_expected = expected_source(revision, intent, changed)
    report = _report(
        revision, intent, changed, changed_expected, core.identity.assignment_id,
    )
    item = next(
        item for item in report.candidates
        if item.candidate_id == candidate.candidate_id
    )
    assert item.independent_verdict is IndependentVerdict.FAIL


def test_legitimate_route_block_and_unsupported_device_remain_blocked() -> None:
    revision, intent, core, document, expected = _fixture(
        plan_kwargs={"default_distance": 255},
    )
    report = _report(revision, intent, document, expected, core.identity.assignment_id)
    default = next(
        item for item in report.candidates
        if item.category == CandidateCategory.DEFAULT_ROUTE.value
    )
    assert default.independent_verdict is IndependentVerdict.BLOCKED

    revision, intent, core, document, expected = _fixture(
        plan_kwargs={"core_pid": "C9200L-24P-4X", "core_family": "catalyst-9200"},
    )
    report = _report(revision, intent, document, expected, core.identity.assignment_id)
    base = [
        item for item in report.candidates
        if item.category != CandidateCategory.DHCP_HELPER_ADDRESS.value
    ]
    assert base and all(
        item.independent_verdict is IndependentVerdict.BLOCKED for item in base
    )


def test_dhcp_only_service_blocker_does_not_block_forwarding() -> None:
    revision, intent, core, document, expected = _fixture(
        plan_kwargs={"core_license": "Network Essentials"},
    )
    assert core.service_blockers == ("l3-license-unmatched",)
    report = _report(revision, intent, document, expected, core.identity.assignment_id)
    assert report.overall_status is ReportOverall.PARTIAL
    assert report.summary.base_categories_passed == 5
    assert report.summary.base_candidates_passed == 9
    helper = next(
        item for item in report.candidates
        if item.category == CandidateCategory.DHCP_HELPER_ADDRESS.value
    )
    assert helper.independent_verdict is IndependentVerdict.BLOCKED


def test_unknown_plan_pid_and_bad_transit_route_are_blocked() -> None:
    revision, intent, core, document, expected = _fixture(
        plan_kwargs={"core_pid": "C9300-24T-A"},
    )
    report = _report(revision, intent, document, expected, core.identity.assignment_id)
    assert report.overall_status is not ReportOverall.PASS
    assert all(
        item.independent_verdict is not IndependentVerdict.PASS
        for item in report.candidates
        if item.category != CandidateCategory.DHCP_HELPER_ADDRESS.value
    )
