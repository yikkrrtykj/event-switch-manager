"""R63 staged reviewed management Evidence tests.

These tests prove the isolated reviewed path (1 PASS / 8 BLOCKED) and the fixed
review binding without activating any production review.  The production
selector must continue to return the original 18-row PENDING draft registry.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from uuid import UUID

import pytest
from layer3_helpers import make_l3_plan, revision_for

from event_switch_manager.planning import management_command_evidence_reviews as reviews_module
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.planning.management_cli_candidates import (
    ManagementRenderError,
    build_management_cli_candidates,
    validate_management_candidates,
)
from event_switch_manager.planning.management_command_evidence import (
    MANAGEMENT_EVIDENCE_DRAFT_REGISTRY,
    ManagementCommandTopic,
)
from event_switch_manager.planning.management_command_evidence_reviews import (
    DOCUMENT_REVIEW_RECORDS,
    MANAGEMENT_APPROVED_REVIEWS,
    PRODUCTION_APPROVED_RECORDS,
    R63_CORRECTED_ROWS,
    R63_OLD_DIGESTS,
    R63_REVIEWED_EVIDENCE_IDS,
    R63_STAGED_DIGESTS,
    R63_STAGED_REGISTRY,
    R63_STAGED_REGISTRY_FINGERPRINT,
    R63A_AI_REVIEW_DATE,
    R63A_AI_REVIEW_TYPE,
    R63A_AI_REVIEWER,
    R63A_REVIEW_RECORD_URL,
    ManagementReviewAttestation,
    ManagementReviewError,
    ManagementReviewRecord,
    build_production_reviewed_registry,
    build_reviewed_registry,
    document_review_record_id,
    document_review_record_valid,
    production_management_registry,
    review_status,
    validate_document_review_record_set,
)
from event_switch_manager.planning.management_command_evidence_reviews import (
    test_only_reviewed_registry as make_test_only_registry,
)
from event_switch_manager.planning.management_intent import (
    build_management_intent,
    management_intent_fingerprint,
)


def _plan_with_management(event_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = make_l3_plan(event_id, static_route_count=1)
    core = next(
        item for item in plan["assignments"] if item["hostname"] == "L3-Core"
    )
    core["management_ip"] = "192.168.10.3"
    core["management_domain"] = "example.com"
    core["credential_reference"] = f"credref:{event_id}:netops"
    return plan, core


def _intent(
    plan: dict[str, Any], assignment_id: str, evidence_registry: Any = None,
) -> tuple[Any, Any, Any]:
    revision = revision_for(plan)
    l2_intent = build_layer2_intent(revision, None)
    intent = build_management_intent(
        revision, l2_intent, UUID(assignment_id),
        **({} if evidence_registry is None else {
            "evidence_registry": evidence_registry,
        }),
    )
    return revision, l2_intent, intent


def _attestations() -> tuple[ManagementReviewAttestation, ...]:
    return tuple(
        ManagementReviewAttestation(
            evidence_id=row.evidence_id,
            content_digest=row.content_digest(),
            reviewer="TEST-ONLY-MANAGEMENT-REVIEW",
            reviewed_at="2026-11-23",
            findings=("test-only R63 reviewed fixture",),
            source_url=row.source_url,
            ai_review_disclosure="test-only; not a production independent review",
        )
        for row in R63_CORRECTED_ROWS
    )


def test_four_corrected_evidence_rows_have_fixed_digests_and_urls() -> None:
    assert len(R63_CORRECTED_ROWS) == 4
    assert {row.evidence_id for row in R63_CORRECTED_ROWS} == set(
        R63_REVIEWED_EVIDENCE_IDS,
    )
    assert R63_STAGED_REGISTRY.registry_id
    assert len(R63_STAGED_REGISTRY.rows) == 18
    assert R63_STAGED_REGISTRY.renderable_count == 0
    assert R63_STAGED_REGISTRY.fingerprint == R63_STAGED_REGISTRY_FINGERPRINT
    for row in R63_CORRECTED_ROWS:
        assert row.family.value in {"catalyst-9300", "catalyst-9200"}
        assert row.releases == ("17.12.4",)
        assert row.licenses
        assert row.source_url.startswith("https://www.cisco.com/")
        if row.topic is ManagementCommandTopic.DOMAIN_NAME:
            assert row.source_url.endswith("configuring_secure_shell__ssh_.html")
            assert "ip domain name" in row.command
        else:
            assert row.topic is ManagementCommandTopic.SSH_VERSION
            assert row.source_url.endswith("secure_shell_version_2_support.html")
            assert row.command == "ip ssh version 2"
        assert R63_STAGED_DIGESTS[row.evidence_id] == row.content_digest()
        assert R63_OLD_DIGESTS[row.evidence_id] != row.content_digest()
    assert len(R63_STAGED_DIGESTS) == 4
    assert len(R63_OLD_DIGESTS) == 4


def test_no_production_review_is_activated() -> None:
    assert MANAGEMENT_APPROVED_REVIEWS == ()
    production = production_management_registry()
    assert production is MANAGEMENT_EVIDENCE_DRAFT_REGISTRY
    assert production.registry_id == "cis-04b-management-command-evidence-draft-v1"
    assert production.fingerprint == (
        "7ad9d17396f8cd8ed2c18c70b3ca021a3932800d54b94eef9c5d22405694d640"
    )
    assert production.renderable_count == 0
    assert all(review_status(evidence_id) == "DOCUMENT-SYNTAX-REVIEWED"
               for evidence_id in R63_REVIEWED_EVIDENCE_IDS)
    assert all(review_status(evidence_id) != "REVIEWED"
               for evidence_id in R63_REVIEWED_EVIDENCE_IDS)
    assert sum(1 for row in R63_STAGED_REGISTRY.rows
               if row.review_state.value == "pending-independent-review") == 18


def test_fixed_manifest_builds_a_reviewed_registry_and_invalidates_tampering() -> None:
    registry = build_reviewed_registry(
        _attestations(),
        registry_id="cis-04b1-management-test-only-reviewed-v1",
        test_only=True,
    )
    assert registry.registry_id == "cis-04b1-management-test-only-reviewed-v1"
    assert registry.renderable_count == 4
    assert sum(1 for row in registry.rows if row.renderable) == 4

    incomplete = _attestations()[:3]
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry(
            incomplete,
            registry_id="cis-04b1-management-test-only-reviewed-v1",
            test_only=True,
        )
    assert error.value.reason_code == "management-review-incomplete-manifest"

    wrong_digest = _attestations()[0]
    wrong_digest = replace(wrong_digest, content_digest=R63_OLD_DIGESTS[
        wrong_digest.evidence_id
    ])
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry(
            (wrong_digest, *_attestations()[1:]),
            registry_id="cis-04b1-management-test-only-reviewed-v1",
            test_only=True,
        )
    assert error.value.reason_code == "management-review-digest-mismatch"

    forged = replace(_attestations()[0], reviewer="")
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry(
            (forged, *_attestations()[1:]),
            registry_id="cis-04b1-management-test-only-reviewed-v1",
            test_only=True,
        )
    assert error.value.reason_code == "management-review-attestation-incomplete"

    wrong_source = replace(
        _attestations()[0], source_url="https://example.invalid/review",
    )
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry(
            (wrong_source, *_attestations()[1:]),
            registry_id="cis-04b1-management-test-only-reviewed-v1",
            test_only=True,
        )
    assert error.value.reason_code == "management-review-attestation-incomplete"


def test_intent_uses_the_same_reviewed_registry_boundary() -> None:
    plan, core = _plan_with_management("00000000-0000-0000-0000-000000000099")
    registry = make_test_only_registry()
    revision = revision_for(plan)
    l2_intent = build_layer2_intent(revision, None)
    draft_intent = build_management_intent(
        revision, l2_intent, UUID(core["id"]),
    )
    reviewed_intent = build_management_intent(
        revision, l2_intent, UUID(core["id"]), evidence_registry=registry,
    )
    assert reviewed_intent.evidence_registry_id == registry.registry_id
    assert reviewed_intent.evidence_registry_fingerprint == registry.fingerprint
    assert reviewed_intent.evidence_status == "PARTIAL"
    assert reviewed_intent.intent_fingerprint != draft_intent.intent_fingerprint
    document = build_management_cli_candidates(
        revision, reviewed_intent, registry, test_only_registry=True,
    )
    report = validate_management_candidates(
        revision, reviewed_intent, document, registry, test_only_registry=True,
    )
    assert document.source.evidence_registry_id == registry.registry_id
    assert document.source.evidence_registry_fingerprint == registry.fingerprint
    assert report.source.evidence_registry_id == registry.registry_id
    assert report.source.evidence_registry_fingerprint == registry.fingerprint
    with pytest.raises(ManagementRenderError) as error:
        build_management_cli_candidates(
            revision, draft_intent, registry, test_only_registry=True,
        )
    assert error.value.reason_code == "management-intent-registry-mismatch"


def test_isolated_reviewed_path_has_one_domain_pass_and_ssh_blocked() -> None:
    plan, core = _plan_with_management("00000000-0000-0000-0000-000000000099")
    registry = make_test_only_registry()
    revision, _l2, intent = _intent(plan, core["id"], registry)
    document = build_management_cli_candidates(
        revision, intent, registry, test_only_registry=True,
    )
    report = validate_management_candidates(
        revision, intent, document, registry, test_only_registry=True,
    )
    assert intent.evidence_status == "PARTIAL"
    assert intent.evidence_registry_id == registry.registry_id
    assert intent.evidence_registry_fingerprint == registry.fingerprint
    assert document.summary.model_dump() == {
        "total": 9, "candidates": 1, "blocked": 8, "skipped": 0,
    }
    assert report.summary.model_dump() == {
        "total": 9, "passed": 1, "blocked": 8, "failed": 0,
    }
    assert report.overall_status == "partial"
    domain = next(
        item for item in document.candidates
        if item.topic == "management-domain-name"
    )
    ssh = next(
        item for item in document.candidates
        if item.topic == "management-ssh-version"
    )
    assert domain.status == "candidate"
    assert domain.candidate_text == "ip domain name example.com"
    assert ssh.status == "blocked"
    assert ssh.candidate_text is None
    assert "ssh-rsa-key-state-unknown" in ssh.blocking_reasons
    assert "management-authentication-not-validated" in ssh.blocking_reasons
    assert all(
        item.candidate_text is None for item in document.candidates
        if item.topic != "management-domain-name"
    )
    assert all(
        not item.secret_text_present for item in report.candidates
    )
    assert all(
        item.status == "blocked" for item in document.candidates
        if item.topic in {
            "management-local-username", "management-vty-transport",
            "management-login-local", "management-aaa-new-model",
            "management-aaa-login-default", "management-console-auth",
        }
    )


@pytest.mark.parametrize("domain", [
    "example.com\nip route 0.0.0.0 0.0.0.0 192.0.2.1",
    "example.com; interface Gi1/0/1",
    "example.com with-space",
    "example..com",
    "bad_domain.example",
    "example.com.",
    "-bad.example",
])
def test_domain_injection_and_invalid_domains_are_blocked(domain: str) -> None:
    plan, core = _plan_with_management("00000000-0000-0000-0000-000000000099")
    registry = make_test_only_registry()
    revision, _l2, intent = _intent(plan, core["id"], registry)
    changed = intent.model_copy(update={"management_domain": domain})
    changed = changed.model_copy(update={
        "intent_fingerprint": management_intent_fingerprint(changed),
    })
    document = build_management_cli_candidates(
        revision, changed, registry, test_only_registry=True,
    )
    report = validate_management_candidates(
        revision, changed, document, registry, test_only_registry=True,
    )
    candidate = next(
        item for item in document.candidates
        if item.topic == "management-domain-name"
    )
    assert candidate.status == "blocked"
    assert candidate.candidate_text is None
    assert "management-domain-invalid" in candidate.blocking_reasons
    assert report.summary.passed == 0
    assert report.summary.blocked == 9


def test_unknown_pid_release_or_license_stays_fail_closed_for_reviewed_path() -> None:
    for field, value in (
        ("software_image", "17.12.5"),
        ("software_license", "Network Unknown"),
        ("exact_pid", "C9300-UNKNOWN"),
    ):
        plan, core = _plan_with_management("00000000-0000-0000-0000-000000000099")
        registry = make_test_only_registry()
        revision, _l2, intent = _intent(plan, core["id"], registry)
        changed = intent.model_copy(update={
            "identity": intent.identity.model_copy(update={field: value}),
        })
        changed = changed.model_copy(update={
            "intent_fingerprint": management_intent_fingerprint(changed),
        })
        document = build_management_cli_candidates(
            revision, changed, registry, test_only_registry=True,
        )
        report = validate_management_candidates(
            revision, changed, document, registry, test_only_registry=True,
        )
        assert report.summary.passed == 0
        assert document.summary.candidates == 0
        assert all(item.candidate_text is None for item in document.candidates)


def test_test_only_reviewed_registry_cannot_be_selected_by_production() -> None:
    plan, core = _plan_with_management("00000000-0000-0000-0000-000000000099")
    registry = make_test_only_registry()
    revision, _l2, test_intent = _intent(plan, core["id"], registry)
    with pytest.raises(ManagementRenderError) as error:
        build_management_cli_candidates(revision, test_intent, registry)
    assert error.value.reason_code == "unapproved-management-evidence-registry"
    production = production_management_registry()
    production_revision, _l2_prod, production_intent = _intent(
        plan, core["id"],
    )
    document = build_management_cli_candidates(
        production_revision, production_intent, production,
    )
    report = validate_management_candidates(
        production_revision, production_intent, document, production,
    )
    assert report.summary.model_dump() == {
        "total": 9, "passed": 0, "blocked": 9, "failed": 0,
    }
    assert report.overall_status == "blocked"
    assert all(item.candidate_text is None for item in document.candidates)
def test_ai_document_review_records_are_document_syntax_only() -> None:
    assert len(DOCUMENT_REVIEW_RECORDS) == 4
    assert R63A_AI_REVIEW_TYPE == "AI-independent-read-only-document-review"
    assert R63A_AI_REVIEWER.startswith("ChatGPT (GPT-6)")
    assert R63A_AI_REVIEW_DATE == "2026-11-23"
    assert R63A_REVIEW_RECORD_URL.startswith(
        "https://github.com/yikkrrtykj/event-switch-manager/pull/40#issuecomment-"
    )
    for record in DOCUMENT_REVIEW_RECORDS:
        assert record.evidence_id in R63_REVIEWED_EVIDENCE_IDS
        assert record.content_digest == R63_STAGED_DIGESTS[record.evidence_id]
        assert record.approval_scope == "DOCUMENT_SYNTAX_ONLY"
        assert record.production_authorized is False
        assert record.review_record_url == R63A_REVIEW_RECORD_URL
        assert record.review_type == R63A_AI_REVIEW_TYPE
        assert record.reviewer == R63A_AI_REVIEWER
        assert record.reviewed_at == R63A_AI_REVIEW_DATE
        assert document_review_record_valid(record) is True
        assert record.findings
    assert PRODUCTION_APPROVED_RECORDS == ()
    with pytest.raises(ManagementReviewError) as error:
        build_production_reviewed_registry()
    assert error.value.reason_code == (
        "management-review-production-authorization-pending"
    )


@pytest.mark.parametrize("reviewer", [
    "Cisco TAC",
    "ChatGPT (GPT-6) — independent read-only AI documentation reviewer",
    "A. Human Independent Reviewer",
])
def test_complete_looking_forged_attestations_cannot_authorize_production(
    reviewer: str,
) -> None:
    forged_attestation = replace(
        _attestations()[0],
        reviewer=reviewer,
        reviewed_at="2026-11-23",
        findings=("fabricated but structurally complete review finding",),
    )
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry((
            forged_attestation, *_attestations()[1:],
        ))
    assert error.value.reason_code == (
        "management-review-production-authorization-required"
    )
    assert review_status(forged_attestation.evidence_id) != "REVIEWED"
    assert production_management_registry().renderable_count == 0


def test_complete_looking_forged_attestation_is_test_only_isolated() -> None:
    forged_attestation = replace(
        _attestations()[0],
        reviewer="Cisco TAC",
        reviewed_at="2099-12-31",
        findings=("forged test-only review",),
    )
    isolated = build_reviewed_registry(
        (forged_attestation, *_attestations()[1:]),
        test_only=True,
        registry_id="cis-04b1-management-test-only-forged-v1",
    )
    assert isolated.renderable_count == 4
    assert production_management_registry().renderable_count == 0
    # Test-only naming is required even for isolated reviewed fixtures.
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry(
            _attestations(), test_only=True,
            registry_id="cis-04b1-management-command-evidence-reviewed-v1",
        )
    assert error.value.reason_code == "management-review-test-only-registry-id"


@pytest.mark.parametrize("field", ["reviewer", "reviewed_at", "findings"])
def test_incomplete_reviewer_fields_are_rejected(field: str) -> None:
    base = _attestations()[0]
    if field == "reviewer":
        attestation = replace(base, reviewer="")
    elif field == "reviewed_at":
        attestation = replace(base, reviewed_at="")
    else:
        attestation = replace(base, findings=())
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry(
            (attestation, *_attestations()[1:]),
            test_only=True,
            registry_id="cis-04b1-management-test-only-reviewed-v1",
        )
    assert error.value.reason_code == "management-review-attestation-incomplete"
def test_fabricated_date_findings_and_unapproved_source_are_rejected() -> None:
    fabricated = replace(
        _attestations()[0],
        reviewer="Cisco TAC",
        reviewed_at="2099-12-31",
        findings=("fabricated findings with no independent provenance",),
    )
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry((
            fabricated, *_attestations()[1:],
        ))
    assert error.value.reason_code == (
        "management-review-production-authorization-required"
    )


def test_duplicate_and_unknown_evidence_ids_are_rejected() -> None:
    attestations = _attestations()
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry(
            (attestations[0], *attestations),
            test_only=True,
            registry_id="cis-04b1-management-test-only-reviewed-v1",
        )
    assert error.value.reason_code == "management-review-evidence-duplicate"
    unknown = replace(attestations[0], evidence_id="mgmt-unknown-evidence")
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry(
            (unknown, *attestations[1:]),
            test_only=True,
            registry_id="cis-04b1-management-test-only-reviewed-v1",
        )
    assert error.value.reason_code == "management-review-evidence-unknown"


def test_changed_evidence_invalidates_document_review_record() -> None:
    record = DOCUMENT_REVIEW_RECORDS[0]
    changed = replace(record, content_digest=R63_OLD_DIGESTS[record.evidence_id])
    assert document_review_record_valid(changed) is False
    assert document_review_record_valid(record) is True
    # Server-fixed provenance remains unchanged and never becomes production.
    assert review_status(record.evidence_id) == "DOCUMENT-SYNTAX-REVIEWED"
    assert review_status(record.evidence_id) != "REVIEWED"
    assert review_status("mgmt-unknown-evidence") == "PENDING"
def _production_records() -> tuple[ManagementReviewRecord, ...]:
    return tuple(
        replace(
            record,
            record_id=f"prod-{record.evidence_id}",
            production_authorized=True,
            approval_scope="PRODUCTION_ACTIVATION",
        )
        for record in DOCUMENT_REVIEW_RECORDS
    )


def test_fixed_document_records_pass_exact_integrity_and_startup_set() -> None:
    assert validate_document_review_record_set(DOCUMENT_REVIEW_RECORDS) is True
    for record in DOCUMENT_REVIEW_RECORDS:
        assert record.record_id == document_review_record_id(record.evidence_id)
        assert document_review_record_valid(record) is True
    assert all(
        review_status(record.evidence_id) == "DOCUMENT-SYNTAX-REVIEWED"
        for record in DOCUMENT_REVIEW_RECORDS
    )


@pytest.mark.parametrize("field", [
    "findings", "record_id", "reviewer", "reviewed_at", "review_record_url",
    "content_digest", "evidence_source_url",
])
def test_fixed_document_record_field_tampering_is_rejected(field: str) -> None:
    record = DOCUMENT_REVIEW_RECORDS[0]
    if field == "findings":
        tampered = replace(record, findings=("tampered non-empty findings",))
    elif field == "record_id":
        tampered = replace(record, record_id="r63a-ai-document-forged")
    elif field == "reviewer":
        tampered = replace(record, reviewer="Cisco TAC")
    elif field == "reviewed_at":
        tampered = replace(record, reviewed_at="2099-12-31")
    elif field == "review_record_url":
        tampered = replace(
            record,
            review_record_url="https://github.com/forged/review-comment",
        )
    elif field == "content_digest":
        tampered = replace(
            record, content_digest=R63_OLD_DIGESTS[record.evidence_id],
        )
    else:
        tampered = replace(
            record,
            evidence_source_url="https://www.cisco.com/forged-source.html",
        )
    assert document_review_record_valid(tampered) is False


def test_document_record_cannot_self_declare_production_authority() -> None:
    record = replace(
        DOCUMENT_REVIEW_RECORDS[0],
        production_authorized=True,
        approval_scope="PRODUCTION_ACTIVATION",
    )
    assert document_review_record_valid(record) is False
    assert review_status(record.evidence_id) == "DOCUMENT-SYNTAX-REVIEWED"
    assert review_status(record.evidence_id) != "REVIEWED"


def test_fixed_document_record_set_rejects_duplicate_missing_unknown() -> None:
    records = DOCUMENT_REVIEW_RECORDS
    with pytest.raises(ManagementReviewError) as error:
        validate_document_review_record_set((records[0], records[0], records[1], records[2]))
    assert error.value.reason_code == (
        "management-review-document-record-set-duplicate"
    )
    with pytest.raises(ManagementReviewError) as error:
        validate_document_review_record_set(records[:3])
    assert error.value.reason_code == (
        "management-review-document-record-set-incomplete"
    )
    unknown = replace(
        records[3],
        evidence_id="mgmt-unknown-review",
        record_id="r63a-ai-document-mgmt-unknown-review",
    )
    with pytest.raises(ManagementReviewError) as error:
        validate_document_review_record_set((*records[:3], unknown))
    assert error.value.reason_code == (
        "management-review-document-record-unknown"
    )
    duplicate_id = replace(records[1], record_id=records[0].record_id)
    with pytest.raises(ManagementReviewError) as error:
        validate_document_review_record_set(
            (records[0], duplicate_id, records[2], records[3]),
        )
    assert error.value.reason_code == (
        "management-review-document-record-set-duplicate"
    )
    with pytest.raises(ManagementReviewError) as error:
        validate_document_review_record_set((*records, records[0]))
    assert error.value.reason_code == (
        "management-review-document-record-set-incomplete"
    )


def test_empty_production_manifest_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reviews_module, "PRODUCTION_APPROVED_RECORDS", ())
    with pytest.raises(ManagementReviewError) as error:
        build_production_reviewed_registry()
    assert error.value.reason_code == (
        "management-review-production-authorization-pending"
    )
    assert production_management_registry() is MANAGEMENT_EVIDENCE_DRAFT_REGISTRY


def test_three_record_production_manifest_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reviews_module, "PRODUCTION_APPROVED_RECORDS", _production_records()[:3],
    )
    with pytest.raises(ManagementReviewError) as error:
        build_production_reviewed_registry()
    assert error.value.reason_code == "management-review-incomplete-manifest"


def test_duplicate_production_evidence_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = _production_records()
    duplicate = replace(records[0], record_id="prod-duplicate-evidence")
    monkeypatch.setattr(
        reviews_module,
        "PRODUCTION_APPROVED_RECORDS",
        (duplicate, records[0], records[1], records[2]),
    )
    with pytest.raises(ManagementReviewError) as error:
        build_production_reviewed_registry()
    assert error.value.reason_code == "management-review-evidence-duplicate"


def test_duplicate_production_record_id_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = tuple(replace(record, record_id="same-record") for record in _production_records())
    monkeypatch.setattr(reviews_module, "PRODUCTION_APPROVED_RECORDS", records)
    with pytest.raises(ManagementReviewError) as error:
        build_production_reviewed_registry()
    assert error.value.reason_code == "management-review-record-id-duplicate"


def test_blank_production_record_id_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = list(_production_records())
    records[0] = replace(records[0], record_id="")
    monkeypatch.setattr(
        reviews_module, "PRODUCTION_APPROVED_RECORDS", tuple(records),
    )
    with pytest.raises(ManagementReviewError) as error:
        build_production_reviewed_registry()
    assert error.value.reason_code == "management-review-record-id-invalid"


def test_unknown_production_evidence_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = list(_production_records())
    records[3] = replace(
        records[3],
        evidence_id="mgmt-unknown-production-evidence",
        record_id="prod-unknown",
    )
    monkeypatch.setattr(
        reviews_module, "PRODUCTION_APPROVED_RECORDS", tuple(records),
    )
    with pytest.raises(ManagementReviewError) as error:
        build_production_reviewed_registry()
    assert error.value.reason_code == "management-review-evidence-unknown"


def test_exact_unique_production_manifest_passes_structure_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = _production_records()
    monkeypatch.setattr(
        reviews_module, "PRODUCTION_APPROVED_RECORDS", records,
    )
    registry = build_production_reviewed_registry()
    # This is a temporary test double only; the returned object is not
    # production-enabled, and monkeypatch restores the empty real manifest.
    assert registry.production is False
    assert registry.renderable_count == 4
    assert reviews_module.PRODUCTION_APPROVED_RECORDS == records
def test_review_status_requires_complete_production_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = _production_records()
    evidence_id = records[0].evidence_id
    for invalid_manifest in (
        records[:1],
        records[:3],
        (records[0], replace(records[0], record_id="other"), *records[1:3]),
    ):
        monkeypatch.setattr(
            reviews_module, "PRODUCTION_APPROVED_RECORDS", invalid_manifest,
        )
        assert review_status(evidence_id) != "REVIEWED"
        assert review_status(evidence_id) == "DOCUMENT-SYNTAX-REVIEWED"
    monkeypatch.setattr(
        reviews_module, "PRODUCTION_APPROVED_RECORDS", records,
    )
    assert all(review_status(record.evidence_id) == "REVIEWED" for record in records)
    # The test double is temporary; the real production manifest remains empty.
    monkeypatch.setattr(reviews_module, "PRODUCTION_APPROVED_RECORDS", ())
    assert review_status(evidence_id) == "DOCUMENT-SYNTAX-REVIEWED"
