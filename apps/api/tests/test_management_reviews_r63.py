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
    MANAGEMENT_APPROVED_REVIEWS,
    R63_CORRECTED_ROWS,
    R63_OLD_DIGESTS,
    R63_REVIEWED_EVIDENCE_IDS,
    R63_STAGED_DIGESTS,
    R63_STAGED_REGISTRY,
    R63_STAGED_REGISTRY_FINGERPRINT,
    ManagementReviewAttestation,
    ManagementReviewError,
    build_reviewed_registry,
    production_management_registry,
    review_status,
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


def _intent(plan: dict[str, Any], assignment_id: str) -> tuple[Any, Any, Any]:
    revision = revision_for(plan)
    l2_intent = build_layer2_intent(revision, None)
    intent = build_management_intent(revision, l2_intent, UUID(assignment_id))
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
    assert all(review_status(evidence_id) == "PENDING"
               for evidence_id in R63_REVIEWED_EVIDENCE_IDS)
    assert sum(1 for row in R63_STAGED_REGISTRY.rows
               if row.review_state.value == "pending-independent-review") == 18


def test_fixed_manifest_builds_a_reviewed_registry_and_invalidates_tampering() -> None:
    registry = build_reviewed_registry(_attestations(), registry_id=(
        "cis-04b1-management-test-only-reviewed-v1"
    ))
    assert registry.registry_id == "cis-04b1-management-test-only-reviewed-v1"
    assert registry.renderable_count == 4
    assert sum(1 for row in registry.rows if row.renderable) == 4

    incomplete = _attestations()[:3]
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry(incomplete)
    assert error.value.reason_code == "management-review-incomplete-manifest"

    wrong_digest = _attestations()[0]
    wrong_digest = replace(wrong_digest, content_digest=R63_OLD_DIGESTS[
        wrong_digest.evidence_id
    ])
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry((wrong_digest, *_attestations()[1:]))
    assert error.value.reason_code == "management-review-digest-mismatch"

    forged = replace(_attestations()[0], reviewer="")
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry((forged, *_attestations()[1:]))
    assert error.value.reason_code == "management-review-attestation-incomplete"

    wrong_source = replace(
        _attestations()[0], source_url="https://example.invalid/review",
    )
    with pytest.raises(ManagementReviewError) as error:
        build_reviewed_registry((wrong_source, *_attestations()[1:]))
    assert error.value.reason_code == "management-review-attestation-incomplete"


def test_isolated_reviewed_path_has_one_domain_pass_and_ssh_blocked() -> None:
    plan, core = _plan_with_management("00000000-0000-0000-0000-000000000099")
    revision, _l2, intent = _intent(plan, core["id"])
    registry = make_test_only_registry()
    document = build_management_cli_candidates(
        revision, intent, registry, test_only_registry=True,
    )
    report = validate_management_candidates(
        revision, intent, document, registry, test_only_registry=True,
    )
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
    revision, _l2, intent = _intent(plan, core["id"])
    changed = intent.model_copy(update={"management_domain": domain})
    changed = changed.model_copy(update={
        "intent_fingerprint": management_intent_fingerprint(changed),
    })
    registry = make_test_only_registry()
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
        revision, _l2, intent = _intent(plan, core["id"])
        changed = intent.model_copy(update={
            "identity": intent.identity.model_copy(update={field: value}),
        })
        changed = changed.model_copy(update={
            "intent_fingerprint": management_intent_fingerprint(changed),
        })
        registry = make_test_only_registry()
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
    revision, _l2, intent = _intent(plan, core["id"])
    registry = make_test_only_registry()
    with pytest.raises(ManagementRenderError) as error:
        build_management_cli_candidates(revision, intent, registry)
    assert error.value.reason_code == "unapproved-management-evidence-registry"
    production = production_management_registry()
    document = build_management_cli_candidates(revision, intent, production)
    report = validate_management_candidates(revision, intent, document, production)
    assert report.summary.model_dump() == {
        "total": 9, "passed": 0, "blocked": 9, "failed": 0,
    }
    assert report.overall_status == "blocked"
    assert all(item.candidate_text is None for item in document.candidates)
