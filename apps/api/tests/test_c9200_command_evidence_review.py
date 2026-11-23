"""CIS-03-04A-3 C9200 review attestation and lifecycle tests."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import pytest
from layer3_helpers import make_l3_plan, revision_for

from event_switch_manager.planning.layer3_c9200_command_evidence import (
    ROWS,
    pending_digests,
)
from event_switch_manager.planning.layer3_c9200_command_evidence_reviews import (
    C9200_REVIEW_CONTENT_DIGESTS,
    C9200_REVIEW_DATE,
    C9200_REVIEW_PROVENANCE,
    C9200_REVIEW_REVIEWER,
    C9200_REVIEW_SOURCE_URL,
    C9200_REVIEWED_REGISTRY,
    C9200_REVIEWED_REGISTRY_ID,
    build_review,
    validate_attestation,
    validate_reviewed_registry,
)
from event_switch_manager.planning.layer3_command_evidence import (
    DEFAULT_REGISTRY,
    REVIEW_LIFECYCLE_GAP,
    CommandEvidenceRegistry,
    CommandEvidenceRow,
    EvidenceReview,
    EvidenceReviewState,
    ParameterRule,
)
from event_switch_manager.planning.layer3_intent import build_layer3_intent
from event_switch_manager.planning.layer3_registry_selection import (
    C9200_REVIEWED_REGISTRY as REGISTERED_C9200,
)
from event_switch_manager.planning.layer3_registry_selection import (
    UNREVIEWED_PLATFORM_REGISTRY,
    RegistrySelectionError,
    assert_production_registry,
    select_l3_registry,
)


def test_provenance_is_real_ai_review_and_not_human_approval() -> None:
    provenance = C9200_REVIEW_PROVENANCE
    assert provenance.reviewer == C9200_REVIEW_REVIEWER
    assert provenance.reviewed_at == C9200_REVIEW_DATE == "2026-11-23"
    assert provenance.review_type == "AI-independent-read-only-document-review"
    assert provenance.source_url == C9200_REVIEW_SOURCE_URL
    assert provenance.human_approval is False
    assert provenance.hardware_verified is False
    assert provenance.deployment_authorized is False
    assert "AI" in provenance.reviewer


def test_all_four_attestations_bind_the_original_digests() -> None:
    assert len(C9200_REVIEWED_REGISTRY.rows) == 4
    assert C9200_REVIEWED_REGISTRY.registry_id == C9200_REVIEWED_REGISTRY_ID
    assert C9200_REVIEWED_REGISTRY.production is True
    assert C9200_REVIEWED_REGISTRY.eligible_count == 4
    assert C9200_REVIEWED_REGISTRY.renderable_count == 4
    original = {row.evidence_id: row for row in ROWS}
    for reviewed in C9200_REVIEWED_REGISTRY.rows:
        source = original[reviewed.evidence_id]
        assert reviewed.review.state is EvidenceReviewState.REVIEWED
        assert reviewed.review.reviewer == C9200_REVIEW_REVIEWER
        assert reviewed.review.reviewed_at == C9200_REVIEW_DATE
        assert reviewed.review.findings
        assert reviewed.review.content_digest == pending_digests()[source.evidence_id]
        assert reviewed.review.content_digest == source.content_digest()
        assert reviewed.content_digest() == source.content_digest()
        assert reviewed.renderable
        assert not any(
            blocker.endswith(REVIEW_LIFECYCLE_GAP)
            for blocker in reviewed.scope_blockers()
        )


@pytest.mark.parametrize(
    "review",
    (
        EvidenceReview(
            EvidenceReviewState.PENDING, "", "", (), "",
        ),
        EvidenceReview(
            EvidenceReviewState.REJECTED,
            "independent reviewer",
            C9200_REVIEW_DATE,
            ("rejected",),
            "0" * 64,
        ),
        EvidenceReview(
            EvidenceReviewState.REVIEWED,
            "forged reviewer",
            C9200_REVIEW_DATE,
            ("forged",),
            "0" * 64,
        ),
        EvidenceReview(
            EvidenceReviewState.REVIEWED,
            C9200_REVIEW_REVIEWER,
            "",
            (),
            "0" * 64,
        ),
    ),
)
def test_pending_rejected_or_malformed_review_cannot_release_cli(
    review: EvidenceReview,
) -> None:
    row = replace(ROWS[0], review=review)
    blockers = row.scope_blockers()
    assert not row.renderable
    assert f"evidence-scope-gap-{REVIEW_LIFECYCLE_GAP}" in blockers


def test_frozen_review_map_matches_r55_r56_baseline() -> None:
    assert C9200_REVIEW_CONTENT_DIGESTS == {
        "l3-9200-ip-routing-v1": (
            "84fb338c43bd5584f0797baf9172291973f26720227dc18bbf0fb09a48c4db38"
        ),
        "l3-9200-svi-interface-v1": (
            "37223459db80efc3d531a6ccf898c217fc7319893cbee56d3c7ec4eccf2e2193"
        ),
        "l3-9200-svi-address-v1": (
            "e61264cf0a1b2441f443b8e5213e42ef3b2b6db946619909bd396650ba56c6d9"
        ),
        "l3-9200-static-route-v1": (
            "8206b57a147c5d3a4a3b29506a91ec9f7de1b586ed0fd074f30bae453df55a4a"
        ),
    }
    assert set(C9200_REVIEW_CONTENT_DIGESTS) == {
        row.evidence_id for row in ROWS
    }
    validate_reviewed_registry()
    assert C9200_REVIEWED_REGISTRY.fingerprint == (
        "2c73c8b39100622360c6bfab935d995d8fb884dd999b6df0ae744a7be7cec876"
    )


TAMPERED_ROW_MUTATIONS = (
    ("command", lambda row: replace(row, command="ip routing tampered")),
    ("grammar", lambda row: replace(row, grammar="ip routing tampered")),
    (
        "parameters",
        lambda row: replace(
            row,
            parameters=(ParameterRule("vlan-id", "vlan-id", 1, 4094),),
        ),
    ),
    ("limits", lambda row: replace(row, limits=row.limits + ("tampered",))),
    ("source_url", lambda row: replace(row, source_url="https://forged.invalid")),
    ("source_section", lambda row: replace(row, source_section="forged section")),
    (
        "classification",
        lambda row: replace(
            row,
            classification=replace(row.classification, platform_documented=False),
        ),
    ),
    (
        "verified_pids",
        lambda row: replace(
            row,
            classification=replace(
                row.classification,
                verified_pids=row.classification.verified_pids[:-1],
            ),
        ),
    ),
    ("licenses", lambda row: replace(row, licenses=("DNA Essentials",))),
    ("releases", lambda row: replace(row, releases=("17.12.5",))),
)


@pytest.mark.parametrize(("field", "mutate"), TAMPERED_ROW_MUTATIONS)
def test_tampered_evidence_cannot_receive_a_new_review_attestation(
    field: str,
    mutate: Callable[[CommandEvidenceRow], CommandEvidenceRow],
) -> None:
    changed = mutate(ROWS[0])
    assert changed.content_digest() != C9200_REVIEW_CONTENT_DIGESTS[ROWS[0].evidence_id]
    with pytest.raises(ValueError, match="fixed review digest"):
        build_review(changed)
    with pytest.raises(ValueError, match="fixed review"):
        validate_attestation(changed, build_review(ROWS[0]))


def test_unknown_evidence_id_cannot_inherit_a_review() -> None:
    unknown = replace(ROWS[0], evidence_id="l3-9200-unknown-v1")
    with pytest.raises(ValueError, match="No reviewed C9200 attestation"):
        build_review(unknown)


def test_missing_fixed_review_id_prevents_registry_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.planning import (
        layer3_c9200_command_evidence_reviews as reviews,
    )

    reduced = CommandEvidenceRegistry(
        C9200_REVIEWED_REGISTRY.rows[:-1],
        registry_id=C9200_REVIEWED_REGISTRY_ID,
        production=True,
    )
    monkeypatch.setattr(reviews, "C9200_REVIEWED_REGISTRY", reduced)
    with pytest.raises(ValueError, match="row count changed"):
        validate_reviewed_registry()


def test_forged_reviewer_date_findings_cannot_replace_fixed_digest() -> None:
    row = ROWS[0]
    fixed_digest = C9200_REVIEW_CONTENT_DIGESTS[row.evidence_id]
    for review in (
        EvidenceReview(
            EvidenceReviewState.REVIEWED,
            "forged reviewer",
            C9200_REVIEW_DATE,
            ("forged",),
            fixed_digest,
        ),
        EvidenceReview(
            EvidenceReviewState.REVIEWED,
            C9200_REVIEW_REVIEWER,
            "2026-11-24",
            ("forged",),
            fixed_digest,
        ),
        EvidenceReview(
            EvidenceReviewState.REVIEWED,
            C9200_REVIEW_REVIEWER,
            C9200_REVIEW_DATE,
            ("forged",),
            fixed_digest,
        ),
    ):
        with pytest.raises(ValueError):
            validate_attestation(row, review)


def test_fixed_digest_positive_path_still_passes() -> None:
    row = ROWS[0]
    review = build_review(row)
    validate_attestation(row, review)
    assert review.content_digest == C9200_REVIEW_CONTENT_DIGESTS[row.evidence_id]
    assert review.content_digest == row.content_digest()


def test_other_blocking_gaps_remain_after_lifecycle_review_with_test_fixture() -> None:
    original = ROWS[0]
    assert original.classification is not None
    changed = replace(
        original,
        classification=replace(
            original.classification,
            blocking_evidence_gaps=(
                REVIEW_LIFECYCLE_GAP,
                "other-material-gap",
            ),
        ),
    )
    test_review = EvidenceReview(
        EvidenceReviewState.REVIEWED,
        "TEST-ONLY isolated lifecycle fixture; not a production reviewer",
        C9200_REVIEW_DATE,
        ("test-only lifecycle fixture",),
        changed.content_digest(),
    )
    reviewed = replace(changed, review=test_review)
    assert reviewed.renderable
    assert not any(
        blocker.endswith(REVIEW_LIFECYCLE_GAP)
        for blocker in reviewed.scope_blockers()
    )
    assert "evidence-scope-gap-other-material-gap" in reviewed.scope_blockers()
    # The test fixture is not in the production reviewed Registry.
    assert all(
        row.evidence_id != changed.evidence_id
        or row.content_digest() != changed.content_digest()
        for row in C9200_REVIEWED_REGISTRY.rows
    )


def test_forged_registry_with_same_id_or_reviewer_is_not_trusted() -> None:
    forged_rows = tuple(
        replace(row, review=replace(
            row.review,
            state=EvidenceReviewState.REVIEWED,
            reviewer="forged reviewer",
            reviewed_at=C9200_REVIEW_DATE,
            findings=("forged",),
            content_digest=row.content_digest(),
        ))
        for row in ROWS
    )
    forged = CommandEvidenceRegistry(
        forged_rows,
        registry_id=C9200_REVIEWED_REGISTRY_ID,
        production=True,
    )
    assert forged.eligible_count == 4
    plan = make_l3_plan(
        "00000000-0000-0000-0000-000000000099",
        core_pid="C9200L-24P-4X", core_family="catalyst-9200",
        core_image="17.12.4", core_license="Network Advantage",
        with_relay=False, with_default=False, static_route_count=1,
    )
    revision = revision_for(plan)
    intent = build_layer3_intent(revision)
    core = next(
        item for item in intent.devices if item.identity.hostname == "L3-Core"
    )
    assert select_l3_registry(core.identity).registry is REGISTERED_C9200
    with pytest.raises(RegistrySelectionError, match="untrusted-production-registry"):
        assert_production_registry(forged, core.identity)
    assert forged is not C9200_REVIEWED_REGISTRY
    assert forged is not UNREVIEWED_PLATFORM_REGISTRY


def test_test_only_reviewer_cannot_create_production_registry() -> None:
    rows = tuple(
        replace(row, review=replace(
            build_review(row),
            reviewer="test-only-reviewer",
        ))
        for row in ROWS
    )
    with pytest.raises(ValueError, match="test-only"):
        CommandEvidenceRegistry(
            rows,
            registry_id="cis-03-c9200-test-only-reviewer-v1",
            production=True,
        )


def test_reviewed_registry_is_the_same_object_selected_by_identity() -> None:
    plan = make_l3_plan(
        "00000000-0000-0000-0000-000000000099",
        core_pid="C9200L-24P-4X", core_family="catalyst-9200",
        core_image="17.12.4", core_license="Network Advantage",
        with_relay=False, with_default=False, static_route_count=1,
    )
    revision = revision_for(plan)
    intent = build_layer3_intent(revision)
    core = next(
        item for item in intent.devices if item.identity.hostname == "L3-Core"
    )
    selection = select_l3_registry(core.identity)
    assert selection.registry is C9200_REVIEWED_REGISTRY
    assert selection.evidence_approved is True
    assert C9200_REVIEWED_REGISTRY is REGISTERED_C9200
    assert DEFAULT_REGISTRY is not C9200_REVIEWED_REGISTRY
    assert UNREVIEWED_PLATFORM_REGISTRY.rows == ()


def test_original_draft_registry_remains_pending_and_non_production() -> None:
    from event_switch_manager.planning.layer3_c9200_command_evidence import (
        DRAFT_REGISTRY,
    )

    assert DRAFT_REGISTRY.production is False
    assert DRAFT_REGISTRY.renderable_count == 0
    assert all(
        row.review.state is EvidenceReviewState.PENDING
        for row in DRAFT_REGISTRY.rows
    )
