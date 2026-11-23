"""CIS-03-04A-3 reviewed C9200 L3 evidence attestations.

The four R55/R56 evidence drafts were independently reviewed as read-only AI
documentation review.  This module records that review, bound to the exact
R55 content digests.  It does not claim human engineering approval, Cisco TAC
validation, hardware verification or deployment authorization.

The original draft registry and original PENDING rows remain untouched.  The
reviewed rows below are constructed by replacing only review metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from .layer3_c9200_command_evidence import (
    C9200_DRAFT_REGISTRY_ID,
    ROWS,
)
from .layer3_command_evidence import (
    CommandEvidenceRegistry,
    CommandEvidenceRow,
    EvidenceReview,
    EvidenceReviewState,
)

C9200_REVIEWED_REGISTRY_ID = "cis-03-c9200-l3-command-evidence-v1"
C9200_REVIEW_REVIEWER = "ChatGPT GPT-6 (AI independent read-only document reviewer)"
C9200_REVIEW_DATE = "2026-11-23"
C9200_REVIEW_SOURCE_URL = (
    "https://github.com/yikkrrtykj/event-switch-manager/"
    "issues/4#issuecomment-7099400033"
)
C9200_REVIEW_PR_URL = (
    "https://github.com/yikkrrtykj/event-switch-manager/pull/36"
)

#: Frozen R55/R56 review baseline.  These values are deliberately independent
#: of the mutable Evidence content; content changes must fail review instead of
#: silently receiving a new attestation.
C9200_REVIEW_CONTENT_DIGESTS: dict[str, str] = {
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


@dataclass(frozen=True, slots=True)
class C9200ReviewProvenance:
    reviewer: str
    reviewed_at: str
    review_type: Literal["AI-independent-read-only-document-review"]
    source_url: str
    pr_url: str
    human_approval: bool
    hardware_verified: bool
    deployment_authorized: bool


C9200_REVIEW_PROVENANCE = C9200ReviewProvenance(
    reviewer=C9200_REVIEW_REVIEWER,
    reviewed_at=C9200_REVIEW_DATE,
    review_type="AI-independent-read-only-document-review",
    source_url=C9200_REVIEW_SOURCE_URL,
    pr_url=C9200_REVIEW_PR_URL,
    human_approval=False,
    hardware_verified=False,
    deployment_authorized=False,
)

_TOPIC_FINDINGS: dict[str, tuple[str, ...]] = {
    "l3-9200-ip-routing-v1": (
        "Cisco 17.12 platform guide directly documents ip routing in global "
        "configuration mode.",
        "Basic routing under Network Essentials is explicitly supported by the "
        "Interface Connections license statement.",
        "AI read-only review is not human engineering, Cisco TAC, hardware or "
        "deployment approval.",
        "Actual device license activation and hardware behavior remain unverified.",
    ),
    "l3-9200-svi-interface-v1": (
        "Cisco 17.12 Routing and Interface Characteristics guides document "
        "interface vlan vlan-id and SVI behavior.",
        "Network Essentials supports basic routing; Network Advantage provides "
        "the higher routing tier.",
        "Renderer-specific Vlan canonicalization and VLAN exclusions remain "
        "explicit safety scope.",
        "AI read-only review is not human, hardware or deployment approval.",
    ),
    "l3-9200-svi-address-v1": (
        "Catalyst 9200 17.12 Command Reference contains the platform ip address "
        "command.",
        "The reviewed evidence uses a primary IPv4-only renderer subset and does "
        "not claim platform rejection of excluded forms.",
        "Network Essentials basic routing and Network Advantage higher routing "
        "license basis were reviewed.",
        "AI read-only review is not human, hardware or deployment approval.",
    ),
    "l3-9200-static-route-v1": (
        "Cisco 17.12 Protocol-Independent Features documents ip route prefix "
        "mask {address | interface} [distance].",
        "Network Essentials explicitly supports basic static routing; the "
        "project only permits IPv4 next-hop.",
        "Default Route, VRF, track/tag, interface-only next-hop and dynamic "
        "routing remain excluded.",
        "AI read-only review is not human, hardware or deployment approval.",
    ),
}


def build_review(row: CommandEvidenceRow) -> EvidenceReview:
    """Create the fixed AI review attestation for an exact reviewed row.

    The expected digest is read from the frozen review baseline, never from
    the current mutable row.  If the row content changed, the old review is
    invalid and a fresh independent review is required.
    """
    expected_digest = C9200_REVIEW_CONTENT_DIGESTS.get(row.evidence_id)
    if expected_digest is None:
        raise ValueError("No reviewed C9200 attestation for this evidence ID")
    actual_digest = row.content_digest()
    if actual_digest != expected_digest:
        raise ValueError(
            "C9200 evidence content changed; fixed review digest no longer matches",
        )
    return EvidenceReview(
        state=EvidenceReviewState.REVIEWED,
        reviewer=C9200_REVIEW_REVIEWER,
        reviewed_at=C9200_REVIEW_DATE,
        findings=_TOPIC_FINDINGS[row.evidence_id],
        content_digest=expected_digest,
    )


def validate_attestation(
    row: CommandEvidenceRow,
    review: EvidenceReview,
) -> None:
    """Reject an attestation unless it is the fixed reviewed baseline."""
    expected_digest = C9200_REVIEW_CONTENT_DIGESTS.get(row.evidence_id)
    if expected_digest is None:
        raise ValueError("evidence ID is not in the fixed review baseline")
    if row.content_digest() != expected_digest:
        raise ValueError("evidence content no longer matches fixed review digest")
    if review.content_digest != expected_digest:
        raise ValueError("review digest is not the fixed baseline digest")
    if review.state is not EvidenceReviewState.REVIEWED:
        raise ValueError("review state is not REVIEWED")
    if review.reviewer != C9200_REVIEW_REVIEWER:
        raise ValueError("review reviewer is not the reviewed provenance")
    if review.reviewed_at != C9200_REVIEW_DATE:
        raise ValueError("review date is not the reviewed provenance")
    if review.findings != _TOPIC_FINDINGS.get(row.evidence_id):
        raise ValueError("review findings are not the reviewed provenance")
    if not review.well_formed:
        raise ValueError("review metadata is incomplete")


def _reviewed_row(row: CommandEvidenceRow) -> CommandEvidenceRow:
    review = build_review(row)
    expected_digest = C9200_REVIEW_CONTENT_DIGESTS[row.evidence_id]
    if (
        review.content_digest != expected_digest
        or reviewed_content_digest(row) != expected_digest
        or review.state is not EvidenceReviewState.REVIEWED
        or not review.well_formed
    ):
        raise ValueError("C9200 review attestation is not digest-bound")
    return replace(row, review=review)


def reviewed_content_digest(row: CommandEvidenceRow) -> str:
    """Compute current content digest only for a fixed-baseline comparison."""
    return row.content_digest()


C9200_REVIEWED_ROWS: tuple[CommandEvidenceRow, ...] = tuple(
    _reviewed_row(row) for row in ROWS
)

#: Explicitly registered production C9200 Evidence object.  Selection trusts
#: this object identity, not its ID or fingerprint string.
C9200_REVIEWED_REGISTRY = CommandEvidenceRegistry(
    C9200_REVIEWED_ROWS,
    registry_id=C9200_REVIEWED_REGISTRY_ID,
    production=True,
)

# Draft Registry remains available for provenance/review checks but is not
# selected by production code.
C9200_REVIEWED_DRAFT_REGISTRY_ID = C9200_DRAFT_REGISTRY_ID


def validate_reviewed_registry() -> None:
    """Fail closed if reviewed data or attestations drift from fixed baseline."""
    if C9200_REVIEWED_REGISTRY.production is not True:
        raise ValueError("C9200 reviewed Registry must be production")
    if len(C9200_REVIEWED_REGISTRY.rows) != len(C9200_REVIEW_CONTENT_DIGESTS):
        raise ValueError("C9200 reviewed Registry row count changed")
    reviewed_ids = [row.evidence_id for row in C9200_REVIEWED_REGISTRY.rows]
    if len(reviewed_ids) != len(set(reviewed_ids)):
        raise ValueError("C9200 reviewed Registry has duplicate evidence IDs")
    if set(reviewed_ids) != set(C9200_REVIEW_CONTENT_DIGESTS):
        raise ValueError("C9200 reviewed Registry evidence ID set changed")
    original_by_id = {row.evidence_id: row for row in ROWS}
    for reviewed in C9200_REVIEWED_REGISTRY.rows:
        original = original_by_id.get(reviewed.evidence_id)
        if original is None:
            raise ValueError("C9200 reviewed row is not an original Evidence row")
        validate_attestation(original, reviewed.review)
        validate_attestation(reviewed, reviewed.review)
        if not reviewed.review.well_formed or not reviewed.renderable:
            raise ValueError("C9200 reviewed row is not renderable")
        if any(
            blocker == "evidence-scope-gap-independent-evidence-review-required"
            for blocker in reviewed.scope_blockers()
        ):
            raise ValueError("Review lifecycle gate did not release")
    if C9200_REVIEWED_REGISTRY.eligible_count != len(C9200_REVIEW_CONTENT_DIGESTS):
        raise ValueError("C9200 reviewed Registry has ineligible rows")
    if C9200_REVIEWED_REGISTRY.renderable_count != len(C9200_REVIEW_CONTENT_DIGESTS):
        raise ValueError("C9200 reviewed Registry has unreviewed rows")


validate_reviewed_registry()


__all__ = [
    "C9200_REVIEWED_DRAFT_REGISTRY_ID",
    "C9200_REVIEWED_REGISTRY",
    "C9200_REVIEWED_REGISTRY_ID",
    "C9200_REVIEWED_ROWS",
    "C9200_REVIEW_DATE",
    "C9200_REVIEW_CONTENT_DIGESTS",
    "C9200_REVIEW_PROVENANCE",
    "C9200_REVIEW_PR_URL",
    "C9200_REVIEW_REVIEWER",
    "C9200_REVIEW_SOURCE_URL",
    "C9200ReviewProvenance",
    "build_review",
    "validate_attestation",
    "validate_reviewed_registry",
]
