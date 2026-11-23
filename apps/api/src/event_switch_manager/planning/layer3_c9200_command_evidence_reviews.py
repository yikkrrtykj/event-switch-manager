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
    """Create the real AI review attestation for one original row."""
    if row.evidence_id not in _TOPIC_FINDINGS:
        raise ValueError("No reviewed C9200 attestation for this evidence ID")
    return EvidenceReview(
        state=EvidenceReviewState.REVIEWED,
        reviewer=C9200_REVIEW_REVIEWER,
        reviewed_at=C9200_REVIEW_DATE,
        findings=_TOPIC_FINDINGS[row.evidence_id],
        content_digest=row.content_digest(),
    )


def _reviewed_row(row: CommandEvidenceRow) -> CommandEvidenceRow:
    review = build_review(row)
    if (
        review.content_digest != row.content_digest()
        or review.state is not EvidenceReviewState.REVIEWED
        or not review.well_formed
    ):
        raise ValueError("C9200 review attestation is not digest-bound")
    return replace(row, review=review)


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
    """Fail closed if reviewed data or attestations drift from original rows."""
    if C9200_REVIEWED_REGISTRY.production is not True:
        raise ValueError("C9200 reviewed Registry must be production")
    if len(C9200_REVIEWED_REGISTRY.rows) != len(ROWS):
        raise ValueError("C9200 reviewed Registry row count changed")
    for original, reviewed in zip(ROWS, C9200_REVIEWED_REGISTRY.rows, strict=True):
        if original.evidence_id != reviewed.evidence_id:
            raise ValueError("C9200 reviewed Registry row identity changed")
        if reviewed.review.content_digest != original.content_digest():
            raise ValueError("C9200 review digest does not bind original content")
        if reviewed.content_digest() != original.content_digest():
            raise ValueError("C9200 reviewed row content changed")
        if not reviewed.renderable:
            raise ValueError("C9200 reviewed row is not renderable")
        if any(
            blocker.startswith("evidence-scope-gap-independent-evidence-review")
            for blocker in reviewed.scope_blockers()
        ):
            raise ValueError("Review lifecycle gate did not release")
    if C9200_REVIEWED_REGISTRY.eligible_count != len(ROWS):
        raise ValueError("C9200 reviewed Registry has ineligible rows")


validate_reviewed_registry()


__all__ = [
    "C9200_REVIEWED_DRAFT_REGISTRY_ID",
    "C9200_REVIEWED_REGISTRY",
    "C9200_REVIEWED_REGISTRY_ID",
    "C9200_REVIEWED_ROWS",
    "C9200_REVIEW_DATE",
    "C9200_REVIEW_PROVENANCE",
    "C9200_REVIEW_PR_URL",
    "C9200_REVIEW_REVIEWER",
    "C9200_REVIEW_SOURCE_URL",
    "C9200ReviewProvenance",
    "build_review",
    "validate_reviewed_registry",
]
