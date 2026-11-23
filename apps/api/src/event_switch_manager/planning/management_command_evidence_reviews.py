"""CIS-04B-1 staged management Evidence review binding.

The four corrected Evidence rows below have exact Cisco IOS XE 17.12.x URLs
for the command sections.  They remain PENDING in the draft registry until a
fixed, externally approved attestation exists.

No production review is granted here.  ``MANAGEMENT_APPROVED_REVIEWS`` is
deliberately empty.  The reviewed registry builder exists for the eventual
approved fixed manifests and for isolated tests; it never activates itself.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..domain import DeviceFamily
from .management_command_evidence import (
    MANAGEMENT_EVIDENCE_DRAFT_REGISTRY,
    ManagementCommandTopic,
    ManagementEvidenceRegistry,
    ManagementEvidenceRow,
)

R63_STAGED_REGISTRY_ID = (
    "cis-04b1-management-command-evidence-staged-v1"
)
R63_REVIEWED_REGISTRY_ID = (
    "cis-04b1-management-command-evidence-reviewed-v1"
)
R63_REVIEWED_EVIDENCE_IDS: tuple[str, ...] = (
    "mgmt-9300-domain-name-v1",
    "mgmt-9300-ssh-version-v1",
    "mgmt-9200-domain-name-v1",
    "mgmt-9200-ssh-version-v1",
)
R63_REVIEWED_TOPIC_IDS: tuple[str, ...] = (
    "management-domain-name",
    "management-ssh-version",
)

URL_9300_CONFIG_SSH = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/configuration_guide/sec/b_1712_sec_9300_cg/"
    "configuring_secure_shell__ssh_.html"
)
URL_9200_CONFIG_SSH = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/configuration_guide/sec/b_1712_sec_9200_cg/"
    "configuring_secure_shell__ssh_.html"
)
URL_9300_SSH_V2 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/configuration_guide/sec/b_1712_sec_9300_cg/"
    "secure_shell_version_2_support.html"
)
URL_9200_SSH_V2 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/configuration_guide/sec/b_1712_sec_9200_cg/"
    "secure_shell_version_2_support.html"
)


class ManagementReviewError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class ManagementReviewAttestation:
    """A fixed external review attestation for exactly one Evidence digest."""

    evidence_id: str
    content_digest: str
    reviewer: str
    reviewed_at: str
    findings: tuple[str, ...]
    source_url: str
    ai_review_disclosure: str

    @property
    def complete(self) -> bool:
        return bool(
            self.evidence_id
            and len(self.content_digest) == 64
            and self.reviewer
            and self.reviewed_at
            and self.findings
            and self.source_url.startswith("https://www.cisco.com/")
            and self.ai_review_disclosure
        )


# Deliberately empty: no independent review has been granted for R63.
MANAGEMENT_APPROVED_REVIEWS: tuple[ManagementReviewAttestation, ...] = ()


def _reviewed_row(
    row: ManagementEvidenceRow, *, source_url: str, source_section: str,
    preconditions: tuple[str, ...], exclusions: tuple[str, ...],
    risks: tuple[str, ...],
) -> ManagementEvidenceRow:
    return replace(
        row,
        source_url=source_url,
        source_section=source_section,
        preconditions=preconditions,
        exclusions=exclusions,
        risks=risks,
    )


def _corrected_rows() -> tuple[ManagementEvidenceRow, ...]:
    by_id = {row.evidence_id: row for row in MANAGEMENT_EVIDENCE_DRAFT_REGISTRY.rows}
    corrected: list[ManagementEvidenceRow] = []
    for evidence_id in R63_REVIEWED_EVIDENCE_IDS:
        row = by_id[evidence_id]
        family = row.family
        if row.topic is ManagementCommandTopic.DOMAIN_NAME:
            source_url = (
                URL_9300_CONFIG_SSH
                if family is DeviceFamily.CATALYST_9300 else URL_9200_CONFIG_SSH
            )
            corrected.append(_reviewed_row(
                row,
                source_url=source_url,
                source_section=(
                    "Setting Up the Device to Run SSH > ip domain name"
                ),
                preconditions=(
                    "hostname-configured",
                    "management-domain-planned",
                ),
                exclusions=(
                    "do not derive a domain from a URL",
                    "do not accept whitespace, newline, quotes or CLI punctuation",
                ),
                risks=(
                    "domain change can affect SSH host identity",
                    "invalid domain can break RSA/SSH host-key generation",
                ),
            ))
        elif row.topic is ManagementCommandTopic.SSH_VERSION:
            source_url = (
                URL_9300_SSH_V2
                if family is DeviceFamily.CATALYST_9300 else URL_9200_SSH_V2
            )
            corrected.append(_reviewed_row(
                row,
                source_url=source_url,
                source_section=(
                    "Secure Shell Version 2 Support > ip ssh version 2"
                ),
                preconditions=(
                    "management-ip-planned",
                    "authentication-verified",
                    "rsa-key-present-verified",
                    "console-recovery-verified",
                ),
                exclusions=(
                    "no SSH server enable",
                    "no VTY, login, AAA or console change",
                    "no key generation or replacement",
                ),
                risks=(
                    "version-only change does not prove SSH server readiness",
                    "SSH management may lock out operators before recovery is verified",
                ),
            ))
        else:  # pragma: no cover - guarded by the frozen ID list
            raise ManagementReviewError("unexpected-r63-evidence-topic")
    return tuple(corrected)


R63_CORRECTED_ROWS = _corrected_rows()
_CORRECTED_BY_ID = {row.evidence_id: row for row in R63_CORRECTED_ROWS}
R63_STAGED_ROWS: tuple[ManagementEvidenceRow, ...] = tuple(
    _CORRECTED_BY_ID.get(row.evidence_id, row)
    for row in MANAGEMENT_EVIDENCE_DRAFT_REGISTRY.rows
)
R63_STAGED_REGISTRY = ManagementEvidenceRegistry(
    R63_STAGED_ROWS,
    registry_id=R63_STAGED_REGISTRY_ID,
    production=False,
)
R63_STAGED_REGISTRY_FINGERPRINT = (
    "565d4ded43aa867f0e46bc16797d9ea6d6d9817286b8323a295adb94014489c2"
)

# Frozen old and corrected content digests for the four candidate rows.  The
# corrected rows remain PENDING until an external fixed manifest is supplied.
R63_OLD_DIGESTS: dict[str, str] = {
    "mgmt-9300-domain-name-v1": (
        "1350a8446a67a4aa744aabf3981508a8b4a3779da6603ae0731f2d18893189f3"
    ),
    "mgmt-9300-ssh-version-v1": (
        "045576701a4effa0bcc4284b5d42d95e643e7829a60221b5d72a8b0c393a2dd7"
    ),
    "mgmt-9200-domain-name-v1": (
        "b585e1d6612794bc273e2457e1c3bad9c8f358d4cf1974f5468afaace05ab945"
    ),
    "mgmt-9200-ssh-version-v1": (
        "be5db50d62874e19c28370b1f92a3e25a77a4bd0317da90d4b505bb95406f370"
    ),
}
R63_STAGED_DIGESTS: dict[str, str] = {
    "mgmt-9300-domain-name-v1": (
        "b476f57fa27800820d04ae75bd8aee091af2bb4bc7d491e4ba4a84479982473d"
    ),
    "mgmt-9300-ssh-version-v1": (
        "27b5c1975cf2bbc98337875827b9b931d535d9aba10055f0d467cdc00b5f88f5"
    ),
    "mgmt-9200-domain-name-v1": (
        "e221b98733c8a9df0d45d2d68878c62efcf3051e89ecdd7bcffeca30fc642b44"
    ),
    "mgmt-9200-ssh-version-v1": (
        "62786d76920888edd472a14118393db3cf608f8b2499fffc8c8a8a45b1fd6882"
    ),
}
for _row in R63_CORRECTED_ROWS:
    if _row.content_digest() != R63_STAGED_DIGESTS[_row.evidence_id]:
        raise ManagementReviewError("management-review-staged-digest-drift")
for _row in MANAGEMENT_EVIDENCE_DRAFT_REGISTRY.rows:
    if (_row.evidence_id in R63_OLD_DIGESTS
            and _row.content_digest() != R63_OLD_DIGESTS[_row.evidence_id]):
        raise ManagementReviewError("management-review-legacy-digest-drift")
if R63_STAGED_REGISTRY.fingerprint != R63_STAGED_REGISTRY_FINGERPRINT:
    raise ManagementReviewError("management-review-staged-registry-fingerprint-drift")


def review_status(evidence_id: str) -> str:
    for attestation in MANAGEMENT_APPROVED_REVIEWS:
        if attestation.evidence_id == evidence_id:
            return "REVIEWED"
    return "PENDING"


def build_reviewed_registry(
    attestations: tuple[ManagementReviewAttestation, ...],
    *,
    registry_id: str = R63_REVIEWED_REGISTRY_ID,
) -> ManagementEvidenceRegistry:
    """Build a reviewed registry only from a complete fixed four-row manifest."""
    by_id = {row.evidence_id: row for row in R63_CORRECTED_ROWS}
    seen: set[str] = set()
    reviewed: list[ManagementEvidenceRow] = []
    for attestation in attestations:
        if not attestation.complete:
            raise ManagementReviewError("management-review-attestation-incomplete")
        if attestation.evidence_id not in by_id:
            raise ManagementReviewError("management-review-evidence-unknown")
        if attestation.evidence_id in seen:
            raise ManagementReviewError("management-review-evidence-duplicate")
        seen.add(attestation.evidence_id)
        row = by_id[attestation.evidence_id]
        if attestation.content_digest != row.content_digest():
            raise ManagementReviewError("management-review-digest-mismatch")
        if attestation.source_url != row.source_url:
            raise ManagementReviewError("management-review-source-mismatch")
        reviewed.append(row.with_review(
            reviewer=attestation.reviewer,
            reviewed_at=attestation.reviewed_at,
            findings=attestation.findings,
        ))
    if seen != set(R63_REVIEWED_EVIDENCE_IDS) or len(reviewed) != 4:
        raise ManagementReviewError("management-review-incomplete-manifest")
    reviewed_by_id = {row.evidence_id: row for row in reviewed}
    rows = tuple(
        reviewed_by_id.get(row.evidence_id, row) for row in R63_STAGED_ROWS
    )
    return ManagementEvidenceRegistry(rows, registry_id=registry_id, production=False)


def production_management_registry() -> ManagementEvidenceRegistry:
    """Return the production registry; no manifest means no reviewed activation."""
    if not MANAGEMENT_APPROVED_REVIEWS:
        return MANAGEMENT_EVIDENCE_DRAFT_REGISTRY
    return build_reviewed_registry(MANAGEMENT_APPROVED_REVIEWS)


def test_only_reviewed_registry() -> ManagementEvidenceRegistry:
    """Isolated reviewed registry for tests; never called by production API."""
    return build_reviewed_registry(tuple(
        ManagementReviewAttestation(
            evidence_id=row.evidence_id,
            content_digest=row.content_digest(),
            reviewer="TEST-ONLY-MANAGEMENT-REVIEW",
            reviewed_at="2026-11-23",
            findings=("test-only R63 reviewed fixture",),
            source_url=row.source_url,
            ai_review_disclosure="test-only; not an independent production review",
        )
        for row in R63_CORRECTED_ROWS
    ), registry_id="cis-04b1-management-test-only-reviewed-v1")


__all__ = [
    "MANAGEMENT_APPROVED_REVIEWS",
    "ManagementReviewAttestation",
    "ManagementReviewError",
    "R63_CORRECTED_ROWS",
    "R63_OLD_DIGESTS",
    "R63_REVIEWED_EVIDENCE_IDS",
    "R63_REVIEWED_REGISTRY_ID",
    "R63_REVIEWED_TOPIC_IDS",
    "R63_STAGED_DIGESTS",
    "R63_STAGED_REGISTRY",
    "R63_STAGED_REGISTRY_ID",
    "R63_STAGED_ROWS",
    "build_reviewed_registry",
    "production_management_registry",
    "review_status",
    "test_only_reviewed_registry",
    "URL_9200_CONFIG_SSH",
    "URL_9200_SSH_V2",
    "URL_9300_CONFIG_SSH",
    "URL_9300_SSH_V2",
]
