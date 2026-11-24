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
    """A caller-supplied structural attestation; it is not production authority."""

    evidence_id: str
    content_digest: str
    reviewer: str
    reviewed_at: str
    findings: tuple[str, ...]
    source_url: str
    ai_review_disclosure: str
    review_type: str = "AI-independent-read-only-document-review"
    approval_scope: str = "DOCUMENT_SYNTAX_ONLY"
    record_id: str = ""

    @property
    def complete(self) -> bool:
        """Structural completeness only. This never grants production authority."""
        return bool(
            self.evidence_id
            and len(self.content_digest) == 64
            and self.reviewer
            and self.reviewed_at
            and self.findings
            and self.source_url.startswith("https://www.cisco.com/")
            and self.ai_review_disclosure
        )


@dataclass(frozen=True, slots=True)
class ManagementReviewRecord:
    """Server-fixed review provenance record.

    A structurally complete record is still not production authorization unless
    it is present in the server-fixed ``PRODUCTION_APPROVED_RECORDS`` manifest
    with ``production_authorized=True`` and an approved scope.
    """

    record_id: str
    evidence_id: str
    content_digest: str
    review_type: str
    reviewer: str
    reviewed_at: str
    findings: tuple[str, ...]
    evidence_source_url: str
    review_record_url: str
    approval_scope: str
    production_authorized: bool

    @property
    def structural_complete(self) -> bool:
        return bool(
            self.record_id
            and self.evidence_id
            and len(self.content_digest) == 64
            and self.review_type
            and self.reviewer
            and self.reviewed_at
            and self.findings
            and self.evidence_source_url.startswith("https://www.cisco.com/")
            and self.review_record_url.startswith("https://github.com/")
            and self.approval_scope
        )


# Deliberately empty: no production authorization has been granted for R63.
MANAGEMENT_APPROVED_REVIEWS: tuple[ManagementReviewAttestation, ...] = ()
PRODUCTION_APPROVED_RECORDS: tuple[ManagementReviewRecord, ...] = ()
R63A_REVIEW_RECORD_URL = (
    "https://github.com/yikkrrtykj/event-switch-manager/pull/40"
    "#issuecomment-7110303139"
)
R63A_AI_REVIEWER = (
    "ChatGPT (GPT-6) — independent read-only AI documentation reviewer"
)
R63A_AI_REVIEW_TYPE = "AI-independent-read-only-document-review"
R63A_AI_REVIEW_DATE = "2026-11-23"


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

_R63A_AI_FINDINGS: tuple[str, ...] = (
    "Catalyst 9300/9200 ip domain name is supported by IOS XE 17.12.x documentation",
    "Catalyst 9300/9200 ip ssh version 2 is supported by IOS XE 17.12.x documentation",
    "Both reviewed commands are Global Configuration Mode commands",
    "Domain Name does not mean the SSH server is enabled",
    "SSH Version does not replace RSA key, Authentication, VTY or Console Recovery verification",
    "No actual hardware or running License verification was performed",
)

# Server-fixed provenance for the externally supplied AI document-syntax review.
# These records are DOCUMENT_SYNTAX_ONLY and are not production authorization.
DOCUMENT_REVIEW_RECORDS: tuple[ManagementReviewRecord, ...] = tuple(
    ManagementReviewRecord(
        record_id=f"r63a-ai-document-{evidence_id}",
        evidence_id=evidence_id,
        content_digest=R63_STAGED_DIGESTS[evidence_id],
        review_type=R63A_AI_REVIEW_TYPE,
        reviewer=R63A_AI_REVIEWER,
        reviewed_at=R63A_AI_REVIEW_DATE,
        findings=_R63A_AI_FINDINGS,
        evidence_source_url=_CORRECTED_BY_ID[evidence_id].source_url,
        review_record_url=R63A_REVIEW_RECORD_URL,
        approval_scope="DOCUMENT_SYNTAX_ONLY",
        production_authorized=False,
    )
    for evidence_id in R63_REVIEWED_EVIDENCE_IDS
)


def document_review_record_id(evidence_id: str) -> str:
    return f"r63a-ai-document-{evidence_id}"


def document_review_record_valid(record: ManagementReviewRecord) -> bool:
    """Exact fixed provenance check; DOCUMENT_SYNTAX_ONLY, never authority."""
    if record.evidence_id not in R63_REVIEWED_EVIDENCE_IDS:
        return False
    row = _CORRECTED_BY_ID.get(record.evidence_id)
    return bool(
        record.structural_complete
        and record.record_id == document_review_record_id(record.evidence_id)
        and record.evidence_id in R63_REVIEWED_EVIDENCE_IDS
        and record.approval_scope == "DOCUMENT_SYNTAX_ONLY"
        and not record.production_authorized
        and row is not None
        and record.content_digest == R63_STAGED_DIGESTS[record.evidence_id]
        and record.content_digest == row.content_digest()
        and record.evidence_source_url == row.source_url
        and record.review_record_url == R63A_REVIEW_RECORD_URL
        and record.review_type == R63A_AI_REVIEW_TYPE
        and record.reviewer == R63A_AI_REVIEWER
        and record.reviewed_at == R63A_AI_REVIEW_DATE
        and record.findings == _R63A_AI_FINDINGS
    )


def validate_document_review_record_set(
    records: tuple[ManagementReviewRecord, ...] = DOCUMENT_REVIEW_RECORDS,
) -> bool:
    """Startup integrity check for exactly the four fixed document records."""
    if len(records) != 4:
        raise ManagementReviewError(
            "management-review-document-record-set-incomplete",
        )
    evidence_ids = [record.evidence_id for record in records]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ManagementReviewError(
            "management-review-document-record-set-duplicate",
        )
    if set(evidence_ids) != set(R63_REVIEWED_EVIDENCE_IDS):
        raise ManagementReviewError(
            "management-review-document-record-unknown",
        )
    record_ids = [record.record_id for record in records]
    if len(record_ids) != len(set(record_ids)):
        raise ManagementReviewError(
            "management-review-document-record-set-duplicate",
        )
    if set(record_ids) != {
        document_review_record_id(evidence_id)
        for evidence_id in R63_REVIEWED_EVIDENCE_IDS
    }:
        raise ManagementReviewError(
            "management-review-document-record-unknown",
        )
    if not all(document_review_record_valid(record) for record in records):
        raise ManagementReviewError("management-review-document-record-invalid")
    return True


validate_document_review_record_set()


def production_review_record_valid(record: ManagementReviewRecord) -> bool:
    """Declared production fields only; manifest membership is authority."""
    row = _CORRECTED_BY_ID.get(record.evidence_id)
    return bool(
        record.structural_complete
        and record.record_id
        and record.production_authorized
        and record.approval_scope == "PRODUCTION_ACTIVATION"
        and row is not None
        and record.content_digest == row.content_digest()
        and record.evidence_source_url == row.source_url
    )


def _validate_production_manifest(
    records: tuple[ManagementReviewRecord, ...],
) -> tuple[ManagementReviewRecord, ...]:
    if not records:
        raise ManagementReviewError(
            "management-review-production-authorization-pending",
        )
    if len(records) != 4:
        raise ManagementReviewError("management-review-incomplete-manifest")
    evidence_ids = [record.evidence_id for record in records]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ManagementReviewError("management-review-evidence-duplicate")
    if set(evidence_ids) != set(R63_REVIEWED_EVIDENCE_IDS):
        raise ManagementReviewError("management-review-evidence-unknown")
    record_ids = [record.record_id for record in records]
    if any(not record_id for record_id in record_ids):
        raise ManagementReviewError("management-review-record-id-invalid")
    if len(record_ids) != len(set(record_ids)):
        raise ManagementReviewError("management-review-record-id-duplicate")
    if not all(production_review_record_valid(record) for record in records):
        raise ManagementReviewError("management-review-production-record-invalid")
    return records


def review_status(evidence_id: str) -> str:
    """Production REVIEWED requires the entire server-fixed Manifest to pass."""
    if PRODUCTION_APPROVED_RECORDS:
        try:
            manifest = _validate_production_manifest(
                PRODUCTION_APPROVED_RECORDS,
            )
        except ManagementReviewError:
            manifest = ()
        for record in manifest:
            if record.evidence_id == evidence_id:
                return "REVIEWED"
    for record in DOCUMENT_REVIEW_RECORDS:
        if (record.evidence_id == evidence_id
                and document_review_record_valid(record)):
            return "DOCUMENT-SYNTAX-REVIEWED"
    return "PENDING"


def _review_rows_from_attestations(
    attestations: tuple[ManagementReviewAttestation, ...],
) -> tuple[ManagementEvidenceRow, ...]:
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
    return tuple(
        reviewed_by_id.get(row.evidence_id, row) for row in R63_STAGED_ROWS
    )


def build_reviewed_registry(
    attestations: tuple[ManagementReviewAttestation, ...],
    *,
    registry_id: str = R63_REVIEWED_REGISTRY_ID,
    test_only: bool = False,
) -> ManagementEvidenceRegistry:
    """Build a test-only reviewed registry, never a production authorization."""
    if not test_only:
        raise ManagementReviewError(
            "management-review-production-authorization-required",
        )
    if not registry_id.startswith("cis-04b1-management-test-only-"):
        raise ManagementReviewError("management-review-test-only-registry-id")
    return ManagementEvidenceRegistry(
        _review_rows_from_attestations(attestations),
        registry_id=registry_id,
        production=False,
    )


def build_production_reviewed_registry() -> ManagementEvidenceRegistry:
    """Build only from the server-fixed, exact four-record production manifest."""
    manifest = _validate_production_manifest(PRODUCTION_APPROVED_RECORDS)
    by_id = {row.evidence_id: row for row in R63_CORRECTED_ROWS}
    reviewed: list[ManagementEvidenceRow] = []
    for record in manifest:
        reviewed.append(by_id[record.evidence_id].with_review(
            reviewer=record.reviewer,
            reviewed_at=record.reviewed_at,
            findings=record.findings,
        ))
    reviewed_by_id = {row.evidence_id: row for row in reviewed}
    rows = tuple(
        reviewed_by_id.get(row.evidence_id, row) for row in R63_STAGED_ROWS
    )
    return ManagementEvidenceRegistry(
        rows, registry_id=R63_REVIEWED_REGISTRY_ID, production=False,
    )


def production_management_registry() -> ManagementEvidenceRegistry:
    """Return the production registry; no manifest means no reviewed activation."""
    if not PRODUCTION_APPROVED_RECORDS:
        return MANAGEMENT_EVIDENCE_DRAFT_REGISTRY
    return build_production_reviewed_registry()


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
            review_type="TEST-ONLY",
            approval_scope="TEST_ONLY",
            record_id="test-only",
        )
        for row in R63_CORRECTED_ROWS
    ), registry_id="cis-04b1-management-test-only-reviewed-v1", test_only=True)


__all__ = [
    "DOCUMENT_REVIEW_RECORDS",
    "MANAGEMENT_APPROVED_REVIEWS",
    "ManagementReviewAttestation",
    "ManagementReviewError",
    "ManagementReviewRecord",
    "PRODUCTION_APPROVED_RECORDS",
    "R63A_AI_REVIEW_DATE",
    "R63A_AI_REVIEWER",
    "R63A_AI_REVIEW_TYPE",
    "R63A_REVIEW_RECORD_URL",
    "R63_CORRECTED_ROWS",
    "R63_OLD_DIGESTS",
    "R63_REVIEWED_EVIDENCE_IDS",
    "R63_REVIEWED_REGISTRY_ID",
    "R63_REVIEWED_TOPIC_IDS",
    "R63_STAGED_DIGESTS",
    "R63_STAGED_REGISTRY",
    "R63_STAGED_REGISTRY_ID",
    "R63_STAGED_ROWS",
    "build_production_reviewed_registry",
    "build_reviewed_registry",
    "document_review_record_id",
    "document_review_record_valid",
    "production_management_registry",
    "production_review_record_valid",
    "review_status",
    "test_only_reviewed_registry",
    "validate_document_review_record_set",
    "URL_9200_CONFIG_SSH",
    "URL_9200_SSH_V2",
    "URL_9300_CONFIG_SSH",
    "URL_9300_SSH_V2",
]
