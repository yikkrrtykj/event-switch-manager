"""CIS-04B management/SSHv2 candidate rendering and independent validation.

Production evidence remains PENDING, so every production candidate is BLOCKED
and carries no command text. A test-only reviewed evidence registry may prove
the renderer/validator mechanics, but is never a production approval. The
secret-bearing local username topic never renders text.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from ..domain import DeviceFamily
from .management_command_evidence import (
    MANAGEMENT_EVIDENCE_DRAFT_REGISTRY,
    ManagementCommandTopic,
    ManagementEvidenceRegistry,
    ManagementEvidenceRow,
)
from .management_intent import ManagementIntent
from .plan import PlanRevision, canonical_plan, plan_hash
from .types import Record

MANAGEMENT_RENDER_SCHEMA_VERSION: Literal[1] = 1
MANAGEMENT_RENDER_CONTRACT_ID: Literal[
    "cis-04b-cisco-management-cli-candidate-v1"
] = "cis-04b-cisco-management-cli-candidate-v1"
MANAGEMENT_VALIDATION_SCHEMA_VERSION: Literal[1] = 1
MANAGEMENT_VALIDATION_CONTRACT_ID: Literal[
    "cis-04b-management-cli-validation-v1"
] = "cis-04b-management-cli-validation-v1"


class ManagementRenderError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ManagementCandidate(Record):
    candidate_id: str
    assignment_id: UUID
    topic: str
    command_context_mode: Literal["global", "line"]
    command_context_header: str
    target_name: str
    status: Literal["candidate", "blocked", "unsupported"]
    candidate_text: str | None
    parameters: dict[str, JsonValue] = {}
    evidence_id: str
    evidence_review_state: str
    evidence_content_digest: str
    evidence_source_url: str
    secret_bearing: bool
    requires_field_verification: bool = True
    blocking_reasons: tuple[str, ...] = ()
    candidate_fingerprint: str


class ManagementSource(Record):
    revision_uuid: UUID
    revision_number: int
    revision_hash: str
    management_intent_fingerprint: str
    evidence_registry_id: str
    evidence_registry_fingerprint: str


class ManagementDeviceRef(Record):
    assignment_id: UUID
    hostname: str
    family: str | None
    exact_pid: str | None
    software_image: str | None
    software_license: str | None
    stack_identity: str


class ManagementSafety(Record):
    candidate_only: Literal[True] = True
    read_only: Literal[True] = True
    executable: Literal[False] = False
    deployable: Literal[False] = False
    deployment_allowed: Literal[False] = False
    device_connection: Literal["none"] = "none"
    running_config_read: Literal[False] = False
    device_writes_enabled: Literal[False] = False
    full_config_generated: Literal[False] = False
    cli: None = None
    deployment_artifact: None = None
    hardware_verified: Literal[False] = False
    secrets_included: Literal[False] = False
    secret_placeholder_included: Literal[False] = False


class ManagementSummary(Record):
    total: int
    candidates: int
    blocked: int
    skipped: int


class ManagementCandidateDocument(Record):
    management_render_schema_version: Literal[1] = (
        MANAGEMENT_RENDER_SCHEMA_VERSION
    )
    contract_id: Literal[
        "cis-04b-cisco-management-cli-candidate-v1"
    ] = MANAGEMENT_RENDER_CONTRACT_ID
    source: ManagementSource
    assignment_id: UUID
    device: ManagementDeviceRef
    candidates: tuple[ManagementCandidate, ...]
    unresolved_prerequisites: tuple[str, ...]
    deployment_blockers: tuple[str, ...]
    safety: ManagementSafety = ManagementSafety()
    summary: ManagementSummary
    verification: Literal["not-verified"] = "not-verified"
    deployment_status: Literal["blocked"] = "blocked"
    render_fingerprint: str


class ManagementExpectedSource(Record):
    revision_uuid: UUID
    revision_number: int
    revision_hash: str
    management_intent_fingerprint: str
    evidence_registry_id: str
    evidence_registry_fingerprint: str
    assignment_id: UUID


class ManagementCandidateValidation(Record):
    candidate_id: str
    topic: str
    status: str
    independent_verdict: Literal["pass", "fail", "blocked", "not-run"]
    candidate_text_present: bool
    secret_text_present: bool
    evidence_id: str
    evidence_review_state: str
    evidence_source_url: str
    secret_bearing: bool
    evidence_digest_match: bool
    blocking_reasons: tuple[str, ...] = ()


class ManagementValidationSummary(Record):
    total: int
    passed: int
    blocked: int
    failed: int


class ManagementValidationReport(Record):
    validation_schema_version: Literal[1] = MANAGEMENT_VALIDATION_SCHEMA_VERSION
    validation_contract_id: Literal[
        "cis-04b-management-cli-validation-v1"
    ] = MANAGEMENT_VALIDATION_CONTRACT_ID
    source: ManagementSource
    expected_source: ManagementExpectedSource
    assignment_id: UUID
    candidates: tuple[ManagementCandidateValidation, ...]
    summary: ManagementValidationSummary
    overall_status: Literal["pass", "partial", "blocked", "fail"]
    integrity: dict[str, bool]
    safety: ManagementSafety
    report_fingerprint: str


def _sha256(value: object) -> str:
    canonical = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _candidate_fingerprint(candidate: ManagementCandidate) -> str:
    payload = candidate.model_dump(mode="json")
    payload.pop("candidate_fingerprint", None)
    return _sha256(payload)


def _document_fingerprint(document: ManagementCandidateDocument) -> str:
    payload = document.model_dump(mode="json")
    payload.pop("render_fingerprint", None)
    return _sha256(payload)


def _report_fingerprint(report: ManagementValidationReport) -> str:
    payload = report.model_dump(mode="json")
    payload.pop("report_fingerprint", None)
    return _sha256(payload)


def _device_ref(intent: ManagementIntent) -> ManagementDeviceRef:
    return ManagementDeviceRef(
        assignment_id=intent.assignment_id,
        hostname=intent.identity.hostname,
        family=intent.identity.family,
        exact_pid=intent.identity.exact_pid,
        software_image=intent.identity.software_image,
        software_license=intent.identity.software_license,
        stack_identity=intent.identity.stack_identity,
    )


def _family(intent: ManagementIntent) -> DeviceFamily | None:
    return {
        "catalyst-9300": DeviceFamily.CATALYST_9300,
        "catalyst-9200": DeviceFamily.CATALYST_9200,
    }.get(intent.identity.family or "")


def _find_evidence(
    intent: ManagementIntent,
    topic: ManagementCommandTopic,
    registry: ManagementEvidenceRegistry,
) -> ManagementEvidenceRow | None:
    family = _family(intent)
    if (family is None or intent.identity.exact_pid is None
        or intent.identity.software_image is None
        or intent.identity.software_license is None):
        return None
    return registry.find(
        family,
        intent.identity.exact_pid,
        intent.identity.software_image,
        intent.identity.software_license,
        topic,
    )


def _command_text(
    intent: ManagementIntent,
    topic: ManagementCommandTopic,
    row: ManagementEvidenceRow,
) -> str | None:
    if row.secret_bearing:
        return None
    if topic is ManagementCommandTopic.DOMAIN_NAME:
        if intent.management_domain is None:
            return None
        return f"ip domain name {intent.management_domain}"
    if topic is ManagementCommandTopic.SSH_VERSION:
        return "ip ssh version 2"
    if topic is ManagementCommandTopic.RSA_KEY:
        return "crypto key generate rsa modulus 4096"
    if topic is ManagementCommandTopic.VTY_TRANSPORT:
        return "transport input ssh"
    if topic is ManagementCommandTopic.LOGIN_LOCAL:
        return "login local"
    if topic is ManagementCommandTopic.AAA_NEW_MODEL:
        return "aaa new-model"
    if topic is ManagementCommandTopic.AAA_LOGIN_LOCAL:
        return "aaa authentication login default local"
    if topic is ManagementCommandTopic.CONSOLE_AUTH:
        return "login authentication CONSOLE"
    return None


def _topic_blockers(
    intent: ManagementIntent, topic: ManagementCommandTopic,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if topic is ManagementCommandTopic.DOMAIN_NAME:
        if intent.management_domain is None:
            reasons.append("management-domain-not-planned")
        return tuple(reasons)
    if topic is ManagementCommandTopic.LOCAL_USERNAME:
        reasons.extend(("credential-secret-not-available", "secret-command-not-renderable"))
    if topic in {
        ManagementCommandTopic.SSH_VERSION,
        ManagementCommandTopic.RSA_KEY,
        ManagementCommandTopic.VTY_TRANSPORT,
        ManagementCommandTopic.LOGIN_LOCAL,
        ManagementCommandTopic.AAA_NEW_MODEL,
        ManagementCommandTopic.AAA_LOGIN_LOCAL,
        ManagementCommandTopic.CONSOLE_AUTH,
    }:
        reasons.extend((
            "management-authentication-not-validated",
            "console-recovery-not-verified",
            "management-lockout-risk",
        ))
    if topic in {
        ManagementCommandTopic.AAA_NEW_MODEL,
        ManagementCommandTopic.AAA_LOGIN_LOCAL,
        ManagementCommandTopic.CONSOLE_AUTH,
    }:
        reasons.append("aaa-or-console-lockout-risk")
    return tuple(dict.fromkeys(reasons))


def _candidate(
    intent: ManagementIntent,
    topic: ManagementCommandTopic,
    row: ManagementEvidenceRow | None,
    registry: ManagementEvidenceRegistry,
) -> ManagementCandidate:
    blockers: list[str] = list(_topic_blockers(intent, topic))
    if row is None:
        blockers.append("management-evidence-missing")
        evidence_id = ""
        review_state = "missing"
        digest = ""
        source_url = ""
        secret_bearing = topic is ManagementCommandTopic.LOCAL_USERNAME
    else:
        evidence_id = row.evidence_id
        review_state = row.review_state.value
        digest = row.content_digest()
        source_url = row.source_url
        secret_bearing = row.secret_bearing
        if not row.renderable:
            blockers.append("management-evidence-not-renderable")
        if not row.well_formed:
            blockers.append("management-evidence-malformed")
    status: Literal["candidate", "blocked", "unsupported"] = (
        "blocked" if blockers else "candidate"
    )
    candidate_text = (
        _command_text(intent, topic, row)
        if status == "candidate" and row is not None else None
    )
    if secret_bearing:
        candidate_text = None
        if status == "candidate":
            status = "blocked"
            blockers.append("secret-command-not-renderable")
    if candidate_text is None and status == "candidate":
        status = "blocked"
        blockers.append("management-command-text-unavailable")
    context_mode = row.configuration_mode if row else (
        "line" if topic in {
            ManagementCommandTopic.VTY_TRANSPORT,
            ManagementCommandTopic.LOGIN_LOCAL,
            ManagementCommandTopic.CONSOLE_AUTH,
        } else "global"
    )
    header = (
        "line vty 0 4"
        if context_mode == "line" and topic is not ManagementCommandTopic.CONSOLE_AUTH
        else "line console 0" if context_mode == "line" else "global"
    )
    candidate = ManagementCandidate(
        candidate_id="mgmtcand-" + _sha256({
            "topic": topic.value,
            "assignment_id": str(intent.assignment_id),
            "evidence_id": evidence_id,
            "revision": str(intent.revision_id),
        })[:16],
        assignment_id=intent.assignment_id,
        topic=topic.value,
        command_context_mode=context_mode,
        command_context_header=header,
        target_name=intent.identity.hostname,
        status=status,
        candidate_text=candidate_text,
        parameters={
            "secret_bearing": secret_bearing,
            "credential_reference_present": intent.authentication.credential_reference.present,
            "credential_secret_available": False,
        },
        evidence_id=evidence_id,
        evidence_review_state=review_state,
        evidence_content_digest=digest,
        evidence_source_url=source_url,
        secret_bearing=secret_bearing,
        blocking_reasons=tuple(dict.fromkeys(blockers)),
        candidate_fingerprint="",
    )
    return candidate.model_copy(update={
        "candidate_fingerprint": _candidate_fingerprint(candidate),
    })


def build_management_cli_candidates(
    revision: PlanRevision,
    intent: ManagementIntent,
    registry: ManagementEvidenceRegistry = MANAGEMENT_EVIDENCE_DRAFT_REGISTRY,
    *,
    test_only_registry: bool = False,
) -> ManagementCandidateDocument:
    if plan_hash(canonical_plan(revision.plan)) != revision.content_hash:
        raise ManagementRenderError("revision-canonical-hash-mismatch")
    if intent.revision_id != revision.id or intent.revision_hash != revision.content_hash:
        raise ManagementRenderError("management-intent-revision-mismatch")
    if intent.assignment_id not in {item.id for item in revision.plan.assignments}:
        raise ManagementRenderError("assignment-not-in-saved-revision")
    if not test_only_registry and registry.renderable_count:
        raise ManagementRenderError("unapproved-management-evidence-registry")
    candidates = tuple(
        _candidate(intent, topic, _find_evidence(intent, topic, registry), registry)
        for topic in ManagementCommandTopic
    )
    source = ManagementSource(
        revision_uuid=revision.id,
        revision_number=revision.number,
        revision_hash=revision.content_hash,
        management_intent_fingerprint=intent.intent_fingerprint,
        evidence_registry_id=registry.registry_id,
        evidence_registry_fingerprint=registry.fingerprint,
    )
    blocked = sum(1 for item in candidates if item.status != "candidate")
    draft = ManagementCandidateDocument(
        source=source,
        assignment_id=intent.assignment_id,
        device=_device_ref(intent),
        candidates=candidates,
        unresolved_prerequisites=tuple(
            dict.fromkeys(
                reason for item in candidates for reason in item.blocking_reasons
            ),
        ),
        deployment_blockers=(
            "management-evidence-pending",
            "management-authentication-not-validated",
            "console-recovery-not-verified",
            "hardware-not-verified",
        ),
        summary=ManagementSummary(
            total=len(candidates),
            candidates=len(candidates) - blocked,
            blocked=blocked,
            skipped=0,
        ),
        render_fingerprint="",
    )
    return draft.model_copy(update={
        "render_fingerprint": _document_fingerprint(draft),
    })


def _validate_candidate(
    candidate: ManagementCandidate,
    row: ManagementEvidenceRow | None,
    *,
    intent: ManagementIntent,
) -> ManagementCandidateValidation:
    reasons: list[str] = []
    secret_text = bool(
        candidate.candidate_text
        and any(token in candidate.candidate_text.casefold() for token in (
            "password", "secret", "private-key", "<redacted>",
        ))
    )
    if secret_text:
        reasons.append("secret-text-present")
    if candidate.secret_bearing and candidate.candidate_text is not None:
        reasons.append("secret-command-carries-text")
    if candidate.status == "blocked" and candidate.candidate_text is not None:
        reasons.append("blocked-candidate-carries-text")
    if candidate.status == "candidate":
        if candidate.candidate_text is None:
            reasons.append("candidate-text-missing")
        if row is None or not row.renderable:
            reasons.append("management-evidence-not-renderable")
        if row is not None and candidate.evidence_content_digest != row.content_digest():
            reasons.append("management-evidence-digest-mismatch")
        expected = (
            _command_text(intent, ManagementCommandTopic(candidate.topic), row)
            if row else None
        )
        if expected is None or candidate.candidate_text != expected:
            reasons.append("management-command-text-mismatch")
        prereq = _topic_blockers(intent, ManagementCommandTopic(candidate.topic))
        if prereq:
            reasons.append("management-preconditions-not-satisfied")
    if row is not None and candidate.evidence_id != row.evidence_id:
        reasons.append("management-evidence-binding-mismatch")
    verdict: Literal["pass", "fail", "blocked", "not-run"]
    if candidate.status == "candidate":
        verdict = "pass" if not reasons else "fail"
    else:
        verdict = "blocked" if not reasons else "fail"
    return ManagementCandidateValidation(
        candidate_id=candidate.candidate_id,
        topic=candidate.topic,
        status=candidate.status,
        independent_verdict=verdict,
        candidate_text_present=candidate.candidate_text is not None,
        secret_text_present=secret_text,
        evidence_id=candidate.evidence_id,
        evidence_review_state=candidate.evidence_review_state,
        evidence_source_url=candidate.evidence_source_url,
        secret_bearing=candidate.secret_bearing,
        evidence_digest_match=bool(
            row is not None
            and candidate.evidence_content_digest == row.content_digest()
        ),
        blocking_reasons=tuple(dict.fromkeys(reasons)),
    )


def validate_management_candidates(
    revision: PlanRevision,
    intent: ManagementIntent,
    document: ManagementCandidateDocument,
    registry: ManagementEvidenceRegistry = MANAGEMENT_EVIDENCE_DRAFT_REGISTRY,
    *,
    test_only_registry: bool = False,
) -> ManagementValidationReport:
    if plan_hash(canonical_plan(revision.plan)) != revision.content_hash:
        raise ManagementRenderError("revision-canonical-hash-mismatch")
    expected = ManagementExpectedSource(
        revision_uuid=revision.id,
        revision_number=revision.number,
        revision_hash=revision.content_hash,
        management_intent_fingerprint=intent.intent_fingerprint,
        evidence_registry_id=registry.registry_id,
        evidence_registry_fingerprint=registry.fingerprint,
        assignment_id=intent.assignment_id,
    )
    source_ok = (
        document.source.revision_uuid == expected.revision_uuid
        and document.source.revision_number == expected.revision_number
        and document.source.revision_hash == expected.revision_hash
        and document.source.management_intent_fingerprint
        == expected.management_intent_fingerprint
        and document.source.evidence_registry_id == expected.evidence_registry_id
        and document.source.evidence_registry_fingerprint
        == expected.evidence_registry_fingerprint
        and document.assignment_id == expected.assignment_id
    )
    ids = [item.candidate_id for item in document.candidates]
    if len(ids) != len(set(ids)):
        raise ManagementRenderError("duplicate-management-candidate-id")
    if document.render_fingerprint != _document_fingerprint(document):
        raise ManagementRenderError("management-render-fingerprint-mismatch")
    if not test_only_registry and registry.renderable_count:
        raise ManagementRenderError("unapproved-management-evidence-registry")
    validations = tuple(
        _validate_candidate(item, _find_evidence(
            intent, ManagementCommandTopic(item.topic), registry,
        ), intent=intent)
        for item in document.candidates
    )
    if not all(
        item.evidence_digest_match or item.status == "blocked"
        for item in validations
    ):
        raise ManagementRenderError("management-evidence-digest-mismatch")
    passed = sum(1 for item in validations if item.independent_verdict == "pass")
    blocked = sum(1 for item in validations if item.independent_verdict == "blocked")
    failed = sum(1 for item in validations if item.independent_verdict == "fail")
    overall: Literal["pass", "partial", "blocked", "fail"]
    if failed:
        overall = "fail"
    elif passed and blocked:
        overall = "partial"
    elif passed:
        overall = "pass"
    else:
        overall = "blocked"
    safety = ManagementSafety()
    report = ManagementValidationReport(
        source=document.source,
        expected_source=expected,
        assignment_id=document.assignment_id,
        candidates=validations,
        summary=ManagementValidationSummary(
            total=len(validations), passed=passed, blocked=blocked, failed=failed,
        ),
        overall_status=overall,
        integrity={
            "revision_hash": True,
            "intent_binding": True,
            "source_binding": source_ok,
            "evidence_registry": True,
            "candidate_ids_unique": len(ids) == len(set(ids)),
            "candidate_fingerprints": all(
                item.candidate_fingerprint
                == _candidate_fingerprint(item) for item in document.candidates
            ),
            "no_secret_text": all(
                not item.secret_text_present for item in validations
            ),
            "safety": safety.executable is False,
        },
        safety=safety,
        report_fingerprint="",
    )
    return report.model_copy(update={
        "report_fingerprint": _report_fingerprint(report),
    })


__all__ = [
    "MANAGEMENT_RENDER_CONTRACT_ID",
    "MANAGEMENT_VALIDATION_CONTRACT_ID",
    "ManagementCandidate",
    "ManagementCandidateDocument",
    "ManagementCandidateValidation",
    "ManagementExpectedSource",
    "ManagementRenderError",
    "ManagementValidationReport",
    "build_management_cli_candidates",
    "validate_management_candidates",
]
