"""Test-only builders for the CIS-03-03B parser/validator tests."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from event_switch_manager.planning.layer3_cli_candidates import (
    Candidate,
    L3CandidateDocument,
)
from event_switch_manager.planning.layer3_cli_validation import (
    ExpectedSource,
    independent_candidate_fingerprint,
    independent_render_fingerprint,
)
from event_switch_manager.planning.layer3_command_evidence import (
    DEFAULT_REGISTRY,
    CommandEvidenceRegistry,
)
from event_switch_manager.planning.layer3_intent import Layer3Intent
from event_switch_manager.planning.plan import PlanRevision


def expected_source(
    revision: PlanRevision,
    intent: Layer3Intent,
    document: L3CandidateDocument,
    registry: CommandEvidenceRegistry = DEFAULT_REGISTRY,
    *,
    assignment_id: UUID | None = None,
) -> ExpectedSource:
    return ExpectedSource(
        event_id=revision.plan.event_id,
        saved_revision_uuid=revision.id,
        revision_number=revision.number,
        revision_canonical_hash=revision.content_hash,
        l3_intent_schema_version=intent.l3_intent_schema_version,
        l3_intent_fingerprint=intent.intent_fingerprint,
        l3_render_contract_id=document.contract_id,
        l3_render_contract_version=document.l3_render_schema_version,
        l3_render_fingerprint=document.l3_render_fingerprint,
        command_evidence_registry_id=registry.registry_id,
        command_evidence_registry_fingerprint=registry.fingerprint,
        assignment_id=assignment_id or document.assignment_id,
        baseline_revision_uuid=intent.baseline.revision_id,
        baseline_revision_hash=intent.baseline.revision_hash,
    )


def with_candidate_fingerprint(candidate: Candidate) -> Candidate:
    return candidate.model_copy(update={
        "candidate_fingerprint": independent_candidate_fingerprint(candidate),
    })


def rebuild_document(
    document: L3CandidateDocument,
    candidates: tuple[Candidate, ...] | None = None,
    *,
    updates: dict[str, Any] | None = None,
) -> L3CandidateDocument:
    values = {"candidates": candidates or document.candidates}
    if updates:
        values.update(updates)
    draft = document.model_copy(update=values)
    return draft.model_copy(update={
        "l3_render_fingerprint": independent_render_fingerprint(draft),
    })


def replace_candidate(
    document: L3CandidateDocument,
    index: int,
    candidate: Candidate,
) -> L3CandidateDocument:
    candidates = list(document.candidates)
    candidates[index] = with_candidate_fingerprint(candidate)
    return rebuild_document(document, tuple(candidates))


def replace_candidate_and_refresh_source(
    revision: PlanRevision,
    intent: Layer3Intent,
    document: L3CandidateDocument,
    index: int,
    candidate: Candidate,
    registry: CommandEvidenceRegistry = DEFAULT_REGISTRY,
) -> tuple[L3CandidateDocument, ExpectedSource]:
    changed = replace_candidate(document, index, candidate)
    return changed, expected_source(revision, intent, changed, registry)
