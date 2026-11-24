"""R65A real backend serialized Management Reviewed fixtures."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from event_switch_manager.planning import (
    management_command_evidence_reviews as reviews_module,
)
from event_switch_manager.planning.management_command_evidence_reviews import (
    DOCUMENT_REVIEW_RECORDS,
    R63_STAGED_DIGESTS,
    ManagementReviewRecord,
    build_production_reviewed_registry,
)

FIXTURE_DIR = (
    Path(__file__).resolve().parents[3]
    / "apps" / "web" / "src" / "planner" / "fixtures"
)
EXPECTED_TOPICS = {
    "management-domain-name",
    "management-ssh-version",
    "management-rsa-key",
    "management-local-username",
    "management-vty-transport",
    "management-login-local",
    "management-aaa-new-model",
    "management-aaa-login-default",
    "management-console-auth",
}


def _production_manifest() -> tuple[ManagementReviewRecord, ...]:
    return tuple(
        replace(
            record,
            record_id=f"fixture-{record.evidence_id}",
            production_authorized=True,
            approval_scope="PRODUCTION_ACTIVATION",
        )
        for record in DOCUMENT_REVIEW_RECORDS
    )


@pytest.mark.parametrize("filename", [
    "management-reviewed-c9300.json",
    "management-reviewed-c9200.json",
])
def test_readiness_fixture_has_real_reviewed_contract(
    filename: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload: dict[str, Any] = json.loads(
        (FIXTURE_DIR / filename).read_text(encoding="utf-8"),
    )
    intent = payload["intent"]
    document = payload["document"]
    report = payload["report"]
    contract = payload["contract"]
    binding = payload["binding"]

    assert report["summary"] == {
        "total": 9, "passed": 1, "blocked": 8, "failed": 0,
    }
    assert document["summary"] == {
        "total": 9, "candidates": 1, "blocked": 8, "skipped": 0,
    }
    assert report["overall_status"] == "partial"
    assert intent["evidence_status"] == "PARTIAL"
    assert contract["evidenceStatus"] == "PARTIAL"
    assert contract["reviewedTopics"] == [
        "management-domain-name", "management-ssh-version",
    ]
    assert {item["topic"] for item in report["candidates"]} == EXPECTED_TOPICS
    domain = next(
        item for item in report["candidates"]
        if item["topic"] == "management-domain-name"
    )
    ssh = next(
        item for item in report["candidates"]
        if item["topic"] == "management-ssh-version"
    )
    assert domain["evidence_review_state"] == "independently-reviewed"
    assert domain["status"] == "candidate"
    assert domain["independent_verdict"] == "pass"
    assert ssh["evidence_review_state"] == "independently-reviewed"
    assert ssh["status"] == "blocked"
    assert ssh["independent_verdict"] == "blocked"
    assert all(
        item["evidence_review_state"] == "pending-independent-review"
        for item in report["candidates"]
        if item["topic"] not in {
            "management-domain-name", "management-ssh-version",
        }
    )
    assert all(
        item["candidate_text_present"] is False
        for item in report["candidates"]
        if item["topic"] != "management-domain-name"
    )

    domain_doc = next(
        item for item in document["candidates"]
        if item["topic"] == "management-domain-name"
    )
    ssh_doc = next(
        item for item in document["candidates"]
        if item["topic"] == "management-ssh-version"
    )
    assignment_id = binding["assignment"]["assignmentId"]
    assignment = next(
        item for item in binding["revision"]["plan"]["assignments"]
        if item["id"] == assignment_id
    )
    assert domain_doc["candidate_text"] == (
        "ip domain name " + assignment["management_domain"]
    )
    assert domain_doc["evidence_content_digest"] == R63_STAGED_DIGESTS[
        "mgmt-9300-domain-name-v1"
    ] or domain_doc["evidence_content_digest"] == R63_STAGED_DIGESTS[
        "mgmt-9200-domain-name-v1"
    ]
    assert ssh_doc["candidate_text"] is None
    assert ssh_doc["evidence_content_digest"] == R63_STAGED_DIGESTS[
        "mgmt-9300-ssh-version-v1"
    ] or ssh_doc["evidence_content_digest"] == R63_STAGED_DIGESTS[
        "mgmt-9200-ssh-version-v1"
    ]
    assert intent["management_domain"] == assignment["management_domain"]

    monkeypatch.setattr(
        reviews_module,
        "PRODUCTION_APPROVED_RECORDS",
        _production_manifest(),
    )
    registry = build_production_reviewed_registry(test_only=True)
    assert contract["id"] == registry.registry_id
    assert contract["fingerprint"] == registry.fingerprint
    assert "password" not in json.dumps(payload).casefold()
    assert "private_key" not in json.dumps(payload).casefold()
    assert "credential_value" not in json.dumps(payload).casefold()
