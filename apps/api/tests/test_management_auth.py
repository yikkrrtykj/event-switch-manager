"""CIS-04B management/SSHv2/authentication tests."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from layer3_helpers import make_l3_plan, revision_for
from test_event_plans import API, ORIGIN

from event_switch_manager.app import create_app
from event_switch_manager.domain import DeviceFamily
from event_switch_manager.management_api import MANAGEMENT_SCOPE_HEADER
from event_switch_manager.planning import (
    management_command_evidence_reviews as reviews_module,
)
from event_switch_manager.planning.inventory import EventDeviceAssignment
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.planning.management_cli_candidates import (
    MANAGEMENT_EXPECTED_TOPICS,
    ManagementRenderError,
    _candidate_fingerprint,
    _document_fingerprint,
    build_management_cli_candidates,
    validate_management_candidates,
)
from event_switch_manager.planning.management_command_evidence import (
    MANAGEMENT_EVIDENCE_DRAFT_REGISTRY,
    MANAGEMENT_EVIDENCE_ROWS,
    ManagementCommandTopic,
    ManagementEvidenceRegistry,
)
from event_switch_manager.planning.management_command_evidence_reviews import (
    DOCUMENT_REVIEW_RECORDS,
    R63_REVIEWED_REGISTRY_ID,
    ManagementReviewRecord,
    build_production_reviewed_registry,
)
from event_switch_manager.planning.management_intent import build_management_intent
from event_switch_manager.planning.plan import EventPlan, canonical_plan, plan_hash
from event_switch_manager.settings import Settings


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(
        create_app(Settings(database_path=tmp_path / "management.sqlite3")),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN},
    ) as session:
        yield session


def _event(client: TestClient, name: str = "management") -> str:
    response = client.post(API + "/events", json={"name": name, "management_vlan": 10})
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _plan_with_management(event_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = make_l3_plan(event_id, static_route_count=1)
    core = next(
        item for item in plan["assignments"] if item["hostname"] == "L3-Core"
    )
    core["management_ip"] = "192.168.10.3"
    core["management_domain"] = "example.com"
    core["credential_reference"] = f"credref:{event_id}:netops"
    return plan, core


def _save(client: TestClient, event_id: str, plan: dict[str, Any]) -> dict[str, Any]:
    response = client.post(
        API + f"/events/{event_id}/plan-revisions", json=plan,
    )
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def _intent(
    plan: dict[str, Any], assignment_id: str,
    evidence_registry: ManagementEvidenceRegistry | None = None,
) -> tuple[Any, Any, Any]:
    revision = revision_for(plan)
    l2_intent = build_layer2_intent(revision, None)
    kwargs = (
        {} if evidence_registry is None
        else {"evidence_registry": evidence_registry}
    )
    return revision, l2_intent, build_management_intent(
        revision, l2_intent, UUID(assignment_id), **kwargs,
    )


def _reviewed_registry() -> ManagementEvidenceRegistry:
    return ManagementEvidenceRegistry(
        tuple(
            row.with_review(
                reviewer="TEST-ONLY-MANAGEMENT-REVIEW",
                reviewed_at="2026-11-23",
                findings=("test-only management fixture",),
            )
            for row in MANAGEMENT_EVIDENCE_ROWS
        ),
        registry_id="cis-04b-management-test-only-reviewed-v1",
        production=False,
    )


def test_evidence_matrix_is_pending_and_official() -> None:
    assert len(MANAGEMENT_EVIDENCE_ROWS) == 18
    assert MANAGEMENT_EVIDENCE_DRAFT_REGISTRY.production is False
    assert MANAGEMENT_EVIDENCE_DRAFT_REGISTRY.renderable_count == 0
    assert all(row.review_state.value == "pending-independent-review"
               for row in MANAGEMENT_EVIDENCE_ROWS)
    for family in ("catalyst-9300", "catalyst-9200"):
        rows = [row for row in MANAGEMENT_EVIDENCE_ROWS if row.family.value == family]
        assert len(rows) == 9
        assert {row.topic for row in rows} == set(ManagementCommandTopic)
        assert all(
            row.source_url.startswith("https://www.cisco.com/") for row in rows
        )
        assert all(row.releases == ("17.12.4",) for row in rows)
        assert all(row.licenses for row in rows)
    secret = next(
        row for row in MANAGEMENT_EVIDENCE_ROWS
        if row.topic is ManagementCommandTopic.LOCAL_USERNAME
    )
    assert secret.secret_bearing is True
    assert all(
        row.renderable is False for row in MANAGEMENT_EVIDENCE_ROWS
    )
    c9200 = MANAGEMENT_EVIDENCE_DRAFT_REGISTRY.find(
        DeviceFamily.CATALYST_9200,
        "C9200-24P",
        "17.12.4",
        "Network Advantage",
        ManagementCommandTopic.DOMAIN_NAME,
    )
    assert c9200 is not None
    assert c9200.family is DeviceFamily.CATALYST_9200
    assert c9200.evidence_id.startswith("mgmt-9200-")
    assert "catalyst9200" in c9200.source_url
    assert MANAGEMENT_EVIDENCE_DRAFT_REGISTRY.find(
        DeviceFamily.CATALYST_9200,
        "C9300-24T",
        "17.12.4",
        "Network Advantage",
        ManagementCommandTopic.DOMAIN_NAME,
    ) is None


def test_management_intent_binds_revision_and_reports_blockers() -> None:
    plan, core = _plan_with_management(
        "00000000-0000-0000-0000-000000000099",
    )
    _revision, _l2, intent = _intent(plan, core["id"])
    assert intent.status == "BLOCKED"
    assert intent.intended_status == "PLANNED"
    assert intent.reachability.status == "PLANNED"
    assert intent.reachability.management_ip == "192.168.10.3"
    assert intent.reachability.management_subnet == "192.168.10.0/24"
    assert intent.authentication.credential_reference.present is True
    assert intent.authentication.credential_reference.valid is True
    assert intent.authentication.credential_reference.event_scoped is True
    assert intent.authentication.credential_reference.secret_material_present is False
    assert intent.authentication.credential_reference.secret_availability == "not-verified"
    assert intent.ssh_policy.target_protocol == "sshv2"
    assert intent.ssh_policy.telnet_enabled is False
    assert intent.ssh_policy.plaintext_management_auth is False
    assert intent.ssh_policy.sshv1_fallback_allowed is False
    assert intent.ssh_policy.rsa_key_assumed is False
    assert intent.console_recovery.required is True
    assert intent.console_recovery.console_operation == "not-executed"
    assert intent.console_recovery.console_access_verified is False
    assert intent.evidence_status == "PENDING"
    assert intent.hardware_verified is False
    assert intent.deployment_allowed is False
    assert not hasattr(intent, "password")
    for reason in (
        "credential-secret-not-verified",
        "management-evidence-pending",
        "ssh-rsa-key-state-unknown",
        "console-recovery-not-verified",
        "authentication-lockout-risk",
    ):
        assert reason in intent.reason_codes


def test_management_api_returns_blocked_candidates_without_secret_text(
    client: TestClient,
) -> None:
    event_id = _event(client)
    plan, core = _plan_with_management(event_id)
    revision = _save(client, event_id, plan)
    base = (
        API + f"/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{core['id']}"
    )
    intent_response = client.get(base + "/management-intent")
    assert intent_response.status_code == 200, intent_response.text
    assert intent_response.headers[MANAGEMENT_SCOPE_HEADER] == "full"
    intent = intent_response.json()
    assert intent["status"] == "BLOCKED"
    assert intent["management_vlan"] == 10
    assert intent["evidence_status"] == "PENDING"

    candidates_response = client.get(base + "/management-cli-candidates")
    assert candidates_response.status_code == 200, candidates_response.text
    document = candidates_response.json()
    assert document["summary"] == {
        "total": 9, "candidates": 0, "blocked": 9, "skipped": 0,
    }
    assert all(item["candidate_text"] is None for item in document["candidates"])

    report_response = client.get(base + "/management-cli-validation")
    assert report_response.status_code == 200, report_response.text
    report = report_response.json()
    assert report["summary"] == {
        "total": 9, "passed": 0, "blocked": 9, "failed": 0,
    }
    assert report["overall_status"] == "blocked"
    assert all(item["candidate_text_present"] is False for item in report["candidates"])
    assert all(item["secret_text_present"] is False for item in report["candidates"])
    assert all(
        item["evidence_review_state"] == "pending-independent-review"
        for item in report["candidates"]
    )
    assert all(
        item["evidence_source_url"].startswith("https://www.cisco.com/")
        for item in report["candidates"]
    )
    assert not any(
        key in json_text(candidates_response.json())
        for key in ("password", "private_key", "credential_value")
    )


def json_text(value: object) -> str:
    import json
    return json.dumps(value, ensure_ascii=True)


def test_test_only_reviewed_evidence_exercises_candidate_and_validator() -> None:
    plan, core = _plan_with_management(
        "00000000-0000-0000-0000-000000000099",
    )
    registry = _reviewed_registry()
    revision, _l2, intent = _intent(plan, core["id"], registry)
    document = build_management_cli_candidates(
        revision, intent, registry, test_only_registry=True,
    )
    report = validate_management_candidates(
        revision, intent, document, registry, test_only_registry=True,
    )
    assert any(
        item.topic == "management-domain-name"
        and item.status == "candidate"
        and item.candidate_text == "ip domain name example.com"
        for item in document.candidates
    )
    assert all(
        item.candidate_text is None
        for item in document.candidates
        if item.secret_bearing
    )
    assert report.overall_status == "partial"
    assert report.integrity["source_binding"] is True
    assert report.integrity["candidate_fingerprints"] is True
    assert all(item.secret_text_present is False for item in report.candidates)
    assert all(
        "password" not in (item.candidate_text or "").casefold()
        and "secret" not in (item.candidate_text or "").casefold()
        for item in document.candidates
    )


def test_evidence_digest_mismatch_blocks_candidate() -> None:
    plan, core = _plan_with_management(
        "00000000-0000-0000-0000-000000000099",
    )
    rows = tuple(
        row.with_review(
            reviewer="TEST-ONLY-MANAGEMENT-REVIEW",
            reviewed_at="2026-11-23",
            findings=("test-only management fixture",),
        )
        for row in MANAGEMENT_EVIDENCE_ROWS
    )
    rows = tuple(
        replace(row, review_digest="0" * 64) if index == 0 else row
        for index, row in enumerate(rows)
    )
    registry = ManagementEvidenceRegistry(rows, production=False)
    revision, _l2, intent = _intent(plan, core["id"], registry)
    document = build_management_cli_candidates(
        revision, intent, registry, test_only_registry=True,
    )
    assert all(item.status == "blocked" for item in document.candidates)
    assert all(item.candidate_text is None for item in document.candidates)


def test_missing_invalid_and_cross_event_management_references() -> None:
    cases: list[dict[str, Any]] = [
        {"management_ip": None},
        {"management_ip": "10.255.255.1"},
        {"management_ip": "192.168.10.2"},  # duplicate access management IP
        {"management_domain": None},
        {"credential_reference": None},
        {"credential_reference": "credref:00000000-0000-0000-0000-000000000001:other"},
    ]
    for override in cases:
        plan = make_l3_plan(
            "00000000-0000-0000-0000-000000000099", static_route_count=1,
        )
        core = next(a for a in plan["assignments"] if a["hostname"] == "L3-Core")
        core["management_ip"] = "192.168.10.3"
        core["management_domain"] = "example.com"
        core["credential_reference"] = (
            "credref:00000000-0000-0000-0000-000000000099:netops"
        )
        for field, value in override.items():
            core[field] = value
        _revision, _l2, intent = _intent(plan, core["id"])
        assert intent.status == "BLOCKED"
        assert any(
            reason.startswith((
                "management-ip-", "management-domain-", "credential-reference-",
            ))
            for reason in intent.reason_codes
        )
        if "credential_reference" in override:
            assert intent.authentication.credential_reference.secret_material_present is False


def test_unknown_release_management_candidates_are_all_blocked() -> None:
    plan = make_l3_plan(
        "00000000-0000-0000-0000-000000000099",
        core_image="17.12.5", static_route_count=1,
    )
    core = next(a for a in plan["assignments"] if a["hostname"] == "L3-Core")
    core["management_ip"] = "192.168.10.3"
    core["management_domain"] = "example.com"
    core["credential_reference"] = (
        "credref:00000000-0000-0000-0000-000000000099:netops"
    )
    revision, _l2, intent = _intent(plan, core["id"])
    document = build_management_cli_candidates(revision, intent)
    assert document.summary.candidates == 0
    assert document.summary.blocked == 9
    assert all(item.candidate_text is None for item in document.candidates)
    assert any(
        "management-evidence-missing" in item.blocking_reasons
        for item in document.candidates
    )


def test_plaintext_secret_fields_are_rejected_by_plan_contract() -> None:
    assignment_fields = set(EventDeviceAssignment.model_fields)
    assert "password" not in assignment_fields
    assert "secret" not in assignment_fields
    assert "private_key" not in assignment_fields
    assert "management_domain" in assignment_fields
    assert "credential_reference" in assignment_fields


def test_old_plan_hash_remains_compatible_without_new_optional_fields() -> None:
    plan = EventPlan.model_validate(make_l3_plan(
        "00000000-0000-0000-0000-000000000099", static_route_count=1,
    ))
    original = canonical_plan(plan)
    payload = plan.model_dump(mode="json")
    for assignment in payload["assignments"]:
        assignment.pop("management_domain", None)
        assignment.pop("credential_reference", None)
    old_plan = EventPlan.model_validate(payload)
    assert canonical_plan(old_plan) == original
    changed_assignment = plan.assignments[0].model_copy(update={
        "management_domain": "example.com",
        "credential_reference": (
            "credref:00000000-0000-0000-0000-000000000099:netops"
        ),
    })
    plan = plan.model_copy(update={
        "assignments": (changed_assignment, *plan.assignments[1:]),
    })
    assert plan_hash(canonical_plan(plan)) != plan_hash(original)


def test_management_api_cross_scope_and_undeclared_input_rejected(
    client: TestClient,
) -> None:
    event_id = _event(client)
    plan, core = _plan_with_management(event_id)
    revision = _save(client, event_id, plan)
    base = (
        API + f"/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{core['id']}"
    )
    assert client.get(base + "/management-intent?credential=forged").status_code == 400
    assert client.post(base + "/management-intent", json={}).status_code == 405
    assert client.request("GET", base + "/management-intent", content=b"{}").status_code == 400
    other_event = _event(client, "other management")
    other_plan, _other_core = _plan_with_management(other_event)
    for index, device in enumerate(other_plan["physical_devices"]):
        device["verified_serial"] = f"MGMT-OTHER-{index}"
    other_revision = _save(client, other_event, other_plan)
    assert client.get(
        API + f"/events/{event_id}/plan-revisions/{other_revision['id']}"
        f"/assignments/{core['id']}/management-intent",
    ).status_code == 404
    assert client.get(
        API + f"/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{uuid4()}/management-intent",
    ).status_code == 404


def test_assembly_management_section_is_dynamic_and_blocked(
    client: TestClient,
) -> None:
    event_id = _event(client)
    plan, core = _plan_with_management(event_id)
    revision = _save(client, event_id, plan)
    base = (
        API + f"/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{core['id']}"
    )
    assembly_response = client.get(base + "/config-assembly-preview")
    assert assembly_response.status_code == 200, assembly_response.text
    assembly = assembly_response.json()
    section = next(
        item for item in assembly["sections"]
        if item["section_id"] == "management-auth-ssh"
    )
    assert section["required"] is True
    assert section["applicability"] == "APPLICABLE"
    assert section["status"] == "BLOCKED"
    assert section["reason_codes"]
    assert section["missing_count"] == 1
    assert section["evidence_references"]
    assert assembly["completeness"]["complete"] is False
    assert assembly["full_config_generated"] is False
    assert assembly["deployment_status"] == "blocked"
    l3 = client.get(base + "/l3-cli-validation").json()
    assert l3["summary"]["passed"] == 9
    assert l3["summary"]["blocked"] == 1


def test_management_secret_not_present_in_revision_or_api(
    client: TestClient,
) -> None:
    event_id = _event(client)
    plan, core = _plan_with_management(event_id)
    revision = _save(client, event_id, plan)
    dumped = json_text(revision)
    for forbidden in ("password", "private_key", "credential_value"):
        assert forbidden not in dumped
    assert "credref:" in dumped
    base = (
        API + f"/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{core['id']}"
    )
    for suffix in ("management-intent", "management-cli-validation"):
        response = client.get(base + "/" + suffix)
        assert response.status_code == 200, response.text
        text = json_text(response.json())
        for forbidden in ("password", "private_key", "credential_value"):
            assert forbidden not in text
def _production_document() -> tuple[Any, Any, Any]:
    plan, core = _plan_with_management(
        "00000000-0000-0000-0000-000000000099",
    )
    revision, _l2, intent = _intent(plan, core["id"])
    return revision, intent, build_management_cli_candidates(revision, intent)


def _reseal(document: Any) -> Any:
    candidates = tuple(
        candidate.model_copy(update={
            "candidate_fingerprint": _candidate_fingerprint(candidate),
        })
        for candidate in document.candidates
    )
    resealed = document.model_copy(update={
        "candidates": candidates,
        "render_fingerprint": "",
    })
    return resealed.model_copy(update={
        "render_fingerprint": _document_fingerprint(resealed),
    })


def _reseal_document_only(document: Any) -> Any:
    return document.model_copy(update={
        "render_fingerprint": _document_fingerprint(
            document.model_copy(update={"render_fingerprint": ""}),
        ),
    })


def test_validator_requires_exact_nine_topic_set() -> None:
    revision, intent, document = _production_document()
    report = validate_management_candidates(revision, intent, document)
    assert report.summary.total == 9
    assert report.summary.passed == 0
    assert report.summary.blocked == 9
    assert {item.topic for item in report.candidates} == set(
        MANAGEMENT_EXPECTED_TOPICS,
    )
    assert len(MANAGEMENT_EXPECTED_TOPICS) == 9


@pytest.mark.parametrize("mutation", ["missing-one", "missing-all", "duplicate", "unknown"])
def test_validator_rejects_topic_set_tampering_even_when_resealed(
    mutation: str,
) -> None:
    revision, intent, document = _production_document()
    candidates = list(document.candidates)
    if mutation == "missing-one":
        candidates.pop(0)
    elif mutation == "missing-all":
        candidates = []
    elif mutation == "duplicate":
        candidates[1] = candidates[0].model_copy(update={
            "candidate_fingerprint": "",
        })
    else:
        candidates[0] = candidates[0].model_copy(update={
            "topic": "management-unknown-topic",
            "candidate_fingerprint": "",
        })
    tampered = document.model_copy(update={"candidates": tuple(candidates)})
    with pytest.raises(ManagementRenderError) as error:
        validate_management_candidates(revision, intent, _reseal(tampered))
    assert error.value.reason_code == "management-candidate-topic-set"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("candidate_id", "mgmtcand-forged", "management-candidate-id-mismatch"),
        ("evidence_id", "mgmt-forged-evidence", "management-evidence-id-mismatch"),
        (
            "evidence_content_digest",
            "0" * 64,
            "management-evidence-digest-mismatch",
        ),
        (
            "evidence_review_state",
            "independently-reviewed",
            "management-evidence-review-mismatch",
        ),
        (
            "evidence_source_url",
            "https://example.invalid/forged",
            "management-evidence-source-mismatch",
        ),
    ],
)
def test_validator_rejects_blocked_evidence_binding_tampering(
    field: str, value: str, reason: str,
) -> None:
    revision, intent, document = _production_document()
    blocked = next(
        candidate for candidate in document.candidates
        if candidate.status == "blocked"
    )
    tampered_candidate = blocked.model_copy(update={
        field: value,
        "candidate_fingerprint": "",
    })
    candidates = tuple(
        tampered_candidate if candidate.candidate_id == blocked.candidate_id
        else candidate
        for candidate in document.candidates
    )
    tampered = document.model_copy(update={"candidates": candidates})
    with pytest.raises(ManagementRenderError) as error:
        validate_management_candidates(revision, intent, _reseal(tampered))
    assert error.value.reason_code == reason


def test_validator_rejects_status_forgery_and_resealed_fingerprints() -> None:
    revision, intent, document = _production_document()
    blocked = next(
        candidate for candidate in document.candidates
        if candidate.topic == "management-ssh-version"
    )
    forged = blocked.model_copy(update={
        "status": "candidate",
        "candidate_text": "ip ssh version 2",
        "evidence_review_state": "independently-reviewed",
        "blocking_reasons": (),
        "candidate_fingerprint": "",
    })
    candidates = tuple(
        forged if candidate.candidate_id == blocked.candidate_id else candidate
        for candidate in document.candidates
    )
    tampered = document.model_copy(update={"candidates": candidates})
    with pytest.raises(ManagementRenderError) as error:
        validate_management_candidates(revision, intent, _reseal(tampered))
    assert error.value.reason_code in {
        "management-evidence-review-mismatch",
        "management-candidate-status-mismatch",
    }


def test_validator_rejects_resealed_summary_and_candidate_fingerprint() -> None:
    revision, intent, document = _production_document()
    summary = document.summary.model_copy(update={"blocked": 8, "candidates": 1})
    tampered = document.model_copy(update={"summary": summary})
    with pytest.raises(ManagementRenderError) as error:
        validate_management_candidates(revision, intent, _reseal(tampered))
    assert error.value.reason_code == "management-candidate-summary-mismatch"

    first = document.candidates[0].model_copy(update={"candidate_fingerprint": "0" * 64})
    tampered = document.model_copy(update={
        "candidates": (first, *document.candidates[1:]),
    })
    with pytest.raises(ManagementRenderError) as error:
        validate_management_candidates(
            revision, intent, _reseal_document_only(tampered),
        )
    assert error.value.reason_code == "management-candidate-fingerprint-mismatch"


def test_reviewed_registry_requires_explicit_test_only_isolation() -> None:
    plan, core = _plan_with_management(
        "00000000-0000-0000-0000-000000000099",
    )
    registry = _reviewed_registry()
    revision, _l2, intent = _intent(plan, core["id"], registry)
    with pytest.raises(ManagementRenderError) as error:
        build_management_cli_candidates(revision, intent, registry)
    assert error.value.reason_code == "unapproved-management-evidence-registry"
    document = build_management_cli_candidates(
        revision, intent, registry, test_only_registry=True,
    )
    with pytest.raises(ManagementRenderError) as error:
        validate_management_candidates(revision, intent, document, registry)
    assert error.value.reason_code == "unapproved-management-evidence-registry"
    report = validate_management_candidates(
        revision, intent, document, registry, test_only_registry=True,
    )
    assert report.summary.model_dump() == {
        "total": 9, "passed": 1, "blocked": 8, "failed": 0,
    }
    assert report.overall_status == "partial"
def _temporary_production_manifest() -> tuple[ManagementReviewRecord, ...]:
    return tuple(
        replace(
            record,
            record_id=f"r65-{record.evidence_id}",
            production_authorized=True,
            approval_scope="PRODUCTION_ACTIVATION",
        )
        for record in DOCUMENT_REVIEW_RECORDS
    )


def test_legacy_four_evidence_isolated_fixture_still_validates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reviews_module,
        "PRODUCTION_APPROVED_RECORDS",
        _temporary_production_manifest(),
    )
    plan, core = _plan_with_management("00000000-0000-0000-0000-000000000099")
    registry = build_production_reviewed_registry(test_only=True)
    assert registry.registry_id == R63_REVIEWED_REGISTRY_ID
    assert registry.renderable_count == 4
    revision, _l2, intent = _intent(plan, core["id"], registry)
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
    domain = next(
        item for item in document.candidates
        if item.topic == "management-domain-name"
    )
    assert domain.candidate_text == "ip domain name example.com"
    # The legacy manifest remains isolated and never becomes the production
    # selector or a production review-status authority.
    assert reviews_module.production_management_registry().registry_id == (
        "cis-04b-management-command-evidence-draft-v1"
    )
    assert reviews_module.review_status("mgmt-9300-ssh-version-v1") == (
        "DOCUMENT-SYNTAX-REVIEWED"
    )
