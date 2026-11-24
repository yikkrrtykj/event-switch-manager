"""R68 Domain-only read-only authorization foundation tests."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from layer3_helpers import make_l3_plan, revision_for
from test_event_plans import API, ORIGIN

from event_switch_manager.app import create_app
from event_switch_manager.planning import (
    management_command_evidence_reviews as reviews,
)
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.planning.management_cli_candidates import (
    ManagementRenderError,
    build_management_cli_candidates,
    validate_management_candidates,
)
from event_switch_manager.planning.management_command_evidence import (
    C9200_MANAGEMENT_HARDWARE_PIDS,
    C9200_MANAGEMENT_ORDERING_SKUS,
    C9200_MANAGEMENT_PIDS,
    C9300_MANAGEMENT_HARDWARE_PIDS,
    C9300_MANAGEMENT_ORDERING_SKUS,
    C9300_MANAGEMENT_PIDS,
    MANAGEMENT_EVIDENCE_DRAFT_REGISTRY,
)
from event_switch_manager.planning.management_command_evidence_reviews import (
    DOCUMENT_REVIEW_RECORDS,
    DOMAIN_ONLY_APPROVAL_RECORD_IDS,
    DOMAIN_ONLY_APPROVAL_SCOPE,
    DOMAIN_ONLY_EVIDENCE_IDS,
    DOMAIN_ONLY_EXPECTED_PIDS,
    DOMAIN_ONLY_ISOLATED_FINGERPRINT,
    DOMAIN_ONLY_ISOLATED_REGISTRY_ID,
    DOMAIN_ONLY_LICENSE_SCOPE,
    DOMAIN_ONLY_PRODUCTION_REGISTRY_ID,
    DOMAIN_ONLY_REQUIRED_LICENSE_LEVEL,
    DOMAIN_ONLY_TEST_DATE,
    DOMAIN_ONLY_TEST_FINDINGS,
    DOMAIN_ONLY_TEST_REVIEWER,
    R63_CORRECTED_ROWS,
    R63_STAGED_DIGESTS,
    DomainApprovalProvenance,
    DomainReadonlyApprovalRecord,
    production_management_registry,
    review_status,
)
from event_switch_manager.planning.management_command_evidence_reviews import (
    test_only_domain_only_registry as make_isolated_domain_registry,
)
from event_switch_manager.planning.management_command_evidence_reviews import (
    test_only_reviewed_registry as make_legacy_reviewed_registry,
)
from event_switch_manager.planning.management_domain_scope import (
    C9200_DOMAIN_DNS_SUPPLEMENT,
    C9300_DOMAIN_DNS_SUPPLEMENT,
    DOMAIN_DNS_SUPPLEMENTS,
    ManagementLicenseEvidenceLevel,
    ManagementPidKind,
    is_ordering_sku,
    management_license_evidence,
    resolve_management_pid,
)
from event_switch_manager.planning.management_intent import (
    build_management_intent,
    management_intent_fingerprint,
)
from event_switch_manager.settings import Settings

FIXTURE_DIR = (
    Path(__file__).resolve().parents[3]
    / "apps" / "web" / "src" / "planner" / "fixtures"
)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(
        create_app(Settings(database_path=tmp_path / "r68.sqlite3")),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN},
    ) as session:
        yield session


def _event(client: TestClient) -> str:
    response = client.post(
        API + "/events", json={"name": "R68 domain-only", "management_vlan": 10},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _plan(
    event_id: str, *, core_pid: str = "C9300L-24P-4X",
) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = make_l3_plan(event_id, core_pid=core_pid, static_route_count=1)
    core = next(item for item in plan["assignments"] if item["hostname"] == "L3-Core")
    core["management_ip"] = "192.168.10.3"
    core["management_domain"] = "example.com"
    core["credential_reference"] = f"credref:{event_id}:netops"
    return plan, core


def _save(client: TestClient, event_id: str, plan: dict[str, Any]) -> dict[str, Any]:
    response = client.post(API + f"/events/{event_id}/plan-revisions", json=plan)
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def _approval_records() -> tuple[DomainReadonlyApprovalRecord, ...]:
    records: list[DomainReadonlyApprovalRecord] = []
    for index, evidence_id in enumerate(DOMAIN_ONLY_EVIDENCE_IDS):
        row = next(
            item for item in R63_CORRECTED_ROWS
            if item.evidence_id == evidence_id
        )
        records.append(DomainReadonlyApprovalRecord(
            record_id=DOMAIN_ONLY_APPROVAL_RECORD_IDS[index],
            evidence_id=evidence_id,
            content_digest=R63_STAGED_DIGESTS[evidence_id],
            family=row.family,
            release="17.12.4",
            exact_device_pids=DOMAIN_ONLY_EXPECTED_PIDS[row.family],
            declared_license_scope=DOMAIN_ONLY_LICENSE_SCOPE,
            license_evidence_level=DOMAIN_ONLY_REQUIRED_LICENSE_LEVEL,
            reviewer=DOMAIN_ONLY_TEST_REVIEWER,
            reviewed_at=DOMAIN_ONLY_TEST_DATE,
            review_scope=reviews.DOMAIN_ONLY_REVIEW_SCOPE,
            findings=DOMAIN_ONLY_TEST_FINDINGS,
            evidence_source_url=row.source_url,
            supplemental_evidence_digest=DOMAIN_DNS_SUPPLEMENTS[
                row.family
            ].content_digest(),
            approval_source_url=(
                "https://github.com/yikkrrtykj/event-switch-manager/"
                "issues/4#issuecomment-r68-test-only"
            ),
            approval_scope=DOMAIN_ONLY_APPROVAL_SCOPE,
            production_authorized=True,
        ).with_payload_digest())
    return tuple(records)


def _install_valid_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    records = _approval_records()
    monkeypatch.setattr(reviews, "DOMAIN_APPROVED_RECORDS", records)
    monkeypatch.setattr(
        reviews,
        "DOMAIN_ONLY_APPROVAL_PROVENANCE",
        {
            record.record_id: DomainApprovalProvenance(
                reviewer=record.reviewer,
                reviewed_at=record.reviewed_at,
                approval_source_url=record.approval_source_url,
                findings=record.findings,
            )
            for record in records
        },
    )


def _assert_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    records: tuple[DomainReadonlyApprovalRecord, ...],
) -> None:
    monkeypatch.setattr(reviews, "DOMAIN_APPROVED_RECORDS", records)
    assert production_management_registry().registry_id == (
        MANAGEMENT_EVIDENCE_DRAFT_REGISTRY.registry_id
    )
    assert production_management_registry().renderable_count == 0
    assert review_status("mgmt-9300-domain-name-v1") == (
        "DOCUMENT-SYNTAX-REVIEWED"
    )


def test_isolated_domain_only_registry_has_two_domain_reviews_only() -> None:
    registry = make_isolated_domain_registry()
    assert registry.registry_id == DOMAIN_ONLY_ISOLATED_REGISTRY_ID
    assert registry.fingerprint == DOMAIN_ONLY_ISOLATED_FINGERPRINT
    assert registry.renderable_count == 2
    assert len(registry.rows) == 18
    reviewed = {row.evidence_id for row in registry.rows if row.renderable}
    assert reviewed == set(DOMAIN_ONLY_EVIDENCE_IDS)
    ssh = next(
        row for row in registry.rows
        if row.evidence_id == "mgmt-9300-ssh-version-v1"
    )
    assert not ssh.renderable
    assert ssh.review_state.value == "pending-independent-review"


def test_domain_only_isolated_path_is_one_pass_eight_blocked() -> None:
    event_id = "00000000-0000-0000-0000-000000000099"
    plan, core = _plan(event_id)
    revision = revision_for(plan)
    l2_intent = build_layer2_intent(revision, None)
    registry = make_isolated_domain_registry()
    intent = build_management_intent(
        revision, l2_intent, UUID(core["id"]), evidence_registry=registry,
    )
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
    assert ssh.evidence_review_state == "pending-independent-review"
    assert "management-evidence-not-renderable" in ssh.blocking_reasons


def test_empty_or_partial_domain_manifest_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = _approval_records()
    _assert_fails_closed(monkeypatch, ())
    _assert_fails_closed(monkeypatch, records[:1])
    _assert_fails_closed(monkeypatch, records + (replace(
        records[0],
        record_id="r68-domain-readonly-extra",
        evidence_id="mgmt-9300-ssh-version-v1",
    ).with_payload_digest(),))


def test_duplicate_unknown_and_forged_domain_manifest_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = _approval_records()
    _assert_fails_closed(
        monkeypatch,
        (records[0], replace(records[0], evidence_id=records[1].evidence_id)),
    )
    _assert_fails_closed(
        monkeypatch,
        (records[0], replace(records[1], record_id=records[0].record_id)),
    )
    _assert_fails_closed(
        monkeypatch,
        (records[0], replace(
            records[1],
            record_id="r68-domain-readonly-unknown",
        ).with_payload_digest()),
    )
    _assert_fails_closed(
        monkeypatch,
        (records[0], replace(
            records[1],
            evidence_id="mgmt-9200-ssh-version-v1",
        ).with_payload_digest()),
    )


def test_scope_and_approval_provenance_are_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = _approval_records()
    for scope in ("PRODUCTION_ACTIVATION", "EXECUTE", "DEPLOY"):
        invalid = (
            records[0],
            replace(records[1], approval_scope=scope).with_payload_digest(),
        )
        _assert_fails_closed(monkeypatch, invalid)

    forged = (
        replace(records[1], reviewer="forged-reviewer").with_payload_digest(),
        replace(records[1], reviewed_at="2099-01-01").with_payload_digest(),
        replace(
            records[1],
            approval_source_url=(
                "https://github.com/yikkrrtykj/event-switch-manager/"
                "issues/4#issuecomment-forged"
            ),
        ).with_payload_digest(),
        replace(records[1], findings=("forged finding",)).with_payload_digest(),
    )
    for invalid_record in forged:
        _assert_fails_closed(monkeypatch, (records[0], invalid_record))

    # Self-consistent records without the server-fixed provenance fail closed.
    monkeypatch.setattr(reviews, "DOMAIN_APPROVED_RECORDS", records)
    monkeypatch.setattr(reviews, "DOMAIN_ONLY_APPROVAL_PROVENANCE", {})
    assert production_management_registry().registry_id == (
        MANAGEMENT_EVIDENCE_DRAFT_REGISTRY.registry_id
    )
    assert review_status("mgmt-9300-domain-name-v1") == (
        "DOCUMENT-SYNTAX-REVIEWED"
    )


def test_exact_pid_license_and_supplemental_binding_are_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = _approval_records()
    invalid_variants = (
        replace(records[1], exact_device_pids=(
            "C9200L-24P-4X-A",
        )).with_payload_digest(),
        replace(records[1], license_evidence_level=(
            ManagementLicenseEvidenceLevel.DEVICE_VERIFIED.value
        )).with_payload_digest(),
        replace(records[1], declared_license_scope=(
            "Network Essentials",
        )).with_payload_digest(),
        replace(records[1], supplemental_evidence_digest="0" * 64
                ).with_payload_digest(),
        replace(records[1], approval_payload_digest="0" * 64),
    )
    for invalid in invalid_variants:
        _assert_fails_closed(monkeypatch, (records[0], invalid))


def test_valid_domain_manifest_selects_domain_only_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_valid_approval(monkeypatch)
    registry = production_management_registry()
    assert registry.registry_id == DOMAIN_ONLY_PRODUCTION_REGISTRY_ID
    assert registry.renderable_count == 2
    assert review_status("mgmt-9300-domain-name-v1") == "REVIEWED"
    assert review_status("mgmt-9200-domain-name-v1") == "REVIEWED"
    assert review_status("mgmt-9300-ssh-version-v1") == (
        "DOCUMENT-SYNTAX-REVIEWED"
    )
    assert review_status("mgmt-9200-ssh-version-v1") == (
        "DOCUMENT-SYNTAX-REVIEWED"
    )
    assert make_isolated_domain_registry().registry_id != registry.registry_id
    assert make_isolated_domain_registry().fingerprint != registry.fingerprint

    # The Domain-only contract takes precedence over the legacy four-Evidence
    # fixture and never inherits SSH review authorization.
    monkeypatch.setattr(
        reviews, "PRODUCTION_APPROVED_RECORDS", DOCUMENT_REVIEW_RECORDS,
    )
    assert production_management_registry().registry_id == (
        DOMAIN_ONLY_PRODUCTION_REGISTRY_ID
    )
    assert review_status("mgmt-9300-ssh-version-v1") == (
        "DOCUMENT-SYNTAX-REVIEWED"
    )


def test_test_only_domain_registry_is_not_selected_by_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reviews, "DOMAIN_APPROVED_RECORDS", ())
    plan, core = _plan("00000000-0000-0000-0000-000000000099")
    revision = revision_for(plan)
    l2_intent = build_layer2_intent(revision, None)
    registry = make_isolated_domain_registry()
    intent = build_management_intent(
        revision, l2_intent, UUID(core["id"]), evidence_registry=registry,
    )
    with pytest.raises(ManagementRenderError) as error:
        build_management_cli_candidates(revision, intent, registry)
    assert error.value.reason_code == "unapproved-management-evidence-registry"


def test_ordering_sku_is_not_an_exact_device_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_valid_approval(monkeypatch)
    plan, core = _plan(
        "00000000-0000-0000-0000-000000000099",
        core_pid="C9300L-24T-4G-E",
    )
    revision = revision_for(plan)
    l2_intent = build_layer2_intent(revision, None)
    registry = production_management_registry()
    intent = build_management_intent(
        revision, l2_intent, UUID(core["id"]), evidence_registry=registry,
    )
    document = build_management_cli_candidates(revision, intent, registry)
    domain = next(
        item for item in document.candidates
        if item.topic == "management-domain-name"
    )
    assert domain.status == "blocked"
    assert domain.candidate_text is None
    assert "management-ordering-sku-not-exact-device-pid" in (
        domain.blocking_reasons
    )
    assert domain.evidence_id == "mgmt-9300-domain-name-v1"
    assert document.summary.candidates == 0


def test_unknown_release_or_license_does_not_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_valid_approval(monkeypatch)
    plan, core = _plan("00000000-0000-0000-0000-000000000099")
    revision = revision_for(plan)
    l2_intent = build_layer2_intent(revision, None)
    registry = production_management_registry()
    intent = build_management_intent(
        revision, l2_intent, UUID(core["id"]), evidence_registry=registry,
    )
    for field, value in (
        ("software_image", "17.12.3"),
        ("software_license", "LAN Base"),
        ("software_license", "Unknown"),
    ):
        changed = intent.model_copy(update={
            "identity": intent.identity.model_copy(update={field: value}),
        })
        changed = changed.model_copy(update={
            "intent_fingerprint": management_intent_fingerprint(changed),
        })
        document = build_management_cli_candidates(
            revision, changed, registry,
        )
        domain = next(
            item for item in document.candidates
            if item.topic == "management-domain-name"
        )
        assert domain.status == "blocked"
        assert domain.candidate_text is None
        report = validate_management_candidates(
            revision, changed, document, registry,
        )
        assert report.summary.passed == 0


def test_pid_sku_and_license_evidence_levels() -> None:
    assert set(C9300_MANAGEMENT_HARDWARE_PIDS) & set(
        C9300_MANAGEMENT_ORDERING_SKUS,
    ) == set()
    assert set(C9300_MANAGEMENT_HARDWARE_PIDS) | set(
        C9300_MANAGEMENT_ORDERING_SKUS,
    ) == set(C9300_MANAGEMENT_PIDS)
    assert C9200_MANAGEMENT_HARDWARE_PIDS + C9200_MANAGEMENT_ORDERING_SKUS == (
        C9200_MANAGEMENT_PIDS
    )
    exact = resolve_management_pid("C9300L-24P-4X")
    ordering = resolve_management_pid("C9300L-24P-4X-E")
    assert exact is not None and exact.kind is ManagementPidKind.HARDWARE_MODEL
    assert exact.is_exact_device_pid is True
    assert ordering is not None and ordering.kind is ManagementPidKind.ORDERING_SKU
    assert ordering.is_exact_device_pid is False
    assert ordering.hardware_model == "C9300L-24P-4X"
    assert ordering.default_license == "Network Essentials"
    assert is_ordering_sku("C9300L-24P-4X-E")
    assert is_ordering_sku("C9300L-24P-4X") is False

    documented = management_license_evidence(
        "C9300L-24P-4X-E", "Network Essentials",
    )
    assert documented.ordering_default_license == "Network Essentials"
    assert documented.feature_compatibility is (
        ManagementLicenseEvidenceLevel.DOCUMENTED_COMPATIBILITY
    )
    assert documented.active_license_evidence is (
        ManagementLicenseEvidenceLevel.DECLARED_NOT_DEVICE_VERIFIED
    )
    assert documented.active_license_verified is False
    assert documented.source_url.startswith("https://www.cisco.com/")
    assert management_license_evidence(
        "C9300L-24P-4X-E", "LAN Base",
    ).active_license_evidence is ManagementLicenseEvidenceLevel.UNSUPPORTED
    assert management_license_evidence(
        "C9300L-24P-4X-E", None,
    ).active_license_evidence is ManagementLicenseEvidenceLevel.UNKNOWN
    verified = management_license_evidence(
        "C9300L-24P-4X-E",
        "Network Essentials",
        device_verified_license="Network Essentials",
    )
    assert verified.active_license_evidence is (
        ManagementLicenseEvidenceLevel.DEVICE_VERIFIED
    )
    assert verified.active_license_verified is True


def test_supplemental_dns_evidence_and_frozen_digests() -> None:
    assert C9300_DOMAIN_DNS_SUPPLEMENT.source_url.endswith(
        "b_1712_sys_mgmt_9300_cg/administering_the_device.html"
    )
    assert C9200_DOMAIN_DNS_SUPPLEMENT.source_url.endswith(
        "b_1712_sys_mgmt_9200_cg/administering_the_device.html"
    )
    for supplement in (C9300_DOMAIN_DNS_SUPPLEMENT, C9200_DOMAIN_DNS_SUPPLEMENT):
        assert supplement.source_section == "Setting Up DNS"
        assert supplement.command == "ip domain name name"
        assert supplement.configuration_mode == "global configuration"
        assert "Do not include the initial period" in supplement.leading_dot_rule
        assert supplement.default_domain_setting.startswith(
            "DNS default domain name: none configured"
        )
        assert any("maximum" in item for item in supplement.limitations)
        assert any("conservative" in item for item in supplement.limitations)
        assert len(supplement.content_digest()) == 64
    assert R63_STAGED_DIGESTS == {
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
    assert len(DOCUMENT_REVIEW_RECORDS) == 4
    legacy = make_legacy_reviewed_registry()
    assert legacy.renderable_count == 4
    assert DOMAIN_ONLY_ISOLATED_REGISTRY_ID != legacy.registry_id


def test_production_api_without_domain_approval_remains_zero_nine(
    client: TestClient,
) -> None:
    event_id = _event(client)
    plan, core = _plan(event_id)
    revision = _save(client, event_id, plan)
    base = (
        API + f"/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{core['id']}"
    )
    intent = client.get(base + "/management-intent")
    document = client.get(base + "/management-cli-candidates")
    report = client.get(base + "/management-cli-validation")
    assembly = client.get(base + "/config-assembly-preview")
    l3 = client.get(base + "/l3-cli-validation")
    assert intent.status_code == document.status_code == report.status_code == 200
    assert intent.json()["evidence_registry_id"] == (
        MANAGEMENT_EVIDENCE_DRAFT_REGISTRY.registry_id
    )
    assert intent.json()["evidence_status"] == "PENDING"
    assert document.json()["summary"] == {
        "total": 9, "candidates": 0, "blocked": 9, "skipped": 0,
    }
    assert report.json()["summary"] == {
        "total": 9, "passed": 0, "blocked": 9, "failed": 0,
    }
    assert all(
        item["candidate_text"] is None
        for item in document.json()["candidates"]
    )
    assert assembly.status_code == 200
    chapter = next(
        section for section in assembly.json()["sections"]
        if section["section_id"] == "management-auth-ssh"
    )
    assert chapter["required"] is True
    assert chapter["status"] == "BLOCKED"
    assert len(assembly.json()["sections"]) == 12
    assert len(assembly.json()["cross_layer_checks"]) == 11
    assert l3.status_code == 200
    assert l3.json()["summary"]["passed"] == 9
    assert l3.json()["summary"]["blocked"] == 1


def test_production_api_with_domain_approval_is_one_pass_eight_blocked(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_valid_approval(monkeypatch)
    event_id = _event(client)
    plan, core = _plan(event_id)
    revision = _save(client, event_id, plan)
    base = (
        API + f"/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{core['id']}"
    )
    intent = client.get(base + "/management-intent")
    document = client.get(base + "/management-cli-candidates")
    report = client.get(base + "/management-cli-validation")
    assert intent.status_code == document.status_code == report.status_code == 200
    assert intent.json()["evidence_registry_id"] == (
        DOMAIN_ONLY_PRODUCTION_REGISTRY_ID
    )
    assert intent.json()["evidence_status"] == "PARTIAL"
    assert document.json()["summary"] == {
        "total": 9, "candidates": 1, "blocked": 8, "skipped": 0,
    }
    assert report.json()["summary"] == {
        "total": 9, "passed": 1, "blocked": 8, "failed": 0,
    }
    assert report.json()["overall_status"] == "partial"
    domain = next(
        item for item in document.json()["candidates"]
        if item["topic"] == "management-domain-name"
    )
    ssh = next(
        item for item in report.json()["candidates"]
        if item["topic"] == "management-ssh-version"
    )
    assert domain["candidate_text"] == "ip domain name example.com"
    assert ssh["status"] == "blocked"
    assert ssh["evidence_review_state"] == "pending-independent-review"
    assert ssh["candidate_text_present"] is False
    assembly = client.get(base + "/config-assembly-preview")
    assert assembly.status_code == 200
    chapter = next(
        section for section in assembly.json()["sections"]
        if section["section_id"] == "management-auth-ssh"
    )
    assert chapter["status"] == "BLOCKED"
@pytest.mark.parametrize("filename", [
    "management-domain-only-c9300.json",
    "management-domain-only-c9200.json",
])
def test_frontend_domain_only_fixtures_match_backend_contract(
    filename: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.loads((FIXTURE_DIR / filename).read_text(encoding="utf-8"))
    _install_valid_approval(monkeypatch)
    registry = production_management_registry()
    contract = payload["contract"]
    assert contract["id"] == registry.registry_id
    assert contract["fingerprint"] == registry.fingerprint
    assert contract["reviewedTopics"] == ["management-domain-name"]
    assert contract["passed"] == 1
    assert contract["blocked"] == 8
    assert contract["overall"] == "partial"
    assert payload["report"]["summary"] == {
        "total": 9, "passed": 1, "blocked": 8, "failed": 0,
    }
    assert payload["document"]["summary"] == {
        "total": 9, "candidates": 1, "blocked": 8, "skipped": 0,
    }
    report_ssh = next(
        item for item in payload["report"]["candidates"]
        if item["topic"] == "management-ssh-version"
    )
    assert report_ssh["evidence_review_state"] == "pending-independent-review"
    assert report_ssh["status"] == "blocked"
    assert report_ssh["candidate_text_present"] is False
    assert sum(
        1 for item in payload["report"]["candidates"]
        if item["evidence_review_state"] == "independently-reviewed"
    ) == 1
    domain = next(
        item for item in payload["document"]["candidates"]
        if item["topic"] == "management-domain-name"
    )
    ssh = next(
        item for item in payload["document"]["candidates"]
        if item["topic"] == "management-ssh-version"
    )
    assert domain["candidate_text"] == "ip domain name example.com"
    assert ssh["candidate_text"] is None
    assignment_id = payload["binding"]["assignment"]["assignmentId"]
    assignment = next(
        item for item in payload["binding"]["revision"]["plan"]["assignments"]
        if item["id"] == assignment_id
    )
    assert payload["intent"]["management_domain"] == assignment["management_domain"]
