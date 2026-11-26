"""R71 Cisco read-only review bundle tests."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from layer3_helpers import make_l3_plan
from test_config_assembly import c9200_candidate_plan
from test_event_plans import API, ORIGIN

from event_switch_manager.app import create_app
from event_switch_manager.planning.cisco_review_bundle import (
    REVIEW_BUNDLE_BANNER,
    REVIEW_BUNDLE_CONTRACT_ID,
    ReviewBundleContent,
    ReviewBundleError,
    build_cisco_review_bundle,
    review_bundle_content_digest,
)
from event_switch_manager.planning.config_assembly import ConfigurationAssembly
from event_switch_manager.planning.layer2_cli_candidates import (
    L2CliCandidateDocument,
)
from event_switch_manager.planning.layer2_cli_validation import (
    ValidationReport as L2ValidationReport,
)
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.planning.layer3_cli_candidates import (
    L3CandidateDocument,
)
from event_switch_manager.planning.layer3_cli_validation import L3ValidationReport
from event_switch_manager.planning.management_cli_candidates import (
    ManagementCandidateDocument,
    ManagementValidationReport,
    build_management_cli_candidates,
    validate_management_candidates,
)
from event_switch_manager.planning.management_command_evidence_reviews import (
    test_only_domain_only_registry as make_isolated_management_registry,
)
from event_switch_manager.planning.management_intent import (
    build_management_intent,
)
from event_switch_manager.planning.plan import PlanRevision
from event_switch_manager.settings import Settings


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(
        create_app(Settings(database_path=tmp_path / "review-bundle.sqlite3")),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN},
    ) as session:
        yield session


def _event(client: TestClient, name: str = "R71 Review") -> str:
    response = client.post(
        API + "/events", json={"name": name, "management_vlan": 10},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _plan(event_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = make_l3_plan(event_id, static_route_count=1)
    core = next(item for item in plan["assignments"] if item["hostname"] == "L3-Core")
    core["management_ip"] = "192.168.10.3"
    core["management_domain"] = "example.com"
    core["credential_reference"] = f"credref:{event_id}:netops"
    return plan, core


def _c9200_plan(event_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = c9200_candidate_plan(event_id)
    core = next(item for item in plan["assignments"] if item["hostname"] == "L3-Core")
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


def _base(event_id: str, revision_id: str, assignment_id: str) -> str:
    return (
        API + f"/events/{event_id}/plan-revisions/{revision_id}"
        f"/assignments/{assignment_id}"
    )


def _bundle(client: TestClient, event_id: str, revision_id: str,
            assignment_id: str) -> tuple[Any, dict[str, Any]]:
    response = client.get(_base(event_id, revision_id, assignment_id)
                          + "/cisco-review-bundle")
    return response, response.json() if response.status_code == 200 else {}


def _assert_no_deployable_artifact(payload: dict[str, Any]) -> None:
    text = repr(payload).casefold()
    assert ".cfg" not in text

    def all_null(value: object, keys: set[str]) -> bool:
        if isinstance(value, dict):
            return all(
                (item is None if key in keys else all_null(item, keys))
                for key, item in value.items()
            )
        if isinstance(value, list):
            return all(all_null(item, keys) for item in value)
        return True

    assert all_null(payload, {"deployment_artifact", "cli"})
    safety = payload["content"]["safety"]
    assert safety["read_only"] is True
    assert safety["non_executable"] is True
    assert safety["full_config_generated"] is False
    assert safety["executable"] is False
    assert safety["deployment_allowed"] is False
    assert safety["hardware_verified"] is False
    assert safety["device_connection"] == "none"
    assert safety["device_writes_enabled"] is False
    assert safety["production_authorization"] == "PENDING"


def test_c9300_review_bundle_is_bound_and_redacted(
    client: TestClient,
) -> None:
    event_id = _event(client)
    plan, core = _plan(event_id)
    revision = _save(client, event_id, plan)
    response, body = _bundle(client, event_id, revision["id"], core["id"])
    assert response.status_code == 200, response.text
    assert response.headers["x-cisco-review-bundle-scope"] == "read-only"
    assert response.headers["x-cisco-review-bundle-content-digest"] == (
        body["content_digest"]
    )
    assert "attachment" in response.headers["content-disposition"]
    assert body["suggested_filename"].endswith(".json")
    assert ".cfg" not in body["suggested_filename"]
    assert body["bundle_schema_version"] == 1
    assert body["contract_id"] == REVIEW_BUNDLE_CONTRACT_ID
    assert body["content"]["banner"] == list(REVIEW_BUNDLE_BANNER)
    identity = body["content"]["identity"]
    assert identity["event_id"] == event_id
    assert identity["revision_id"] == revision["id"]
    assert identity["revision_canonical_hash"] == revision["content_hash"]
    assert identity["assignment_id"] == core["id"]
    assert identity["family"] == "catalyst-9300"
    assert identity["exact_pid"] == "C9300L-24P-4X"
    assert identity["software_image"] == "17.12.4"
    assert identity["software_license"] == "Network Advantage"
    assert body["content"]["l2"]["summary"]["total_candidates"] == 16
    assert body["content"]["l3"]["summary"]["passed"] == 9
    assert body["content"]["l3"]["summary"]["blocked"] == 1
    assert body["content"]["management"]["summary"] == {
        "total": 9, "passed": 0, "blocked": 9, "failed": 0,
    }
    assert body["content"]["management"]["production_authorization"] == "PENDING"
    assert len(body["content"]["assembly"]["sections"]) == 12
    assert len(body["content"]["assembly"]["cross_layer_checks"]) == 11
    assert body["content"]["assembly"]["completeness"]["complete"] is False
    assert body["content"]["source_fingerprints"]["assembly"] == (
        body["content"]["assembly"]["assembly_fingerprint"]
    )
    for layer in ("l2", "l3", "management"):
        for candidate in body["content"][layer]["candidates"]:
            assert candidate["command_text_included"] is (
                candidate["command_text"] is not None
            )
            if candidate["independent_verdict"] != "pass":
                assert candidate["command_text"] is None
    for candidate in body["content"]["management"]["candidates"]:
        assert candidate["command_text"] is None
        assert candidate["secret_bearing"] is False or (
            candidate["command_text"] is None
        )
    _assert_no_deployable_artifact(body)
    forbidden_keys = {
        "password", "private_key", "secret_value", "credential_value",
        "credential_secret", "pre_shared_key",
    }

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                assert key.casefold() not in forbidden_keys
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(body)
    assert "credref:" not in repr(body).casefold()
    assert "private key" not in repr(body).casefold()
    content = ReviewBundleContent.model_validate(body["content"])
    assert review_bundle_content_digest(content) == body["content_digest"]
    # The same frozen content must produce a repeatable digest.
    second = client.get(
        _base(event_id, revision["id"], core["id"]) + "/cisco-review-bundle",
    )
    assert second.status_code == 200
    assert second.json()["content_digest"] == body["content_digest"]


def test_c9200_review_bundle_preserves_blocked_candidates(
    client: TestClient,
) -> None:
    event_id = _event(client, "R71 C9200")
    plan, core = _c9200_plan(event_id)
    revision = _save(client, event_id, plan)
    response, body = _bundle(client, event_id, revision["id"], core["id"])
    assert response.status_code == 200, response.text
    assert body["content"]["identity"]["family"] == "catalyst-9200"
    assert body["content"]["l3"]["summary"]["passed"] == 6
    assert body["content"]["l3"]["summary"]["blocked"] == 2
    assert body["content"]["management"]["summary"] == {
        "total": 9, "passed": 0, "blocked": 9, "failed": 0,
    }
    assert any(
        candidate["independent_verdict"] == "blocked"
        and candidate["command_text"] is None
        for candidate in body["content"]["l3"]["candidates"]
    )
    assert len(body["content"]["assembly"]["sections"]) == 12
    assert len(body["content"]["assembly"]["cross_layer_checks"]) == 11
    _assert_no_deployable_artifact(body)


def test_unsupported_family_and_non_core_are_rejected(
    client: TestClient,
) -> None:
    event_id = _event(client, "R71 unsupported")
    plan = make_l3_plan(
        event_id, core_family="catalyst-2960x", core_pid="WS-C2960X-24TS-L",
        static_route_count=1,
    )
    core = next(item for item in plan["assignments"] if item["hostname"] == "L3-Core")
    revision = _save(client, event_id, plan)
    response = client.get(
        _base(event_id, revision["id"], core["id"]) + "/cisco-review-bundle",
    )
    assert response.status_code == 409
    assert response.json()["detail"]["reason_code"] == (
        "review-bundle-platform-not-supported"
    )


def test_revision_and_assignment_bindings_are_exact(
    client: TestClient,
) -> None:
    event_id = _event(client, "R71 binding")
    plan, core = _plan(event_id)
    revision = _save(client, event_id, plan)
    wrong_assignment = client.get(
        _base(event_id, revision["id"], str(uuid4())) + "/cisco-review-bundle",
    )
    assert wrong_assignment.status_code == 404
    other_event = _event(client, "R71 other event")
    wrong_event = client.get(
        _base(other_event, revision["id"], core["id"]) + "/cisco-review-bundle",
    )
    assert wrong_event.status_code == 404
    wrong_query = client.get(
        _base(event_id, revision["id"], core["id"])
        + "/cisco-review-bundle?revision=forged",
    )
    assert wrong_query.status_code == 400
    assert wrong_query.json()["detail"]["reason_code"] == "undeclared-input"


def _server_objects(
    client: TestClient, event_id: str, plan: dict[str, Any],
    core: dict[str, Any], revision: dict[str, Any],
) -> dict[str, Any]:
    base = _base(event_id, revision["id"], core["id"])
    revision_model = PlanRevision.model_validate(
        client.get(
            API + f"/events/{event_id}/plan-revisions/{revision['id']}",
        ).json(),
    )
    return {
        "revision": revision_model,
        "l2_document": L2CliCandidateDocument.model_validate(
            client.get(base + "/l2-cli-candidates").json(),
        ),
        "l2_report": L2ValidationReport.model_validate(
            client.get(base + "/l2-cli-validation").json(),
        ),
        "l3_document": L3CandidateDocument.model_validate(
            client.get(base + "/l3-cli-candidates").json(),
        ),
        "l3_report": L3ValidationReport.model_validate(
            client.get(base + "/l3-cli-validation").json(),
        ),
        "management_document": ManagementCandidateDocument.model_validate(
            client.get(base + "/management-cli-candidates").json(),
        ),
        "management_report": ManagementValidationReport.model_validate(
            client.get(base + "/management-cli-validation").json(),
        ),
        "assembly": ConfigurationAssembly.model_validate(
            client.get(base + "/config-assembly-preview").json(),
        ),
    }


def _build_from_objects(objects: dict[str, Any], event_id: str, core: dict[str, Any]) -> Any:
    return build_cisco_review_bundle(
        event_id=UUID(event_id),
        event_name="R71 tamper",
        revision=objects["revision"],
        assignment_id=UUID(core["id"]),
        l2_document=objects["l2_document"],
        l2_report=objects["l2_report"],
        l3_document=objects["l3_document"],
        l3_report=objects["l3_report"],
        management_document=objects["management_document"],
        management_report=objects["management_report"],
        assembly=objects["assembly"],
        generated_at="2026-11-24T00:00:00+00:00",
    )


def _isolated_management_objects(
    objects: dict[str, Any], core: dict[str, Any],
) -> tuple[ManagementCandidateDocument, ManagementValidationReport]:
    revision = objects["revision"]
    registry = make_isolated_management_registry()
    l2_intent = build_layer2_intent(revision, None)
    intent = build_management_intent(
        revision, l2_intent, UUID(core["id"]), evidence_registry=registry,
    )
    document = build_management_cli_candidates(
        revision, intent, registry, test_only_registry=True,
    )
    report = validate_management_candidates(
        revision, intent, document, registry, test_only_registry=True,
    )
    return document, report


def test_pass_candidate_text_tampering_is_rejected_for_all_layers(
    client: TestClient,
) -> None:
    event_id = _event(client, "R71 pass text tamper")
    plan, core = _plan(event_id)
    revision = _save(client, event_id, plan)
    objects = _server_objects(client, event_id, plan, core, revision)

    l2_pass = next(
        candidate for candidate in objects["l2_document"].candidates
        if candidate.status.value == "candidate" and candidate.candidate_text
    )
    l2_objects = dict(objects)
    l2_objects["l2_document"] = objects["l2_document"].model_copy(update={
        "candidates": tuple(
            candidate.model_copy(update={
                "candidate_text": (candidate.candidate_text or "") + " injected",
            })
            if candidate.candidate_id == l2_pass.candidate_id else candidate
            for candidate in objects["l2_document"].candidates
        ),
    })
    with pytest.raises(ReviewBundleError) as error:
        _build_from_objects(l2_objects, event_id, core)
    assert error.value.reason_code in {
        "review-bundle-l2-document-fingerprint-mismatch",
        "review-bundle-l2-candidate-fingerprint-mismatch",
    }

    l3_pass = next(
        candidate for candidate in objects["l3_document"].candidates
        if candidate.status.value == "candidate" and candidate.candidate_text
    )
    l3_objects = dict(objects)
    l3_objects["l3_document"] = objects["l3_document"].model_copy(update={
        "candidates": tuple(
            candidate.model_copy(update={
                "candidate_text": (candidate.candidate_text or "") + " injected",
            })
            if candidate.candidate_id == l3_pass.candidate_id else candidate
            for candidate in objects["l3_document"].candidates
        ),
    })
    with pytest.raises(ReviewBundleError) as error:
        _build_from_objects(l3_objects, event_id, core)
    assert error.value.reason_code in {
        "review-bundle-l3-document-fingerprint-mismatch",
        "review-bundle-l3-candidate-fingerprint-mismatch",
    }

    isolated_document, isolated_report = _isolated_management_objects(objects, core)
    domain_pass = next(
        candidate for candidate in isolated_document.candidates
        if candidate.status == "candidate" and candidate.candidate_text
    )
    domain_objects = dict(objects)
    domain_objects["management_document"] = isolated_document
    domain_objects["management_report"] = isolated_report
    assert _build_from_objects(domain_objects, event_id, core).content_digest
    tampered_management = isolated_document.model_copy(update={
        "candidates": tuple(
            candidate.model_copy(update={
                "candidate_text": (candidate.candidate_text or "") + " injected",
            })
            if candidate.candidate_id == domain_pass.candidate_id else candidate
            for candidate in isolated_document.candidates
        ),
    })
    domain_objects["management_document"] = tampered_management
    with pytest.raises(ReviewBundleError) as error:
        _build_from_objects(domain_objects, event_id, core)
    assert error.value.reason_code == (
        "review-bundle-management-document-fingerprint-mismatch"
    )


def test_additional_candidate_and_document_tampering_is_rejected(
    client: TestClient,
) -> None:
    event_id = _event(client, "R71 candidate tamper")
    plan, core = _plan(event_id)
    revision = _save(client, event_id, plan)
    objects = _server_objects(client, event_id, plan, core, revision)

    replaced_fingerprint = dict(objects)
    replaced_fingerprint["l2_document"] = objects["l2_document"].model_copy(update={
        "candidates": tuple(
            candidate.model_copy(update={"candidate_fingerprint": "0" * 64})
            if index == 0 else candidate
            for index, candidate in enumerate(objects["l2_document"].candidates)
        ),
    })
    with pytest.raises(ReviewBundleError):
        _build_from_objects(replaced_fingerprint, event_id, core)

    replaced_document = dict(objects)
    replaced_document["l3_document"] = objects["l3_document"].model_copy(update={
        "l3_render_fingerprint": "0" * 64,
    })
    with pytest.raises(ReviewBundleError):
        _build_from_objects(replaced_document, event_id, core)

    missing_candidate = dict(objects)
    missing_candidate["l2_document"] = objects["l2_document"].model_copy(update={
        "candidates": objects["l2_document"].candidates[1:],
    })
    with pytest.raises(ReviewBundleError):
        _build_from_objects(missing_candidate, event_id, core)

    duplicate_candidate = dict(objects)
    duplicate_candidate["l2_document"] = objects["l2_document"].model_copy(update={
        "candidates": (
            objects["l2_document"].candidates[0],
            objects["l2_document"].candidates[0],
        ),
    })
    with pytest.raises(ReviewBundleError):
        _build_from_objects(duplicate_candidate, event_id, core)

def test_builder_rejects_source_registry_and_assembly_tampering(
    client: TestClient,
) -> None:
    event_id = _event(client, "R71 tamper")
    plan, core = _plan(event_id)
    revision = _save(client, event_id, plan)
    objects = _server_objects(client, event_id, plan, core, revision)
    original = _build_from_objects(objects, event_id, core)
    assert original.content_digest == review_bundle_content_digest(original.content)

    bad_registry = dict(objects)
    bad_registry["l2_document"] = objects["l2_document"].model_copy(update={
        "source": objects["l2_document"].source.model_copy(update={
            "command_evidence_fingerprint": "0" * 64,
        }),
    })
    with pytest.raises(ReviewBundleError) as error:
        _build_from_objects(bad_registry, event_id, core)
    assert error.value.reason_code == "review-bundle-registry-binding-mismatch"

    bad_assembly = dict(objects)
    bad_assembly["assembly"] = objects["assembly"].model_copy(update={
        "assembly_fingerprint": "0" * 64,
    })
    with pytest.raises(ReviewBundleError) as error:
        _build_from_objects(bad_assembly, event_id, core)
    assert error.value.reason_code == "review-bundle-assembly-fingerprint-mismatch"

    bad_report = dict(objects)
    bad_report["l2_report"] = objects["l2_report"].model_copy(update={
        "report_fingerprint": "0" * 64,
    })
    with pytest.raises(ReviewBundleError):
        _build_from_objects(bad_report, event_id, core)


def test_builder_rejects_revision_document_and_assignment_mismatch(
    client: TestClient,
) -> None:
    event_id = _event(client, "R71 revision mismatch")
    plan, core = _plan(event_id)
    revision = _save(client, event_id, plan)
    objects = _server_objects(client, event_id, plan, core, revision)
    with pytest.raises(ReviewBundleError) as error:
        _build_from_objects(objects, event_id, {"id": str(uuid4())})
    assert error.value.reason_code == "review-bundle-revision-assignment-binding-mismatch"

    bad_document = dict(objects)
    bad_document["l2_document"] = objects["l2_document"].model_copy(update={
        "render_fingerprint": "0" * 64,
    })
    with pytest.raises(ReviewBundleError):
        _build_from_objects(bad_document, event_id, core)


def test_l2_report_content_tamper_without_fingerprint_is_rejected(
    client: TestClient,
) -> None:
    event_id = _event(client, "R71B L2 report tamper")
    plan, core = _plan(event_id)
    revision = _save(client, event_id, plan)
    objects = _server_objects(client, event_id, plan, core, revision)
    report = objects["l2_report"]
    first = report.candidates[0]
    forged_risk = first.risk.model_copy(update={
        "findings": (*first.risk.findings, "forged-risk-finding"),
    })
    forged_candidate = first.model_copy(update={"risk": forged_risk})
    tampered = report.model_copy(update={
        "candidates": (forged_candidate, *report.candidates[1:]),
    })
    objects["l2_report"] = tampered
    # Document, candidate fingerprints, Report fingerprint, Assembly and
    # Revision remain unchanged.  The current L2 Report content must be
    # independently fingerprinted before command text is emitted.
    with pytest.raises(ReviewBundleError) as error:
        _build_from_objects(objects, event_id, core)
    assert error.value.reason_code == (
        "review-bundle-l2-report-fingerprint-mismatch"
    )

def test_builder_rejects_blocked_candidate_text_injection(
    client: TestClient,
) -> None:
    event_id = _event(client, "R71 text injection")
    plan, core = _plan(event_id)
    revision = _save(client, event_id, plan)
    objects = _server_objects(client, event_id, plan, core, revision)
    blocked = next(
        candidate for candidate in objects["l3_document"].candidates
        if candidate.status.value != "candidate"
    )
    tampered_document = objects["l3_document"].model_copy(update={
        "candidates": tuple(
            candidate.model_copy(update={"candidate_text": "ip route 0.0.0.0 0.0.0.0 192.0.2.1"})
            if candidate.candidate_id == blocked.candidate_id else candidate
            for candidate in objects["l3_document"].candidates
        ),
    })
    objects["l3_document"] = tampered_document
    with pytest.raises(ReviewBundleError) as error:
        _build_from_objects(objects, event_id, core)
    assert error.value.reason_code in {
        "review-bundle-l3-document-fingerprint-mismatch",
        "review-bundle-l3-blocked-text-present",
    }

def test_r85_console_only_pid_review_bundle_is_blocked(
    client: TestClient,
) -> None:
    event_id = _event(client, "R85 console-only review bundle")
    plan = make_l3_plan(
        event_id,
        core_pid="C1000-16T-2G-L",
        core_family="catalyst-c1000",
        core_image="15.2(7)E2",
        core_license=None,
        static_route_count=1,
    )
    core = next(item for item in plan["assignments"] if item["hostname"] == "L3-Core")
    revision = _save(client, event_id, plan)
    response = client.get(
        _base(event_id, revision["id"], core["id"]) + "/cisco-review-bundle",
    )
    assert response.status_code == 409
    assert response.json()["detail"]["reason_code"] == (
        "review-bundle-platform-not-supported"
    )
