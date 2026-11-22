"""CIS-03-03C read-only L3 candidate/validation API integration tests."""

from __future__ import annotations

import ast
import copy
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from layer3_helpers import make_l3_plan, make_stack_plan
from pydantic import ValidationError

from event_switch_manager import layer3_cli_api
from event_switch_manager.app import create_app
from event_switch_manager.planning.layer3_cli_candidates import (
    Candidate,
    CandidateStatus,
    L3CandidateDocument,
    build_l3_cli_candidates,
)
from event_switch_manager.planning.layer3_cli_validation import (
    ExpectedSource,
    L3ValidationReport,
    ValidationIntegrityError,
    independent_candidate_fingerprint,
    independent_render_fingerprint,
    independent_report_fingerprint,
)
from event_switch_manager.planning.layer3_cli_validation import (
    validate_l3_candidates as real_validate_l3_candidates,
)
from event_switch_manager.planning.layer3_command_evidence import DEFAULT_REGISTRY
from event_switch_manager.settings import Settings

API = "/api/v1"
ORIGIN = "http://127.0.0.1:8765"
EXPECTED_SOURCE_FIELDS = {
    "event_id",
    "saved_revision_uuid",
    "revision_number",
    "revision_canonical_hash",
    "l3_intent_schema_version",
    "l3_intent_fingerprint",
    "l3_render_contract_id",
    "l3_render_contract_version",
    "l3_render_fingerprint",
    "command_evidence_registry_id",
    "command_evidence_registry_fingerprint",
    "assignment_id",
    "baseline_revision_uuid",
    "baseline_revision_hash",
}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "l3-cli-api.sqlite3")
    with TestClient(
        create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN},
    ) as session:
        yield session


def _event(client: TestClient, name: str = "R40 event") -> str:
    response = client.post(f"{API}/events", json={"name": name})
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _save(
    client: TestClient, event_id: str, plan: dict[str, Any],
) -> dict[str, Any]:
    plan = copy.deepcopy(plan)
    plan["event_id"] = event_id
    response = client.post(
        f"{API}/events/{event_id}/plan-revisions", json=plan,
    )
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def _assignment(plan: dict[str, Any], hostname: str = "L3-Core") -> str:
    return str(next(
        item["id"] for item in plan["assignments"]
        if item["hostname"] == hostname
    ))


def _path(event_id: str, revision_id: str, assignment_id: str, suffix: str) -> str:
    return (
        f"{API}/events/{event_id}/plan-revisions/{revision_id}"
        f"/assignments/{assignment_id}/{suffix}"
    )


def _save_core(
    client: TestClient,
    *,
    plan_kwargs: dict[str, Any] | None = None,
    stack: bool = False,
    name: str = "R40 event",
) -> tuple[str, str, dict[str, Any]]:
    event_id = _event(client, name)
    if stack:
        plan = make_stack_plan(event_id)
    else:
        kwargs = {"static_route_count": 1, **(plan_kwargs or {})}
        plan = make_l3_plan(event_id, **kwargs)
    revision = _save(client, event_id, plan)
    return event_id, _assignment(plan), revision


def _unique_serials(plan: dict[str, Any], suffix: str) -> dict[str, Any]:
    changed = copy.deepcopy(plan)
    for index, device in enumerate(changed["physical_devices"]):
        serial = device.get("verified_serial")
        if serial is not None:
            device["verified_serial"] = f"{serial}-{suffix}-{index}"
    return changed


def _get_candidates(
    client: TestClient, event_id: str, revision: dict[str, Any], assignment_id: str,
) -> Any:
    return client.get(
        _path(event_id, str(revision["id"]), assignment_id, "l3-cli-candidates"),
    )


def _get_validation(
    client: TestClient, event_id: str, revision: dict[str, Any], assignment_id: str,
) -> Any:
    return client.get(
        _path(event_id, str(revision["id"]), assignment_id, "l3-cli-validation"),
    )


def _detail(response: Any) -> dict[str, Any]:
    return cast(dict[str, Any], response.json()["detail"])


def _assert_error(response: Any, status: int, reason: str) -> None:
    assert response.status_code == status, response.text
    detail = _detail(response)
    assert detail["reason_code"] == reason
    assert "Traceback" not in response.text
    assert "sqlite" not in response.text.lower()


def _mutate_candidate_document(
    document: L3CandidateDocument,
    candidate: Candidate,
    *,
    index: int | None = None,
) -> L3CandidateDocument:
    candidates = list(document.candidates)
    if index is None:
        index = next(
            index for index, item in enumerate(candidates)
            if item.candidate_id == candidate.candidate_id
        )
    candidates[index] = candidate.model_copy(update={
        "candidate_fingerprint": independent_candidate_fingerprint(candidate),
    })
    changed = document.model_copy(update={"candidates": tuple(candidates)})
    return changed.model_copy(update={
        "l3_render_fingerprint": independent_render_fingerprint(changed),
    })


def _monkeypatch_document(
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[L3CandidateDocument], L3CandidateDocument],
) -> None:
    real_build = build_l3_cli_candidates

    def forged_build(*args: Any, **kwargs: Any) -> L3CandidateDocument:
        return mutate(real_build(*args, **kwargs))

    monkeypatch.setattr(layer3_cli_api, "build_l3_cli_candidates", forged_build)


def test_real_candidate_endpoint_has_nine_texts_and_one_blocked(client: TestClient) -> None:
    event_id, assignment_id, revision = _save_core(client)
    response = _get_candidates(client, event_id, revision, assignment_id)
    assert response.status_code == 200, response.text
    document = L3CandidateDocument.model_validate(response.json())
    assert document.contract_id == "cis-03-cisco-l3-cli-candidate-v1"
    assert document.l3_render_schema_version == 1
    assert document.render_state.value == "review-candidates"
    assert document.summary.total == 10
    assert document.summary.candidates == 9
    assert document.summary.blocked == 1
    assert sum(
        item.candidate_text is not None for item in document.candidates
    ) == 9
    helper = next(
        item for item in document.candidates
        if item.category.value == "dhcp-helper-address"
    )
    assert helper.status is CandidateStatus.BLOCKED
    assert helper.candidate_text is None
    assert helper.syntax_validation.parser_verified is False
    assert document.l3_render_fingerprint == independent_render_fingerprint(document)
    for candidate in document.candidates:
        assert candidate.candidate_fingerprint == independent_candidate_fingerprint(candidate)
    assert document.safety.candidate_only is True
    assert document.safety.executable is False
    assert document.safety.deployable is False
    assert document.safety.deployment_allowed is False
    assert document.safety.device_connection == "none"
    assert document.safety.running_config_read is False
    assert document.safety.device_writes_enabled is False
    assert document.safety.cli is None
    assert document.safety.deployment_artifact is None


def test_real_validation_endpoint_is_bound_and_has_no_text(client: TestClient) -> None:
    event_id, assignment_id, revision = _save_core(client)
    response = _get_validation(client, event_id, revision, assignment_id)
    assert response.status_code == 200, response.text
    assert response.headers[layer3_cli_api.VALIDATION_SCOPE_HEADER] == "full"
    body = response.json()
    report = L3ValidationReport.model_validate(body)
    assert report.validation_contract_id == "cis-03-03-independent-cli-validation-v1"
    assert report.validation_schema_version == 1
    assert report.validation_scope == "production"
    assert str(report.assignment_id) == assignment_id
    assert report.overall_status.value == "partial"
    assert report.summary.total == 10
    assert report.summary.passed == 9
    assert report.summary.failed == 0
    assert report.summary.blocked == 1
    assert report.summary.base_categories_passed == 5
    assert report.summary.base_candidates_passed == 9
    assert report.summary.dhcp_helper_blocked is True
    assert report.report_fingerprint == independent_report_fingerprint(report)
    assert set(body["expected_source"]) == EXPECTED_SOURCE_FIELDS
    assert body["expected_source"]["event_id"] == event_id
    assert body["expected_source"]["saved_revision_uuid"] == revision["id"]
    assert body["expected_source"]["revision_canonical_hash"] == revision["content_hash"]
    assert body["expected_source"]["assignment_id"] == assignment_id
    assert body["expected_source"]["baseline_revision_uuid"] is None
    assert body["expected_source"]["baseline_revision_hash"] is None
    assert body["expected_source"]["command_evidence_registry_id"] == (
        DEFAULT_REGISTRY.registry_id
    )
    assert body["expected_source"]["command_evidence_registry_fingerprint"] == (
        DEFAULT_REGISTRY.fingerprint
    )
    assert body["source"]["event_id"] == event_id
    assert body["source"]["saved_revision_uuid"] == revision["id"]
    assert body["source"]["assignment_id"] == assignment_id
    assert body["source"]["command_evidence_registry_id"] == DEFAULT_REGISTRY.registry_id
    assert body["source"]["command_evidence_registry_fingerprint"] == DEFAULT_REGISTRY.fingerprint
    assert set(body["integrity"]) == {
        "revision_canonical_hash", "baseline_canonical_hash", "intent_rebuilt",
        "intent_fingerprint", "expected_source", "document_source",
        "document_fingerprint", "candidate_fingerprints", "candidate_ids_unique",
        "candidate_set", "summary", "safety",
    }
    assert all(body["integrity"].values())
    assert "candidate_text" not in json.dumps(body)
    assert body["safety"]["candidate_only"] is True
    assert body["safety"]["executable"] is False
    assert body["safety"]["deployment_allowed"] is False
    assert body["safety"]["cli"] is None
    assert body["safety"]["deployment_artifact"] is None
    helper = next(
        item for item in body["candidates"]
        if item["category"] == "dhcp-helper-address"
    )
    assert helper["independent_verdict"] == "blocked"
    assert helper["parse"]["status"] == "not-run"


def test_two_endpoints_bind_the_same_trusted_source(client: TestClient) -> None:
    event_id, assignment_id, revision = _save_core(client)
    candidate_response = _get_candidates(client, event_id, revision, assignment_id)
    validation_response = _get_validation(client, event_id, revision, assignment_id)
    assert candidate_response.status_code == 200
    assert validation_response.status_code == 200
    document = L3CandidateDocument.model_validate(candidate_response.json())
    report = L3ValidationReport.model_validate(validation_response.json())
    assert report.source.l3_render_fingerprint == document.l3_render_fingerprint
    assert report.source.saved_revision_uuid == document.source.revision_uuid
    assert report.source.assignment_id == UUID(assignment_id)
    assert [item.candidate_id for item in report.candidates] == [
        item.candidate_id for item in document.candidates
    ]


def test_second_revision_binds_previous_revision(client: TestClient) -> None:
    event_id = _event(client, "R40 baseline")
    first_plan = make_l3_plan(event_id, static_route_count=1)
    first = _save(client, event_id, first_plan)
    assignment_id = _assignment(first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["static_routes"].append({
        "id": str(uuid4()),
        "assignment_id": assignment_id,
        "destination": "10.201.0.0/24",
        "next_hop": {"kind": "ip", "address": "10.0.0.2"},
        "preference": 1,
    })
    second = _save(client, event_id, second_plan)
    response = _get_validation(client, event_id, second, assignment_id)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["expected_source"]["baseline_revision_uuid"] == first["id"]
    assert body["expected_source"]["baseline_revision_hash"] == first["content_hash"]
    assert body["source"]["baseline_revision_uuid"] == first["id"]
    assert body["source"]["baseline_revision_hash"] == first["content_hash"]
    candidate_response = _get_candidates(client, event_id, second, assignment_id)
    if candidate_response.status_code == 409:
        # The planning baseline difference is independently reported as a
        # cleanup/removal safety blocker; the Candidate endpoint must fail
        # closed rather than emit a document whose validation has FAILs.
        _assert_error(candidate_response, 409, "candidate-document-not-reviewable")
    else:
        assert candidate_response.status_code == 200, candidate_response.text
        document = L3CandidateDocument.model_validate(candidate_response.json())
        assert all(item.candidate_text is None for item in document.candidates)


@pytest.mark.parametrize(
    ("suffix", "field"),
    (
        ("?category=ip-routing", "category"),
        ("?fingerprint=abc", "fingerprint"),
        ("?registry_id=other", "registry_id"),
        ("?unknown=1", "unknown"),
        ("?revision_hash=abc", "revision_hash"),
    ),
)
def test_undeclared_query_is_rejected(
    client: TestClient, suffix: str, field: str,
) -> None:
    event_id, assignment_id, revision = _save_core(client)
    for endpoint in ("l3-cli-candidates", "l3-cli-validation"):
        response = client.get(
            _path(event_id, str(revision["id"]), assignment_id, endpoint) + suffix,
        )
        assert response.status_code == 400, response.text
        detail = _detail(response)
        assert detail["reason_code"] == "undeclared-input"
        assert detail["fields"] == [field]


def test_request_body_and_conditional_headers_are_rejected(
    client: TestClient,
) -> None:
    event_id, assignment_id, revision = _save_core(client)
    for endpoint in ("l3-cli-candidates", "l3-cli-validation"):
        url = _path(event_id, str(revision["id"]), assignment_id, endpoint)
        body_response = client.request("GET", url, content=b"{}")
        _assert_error(body_response, 400, "undeclared-input")
        assert _detail(body_response)["fields"] == ["request-body"]
        for header in ("If-Match", "If-None-Match"):
            response = client.get(url, headers={header: '"etag"'})
            _assert_error(response, 400, "undeclared-input")
            assert _detail(response)["fields"] == [header.lower()]


def test_routes_are_get_only(client: TestClient) -> None:
    event_id, assignment_id, revision = _save_core(client)
    for endpoint in ("l3-cli-candidates", "l3-cli-validation"):
        url = _path(event_id, str(revision["id"]), assignment_id, endpoint)
        for method in (client.post, client.put, client.patch, client.delete):
            assert method(url).status_code == 405


def test_invalid_uuid_uses_framework_validation(client: TestClient) -> None:
    event_id = _event(client)
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/not-a-uuid/"
        f"assignments/{uuid4()}/l3-cli-candidates",
    )
    assert response.status_code == 422


def test_cross_event_revision_and_assignment_are_isolated(
    client: TestClient,
) -> None:
    first_event = _event(client, "First")
    first_plan = make_l3_plan(first_event)
    first_revision = _save(client, first_event, first_plan)
    first_assignment = _assignment(first_plan)
    second_event = _event(client, "Second")
    second_plan = _unique_serials(
        make_l3_plan(second_event, static_route_count=1), "second",
    )
    second_revision = _save(client, second_event, second_plan)
    second_assignment = _assignment(second_plan)

    cross_revision = _get_candidates(
        client, second_event, first_revision, first_assignment,
    )
    _assert_error(cross_revision, 404, "saved-revision-not-found")
    cross_assignment = _get_candidates(
        client, first_event, first_revision, second_assignment,
    )
    _assert_error(cross_assignment, 404, "assignment-not-found")
    assert second_revision["id"] != first_revision["id"]


def test_missing_assignment_and_event_revision_errors(client: TestClient) -> None:
    event_id, _assignment_id, revision = _save_core(client)
    missing_assignment = _get_candidates(
        client, event_id, revision, str(uuid4()),
    )
    _assert_error(missing_assignment, 404, "assignment-not-found")
    missing_event = client.get(
        _path(str(uuid4()), str(revision["id"]), str(uuid4()), "l3-cli-candidates"),
    )
    _assert_error(missing_event, 404, "event-not-found")
    missing_revision = _get_candidates(
        client, event_id, {"id": str(uuid4())}, str(uuid4()),
    )
    _assert_error(missing_revision, 404, "saved-revision-not-found")


def test_non_core_assignment_is_not_zero_candidate_pass(client: TestClient) -> None:
    event_id = _event(client)
    plan = make_l3_plan(event_id)
    revision = _save(client, event_id, plan)
    access_id = _assignment(plan, "L3-Access")
    response = _get_candidates(client, event_id, revision, access_id)
    _assert_error(response, 409, "assignment-not-eligible-for-l3-cli")
    validation = _get_validation(client, event_id, revision, access_id)
    _assert_error(validation, 409, "assignment-not-eligible-for-l3-cli")


def test_unsupported_pid_remains_blocked_without_becoming_not_found(
    client: TestClient,
) -> None:
    event_id = _event(client)
    plan = make_l3_plan(
        event_id, core_pid="C9200L-24P-4X", core_family="catalyst-9200",
        with_relay=False,
    )
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    response = _get_candidates(client, event_id, revision, assignment_id)
    assert response.status_code == 200, response.text
    document = L3CandidateDocument.model_validate(response.json())
    assert document.summary.candidates == 0
    assert document.summary.blocked > 0
    assert all(item.candidate_text is None for item in document.candidates)
    validation = _get_validation(client, event_id, revision, assignment_id)
    assert validation.status_code == 200, validation.text
    report = L3ValidationReport.model_validate(validation.json())
    assert report.summary.passed == 0
    assert report.summary.failed == 0
    assert report.summary.blocked > 0


def test_network_essentials_dhcp_service_blocker_does_not_block_base(
    client: TestClient,
) -> None:
    event_id = _event(client)
    plan = make_l3_plan(event_id, static_route_count=1, core_license="Network Essentials")
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    response = _get_candidates(client, event_id, revision, assignment_id)
    assert response.status_code == 200, response.text
    document = L3CandidateDocument.model_validate(response.json())
    assert document.summary.candidates == 9
    helper = next(
        item for item in document.candidates
        if item.category.value == "dhcp-helper-address"
    )
    assert helper.status is CandidateStatus.BLOCKED
    assert helper.candidate_text is None
    validation = _get_validation(client, event_id, revision, assignment_id)
    assert validation.status_code == 200, validation.text
    report = L3ValidationReport.model_validate(validation.json())
    assert report.summary.base_categories_passed == 5
    assert report.summary.base_candidates_passed == 9
    assert report.summary.failed == 0


def test_deny_policy_produces_no_executable_candidate(client: TestClient) -> None:
    event_id = _event(client)
    plan = make_l3_plan(event_id, deny_policy=True)
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    response = _get_candidates(client, event_id, revision, assignment_id)
    assert response.status_code == 200, response.text
    document = L3CandidateDocument.model_validate(response.json())
    assert all(item.candidate_text is None for item in document.candidates)
    assert document.render_state.value == "blocked"


def test_unresolved_stack_does_not_release_text(client: TestClient) -> None:
    event_id = _event(client)
    plan = make_stack_plan(event_id, second_serial=None)
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    response = _get_candidates(client, event_id, revision, assignment_id)
    if response.status_code == 409:
        _assert_error(response, 409, "candidate-document-not-reviewable")
    else:
        assert response.status_code == 200, response.text
        document = L3CandidateDocument.model_validate(response.json())
        assert all(item.candidate_text is None for item in document.candidates)
    validation = _get_validation(client, event_id, revision, assignment_id)
    assert validation.status_code == 200, validation.text
    report = L3ValidationReport.model_validate(validation.json())
    assert all(
        item.independent_verdict.value != "pass"
        for item in report.candidates
    )


def test_candidate_and_validation_are_read_only(client: TestClient) -> None:
    event_id, assignment_id, revision = _save_core(client)
    revision_url = f"{API}/events/{event_id}/plan-revisions/{revision['id']}"
    export_before = client.get(f"{revision_url}/export")
    revision_before = client.get(revision_url)
    list_before = client.get(f"{API}/events/{event_id}/plan-revisions")
    assert _get_candidates(client, event_id, revision, assignment_id).status_code == 200
    assert _get_validation(client, event_id, revision, assignment_id).status_code == 200
    export_after = client.get(f"{revision_url}/export")
    revision_after = client.get(revision_url)
    list_after = client.get(f"{API}/events/{event_id}/plan-revisions")
    assert export_before.content == export_after.content
    assert export_before.headers["etag"] == export_after.headers["etag"]
    assert revision_before.json() == revision_after.json()
    assert list_before.json() == list_after.json()


def test_canonical_hash_failure_returns_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, assignment_id, revision = _save_core(client)
    monkeypatch.setattr(
        layer3_cli_api, "plan_hash", lambda _content: "0" * 64,
    )
    response = _get_candidates(client, event_id, revision, assignment_id)
    _assert_error(response, 409, "revision-canonical-hash-mismatch")


def test_intent_build_failure_returns_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, assignment_id, revision = _save_core(client)

    def fail_intent(*_args: Any, **_kwargs: Any) -> Any:
        raise ValidationError.from_exception_data("Layer3Intent", [])

    monkeypatch.setattr(layer3_cli_api, "build_layer3_intent", fail_intent)
    response = _get_candidates(client, event_id, revision, assignment_id)
    _assert_error(response, 409, "layer3-intent-build-failed")


def test_renderer_binding_failure_returns_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.planning.layer3_cli_candidates import RenderBindingError

    event_id, assignment_id, revision = _save_core(client)

    def fail_render(*_args: Any, **_kwargs: Any) -> Any:
        raise RenderBindingError("renderer-test-binding")

    monkeypatch.setattr(layer3_cli_api, "build_l3_cli_candidates", fail_render)
    response = _get_candidates(client, event_id, revision, assignment_id)
    _assert_error(response, 409, "renderer-binding-failure")


def test_validator_integrity_error_returns_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, assignment_id, revision = _save_core(client)

    def fail_validation(*_args: Any, **_kwargs: Any) -> Any:
        raise ValidationIntegrityError("candidate-id-mismatch", ("forged",))

    monkeypatch.setattr(layer3_cli_api, "validate_l3_candidates", fail_validation)
    response = _get_candidates(client, event_id, revision, assignment_id)
    _assert_error(response, 409, "validation-integrity-failure")


def test_forged_candidate_id_returns_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, assignment_id, revision = _save_core(client)

    def mutate(document: L3CandidateDocument) -> L3CandidateDocument:
        candidate = document.candidates[0]
        return _mutate_candidate_document(
            document,
            candidate.model_copy(update={"candidate_id": "l3cand-0000000000000000"}),
            index=0,
        )

    _monkeypatch_document(monkeypatch, mutate)
    response = _get_candidates(client, event_id, revision, assignment_id)
    _assert_error(response, 409, "validation-integrity-failure")


def test_forged_device_identity_returns_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, assignment_id, revision = _save_core(client)

    def mutate(document: L3CandidateDocument) -> L3CandidateDocument:
        device = document.device.model_copy(update={"hostname": "FORGED-CORE"})
        changed = document.model_copy(update={"device": device})
        return changed.model_copy(update={
            "l3_render_fingerprint": independent_render_fingerprint(changed),
        })

    _monkeypatch_document(monkeypatch, mutate)
    response = _get_candidates(client, event_id, revision, assignment_id)
    _assert_error(response, 409, "validation-integrity-failure")


def test_forged_blocked_helper_metadata_returns_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, assignment_id, revision = _save_core(client)

    def mutate(document: L3CandidateDocument) -> L3CandidateDocument:
        candidate = next(
            item for item in document.candidates
            if item.category.value == "dhcp-helper-address"
        )
        changed = candidate.model_copy(update={
            "parameters": {
                **candidate.parameters,
                "server": "192.168.99.9",
            },
        })
        return _mutate_candidate_document(document, changed)

    _monkeypatch_document(monkeypatch, mutate)
    response = _get_candidates(client, event_id, revision, assignment_id)
    _assert_error(response, 409, "validation-integrity-failure")


def test_forged_evidence_candidate_fails_and_validation_returns_fail_report(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, assignment_id, revision = _save_core(client)

    def mutate(document: L3CandidateDocument) -> L3CandidateDocument:
        candidate = next(
            item for item in document.candidates
            if item.category.value == "dhcp-helper-address"
        )
        ref = candidate.syntax_evidence[0].model_copy(update={
            "content_digest": "0" * 64,
        })
        changed = candidate.model_copy(update={"syntax_evidence": (ref,)})
        return _mutate_candidate_document(document, changed)

    _monkeypatch_document(monkeypatch, mutate)
    candidate_response = _get_candidates(client, event_id, revision, assignment_id)
    _assert_error(candidate_response, 409, "candidate-document-not-reviewable")
    validation_response = _get_validation(client, event_id, revision, assignment_id)
    assert validation_response.status_code == 200, validation_response.text
    report = L3ValidationReport.model_validate(validation_response.json())
    helper = next(
        item for item in report.candidates
        if item.category == "dhcp-helper-address"
    )
    assert helper.independent_verdict.value == "fail"
    assert report.overall_status.value == "fail"


def test_tampered_report_fingerprint_returns_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, assignment_id, revision = _save_core(client)
    real_validate = real_validate_l3_candidates

    def forge_report(*args: Any, **kwargs: Any) -> L3ValidationReport:
        report = real_validate(*args, **kwargs)
        return report.model_copy(update={"report_fingerprint": "0" * 64})

    monkeypatch.setattr(layer3_cli_api, "validate_l3_candidates", forge_report)
    response = _get_validation(client, event_id, revision, assignment_id)
    _assert_error(response, 409, "validation-integrity-failure")


def test_tampered_report_integrity_flag_returns_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, assignment_id, revision = _save_core(client)
    real_validate = real_validate_l3_candidates

    def forge_report(*args: Any, **kwargs: Any) -> L3ValidationReport:
        report = real_validate(*args, **kwargs)
        integrity = report.integrity.model_copy(update={"candidate_set": False})
        return report.model_copy(update={"integrity": integrity})

    monkeypatch.setattr(layer3_cli_api, "validate_l3_candidates", forge_report)
    response = _get_validation(client, event_id, revision, assignment_id)
    _assert_error(response, 409, "validation-integrity-failure")


def test_api_module_has_no_device_or_process_access() -> None:
    source = Path(layer3_cli_api.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
    for forbidden in (
        "subprocess", "socket", "paramiko", "telnetlib", "netmiko",
        "asyncssh", "scrapli", "ncclient",
    ):
        assert all(not item.endswith(forbidden) for item in imports)
    calls = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert calls.isdisjoint({
        "eval", "exec", "compile", "__import__", "system", "popen",
        "Popen", "run", "check_output",
    })


def test_candidate_document_has_no_execution_schema_keys(client: TestClient) -> None:
    event_id, assignment_id, revision = _save_core(client)
    response = _get_candidates(client, event_id, revision, assignment_id)
    assert response.status_code == 200
    serialized = json.dumps(response.json())
    for field in (
        "execution_order", "deployment_script", "paste_ready_config",
        "rollback_commands", "push_config", "device_credentials",
        "device_session",
    ):
        assert field not in serialized


def test_openapi_exposes_only_two_new_get_routes(client: TestClient) -> None:
    schema = client.get("/api/v1/openapi.json").json()
    for suffix in ("l3-cli-candidates", "l3-cli-validation"):
        path = (
            "/api/v1/events/{event_id}/plan-revisions/{revision_id}"
            f"/assignments/{{assignment_id}}/{suffix}"
        )
        assert path in schema["paths"]
        assert set(schema["paths"][path]) == {"get"}
        parameters = schema["paths"][path]["get"].get("parameters", [])
        assert all(item["in"] == "path" for item in parameters)
        assert all(item["name"] != "category" for item in parameters)
    assert "execution_order" not in json.dumps(schema)
    assert "deployment_script" not in json.dumps(schema)


def test_expected_source_is_a_complete_trusted_object(client: TestClient) -> None:
    event_id, assignment_id, revision = _save_core(client)
    response = _get_validation(client, event_id, revision, assignment_id)
    body = response.json()
    expected = ExpectedSource.model_validate(body["expected_source"])
    assert expected.event_id == UUID(event_id)
    assert str(expected.saved_revision_uuid) == revision["id"]
    assert expected.revision_number == revision["number"]
    assert expected.revision_canonical_hash == revision["content_hash"]
    assert str(expected.assignment_id) == assignment_id
    assert expected.command_evidence_registry_id == DEFAULT_REGISTRY.registry_id
    assert expected.command_evidence_registry_fingerprint == DEFAULT_REGISTRY.fingerprint
    assert expected.l3_render_fingerprint == body["source"]["l3_render_fingerprint"]
    assert expected.baseline_revision_uuid is None
