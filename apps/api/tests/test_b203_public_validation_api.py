"""CIS-02B2-03 R19 public read-only validation API integration regressions.

These tests exercise the new ``/l2-cli-validation`` endpoint through the real
FastAPI application, real SQLite revisions and real saved plan imports. They
cover the R18 contract plus the three independent-review amendments:

A. structured 404 mapping (event / revision / assignment), never the legacy
   bare-string ``HTTPException`` payloads;
B. complete seven-field ``ExpectedSource`` binding with an integrity gate;
C. explicit validation scope: ``X-Validation-Scope: full | filtered`` and the
   rule that a filtered PASS is not a full PASS.

Only a small number of tests inject faults via precise ``monkeypatch`` calls at
the new API module boundary; every happy path uses the real server rebuild.
"""

from __future__ import annotations

import copy
import dataclasses
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from b203_corpus import FROZEN_FAMILY_COUNTS
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_b203_r16_p2_regressions import _find, _forge_to_port_channel, _settle
from test_event_plans import API, ORIGIN
from test_l2_cli_candidates import FAMILIES, assignment_of, full_plan, plan_of, render
from test_layer2_intent import event, save

import event_switch_manager.l2_validation_api as validation_api
import event_switch_manager.planning.layer2_cli_candidates as candidates_module
from event_switch_manager.app import create_app
from event_switch_manager.plan_api import (
    revision_and_baseline as _plan_api_revision_and_baseline,
)
from event_switch_manager.planning.command_evidence import DEFAULT_REGISTRY
from event_switch_manager.planning.layer2_cli_candidates import (
    CandidateCategory,
    CandidateStatus,
    L2CliCandidateDocument,
    evidence_fingerprint,
)
from event_switch_manager.planning.layer2_cli_candidates import (
    build_l2_cli_candidates as _renderer_build_document,
)
from event_switch_manager.planning.layer2_cli_validation import (
    ExpectedSource,
    canonical_sha256,
    recompute_render_fingerprint,
)
from event_switch_manager.planning.layer2_config_preview import (
    Layer2DeviceConfigPreview,
    PreviewInputError,
)
from event_switch_manager.planning.layer2_intent import Layer2Intent
from event_switch_manager.planning.plan import (
    EventPlan,
    PlanRevision,
    canonical_plan,
    plan_hash,
)
from event_switch_manager.settings import Settings

VALIDATION_PATH = (
    f"{API}/events/{{event_id}}/plan-revisions/{{revision_id}}"
    f"/assignments/{{assignment_id}}/l2-cli-validation"
)
REPORT_CONTRACT_ID = "cis-02b2-03-independent-cli-validation-v1"
FORBIDDEN_REPORT_KEYS = frozenset({
    "candidate_text", "commands", "command_lines", "cli_commands", "cli_lines",
    "configuration", "config", "config_snippet", "deployment_script",
    "execution_order", "execution_plan", "order", "paste_ready", "sequence",
})

_REAL_REVISION_AND_BASELINE = _plan_api_revision_and_baseline
_REAL_EXPECTED_SOURCE = validation_api._trusted_expected_source
_REAL_BUILD_DOCUMENT = _renderer_build_document


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "public-validation.sqlite3")
    with TestClient(
        create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN},
    ) as session:
        yield session


def _url(
    event_id: str, revision_id: str, assignment_id: str,
) -> str:
    return VALIDATION_PATH.format(
        event_id=event_id, revision_id=revision_id, assignment_id=assignment_id,
    )


def _validation(
    client: TestClient,
    event_id: str,
    revision: dict[str, Any],
    assignment_id: str,
    query: str = "",
) -> Any:
    return client.get(
        _url(event_id, str(revision["id"]), assignment_id) + query,
    )


def _report(response: Any) -> dict[str, Any]:
    return cast(dict[str, Any], response.json())


def _detail(response: Any) -> dict[str, Any]:
    return cast(dict[str, Any], _report(response)["detail"])


def _saved_9300(
    client: TestClient,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    event_id = event(client)
    plan = full_plan(event_id, "9300")
    revision = save(client, event_id, plan)
    return event_id, plan, revision


def _candidate_document(
    client: TestClient,
    event_id: str,
    plan: dict[str, Any],
    revision: dict[str, Any],
    query: str = "",
) -> L2CliCandidateDocument:
    payload = render(client, event_id, str(revision["id"]), assignment_of(plan), query)
    return L2CliCandidateDocument.model_validate(payload)


def _sample_validation_error() -> ValidationError:
    try:
        EventPlan.model_validate({})
    except ValidationError as exc:
        return exc
    raise AssertionError("empty plan unexpectedly validated")


def _zero_hash(_content: str) -> str:
    return "0" * 64


def _builder_returning(
    forged: L2CliCandidateDocument,
) -> Callable[..., L2CliCandidateDocument]:
    def _fake(
        revision: PlanRevision,
        intent: Layer2Intent,
        preview: Layer2DeviceConfigPreview,
        *,
        categories: tuple[CandidateCategory, ...] | None = None,
    ) -> L2CliCandidateDocument:
        return forged

    return _fake


def _builder_with_forged_source(
    revision: PlanRevision,
    intent: Layer2Intent,
    preview: Layer2DeviceConfigPreview,
    *,
    categories: tuple[CandidateCategory, ...] | None = None,
) -> L2CliCandidateDocument:
    document = _REAL_BUILD_DOCUMENT(
        revision, intent, preview, categories=categories,
    )
    tampered = document.model_copy(update={
        "source": document.source.model_copy(update={
            "revision_canonical_hash": "0" * 64,
        }),
    })
    return tampered.model_copy(update={
        "render_fingerprint": recompute_render_fingerprint(tampered),
    })


def _builder_with_bad_render_fingerprint(
    revision: PlanRevision,
    intent: Layer2Intent,
    preview: Layer2DeviceConfigPreview,
    *,
    categories: tuple[CandidateCategory, ...] | None = None,
) -> L2CliCandidateDocument:
    document = _REAL_BUILD_DOCUMENT(
        revision, intent, preview, categories=categories,
    )
    return document.model_copy(update={"render_fingerprint": "0" * 64})


def _revision_event_tampered(
    event_id: UUID, revision_id: UUID, session: Any,
) -> tuple[PlanRevision, PlanRevision | None]:
    revision, baseline = _REAL_REVISION_AND_BASELINE(event_id, revision_id, session)
    plan = revision.plan.model_copy(update={"event_id": uuid4()})
    digest = plan_hash(canonical_plan(plan))
    return revision.model_copy(update={"plan": plan, "content_hash": digest}), baseline


def _baseline_hash_tampered(
    event_id: UUID, revision_id: UUID, session: Any,
) -> tuple[PlanRevision, PlanRevision | None]:
    revision, baseline = _REAL_REVISION_AND_BASELINE(event_id, revision_id, session)
    assert baseline is not None
    return revision, baseline.model_copy(update={"content_hash": "0" * 64})


def _revision_document_invalid(
    event_id: UUID, revision_id: UUID, session: Any,
) -> tuple[PlanRevision, PlanRevision | None]:
    raise _sample_validation_error()


def _intent_explode(*_args: object, **_kwargs: object) -> Layer2Intent:
    raise _sample_validation_error()


def _preview_binding_failure(*_args: object, **_kwargs: object) -> Any:
    raise PreviewInputError("intent-revision-hash-mismatch")


def _expected_source_hash_mismatch(
    revision: Any, intent: Any, preview: Any, document: Any, assignment_id: Any,
) -> ExpectedSource:
    expected = _REAL_EXPECTED_SOURCE(
        revision, intent, preview, document, assignment_id,
    )
    return dataclasses.replace(expected, revision_canonical_hash="0" * 64)


def _expected_source_incomplete(
    revision: Any, intent: Any, preview: Any, document: Any, assignment_id: Any,
) -> ExpectedSource:
    expected = _REAL_EXPECTED_SOURCE(
        revision, intent, preview, document, assignment_id,
    )
    return dataclasses.replace(expected, saved_revision_uuid=None)


# --------------------------------------------------------------------------- #
# A. Trusted binding, source binding and read-only behaviour
# --------------------------------------------------------------------------- #


def test_validation_report_binds_trusted_saved_revision(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    assignment_id = assignment_of(plan)
    response = _validation(client, event_id, revision, assignment_id)
    assert response.status_code == 200, response.text
    assert response.headers[validation_api.VALIDATION_SCOPE_HEADER] == "full"
    body = _report(response)
    document = _candidate_document(client, event_id, plan, revision)

    assert body["validation_contract_id"] == REPORT_CONTRACT_ID
    assert body["validation_schema_version"] == 1
    assert body["assignment_id"] == assignment_id

    source = cast(dict[str, Any], body["source"])
    assert source["saved_revision_uuid"] == revision["id"]
    assert source["revision_number"] == revision["number"]
    assert source["revision_canonical_hash"] == revision["content_hash"]
    assert source["render_fingerprint"] == document.render_fingerprint
    assert source["render_schema_version"] == 1
    assert source["render_contract_id"] == "cis-02b2-cisco-l2-cli-candidate-v1"
    assert source["intent_schema_version"] == 1
    assert source["preview_schema_version"] == 1
    assert source["preview_contract_id"] == "cis-02b1-layer2-config-preview-v1"
    assert source["command_evidence_registry_id"] == "cis-02b2-l1-command-evidence-v1"
    assert source["command_evidence_fingerprint"] == evidence_fingerprint(
        DEFAULT_REGISTRY,
    )
    assert len(source["intent_fingerprint"]) == 64
    assert len(source["preview_fingerprint"]) == 64

    integrity = cast(dict[str, Any], body["integrity"])
    assert integrity["status"] == "pass"
    assert integrity["expected_source_match"] is True
    assert integrity["render_fingerprint_match"] is True
    assert integrity["candidate_fingerprints_match"] is True
    assert integrity["candidate_ids_unique"] is True
    assert integrity["source_binding_format_ok"] is True
    assert integrity["evidence_content_digests_ok"] is True
    assert integrity["assignment_binding_ok"] is True
    assert integrity["failures"] == []

    material = dict(body)
    material.pop("report_fingerprint")
    assert body["report_fingerprint"] == canonical_sha256(material)

    summary = cast(dict[str, Any], body["summary"])
    assert summary["total_candidates"] == 32
    assert summary["parse_pass"] == 25
    assert summary["not_run"] == 7
    assert summary["parse_fail"] == 0
    assert summary["failed_candidates"] == 0
    assert summary["overall_status"] == "pass"
    assert summary["registry_rows"] == 72
    assert summary["registry_reviewed"] == 69
    assert summary["registry_rejected"] == 1
    assert summary["registry_unreviewed"] == 2
    assert cast(dict[str, Any], body["device"])["identity_verdict"] == "pass"

    for item in cast(list[dict[str, Any]], body["candidates"]):
        assert item["parser_verified"] is False
        assert item["syntax_validation_level"] in {"dictionary-only", "not-run"}
        assert item["candidate_fingerprint_match"] is True
        assert len(item["candidate_fingerprint"]) == 64


def test_report_json_contains_no_executable_content(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    body = _report(_validation(client, event_id, revision, assignment_of(plan)))
    keys: set[str] = set()

    def _walk(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                keys.add(str(key))
                _walk(item)
        elif isinstance(value, list):
            for item in value:
                _walk(item)

    _walk(body)
    assert keys.isdisjoint(FORBIDDEN_REPORT_KEYS)
    safety = cast(dict[str, Any], body["safety"])
    assert safety == {
        "candidate_only": True,
        "executable": False,
        "deployable": False,
        "deployment_allowed": False,
        "hardware_verified": False,
        "device_connection": "none",
        "running_config_read": False,
        "device_writes_enabled": False,
        "device_runtime_state": "unknown-not-read",
        "cli": None,
        "deployment_artifact": None,
        "independent_validation_is_not_execution_authorization": True,
        "public_candidate_schema_unchanged": True,
        "parser_verified_public_field_unchanged": True,
    }
    for item in cast(list[dict[str, Any]], body["candidates"]):
        assert item["parser_verified"] is False
        assert "candidate_text" not in item
        assert isinstance(item["candidate_text_present"], bool)


@pytest.mark.parametrize("key", sorted(FAMILIES))
def test_five_family_validation_matches_frozen_renderer_counts(
    client: TestClient, key: str,
) -> None:
    event_id = event(client)
    plan = full_plan(event_id, key)
    revision = save(client, event_id, plan)
    document = _candidate_document(client, event_id, plan, revision)
    body = _report(_validation(client, event_id, revision, assignment_of(plan)))
    expected_candidates, expected_blocked, expected_unsupported = (
        FROZEN_FAMILY_COUNTS[key]
    )
    summary = cast(dict[str, Any], body["summary"])
    assert summary["total_candidates"] == (
        expected_candidates + expected_blocked + expected_unsupported
    )
    assert summary["parse_pass"] == expected_candidates
    assert summary["not_run"] == expected_blocked
    assert summary["failed_candidates"] == 0
    assert summary["overall_status"] == "pass"
    assert cast(dict[str, Any], body["device"])["identity_verdict"] == "pass"
    assert document.summary.candidates == expected_candidates
    assert document.summary.blocked == expected_blocked
    assert document.summary.unsupported == expected_unsupported
    assert cast(dict[str, Any], body["source"])["render_fingerprint"] == (
        document.render_fingerprint
    )


def test_report_matches_candidate_endpoint_document(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    assignment_id = assignment_of(plan)
    document = _candidate_document(client, event_id, plan, revision)
    body = _report(_validation(client, event_id, revision, assignment_id))
    source = cast(dict[str, Any], body["source"])
    assert source["render_fingerprint"] == document.render_fingerprint
    candidates = cast(list[dict[str, Any]], body["candidates"])
    assert len(candidates) == len(document.candidates)
    for item, candidate in zip(candidates, document.candidates, strict=True):
        assert item["candidate_id"] == candidate.candidate_id
        assert item["category"] == candidate.category.value
        assert item["renderer_status"] == candidate.status.value
        assert item["syntax_validation_level"] == candidate.syntax_validation.level.value
        assert item["parser_verified"] is False
        assert item["candidate_fingerprint"] == candidate.candidate_fingerprint
        assert str(candidate.assignment_id) == assignment_id


def test_validation_is_deterministic_across_requests(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    assignment_id = assignment_of(plan)
    first = _validation(client, event_id, revision, assignment_id)
    again = _validation(client, event_id, revision, assignment_id)
    assert first.status_code == again.status_code == 200
    assert first.content == again.content
    assert (
        first.headers[validation_api.VALIDATION_SCOPE_HEADER]
        == again.headers[validation_api.VALIDATION_SCOPE_HEADER]
        == "full"
    )
    assert _report(first)["report_fingerprint"] == _report(again)["report_fingerprint"]


def test_validation_is_read_only(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    assignment_id = assignment_of(plan)
    revision_url = f"{API}/events/{event_id}/plan-revisions/{revision['id']}"
    export_before = client.get(revision_url + "/export")
    revision_before = client.get(revision_url)
    candidate_before = render(client, event_id, str(revision["id"]), assignment_id)
    response = _validation(client, event_id, revision, assignment_id)
    assert response.status_code == 200
    export_after = client.get(revision_url + "/export")
    revision_after = client.get(revision_url)
    candidate_after = render(client, event_id, str(revision["id"]), assignment_id)
    assert export_after.content == export_before.content
    assert export_after.headers["etag"] == export_before.headers["etag"]
    assert revision_after.json() == revision_before.json()
    assert candidate_after == candidate_before
    assert _report(response)["safety"]["device_writes_enabled"] is False


def test_device_binding_is_scoped_to_the_path_assignment(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    assignment_id = assignment_of(plan)
    body = _report(_validation(client, event_id, revision, assignment_id))
    device = cast(dict[str, Any], body["device"])
    assert device["hostname"] == "L2-Access"
    assert device["exact_pid"] == "C9300L-24P-4X"
    assert device["family"] == "catalyst-9300"
    assert device["identity_verdict"] == "pass"
    for item in cast(list[dict[str, Any]], body["candidates"]):
        assert str(item["candidate_id"]).startswith("cand-")


# --------------------------------------------------------------------------- #
# B. Structured 404 mapping (review amendment A)
# --------------------------------------------------------------------------- #


def test_missing_event_returns_structured_404(client: TestClient) -> None:
    _event_id, plan, revision = _saved_9300(client)
    response = _validation(client, str(uuid4()), revision, assignment_of(plan))
    assert response.status_code == 404, response.text
    assert _detail(response) == {
        "reason_code": "event-not-found", "stage": "event",
    }
    assert set(_report(response)) == {"detail"}


def test_missing_revision_returns_structured_404(client: TestClient) -> None:
    event_id, plan, _revision = _saved_9300(client)
    response = _validation(
        client, event_id, {"id": str(uuid4())}, assignment_of(plan),
    )
    assert response.status_code == 404, response.text
    assert _detail(response) == {
        "reason_code": "saved-revision-not-found", "stage": "revision",
    }


def test_cross_event_revision_returns_structured_404(client: TestClient) -> None:
    _event_id, plan, revision = _saved_9300(client)
    other_event = event(client, "Other event")
    response = _validation(client, other_event, revision, assignment_of(plan))
    assert response.status_code == 404, response.text
    assert _detail(response) == {
        "reason_code": "saved-revision-not-found", "stage": "revision",
    }


def test_missing_assignment_returns_structured_404(client: TestClient) -> None:
    event_id, _plan, revision = _saved_9300(client)
    response = _validation(client, event_id, revision, str(uuid4()))
    assert response.status_code == 404, response.text
    assert _detail(response) == {
        "reason_code": "assignment-not-found", "stage": "preview",
    }


def test_other_event_assignment_returns_structured_404(client: TestClient) -> None:
    event_id, _plan, revision = _saved_9300(client)
    other_event = event(client, "Other event")
    other_plan = full_plan(other_event, "9300")
    save(client, other_event, other_plan)
    response = _validation(
        client, event_id, revision, assignment_of(other_plan),
    )
    assert response.status_code == 404, response.text
    assert _detail(response) == {
        "reason_code": "assignment-not-found", "stage": "preview",
    }


def test_removed_assignment_returns_structured_404(client: TestClient) -> None:
    event_id = event(client)
    plan = plan_of(event_id, "9300", ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    removed_device = str(uuid4())
    removed_assignment = str(uuid4())
    plan["physical_devices"].append({
        "id": removed_device, "vendor": "cisco", "model": "C9300L-24P-4X",
        "verified_serial": "SYN-L2-REMOVED",
    })
    plan["assignments"].append({
        "id": removed_assignment, "hostname": "L2-Removed", "role": "access",
        "family": "catalyst-9300", "physical_device_id": removed_device,
        "software": {"image": "17.12.4", "license": "Network Advantage"},
    })
    plan["physical_interfaces"].append({
        "id": str(uuid4()), "assignment_id": removed_assignment,
        "physical_device_id": removed_device, "name": "Gi1/0/1",
        "settings": {"mode": "access", "access_vlan": 20},
    })
    save(client, event_id, plan)
    retained = copy.deepcopy(plan)
    retained["physical_devices"] = [
        device for device in retained["physical_devices"]
        if device["id"] != removed_device
    ]
    retained["assignments"] = [
        assignment for assignment in retained["assignments"]
        if assignment["id"] != removed_assignment
    ]
    retained["physical_interfaces"] = [
        interface for interface in retained["physical_interfaces"]
        if interface["assignment_id"] != removed_assignment
    ]
    second = save(client, event_id, retained)
    response = _validation(client, event_id, second, removed_assignment)
    assert response.status_code == 404, response.text
    assert _detail(response) == {
        "reason_code": "assignment-not-found", "stage": "preview",
    }


def test_legacy_routes_keep_their_legacy_error_payloads(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    legacy = client.get(
        f"{API}/events/{event_id}/plan-revisions/{uuid4()}/export",
    )
    assert legacy.status_code == 404
    assert legacy.json()["detail"] == "Plan revision not found"
    candidates = client.get(
        f"{API}/events/{event_id}/plan-revisions/{uuid4()}"
        f"/assignments/{assignment_of(plan)}/l2-cli-candidates",
    )
    assert candidates.status_code == 404
    assert candidates.json()["detail"] == "Plan revision not found"
    assert _report(_validation(client, event_id, revision, assignment_of(plan)))[
        "validation_contract_id"
    ] == REPORT_CONTRACT_ID


# --------------------------------------------------------------------------- #
# C. Request contract: 400 / 422 / method
# --------------------------------------------------------------------------- #

_UNDECLARED_QUERIES: tuple[str, ...] = (
    "?expected_preview_fingerprint=" + "a" * 64,
    "?expected_intent_fingerprint=" + "a" * 64,
    "?expected_source={}",
    "?preview_fingerprint=" + "a" * 64,
    "?render_fingerprint=" + "a" * 64,
    "?candidate_text=reload",
    "?validation_report={}",
    "?preview_document={}",
    "?plan=%7B%7D",
    "?force=true",
)


@pytest.mark.parametrize("query", _UNDECLARED_QUERIES)
def test_undeclared_query_parameters_are_rejected(
    client: TestClient, query: str,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    response = _validation(client, event_id, revision, assignment_of(plan), query)
    assert response.status_code == 400, response.text
    detail = _detail(response)
    assert detail["reason_code"] == "undeclared-input"
    assert detail["fields"] == [query[1:].split("=")[0]]
    assert set(_report(response)) == {"detail"}


def test_request_body_is_rejected(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    response = client.request(
        "GET",
        _url(event_id, str(revision["id"]), assignment_of(plan)),
        content=b'{"candidate_text": "reload"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400, response.text
    assert _detail(response) == {
        "reason_code": "undeclared-input", "fields": ["request-body"],
    }


def test_conditional_request_headers_are_refused(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    for header in ("If-Match", "If-None-Match"):
        response = client.get(
            _url(event_id, str(revision["id"]), assignment_of(plan)),
            headers={header: f'"{revision["content_hash"]}"'},
        )
        assert response.status_code == 400, header
        detail = _detail(response)
        assert detail["reason_code"] == "undeclared-input"
        assert detail["fields"] == [header.lower()]


def test_invalid_category_is_rejected(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    response = _validation(
        client, event_id, revision, assignment_of(plan), "?category=reload",
    )
    assert response.status_code == 422, response.text
    assert set(_report(response)) == {"detail"}
    assert _report(response)["detail"][0]["loc"] == ["query", "category", 0]


def test_malformed_uuid_path_is_rejected(client: TestClient) -> None:
    event_id, _plan, revision = _saved_9300(client)
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/not-a-uuid/l2-cli-validation",
    )
    assert response.status_code == 422, response.text
    assert _report(response)["detail"][0]["loc"] == ["path", "assignment_id"]


def test_validation_route_is_get_only(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    url = _url(event_id, str(revision["id"]), assignment_of(plan))
    for method in ("POST", "PUT", "DELETE"):
        assert client.request(method, url).status_code == 405, method
    openapi = cast(dict[str, Any], client.get(f"{API}/openapi.json").json())
    path = openapi["paths"][VALIDATION_PATH]
    assert set(path) == {"get"}


# --------------------------------------------------------------------------- #
# D. Fail-closed 409: revision, intent, preview, renderer, integrity
# --------------------------------------------------------------------------- #


def _assert_conflict_without_report(
    response: Any, reason_code: str, stage: str,
) -> dict[str, Any]:
    assert response.status_code == 409, response.text
    body = _report(response)
    assert set(body) == {"detail"}
    detail = _detail(response)
    assert detail["reason_code"] == reason_code
    assert detail["stage"] == stage
    assert "candidates" not in body
    assert "summary" not in body
    return detail


def test_revision_canonical_hash_mismatch_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    monkeypatch.setattr(validation_api, "plan_hash", _zero_hash)
    response = _validation(client, event_id, revision, assignment_of(plan))
    detail = _assert_conflict_without_report(
        response, "revision-canonical-hash-mismatch", "revision",
    )
    assert detail["revision_scope"] == "requested"


def test_revision_document_invalid_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    monkeypatch.setattr(
        validation_api, "revision_and_baseline", _revision_document_invalid,
    )
    response = _validation(client, event_id, revision, assignment_of(plan))
    _assert_conflict_without_report(
        response, "revision-document-invalid", "revision",
    )


def test_revision_event_mismatch_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    monkeypatch.setattr(
        validation_api, "revision_and_baseline", _revision_event_tampered,
    )
    response = _validation(client, event_id, revision, assignment_of(plan))
    detail = _assert_conflict_without_report(
        response, "revision-event-mismatch", "revision",
    )
    assert detail["revision_scope"] == "requested"


def test_baseline_hash_mismatch_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = event(client)
    plan = full_plan(event_id, "9300")
    save(client, event_id, plan)
    second = copy.deepcopy(plan)
    second["physical_interfaces"][0]["settings"]["description"] = "changed"
    revision = save(client, event_id, second)
    monkeypatch.setattr(
        validation_api, "revision_and_baseline", _baseline_hash_tampered,
    )
    response = _validation(client, event_id, revision, assignment_of(second))
    detail = _assert_conflict_without_report(
        response, "revision-canonical-hash-mismatch", "revision",
    )
    assert detail["revision_scope"] == "baseline"


def test_intent_rebuild_failure_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    monkeypatch.setattr(validation_api, "build_layer2_intent", _intent_explode)
    response = _validation(client, event_id, revision, assignment_of(plan))
    _assert_conflict_without_report(response, "intent-rebuild-failed", "intent")


def test_intent_binding_failure_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    monkeypatch.setattr(
        validation_api,
        "build_device_layer2_config_preview",
        _preview_binding_failure,
    )
    response = _validation(client, event_id, revision, assignment_of(plan))
    _assert_conflict_without_report(
        response, "intent-revision-hash-mismatch", "intent",
    )


def test_renderer_binding_failure_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    monkeypatch.setattr(candidates_module, "plan_hash", _zero_hash)
    response = _validation(client, event_id, revision, assignment_of(plan))
    _assert_conflict_without_report(
        response, "stored-revision-integrity-failure", "renderer",
    )


def test_expected_source_mismatch_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    monkeypatch.setattr(
        validation_api, "_trusted_expected_source", _expected_source_hash_mismatch,
    )
    response = _validation(client, event_id, revision, assignment_of(plan))
    detail = _assert_conflict_without_report(
        response, "validation-integrity-failure", "validation",
    )
    assert "expected-source-mismatch:revision_canonical_hash" in cast(
        list[str], detail["failures"],
    )


def test_incomplete_expected_source_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    monkeypatch.setattr(
        validation_api, "_trusted_expected_source", _expected_source_incomplete,
    )
    response = _validation(client, event_id, revision, assignment_of(plan))
    detail = _assert_conflict_without_report(
        response, "validation-integrity-failure", "validation",
    )
    assert detail["failures"] == ["expected-source-incomplete"]


def test_forged_source_binding_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    monkeypatch.setattr(
        validation_api, "build_l2_cli_candidates", _builder_with_forged_source,
    )
    response = _validation(client, event_id, revision, assignment_of(plan))
    detail = _assert_conflict_without_report(
        response, "validation-integrity-failure", "validation",
    )
    assert "expected-source-mismatch:revision_canonical_hash" in cast(
        list[str], detail["failures"],
    )


def test_tampered_render_fingerprint_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    monkeypatch.setattr(
        validation_api,
        "build_l2_cli_candidates",
        _builder_with_bad_render_fingerprint,
    )
    response = _validation(client, event_id, revision, assignment_of(plan))
    detail = _assert_conflict_without_report(
        response, "validation-integrity-failure", "validation",
    )
    assert "render-fingerprint-mismatch" in cast(list[str], detail["failures"])


# --------------------------------------------------------------------------- #
# E. 200 validation verdicts: parser / security / P2-01 / P2-02
# --------------------------------------------------------------------------- #


def test_forged_dangerous_text_is_reported_as_fail_not_pass(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    document = _candidate_document(client, event_id, plan, revision)
    index, _candidate = _find(document, status=CandidateStatus.CANDIDATE)
    forged = _settle(document, index=index, changes={"candidate_text": "reload"})
    monkeypatch.setattr(
        validation_api, "build_l2_cli_candidates", _builder_returning(forged),
    )
    response = _validation(client, event_id, revision, assignment_of(plan))
    assert response.status_code == 200, response.text
    body = _report(response)
    assert cast(dict[str, Any], body["summary"])["overall_status"] == "fail"
    item = cast(list[dict[str, Any]], body["candidates"])[index]
    assert item["parse"]["status"] == "fail"
    assert item["security"]["status"] == "fail"
    assert item["independent_verdict"] == "fail"
    assert item["fail_closed_action"] == (
        "block-visible-candidate-until-independent-validation-passes"
    )
    assert "candidate_text" not in item
    assert cast(dict[str, Any], body["integrity"])["status"] == "pass"


def test_p2_01_forged_port_channel_context_is_reported_as_fail(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id, plan, revision = _saved_9300(client)
    document = _candidate_document(client, event_id, plan, revision)
    index, _candidate = _find(
        document, category="lacp-mode", status=CandidateStatus.CANDIDATE,
        text="channel-group 1 mode active",
    )
    forged = _forge_to_port_channel(document, index, field="member")
    monkeypatch.setattr(
        validation_api, "build_l2_cli_candidates", _builder_returning(forged),
    )
    response = _validation(client, event_id, revision, assignment_of(plan))
    assert response.status_code == 200, response.text
    body = _report(response)
    assert cast(dict[str, Any], body["summary"])["overall_status"] == "fail"
    item = cast(list[dict[str, Any]], body["candidates"])[index]
    assert item["parse"]["status"] == "fail"
    assert "mode-mismatch" in {
        failure["code"] for failure in cast(list[dict[str, Any]], item["parse"][
            "failures"
        ])
    }
    assert item["context_binding"]["status"] == "not-run"
    assert item["independent_verdict"] == "fail"


def test_p2_02_forged_non_poe_pid_is_reported_as_fail(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = event(client)
    plan = plan_of(event_id, "9300", ports=[
        {
            "name": "Gi1/0/1",
            "settings": {"mode": "access", "access_vlan": 20, "poe_mode": "auto"},
        },
    ])
    revision = save(client, event_id, plan)
    document = _candidate_document(client, event_id, plan, revision)
    index, _candidate = _find(
        document, category="poe-mode", status=CandidateStatus.CANDIDATE,
    )
    forged = _settle(document, device_changes={"exact_pid": "C9300L-24T-4G"})
    monkeypatch.setattr(
        validation_api, "build_l2_cli_candidates", _builder_returning(forged),
    )
    response = _validation(client, event_id, revision, assignment_of(plan))
    assert response.status_code == 200, response.text
    body = _report(response)
    assert cast(dict[str, Any], body["summary"])["overall_status"] == "fail"
    item = cast(list[dict[str, Any]], body["candidates"])[index]
    assert item["target_capability"]["status"] == "fail"
    assert any(
        str(reason).startswith("target-port-not-poe-capable:")
        for reason in cast(list[Any], item["target_capability"]["reasons"])
    )
    assert item["independent_verdict"] == "fail"


def test_blocked_candidates_stay_not_run_and_unpromoted(client: TestClient) -> None:
    event_id = event(client)
    plan = full_plan(event_id, "2960x")
    revision = save(client, event_id, plan)
    document = _candidate_document(client, event_id, plan, revision)
    body = _report(_validation(client, event_id, revision, assignment_of(plan)))
    assert body["summary"]["parse_pass"] == 8
    assert body["summary"]["not_run"] == 24
    assert body["summary"]["failed_candidates"] == 0
    assert body["summary"]["overall_status"] == "pass"
    candidates = cast(list[dict[str, Any]], body["candidates"])
    assert len(candidates) == len(document.candidates)
    for item, candidate in zip(candidates, document.candidates, strict=True):
        if candidate.status is CandidateStatus.CANDIDATE:
            assert item["independent_verdict"] == "pass"
            assert item["candidate_text_present"] is True
        else:
            assert item["renderer_status"] == candidate.status.value
            assert item["independent_verdict"] == "not-run"
            assert item["candidate_text_present"] is False
            assert item["fail_closed_action"] is None
    registry = cast(list[dict[str, Any]], body["registry_coverage"])
    assert len(registry) == 72
    states = [cast(str, row["review_state"]) for row in registry]
    assert states.count("independently-reviewed") == 69
    assert states.count("independently-rejected") == 1
    assert states.count("pending-independent-review") == 2
    for item in candidates:
        if item["independent_verdict"] == "pass":
            scope = cast(dict[str, Any], item["scope"])
            assert scope["status"] == "allowed"
            assert scope["evidence_review_state"] == "independently-reviewed"


def test_zero_visible_candidates_is_not_full_verification(
    client: TestClient,
) -> None:
    event_id = event(client)
    first = full_plan(event_id, "9300")
    save(client, event_id, first)
    second = copy.deepcopy(first)
    second["assignments"][0]["location"] = "Hall B"
    revision = save(client, event_id, second)
    document = _candidate_document(client, event_id, second, revision)
    assert document.render_state.value == "no-supported-candidates"
    assert document.candidates == ()
    response = _validation(client, event_id, revision, assignment_of(second))
    assert response.status_code == 200, response.text
    body = _report(response)
    summary = cast(dict[str, Any], body["summary"])
    assert summary["total_candidates"] == 0
    assert summary["parse_pass"] == 0
    assert summary["failed_candidates"] == 0
    assert summary["overall_status"] == "pass"
    assert body["candidates"] == []
    assert response.headers[validation_api.VALIDATION_SCOPE_HEADER] == "full"


def test_only_blocked_candidates_report_stays_fail_closed(client: TestClient) -> None:
    event_id = event(client)
    plan = plan_of(event_id, "9300", ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ], with_serial=False)
    revision = save(client, event_id, plan)
    document = _candidate_document(client, event_id, plan, revision)
    assert document.render_state.value == "blocked"
    assert document.summary.candidates == 0
    body = _report(_validation(client, event_id, revision, assignment_of(plan)))
    summary = cast(dict[str, Any], body["summary"])
    assert summary["total_candidates"] == document.summary.total
    assert summary["parse_pass"] == 0
    assert summary["not_run"] == document.summary.total
    assert summary["failed_candidates"] == 0
    assert summary["overall_status"] == "pass"
    assert cast(dict[str, Any], body["device"])["identity_verdict"] == "fail"
    for item in cast(list[dict[str, Any]], body["candidates"]):
        assert item["renderer_status"] == "blocked"
        assert item["independent_verdict"] == "not-run"
        assert item["candidate_text_present"] is False


# --------------------------------------------------------------------------- #
# F. Category filter scope (review amendment C)
# --------------------------------------------------------------------------- #


def test_category_filter_scope_is_explicit_and_not_full(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    assignment_id = assignment_of(plan)
    full_response = _validation(client, event_id, revision, assignment_id)
    filtered_response = _validation(
        client, event_id, revision, assignment_id, "?category=access-vlan",
    )
    assert full_response.headers[validation_api.VALIDATION_SCOPE_HEADER] == "full"
    assert (
        filtered_response.headers[validation_api.VALIDATION_SCOPE_HEADER]
        == "filtered"
    )
    full = _report(full_response)
    filtered = _report(filtered_response)
    full_summary = cast(dict[str, Any], full["summary"])
    filtered_summary = cast(dict[str, Any], filtered["summary"])
    assert full_summary["total_candidates"] == 32
    assert filtered_summary["total_candidates"] == 4
    assert filtered_summary["parse_pass"] == 4
    assert filtered_summary["overall_status"] == "pass"
    categories = {
        item["category"] for item in cast(list[dict[str, Any]], filtered["candidates"])
    }
    assert categories == {"access-vlan"}
    full_source = cast(dict[str, Any], full["source"])
    filtered_source = cast(dict[str, Any], filtered["source"])
    assert (
        full_source["saved_revision_uuid"] == filtered_source["saved_revision_uuid"]
    )
    assert full_source["intent_fingerprint"] == filtered_source["intent_fingerprint"]
    assert full_source["preview_fingerprint"] == filtered_source["preview_fingerprint"]
    assert full_source["render_fingerprint"] != filtered_source["render_fingerprint"]
    assert full["report_fingerprint"] != filtered["report_fingerprint"]
    assert "scope" not in full
    assert "filter" not in full
    filtered_document = _candidate_document(
        client, event_id, plan, revision, "?category=access-vlan",
    )
    assert filtered_source["render_fingerprint"] == filtered_document.render_fingerprint
    assert len(filtered["candidates"]) == len(filtered_document.candidates)


def test_empty_filter_result_reports_zero_candidates(client: TestClient) -> None:
    event_id = event(client)
    plan = plan_of(event_id, "9300", ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ])
    revision = save(client, event_id, plan)
    document = _candidate_document(client, event_id, plan, revision)
    present = {candidate.category for candidate in document.candidates}
    absent = next(
        category for category in CandidateCategory if category not in present
    )
    response = _validation(
        client, event_id, revision, assignment_of(plan),
        f"?category={absent.value}",
    )
    assert response.status_code == 200, response.text
    assert response.headers[validation_api.VALIDATION_SCOPE_HEADER] == "filtered"
    body = _report(response)
    summary = cast(dict[str, Any], body["summary"])
    assert summary["total_candidates"] == 0
    assert summary["parse_pass"] == 0
    assert body["candidates"] == []
    assert "scope" not in body


def test_category_filter_cannot_unblock_blocked_candidates(client: TestClient) -> None:
    event_id = event(client)
    plan = full_plan(event_id, "2960x")
    revision = save(client, event_id, plan)
    response = _validation(
        client, event_id, revision, assignment_of(plan), "?category=access-vlan",
    )
    assert response.status_code == 200, response.text
    assert response.headers[validation_api.VALIDATION_SCOPE_HEADER] == "filtered"
    body = _report(response)
    summary = cast(dict[str, Any], body["summary"])
    assert summary["total_candidates"] == 4
    assert summary["parse_pass"] == 0
    assert summary["overall_status"] == "pass"
    for item in cast(list[dict[str, Any]], body["candidates"]):
        assert item["renderer_status"] == "blocked"
        assert item["independent_verdict"] == "not-run"
        assert item["candidate_text_present"] is False


# --------------------------------------------------------------------------- #
# G. OpenAPI / compatibility surface
# --------------------------------------------------------------------------- #


def test_openapi_describes_validation_route_and_report_schema(
    client: TestClient,
) -> None:
    openapi = cast(dict[str, Any], client.get(f"{API}/openapi.json").json())
    paths = cast(dict[str, dict[str, Any]], openapi["paths"])
    assert VALIDATION_PATH in paths
    assert set(paths[VALIDATION_PATH]) == {"get"}
    response_schema = cast(
        dict[str, Any],
        paths[VALIDATION_PATH]["get"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"],
    )
    assert response_schema.get("$ref") == "#/components/schemas/ValidationReport"
    components = cast(dict[str, Any], openapi["components"]["schemas"])
    assert "ValidationReport" in components
    assert "ValidationSafety" in components
    assert "ExpectedSource" not in components
    assert not any(
        "l2-cli-validation" in path and path.endswith("/schema")
        for path in paths
    )


def test_candidate_document_v1_contract_is_unchanged(client: TestClient) -> None:
    event_id, plan, revision = _saved_9300(client)
    document = render(client, event_id, str(revision["id"]), assignment_of(plan))
    assert document["contract_id"] == "cis-02b2-cisco-l2-cli-candidate-v1"
    assert document["render_schema_version"] == 1
    assert "validation_report" not in document
    assert "parser_verified" not in document
    assert document["safety"]["cli"] is None
    assert document["safety"]["executable"] is False
    for candidate in cast(list[dict[str, Any]], document["candidates"]):
        assert candidate["syntax_validation"]["parser_verified"] is False
        assert candidate["syntax_validation"]["level"] in {
            "dictionary-only", "not-run",
        }
    # The new read-only endpoint must not mutate the frozen candidate document.
    assert _validation(client, event_id, revision, assignment_of(plan)).status_code == 200
    assert render(client, event_id, str(revision["id"]), assignment_of(plan)) == document
