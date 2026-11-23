"""CIS-03-04A-1 trusted multi-platform L3 Registry selection tests."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from layer3_helpers import (
    make_l3_plan,
    revision_for,
)
from layer3_helpers import (
    test_only_evidence_registry as _test_only_registry,
)
from layer3_parser_helpers import expected_source
from test_event_plans import API, ORIGIN

from event_switch_manager.app import create_app
from event_switch_manager.planning.layer3_cli_candidates import (
    CandidateStatus,
    L3CandidateDocument,
    RenderBindingError,
    build_l3_cli_candidates,
)
from event_switch_manager.planning.layer3_cli_validation import (
    ValidationIntegrityError,
    validate_l3_candidates,
)
from event_switch_manager.planning.layer3_command_evidence import (
    DEFAULT_REGISTRY,
    CommandEvidenceRegistry,
)
from event_switch_manager.planning.layer3_intent import (
    L3DeviceIntent,
    Layer3Intent,
    build_layer3_intent,
)
from event_switch_manager.planning.layer3_registry_selection import (
    C9200_REVIEWED_REGISTRY,
    UNREVIEWED_PLATFORM_REGISTRY,
    UNREVIEWED_PLATFORM_REGISTRY_ID,
    RegistrySelectionError,
    assert_production_registry,
    select_l3_registry,
)
from event_switch_manager.planning.plan import PlanRevision
from event_switch_manager.settings import Settings

FROZEN_9300_FINGERPRINT = (
    "27d9c46f610b974de5570fb13e115260e2d109475a8d967704de9bb9ca6ef00b"
)
C9200 = {"core_pid": "C9200L-24P-4X", "core_family": "catalyst-9200"}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(
        create_app(Settings(database_path=tmp_path / "registry-selection.sqlite3")),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN},
    ) as session:
        yield session


def _event(client: TestClient) -> str:
    response = client.post(f"{API}/events", json={"name": "R52 registry", "management_vlan": 10})
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _save(client: TestClient, event_id: str, plan: dict[str, Any]) -> dict[str, Any]:
    changed = copy.deepcopy(plan)
    changed["event_id"] = event_id
    response = client.post(f"{API}/events/{event_id}/plan-revisions", json=changed)
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def _assignment(plan: dict[str, Any], hostname: str = "L3-Core") -> str:
    return str(next(item["id"] for item in plan["assignments"] if item["hostname"] == hostname))


def _path(event_id: str, revision_id: str, assignment_id: str, suffix: str) -> str:
    return (
        f"{API}/events/{event_id}/plan-revisions/{revision_id}"
        f"/assignments/{assignment_id}/{suffix}"
    )


def _intent(
    plan_kwargs: dict[str, Any] | None = None,
) -> tuple[PlanRevision, Layer3Intent, L3DeviceIntent]:
    revision = revision_for(make_l3_plan(
        "00000000-0000-0000-0000-000000000099",
        static_route_count=1,
        **(plan_kwargs or {}),
    ))
    intent = build_layer3_intent(revision)
    core = next(
        item for item in intent.devices if item.identity.hostname == "L3-Core"
    )
    return revision, intent, core


def _c9200_candidate_intent() -> tuple[PlanRevision, Layer3Intent, L3DeviceIntent]:
    plan = make_l3_plan(
        "00000000-0000-0000-0000-000000000099",
        core_pid="C9200L-24P-4X",
        core_family="catalyst-9200",
        core_image="17.12.4",
        core_license="Network Advantage",
        with_relay=False,
        with_default=False,
        static_route_count=1,
    )
    core = next(
        item for item in plan["assignments"] if item["hostname"] == "L3-Core"
    )
    plan["transit"] = None
    plan["default_routes"] = []
    plan["static_routes"] = [
        route for route in plan["static_routes"]
        if route["assignment_id"] == core["id"]
    ]
    for route in plan["static_routes"]:
        route["next_hop"] = {"kind": "ip", "address": "192.168.10.2"}
    revision = revision_for(plan)
    intent = build_layer3_intent(revision)
    core_intent = next(
        item for item in intent.devices if item.identity.hostname == "L3-Core"
    )
    return revision, intent, core_intent


def test_9300_selects_the_frozen_default_registry() -> None:
    _, _, core = _intent()
    selection = select_l3_registry(core.identity)
    assert selection.registry is DEFAULT_REGISTRY
    assert selection.assignment_id == core.identity.assignment_id
    assert selection.family is not None
    assert selection.evidence_approved is True
    assert selection.reason_code == "registry-selected-reviewed-platform"
    assert DEFAULT_REGISTRY.fingerprint == FROZEN_9300_FINGERPRINT
    assert_production_registry(DEFAULT_REGISTRY, core.identity)


def test_c9200_resolves_to_the_reviewed_registry_for_exact_scope() -> None:
    _, _, core = _intent(C9200)
    selection = select_l3_registry(core.identity)
    assert selection.registry is C9200_REVIEWED_REGISTRY
    assert selection.assignment_id == core.identity.assignment_id
    assert selection.family is not None
    assert selection.family.value == "catalyst-9200"
    assert selection.evidence_approved is True
    assert selection.reason_code == "registry-selected-reviewed-platform"
    assert selection.registry.registry_id == "cis-03-c9200-l3-command-evidence-v1"
    assert selection.registry.renderable_count == 4


def test_unknown_c9200_scope_falls_back_to_sentinel() -> None:
    for kwargs in (
        {"core_image": "17.12.5"},
        {"core_license": "Unknown License"},
        {"core_pid": "C9200-48T"},
    ):
        _, _, core = _intent({**C9200, **kwargs})
        selection = select_l3_registry(core.identity)
        assert selection.registry is UNREVIEWED_PLATFORM_REGISTRY
        assert selection.evidence_approved is False
        assert selection.registry.rows == ()
        assert selection.registry.registry_id == UNREVIEWED_PLATFORM_REGISTRY_ID


@pytest.mark.parametrize(
    "kwargs",
    (
        {"core_image": "17.12.5"},
        {"core_license": "Unknown License"},
        {"core_pid": "C9300-24T-A"},
    ),
)
def test_unknown_9300_scope_does_not_reuse_9300_evidence(
    kwargs: dict[str, Any],
) -> None:
    _, _, core = _intent(kwargs)
    selection = select_l3_registry(core.identity)
    assert selection.registry is UNREVIEWED_PLATFORM_REGISTRY
    assert selection.evidence_approved is False
    assert selection.registry.rows == ()


def test_cross_platform_and_unregistered_registries_fail_closed() -> None:
    _, _, core_9300 = _intent()
    _, _, core_9200 = _intent(C9200)
    with pytest.raises(RegistrySelectionError, match="registry-selection-mismatch"):
        assert_production_registry(DEFAULT_REGISTRY, core_9200.identity)
    with pytest.raises(RegistrySelectionError, match="registry-selection-mismatch"):
        assert_production_registry(UNREVIEWED_PLATFORM_REGISTRY, core_9300.identity)
    forged = CommandEvidenceRegistry(
        DEFAULT_REGISTRY.rows,
        registry_id=DEFAULT_REGISTRY.registry_id,
        production=True,
    )
    with pytest.raises(RegistrySelectionError, match="untrusted-production-registry"):
        assert_production_registry(forged, core_9300.identity)
    with pytest.raises(RegistrySelectionError, match="untrusted-production-registry"):
        assert_production_registry(_test_only_registry(), core_9300.identity)


def test_renderer_accepts_only_the_selected_production_registry() -> None:
    revision, intent, core = _intent()
    with pytest.raises(RenderBindingError, match="registry-selection-mismatch"):
        build_l3_cli_candidates(
            revision, intent, core.identity.assignment_id,
            UNREVIEWED_PLATFORM_REGISTRY,
        )
    document = build_l3_cli_candidates(
        revision, intent, core.identity.assignment_id, DEFAULT_REGISTRY,
    )
    assert document.source.command_evidence_registry_id == DEFAULT_REGISTRY.registry_id
    assert document.source.command_evidence_registry_fingerprint == FROZEN_9300_FINGERPRINT
    assert document.summary.candidates > 0

    revision_9200, intent_9200, core_9200 = _c9200_candidate_intent()
    with pytest.raises(RenderBindingError, match="registry-selection-mismatch"):
        build_l3_cli_candidates(
            revision_9200, intent_9200, core_9200.identity.assignment_id,
            DEFAULT_REGISTRY,
        )
    document_9200 = build_l3_cli_candidates(
        revision_9200, intent_9200, core_9200.identity.assignment_id,
        C9200_REVIEWED_REGISTRY,
    )
    assert document_9200.summary.candidates == 6
    assert all(
        item.candidate_text is not None
        for item in document_9200.candidates
        if item.status is CandidateStatus.CANDIDATE
    )


def test_renderer_and_validator_must_use_the_same_registry() -> None:
    revision, intent, core = _intent()
    document = build_l3_cli_candidates(
        revision, intent, core.identity.assignment_id, DEFAULT_REGISTRY,
    )
    expected = expected_source(revision, intent, document, DEFAULT_REGISTRY)
    with pytest.raises(ValidationIntegrityError, match="registry-selection-mismatch"):
        validate_l3_candidates(
            revision, intent, document, expected, core.identity.assignment_id,
            UNREVIEWED_PLATFORM_REGISTRY,
        )
    report = validate_l3_candidates(
        revision, intent, document, expected, core.identity.assignment_id,
        DEFAULT_REGISTRY,
    )
    assert report.source.command_evidence_registry_fingerprint == FROZEN_9300_FINGERPRINT


def test_test_only_second_registry_completes_the_same_full_flow() -> None:
    revision, intent, core = _intent()
    second = CommandEvidenceRegistry(
        _test_only_registry().rows,
        registry_id="cis-03-test-only-second-registry-v1",
        production=False,
    )
    document = build_l3_cli_candidates(
        revision, intent, core.identity.assignment_id, second,
        test_only_registry=True,
    )
    assert document.source.command_evidence_registry_id == second.registry_id
    assert document.source.command_evidence_registry_fingerprint == second.fingerprint
    expected = expected_source(revision, intent, document, second)
    report = validate_l3_candidates(
        revision, intent, document, expected, core.identity.assignment_id,
        second, test_only_registry=True,
    )
    assert report.validation_scope == "test-only"
    assert report.source.command_evidence_registry_id == second.registry_id
    assert report.source.command_evidence_registry_fingerprint == second.fingerprint
    assert any(item.candidate_text for item in document.candidates)

    with pytest.raises(RenderBindingError, match="non-production-registry-not-allowed"):
        build_l3_cli_candidates(
            revision, intent, core.identity.assignment_id, second,
        )
    with pytest.raises(ValidationIntegrityError, match="untrusted-production-registry"):
        validate_l3_candidates(
            revision, intent, document, expected, core.identity.assignment_id,
            second,
        )


def test_9300_api_still_binds_the_frozen_default_registry(client: TestClient) -> None:
    event_id = _event(client)
    plan = make_l3_plan(event_id, static_route_count=1)
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    candidate_response = client.get(
        _path(event_id, str(revision["id"]), assignment_id, "l3-cli-candidates"),
    )
    assert candidate_response.status_code == 200, candidate_response.text
    document = L3CandidateDocument.model_validate(candidate_response.json())
    assert document.source.command_evidence_registry_id == DEFAULT_REGISTRY.registry_id
    assert document.source.command_evidence_registry_fingerprint == FROZEN_9300_FINGERPRINT
    assert document.summary.candidates > 0
    validation_response = client.get(
        _path(event_id, str(revision["id"]), assignment_id, "l3-cli-validation"),
    )
    assert validation_response.status_code == 200, validation_response.text
    assert validation_response.headers["X-Validation-Scope"] == "full"
    assert validation_response.json()["source"]["command_evidence_registry_id"] == (
        DEFAULT_REGISTRY.registry_id
    )


def test_c9200_api_returns_reviewed_candidates(client: TestClient) -> None:
    event_id = _event(client)
    plan = make_l3_plan(
        event_id, core_pid="C9200L-24P-4X", core_family="catalyst-9200",
        core_image="17.12.4", core_license="Network Advantage",
        with_relay=False, with_default=False, static_route_count=1,
    )
    core = next(
        item for item in plan["assignments"] if item["hostname"] == "L3-Core"
    )
    plan["transit"] = None
    plan["default_routes"] = []
    plan["static_routes"] = [
        route for route in plan["static_routes"]
        if route["assignment_id"] == core["id"]
    ]
    for route in plan["static_routes"]:
        route["next_hop"] = {"kind": "ip", "address": "192.168.10.2"}
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    candidate_response = client.get(
        _path(event_id, str(revision["id"]), assignment_id, "l3-cli-candidates"),
    )
    assert candidate_response.status_code == 200, candidate_response.text
    document = L3CandidateDocument.model_validate(candidate_response.json())
    assert document.source.command_evidence_registry_id == (
        C9200_REVIEWED_REGISTRY.registry_id
    )
    assert document.summary.candidates == 6
    assert all(
        item.candidate_text is None
        for item in document.candidates if item.status is CandidateStatus.BLOCKED
    )

    validation_response = client.get(
        _path(event_id, str(revision["id"]), assignment_id, "l3-cli-validation"),
    )
    assert validation_response.status_code == 200, validation_response.text
    body = validation_response.json()
    assert body["source"]["command_evidence_registry_id"] == (
        C9200_REVIEWED_REGISTRY.registry_id
    )
    assert body["summary"]["passed"] == 6
    assert body["summary"]["failed"] == 0
    assert body["summary"]["blocked"] == 2
