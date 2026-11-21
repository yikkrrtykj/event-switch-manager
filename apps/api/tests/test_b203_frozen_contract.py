"""CIS-02B2-03 frozen B2-02 contract and public-surface regression tests.

These tests pin the frozen B2-02 implementation, registry, contract identifiers
and public API surface. They are read-only assertions: B2-03 adds no public
field, route or Markdown artifact.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, cast, get_args, get_type_hints

import pytest
from fastapi.testclient import TestClient
from test_event_plans import ORIGIN
from test_l2_cli_candidates import full_plan, render
from test_layer2_intent import event, save

from event_switch_manager.app import create_app
from event_switch_manager.plan_api import router
from event_switch_manager.planning.command_evidence import (
    DEFAULT_REGISTRY,
    ROWS,
)
from event_switch_manager.planning.layer2_cli_candidates import (
    CONTRACT_ID,
    DICTIONARY_ID,
    RENDER_SCHEMA_VERSION,
    SUPPORTED_INTENT_SCHEMA_VERSION,
    SUPPORTED_PREVIEW_CONTRACT_ID,
    SUPPORTED_PREVIEW_SCHEMA_VERSION,
    CandidateStatus,
    L2CliCandidateDocument,
    RenderSafety,
    RenderState,
    SyntaxValidation,
    SyntaxValidationLevel,
    candidate_document_json_schema,
    candidate_fingerprint,
    render_fingerprint,
)
from event_switch_manager.planning.layer2_cli_validation import (
    VALIDATION_CONTRACT_ID,
    VALIDATION_SCHEMA_VERSION,
    ValidationReport,
    ValidationSafety,
)
from event_switch_manager.settings import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = REPO_ROOT / "apps" / "api" / "src" / "event_switch_manager"

FROZEN_SOURCE_HASHES: dict[str, str] = {
    "planning/layer2_cli_candidates.py": (
        "dbf5efb23aaae14098f5d885e80b87c96"
        "fd251e216b23d228a4473be3a7888bc"
    ),
    "planning/command_evidence.py": (
        "9d1d35bc3b4cb8d8e3e0967ff3d5cfc2"
        "39b5c1a4f48f0d46a64c421d1d3f1be2"
    ),
    "planning/command_evidence_reviews.py": (
        "9e83c6ea6a0eb7bf5c437a3a0e1aa143"
        "8cace84bffa914ede6a6338cea1a018c"
    ),
    "planning/layer2_config_preview.py": (
        "6e5b015cf4c2d5b59ebc3401aafae24a"
        "a86f8b23272f3da2b19e575f0dc931e0"
    ),
    "planning/layer2_intent.py": (
        "049abfb8d53300931a2abe280b7a087e"
        "248d96c5b988654401df9affde7ab119"
    ),
    "plan_api.py": (
        "577e5def00f211ba3f25bd1c89148f47"
        "6e78c67069608933c6db201635fba815"
    ),
}

FROZEN_REGISTRY_FINGERPRINT = (
    "3547df751ec024972841bcdd65e8050a2f65c069e357d07a60891851a2d9b42c"
)

FROZEN_DOCS = frozenset({
    "architecture.md",
    "cis-02a-layer2-intent.md",
    "cis-02b1-layer2-config-preview.md",
    "cisco-capability-evidence.md",
    "frontend-design.md",
    "pr2-data-model.md",
    "support-matrix.md",
    "v1-roadmap.md",
    "web-02a-port-settings.md",
    "web-02b-capability-preview.md",
    "web-02c-capability-controls.md",
})

FROZEN_ROUTES = frozenset({
    "/api/v1/events/{event_id}/plan-revisions",
    "/api/v1/events/{event_id}/plan-revisions/{revision_id}",
    (
        "/api/v1/events/{event_id}/plan-revisions/{revision_id}/assignments/"
        "{assignment_id}/cisco-capability"
    ),
    (
        "/api/v1/events/{event_id}/plan-revisions/{revision_id}/assignments/"
        "{assignment_id}/l2-cli-candidates"
    ),
    "/api/v1/events/{event_id}/plan-revisions/{revision_id}/export",
    "/api/v1/events/{event_id}/plan-revisions/{revision_id}/layer2-config-preview",
    (
        "/api/v1/events/{event_id}/plan-revisions/{revision_id}/"
        "layer2-config-preview/devices/{assignment_id}"
    ),
    "/api/v1/events/{event_id}/plan-revisions/{revision_id}/layer2-intent",
    "/api/v1/events/{event_id}/plan/capability-preview",
    "/api/v1/events/{event_id}/plan/seed",
    "/api/v1/events/{event_id}/plan/validate",
})

FROZEN_TOPICS = (
    "vlan", "vlan-name", "access-mode", "access-vlan", "trunk-mode",
    "native-vlan", "allowed-vlans", "port-channel-interface",
    "channel-group-static", "channel-group-lacp", "rapid-pvst",
    "vtp-transparent", "root-priority", "portfast", "bpdu-guard", "poe-mode",
    "speed", "duplex", "description", "admin-shutdown",
)


def _normalized_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("relative", sorted(FROZEN_SOURCE_HASHES))
def test_frozen_b202_source_files_are_byte_identical(relative: str) -> None:
    assert _normalized_sha256(SRC / relative) == FROZEN_SOURCE_HASHES[relative]


def test_frozen_evidence_registry_is_unchanged() -> None:
    assert DEFAULT_REGISTRY.fingerprint == FROZEN_REGISTRY_FINGERPRINT
    assert len(ROWS) == 72
    assert {row.topic.value for row in ROWS} == set(FROZEN_TOPICS)
    assert len({row.topic for row in ROWS}) == 20


def test_frozen_b202_contract_identifiers_are_unchanged() -> None:
    assert CONTRACT_ID == "cis-02b2-cisco-l2-cli-candidate-v1"
    assert RENDER_SCHEMA_VERSION == 1
    assert DICTIONARY_ID == "cis-02b2-l1-command-dictionary-v1"
    assert SUPPORTED_INTENT_SCHEMA_VERSION == 1
    assert SUPPORTED_PREVIEW_SCHEMA_VERSION == 1
    assert SUPPORTED_PREVIEW_CONTRACT_ID == "cis-02b1-layer2-config-preview-v1"
    assert {status.value for status in CandidateStatus} == {
        "candidate", "blocked", "unsupported",
    }
    assert {state.value for state in RenderState} == {
        "blocked", "no-supported-candidates", "review-candidates",
    }


def test_frozen_syntax_validation_cannot_express_parser_verified() -> None:
    assert {level.value for level in SyntaxValidationLevel} == {
        "not-run", "dictionary-only",
    }
    hints = get_type_hints(SyntaxValidation)
    assert get_args(hints["parser_verified"]) == (False,)
    assert SyntaxValidation().parser_verified is False
    schema = cast(dict[str, Any], candidate_document_json_schema())
    definitions = cast(dict[str, Any], schema["$defs"])
    assert definitions["SyntaxValidationLevel"]["enum"] == [
        "not-run", "dictionary-only",
    ]
    assert definitions["SyntaxValidation"]["properties"]["parser_verified"][
        "const"
    ] is False


def test_frozen_candidate_document_schema_and_safety_are_unchanged() -> None:
    schema = cast(dict[str, Any], candidate_document_json_schema())
    assert set(schema["required"]) == {
        "source", "assignment_id", "device", "render_state", "candidates",
        "unresolved_prerequisites", "evidence", "device_runtime_state",
        "safety", "summary", "deployment_blockers", "render_fingerprint",
    }
    assert "validation_report" not in schema["properties"]
    definitions = schema["$defs"]
    properties = definitions["RenderSafety"]["properties"]
    expected_constants: dict[str, object] = {
        "candidate_only": True,
        "executable": False,
        "deployable": False,
        "deployment_allowed": False,
        "device_connection": "none",
        "running_config_read": False,
        "device_writes_enabled": False,
        "device_runtime_state": "unknown-not-read",
        "hardware_verified": False,
    }
    for field, value in expected_constants.items():
        assert properties[field]["const"] == value
    assert properties["cli"]["type"] == "null"
    assert properties["deployment_artifact"]["type"] == "null"
    safety = RenderSafety()
    assert safety.candidate_only is True
    assert safety.hardware_verified is False
    assert safety.deployment_allowed is False
    assert safety.executable is False
    assert safety.deployable is False
    assert safety.device_writes_enabled is False
    assert safety.device_connection == "none"
    assert safety.running_config_read is False
    assert safety.device_runtime_state == "unknown-not-read"
    assert safety.cli is None
    assert safety.deployment_artifact is None


def test_frozen_fingerprint_rules_are_unchanged(tmp_path: Path) -> None:
    document = _api_document(tmp_path)
    assert document.render_fingerprint == render_fingerprint(document)
    assert all(
        candidate.candidate_fingerprint == candidate_fingerprint(candidate)
        for candidate in document.candidates
    )


def test_b203_internal_report_contract_is_separate_and_not_public() -> None:
    assert VALIDATION_SCHEMA_VERSION == 1
    assert VALIDATION_CONTRACT_ID == "cis-02b2-03-independent-cli-validation-v1"
    assert "validation_schema_version" in ValidationReport.model_fields
    safety = ValidationSafety()
    assert safety.hardware_verified is False
    assert safety.deployment_allowed is False
    assert safety.executable is False
    assert safety.deployable is False
    assert safety.independent_validation_is_not_execution_authorization is True
    assert safety.public_candidate_schema_unchanged is True


def test_public_api_route_surface_is_unchanged() -> None:
    routes = {getattr(route, "path", "") for route in router.routes}
    assert routes == set(FROZEN_ROUTES)
    assert not any(
        "validation" in path or "parser" in path or "b203" in path
        for path in routes
    )


def _l2_contract_routes(tmp_path: Path) -> set[str]:
    settings = Settings(database_path=tmp_path / "contract-routes.sqlite3")
    app = create_app(settings)
    return {
        getattr(route, "path", "")
        for route in app.routes
        if "l2-cli" in getattr(route, "path", "")
    }


def test_public_l2_candidate_routes_are_unchanged(tmp_path: Path) -> None:
    assert _l2_contract_routes(tmp_path) == {
        "/api/v1/contracts/l2-cli-candidates/schema",
        "/api/v1/contracts/l2-cli-candidates/schema/catalog",
        (
            "/api/v1/events/{event_id}/plan-revisions/{revision_id}/assignments/"
            "{assignment_id}/l2-cli-candidates"
        ),
        (
            "/api/v1/events/{event_id}/plan-revisions/{revision_id}/assignments/"
            "{assignment_id}/l2-cli-validation"
        ),
    }


def test_public_validation_route_is_added_without_changing_plan_api(
    tmp_path: Path,
) -> None:
    """R19 adds exactly one read-only route; the frozen plan_api surface stays."""
    settings = Settings(database_path=tmp_path / "public-validation-route.sqlite3")
    app = create_app(settings)
    paths = [getattr(route, "path", "") for route in app.routes]
    validation_route = (
        "/api/v1/events/{event_id}/plan-revisions/{revision_id}/assignments/"
        "{assignment_id}/l2-cli-validation"
    )
    assert paths.count(validation_route) == 1
    assert {getattr(route, "path", "") for route in router.routes} == set(
        FROZEN_ROUTES
    )


def test_no_new_repository_markdown_artifact_is_added() -> None:
    docs = REPO_ROOT / "docs"
    assert {path.name for path in docs.glob("*.md")} == set(FROZEN_DOCS)
    assert {path.name for path in REPO_ROOT.glob("*.md")} == {
        "README.md", "design.md",
    }


def _api_document(tmp_path: Path) -> L2CliCandidateDocument:
    """Render one frozen 9300 document through the real API."""
    settings = Settings(database_path=tmp_path / "frozen-contract.sqlite3")
    with TestClient(
        create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN},
    ) as client:
        event_id = event(client)
        plan = full_plan(event_id, "9300")
        revision = save(client, event_id, plan)
        document = render(
            client, event_id, str(revision["id"]),
            str(plan["assignments"][0]["id"]),
        )
        return L2CliCandidateDocument.model_validate(document)


def test_internal_report_schema_version_is_literal_one() -> None:
    hints = get_type_hints(ValidationReport)
    assert get_args(hints["validation_schema_version"]) == (1,)
