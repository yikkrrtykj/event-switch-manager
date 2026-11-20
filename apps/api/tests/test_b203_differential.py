"""CIS-02B2-03 Renderer/Parser differential corpus.

The corpus consumes the frozen five-family B2-02 fixture, real renderer
documents for cleanup/migration/protocol/routed/Stack/core-role scenarios and
tampered-document negative cases. Every status=candidate text is independently
parsed; every blocked/unsupported candidate stays blocked with no promotion.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Iterator
from functools import cache
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from b203_corpus import (
    FROZEN_FAMILY_COUNTS,
    FROZEN_RENDER_FINGERPRINTS,
    deterministic_plan,
    render_plan,
    render_sequence,
)
from fastapi.testclient import TestClient
from test_event_plans import ORIGIN
from test_l2_cli_candidates import (
    FAMILIES,
    assignment_of,
    full_plan,
    render,
    saved_document,
)
from test_layer2_intent import event, make_plan, make_stack_plan, save

from event_switch_manager.app import create_app
from event_switch_manager.planning.layer2_cli_candidates import (
    CandidateCategory,
    CandidateStatus,
    L2CliCandidateDocument,
    RenderStackMember,
    RiskClass,
    SyntaxValidationLevel,
)
from event_switch_manager.planning.layer2_cli_validation import (
    ExpectedSource,
    ValidationReport,
    Verdict,
    canonical_sha256,
    recompute_candidate_fingerprint,
    recompute_render_fingerprint,
    validate_candidate_document,
)
from event_switch_manager.settings import Settings

FROZEN_TOPICS: dict[str, tuple[str, ...]] = {
    "2960x": (
        "admin-shutdown", "channel-group-lacp", "description", "duplex",
        "poe-mode", "port-channel-interface", "speed",
    ),
    "3850": (
        "admin-shutdown", "channel-group-lacp", "description", "duplex",
        "poe-mode", "port-channel-interface", "speed",
    ),
    "9200": (
        "access-mode", "access-vlan", "admin-shutdown", "allowed-vlans",
        "bpdu-guard", "channel-group-lacp", "duplex", "poe-mode",
        "port-channel-interface", "portfast", "speed", "trunk-mode", "vlan",
        "vlan-name",
    ),
    "9300": (
        "access-mode", "access-vlan", "admin-shutdown", "allowed-vlans",
        "bpdu-guard", "channel-group-lacp", "duplex", "poe-mode",
        "port-channel-interface", "portfast", "speed", "trunk-mode", "vlan",
        "vlan-name",
    ),
    "c1000": (
        "admin-shutdown", "channel-group-lacp", "description", "duplex",
        "poe-mode", "port-channel-interface", "speed",
    ),
}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "b203-differential.sqlite3")
    with TestClient(
        create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN},
    ) as session:
        yield session


@cache
def _frozen_document(key: str) -> L2CliCandidateDocument:
    plan = deterministic_plan(full_plan(str(uuid4()), key))
    return render_plan(plan)


def _status_counts(
    document: L2CliCandidateDocument,
) -> tuple[int, int, int]:
    statuses = [candidate.status for candidate in document.candidates]
    return (
        statuses.count(CandidateStatus.CANDIDATE),
        statuses.count(CandidateStatus.BLOCKED),
        statuses.count(CandidateStatus.UNSUPPORTED),
    )


def _tamper_at(
    document: L2CliCandidateDocument,
    index: int,
    changes: dict[str, Any],
    *,
    recompute: bool = True,
) -> L2CliCandidateDocument:
    candidates = list(document.candidates)
    changed = candidates[index].model_copy(update=changes)
    if recompute:
        changed = changed.model_copy(update={
            "candidate_fingerprint": recompute_candidate_fingerprint(changed),
        })
    candidates[index] = changed
    tampered = document.model_copy(update={"candidates": tuple(candidates)})
    if recompute:
        tampered = tampered.model_copy(update={
            "render_fingerprint": recompute_render_fingerprint(tampered),
        })
    return tampered


def _index_of(
    document: L2CliCandidateDocument,
    *,
    category: str | None = None,
    status: CandidateStatus | None = None,
) -> int:
    for index, candidate in enumerate(document.candidates):
        if category is not None and candidate.category.value != category:
            continue
        if status is not None and candidate.status is not status:
            continue
        return index
    raise AssertionError(f"no candidate for {category!r}/{status!r}")


# --------------------------------------------------------------------------- #
# Frozen five-family differential corpus
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("key", sorted(FAMILIES))
def test_frozen_five_family_renderer_output_is_stable(key: str) -> None:
    document = _frozen_document(key)
    expected_counts = FROZEN_FAMILY_COUNTS[key]
    assert _status_counts(document) == expected_counts
    assert len(document.candidates) == 32
    assert document.render_fingerprint == FROZEN_RENDER_FINGERPRINTS[key]
    assert document.render_schema_version == 1
    assert document.contract_id == "cis-02b2-cisco-l2-cli-candidate-v1"
    assert document.safety.candidate_only is True
    assert document.safety.hardware_verified is False
    assert document.safety.deployment_allowed is False
    assert document.safety.executable is False
    assert document.safety.deployable is False
    assert document.safety.device_writes_enabled is False
    assert document.safety.device_connection == "none"
    assert document.safety.running_config_read is False
    assert document.device_runtime_state == "unknown-not-read"
    assert document.safety.cli is None
    assert document.safety.deployment_artifact is None
    for candidate in document.candidates:
        assert candidate.syntax_validation.parser_verified is False
        if candidate.status is CandidateStatus.CANDIDATE:
            assert candidate.syntax_validation.level is (
                SyntaxValidationLevel.DICTIONARY_ONLY
            )
            assert candidate.candidate_text is not None
        else:
            assert candidate.syntax_validation.level is (
                SyntaxValidationLevel.NOT_RUN
            )
            assert candidate.candidate_text is None
        assert candidate.candidate_fingerprint == (
            recompute_candidate_fingerprint(candidate)
        )
    assert document.render_fingerprint == recompute_render_fingerprint(document)


@pytest.mark.parametrize("key", sorted(FAMILIES))
def test_frozen_document_passes_independent_validation(key: str) -> None:
    document = _frozen_document(key)
    report = validate_candidate_document(document)

    assert report.summary.overall_status is Verdict.PASS
    assert report.integrity.status is Verdict.PASS
    assert report.topology_review.status is Verdict.PASS
    assert report.device.identity_verdict is Verdict.PASS
    assert report.summary.total_candidates == 32
    assert report.summary.parse_pass == FROZEN_FAMILY_COUNTS[key][0]
    assert report.summary.not_run == FROZEN_FAMILY_COUNTS[key][1]
    assert report.summary.parse_fail == 0
    assert report.summary.failed_candidates == 0
    assert report.summary.registry_rows == 72
    assert report.summary.registry_reviewed == 69
    assert report.summary.registry_rejected == 1
    assert report.summary.registry_unreviewed == 2
    assert report.summary.topics_parsed == FROZEN_TOPICS[key]
    assert report.source.render_fingerprint == document.render_fingerprint
    assert report.assignment_id == document.assignment_id
    assert report.safety.independent_validation_is_not_execution_authorization
    assert report.safety.public_candidate_schema_unchanged

    for candidate, candidate_report in zip(
        document.candidates, report.candidates, strict=True,
    ):
        assert candidate_report.candidate_id == candidate.candidate_id
        assert candidate_report.candidate_fingerprint_match is True
        assert candidate_report.risk.status is Verdict.PASS
        if candidate.status is CandidateStatus.CANDIDATE:
            assert candidate_report.parse.status is Verdict.PASS
            assert candidate_report.scope.status.value == "allowed"
            assert candidate_report.scope.evidence_id is not None
            assert candidate_report.security.status is Verdict.PASS
            assert candidate_report.semantics.status is Verdict.PASS
            assert candidate_report.independent_verdict is Verdict.PASS
            assert candidate_report.fail_closed_action is None
            assert candidate_report.parse.topic is not None
        else:
            assert candidate_report.parse.status is Verdict.NOT_RUN
            assert candidate_report.parse.topic is None
            assert candidate_report.independent_verdict is Verdict.NOT_RUN
            assert candidate_report.scope.status.value == "not-run"
            assert candidate_report.candidate_text_present is False


@pytest.mark.parametrize("key", sorted(FAMILIES))
def test_report_is_deterministic_and_round_trips_through_the_typed_model(
    key: str,
) -> None:
    document = _frozen_document(key)
    first = validate_candidate_document(document)
    second = validate_candidate_document(document)
    assert first.report_fingerprint == second.report_fingerprint
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    payload = first.model_dump(mode="json")
    material = dict(payload)
    material.pop("report_fingerprint")
    assert first.report_fingerprint == canonical_sha256(material)
    round_tripped = ValidationReport.model_validate(payload)
    assert round_tripped.report_fingerprint == first.report_fingerprint
    with pytest.raises(ValueError):
        ValidationReport.model_validate({**payload, "unexpected": 1})


def test_report_binds_every_candidate_and_source_field() -> None:
    document = _frozen_document("9300")
    report = validate_candidate_document(
        document,
        expected=ExpectedSource(
            saved_revision_uuid=document.source.saved_revision_uuid,
            revision_number=document.source.revision_number,
            revision_canonical_hash=document.source.revision_canonical_hash,
            intent_fingerprint=document.source.intent_fingerprint,
            preview_fingerprint=document.source.preview_fingerprint,
            render_fingerprint=document.render_fingerprint,
            assignment_id=document.assignment_id,
        ),
    )
    assert report.integrity.expected_source_match is True
    assert report.integrity.status is Verdict.PASS
    assert report.source.saved_revision_uuid == document.source.saved_revision_uuid
    assert report.source.revision_canonical_hash == (
        document.source.revision_canonical_hash
    )
    assert report.source.intent_fingerprint == document.source.intent_fingerprint
    assert report.source.preview_fingerprint == document.source.preview_fingerprint
    assert report.source.command_evidence_registry_id == (
        "cis-02b2-l1-command-evidence-v1"
    )
    assert len(report.source.command_evidence_fingerprint) == 64
    assert {item.candidate_id for item in report.candidates} == {
        candidate.candidate_id for candidate in document.candidates
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("saved_revision_uuid", uuid4()),
        ("revision_number", 999),
        ("revision_canonical_hash", "0" * 64),
        ("intent_fingerprint", "0" * 64),
        ("preview_fingerprint", "0" * 64),
        ("render_fingerprint", "0" * 64),
        ("assignment_id", uuid4()),
    ],
)
def test_expected_source_mismatch_fails_closed(field: str, value: object) -> None:
    document = _frozen_document("9300")
    constructor = cast(Callable[..., ExpectedSource], ExpectedSource)
    report = validate_candidate_document(
        document, expected=constructor(**{field: value}),
    )
    assert report.summary.overall_status is Verdict.FAIL
    assert report.integrity.expected_source_match is False
    assert f"expected-source-mismatch:{field}" in report.integrity.failures
    for candidate_report in report.candidates:
        assert candidate_report.independent_verdict is Verdict.FAIL
        assert candidate_report.fail_closed_action == (
            "reject-document-until-source-integrity-passes"
        )


def test_report_contains_no_execution_order_or_deployment_fields() -> None:
    report = validate_candidate_document(_frozen_document("9300"))
    payload = report.model_dump(mode="json")
    forbidden = {
        "commands", "command_lines", "cli_lines", "configuration", "config",
        "config_snippet", "script", "execution_order", "execution_plan",
        "sequence", "order", "paste_ready", "deployment_script",
    }

    def keys(value: object) -> set[str]:
        found: set[str] = set()
        if isinstance(value, dict):
            for key, item in value.items():
                found.add(str(key))
                found |= keys(item)
        elif isinstance(value, list):
            for item in value:
                found |= keys(item)
        return found

    assert keys(payload) & forbidden == set()
    assert payload["safety"]["cli"] is None
    assert payload["safety"]["deployment_artifact"] is None
    assert report.safety.candidate_only is True
    assert report.safety.executable is False
    assert report.safety.deployable is False
    assert report.safety.deployment_allowed is False
    assert report.safety.hardware_verified is False
    assert report.safety.device_connection == "none"
    assert report.safety.running_config_read is False
    assert report.safety.device_writes_enabled is False
    assert report.safety.device_runtime_state == "unknown-not-read"


# --------------------------------------------------------------------------- #
# Category filter and cross-device isolation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("key", ["9200", "9300"])
def test_category_filtered_documents_validate_independently(key: str) -> None:
    plan = deterministic_plan(full_plan(str(uuid4()), key))
    full = render_plan(plan)
    categories = tuple(dict.fromkeys(
        candidate.category for candidate in full.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    ))[:3]
    filtered = render_plan(plan, categories=categories)
    assert {candidate.category for candidate in filtered.candidates} <= set(
        categories
    )
    report = validate_candidate_document(filtered)
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.parse_pass == sum(
        1 for candidate in filtered.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    )


def test_cross_device_documents_are_isolated() -> None:
    first_plan = full_plan(str(uuid4()), "9300")
    second_plan = full_plan(str(uuid4()), "9300")
    first = render_plan(first_plan)
    second = render_plan(second_plan)
    assert first.assignment_id != second.assignment_id
    first_ids = {candidate.candidate_id for candidate in first.candidates}
    second_ids = {candidate.candidate_id for candidate in second.candidates}
    assert first_ids.isdisjoint(second_ids)
    assert first.render_fingerprint != second.render_fingerprint
    first_report = validate_candidate_document(first)
    second_report = validate_candidate_document(second)
    assert first_report.summary.overall_status is Verdict.PASS
    assert second_report.summary.overall_status is Verdict.PASS
    assert first_report.assignment_id != second_report.assignment_id


# --------------------------------------------------------------------------- #
# Cleanup, migration, protocol, routed, core role and Stack scenarios
# --------------------------------------------------------------------------- #


def _cleanup_document() -> L2CliCandidateDocument:
    first = full_plan(str(uuid4()), "9300")
    first["physical_interfaces"][0]["settings"]["admin_state"] = "down"
    second = copy.deepcopy(first)
    for field in ("description", "portfast", "bpdu_guard"):
        second["physical_interfaces"][0]["settings"].pop(field, None)
    second["physical_interfaces"][0]["settings"]["admin_state"] = "up"
    return render_sequence([first, second])


def test_cleanup_candidates_are_never_promoted() -> None:
    document = _cleanup_document()
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    cleanup = [
        candidate for candidate in document.candidates
        if candidate.provenance.cleanup
        or "removal-not-rendered" in candidate.blocking_reasons
        or "baseline-only-cleanup-requires-field-verification"
        in candidate.blocking_reasons
    ]
    assert cleanup
    for candidate in cleanup:
        assert candidate.status is not CandidateStatus.CANDIDATE
        assert candidate.candidate_text is None
        assert candidate.syntax_validation.level is SyntaxValidationLevel.NOT_RUN
    texts = [
        candidate.candidate_text for candidate in document.candidates
        if candidate.candidate_text is not None
    ]
    assert all(text == "no shutdown" for text in texts)
    assert report.summary.parse_pass == len(texts)


def _migration_document() -> tuple[L2CliCandidateDocument, dict[str, Any]]:
    first = full_plan(str(uuid4()), "9300")
    second = copy.deepcopy(first)
    second["port_channels"][0]["number"] = 2
    second["logical_interfaces"][0]["name"] = "Port-channel2"
    return render_sequence([first, second]), second


def test_channel_migration_candidates_are_never_promoted() -> None:
    document, plan = _migration_document()
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    channel_candidates = [
        candidate for candidate in document.candidates
        if candidate.category.value in {"port-channel", "lacp-mode"}
    ]
    assert channel_candidates
    for candidate in channel_candidates:
        if candidate.status is CandidateStatus.CANDIDATE:
            assert candidate.candidate_text is not None
        else:
            assert candidate.candidate_text is None
    assert report.summary.parse_pass == sum(
        1 for candidate in document.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    )


def test_aggregation_protocol_switch_candidates_are_never_promoted() -> None:
    first = full_plan(str(uuid4()), "9300")
    second = copy.deepcopy(first)
    second["port_channels"][0]["lacp"] = "static"
    document = render_sequence([first, second])
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    channel_candidates = [
        candidate for candidate in document.candidates
        if candidate.category.value in {"port-channel", "lacp-mode"}
    ]
    assert channel_candidates
    assert all(
        candidate.candidate_text is None for candidate in channel_candidates
        if candidate.status is not CandidateStatus.CANDIDATE
    )
    for candidate_report in report.candidates:
        assert candidate_report.risk.status is Verdict.PASS


def test_routed_port_target_is_never_rendered_as_layer2() -> None:
    event_id = str(uuid4())
    plan = make_plan(
        event_id,
        pid="C9300L-24P-4X",
        family="catalyst-9300",
        image="17.12.4",
        license_name="Network Advantage",
        ports=[
            {
                "name": "Gi1/0/1",
                "settings": {"mode": "routed", "address": "192.0.2.1/24"},
            },
            {
                "name": "Gi1/0/2",
                "settings": {
                    "mode": "access", "access_vlan": 20,
                    "description": "Routed neighbor",
                },
            },
        ],
    )
    document = render_plan(plan)
    routed = [
        candidate for candidate in document.candidates
        if candidate.target.name == "Gi1/0/1"
        and candidate.category.value in {"access-mode", "access-vlan"}
    ]
    assert routed
    for candidate in routed:
        assert candidate.status is CandidateStatus.UNSUPPORTED
        assert "routed-port-not-l2" in candidate.blocking_reasons
        assert candidate.candidate_text is None
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.scope_blocked == 0
    assert report.topology_review.status is Verdict.PASS


def test_core_role_blocks_topology_and_edge_commands() -> None:
    plan = full_plan(str(uuid4()), "9300")
    plan["assignments"][0]["role"] = "core"
    document = render_plan(plan)
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    topology = [
        candidate for candidate in document.candidates
        if candidate.category.value in {
            "rapid-pvst", "vtp-transparent", "root-priority",
        }
    ]
    assert topology
    for candidate in topology:
        assert candidate.status is CandidateStatus.BLOCKED
        assert candidate.risk_class.value == "R5"
        assert candidate.candidate_text is None
    edge = [
        candidate for candidate in document.candidates
        if candidate.category.value in {"portfast", "bpdu-guard"}
    ]
    assert edge
    for candidate in edge:
        assert candidate.status is CandidateStatus.BLOCKED
        assert candidate.risk_class.value == "R5"
    for candidate_report in report.candidates:
        assert candidate_report.independent_verdict is not Verdict.FAIL


def test_resolved_stack_document_validates() -> None:
    plan = make_stack_plan(str(uuid4()))
    document = render_plan(plan)
    assert document.device.stack_identity == "resolved"
    assert len(document.device.stack_members) == 2
    report = validate_candidate_document(document)
    assert report.device.identity_verdict is Verdict.PASS
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.parse_pass == sum(
        1 for candidate in document.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    )


def test_unresolved_stack_document_is_not_promoted() -> None:
    plan = make_stack_plan(str(uuid4()))
    plan["stacks"][0]["members"][1]["state"] = "missing"
    document = render_plan(plan)
    report = validate_candidate_document(document)
    assert report.device.identity_verdict is Verdict.FAIL
    assert "stack-member-not-ready" in report.device.identity_reasons
    assert report.summary.parse_pass == 0
    assert report.summary.failed_candidates == 0
    assert report.summary.overall_status is Verdict.PASS
    for candidate in document.candidates:
        assert candidate.status is CandidateStatus.BLOCKED
        assert candidate.candidate_text is None


@pytest.mark.parametrize(
    ("key", "image", "expected_parse"),
    [
        ("2960x", "15.2(7)E1a", 0),
        ("3850", "16.12.10a", 3),
        ("9200", "17.12.5", 0),
        ("9300", "17.12.5", 0),
        ("c1000", "15.2(7)E", 0),
    ],
)
def test_identity_only_and_aggregation_only_releases_do_not_render(
    key: str, image: str, expected_parse: int,
) -> None:
    plan = full_plan(str(uuid4()), key)
    plan["assignments"][0]["software"]["image"] = image
    document = render_plan(plan)
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.parse_pass == expected_parse
    assert report.summary.failed_candidates == 0
    assert all(
        candidate.candidate_text is None
        for candidate in document.candidates
        if candidate.status is not CandidateStatus.CANDIDATE
    )


def test_bpdu_guard_disable_is_reviewed_for_9300_and_blocked_for_9200() -> None:
    disabled = full_plan(str(uuid4()), "9300")
    disabled["physical_interfaces"][0]["settings"]["bpdu_guard"] = "disabled"
    document = render_plan(disabled)
    texts = [
        candidate.candidate_text for candidate in document.candidates
        if candidate.candidate_text is not None
    ]
    assert "spanning-tree bpduguard disable" in texts
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    disable_report = next(
        item for item in report.candidates
        if item.category == "bpdu-guard" and item.parse.topic == "bpdu-guard"
        and item.independent_verdict is Verdict.PASS
    )
    assert disable_report.parse.parameters["bpdu-guard"] == "disable"

    disabled_9200 = full_plan(str(uuid4()), "9200")
    disabled_9200["physical_interfaces"][0]["settings"]["bpdu_guard"] = "disabled"
    document_9200 = render_plan(disabled_9200)
    assert all(
        candidate.candidate_text != "spanning-tree bpduguard disable"
        for candidate in document_9200.candidates
    )
    report_9200 = validate_candidate_document(document_9200)
    assert report_9200.summary.overall_status is Verdict.PASS


def test_portfast_disable_form_is_not_reviewed() -> None:
    plan = full_plan(str(uuid4()), "9300")
    plan["physical_interfaces"][0]["settings"]["portfast"] = "disabled"
    document = render_plan(plan)
    portfast = [
        candidate for candidate in document.candidates
        if candidate.category.value == "portfast"
    ]
    assert portfast
    for candidate in portfast:
        assert candidate.candidate_text is None
        assert candidate.status is CandidateStatus.BLOCKED
        assert "parameter-not-allowed:portfast" in candidate.blocking_reasons
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS


# --------------------------------------------------------------------------- #
# Management/link role, aggregation-gate and routed-boundary differential cases
# --------------------------------------------------------------------------- #


def _link_role_plan(*, admin_down: bool = False) -> dict[str, Any]:
    plan = full_plan(str(uuid4()), "9300")
    endpoints = [
        plan["physical_interfaces"][0]["id"],
        plan["physical_interfaces"][1]["id"],
    ]
    plan["links"] = [{"id": str(uuid4()), "endpoints": endpoints}]
    if admin_down:
        plan["physical_interfaces"][0]["settings"]["admin_state"] = "down"
    return plan


def test_link_role_blocks_edge_and_shutdown_commands() -> None:
    document = render_plan(_link_role_plan(admin_down=True))
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.failed_candidates == 0
    port0 = "Gi1/0/1"
    for candidate in document.candidates:
        if candidate.target.name != port0:
            continue
        if candidate.category.value in {"portfast", "bpdu-guard"}:
            assert candidate.status is CandidateStatus.BLOCKED
            assert candidate.risk_class.value == "R5"
            assert candidate.candidate_text is None
        if candidate.category.value == "admin-shutdown":
            assert candidate.status is CandidateStatus.BLOCKED
            assert candidate.risk_class.value == "R5"
            assert candidate.candidate_text is None
    assert report.summary.parse_pass == sum(
        1 for candidate in document.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    )


def test_channel_object_replacement_is_blocked_without_promotion() -> None:
    first = full_plan(str(uuid4()), "9300")
    second = copy.deepcopy(first)
    second["logical_interfaces"][0]["id"] = str(uuid4())
    document = render_sequence([first, second])
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.parse_pass == sum(
        1 for candidate in document.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    )
    channel_records = [
        candidate for candidate in document.candidates
        if candidate.category.value in {"port-channel", "lacp-mode"}
    ]
    assert channel_records
    for candidate in channel_records:
        if candidate.status is not CandidateStatus.CANDIDATE:
            assert candidate.candidate_text is None


def test_removed_channel_member_cleanup_is_blocked_without_promotion() -> None:
    first = full_plan(str(uuid4()), "9300")
    second = copy.deepcopy(first)
    second["port_channels"][0]["member_ids"] = [
        second["port_channels"][0]["member_ids"][1],
    ]
    document = render_sequence([first, second])
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    texts = [
        candidate.candidate_text for candidate in document.candidates
        if candidate.candidate_text is not None
    ]
    assert all(not text.casefold().startswith(("no ", "default ")) for text in texts)
    for candidate in document.candidates:
        if candidate.status is not CandidateStatus.CANDIDATE:
            assert candidate.candidate_text is None


def test_member_mode_transition_is_blocked_without_promotion() -> None:
    first = full_plan(str(uuid4()), "9300")
    second = copy.deepcopy(first)
    second["physical_interfaces"][2]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
    }
    document = render_sequence([first, second])
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.failed_candidates == 0
    for candidate in document.candidates:
        if candidate.status is not CandidateStatus.CANDIDATE:
            assert candidate.candidate_text is None


def test_routed_aggregate_boundary_is_never_rendered_as_l2() -> None:
    from test_l2_cli_candidate_round5 import routed_plan

    plan = routed_plan(str(uuid4()))
    document = render_plan(plan)
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.failed_candidates == 0
    for candidate in document.candidates:
        if candidate.category.value in {
            "port-channel", "lacp-mode", "access-mode", "access-vlan",
            "trunk-mode", "native-vlan", "allowed-vlans", "portfast",
            "bpdu-guard",
        }:
            assert candidate.status is not CandidateStatus.CANDIDATE
            assert candidate.candidate_text is None


def test_l2_to_routed_transition_keeps_cleanup_blocked() -> None:
    from test_l2_cli_candidate_round5 import l2_plan

    first = l2_plan(str(uuid4()))
    second = copy.deepcopy(first)
    for index in range(len(second["physical_interfaces"])):
        second["physical_interfaces"][index]["settings"] = {"mode": "routed"}
    second["port_channels"][0]["settings"] = {
        "mode": "routed", "address": "192.0.2.254/24",
    }
    document = render_sequence([first, second])
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.failed_candidates == 0
    assert all(
        not (candidate.candidate_text or "").casefold().startswith("no ")
        for candidate in document.candidates
    )


# --------------------------------------------------------------------------- #
# Comprehensive reviewed-grammar differential plan
# --------------------------------------------------------------------------- #

COMPREHENSIVE_FAMILIES: dict[str, tuple[str, str, str, str | None]] = {
    "2960x": ("WS-C2960X-24PS-L", "catalyst-2960x", "15.2(7)E", "LAN Base"),
    "3850": ("WS-C3850-24P", "catalyst-3850", "16.12.12", "IP Base"),
    "9200": ("C9200L-24P-4X", "catalyst-9200", "17.12.4", "Network Advantage"),
    "9300": ("C9300L-24P-4X", "catalyst-9300", "17.12.4", "Network Advantage"),
    "c1000": ("C1000-24P-4G-L", "catalyst-c1000", "15.2(7)E1", None),
}

INTERFACE_FORM_SET = frozenset({
    "channel-group-lacp", "channel-group-static", "duplex", "no-shutdown",
    "poe-mode", "port-channel-interface", "shutdown", "speed",
})
L2_FORM_SET = frozenset({
    "access-mode", "access-vlan", "allowed-vlans", "bpdu-guard",
    "portfast", "portfast-trunk", "trunk-mode", "vlan", "vlan-name",
})


def _multi_channel_plan(key: str) -> dict[str, Any]:
    pid, family, image, license_name = COMPREHENSIVE_FAMILIES[key]
    settings = [
        {
            "mode": "access", "access_vlan": 20,
            "description": "Players desk", "admin_state": "up",
            "speed": 1000, "duplex": "full", "poe_mode": "auto",
            "portfast": "edge", "bpdu_guard": "enabled",
        },
        {
            "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20, 30],
            "description": "Uplink trunk", "admin_state": "down",
            "speed": "auto", "duplex": "half", "poe_mode": "static",
            "portfast": "edge-trunk", "bpdu_guard": "enabled",
        },
        {
            "mode": "access", "access_vlan": 20,
            "description": "Channel member one", "speed": 100,
            "duplex": "auto", "poe_mode": "never",
        },
        {
            "mode": "access", "access_vlan": 20,
            "description": "Channel member two", "admin_state": "down",
        },
        {
            "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20],
            "description": "Static member one", "portfast": "edge-trunk",
        },
        {
            "mode": "access", "access_vlan": 20,
            "description": "Static member two", "poe_mode": "auto",
        },
    ]
    plan = make_plan(
        str(uuid4()), pid=pid, family=family, image=image,
        license_name=license_name,
        ports=[
            {"name": f"Gi1/0/{index + 1}", "settings": item}
            for index, item in enumerate(settings)
        ],
    )
    assignment_id = plan["assignments"][0]["id"]
    physical = plan["physical_interfaces"]
    plan["logical_interfaces"] = [
        {
            "id": str(uuid4()), "assignment_id": assignment_id,
            "name": "Port-channel1", "kind": "port-channel",
        },
        {
            "id": str(uuid4()), "assignment_id": assignment_id,
            "name": "Port-channel2", "kind": "port-channel",
        },
    ]
    plan["port_channels"] = [
        {
            "interface_id": plan["logical_interfaces"][0]["id"],
            "number": 1,
            "member_ids": [physical[2]["id"], physical[3]["id"]],
            "settings": {
                "mode": "access", "access_vlan": 20,
                "description": "Aggregate one", "admin_state": "up",
                "portfast": "edge", "bpdu_guard": "enabled",
            },
            "lacp": "active",
        },
        {
            "interface_id": plan["logical_interfaces"][1]["id"],
            "number": 2,
            "member_ids": [physical[4]["id"], physical[5]["id"]],
            "settings": {
                "mode": "trunk", "native_vlan": 10,
                "allowed_vlans": [10, 20],
                "description": "Aggregate two", "admin_state": "down",
                "portfast": "edge-trunk", "bpdu_guard": "enabled",
            },
            "lacp": "static",
        },
    ]
    return plan


@pytest.mark.parametrize("key", sorted(COMPREHENSIVE_FAMILIES))
def test_comprehensive_reviewed_grammar_differential(key: str) -> None:
    document = render_plan(_multi_channel_plan(key))
    report = validate_candidate_document(document)
    candidates = [
        candidate for candidate in document.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    ]
    assert candidates
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.parse_pass == len(candidates)
    assert report.summary.parse_fail == 0
    assert report.summary.failed_candidates == 0
    assert all(
        candidate.candidate_text is not None for candidate in candidates
    )
    assert all(
        candidate.candidate_text is None
        for candidate in document.candidates
        if candidate.status is not CandidateStatus.CANDIDATE
    )
    forms = {
        item.parse.form for item in report.candidates
        if item.parse.status is Verdict.PASS
    }
    expected = set(INTERFACE_FORM_SET)
    if key in {"9200", "9300"}:
        expected |= set(L2_FORM_SET)
    assert expected <= forms, (key, sorted(expected - forms))
    for candidate_report in report.candidates:
        assert candidate_report.risk.status is Verdict.PASS
        if candidate_report.renderer_status == "candidate":
            assert candidate_report.scope.status.value == "allowed"
            assert candidate_report.security.status is Verdict.PASS
            assert candidate_report.semantics.status is Verdict.PASS


# --------------------------------------------------------------------------- #
# Tampered / forged document negative corpus
# --------------------------------------------------------------------------- #


def test_tampered_text_without_fingerprint_recomputation_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, status=CandidateStatus.CANDIDATE)
    tampered = _tamper_at(
        document, index, {"candidate_text": "reload"}, recompute=False,
    )
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    assert report.integrity.status is Verdict.FAIL
    assert report.integrity.render_fingerprint_match is False
    for candidate_report in report.candidates:
        assert candidate_report.independent_verdict is Verdict.FAIL
        assert candidate_report.fail_closed_action == (
            "reject-document-until-source-integrity-passes"
        )
    assert any(
        finding.startswith("integrity:") for finding in report.topology_review.findings
    )


def test_forged_dangerous_text_with_recomputed_fingerprints_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, status=CandidateStatus.CANDIDATE)
    tampered = _tamper_at(document, index, {"candidate_text": "reload"})
    report = validate_candidate_document(tampered)
    assert report.integrity.status is Verdict.PASS
    candidate_report = report.candidates[index]
    assert candidate_report.independent_verdict is Verdict.FAIL
    assert candidate_report.parse.status is Verdict.FAIL
    assert "dangerous-operation-denied" in candidate_report.security.reason_codes
    assert any(
        finding.startswith("dangerous-command-text:")
        for finding in report.topology_review.findings
    )
    assert report.summary.overall_status is Verdict.FAIL


def test_forged_parameter_change_with_recomputed_fingerprints_is_rejected() -> None:
    document = _frozen_document("9300")
    index = next(
        index for index, candidate in enumerate(document.candidates)
        if candidate.category.value == "access-vlan"
        and candidate.status is CandidateStatus.CANDIDATE
    )
    tampered = _tamper_at(document, index, {"parameters": {"vlan-id": 30}})
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    candidate_report = report.candidates[index]
    assert candidate_report.independent_verdict is Verdict.FAIL
    assert "parameter-mismatch:vlan-id" in candidate_report.semantics.mismatches


def test_forged_promotion_of_blocked_topology_command_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, category="rapid-pvst")
    blocked = document.candidates[index]
    tampered = _tamper_at(document, index, {
        "status": CandidateStatus.CANDIDATE,
        "candidate_text": "spanning-tree mode rapid-pvst",
        "blocking_reasons": (),
        "syntax_validation": blocked.syntax_validation.model_copy(update={
            "level": SyntaxValidationLevel.DICTIONARY_ONLY,
        }),
    })
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    candidate_report = report.candidates[index]
    assert candidate_report.independent_verdict is Verdict.FAIL
    assert any(
        finding.startswith("topology-wide-command-visible-without-field-evidence")
        for finding in candidate_report.risk.findings
    )
    assert any(
        finding.startswith("topology-wide-command-visible:")
        for finding in report.topology_review.findings
    )


def test_forged_parser_verified_flag_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, status=CandidateStatus.CANDIDATE)
    candidate = document.candidates[index]
    tampered = _tamper_at(document, index, {
        "syntax_validation": candidate.syntax_validation.model_copy(update={
            "parser_verified": True,
        }),
    })
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    assert "frozen-v1-parser-verified-must-stay-false" in (
        report.candidates[index].risk.findings
    )


def test_forged_duplicate_candidate_id_is_rejected() -> None:
    document = _frozen_document("9300")
    first = document.candidates[0]
    second = document.candidates[1]
    tampered = _tamper_at(document, 1, {"candidate_id": first.candidate_id})
    assert second.candidate_id != tampered.candidates[1].candidate_id
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    assert report.integrity.candidate_ids_unique is False


def test_forged_text_on_blocked_candidate_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, category="description", status=CandidateStatus.BLOCKED)
    tampered = _tamper_at(document, index, {
        "candidate_text": "description Players desk",
    })
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    candidate_report = report.candidates[index]
    assert candidate_report.independent_verdict is Verdict.FAIL
    assert "blocked-candidate-carries-text" in candidate_report.risk.findings


@pytest.mark.parametrize(
    "category", ["rapid-pvst", "vtp-transparent", "root-priority"],
)
def test_forged_risk_downgrade_is_rejected(category: str) -> None:
    document = _frozen_document("9300")
    index = _index_of(document, category=category)
    tampered = _tamper_at(document, index, {"risk_class": RiskClass.R2})
    report = validate_candidate_document(tampered)
    candidate_report = report.candidates[index]
    assert candidate_report.independent_verdict is Verdict.FAIL
    assert any(
        finding.startswith("topology-wide-block-not-escalated-to-r5")
        for finding in candidate_report.risk.findings
    )


def test_forged_cleanup_risk_downgrade_is_rejected() -> None:
    document = _cleanup_document()
    index = next(
        index for index, candidate in enumerate(document.candidates)
        if candidate.provenance.cleanup
        or "removal-not-rendered" in candidate.blocking_reasons
    )
    tampered = _tamper_at(document, index, {"risk_class": RiskClass.R2})
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    assert "cleanup-risk-below-r4:R2" in report.candidates[index].risk.findings


def test_forged_connectivity_flag_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, category="speed")
    tampered = _tamper_at(
        document, index, {"potential_connectivity_impact": False},
    )
    report = validate_candidate_document(tampered)
    assert "connectivity-impact-understated" in (
        report.candidates[index].risk.findings
    )
    assert report.summary.overall_status is Verdict.FAIL


def test_forged_context_mismatch_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, status=CandidateStatus.CANDIDATE)
    candidate = document.candidates[index]
    tampered = _tamper_at(document, index, {
        "command_context": candidate.command_context.model_copy(update={
            "mode_header": "interface EVIL1/0/1",
        }),
    })
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    assert "mode-header-mismatch:interface EVIL1/0/1" in (
        report.candidates[index].semantics.mismatches
    )


def test_forged_syntax_evidence_command_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, status=CandidateStatus.CANDIDATE)
    candidate = document.candidates[index]
    evidence = candidate.syntax_evidence[0]
    tampered_candidate = candidate.model_copy(update={
        "syntax_evidence": (evidence.model_copy(update={"command": "reload"}),),
    })
    tampered = _tamper_at(document, index, {
        "syntax_evidence": tampered_candidate.syntax_evidence,
    })
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    assert any(
        mismatch.startswith("syntax-evidence-command-mismatch:")
        for mismatch in report.candidates[index].semantics.mismatches
    )


def test_forged_missing_syntax_evidence_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, status=CandidateStatus.CANDIDATE)
    tampered = _tamper_at(document, index, {"syntax_evidence": ()})
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    candidate_report = report.candidates[index]
    assert "visible-candidate-without-syntax-evidence" in candidate_report.risk.findings
    assert "syntax-evidence-missing" in candidate_report.semantics.mismatches


def test_forged_malformed_source_hash_is_rejected() -> None:
    document = _frozen_document("9300")
    source = document.source.model_copy(update={
        "revision_canonical_hash": "not-a-hash",
    })
    tampered = document.model_copy(update={"source": source})
    tampered = tampered.model_copy(update={
        "render_fingerprint": recompute_render_fingerprint(tampered),
    })
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    assert report.integrity.source_binding_format_ok is False


# --------------------------------------------------------------------------- #
# Hardening negatives: category/target/identity/registry forgery
# --------------------------------------------------------------------------- #


def _settle_document(
    document: L2CliCandidateDocument,
    updates: dict[int, dict[str, Any]],
) -> L2CliCandidateDocument:
    candidates = list(document.candidates)
    for index, changes in updates.items():
        changed = candidates[index].model_copy(update=changes)
        changed = changed.model_copy(update={
            "candidate_fingerprint": recompute_candidate_fingerprint(changed),
        })
        candidates[index] = changed
    settled = document.model_copy(update={"candidates": tuple(candidates)})
    return settled.model_copy(update={
        "render_fingerprint": recompute_render_fingerprint(settled),
    })


def test_forged_category_relabel_of_visible_topology_command_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, category="rapid-pvst")
    blocked = document.candidates[index]
    tampered = _settle_document(document, {
        index: {
            "status": CandidateStatus.CANDIDATE,
            "category": CandidateCategory.VLAN_DEFINITION,
            "candidate_text": "spanning-tree mode rapid-pvst",
            "parameters": {},
            "risk_class": RiskClass.R0,
            "blocking_reasons": (),
            "syntax_validation": blocked.syntax_validation.model_copy(update={
                "level": SyntaxValidationLevel.DICTIONARY_ONLY,
            }),
        },
    })
    report = validate_candidate_document(tampered)
    candidate_report = report.candidates[index]
    assert report.summary.overall_status is Verdict.FAIL
    assert candidate_report.independent_verdict is Verdict.FAIL
    assert any(
        mismatch.startswith("category-topic-mismatch:")
        for mismatch in candidate_report.semantics.mismatches
    )
    assert any(
        finding.startswith("topology-wide-command-visible-without-field-evidence")
        for finding in candidate_report.risk.findings
    )
    assert any(
        finding.startswith("topology-wide-command-visible:")
        for finding in report.topology_review.findings
    )


def test_forged_category_relabel_of_blocked_topology_command_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, category="rapid-pvst")
    tampered = _settle_document(document, {
        index: {"category": CandidateCategory.VLAN_DEFINITION, "risk_class": RiskClass.R0},
    })
    report = validate_candidate_document(tampered)
    candidate_report = report.candidates[index]
    assert candidate_report.independent_verdict is Verdict.FAIL
    assert any(
        mismatch.startswith("category-topic-mismatch:")
        for mismatch in candidate_report.semantics.mismatches
    )
    assert any(
        mismatch.startswith("category-evidence-topic-mismatch:")
        for mismatch in candidate_report.semantics.mismatches
    )


def test_forged_category_relabel_of_visible_blocked_data_command_is_rejected() -> None:
    document = _frozen_document("9300")
    index = next(
        index for index, candidate in enumerate(document.candidates)
        if candidate.category.value == "access-vlan"
        and candidate.status is CandidateStatus.CANDIDATE
    )
    tampered = _settle_document(document, {
        index: {"category": CandidateCategory.ACCESS_MODE},
    })
    report = validate_candidate_document(tampered)
    candidate_report = report.candidates[index]
    assert report.summary.overall_status is Verdict.FAIL
    assert candidate_report.independent_verdict is Verdict.FAIL
    assert any(
        mismatch.startswith("category-topic-mismatch:")
        for mismatch in candidate_report.semantics.mismatches
    )


def test_forged_interface_target_outside_reviewed_layout_is_rejected() -> None:
    document = _frozen_document("9300")
    index = next(
        index for index, candidate in enumerate(document.candidates)
        if candidate.target.kind.value == "interface"
        and candidate.status is CandidateStatus.CANDIDATE
    )
    candidate = document.candidates[index]
    target = candidate.target.model_copy(update={"name": "Gi1/9/9"})
    context = candidate.command_context.model_copy(update={
        "target_name": "Gi1/9/9",
        "mode_header": "interface Gi1/9/9",
    })
    tampered = _settle_document(document, {
        index: {"target": target, "command_context": context},
    })
    report = validate_candidate_document(tampered)
    candidate_report = report.candidates[index]
    assert report.summary.overall_status is Verdict.FAIL
    assert candidate_report.independent_verdict is Verdict.FAIL
    assert "target-interface-not-in-reviewed-layout" in (
        candidate_report.semantics.mismatches
    )


def test_zero_padded_module_interface_name_is_accepted() -> None:
    plan = make_plan(
        str(uuid4()),
        pid="C9300L-24P-4X",
        family="catalyst-9300",
        image="17.12.4",
        license_name="Network Advantage",
        ports=[
            {
                "name": "Gi1/00/1",
                "settings": {"mode": "access", "access_vlan": 20},
            },
            {
                "name": "Gi1/000/1",
                "settings": {"mode": "access", "access_vlan": 20},
            },
        ],
    )
    document = render_plan(plan)
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.failed_candidates == 0
    assert report.summary.parse_pass == sum(
        1 for candidate in document.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    )
    assert report.summary.parse_pass > 0


def test_forged_port_channel_stable_id_is_rejected() -> None:
    document = _frozen_document("9300")
    index = next(
        index for index, candidate in enumerate(document.candidates)
        if candidate.target.kind.value == "port-channel"
        and candidate.status is CandidateStatus.CANDIDATE
    )
    candidate = document.candidates[index]
    target = candidate.target.model_copy(update={"stable_id": "not-a-uuid"})
    tampered = _settle_document(document, {index: {"target": target}})
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    assert "target-port-channel-stable-id-invalid" in (
        report.candidates[index].semantics.mismatches
    )


def test_forged_license_case_cannot_bypass_stack_limit() -> None:
    document = _frozen_document("2960x")
    members = tuple(
        (number, "WS-C2960X-24PS-L", "ready") for number in range(1, 21)
    )
    for license_name in ("lan base", "LAN BASE", "Lan Base"):
        device = document.device.model_copy(update={
            "license": license_name,
            "stack_identity": "resolved",
            "stack_members": tuple(
                RenderStackMember(
                    number=number,
                    exact_pid="WS-C2960X-24PS-L",
                    state="ready",
                )
                for number, _pid, _state in members
            ),
        })
        tampered = document.model_copy(update={"device": device})
        tampered = tampered.model_copy(update={
            "render_fingerprint": recompute_render_fingerprint(tampered),
        })
        report = validate_candidate_document(tampered)
        assert report.device.identity_verdict is Verdict.FAIL
        assert any(
            reason.startswith("stack-limit-exceeded:20:8")
            for reason in report.device.identity_reasons
        ), (license_name, report.device.identity_reasons)


def test_forged_stack_member_pid_is_rejected() -> None:
    document = _frozen_document("9300")
    device = document.device.model_copy(update={
        "stack_identity": "resolved",
        "stack_members": (
            RenderStackMember(
                number=1, exact_pid="WS-C2960X-24PS-L", state="ready",
            ),
        ),
    })
    tampered = document.model_copy(update={"device": device})
    tampered = tampered.model_copy(update={
        "render_fingerprint": recompute_render_fingerprint(tampered),
    })
    report = validate_candidate_document(tampered)
    assert report.device.identity_verdict is Verdict.FAIL
    assert "stack-member-pid-not-verified" in report.device.identity_reasons


def test_forged_evidence_registry_binding_is_rejected() -> None:
    document = _frozen_document("9300")
    source = document.source.model_copy(update={
        "command_evidence_registry_id": "cis-02b2-l1-command-evidence-evil",
        "command_evidence_fingerprint": "0" * 64,
    })
    tampered = document.model_copy(update={"source": source})
    tampered = tampered.model_copy(update={
        "render_fingerprint": recompute_render_fingerprint(tampered),
    })
    report = validate_candidate_document(tampered)
    assert report.summary.overall_status is Verdict.FAIL
    assert report.integrity.status is Verdict.FAIL
    assert "command-evidence-registry-binding-mismatch" in (
        report.integrity.failures
    )


def test_forged_native_vlan_risk_downgrade_is_rejected() -> None:
    document = _frozen_document("9300")
    index = _index_of(document, category="native-vlan")
    tampered = _settle_document(document, {index: {"risk_class": RiskClass.R0}})
    report = validate_candidate_document(tampered)
    candidate_report = report.candidates[index]
    assert candidate_report.independent_verdict is Verdict.FAIL
    assert "native-vlan-risk-below-r5:R0" in candidate_report.risk.findings


# --------------------------------------------------------------------------- #
# Real API integration: the frozen public v1 response is unchanged
# --------------------------------------------------------------------------- #


def test_public_v1_api_response_round_trips_and_validates(
    client: TestClient,
) -> None:
    document_json, plan, revision = saved_document(client, "9300")
    document = L2CliCandidateDocument.model_validate(document_json)
    report = validate_candidate_document(
        document,
        expected=ExpectedSource(
            saved_revision_uuid=document.source.saved_revision_uuid,
            revision_canonical_hash=document.source.revision_canonical_hash,
            intent_fingerprint=document.source.intent_fingerprint,
            preview_fingerprint=document.source.preview_fingerprint,
            render_fingerprint=document.render_fingerprint,
            assignment_id=document.assignment_id,
        ),
    )
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.parse_pass == 25
    assert report.summary.not_run == 7

    again = render(
        client, cast(str, plan["event_id"]), cast(str, revision["id"]),
        assignment_of(plan),
    )
    assert again == document_json
    parsed_again = L2CliCandidateDocument.model_validate(again)
    report_again = validate_candidate_document(parsed_again)
    assert report_again.report_fingerprint == (
        validate_candidate_document(document).report_fingerprint
    )


def test_public_v1_response_has_no_validation_or_execution_fields(
    client: TestClient,
) -> None:
    document_json, _plan, _revision = saved_document(client, "9300")
    payload = document_json
    assert "validation_report" not in payload
    assert "report" not in payload
    assert "order" not in payload
    assert "sequence" not in payload
    assert "execution_plan" not in payload
    assert payload["safety"]["deployment_artifact"] is None
    assert payload["safety"]["cli"] is None
    for candidate in cast(list[dict[str, Any]], payload["candidates"]):
        assert candidate["syntax_validation"]["parser_verified"] is False
        assert candidate["syntax_validation"]["level"] in {
            "dictionary-only", "not-run",
        }
        assert candidate["syntax_validation"]["dictionary_id"] == (
            "cis-02b2-l1-command-dictionary-v1"
        )


def test_api_category_filter_document_validates_independently(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = full_plan(event_id, "9200")
    revision = save(client, event_id, plan)
    document_json = render(
        client, event_id, cast(str, revision["id"]), assignment_of(plan),
        "?category=access-vlan",
    )
    document = L2CliCandidateDocument.model_validate(document_json)
    assert {candidate.category.value for candidate in document.candidates} == {
        "access-vlan",
    }
    report = validate_candidate_document(document)
    assert report.summary.overall_status is Verdict.PASS
    assert report.summary.parse_pass == sum(
        1 for candidate in document.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    )
