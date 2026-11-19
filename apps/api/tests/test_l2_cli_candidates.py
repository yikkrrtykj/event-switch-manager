"""CIS-02B2 offline candidate renderer and read-only API regressions."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from test_event_plans import API, ORIGIN
from test_layer2_intent import (
    event,
    make_plan,
    make_stack_plan,
    new_id,
    save,
)

from event_switch_manager.app import create_app
from event_switch_manager.domain import DeviceFamily
from event_switch_manager.planning.command_evidence import (
    DEFAULT_REGISTRY,
    EVIDENCE_REGISTRY_ID,
    PENDING_REVIEW,
    ROWS,
    CommandEvidenceRegistry,
    CommandTopic,
    EvidenceReview,
    EvidenceReviewState,
)
from event_switch_manager.planning.layer2_cli_candidates import (
    CONTRACT_ID,
    DICTIONARY_ID,
    RENDER_SCHEMA_VERSION,
    CandidateCategory,
    CandidateStatus,
    L2CliCandidateDocument,
    RenderBindingError,
    RiskClass,
    build_l2_cli_candidates,
    candidate_catalog_json_schema,
    candidate_document_json_schema,
    description_reason,
    evidence_fingerprint,
    interface_name_reason,
    port_channel_name_reason,
    render_fingerprint,
    verify_render_binding,
    vlan_name_reason,
)
from event_switch_manager.planning.layer2_config_preview import (
    build_device_layer2_config_preview,
)
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.planning.plan import (
    EventPlan,
    PlanRevision,
    canonical_plan,
    plan_hash,
)
from event_switch_manager.settings import Settings

Document = dict[str, Any]
Candidate = dict[str, Any]
Item = dict[str, Any]

FAMILIES: dict[str, dict[str, Any]] = {
    "2960x": {
        "pid": "WS-C2960X-24PS-L", "family": "catalyst-2960x",
        "image": "15.2(7)E", "license_name": "LAN Base",
    },
    "3850": {
        "pid": "WS-C3850-24P", "family": "catalyst-3850",
        "image": "16.12.12", "license_name": "IP Base",
    },
    "9200": {
        "pid": "C9200L-24P-4X", "family": "catalyst-9200",
        "image": "17.12.4", "license_name": "Network Advantage",
    },
    "9300": {
        "pid": "C9300L-24P-4X", "family": "catalyst-9300",
        "image": "17.12.4", "license_name": "Network Advantage",
    },
    "c1000": {
        "pid": "C1000-24P-4G-L", "family": "catalyst-c1000",
        "image": "15.2(7)E1", "license_name": None,
    },
}

TOPIC_CATEGORY: dict[CommandTopic, CandidateCategory] = {
    CommandTopic.VLAN: CandidateCategory.VLAN_DEFINITION,
    CommandTopic.VLAN_NAME: CandidateCategory.VLAN_DEFINITION,
    CommandTopic.ACCESS_MODE: CandidateCategory.ACCESS_MODE,
    CommandTopic.ACCESS_VLAN: CandidateCategory.ACCESS_VLAN,
    CommandTopic.TRUNK_MODE: CandidateCategory.TRUNK_MODE,
    CommandTopic.NATIVE_VLAN: CandidateCategory.NATIVE_VLAN,
    CommandTopic.ALLOWED_VLANS: CandidateCategory.ALLOWED_VLANS,
    CommandTopic.PORT_CHANNEL_INTERFACE: CandidateCategory.PORT_CHANNEL,
    CommandTopic.CHANNEL_GROUP_STATIC: CandidateCategory.PORT_CHANNEL,
    CommandTopic.CHANNEL_GROUP_LACP: CandidateCategory.LACP_MODE,
    CommandTopic.RAPID_PVST: CandidateCategory.RAPID_PVST,
    CommandTopic.VTP_TRANSPARENT: CandidateCategory.VTP_TRANSPARENT,
    CommandTopic.ROOT_PRIORITY: CandidateCategory.ROOT_PRIORITY,
    CommandTopic.PORTFAST: CandidateCategory.PORTFAST,
    CommandTopic.BPDU_GUARD: CandidateCategory.BPDU_GUARD,
    CommandTopic.POE_MODE: CandidateCategory.POE_MODE,
    CommandTopic.SPEED: CandidateCategory.SPEED,
    CommandTopic.DUPLEX: CandidateCategory.DUPLEX,
    CommandTopic.DESCRIPTION: CandidateCategory.DESCRIPTION,
    CommandTopic.ADMIN_SHUTDOWN: CandidateCategory.ADMIN_SHUTDOWN,
}
# Categories the B2 risk model always blocks, whatever the evidence state.
POLICY_BLOCKED = {
    CandidateCategory.NATIVE_VLAN,
    CandidateCategory.RAPID_PVST,
    CandidateCategory.VTP_TRANSPARENT,
    CandidateCategory.ROOT_PRIORITY,
}
# Topics whose CIS-01A capability is supported for each family, for the plan
# shape used by full_plan(). Everything else fails closed on capability.
L2_CAPABILITY_FAMILIES = {"catalyst-9200", "catalyst-9300"}
FORBIDDEN_KEYS = {
    "commands", "command_lines", "configuration", "config", "config_snippet",
    "cli_commands", "cli_lines", "script", "execution_order", "sequence", "order",
    "paste_ready", "deployment_script",
}
FORBIDDEN_TEXT = (
    "reload", "erase", "format", "factory-reset", "boot system", "copy run",
    "username", "enable secret", "ip route", "no vlan", "shutdown all",
)
CLI_LINE = re.compile(
    r"^(interface|switchport|spanning-tree|vlan\s|hostname|enable|configure|no\s|"
    r"shutdown|power inline|speed|duplex|description|channel-group|vtp\s|name\s)"
)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "b2-candidates.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as session:
        yield session


def full_plan(event_id: str, key: str = "9300") -> dict[str, Any]:
    family = FAMILIES[key]
    return make_plan(
        event_id,
        pid=family["pid"],
        family=family["family"],
        image=family["image"],
        license_name=family["license_name"],
        ports=[
            {
                "name": "Gi1/0/1",
                "settings": {
                    "mode": "access", "access_vlan": 20,
                    "description": "Players desk", "admin_state": "up",
                    "speed": 1000, "duplex": "full", "poe_mode": "auto",
                    "portfast": "edge", "bpdu_guard": "enabled",
                },
            },
            {
                "name": "Gi1/0/2",
                "settings": {
                    "mode": "trunk", "native_vlan": 10,
                    "allowed_vlans": [10, 20, 30],
                },
            },
            {"name": "Gi1/0/3", "settings": {"mode": "access", "access_vlan": 20}},
            {"name": "Gi1/0/4", "settings": {"mode": "access", "access_vlan": 20}},
        ],
        channel={
            "members": [2, 3],
            "settings": {"mode": "access", "access_vlan": 20},
            "lacp": "active",
        },
    )


def plan_of(
    event_id: str, key: str = "9300", *, ports: list[dict[str, Any]],
    channel: dict[str, Any] | None = None, with_serial: bool = True,
    **overrides: Any,
) -> dict[str, Any]:
    family = {**FAMILIES[key], **overrides}
    return make_plan(
        event_id,
        pid=family["pid"],
        family=family["family"],
        image=family["image"],
        license_name=family["license_name"],
        ports=ports,
        channel=channel,
        with_serial=with_serial,
    )


def assignment_of(plan: dict[str, Any]) -> str:
    return str(plan["assignments"][0]["id"])


def render(
    client: TestClient, event_id: str, revision_id: str, assignment_id: str,
    query: str = "",
) -> Document:
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision_id}"
        f"/assignments/{assignment_id}/l2-cli-candidates{query}"
    )
    assert response.status_code == 200, response.text
    return cast(Document, response.json())


def saved_document(
    client: TestClient, key: str = "9300", query: str = "",
) -> tuple[Document, dict[str, Any], dict[str, Any]]:
    event_id = event(client)
    plan = full_plan(event_id, key)
    revision = save(client, event_id, plan)
    return render(client, event_id, revision["id"], assignment_of(plan), query), plan, revision


def candidates(document: Document) -> list[Candidate]:
    return cast(list[Candidate], document["candidates"])


def of_category(document: Document, category: CandidateCategory) -> list[Candidate]:
    return [
        candidate for candidate in candidates(document)
        if candidate["category"] == category.value
    ]


def texts(document: Document) -> list[str]:
    return [
        cast(str, candidate["candidate_text"]) for candidate in candidates(document)
        if candidate["candidate_text"] is not None
    ]


def fingerprint_of(document: Document) -> str:
    payload = {
        key: value for key, value in document.items() if key != "render_fingerprint"
    }
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def candidate_fingerprint_of(candidate: Candidate) -> str:
    payload = {
        key: value for key, value in candidate.items() if key != "candidate_fingerprint"
    }
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def expected_categories(key: str) -> set[str]:
    family = FAMILIES[key]
    device_family = DeviceFamily(family["family"])
    supported: set[CandidateCategory] = set()
    for topic in CommandTopic:
        if topic not in {CommandTopic.SPEED, CommandTopic.DUPLEX,
                         CommandTopic.DESCRIPTION, CommandTopic.ADMIN_SHUTDOWN,
                         CommandTopic.POE_MODE, CommandTopic.PORT_CHANNEL_INTERFACE,
                         CommandTopic.CHANNEL_GROUP_STATIC,
                         CommandTopic.CHANNEL_GROUP_LACP} and (
            family["family"] not in L2_CAPABILITY_FAMILIES
        ):
            continue
        row = DEFAULT_REGISTRY.renderable(
            device_family, family["pid"], family["image"], family["license_name"],
            topic,
        )
        if row is None:
            continue
        category = TOPIC_CATEGORY[topic]
        if category in POLICY_BLOCKED:
            continue
        supported.add(category)
    return {category.value for category in supported}


def in_process(plan: dict[str, Any]) -> tuple[PlanRevision, Any, Any]:
    event_plan = EventPlan.model_validate(plan)
    revision = PlanRevision(
        id=UUID(new_id()), number=1, created_at=datetime.now(UTC),
        content_hash=plan_hash(canonical_plan(event_plan)), schema_version=1,
        plan=event_plan, warnings=(), validation_errors=(),
        validation_status="VALID_WITH_WARNINGS",
    )
    intent = build_layer2_intent(revision, None)
    preview = build_device_layer2_config_preview(
        revision, intent, event_plan.assignments[0].id,
    )
    return revision, intent, preview


# --------------------------------------------------------------------------- #
# Document identity and safety invariants
# --------------------------------------------------------------------------- #


def test_document_binds_rebuilt_inputs_and_keeps_every_safety_invariant(
    client: TestClient,
) -> None:
    document, plan, revision = saved_document(client)
    assert document["render_schema_version"] == RENDER_SCHEMA_VERSION
    assert document["contract_id"] == CONTRACT_ID
    assert document["assignment_id"] == assignment_of(plan)
    source = cast(dict[str, Any], document["source"])
    assert source["saved_revision_uuid"] == revision["id"]
    assert source["revision_number"] == revision["number"]
    assert source["revision_canonical_hash"] == revision["content_hash"]
    assert source["intent_schema_version"] == 1
    assert source["preview_schema_version"] == 1
    assert source["preview_contract_id"] == "cis-02b1-layer2-config-preview-v1"
    assert source["command_evidence_registry_id"] == EVIDENCE_REGISTRY_ID
    assert source["command_evidence_fingerprint"] == evidence_fingerprint(
        DEFAULT_REGISTRY
    )
    assert document["device_runtime_state"] == "unknown-not-read"
    assert cast(dict[str, Any], document["safety"]) == {
        "candidate_only": True,
        "executable": False,
        "deployable": False,
        "deployment_allowed": False,
        "device_connection": "none",
        "running_config_read": False,
        "device_writes_enabled": False,
        "cli": None,
        "deployment_artifact": None,
        "device_runtime_state": "unknown-not-read",
        "hardware_verified": False,
    }
    assert "candidate-only-no-execution" in cast(list[str], document["deployment_blockers"])
    assert document["render_state"] == "review-candidates"
    assert document["render_fingerprint"] == fingerprint_of(document)


def test_device_block_records_exact_identity_and_stack_state(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    device = cast(dict[str, Any], document["device"])
    assert device["hostname"] == "L2-Access"
    assert device["family"] == "catalyst-9300"
    assert device["exact_pid"] == "C9300L-24P-4X"
    assert device["release"] == "17.12.4"
    assert device["license"] == "Network Advantage"
    assert device["role"] == "access"
    assert device["stack_identity"] == "standalone"
    assert device["stack_members"] == []


def test_candidate_objects_carry_every_contract_field(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    assert candidates(document)
    for candidate in candidates(document):
        assert candidate["candidate_id"].startswith("cand-")
        assert candidate["assignment_id"] == document["assignment_id"]
        target = cast(dict[str, Any], candidate["target"])
        assert set(target) == {"kind", "stable_id", "name"}
        context = cast(dict[str, Any], candidate["command_context"])
        assert set(context) == {"mode", "mode_header", "target_name"}
        assert context["mode"] in {"global", "vlan", "interface", "port-channel"}
        assert candidate["category"] in {category.value for category in CandidateCategory}
        assert candidate["status"] in {"candidate", "blocked", "unsupported"}
        assert candidate["risk_class"] in {risk.value for risk in RiskClass}
        assert isinstance(candidate["parameters"], dict)
        provenance = cast(dict[str, Any], candidate["provenance"])
        assert provenance["preview_item_id"].startswith("cfg-")
        assert provenance["b1_field"]
        assert provenance["b1_category"]
        validation = cast(dict[str, Any], candidate["syntax_validation"])
        assert validation == {
            "level": "dictionary-only",
            "dictionary_id": DICTIONARY_ID,
            "parser_verified": False,
        }
        assert candidate["candidate_fingerprint"] == candidate_fingerprint_of(candidate)


def test_candidate_text_only_exists_for_rendered_candidates(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    for candidate in candidates(document):
        if candidate["status"] == "candidate":
            assert candidate["candidate_text"]
            assert not candidate["blocking_reasons"]
        else:
            assert candidate["candidate_text"] is None
            assert candidate["blocking_reasons"]


def test_summary_reconciles_with_candidate_statuses(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    summary = cast(dict[str, Any], document["summary"])
    statuses = [candidate["status"] for candidate in candidates(document)]
    assert summary["total"] == len(statuses)
    assert summary["candidates"] == statuses.count("candidate")
    assert summary["blocked"] == statuses.count("blocked")
    assert summary["unsupported"] == statuses.count("unsupported")
    assert set(summary["categories_rendered"]) <= {
        candidate["category"] for candidate in candidates(document)
    }


def test_repeated_render_is_byte_identical(client: TestClient) -> None:
    document, plan, revision = saved_document(client)
    again = render(client, str(plan["event_id"]), revision["id"], assignment_of(plan))
    assert again == document
    assert again["render_fingerprint"] == document["render_fingerprint"]


def test_rendering_does_not_mutate_the_saved_revision(client: TestClient) -> None:
    event_id = event(client)
    plan = full_plan(event_id)
    revision = save(client, event_id, plan)
    before = client.get(f"{API}/events/{event_id}/plan-revisions/{revision['id']}")
    assert before.status_code == 200
    render(client, event_id, revision["id"], assignment_of(plan))
    after = client.get(f"{API}/events/{event_id}/plan-revisions/{revision['id']}")
    assert after.json() == before.json()
    preview = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision['id']}/layer2-config-preview"
    )
    assert preview.status_code == 200
    assert preview.json()["cli"] is None
    assert preview.json()["executable"] is False


# --------------------------------------------------------------------------- #
# Request contract
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "query",
    [
        "?expected_preview_fingerprint=" + "a" * 64,
        "?expected_intent_fingerprint=" + "a" * 64,
        "?preview_fingerprint=" + "a" * 64,
        "?candidate_text=reload",
        "?preview_document={}",
        "?plan=%7B%7D",
        "?running_config=show%20run",
        "?evidence=reviewed",
        "?force=true",
    ],
)
def test_undeclared_query_parameters_are_rejected(
    client: TestClient, query: str,
) -> None:
    document, plan, revision = saved_document(client)
    response = client.get(
        f"{API}/events/{plan['event_id']}/plan-revisions/{revision['id']}"
        f"/assignments/{assignment_of(plan)}/l2-cli-candidates{query}"
    )
    assert response.status_code == 400, response.text
    assert response.json()["detail"]["reason_code"] == "undeclared-input"
    assert document["contract_id"] == CONTRACT_ID


def test_request_body_is_rejected(client: TestClient) -> None:
    document, plan, revision = saved_document(client)
    response = client.request(
        "GET",
        f"{API}/events/{plan['event_id']}/plan-revisions/{revision['id']}"
        f"/assignments/{assignment_of(plan)}/l2-cli-candidates",
        content=b'{"candidate_text": "reload"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400, response.text
    assert response.json()["detail"]["fields"] == ["request-body"]
    assert document["contract_id"] == CONTRACT_ID


def test_unknown_category_is_rejected(client: TestClient) -> None:
    document, plan, revision = saved_document(client)
    response = client.get(
        f"{API}/events/{plan['event_id']}/plan-revisions/{revision['id']}"
        f"/assignments/{assignment_of(plan)}/l2-cli-candidates?category=reload"
    )
    assert response.status_code == 422
    assert document["contract_id"] == CONTRACT_ID


def test_conditional_request_headers_are_refused(client: TestClient) -> None:
    document, plan, revision = saved_document(client)
    for header in ("If-Match", "If-None-Match"):
        response = client.get(
            f"{API}/events/{plan['event_id']}/plan-revisions/{revision['id']}"
            f"/assignments/{assignment_of(plan)}/l2-cli-candidates",
            headers={header: f'"{revision["content_hash"]}"'},
        )
        assert response.status_code == 400, header
        assert response.json()["detail"]["reason_code"] == "undeclared-input"
    assert document["contract_id"] == CONTRACT_ID


def test_category_filter_selects_only_requested_categories(client: TestClient) -> None:
    document, plan, revision = saved_document(
        client, query="?category=description&category=speed",
    )
    for candidate in candidates(document):
        assert candidate["category"] in {"description", "speed"}
    assert {candidate["category"] for candidate in candidates(document)}
    assert render(
        client, str(plan["event_id"]), revision["id"], assignment_of(plan),
    )["summary"]["total"] >= document["summary"]["total"]


def test_cross_event_revision_and_assignment_are_rejected(client: TestClient) -> None:
    document, plan, revision = saved_document(client)
    other_event = event(client, "Another event")
    response = client.get(
        f"{API}/events/{other_event}/plan-revisions/{revision['id']}"
        f"/assignments/{assignment_of(plan)}/l2-cli-candidates"
    )
    assert response.status_code == 404
    response = client.get(
        f"{API}/events/{plan['event_id']}/plan-revisions/{revision['id']}"
        f"/assignments/{new_id()}/l2-cli-candidates"
    )
    assert response.status_code == 404
    response = client.get(
        f"{API}/events/{plan['event_id']}/plan-revisions/{new_id()}"
        f"/assignments/{assignment_of(plan)}/l2-cli-candidates"
    )
    assert response.status_code == 404
    assert document["contract_id"] == CONTRACT_ID


# --------------------------------------------------------------------------- #
# Five-family support and block matrix
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("key", list(FAMILIES))
def test_five_family_matrix_renders_exactly_the_reviewed_scope(
    client: TestClient, key: str,
) -> None:
    document, _plan, _revision = saved_document(client, key)
    rendered = {
        candidate["category"] for candidate in candidates(document)
        if candidate["status"] == "candidate"
    }
    assert rendered == expected_categories(key), (
        key, sorted(rendered), sorted(expected_categories(key))
    )
    assert document["render_state"] == (
        "review-candidates" if rendered else "no-supported-candidates"
    )


@pytest.mark.parametrize("key", ["2960x", "3850", "c1000"])
def test_layer2_categories_are_blocked_without_feature_evidence(
    client: TestClient, key: str,
) -> None:
    document, _plan, _revision = saved_document(client, key)
    blocked = {
        CandidateCategory.VLAN_DEFINITION,
        CandidateCategory.ACCESS_MODE,
        CandidateCategory.ACCESS_VLAN,
        CandidateCategory.TRUNK_MODE,
        CandidateCategory.ALLOWED_VLANS,
        CandidateCategory.PORTFAST,
        CandidateCategory.BPDU_GUARD,
    }
    for candidate in candidates(document):
        if CandidateCategory(candidate["category"]) in blocked:
            assert candidate["status"] == "blocked"
            assert candidate["candidate_text"] is None
            assert any(
                reason.startswith("capability-unknown:")
                for reason in cast(list[str], candidate["blocking_reasons"])
            )


@pytest.mark.parametrize(
    ("key", "overrides", "reasons"),
    [
        ("9200", {"image": "17.12.5"}, ("capability-unknown:",)),
        ("9300", {"image": "17.12.5"}, ("capability-unknown:",)),
        ("2960x", {"image": "15.2(7)E1a"}, ("capability-unknown:",)),
        ("9200", {"license_name": "LAN Base"}, ("device-identity-incomplete:",)),
        ("c1000", {"license_name": "LAN Base"},
         ("device-identity-incomplete:", "capability-unknown:")),
    ],
)
def test_excluded_release_and_license_scopes_fail_closed(
    client: TestClient, key: str, overrides: dict[str, Any], reasons: tuple[str, ...],
) -> None:
    event_id = event(client)
    plan = plan_of(event_id, key, ports=[
        {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
    ], **overrides)
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    assert texts(document) == []
    assert document["render_state"] in {"blocked", "no-supported-candidates"}
    blockers = [
        blocker for candidate in candidates(document)
        for blocker in cast(list[str], candidate["blocking_reasons"])
    ]
    assert any(
        blocker.startswith(prefix) for prefix in reasons for blocker in blockers
    ), blockers


def test_3850_16_12_10a_renders_aggregation_only(client: TestClient) -> None:
    event_id = event(client)
    plan = plan_of(
        event_id, "3850", image="16.12.10a",
        ports=[
            {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
        ],
        channel={
            "members": [0], "settings": {"mode": "access", "access_vlan": 20},
            "lacp": "active",
        },
    )
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    rendered = {
        candidate["category"] for candidate in candidates(document)
        if candidate["status"] == "candidate"
    }
    assert rendered <= {"port-channel", "lacp-mode"}
    assert "lacp-mode" in rendered
    for category in {"speed", "duplex", "description", "admin-shutdown"}:
        assert category not in rendered


def test_unknown_serial_blocks_every_candidate(client: TestClient) -> None:
    event_id = event(client)
    plan = plan_of(
        event_id, "9300", with_serial=False,
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
    )
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    assert texts(document) == []
    assert document["render_state"] == "blocked"
    assert any(
        "serial-not-verified" in blocker
        for candidate in candidates(document)
        for blocker in cast(list[str], candidate["blocking_reasons"])
    )


def test_homogeneous_stack_renders_and_heterogeneous_stack_blocks(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = make_stack_plan(event_id)
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    assert document["device"]["stack_identity"] == "resolved"
    assert len(document["device"]["stack_members"]) == 2
    assert texts(document)

    broken_event = event(client, "Heterogeneous stack")
    broken = copy.deepcopy(make_stack_plan(broken_event))
    broken["physical_devices"][1]["model"] = "C9300-24T"
    broken["physical_devices"][1]["verified_serial"] = "SYN-OTHER-01"
    broken_revision = save(client, broken_event, broken)
    blocked = render(client, broken_event, broken_revision["id"], assignment_of(broken))
    assert texts(blocked) == []
    assert blocked["render_state"] == "blocked"
    assert any(
        "stack-identity-unresolved" in blocker
        for blocker in cast(list[str], blocked["deployment_blockers"])
    )


def test_stack_member_not_ready_blocks_every_candidate(client: TestClient) -> None:
    event_id = event(client)
    plan = make_stack_plan(event_id)
    plan["stacks"][0]["members"][1]["state"] = "missing"
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    assert texts(document) == []
    reasons = [
        blocker for candidate in candidates(document)
        for blocker in cast(list[str], candidate["blocking_reasons"])
    ]
    assert any("stack-member-not-ready" in reason for reason in reasons)
    assert any("stack-member-not-ready" in blocker for blocker in document["deployment_blockers"])


# --------------------------------------------------------------------------- #
# Category semantics
# --------------------------------------------------------------------------- #


def test_access_mode_and_access_vlan_are_separate_candidates(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    mode = [
        candidate for candidate in of_category(
            document, CandidateCategory.ACCESS_MODE,
        ) if candidate["target"]["name"] == "Gi1/0/1"
    ]
    vlan = [
        candidate for candidate in of_category(
            document, CandidateCategory.ACCESS_VLAN,
        ) if candidate["target"]["name"] == "Gi1/0/1"
    ]
    assert len(mode) == 1 and len(vlan) == 1
    assert mode[0]["candidate_text"] == "switchport mode access"
    assert vlan[0]["candidate_text"] == "switchport access vlan 20"
    assert mode[0]["candidate_id"] != vlan[0]["candidate_id"]


def test_port_channel_logical_and_member_commands_are_separate(
    client: TestClient,
) -> None:
    document, _plan, _revision = saved_document(client)
    logical = [
        candidate for candidate in of_category(document, CandidateCategory.PORT_CHANNEL)
        if candidate["target"]["kind"] == "port-channel"
        and candidate["candidate_text"] is not None
    ]
    members = [
        candidate for candidate in candidates(document)
        if candidate["target"]["kind"] == "interface"
        and "channel-group" in str(candidate["candidate_text"])
    ]
    assert [candidate["candidate_text"] for candidate in logical] == [
        "interface Port-Channel1"
    ]
    assert logical[0]["command_context"]["mode"] == "global"
    assert sorted(candidate["target"]["name"] for candidate in members) == [
        "Gi1/0/3", "Gi1/0/4"
    ]
    assert all(
        candidate["command_context"]["mode"] == "interface" for candidate in members
    )


@pytest.mark.parametrize(
    ("lacp", "expected_text", "category"),
    [
        ("active", "channel-group 1 mode active", "lacp-mode"),
        ("passive", "channel-group 1 mode passive", "lacp-mode"),
        ("static", "channel-group 1 mode on", "port-channel"),
    ],
)
def test_lacp_modes_are_rendered_without_confusing_static(
    client: TestClient, lacp: str, expected_text: str, category: str,
) -> None:
    event_id = event(client)
    plan = plan_of(
        event_id, "9300",
        ports=[
            {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
            {"name": "Gi1/0/2", "settings": {"mode": "access", "access_vlan": 20}},
        ],
        channel={
            "members": [0], "settings": {"mode": "access", "access_vlan": 20},
            "lacp": lacp,
        },
    )
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    channel_group = [
        candidate for candidate in candidates(document)
        if candidate["candidate_text"] == expected_text
    ]
    assert len(channel_group) == 1
    assert channel_group[0]["category"] == category
    assert channel_group[0]["status"] == "candidate"
    modes = {
        candidate["parameters"].get("mode") for candidate in candidates(document)
        if "channel-group" in str(candidate["candidate_text"])
    }
    if lacp == "static":
        assert "lacp-mode" not in {candidate["category"] for candidate in candidates(document)}
        assert modes == {"on"}
    else:
        assert modes == {lacp}


def test_routed_port_is_never_converted_to_switchport(client: TestClient) -> None:
    event_id = event(client)
    plan = plan_of(
        event_id, "9300",
        ports=[{
            "name": "Gi1/0/1",
            "settings": {"mode": "routed", "address": "192.0.2.1/24"},
        }],
    )
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    routed = [
        candidate for candidate in candidates(document)
        if candidate["target"]["name"] == "Gi1/0/1"
    ]
    switchport = [
        candidate for candidate in routed
        if candidate["category"] in {"access-mode", "trunk-mode", "access-vlan"}
    ]
    assert switchport
    assert all(candidate["status"] == "unsupported" for candidate in switchport)
    assert all(
        "routed-port-not-l2" in cast(list[str], candidate["blocking_reasons"])
        for candidate in switchport
    )
    assert all(candidate["candidate_text"] is None for candidate in switchport)
    assert not [text for text in texts(document) if "switchport" in text]


def test_native_vlan_and_topology_wide_changes_stay_blocked_r5(
    client: TestClient,
) -> None:
    document, _plan, _revision = saved_document(client)
    expectations = {
        CandidateCategory.NATIVE_VLAN: "r5-requires-field-topology-evidence",
        CandidateCategory.RAPID_PVST: "topology-wide-change-requires-field-evidence",
        CandidateCategory.VTP_TRANSPARENT: "topology-wide-change-requires-field-evidence",
        CandidateCategory.ROOT_PRIORITY: "topology-wide-change-requires-field-evidence",
    }
    for category, reason in expectations.items():
        found = of_category(document, category)
        assert found, category
        for candidate in found:
            assert candidate["status"] == "blocked"
            assert candidate["risk_class"] == "R5"
            assert candidate["candidate_text"] is None
            assert reason in cast(list[str], candidate["blocking_reasons"])
            assert candidate["requires_field_verification"] is True
            assert candidate["potential_connectivity_impact"] is True
    assert not [text for text in texts(document) if text.startswith("vtp mode")]
    assert not [text for text in texts(document) if text.startswith("spanning-tree mode")]
    assert not [text for text in texts(document) if "native vlan" in text]


def test_unused_port_policy_and_referenced_shutdown_stay_blocked(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = plan_of(
        event_id, "9300",
        ports=[
            {
                "name": "Gi1/0/1",
                "settings": {"mode": "access", "access_vlan": 20, "admin_state": "down"},
            },
            {
                "name": "Gi1/0/2",
                "settings": {"mode": "access", "access_vlan": 20, "admin_state": "down"},
            },
        ],
        channel={"members": [1], "settings": {"mode": "access", "access_vlan": 20}},
    )
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    unused = of_category(document, CandidateCategory.UNUSED_SHUTDOWN)
    assert unused
    assert all(candidate["status"] == "blocked" for candidate in unused)
    assert all(
        "unused-port-policy-requires-field-verification"
        in cast(list[str], candidate["blocking_reasons"])
        for candidate in unused
    )
    shutdown = [
        candidate for candidate in of_category(document, CandidateCategory.ADMIN_SHUTDOWN)
        if candidate["parameters"].get("admin-state") == "down"
    ]
    blocked = [
        candidate for candidate in shutdown
        if candidate["target"]["name"] == "Gi1/0/2"
    ]
    explicit = [
        candidate for candidate in shutdown
        if candidate["target"]["name"] == "Gi1/0/1"
    ]
    assert blocked and blocked[0]["status"] == "blocked"
    assert "shutdown-of-referenced-port-requires-topology-evidence" in cast(
        list[str], blocked[0]["blocking_reasons"]
    )
    # An explicit admin_state=down on a port the plan does not reference is a
    # deliberate R1 intent, so it renders; it is never inferred from a baseline.
    assert explicit and explicit[0]["status"] == "candidate"
    assert explicit[0]["risk_class"] == "R1"


def test_vlan_removal_and_unreferenced_never_render_delete(client: TestClient) -> None:
    event_id = event(client)
    first = plan_of(
        event_id, "9300",
        ports=[{
            "name": "Gi1/0/1",
            "settings": {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20, 30]},
        }],
    )
    first_revision = save(client, event_id, first)
    assert render(client, event_id, first_revision["id"], assignment_of(first))

    second = copy.deepcopy(first)
    second["physical_interfaces"][0]["settings"]["allowed_vlans"] = [10, 20]
    second_revision = save(client, event_id, second)
    document = render(client, event_id, second_revision["id"], assignment_of(second))
    assert not [text for text in texts(document) if "vlan" in text and text.startswith("no")]
    removed = [
        candidate for candidate in of_category(document, CandidateCategory.VLAN_DEFINITION)
        if candidate["status"] != "candidate"
    ]
    assert removed
    assert any(
        "vlan-removal-not-rendered" in cast(list[str], candidate["blocking_reasons"])
        for candidate in removed
    )


def test_vlan_definitions_follow_device_references_not_the_event_database(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = plan_of(
        event_id, "9300",
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
    )
    plan["vlans"].append({"id": 40, "name": "Unreferenced", "purpose": "ordinary"})
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    vlan_targets = {
        candidate["target"]["name"] for candidate in candidates(document)
        if candidate["target"]["kind"] == "vlan"
    }
    assert vlan_targets == {"VLAN 20"}
    assert "vlan 40" not in texts(document)


def test_vlan_definition_and_name_are_rendered_as_distinct_commands(
    client: TestClient,
) -> None:
    document, _plan, _revision = saved_document(client)
    definitions = of_category(document, CandidateCategory.VLAN_DEFINITION)
    rendered = [candidate["candidate_text"] for candidate in definitions
                if candidate["status"] == "candidate"]
    assert "vlan 20" in rendered
    assert "name Players" in rendered
    name = next(candidate for candidate in definitions
                if candidate["candidate_text"] == "name Players")
    assert name["command_context"]["mode"] == "vlan"
    assert name["command_context"]["mode_header"] == "vlan 20"
    assert name["risk_class"] == "R2"


def test_static_plan_records_no_cleanup_only_candidate(
    client: TestClient,
) -> None:
    document, _plan, _revision = saved_document(client)
    for candidate in candidates(document):
        if candidate["status"] == "candidate":
            assert not candidate["provenance"]["cleanup"]
            assert candidate["risk_class"] in {"R0", "R1", "R2", "R3"}


# --------------------------------------------------------------------------- #
# Text and parameter validation
# --------------------------------------------------------------------------- #

ALLOWED_DESCRIPTIONS = [
    "A",
    "Players desk",
    "Rack 2 / U14 - uplink to core",
    "AP-3F-01 55.5%",
]

INJECTION_DESCRIPTIONS = [
    "players; reload",
    "players!",
    "#comment",
    'quote"inside',
    "single'quote",
    "back\\slash",
    "back`tick",
    "pipe|cmd",
    "amp&ersand",
    "angle<b>",
    "question?",
    "star*",
    "dollar$",
    "equals=",
    "paren(s)",
    "bracket[s]",
    "brace{s}",
    "tilde~",
    "caret^",
    "caf\u00e9",
]


def test_description_characters_are_revalidated_end_to_end(client: TestClient) -> None:
    for description in INJECTION_DESCRIPTIONS:
        event_id = event(client)
        plan = plan_of(
            event_id, "3850",
            ports=[{
                "name": "Gi1/0/1",
                "settings": {
                    "mode": "access", "access_vlan": 20, "description": description,
                },
            }],
        )
        revision = save(client, event_id, plan)
        document = render(client, event_id, revision["id"], assignment_of(plan))
        found = of_category(document, CandidateCategory.DESCRIPTION)
        assert len(found) == 1, description
        assert found[0]["status"] == "blocked", description
        assert found[0]["candidate_text"] is None
        assert "unsafe-text:description:Gi1/0/1" in cast(
            list[str], found[0]["blocking_reasons"]
        )
        assert description not in texts(document)


@pytest.mark.parametrize("description", ALLOWED_DESCRIPTIONS)
def test_allowed_descriptions_render_once(
    client: TestClient, description: str,
) -> None:
    event_id = event(client)
    plan = plan_of(
        event_id, "3850",
        ports=[{
            "name": "Gi1/0/1",
            "settings": {"mode": "access", "access_vlan": 20, "description": description},
        }],
    )
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    found = of_category(document, CandidateCategory.DESCRIPTION)
    assert [candidate["candidate_text"] for candidate in found] == [
        f"description {description}"
    ]
    assert found[0]["status"] == "candidate"


def test_description_length_boundary_minus_one_and_two_consecutive_spaces(
    client: TestClient,
) -> None:
    allowed = "D" * 240
    event_id = event(client)
    plan = plan_of(
        event_id, "3850",
        ports=[{
            "name": "Gi1/0/1",
            "settings": {"mode": "access", "access_vlan": 20, "description": allowed},
        }],
    )
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    found = of_category(document, CandidateCategory.DESCRIPTION)
    assert found[0]["status"] == "candidate"
    assert found[0]["candidate_text"] == f"description {allowed}"

    spaced = plan_of(
        event_id, "3850",
        ports=[{
            "name": "Gi1/0/1",
            "settings": {
                "mode": "access", "access_vlan": 20, "description": "two  spaces",
            },
        }],
    )
    revision = save(client, event_id, spaced)
    blocked = render(client, event_id, revision["id"], assignment_of(spaced))
    reason = of_category(blocked, CandidateCategory.DESCRIPTION)[0]
    assert reason["status"] == "blocked"
    assert "unsafe-text-class:unsafe-whitespace" in cast(
        list[str], reason["blocking_reasons"]
    )


def test_description_over_limit_is_rejected_before_storage(client: TestClient) -> None:
    event_id = event(client)
    plan = plan_of(
        event_id, "9300",
        ports=[{
            "name": "Gi1/0/1",
            "settings": {
                "mode": "access", "access_vlan": 20, "description": "D" * 241,
            },
        }],
    )
    response = client.post(f"{API}/events/{event_id}/plan-revisions", json=plan)
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("A", None),
        ("VOICE_20", None),
        ("players.desk-2", None),
        ("A" * 32, None),
        ("A" * 33, "unsafe-text-class:vlan-name-too-long"),
        ("players desk", "unsafe-text-class:forbidden-character"),
        ("players;reload", "unsafe-text-class:forbidden-character"),
        ("-leading", "unsafe-text-class:forbidden-character"),
        ("_leading", "unsafe-text-class:forbidden-character"),
        ("caf\u00e9", "unsafe-text-class:non-ascii-vlan-name"),
    ],
)
def test_vlan_name_policy(value: str, expected: str | None) -> None:
    assert vlan_name_reason(value, 32) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Players desk", None),
        ("Rack 2 / U14 - uplink", None),
        ("  leading", "unsafe-text-class:unsafe-whitespace"),
        ("trailing ", "unsafe-text-class:unsafe-whitespace"),
        ("two  spaces", "unsafe-text-class:unsafe-whitespace"),
        ("line1\nline2", "unsafe-text-class:forbidden-character"),
        ("line1\rline2", "unsafe-text-class:forbidden-character"),
        ("null\x00byte", "unsafe-text-class:forbidden-character"),
        ("escape\x1b[31m", "unsafe-text-class:forbidden-character"),
        ("tab\there", "unsafe-text-class:forbidden-character"),
        ("semi;colon", "unsafe-text-class:forbidden-character"),
        ("caf\u00e9", "unsafe-text-class:non-ascii-description"),
        ("\u200bzero", "unsafe-text-class:non-ascii-description"),
        ("", "unsafe-text-class:empty-description"),
        ("D" * 241, "unsafe-text-class:description-too-long"),
    ],
)
def test_description_policy(value: str, expected: str | None) -> None:
    assert description_reason(value, 240) == expected


def test_vlan_name_boundary_renders_and_overlong_name_blocks(
    client: TestClient,
) -> None:
    for vlan_name, expected_status in (("A" * 32, "candidate"), ("A" * 33, "blocked")):
        event_id = event(client)
        plan = plan_of(
            event_id, "9300",
            ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}}],
        )
        plan["vlans"][1]["name"] = vlan_name
        revision = save(client, event_id, plan)
        document = render(client, event_id, revision["id"], assignment_of(plan))
        names = [
            candidate for candidate in of_category(
                document, CandidateCategory.VLAN_DEFINITION,
            ) if candidate["parameters"].get("vlan-name") == vlan_name
        ]
        if expected_status == "candidate":
            assert len(names) == 1
            assert names[0]["status"] == "candidate"
        else:
            assert len(names) == 1
            assert names[0]["status"] == "blocked"
            assert names[0]["candidate_text"] is None
            assert "unsafe-text-class:vlan-name-too-long" in cast(
                list[str], names[0]["blocking_reasons"]
            )


def test_interface_names_are_revalidated_against_the_exact_port_layout(
    client: TestClient,
) -> None:
    event_id = event(client)
    plan = plan_of(
        event_id, "9300",
        ports=[
            {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20}},
            {"name": "Gi1/0/99", "settings": {"mode": "access", "access_vlan": 20}},
            {"name": "Te1/1/9", "settings": {"mode": "access", "access_vlan": 20}},
        ],
    )
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    for name in ("Gi1/0/99", "Te1/1/9"):
        found = [
            candidate for candidate in candidates(document)
            if candidate["target"]["name"] == name
        ]
        assert found
        assert all(candidate["status"] != "candidate" for candidate in found)
        assert all(candidate["candidate_text"] is None for candidate in found)
        assert any(
            "unsafe-text-class:forbidden-interface-name" in cast(
                list[str], candidate["blocking_reasons"]
            )
            or "interface-not-in-documented-layout" in cast(
                list[str], candidate["blocking_reasons"]
            )
            for candidate in found
        )
    assert "switchport access vlan 20" in texts(document)


@pytest.mark.parametrize(
    "name",
    ["Gi1/0/1\n", "Gi1/0/1\r", "Gi1/0/1\x00", "Fa0/1", "Gi1/0/1;reload",
     "Gi1/0/1 ", "\u0130i1/0/1"],
)
def test_interface_name_validator_rejects_boundary_forms(name: str) -> None:
    from event_switch_manager.cisco_catalog import PROFILES

    assert interface_name_reason(name, PROFILES["C9300L-24P-4X"], 1) is not None


def test_interface_name_validator_accepts_the_documented_port() -> None:
    from event_switch_manager.cisco_catalog import PROFILES

    profile = PROFILES["C9300L-24P-4X"]
    assert interface_name_reason("Gi1/0/1", profile, 1) is None
    assert interface_name_reason("Gi1/0/24", profile, 1) is None
    assert interface_name_reason("Te1/1/1", profile, 1) is None
    assert interface_name_reason("Gi1/0/25", profile, 1) is not None
    assert interface_name_reason("Gi1/1/1", profile, 1) is not None
    assert interface_name_reason("Gi2/0/1", profile, 1) is not None


@pytest.mark.parametrize(
    ("name", "number", "expected"),
    [
        ("Port-channel1", 1, None),
        ("Port-Channel12", 12, None),
        ("Port-Channel1", 2, "port-channel-name-number-mismatch"),
        ("Port-Channel0", 0, "unsafe-text-class:forbidden-port-channel-name"),
        ("Port-Channel1\n", 1, "unsafe-text-class:forbidden-port-channel-name"),
        ("Gi1/0/1", 1, "unsafe-text-class:forbidden-port-channel-name"),
        ("", 1, "unsafe-text-class:empty-port-channel-name"),
    ],
)
def test_port_channel_name_policy(name: str, number: int, expected: str | None) -> None:
    assert port_channel_name_reason(name, number) == expected


def test_reserved_and_out_of_range_vlan_ids_block_or_fail_import(
    client: TestClient,
) -> None:
    event_id = event(client)
    reserved = plan_of(
        event_id, "9300",
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 1002}}],
    )
    reserved["vlans"].append(
        {"id": 1002, "name": "ReservedRange", "purpose": "ordinary"}
    )
    revision = save(client, event_id, reserved)
    document = render(client, event_id, revision["id"], assignment_of(reserved))
    found = of_category(document, CandidateCategory.ACCESS_VLAN)
    assert found[0]["status"] == "blocked"
    assert "parameter-reserved-value:vlan-id" in cast(
        list[str], found[0]["blocking_reasons"]
    )

    out_of_range = plan_of(
        event_id, "9300",
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 4095}}],
    )
    assert client.post(
        f"{API}/events/{event_id}/plan-revisions", json=out_of_range,
    ).status_code == 422


def test_unreferenced_vlan_reference_blocks(client: TestClient) -> None:
    # The API refuses an unknown VLAN reference at import time, so the renderer
    # guard is exercised directly: a revision stored under an earlier validator
    # must still never render a reference to an undefined VLAN.
    event_id = str(uuid4())
    plan = plan_of(
        event_id, "9300",
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 60}}],
    )
    revision, intent, preview = in_process(plan)
    document = build_l2_cli_candidates(revision, intent, preview)
    found = [
        candidate for candidate in document.candidates
        if candidate.category is CandidateCategory.ACCESS_VLAN
    ]
    assert found
    assert found[0].status is CandidateStatus.BLOCKED
    assert found[0].candidate_text is None
    assert any(
        "intent-not-valid" in reason or "vlan-not-defined-in-event-plan" in reason
        for reason in found[0].blocking_reasons
    )

    rejected = plan_of(
        event_id, "9300",
        ports=[{"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 60}}],
    )
    response = client.post(
        f"{API}/events/{event(client)}/plan-revisions", json=rejected,
    )
    assert response.status_code == 422


def test_speed_and_duplex_limits_follow_capability_evidence(client: TestClient) -> None:
    event_id = event(client)
    plan = plan_of(
        event_id, "9300",
        ports=[
            {"name": "Gi1/0/1", "settings": {"mode": "access", "access_vlan": 20,
                                             "speed": 2500}},
            {"name": "Gi1/0/2", "settings": {"mode": "access", "access_vlan": 20,
                                             "speed": 1000, "duplex": "half"}},
            {"name": "Gi1/0/3", "settings": {"mode": "access", "access_vlan": 20,
                                             "speed": 100, "duplex": "half"}},
        ],
    )
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    speed = [
        candidate for candidate in of_category(document, CandidateCategory.SPEED)
        if candidate["target"]["name"] == "Gi1/0/1"
    ]
    assert speed[0]["status"] in {"blocked", "unsupported"}
    assert speed[0]["candidate_text"] is None
    duplex = [
        candidate for candidate in of_category(document, CandidateCategory.DUPLEX)
        if candidate["target"]["name"] == "Gi1/0/2"
    ]
    assert duplex[0]["status"] in {"blocked", "unsupported"}
    half_ok = [
        candidate for candidate in of_category(document, CandidateCategory.DUPLEX)
        if candidate["target"]["name"] == "Gi1/0/3"
    ]
    assert half_ok[0]["status"] == "candidate"
    assert half_ok[0]["candidate_text"] == "duplex half"


def test_admin_shutdown_up_renders_no_shutdown(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    up = [
        candidate for candidate in of_category(document, CandidateCategory.ADMIN_SHUTDOWN)
        if candidate["target"]["name"] == "Gi1/0/1"
    ]
    assert up[0]["status"] == "candidate"
    assert up[0]["candidate_text"] == "no shutdown"
    assert up[0]["risk_class"] == "R1"


def test_portfast_and_bpdu_guard_render_edge_forms_only(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    portfast = of_category(document, CandidateCategory.PORTFAST)
    assert [candidate["candidate_text"] for candidate in portfast] == [
        "spanning-tree portfast"
    ]
    guard = of_category(document, CandidateCategory.BPDU_GUARD)
    assert [candidate["candidate_text"] for candidate in guard] == [
        "spanning-tree bpduguard enable"
    ]
    assert all(candidate["risk_class"] == "R2" for candidate in portfast + guard)


# --------------------------------------------------------------------------- #
# Fail-closed rendering with unreviewed or tampered evidence
# --------------------------------------------------------------------------- #


def test_unreviewed_command_evidence_produces_zero_candidate_text() -> None:
    event_id = str(uuid4())
    plan = full_plan(event_id)
    revision, intent, preview = in_process(plan)
    pending = CommandEvidenceRegistry(
        tuple(dataclasses.replace(row, review=PENDING_REVIEW) for row in ROWS)
    )
    document = build_l2_cli_candidates(revision, intent, preview, registry=pending)
    assert texts(document.model_dump(mode="json")) == []
    assert all(
        candidate.status is not CandidateStatus.CANDIDATE
        for candidate in document.candidates
    )
    assert any(
        reason.startswith("syntax-evidence-not-reviewed:")
        for candidate in document.candidates
        for reason in candidate.blocking_reasons
    )


def test_render_fingerprint_binds_the_evidence_registry_version() -> None:
    event_id = str(uuid4())
    plan = full_plan(event_id)
    revision, intent, preview = in_process(plan)
    baseline = build_l2_cli_candidates(revision, intent, preview)
    assert evidence_fingerprint(DEFAULT_REGISTRY) in {
        baseline.source.command_evidence_fingerprint
    }
    changed_registry = CommandEvidenceRegistry(tuple(
        dataclasses.replace(
            row,
            review=EvidenceReview(
                EvidenceReviewState.REVIEWED,
                "second-reviewer",
                "2026-11-20",
                ("Re-reviewed for the fingerprint regression.",),
            ),
        )
        for row in ROWS
    ))
    changed = build_l2_cli_candidates(
        revision, intent, preview, registry=changed_registry,
    )
    assert changed.render_fingerprint != baseline.render_fingerprint
    assert changed.source.command_evidence_fingerprint != (
        baseline.source.command_evidence_fingerprint
    )


def test_stored_revision_tampering_fails_closed() -> None:
    event_id = str(uuid4())
    plan = full_plan(event_id)
    revision, intent, preview = in_process(plan)
    tampered = revision.model_copy(update={"content_hash": "0" * 64})
    with pytest.raises(RenderBindingError, match="stored-revision-integrity-failure"):
        build_l2_cli_candidates(tampered, intent, preview)


def test_intent_and_preview_tampering_fails_closed() -> None:
    event_id = str(uuid4())
    plan = full_plan(event_id)
    revision, intent, preview = in_process(plan)
    broken_intent = intent.model_copy(update={"intent_fingerprint": "0" * 64})
    with pytest.raises(RenderBindingError, match="intent-rebuild-mismatch"):
        build_l2_cli_candidates(revision, broken_intent, preview)
    broken_preview = preview.model_copy(update={"preview_fingerprint": "0" * 64})
    with pytest.raises(RenderBindingError, match="preview-rebuild-mismatch"):
        build_l2_cli_candidates(revision, intent, broken_preview)
    verify_render_binding(revision, intent, preview)


def test_api_returns_409_when_a_stored_revision_is_tampered(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = event(client)
    plan = full_plan(event_id)
    revision = save(client, event_id, plan)
    # A plan revision is immutable at the database level, so the integrity check
    # is exercised by making the recomputed hash disagree with the stored one.
    import event_switch_manager.planning.layer2_cli_candidates as candidates_module

    monkeypatch.setattr(candidates_module, "plan_hash", lambda _content: "0" * 64)
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{assignment_of(plan)}/l2-cli-candidates"
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "stored-revision-integrity-failure"


# --------------------------------------------------------------------------- #
# Candidate identity, provenance and determinism
# --------------------------------------------------------------------------- #


def test_candidate_ids_are_unique_and_semantic(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    identifiers = [candidate["candidate_id"] for candidate in candidates(document)]
    assert len(identifiers) == len(set(identifiers))
    same_target = [
        candidate for candidate in candidates(document)
        if candidate["target"]["name"] == "Gi1/0/1"
    ]
    assert len(same_target) > 3
    assert len({candidate["candidate_id"] for candidate in same_target}) == len(
        same_target
    )


def test_provenance_traces_back_to_the_b1_preview_item(client: TestClient) -> None:
    event_id = event(client)
    plan = full_plan(event_id)
    revision = save(client, event_id, plan)
    document = render(client, event_id, revision["id"], assignment_of(plan))
    preview = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision['id']}"
        f"/layer2-config-preview/devices/{assignment_of(plan)}"
    )
    assert preview.status_code == 200
    preview_items = {
        item["item_id"] for item in preview.json()["device"]["config_items"]
    }
    for candidate in candidates(document):
        provenance = cast(dict[str, Any], candidate["provenance"])
        assert provenance["preview_item_id"] in preview_items
        assert provenance["planned_source"] in {
            "event-plan", "management-vlan", "reviewed-default-policy",
            "platform-default", "not-in-plan",
        }


def test_evidence_references_are_deduplicated_and_typed(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    evidence = cast(list[dict[str, Any]], document["evidence"])
    assert evidence
    identifiers = [(row["kind"], row["reference_id"]) for row in evidence]
    assert len(identifiers) == len(set(identifiers))
    assert {row["kind"] for row in evidence} == {"capability", "syntax"}
    syntax_rows = [row for row in evidence if row["kind"] == "syntax"]
    assert all(row["reference_id"].startswith("l1-") for row in syntax_rows)


def test_syntax_evidence_is_scoped_to_the_exact_pid_and_release(
    client: TestClient,
) -> None:
    document, _plan, _revision = saved_document(client)
    for candidate in candidates(document):
        for syntax in cast(list[dict[str, Any]], candidate["syntax_evidence"]):
            assert "17.12.4" in str(syntax["release"])
            assert syntax["review_state"] == "independently-reviewed"
            assert syntax["source_url"].startswith("https://www.cisco.com/")


def test_unresolved_prerequisites_are_deduplicated(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    prerequisites = cast(list[str], document["unresolved_prerequisites"])
    assert len(prerequisites) == len(set(prerequisites))
    assert "unused-port-policy-requires-field-verification" in prerequisites
    assert "field-verification-required" in prerequisites


# --------------------------------------------------------------------------- #
# Published schema
# --------------------------------------------------------------------------- #


def test_document_schema_is_directly_validatable(client: TestClient) -> None:
    response = client.get(f"{API}/contracts/l2-cli-candidates/schema")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/schema+json")
    schema = cast(dict[str, Any], response.json())
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema.get("type") == "object"
    assert schema.get("required")
    Draft202012Validator.check_schema(schema)

    document, _plan, _revision = saved_document(client)
    errors = list(Draft202012Validator(schema).iter_errors(document))
    assert errors == []


def test_catalog_route_is_labeled_as_a_catalog_not_a_validator(
    client: TestClient,
) -> None:
    response = client.get(f"{API}/contracts/l2-cli-candidates/schema/catalog")
    assert response.status_code == 200
    catalog = cast(dict[str, Any], response.json())
    assert catalog["contract_id"] == CONTRACT_ID
    assert catalog["render_schema_version"] == RENDER_SCHEMA_VERSION
    assert catalog["command_evidence_registry_id"] == EVIDENCE_REGISTRY_ID
    assert "$schema" not in catalog
    assert catalog["document"]["$schema"] == (
        "https://json-schema.org/draft/2020-12/schema"
    )
    Draft202012Validator.check_schema(candidate_catalog_json_schema()["document"])
    assert candidate_document_json_schema()["type"] == "object"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda document: document.update({"render_schema_version": 2}),
        lambda document: document.update({"contract_id": "other-contract"}),
        lambda document: document.update({"render_state": "deployed"}),
        lambda document: document.pop("safety"),
        lambda document: document.update({"extra": True}),
        lambda document: document["candidates"][0].update({"status": "candidate",
                                                           "candidate_text": None}),
        lambda document: document["candidates"][0].update({"risk_class": "R9"}),
        lambda document: document["candidates"][0].update({"candidate_id": "x"}),
        lambda document: document["safety"].update({"executable": True}),
    ],
)
def test_schema_rejects_tampered_documents(
    client: TestClient, mutation: Any,
) -> None:
    document, _plan, _revision = saved_document(client)
    schema = candidate_document_json_schema()
    Draft202012Validator.check_schema(schema)
    tampered = copy.deepcopy(document)
    mutation(tampered)
    assert list(Draft202012Validator(schema).iter_errors(tampered))


# --------------------------------------------------------------------------- #
# No execution, no device, no full configuration
# --------------------------------------------------------------------------- #


def test_document_exposes_no_command_sequence_or_full_configuration(
    client: TestClient,
) -> None:
    document, _plan, _revision = saved_document(client)

    def walk(value: object) -> Iterator[tuple[str, object]]:
        if isinstance(value, dict):
            mapping = cast(dict[str, Any], value)
            for key, item in mapping.items():
                yield key, item
                yield from walk(item)
        elif isinstance(value, list):
            for item in value:
                yield from walk(item)

    keys = {key for key, _value in walk(document)}
    assert not keys & FORBIDDEN_KEYS
    for candidate in candidates(document):
        text = candidate["candidate_text"]
        if text is None:
            continue
        assert "\n" not in text and "\r" not in text
        assert len(text.splitlines()) == 1
        assert CLI_LINE.match(text), text
        lowered = text.casefold()
        for fragment in FORBIDDEN_TEXT:
            assert fragment not in lowered, text
    assert document["safety"]["cli"] is None
    assert document["safety"]["deployment_artifact"] is None


def test_renderer_module_imports_no_device_or_network_path() -> None:
    source = Path(
        "src/event_switch_manager/planning/layer2_cli_candidates.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "import socket", "import paramiko", "import netmiko", "import napalm",
        "import subprocess", "import requests", "import httpx", "import telnetlib",
        "os.system", "pysnmp",
    ):
        assert forbidden not in source
    for forbidden in ("write(", "commit(", "execute(", ".connect("):
        assert forbidden not in source


def test_candidate_route_is_read_only() -> None:
    from event_switch_manager.plan_api import router

    paths = {
        route.path: route.methods  # type: ignore[attr-defined]
        for route in router.routes
        if getattr(route, "path", "").endswith("/l2-cli-candidates")
    }
    assert list(paths) == [
        "/api/v1/events/{event_id}/plan-revisions/{revision_id}"
        "/assignments/{assignment_id}/l2-cli-candidates"
    ]
    assert paths[next(iter(paths))] == {"GET"}


def test_no_candidate_is_claimed_as_parser_verified(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    for candidate in candidates(document):
        assert candidate["syntax_validation"]["parser_verified"] is False
        assert candidate["syntax_validation"]["level"] == "dictionary-only"
    assert document["render_state"] != "deployed"


def test_full_document_round_trips_through_the_typed_model(client: TestClient) -> None:
    document, _plan, _revision = saved_document(client)
    model = L2CliCandidateDocument.model_validate(document)
    assert model.model_dump(mode="json") == document
    assert model.safety.candidate_only is True
    assert model.safety.executable is False
    assert model.render_fingerprint == render_fingerprint(model)
