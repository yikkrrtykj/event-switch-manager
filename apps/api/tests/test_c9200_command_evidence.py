"""CIS-03-04A-2 Catalyst 9200 evidence draft tests.

These tests verify the evidence-review artifact only.  They do not promote any
row into a production Registry and do not assert that a PENDING command is
approved.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from layer3_helpers import make_l3_plan, revision_for
from test_event_plans import API, ORIGIN

from event_switch_manager.app import create_app
from event_switch_manager.planning import layer3_c9200_command_evidence as c9200_evidence
from event_switch_manager.planning import layer3_capability
from event_switch_manager.planning.layer3_c9200_command_evidence import (
    C9200_DRAFT_REGISTRY_ID,
    C9200_HARDWARE_PIDS,
    C9200_LICENSES,
    C9200_ORDERING_SKU_DEFAULT_LICENSES,
    C9200_ORDERING_SKUS,
    C9200_PIDS,
    C9200_RELEASE,
    C9200_RELEASE_WHATS_NEW,
    DRAFT_REGISTRY,
    ROWS,
    pending_digests,
)
from event_switch_manager.planning.layer3_cli_candidates import (
    build_l3_cli_candidates,
)
from event_switch_manager.planning.layer3_command_evidence import (
    DEFAULT_REGISTRY,
    EvidenceReviewState,
    EvidenceStatus,
    L3CommandTopic,
)
from event_switch_manager.planning.layer3_intent import (
    L3DeviceIntent,
    Layer3Intent,
    build_layer3_intent,
)
from event_switch_manager.planning.layer3_registry_selection import (
    UNREVIEWED_PLATFORM_REGISTRY,
    select_l3_registry,
)
from event_switch_manager.planning.plan import PlanRevision
from event_switch_manager.settings import Settings

C9200 = {"core_pid": "C9200L-24P-4X", "core_family": "catalyst-9200"}
FROZEN_9300_FINGERPRINT = (
    "27d9c46f610b974de5570fb13e115260e2d109475a8d967704de9bb9ca6ef00b"
)
EXPECTED_DIGESTS = {
    "l3-9200-ip-routing-v1": (
        "84fb338c43bd5584f0797baf9172291973f26720227dc18bbf0fb09a48c4db38"
    ),
    "l3-9200-svi-interface-v1": (
        "37223459db80efc3d531a6ccf898c217fc7319893cbee56d3c7ec4eccf2e2193"
    ),
    "l3-9200-svi-address-v1": (
        "e61264cf0a1b2441f443b8e5213e42ef3b2b6db946619909bd396650ba56c6d9"
    ),
    "l3-9200-static-route-v1": (
        "8206b57a147c5d3a4a3b29506a91ec9f7de1b586ed0fd074f30bae453df55a4a"
    ),
}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(
        create_app(Settings(database_path=tmp_path / "c9200-evidence.sqlite3")),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN},
    ) as session:
        yield session


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


def _event(client: TestClient) -> str:
    response = client.post(
        f"{API}/events", json={"name": "R54 C9200", "management_vlan": 10},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _save(client: TestClient, event_id: str, plan: dict[str, Any]) -> dict[str, Any]:
    changed = dict(plan)
    changed["event_id"] = event_id
    response = client.post(f"{API}/events/{event_id}/plan-revisions", json=changed)
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def _assignment(plan: dict[str, Any], hostname: str = "L3-Core") -> str:
    return str(next(
        item["id"] for item in plan["assignments"]
        if item["hostname"] == hostname
    ))


def test_exactly_four_topics_have_independent_family_and_grammar() -> None:
    assert {row.topic for row in ROWS} == {
        L3CommandTopic.IP_ROUTING,
        L3CommandTopic.SVI_INTERFACE,
        L3CommandTopic.SVI_ADDRESS,
        L3CommandTopic.STATIC_ROUTE,
    }
    assert all(row.family.value == "catalyst-9200" for row in ROWS)
    assert {row.evidence_id for row in ROWS} == set(EXPECTED_DIGESTS)
    assert all(row.evidence_id.startswith("l3-9200-") for row in ROWS)
    assert all("9300" not in row.evidence_id for row in ROWS)
    expected_grammar = {
        L3CommandTopic.IP_ROUTING: "ip routing",
        L3CommandTopic.SVI_INTERFACE: "interface Vlan<vlan-id>",
        L3CommandTopic.SVI_ADDRESS: "ip address <ip-address> <subnet-mask>",
        L3CommandTopic.STATIC_ROUTE: "ip route <network> <mask> <next-hop>",
    }
    for row in ROWS:
        assert row.command == expected_grammar[row.topic]
        assert row.grammar == expected_grammar[row.topic]
        assert row.mode.value in {"global", "interface"}


def test_hardware_pids_ordering_skus_and_default_license_mapping() -> None:
    assert C9200_HARDWARE_PIDS == (
        "C9200-24T", "C9200-24P", "C9200L-24T-4G", "C9200L-24P-4X",
    )
    assert C9200_ORDERING_SKUS == (
        "C9200L-24T-4G-E", "C9200L-24P-4X-A",
    )
    assert C9200_PIDS == C9200_HARDWARE_PIDS + C9200_ORDERING_SKUS
    assert set(C9200_HARDWARE_PIDS).isdisjoint(C9200_ORDERING_SKUS)
    assert C9200_ORDERING_SKU_DEFAULT_LICENSES == {
        "C9200L-24T-4G-E": "Network Essentials",
        "C9200L-24P-4X-A": "Network Advantage",
    }
    for row in ROWS:
        assert row.classification is not None
        assert row.pids == C9200_PIDS
        assert row.classification.hardware_pids == C9200_HARDWARE_PIDS
        assert row.classification.ordering_skus == C9200_ORDERING_SKUS
        assert row.classification.verified_pids == C9200_PIDS
        assert "ordering-sku-default-license-is-not-active-license" in (
            row.classification.excluded_scope_notes
        )
        for pid in C9200_PIDS:
            matched = DRAFT_REGISTRY.matching(
                row.topic, pid, C9200_RELEASE, "Network Advantage",
            )
            assert matched == (row,)
        assert DRAFT_REGISTRY.matching(
            row.topic, "C9300L-24P-4X", C9200_RELEASE, "Network Advantage",
        ) == ()
        assert DRAFT_REGISTRY.matching(
            row.topic, None, C9200_RELEASE, "Network Advantage",
        ) == ()


def test_evidence_pid_scope_is_owned_by_the_evidence_module() -> None:
    assert c9200_evidence.C9200_PIDS == C9200_PIDS
    assert not hasattr(c9200_evidence, "_9200_PIDS")
    # Current expected relation to Capability.  A future Capability expansion
    # must deliberately update this test and the Evidence scope, not inherit it.
    assert set(C9200_PIDS) == set(layer3_capability._9200_PIDS)


def test_exact_syntax_and_official_sections_are_bound() -> None:
    expected = {
        L3CommandTopic.IP_ROUTING: (
            "Configuration Guidelines for IP Routing", None, False,
        ),
        L3CommandTopic.SVI_INTERFACE: (
            "Configuration Guidelines for IP Routing", "interface", False,
        ),
        L3CommandTopic.SVI_ADDRESS: (
            "Assigning IP Addresses to Network Interfaces", "ip address", False,
        ),
        L3CommandTopic.STATIC_ROUTE: (
            "Configuring Static Unicast Routes", "ip route", True,
        ),
    }
    for row in ROWS:
        source_section, reference_section, generic = expected[row.topic]
        assert row.source_section == source_section
        assert row.command_reference_section == reference_section
        assert row.classification is not None
        assert row.classification.generic_command_reference is generic
        if row.topic is L3CommandTopic.SVI_INTERFACE:
            assert row.limits and "interface vlan vlan-id" in " ".join(row.limits)
        if row.topic is L3CommandTopic.STATIC_ROUTE:
            assert any(
                "interface next-hop and distance" in limit
                for limit in row.limits
            )


def test_release_scope_is_17_12_4_and_other_releases_do_not_match() -> None:
    for row in ROWS:
        assert row.releases == (C9200_RELEASE,)
        assert any(
            source.url == C9200_RELEASE_WHATS_NEW
            for source in row.supplemental_sources
        )
        assert DRAFT_REGISTRY.matching(
            row.topic, "C9200L-24P-4X", "17.12.5", "Network Advantage",
        ) == ()
        assert DRAFT_REGISTRY.matching(
            row.topic, "C9200L-24P-4X", None, "Network Advantage",
        ) == ()


def test_license_evidence_is_verified_for_basic_routing_and_dna_is_excluded() -> None:
    for row in ROWS:
        assert row.licenses == C9200_LICENSES
        assert row.classification is not None
        assert row.classification.license_evidence is EvidenceStatus.VERIFIED
        assert row.classification.license_source_url is not None
        assert row.classification.license_source_section == "Interface Connections"
        assert not any(
            "license" in reason for reason in row.scope_blockers()
        )
        assert "actual-active-license-not-hardware-verified" in (
            row.classification.excluded_scope_notes
        )
        for license_name in C9200_LICENSES:
            assert DRAFT_REGISTRY.matching(
                row.topic, "C9200L-24P-4X", C9200_RELEASE, license_name,
            ) == (row,)
        for rejected in ("DNA Essentials", "DNA Advantage", "Unknown License"):
            assert DRAFT_REGISTRY.matching(
                row.topic, "C9200L-24P-4X", C9200_RELEASE, rejected,
            ) == ()


def test_pending_review_and_unreviewed_rows_cannot_render() -> None:
    assert all(row.review.state is EvidenceReviewState.PENDING for row in ROWS)
    assert all(not row.renderable for row in ROWS)
    assert DRAFT_REGISTRY.registry_id == C9200_DRAFT_REGISTRY_ID
    assert DRAFT_REGISTRY.production is False
    assert DRAFT_REGISTRY.renderable_count == 0
    assert all(row.scope_blockers() for row in ROWS)


def test_digests_are_deterministic_and_tampering_changes_them() -> None:
    first = pending_digests()
    second = pending_digests()
    assert first == second == EXPECTED_DIGESTS
    assert all(len(value) == 64 for value in first.values())
    original = ROWS[0]
    tampered = replace(original, limits=original.limits + ("tampered-limit",))
    assert tampered.content_digest() != original.content_digest()
    tampered_command = replace(original, command="ip routing modified")
    assert tampered_command.content_digest() != original.content_digest()


def test_unreviewed_draft_registry_cannot_emit_cli_text() -> None:
    revision, intent, core = _intent(C9200)
    document = build_l3_cli_candidates(
        revision, intent, core.identity.assignment_id, DRAFT_REGISTRY,
        test_only_registry=True,
    )
    assert document.summary.candidates == 0
    assert document.summary.total > 0
    assert all(item.candidate_text is None for item in document.candidates)
    assert all(item.status.value == "blocked" for item in document.candidates)


def test_c9200_production_selection_is_still_the_rowless_sentinel() -> None:
    _, _, core = _intent(C9200)
    selection = select_l3_registry(core.identity)
    assert selection.registry is UNREVIEWED_PLATFORM_REGISTRY
    assert selection.registry is not DRAFT_REGISTRY
    assert selection.registry.rows == ()
    assert selection.registry.renderable_count == 0
    assert selection.registry.registry_id != C9200_DRAFT_REGISTRY_ID


def test_c9200_api_remains_all_blocked_with_no_new_cli(client: TestClient) -> None:
    event_id = _event(client)
    plan = make_l3_plan(
        event_id, core_pid="C9200L-24P-4X", core_family="catalyst-9200",
        with_relay=False, static_route_count=1,
    )
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    base = (
        f"{API}/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{assignment_id}"
    )
    candidates = client.get(base + "/l3-cli-candidates")
    assert candidates.status_code == 200, candidates.text
    body = candidates.json()
    assert body["source"]["command_evidence_registry_id"] == (
        "cis-03-l1-command-evidence-unreviewed-v1"
    )
    assert body["summary"]["candidates"] == 0
    assert body["summary"]["blocked"] > 0
    assert all(item["candidate_text"] is None for item in body["candidates"])
    assert all(item["status"] == "blocked" for item in body["candidates"])

    validation = client.get(base + "/l3-cli-validation")
    assert validation.status_code == 200, validation.text
    report = validation.json()
    assert report["source"]["command_evidence_registry_id"] == (
        "cis-03-l1-command-evidence-unreviewed-v1"
    )
    assert report["summary"]["passed"] == 0
    assert report["summary"]["blocked"] > 0
    assert all(
        item["independent_verdict"] != "pass"
        for item in report["candidates"]
    )


def test_9300_frozen_registry_and_dhcp_helper_are_unchanged() -> None:
    assert DEFAULT_REGISTRY.fingerprint == FROZEN_9300_FINGERPRINT
    assert len(DEFAULT_REGISTRY.rows) == 6
    reviewed = [
        row for row in DEFAULT_REGISTRY.rows
        if row.review.state is EvidenceReviewState.REVIEWED
    ]
    pending = [
        row for row in DEFAULT_REGISTRY.rows
        if row.review.state is EvidenceReviewState.PENDING
    ]
    assert len(reviewed) == 5
    assert len(pending) == 1
    assert pending[0].evidence_id == "l3-9300-dhcp-helper-address-v1"
    assert L3CommandTopic.DHCP_HELPER_ADDRESS not in {
        row.topic for row in ROWS
    }
    assert L3CommandTopic.DEFAULT_ROUTE not in {row.topic for row in ROWS}
