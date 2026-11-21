"""CIS-03-03A command evidence registry tests."""

from __future__ import annotations

from dataclasses import replace

import pytest
from layer3_helpers import TEST_REVIEWER
from layer3_helpers import test_only_evidence_registry as _test_only_evidence_registry

from event_switch_manager.domain import DeviceFamily
from event_switch_manager.planning.layer3_command_evidence import (
    DEFAULT_REGISTRY,
    ROWS,
    CommandEvidenceRegistry,
    EvidenceReview,
    EvidenceReviewState,
    EvidenceStatus,
    L3CommandTopic,
)
from event_switch_manager.planning.layer3_command_evidence_reviews import (
    REJECTED_RECORDS,
    REVIEWED_RECORDS,
)


def test_production_rows_are_pending_and_render_no_text() -> None:
    assert len(ROWS) == 6
    assert DEFAULT_REGISTRY.renderable_count == 0
    assert {row.review.state for row in ROWS} == {EvidenceReviewState.PENDING}
    assert {row.topic for row in ROWS} == set(L3CommandTopic)


def test_every_row_has_exact_scope_and_sources() -> None:
    expected_pids = {
        "C9300-24T", "C9300-24P",
        "C9300L-24T-4G", "C9300L-24T-4G-E",
        "C9300L-24P-4X", "C9300L-24P-4X-E",
        "C9300X-24Y", "C9300X-24Y-A",
    }
    for row in ROWS:
        assert row.family is DeviceFamily.CATALYST_9300
        assert set(row.pids) == expected_pids
        assert row.releases == ("17.12.4",)
        assert row.source_url.startswith("https://www.cisco.com/")
        assert row.source_section
        assert row.command and row.grammar
        assert row.content_digest()
        assert row.evidence_version == 3
        assert row.classification is not None
        if row.topic is L3CommandTopic.DHCP_HELPER_ADDRESS:
            assert row.licenses == ("Network Advantage",)
        else:
            assert row.licenses == ("Network Essentials", "Network Advantage")


def test_platform_sections_are_the_real_section_names() -> None:
    expected = {
        L3CommandTopic.IP_ROUTING: "Enabling IP Unicast Routing",
        L3CommandTopic.SVI_INTERFACE: "Configuration Guidelines for IP Routing",
        L3CommandTopic.SVI_ADDRESS: "Assigning IP Addresses to Network Interfaces",
        L3CommandTopic.STATIC_ROUTE: "Configuring Static Unicast Routes",
        L3CommandTopic.DEFAULT_ROUTE: "Configuring Static Unicast Routes",
        L3CommandTopic.DHCP_HELPER_ADDRESS: "Specifying the Packet Forwarding Address",
    }
    for row in ROWS:
        assert row.source_section == expected[row.topic]


def test_classification_separates_platform_generic_license_and_renderer_rules() -> None:
    expected_generic = {
        L3CommandTopic.IP_ROUTING: True,
        L3CommandTopic.SVI_INTERFACE: False,
        L3CommandTopic.SVI_ADDRESS: True,
        L3CommandTopic.STATIC_ROUTE: True,
        L3CommandTopic.DEFAULT_ROUTE: True,
        L3CommandTopic.DHCP_HELPER_ADDRESS: False,
    }
    for row in ROWS:
        classification = row.classification
        assert classification is not None
        assert classification.platform_documented is True
        assert classification.generic_command_reference is expected_generic[row.topic]
        assert classification.renderer_safety_restriction
        assert classification.blocking_evidence_gaps
        assert classification.excluded_scope_notes
        assert "pid-license-suffix-mapping" in classification.blocking_evidence_gaps
        if row.topic is L3CommandTopic.DHCP_HELPER_ADDRESS:
            assert classification.license_evidence is EvidenceStatus.UNRESOLVED
            assert classification.license_source_url is None
            assert classification.license_source_section is None
            assert "dhcp-relay-license" in classification.blocking_evidence_gaps
        else:
            assert classification.license_evidence is EvidenceStatus.PARTIAL
            assert classification.license_source_url is not None
            assert classification.license_source_section == "Information About IP Routing"
            assert "per-pid-release-support" in classification.blocking_evidence_gaps


def test_dhcp_license_remains_contract_consistent_but_unresolved() -> None:
    dhcp = next(item for item in ROWS if item.topic is L3CommandTopic.DHCP_HELPER_ADDRESS)
    assert dhcp.licenses == ("Network Advantage",)
    assert dhcp.classification is not None
    assert dhcp.classification.license_evidence is EvidenceStatus.UNRESOLVED
    assert "dhcp-relay-license" in dhcp.classification.blocking_evidence_gaps


def test_scope_blockers_are_independent_of_review_metadata() -> None:
    dhcp = next(item for item in ROWS if item.topic is L3CommandTopic.DHCP_HELPER_ADDRESS)
    blockers = dhcp.scope_blockers()
    assert "evidence-license-unresolved" in blockers
    assert "evidence-scope-gap-dhcp-relay-license" in blockers
    missing = replace(dhcp, classification=None)
    assert missing.scope_blockers() == ("evidence-classification-missing",)


def test_default_route_excludes_ip_default_network() -> None:
    default = next(item for item in ROWS if item.topic is L3CommandTopic.DEFAULT_ROUTE)
    assert default.source_section == "Configuring Static Unicast Routes"
    assert any("ip default-network" in item for item in default.exclusions)
    assert default.classification is not None
    assert "ip-default-network-excluded" in (
        default.classification.renderer_safety_restriction
    )
    assert any(
        source.section == "Configuring Default Route SGT"
        for source in default.supplemental_sources
    )
    assert not any(
        gap == "explicit-default-0.0.0.0-platform-example"
        for gap in default.classification.blocking_evidence_gaps
    )


def test_static_and_default_route_use_protocol_independent_features() -> None:
    for topic in (L3CommandTopic.STATIC_ROUTE, L3CommandTopic.DEFAULT_ROUTE):
        row = next(item for item in ROWS if item.topic is topic)
        assert "protocol_independent_features.html" in row.source_url
        assert "configuring_ip_unicast_routing.html" not in row.source_url
        assert row.command_reference_url is not None
        assert "iri_pi1.html" in row.command_reference_url
        assert row.command_reference_section == "ip route"
        assert row.command_reference_scope
        assert "Protocol-Independent" in row.command_reference_scope
        assert row.semantic_source_url is not None
        assert "admin-distance" in row.semantic_source_url
        assert "255" in " ".join(row.limits)


def test_dhcp_and_address_sources_are_exact() -> None:
    dhcp = next(item for item in ROWS if item.topic is L3CommandTopic.DHCP_HELPER_ADDRESS)
    assert dhcp.source_url.endswith("configuring_dhcp.html")
    assert dhcp.source_section == "Specifying the Packet Forwarding Address"
    address = next(item for item in ROWS if item.topic is L3CommandTopic.SVI_ADDRESS)
    assert "ip_addressing_services_commands.html" in (address.command_reference_url or "")
    assert address.command_reference_section == "ip address"


def test_parameter_boundaries_are_machine_readable() -> None:
    svi = next(item for item in ROWS if item.topic is L3CommandTopic.SVI_INTERFACE)
    vlan = svi.parameters[0]
    assert (vlan.minimum, vlan.maximum) == (1, 4094)
    assert vlan.reserved_values == (1, 1002, 1003, 1004, 1005)
    for topic in (L3CommandTopic.STATIC_ROUTE, L3CommandTopic.DEFAULT_ROUTE):
        row = next(item for item in ROWS if item.topic is topic)
        distance = next(item for item in row.parameters if item.kind == "distance")
        assert (distance.minimum, distance.maximum) == (1, 255)
    address = next(item for item in ROWS if item.topic is L3CommandTopic.SVI_ADDRESS)
    mask = next(item for item in address.parameters if item.kind == "ipv4-mask")
    assert (mask.minimum, mask.maximum) == (1, 30)


def test_digest_changes_when_content_changes() -> None:
    row = ROWS[0]
    original = row.content_digest()
    changed = replace(row, command=f"{row.command} ")
    assert changed.content_digest() != original
    assert row.renderable is False


def test_reviewed_registry_is_explicitly_test_only_and_renderable() -> None:
    registry = _test_only_evidence_registry()
    assert registry.renderable_count == 6
    assert registry.fingerprint != DEFAULT_REGISTRY.fingerprint
    assert all(
        row.review.reviewer == TEST_REVIEWER
        for row in registry.rows
    )


def test_rejected_or_digest_mismatched_review_is_not_renderable() -> None:
    row = ROWS[0]
    rejected = replace(
        row,
        evidence_id="test-only-rejected-row",
        review=EvidenceReview(
            state=EvidenceReviewState.REJECTED,
            reviewer="TEST-ONLY-REJECTION",
            reviewed_at="2026-11-21",
            findings=("test-only rejection",),
            content_digest=row.content_digest(),
        ),
    )
    assert rejected.renderable is False
    mismatched = replace(
        row,
        evidence_id="test-only-digest-mismatch-row",
        review=EvidenceReview(
            state=EvidenceReviewState.REVIEWED,
            reviewer="TEST-ONLY",
            reviewed_at="2026-11-21",
            findings=("test-only",),
            content_digest="0" * 64,
        ),
    )
    assert mismatched.renderable is False
    registry = CommandEvidenceRegistry((rejected, mismatched), production=False)
    assert registry.renderable_count == 0


def test_review_metadata_must_be_complete_and_valid() -> None:
    row = ROWS[0]
    valid = EvidenceReview(
        state=EvidenceReviewState.REVIEWED,
        reviewer="independent-reviewer",
        reviewed_at="2026-11-21",
        findings=("verified command syntax and platform applicability",),
        content_digest=row.content_digest(),
    )
    assert replace(row, review=valid).renderable is True

    for invalid in (
        EvidenceReview(
            state=EvidenceReviewState.REVIEWED,
            reviewer="",
            reviewed_at="2026-11-21",
            findings=("finding",),
            content_digest=row.content_digest(),
        ),
        EvidenceReview(
            state=EvidenceReviewState.REVIEWED,
            reviewer="independent-reviewer",
            reviewed_at="2026-11-21",
            findings=(),
            content_digest=row.content_digest(),
        ),
        EvidenceReview(
            state=EvidenceReviewState.REVIEWED,
            reviewer="independent-reviewer",
            reviewed_at="not-a-date",
            findings=("finding",),
            content_digest=row.content_digest(),
        ),
        EvidenceReview(
            state=EvidenceReviewState.REVIEWED,
            reviewer="independent-reviewer",
            reviewed_at="2026-11-21",
            findings=("finding",),
            content_digest="not-a-sha256",
        ),
        EvidenceReview(
            state=EvidenceReviewState.REVIEWED,
            reviewer="independent-reviewer",
            reviewed_at="2026-11-21",
            findings=("finding",),
            content_digest="0" * 64,
        ),
    ):
        assert replace(row, review=invalid).renderable is False


def test_production_registry_rejects_test_only_reviewer() -> None:
    row = ROWS[0]
    reviewed = replace(row, review=EvidenceReview(
        state=EvidenceReviewState.REVIEWED,
        reviewer="TEST-ONLY-NOT-A-PRODUCTION-EVIDENCE-REVIEW",
        reviewed_at="2026-11-21",
        findings=("test-only",),
        content_digest=row.content_digest(),
    ))
    with pytest.raises(ValueError, match="test-only reviewer"):
        CommandEvidenceRegistry((reviewed,), production=True)


def test_registry_fingerprint_reflects_review_identity_and_findings() -> None:
    row = ROWS[0]
    first = replace(row, review=EvidenceReview(
        state=EvidenceReviewState.REVIEWED,
        reviewer="reviewer-a",
        reviewed_at="2026-11-21",
        findings=("finding-a",),
        content_digest=row.content_digest(),
    ))
    second = replace(row, review=EvidenceReview(
        state=EvidenceReviewState.REVIEWED,
        reviewer="reviewer-b",
        reviewed_at="2026-11-21",
        findings=("finding-b",),
        content_digest=row.content_digest(),
    ))
    registry_a = CommandEvidenceRegistry((first,), production=False)
    registry_b = CommandEvidenceRegistry((second,), production=False)
    assert registry_a.fingerprint != registry_b.fingerprint


def test_registry_fingerprint_is_content_sensitive_and_deterministic() -> None:
    assert DEFAULT_REGISTRY.fingerprint == CommandEvidenceRegistry(ROWS).fingerprint
    row = ROWS[0]
    changed = replace(row, limits=(*row.limits, "R30 classification fingerprint probe"))
    registry = CommandEvidenceRegistry((changed, *ROWS[1:]))
    assert registry.fingerprint != DEFAULT_REGISTRY.fingerprint


def test_test_registry_has_separate_identity_and_is_not_production() -> None:
    registry = _test_only_evidence_registry()
    assert DEFAULT_REGISTRY.production is True
    assert registry.production is False
    assert registry.registry_id == "cis-03-test-only-command-evidence-v1"
    assert registry.registry_id != DEFAULT_REGISTRY.registry_id


def test_verified_pid_subset_is_explicit_and_bare_models_do_not_match() -> None:
    expected = {
        "C9300L-24T-4G-E", "C9300L-24P-4X-E", "C9300X-24Y-A",
    }
    for row in ROWS:
        assert row.classification is not None
        assert set(row.classification.verified_pids) == expected
        assert "C9300-24T" not in row.classification.verified_pids
        assert "C9300L-24T-4G" not in row.classification.verified_pids
    row = ROWS[0]
    assert DEFAULT_REGISTRY.matching(
        row.topic, "C9300L-24T-4G-E", "17.12.4", "Network Essentials",
    )
    assert not DEFAULT_REGISTRY.matching(
        row.topic, "C9300-24T", "17.12.4", "Network Essentials",
    )


def test_registry_matching_scope_including_license_and_release() -> None:
    row = ROWS[0]
    pid = "C9300L-24T-4G-E"
    assert DEFAULT_REGISTRY.matching(
        row.topic, pid, "17.12.4", "Network Essentials",
    )
    assert not DEFAULT_REGISTRY.matching(row.topic, pid, "17.12.5", "Network Essentials")
    assert not DEFAULT_REGISTRY.matching(
        row.topic, "C9200L-24P-4X", "17.12.4", "Network Essentials",
    )
    dhcp = next(item for item in ROWS if item.topic is L3CommandTopic.DHCP_HELPER_ADDRESS)
    assert not DEFAULT_REGISTRY.matching(
        dhcp.topic, pid, "17.12.4", "Network Essentials",
    )
    assert DEFAULT_REGISTRY.matching(
        dhcp.topic, pid, "17.12.4", "Network Advantage",
    )


def test_no_production_review_attestation_exists() -> None:
    assert REVIEWED_RECORDS == {}
    assert REJECTED_RECORDS == {}
