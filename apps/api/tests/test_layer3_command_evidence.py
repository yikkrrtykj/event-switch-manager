"""CIS-03-03A command evidence registry tests."""

from __future__ import annotations

from dataclasses import replace

from layer3_helpers import TEST_REVIEWER
from layer3_helpers import test_only_evidence_registry as _test_only_evidence_registry

from event_switch_manager.domain import DeviceFamily
from event_switch_manager.planning.layer3_command_evidence import (
    DEFAULT_REGISTRY,
    ROWS,
    CommandEvidenceRegistry,
    EvidenceReview,
    EvidenceReviewState,
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
    for row in ROWS:
        assert row.family is DeviceFamily.CATALYST_9300
        assert len(row.pids) == 8
        assert row.releases == ("17.12.4",)
        assert row.source_url.startswith("https://www.cisco.com/")
        assert row.source_section
        assert row.command and row.grammar
        assert row.content_digest()
        assert row.evidence_version == 1
        if row.topic is L3CommandTopic.DHCP_HELPER_ADDRESS:
            assert row.licenses == ("Network Advantage",)
        else:
            assert row.licenses == ("Network Essentials", "Network Advantage")


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
    assert dhcp.source_section == "Configuring the DHCP Relay Agent"
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
    registry = CommandEvidenceRegistry((rejected, mismatched))
    assert registry.renderable_count == 0


def test_registry_matching_scope_including_license_and_release() -> None:
    row = ROWS[0]
    pid = row.pids[0]
    assert DEFAULT_REGISTRY.matching(
        row.topic, pid, "17.12.4", "Network Essentials",
    )
    assert not DEFAULT_REGISTRY.matching(row.topic, pid, "17.12.5", "Network Essentials")
    assert not DEFAULT_REGISTRY.matching(
        row.topic, "C9200L-24P-4X", "17.12.4", "Network Essentials",
    )
    dhcp = next(item for item in ROWS if item.topic is L3CommandTopic.DHCP_HELPER_ADDRESS)
    assert not DEFAULT_REGISTRY.matching(
        dhcp.topic, dhcp.pids[0], "17.12.4", "Network Essentials",
    )
    assert DEFAULT_REGISTRY.matching(
        dhcp.topic, dhcp.pids[0], "17.12.4", "Network Advantage",
    )


def test_no_production_review_attestation_exists() -> None:
    assert REVIEWED_RECORDS == {}
    assert REJECTED_RECORDS == {}
