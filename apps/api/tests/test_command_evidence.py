"""CIS-02B2 L1 command-evidence registry integrity regressions."""

from __future__ import annotations

import dataclasses

import pytest

from event_switch_manager.cisco_catalog import GUIDE_SCOPES, PROFILES, RELEASES
from event_switch_manager.domain import DeviceFamily
from event_switch_manager.planning.command_evidence import (
    DEFAULT_REGISTRY,
    EVIDENCE_REGISTRY_ID,
    PENDING_REVIEW,
    REJECTED_REVIEW,
    ROWS,
    SCOPES,
    CommandEvidence,
    CommandEvidenceRegistry,
    CommandTopic,
    EvidenceReview,
    EvidenceReviewState,
    evidence_reference,
)

AGGREGATION_TOPICS = {
    CommandTopic.PORT_CHANNEL_INTERFACE,
    CommandTopic.CHANNEL_GROUP_STATIC,
    CommandTopic.CHANNEL_GROUP_LACP,
}
INTERFACE_TOPICS = {
    CommandTopic.SPEED,
    CommandTopic.DUPLEX,
    CommandTopic.DESCRIPTION,
    CommandTopic.ADMIN_SHUTDOWN,
    CommandTopic.POE_MODE,
}
L2_TOPICS = {
    CommandTopic.VLAN,
    CommandTopic.VLAN_NAME,
    CommandTopic.ACCESS_MODE,
    CommandTopic.ACCESS_VLAN,
    CommandTopic.TRUNK_MODE,
    CommandTopic.NATIVE_VLAN,
    CommandTopic.ALLOWED_VLANS,
    CommandTopic.RAPID_PVST,
    CommandTopic.VTP_TRANSPARENT,
    CommandTopic.ROOT_PRIORITY,
    CommandTopic.PORTFAST,
    CommandTopic.BPDU_GUARD,
}


def test_registry_identifier_and_fingerprint_are_stable() -> None:
    assert EVIDENCE_REGISTRY_ID == "cis-02b2-l1-command-evidence-v1"
    first = evidence_reference(DEFAULT_REGISTRY)
    second = evidence_reference(CommandEvidenceRegistry(ROWS))
    assert first == second
    assert first["rows"] == len(ROWS)
    assert first["reviewed_rows"] == sum(1 for row in ROWS if row.renderable)


def test_evidence_ids_are_unique_and_versioned() -> None:
    ids = [row.evidence_id for row in ROWS]
    assert len(ids) == len(set(ids))
    assert all(value.endswith("-v1") for value in ids)
    assert all(value.startswith("l1-") for value in ids)


def test_every_row_binds_an_exact_catalog_pid_release_and_license() -> None:
    for row in ROWS:
        assert row.pids, row.evidence_id
        profiles = [PROFILES[pid] for pid in row.pids]
        assert all(profile.family is row.family for profile in profiles), row.evidence_id
        catalog_releases = set(RELEASES[row.family].releases) | set(
            GUIDE_SCOPES[row.family].interfaces
        )
        assert set(row.releases) <= catalog_releases, row.evidence_id
        for profile in profiles:
            assert set(row.licenses) <= set(profile.licenses), row.evidence_id
        assert row.grammar and row.command and row.command_mode, row.evidence_id


def test_no_row_claims_an_unreviewed_release_or_license() -> None:
    excluded = {
        DeviceFamily.CATALYST_9200: {"17.12.5"},
        DeviceFamily.CATALYST_9300: {"17.12.5"},
        DeviceFamily.CATALYST_2960X: {"15.2(7)E1a"},
        DeviceFamily.CATALYST_C1000: {"15.2(7)E"},
    }
    for row in ROWS:
        assert not set(row.releases) & excluded.get(row.family, set()), row.evidence_id
    for row in ROWS:
        if row.family is DeviceFamily.CATALYST_C1000:
            assert row.licenses == ()


def test_2960x_license_scopes_are_not_extrapolated() -> None:
    lan_base = DEFAULT_REGISTRY.applicable(
        DeviceFamily.CATALYST_2960X, "WS-C2960X-24TS-L", "15.2(7)E", "LAN Base",
        CommandTopic.CHANNEL_GROUP_LACP,
    )
    lan_lite = DEFAULT_REGISTRY.applicable(
        DeviceFamily.CATALYST_2960X, "WS-C2960X-24TS-LL", "15.2(7)E", "LAN Lite",
        CommandTopic.CHANNEL_GROUP_LACP,
    )
    assert len(lan_base) == 1 and len(lan_lite) == 1
    assert lan_base[0].pids != lan_lite[0].pids
    parameter = next(
        rule for rule in lan_base[0].parameters if rule.name == "port-channel-number"
    )
    lite_parameter = next(
        rule for rule in lan_lite[0].parameters if rule.name == "port-channel-number"
    )
    assert parameter.maximum == 24
    assert lite_parameter.maximum == 6
    assert DEFAULT_REGISTRY.applicable(
        DeviceFamily.CATALYST_2960X, "WS-C2960X-24TS-LL", "15.2(7)E", "LAN Base",
        CommandTopic.CHANNEL_GROUP_LACP,
    ) == ()
    assert DEFAULT_REGISTRY.applicable(
        DeviceFamily.CATALYST_2960X, "WS-C2960X-24TS-L", "15.2(7)E", "LAN Lite",
        CommandTopic.CHANNEL_GROUP_LACP,
    ) == ()


def test_release_scope_excludes_identity_only_and_limited_releases() -> None:
    assert DEFAULT_REGISTRY.applicable(
        DeviceFamily.CATALYST_3850, "WS-C3850-24T", "16.12.10a", "IP Base",
        CommandTopic.CHANNEL_GROUP_LACP,
    )
    assert DEFAULT_REGISTRY.applicable(
        DeviceFamily.CATALYST_3850, "WS-C3850-24T", "16.12.10a", "IP Base",
        CommandTopic.SPEED,
    ) == ()
    for pid, family in (
        ("C9200-24T", DeviceFamily.CATALYST_9200),
        ("C9300-24T", DeviceFamily.CATALYST_9300),
    ):
        assert DEFAULT_REGISTRY.applicable(
            family, pid, "17.12.5", "Network Advantage", CommandTopic.SPEED,
        ) == ()
    assert DEFAULT_REGISTRY.applicable(
        DeviceFamily.CATALYST_2960X, "WS-C2960X-24TS-L", "15.2(7)E1a", "LAN Base",
        CommandTopic.SPEED,
    ) == ()


def test_unreviewed_release_of_a_family_never_inherits_rows() -> None:
    for family, pid, release, _license_name in (
        (DeviceFamily.CATALYST_9200, "C9200-24T", "17.12.5", "Network Advantage"),
        (DeviceFamily.CATALYST_9300, "C9300-24T", "17.12.5", "Network Essentials"),
        (DeviceFamily.CATALYST_2960X, "WS-C2960X-24TS-L", "15.2(7)E1a", "LAN Base"),
        (DeviceFamily.CATALYST_C1000, "C1000-24T-4G-L", "15.2(7)E", None),
    ):
        assert not any(
            row.pids and pid in row.pids and release in row.releases
            for row in ROWS if row.family is family
        )


def test_2960x_3850_c1000_have_no_layer2_command_rows() -> None:
    for row in ROWS:
        if row.family in {
            DeviceFamily.CATALYST_2960X,
            DeviceFamily.CATALYST_3850,
            DeviceFamily.CATALYST_C1000,
        }:
            assert row.topic not in L2_TOPICS, row.evidence_id


def test_9200_and_9300_cover_every_command_topic() -> None:
    for family in (DeviceFamily.CATALYST_9200, DeviceFamily.CATALYST_9300):
        topics = {row.topic for row in ROWS if row.family is family}
        assert topics == AGGREGATION_TOPICS | INTERFACE_TOPICS | INTERFACE_TOPICS | L2_TOPICS


def test_aggregation_families_cover_the_reviewed_interface_topics() -> None:
    for family in (
        DeviceFamily.CATALYST_2960X,
        DeviceFamily.CATALYST_3850,
        DeviceFamily.CATALYST_C1000,
    ):
        topics = {row.topic for row in ROWS if row.family is family}
        assert topics == AGGREGATION_TOPICS | INTERFACE_TOPICS


@pytest.mark.parametrize("evidence", ROWS, ids=lambda row: row.evidence_id)
def test_every_row_cites_a_cisco_page_and_section(evidence: CommandEvidence) -> None:
    assert evidence.source_url.startswith("https://www.cisco.com/")
    assert evidence.source_section.strip()
    assert evidence.exclusions
    assert evidence.limits
    assert evidence.parameters or evidence.topic in {
        CommandTopic.ACCESS_MODE,
        CommandTopic.TRUNK_MODE,
        CommandTopic.RAPID_PVST,
        CommandTopic.VTP_TRANSPARENT,
    }


def test_review_attestations_are_complete_and_honest() -> None:
    reviewed = [row for row in ROWS if row.review.state is EvidenceReviewState.REVIEWED]
    assert reviewed, "At least one row must carry an independent review"
    for row in reviewed:
        assert row.review.reviewer
        assert row.review.reviewed_at
        assert row.review.findings
    for row in ROWS:
        if row.review.state is EvidenceReviewState.REJECTED:
            assert not row.renderable
    with pytest.raises(ValueError):
        EvidenceReview(EvidenceReviewState.REVIEWED)


def test_pending_and_rejected_rows_can_never_render() -> None:
    pending = CommandEvidenceRegistry(
        tuple(dataclasses.replace(row, review=PENDING_REVIEW) for row in ROWS)
    )
    for row in pending.rows:
        assert pending.renderable(
            row.family, row.pids[0], row.releases[0], row.licenses[0] if row.licenses else None,
            row.topic,
        ) is None
    assert pending.blocker(
        DeviceFamily.CATALYST_9200, "C9200-24T", "17.12.4", "Network Essentials",
        CommandTopic.VLAN,
    ) == "syntax-evidence-not-reviewed:vlan"

    rejected = CommandEvidenceRegistry(
        tuple(dataclasses.replace(row, review=REJECTED_REVIEW) for row in ROWS)
    )
    assert rejected.blocker(
        DeviceFamily.CATALYST_9200, "C9200-24T", "17.12.4", "Network Essentials",
        CommandTopic.VLAN,
    ) == "syntax-evidence-rejected:vlan"
    assert rejected.renderable(
        DeviceFamily.CATALYST_9200, "C9200-24T", "17.12.4", "Network Essentials",
        CommandTopic.VLAN,
    ) is None


def test_registry_fingerprint_changes_when_a_review_state_changes() -> None:
    base = CommandEvidenceRegistry(ROWS)
    changed = CommandEvidenceRegistry(tuple(
        dataclasses.replace(row, review=PENDING_REVIEW) for row in ROWS
    ))
    assert evidence_reference(base)["row_versions"] != evidence_reference(changed)[
        "row_versions"
    ]


def test_platform_scopes_name_a_family_that_owns_their_pids() -> None:
    assert len({scope.id_key for scope in SCOPES}) == len(SCOPES)
    for scope in SCOPES:
        for pid in scope.pids:
            assert PROFILES[pid].family is scope.family, (scope.id_key, pid)


def test_command_topics_are_closed_and_each_one_is_documented() -> None:
    assert {topic.value for topic in CommandTopic} == {
        "vlan", "vlan-name", "access-mode", "access-vlan", "trunk-mode",
        "native-vlan", "allowed-vlans", "port-channel-interface",
        "channel-group-static", "channel-group-lacp", "rapid-pvst",
        "vtp-transparent", "root-priority", "portfast", "bpdu-guard", "poe-mode",
        "speed", "duplex", "description", "admin-shutdown",
    }
