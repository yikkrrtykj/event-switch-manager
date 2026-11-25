from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

from event_switch_manager.console.allowlist import resolve_profile
from event_switch_manager.console.lease import ConsoleLeaseManager
from event_switch_manager.console.models import (
    ConsoleEvidenceRejected,
    ConsoleObservation,
    ConsoleQueryResult,
    ConsoleSource,
    ObservationCompleteness,
    QueryStatus,
    build_evidence,
    verify_evidence,
)
from event_switch_manager.console.observation import (
    CiscoObservationAdapter,
    IdentityConflict,
    _chassis_inventory,
    _license_info,
    _stack,
    redact_console_output,
)
from event_switch_manager.console.session import ConsoleCredentials, ConsoleSession
from event_switch_manager.console.simulator import (
    SimulatedConsoleTransport,
    SimulatorProfile,
    profiles,
)
from event_switch_manager.integrations import ConsoleQuery

CREDS = ConsoleCredentials("console", "synthetic-password", "synthetic-enable")


def _session(
    profile: SimulatorProfile | None = None,
    *,
    pagination: bool = True,
    chunk_size: int = 1024,
) -> ConsoleSession:
    transport = SimulatedConsoleTransport(
        profile=profile or profiles()[3],
        pagination=pagination,
        chunk_size=chunk_size,
    )
    return ConsoleSession(transport, timeout=1.0)


def test_five_family_full_simulator_pipeline() -> None:
    adapter = CiscoObservationAdapter()
    expected_stack = {
        "catalyst-2960x": 2,
        "catalyst-3850": 2,
        "catalyst-9200": 1,
        "catalyst-9300": 2,
        "catalyst-c1000": 0,
    }
    for profile in profiles():
        session = _session(profile)
        session.open(CREDS)
        try:
            evidence = adapter.observe(session)
        finally:
            session.close()
        observation = evidence.observation
        assert evidence.source is ConsoleSource.SIMULATOR
        assert evidence.content_fingerprint
        assert len(evidence.content_fingerprint) == 64
        assert observation.family is not None
        assert observation.family.value == profile.family.value
        assert observation.exact_pid == profile.model
        assert observation.serial_number == profile.serial_number
        assert observation.software_version == profile.software_version
        assert len(observation.interfaces) == 3
        assert len(observation.stack) == expected_stack[profile.family.value]
        assert observation.license.active_verified is False
        assert observation.hardware_verified is False
        assert observation.deployment_approved is False
        assert evidence.hardware_verified is False
        assert evidence.deployment_approved is False
        if profile.family.value in {"catalyst-9200", "catalyst-9300"}:
            assert observation.license.declared == "Network Advantage"
            assert observation.license.observed == "Network Advantage"
            assert observation.license.status is not None
            assert observation.license.next_boot == "Network Advantage"
            assert observation.boot_state is not None
            assert observation.storage
            assert observation.stack
            assert observation.stack[0].exact_pid == profile.model
            assert observation.stack[0].serial_number is not None
        converted = observation.to_switch_observation()
        assert converted.family is observation.family
        assert converted.model == profile.model
        assert converted.serial_number == profile.serial_number
        assert len(converted.interfaces) == 3
        if profile.family.value in {
            "catalyst-2960x", "catalyst-3850", "catalyst-c1000",
        }:
            assert observation.completeness is ObservationCompleteness.PARTIAL
        else:
            assert observation.completeness is ObservationCompleteness.COMPLETE


def test_recorded_fixture_source_is_supported_but_never_hardware_verified() -> None:
    recorded = replace(
        profiles()[3],
        source=ConsoleSource.RECORDED_FIXTURE,
        fixture_id="recorded-sanitized-9300",
    )
    session = _session(recorded)
    session.open(CREDS)
    try:
        evidence = CiscoObservationAdapter().observe(session)
    finally:
        session.close()
    assert evidence.source is ConsoleSource.RECORDED_FIXTURE
    assert evidence.fixture_id == "recorded-sanitized-9300"
    assert evidence.hardware_verified is False
    assert evidence.deployment_approved is False


def test_live_device_evidence_is_rejected_by_contract() -> None:
    observation = ConsoleObservation(
        source=ConsoleSource.LIVE_DEVICE,
        session_identity="fake-session",
        exact_pid="C9300L-24P-4X",
        serial_number="FIXTURE",
        software_version="17.12.4",
        completeness=ObservationCompleteness.COMPLETE,
    )
    with pytest.raises(ConsoleEvidenceRejected, match="live-device"):
        build_evidence(observation, ())


class _FakeSession:
    source = ConsoleSource.SIMULATOR
    session_identity = "fake-observation"
    port_identity = "fake-port"
    fixture_id = None

    def __init__(self) -> None:
        self.family: object | None = None

    def start_discovery(self, **_: object) -> None:
        return

    def end_discovery(self) -> None:
        return

    def query_result(self, query: ConsoleQuery) -> ConsoleQueryResult:
        if query is ConsoleQuery.VERSION:
            return ConsoleQueryResult(
                query=query, command="show version", status=QueryStatus.OK,
                output=(
                    "Cisco IOS XE Software, Version 17.12.4\n"
                    "cisco C9300L-24P-4X (X86) processor\n"
                    "Processor board ID FAKE9300\n"
                ),
            )
        return ConsoleQueryResult(
            query=query, command="show inventory", status=QueryStatus.OK,
            output=(
                'NAME: "Chassis", DESCR: "Cisco C9200L-24P-4X"\n'
                "PID: C9200L-24P-4X, VID: V02, SN: FAKE9200\n"
            ),
        )

    def set_family(self, family: object) -> None:
        self.family = family

    def set_profile(self, profile: object) -> None:
        self.family = getattr(profile, "family", None)


def test_conflicting_version_and_inventory_identity_is_rejected() -> None:
    fake = _FakeSession()
    with pytest.raises(IdentityConflict):
        CiscoObservationAdapter().observe(cast(Any, fake))


def test_redaction_and_fingerprint_are_deterministic() -> None:
    assert "synthetic-password" not in redact_console_output(
        "username admin\npassword synthetic-password\nshow version",
    )
    assert "[REDACTED]" in redact_console_output("enable password: synthetic-enable")
    assert redact_console_output(
        "bare-value-42 appears here", ("bare-value-42",),
    ) == "[REDACTED] appears here"
    assert "synthetic-password" not in redact_console_output(
        "show version\nsynthetic-password\n",
        ("synthetic-password",),
    )
    profile = profiles()[3]
    first = _session(profile)
    first.open(CREDS)
    try:
        evidence = CiscoObservationAdapter().observe(first)
    finally:
        first.close()
    second = _session(profile)
    second.open(CREDS)
    try:
        evidence2 = CiscoObservationAdapter().observe(second)
    finally:
        second.close()
    assert evidence.content_fingerprint == evidence2.content_fingerprint
    assert evidence.observation.observation_id != evidence2.observation.observation_id


def test_c1000_is_not_interpreted_as_a_native_stack() -> None:
    session = _session(profiles()[4])
    session.open(ConsoleCredentials("console", "synthetic-password", None))
    try:
        observation = CiscoObservationAdapter().observe(session).observation
    finally:
        session.close()
    assert observation.family is not None
    assert observation.family.value == "catalyst-c1000"
    assert observation.stack == ()
    assert "stack" not in observation.unknown_fields


def test_inventory_chassis_is_separated_from_other_components() -> None:
    pid, serial, issues = _chassis_inventory(
        'NAME: "Power Supply 1", DESCR: "PSU"\n'
        "PID: PWR-1, VID: V01, SN: PSU001\n"
        'NAME: "Chassis", DESCR: "Switch"\n'
        "PID: C9300L-24P-4X, VID: V02, SN: CHASSIS001\n",
    )
    assert (pid, serial, issues) == ("C9300L-24P-4X", "CHASSIS001", ())


def test_multiple_license_features_preserve_declared_observed_and_next_boot() -> None:
    info = _license_info(
        "License Level: Network Advantage\n",
        "Index 1 Feature: network-advantage\n"
        "License Type: Permanent\n"
        "License State: Active, In Use\n"
        "Next reboot license level: network-advantage\n"
        "Index 2 Feature: dna-essentials\n"
        "License Type: Subscription\n"
        "License State: Active, In Use\n"
        "Next reboot license level: dna-essentials\n",
    )
    assert info.declared == "Network Advantage"
    assert len(info.features) == 2
    assert info.next_boot == "network-advantage"
    assert info.observed == "Network Advantage, Dna Essentials"
    assert info.ambiguous is False
    assert info.active_verified is False


def test_stack_duplicate_number_and_serial_are_rejected() -> None:
    duplicate_number = (
        "Switch  Role     Model      Serial   Version  State\n"
        "1       Active   C9300-24T  SER1     17.12.4  Ready\n"
        "1       Standby  C9300-24T  SER2     17.12.4  Ready\n"
    )
    with pytest.raises(IdentityConflict):
        _stack(duplicate_number)
    duplicate_serial = (
        "Switch  Role     Model      Serial   Version  State\n"
        "1       Active   C9300-24T  SER1     17.12.4  Ready\n"
        "2       Standby  C9300-24T  SER1     17.12.4  Ready\n"
    )
    with pytest.raises(IdentityConflict):
        _stack(duplicate_serial)
    malformed = (
        "Switch  Role     Model      Serial   Version  State\n"
        "1       Active   C9300-24T\n"
    )
    with pytest.raises(IdentityConflict):
        _stack(malformed)


def test_query_timeout_becomes_partial_evidence_without_further_commands() -> None:
    profile = profiles()[3]
    transport = SimulatedConsoleTransport(
        profile=profile,
        timeout_commands=frozenset({ConsoleQuery.LICENSE}),
    )
    session = ConsoleSession(
        transport, lease_manager=ConsoleLeaseManager(), timeout=0.2,
    )
    session.open(CREDS)
    evidence = CiscoObservationAdapter().observe(session)
    session.close()
    assert evidence.completeness is ObservationCompleteness.PARTIAL
    assert any(
        item.query is ConsoleQuery.LICENSE and item.status is QueryStatus.TIMEOUT
        for item in evidence.query_results
    )
    assert not any(
        item.query in {ConsoleQuery.BOOT, ConsoleQuery.STORAGE}
        for item in evidence.query_results
    )
    assert "license" in evidence.observation.unknown_fields


def test_disabled_pagination_removes_simulator_marker() -> None:
    profile = replace(
        profiles()[3],
        interfaces=tuple(f"Gi1/0/{index}" for index in range(1, 10)),
    )
    session = _session(profile, pagination=False, chunk_size=1)
    session.open(CREDS)
    session.set_profile(resolve_profile("C9300L-24P-4X", "17.12.4"))
    try:
        interfaces = session.query(ConsoleQuery.INTERFACES)
        assert "Gi1/0/9" in interfaces
        assert "--More--" not in interfaces
        assert "FIXTURE930001" in session.query(ConsoleQuery.VERSION)
    finally:
        session.close()


def test_pagination_does_not_truncate_a_complete_observation() -> None:
    profile = replace(
        profiles()[3],
        interfaces=tuple(f"Gi1/0/{index}" for index in range(1, 10)),
    )
    session = _session(profile)
    session.open(CREDS)
    try:
        evidence = CiscoObservationAdapter().observe(session)
    finally:
        session.close()
    assert len(evidence.observation.interfaces) == 9
    assert evidence.observation.completeness is ObservationCompleteness.COMPLETE
    assert any(item.query is ConsoleQuery.LICENSE for item in evidence.query_results)
    assert evidence.observation.license.features


def test_unsupported_queries_are_explicit_in_evidence() -> None:
    profile = replace(profiles()[3], software_version="17.12.5")
    session = _session(profile)
    session.open(CREDS)
    try:
        evidence = CiscoObservationAdapter().observe(session)
    finally:
        session.close()
    assert ConsoleQuery.LICENSE in evidence.unsupported_queries
    assert evidence.completeness is ObservationCompleteness.PARTIAL


def test_evidence_fingerprint_is_verifiable_and_tamper_is_rejected() -> None:
    session = _session()
    session.open(CREDS)
    try:
        evidence = CiscoObservationAdapter().observe(session)
    finally:
        session.close()
    assert verify_evidence(evidence) is True
    tampered = evidence.model_copy(update={
        "observation": evidence.observation.model_copy(update={
            "serial_number": "TAMPERED",
        }),
    })
    assert verify_evidence(tampered) is False
    mismatched_source = evidence.model_copy(update={"source": ConsoleSource.RECORDED_FIXTURE})
    assert verify_evidence(mismatched_source) is False
    with pytest.raises(ConsoleEvidenceRejected):
        build_evidence(
            evidence.observation,
            (ConsoleQueryResult(
                query=ConsoleQuery.VERSION,
                command="configure terminal",
                status=QueryStatus.OK,
            ),),
        )


def test_discovery_cancellation_and_deadline_are_propagated() -> None:
    from threading import Event

    from event_switch_manager.console.session import (
        DiscoveryCancelled,
        DiscoveryTimeout,
    )

    session = _session()
    session.open(CREDS)
    cancelled = Event()
    cancelled.set()
    try:
        with pytest.raises(DiscoveryCancelled):
            CiscoObservationAdapter().observe(session, cancel_event=cancelled)
    finally:
        session.close()
    second = _session()
    second.open(CREDS)
    try:
        second.start_discovery(deadline_seconds=0.001)
        import time
        time.sleep(0.05)
        with pytest.raises(DiscoveryTimeout):
            second.query(ConsoleQuery.VERSION)
    finally:
        second.close()


def test_unknown_exact_pid_stops_after_bootstrap_queries() -> None:
    unknown = replace(profiles()[3], model="C9300-99T")
    session = _session(unknown)
    session.open(CREDS)
    try:
        evidence = CiscoObservationAdapter().observe(session)
    finally:
        session.close()
    assert evidence.observation.exact_pid == "C9300-99T"
    assert evidence.observation.completeness is ObservationCompleteness.PARTIAL
    assert "exact-profile" in evidence.observation.unknown_fields
    assert {item.query for item in evidence.query_results} == {
        ConsoleQuery.VERSION, ConsoleQuery.INVENTORY,
    }


def test_evidence_contains_query_results_but_no_live_source() -> None:
    session = _session(profiles()[2])
    session.open(CREDS)
    try:
        evidence = CiscoObservationAdapter().observe(session)
    finally:
        session.close()
    assert evidence.query_results
    assert {item.query for item in evidence.query_results} >= {
        ConsoleQuery.VERSION, ConsoleQuery.INVENTORY, ConsoleQuery.LICENSE,
    }
    assert all(item.command.startswith("show ") for item in evidence.query_results)
    assert evidence.source is not ConsoleSource.LIVE_DEVICE
