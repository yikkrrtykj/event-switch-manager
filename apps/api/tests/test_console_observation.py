from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

from event_switch_manager.console.models import (
    ConsoleEvidenceRejected,
    ConsoleObservation,
    ConsoleQueryResult,
    ConsoleSource,
    ObservationCompleteness,
    QueryStatus,
    build_evidence,
)
from event_switch_manager.console.observation import (
    CiscoObservationAdapter,
    IdentityConflict,
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


def _session(profile: SimulatorProfile | None = None) -> ConsoleSession:
    transport = SimulatedConsoleTransport(profile=profile or profiles()[3])
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
        if profile.family.value in {"catalyst-2960x", "catalyst-c1000"}:
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
            output='PID: C9200L-24P-4X, VID: V02, SN: FAKE9200\n',
        )

    def set_family(self, family: object) -> None:
        self.family = family


def test_conflicting_version_and_inventory_identity_is_rejected() -> None:
    fake = _FakeSession()
    with pytest.raises(IdentityConflict):
        CiscoObservationAdapter().observe(cast(Any, fake))


def test_redaction_and_fingerprint_are_deterministic() -> None:
    assert "synthetic-password" not in redact_console_output(
        "username admin\npassword synthetic-password\nshow version",
    )
    assert "[REDACTED]" in redact_console_output("enable password: synthetic-enable")
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
