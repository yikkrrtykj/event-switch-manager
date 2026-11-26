from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from event_switch_manager.console.discovery import (
    IdentityQuality,
    SerialDiscovery,
    SerialPlatformStatus,
    SerialPortInfo,
)
from event_switch_manager.console.models import (
    ConsoleEvidenceRejected,
    ConsoleObservation,
    ConsoleQueryResult,
    ConsoleSource,
    LabProvenance,
    ObservationCompleteness,
    QueryStatus,
    build_evidence,
)
from event_switch_manager.console.observation import CiscoObservationAdapter
from event_switch_manager.console.session import (
    ConsoleOperatorAbort,
    ConsoleSession,
    LiveDeviceDisabled,
)
from event_switch_manager.console.transport import (
    SerialTransport,
    TransportError,
)
from event_switch_manager.integrations import ConsoleQuery
from event_switch_manager.lab_runner.authorization import (
    LabAuthorization,
    LabAuthorizationError,
    issue_authorization,
)
from event_switch_manager.lab_runner.cli import run_list_ports, run_self_test
from event_switch_manager.lab_runner.completion import LiveCompletionPolicy
from event_switch_manager.lab_runner.reporting import LabBuildMetadata, LabReportWriter
from event_switch_manager.lab_runner.targets import get_target
from event_switch_manager.lab_runner.transport import AuthorizedSerialTransport


def _port(
    *,
    endpoint: str = "COM3",
    identity: str = "usb:0403:6001:R86ADAPTER",
    quality: IdentityQuality = IdentityQuality.STABLE,
) -> SerialPortInfo:
    return SerialPortInfo(
        port=endpoint,
        description="USB Serial",
        manufacturer="FTDI",
        vid=0x0403,
        pid=0x6001,
        serial_number="R86ADAPTER",
        location="1-2.1",
        adapter_identity=identity,
        identity_quality=quality,
    )


def _discovery(port: SerialPortInfo) -> SerialDiscovery:
    return SerialDiscovery(
        platform="win32",
        status=SerialPlatformStatus.SUPPORTED,
        supported=True,
        ports=(port,),
    )


def _auth(
    target_key: str = "2960x",
    port: SerialPortInfo | None = None,
) -> LabAuthorization:
    selected = port or _port()
    target = get_target(target_key)
    return issue_authorization(
        target,
        com_endpoint=selected.port,
        adapter_identity=selected.adapter_identity,
        ttl_seconds=300,
        operator_confirmed=True,
        artifact_sha256="a" * 64,
        software_git_sha="b" * 40,
    )


class FakeSerial:
    def __init__(self, *, initial: str = "R1>\n", close_failures: int = 0) -> None:
        self.buffer = initial
        self.writes: list[bytes] = []
        self.closed = False
        self.close_failures = close_failures
        self.timeout = 1.0
        self.partial_write = False
        self._partial_sent = False

    @property
    def in_waiting(self) -> int:
        return len(self.buffer.encode("ascii"))

    def write(self, data: bytes) -> int:
        if self.partial_write and not self._partial_sent and len(data) > 1:
            self._partial_sent = True
            self.writes.append(data[:1])
            return 1
        self.writes.append(data)
        return len(data)

    def read(self, count: int) -> bytes:
        if not self.buffer:
            return b""
        text = self.buffer[:count]
        self.buffer = self.buffer[count:]
        return text.encode("ascii")

    def close(self) -> None:
        if self.close_failures > 0:
            self.close_failures -= 1
            raise OSError("synthetic close failure")
        self.closed = True


def _transport(
    *,
    auth: Any | None = None,
    serial: FakeSerial | None = None,
    port: SerialPortInfo | None = None,
) -> tuple[AuthorizedSerialTransport, FakeSerial]:
    selected = port or _port()
    factory_serial = serial or FakeSerial()
    transport = AuthorizedSerialTransport(
        auth or _auth(port=selected),
        discovery=lambda: _discovery(selected),
        serial_factory=lambda _port, _params: factory_serial,
    )
    return transport, factory_serial


def _open_transport(
    *,
    serial: FakeSerial | None = None,
    port: SerialPortInfo | None = None,
    target_key: str = "2960x",
) -> AuthorizedSerialTransport:
    selected = port or _port()
    auth = _auth(target_key=target_key, port=selected)
    transport, _ = _transport(auth=auth, serial=serial, port=selected)
    auth.authorize_open(transport)
    transport.open()
    return transport


def test_product_live_serial_remains_disabled() -> None:
    port = _port()
    with pytest.raises(Exception, match="live serial is disabled"):
        SerialTransport(port, allow_live=True).open()


def test_lab_session_requires_gate() -> None:
    class LabSourceTransport:
        source = ConsoleSource.AUTHORIZED_LIVE_LAB
        port_identity = "usb:test"
        lease_endpoint = "COM3"
        identity_quality = "stable"

        def open(self) -> None:
            return

        def close(self) -> None:
            return

        def write(self, text: str) -> None:
            _ = text

        def read_chunk(self, timeout: float) -> str:
            _ = timeout
            return ""

        def pending_data(self) -> bool:
            return False

    session = ConsoleSession(LabSourceTransport(), timeout=1.0)
    with pytest.raises(LiveDeviceDisabled):
        session.open(None)


def test_authorization_is_single_use_and_expiry_checked() -> None:
    port = _port()
    auth = _auth(port=port)
    first, _ = _transport(auth=auth, port=port)
    auth.authorize_open(first)
    first.open()
    first.close()
    second, _ = _transport(auth=auth, port=port)
    with pytest.raises(LabAuthorizationError):
        auth.authorize_open(second)
    expired = replace(auth, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    third, _ = _transport(auth=expired, port=port)
    with pytest.raises(LabAuthorizationError):
        expired.authorize_open(third)


def test_authorization_rejects_identity_change_and_ambiguous_adapter() -> None:
    port = _port()
    auth = _auth(port=port)
    different = _port(identity="usb:0403:6001:OTHER")
    changed, _ = _transport(auth=auth, port=different)
    auth.authorize_open(changed)
    with pytest.raises(LabAuthorizationError):
        changed.open()
    ambiguous = _port(quality=IdentityQuality.AMBIGUOUS)
    ambiguous_auth = _auth(port=ambiguous)
    ambiguous_transport, _ = _transport(auth=ambiguous_auth, port=ambiguous)
    ambiguous_auth.authorize_open(ambiguous_transport)
    with pytest.raises(LabAuthorizationError):
        ambiguous_transport.open()


def test_authorization_rejects_out_of_scope_query_and_pending_data() -> None:
    c1000 = _open_transport(
        serial=FakeSerial(initial=""),
        target_key="c1000",
    )
    with pytest.raises(LabAuthorizationError):
        c1000.authorization.authorize_query(ConsoleQuery.LICENSE)
    c1000.close()
    pending = _open_transport(serial=FakeSerial(initial="late"))
    with pytest.raises(LabAuthorizationError):
        pending.authorization.authorize_query(ConsoleQuery.VERSION)
    pending.close()


def test_transport_partial_write_and_cleanup_retry() -> None:
    serial = FakeSerial(close_failures=1)
    serial.partial_write = True
    transport = _open_transport(serial=serial)
    transport.write("show version\r")
    assert b"".join(serial.writes) == b"show version\r"
    with pytest.raises(TransportError, match="close"):
        transport.close()
    assert transport.cleanup_required is True
    assert transport.is_open is True
    transport.close()
    assert transport.cleanup_required is False
    assert transport.is_open is False


def test_transport_read_bound_and_pending_data() -> None:
    serial = FakeSerial(initial="A" * 9000)
    transport = _open_transport(serial=serial)
    assert transport.pending_data() is True
    assert len(transport.read_chunk(0.5)) == 4096
    assert transport.cleanup_required is False
    transport.close()


class FakeTerminalSerial(FakeSerial):
    def write(self, data: bytes) -> int:
        self.writes.append(data)
        if b"show version" in data:
            self.buffer += (
                "show version\r\n"
                "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), "
                "Version 15.2(7)E10, RELEASE SOFTWARE (fc3)\r\n"
                "R1>\n"
            )
        return len(data)


def test_authorized_lab_session_opens_and_runs_typed_query() -> None:
    port = _port()
    auth = _auth(port=port)
    serial = FakeTerminalSerial()
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.002),
        timeout=1.0,
    )
    session.open(None)
    try:
        result = session.query_result(ConsoleQuery.VERSION)
        assert result.status is QueryStatus.OK
        assert "15.2(7)E10" in result.output
        assert result.duration_seconds >= 0
        assert auth.consumed is True
        assert serial.writes
    finally:
        session.close()
    assert serial.closed is True


def test_lab_adapter_operator_abort_stops_before_optional_queries() -> None:
    class FakeSession:
        source = ConsoleSource.AUTHORIZED_LIVE_LAB
        session_identity = "lab"
        port_identity = "usb:test"
        fixture_id = None

        def __init__(self) -> None:
            self.queries: list[ConsoleQuery] = []

        def start_discovery(self, **_: object) -> None:
            return

        def end_discovery(self) -> None:
            return

        def set_profile(self, _profile: object) -> None:
            return

        def query_result(self, query: ConsoleQuery) -> ConsoleQueryResult:
            self.queries.append(query)
            if query is ConsoleQuery.VERSION:
                output = (
                    "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), "
                    "Version 15.2(7)E10, RELEASE SOFTWARE (fc3)\n"
                    "cisco WS-C2960X-24TS-L (PowerPC) processor\n"
                )
            elif query is ConsoleQuery.INVENTORY:
                output = (
                    'NAME: "1", DESCR: "WS-C2960X-24TS-L"\n'
                    "PID: WS-C2960X-24TS-L, VID: V05, SN: R86STACK01\n"
                )
            else:
                output = ""
            return ConsoleQueryResult(
                query=query, command=f"show {query.value}",
                status=QueryStatus.OK, output=output,
            )

    fake = FakeSession()
    with pytest.raises(ConsoleOperatorAbort):
        CiscoObservationAdapter().observe(
            fake,  # type: ignore[arg-type]
            expected_pid="WS-C2960X-24TS-L",
            expected_release="15.2(7)E10",
            query_hook=lambda _query, _result: (_ for _ in ()).throw(
                ConsoleOperatorAbort("operator abort")
            ),
        )
    assert fake.queries == [ConsoleQuery.VERSION]


def test_product_serial_close_retains_handle_until_confirmed() -> None:
    transport = SerialTransport(_port())
    serial = FakeSerial(close_failures=1)
    transport._serial = serial
    transport._is_open = True
    with pytest.raises(TransportError):
        transport.close()
    assert transport._serial is serial
    assert transport.cleanup_required is True
    transport.close()
    assert transport._serial is None
    assert transport.cleanup_required is False


def test_completion_policy_is_bounded_quiet_window() -> None:
    import time

    policy = LiveCompletionPolicy(quiet_seconds=0.02)
    policy.observe_chunk("R1>\n")
    policy.candidate_seen()
    assert policy.candidate_ready() is False
    time.sleep(0.03)
    assert policy.candidate_ready() is True
    policy.observe_chunk("late syslog")
    assert policy.candidate_ready() is False


def test_evidence_requires_lab_provenance_and_never_promotes_hardware() -> None:
    observation = ConsoleObservation(
        source=ConsoleSource.AUTHORIZED_LIVE_LAB,
        session_identity="lab-session",
        exact_pid="WS-C2960X-24TS-L",
        software_version="15.2(7)E10",
        serial_number="R86STACK01",
        completeness=ObservationCompleteness.PARTIAL,
    )
    with pytest.raises(ConsoleEvidenceRejected, match="provenance"):
        build_evidence(observation, ())
    provenance = LabProvenance(
        experiment_id="r86-test",
        target="2960x",
        authorization_digest="a" * 64,
        expected_pid="WS-C2960X-24TS-L",
        expected_release="15.2(7)E10",
        observed_pid="WS-C2960X-24TS-L",
        observed_release="15.2(7)E10",
        com_endpoint="COM3",
        adapter_identity_sha256="b" * 64,
        artifact_sha256="c" * 64,
        software_git_sha="d" * 40,
        operator_confirmed=True,
        cleanup_status="RELEASED",
    )
    evidence = build_evidence(
        observation,
        (ConsoleQueryResult(
            query=ConsoleQuery.VERSION,
            command="show version",
            status=QueryStatus.OK,
            output="redacted",
        ),),
        lab_provenance=provenance,
    )
    assert evidence.source is ConsoleSource.AUTHORIZED_LIVE_LAB
    assert evidence.hardware_verified is False
    assert evidence.deployment_approved is False
    assert evidence.observation.hardware_verified is False
    assert evidence.observation.deployment_approved is False


def test_report_redacts_serials_and_has_stable_fingerprint(tmp_path: Path) -> None:
    observation = ConsoleObservation(
        source=ConsoleSource.AUTHORIZED_LIVE_LAB,
        session_identity="lab-session",
        exact_pid="WS-C2960X-24TS-L",
        software_version="15.2(7)E10",
        serial_number="CHASSIS-SECRET-01",
        completeness=ObservationCompleteness.PARTIAL,
    )
    provenance = LabProvenance(
        experiment_id="r86-report",
        target="2960x",
        authorization_digest="a" * 64,
        expected_pid="WS-C2960X-24TS-L",
        expected_release="15.2(7)E10",
        observed_pid="WS-C2960X-24TS-L",
        observed_release="15.2(7)E10",
        com_endpoint="COM3",
        adapter_identity_sha256="b" * 64,
        artifact_sha256="c" * 64,
        software_git_sha="d" * 40,
        operator_confirmed=True,
        cleanup_status="RELEASED",
    )
    evidence = build_evidence(observation, (), lab_provenance=provenance)
    auth = _auth()
    writer = LabReportWriter(
        tmp_path,
        build=LabBuildMetadata("d" * 40, "c" * 64, "test"),
        authorization=auth,
        target=get_target("2960x"),
        discovery=_discovery(_port()),
        port=_port(),
    )
    first = writer.write(
        evidence=evidence,
        connection={"status": "RELEASED"},
        cleanup_status="RELEASED",
        operator_confirmations=2,
        error=None,
    )
    second = writer.write(
        evidence=evidence,
        connection={"status": "RELEASED"},
        cleanup_status="RELEASED",
        operator_confirmations=2,
        error=None,
    )
    report = (tmp_path / "console-lab-report.json").read_text(encoding="utf-8")
    assert "CHASSIS-SECRET-01" not in report
    assert "R86ADAPTER" not in report
    assert first["report_fingerprint"] == second["report_fingerprint"]
    assert (tmp_path / "console-lab-summary.txt").exists()
    assert (tmp_path / "SHA256SUMS").exists()
    assert "console-lab-report.json" in (tmp_path / "SHA256SUMS").read_text(encoding="utf-8")


def test_cli_self_test_and_listing_do_not_open_serial(monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_self_test() == 0
    called: list[bool] = []

    def discovery() -> SerialDiscovery:
        called.append(True)
        return _discovery(_port())

    monkeypatch.setattr("event_switch_manager.lab_runner.cli.discover_serial_ports", discovery)
    assert run_list_ports(as_json=True) == 0
    assert called == [True]


def test_lab_adapter_expected_identity_mismatch_stops_before_optional_queries() -> None:
    class FakeLabSession:
        source = ConsoleSource.AUTHORIZED_LIVE_LAB
        session_identity = "lab"
        port_identity = "usb:test"
        fixture_id = None

        def __init__(self) -> None:
            self.queries: list[ConsoleQuery] = []

        def start_discovery(self, **_: object) -> None:
            return

        def end_discovery(self) -> None:
            return

        def set_profile(self, _profile: object) -> None:
            return

        def query_result(self, query: ConsoleQuery) -> ConsoleQueryResult:
            self.queries.append(query)
            if query is ConsoleQuery.VERSION:
                return ConsoleQueryResult(
                    query=query, command="show version", status=QueryStatus.OK,
                    output=(
                        "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), "
                        "Version 15.2(7)E10, RELEASE SOFTWARE (fc3)\n"
                        "cisco WS-C2960X-24TS-L (PowerPC) processor\n"
                    ),
                )
            if query is ConsoleQuery.INVENTORY:
                return ConsoleQueryResult(
                    query=query, command="show inventory", status=QueryStatus.OK,
                    output=(
                        'NAME: "1", DESCR: "WS-C2960X-24TS-L"\n'
                        "PID: WS-C2960X-24TS-L, VID: V05, SN: R86STACK01\n"
                    ),
                )
            return ConsoleQueryResult(
                query=query, command="show interface", status=QueryStatus.OK,
                output="",
            )

    fake = FakeLabSession()
    with pytest.raises(Exception, match="authorized target"):
        CiscoObservationAdapter().observe(
            fake,  # type: ignore[arg-type]
            expected_pid="C1000-16T-2G-L",
            expected_release="15.2(7)E2",
        )
    assert ConsoleQuery.INTERFACES not in fake.queries
