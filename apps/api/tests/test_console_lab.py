from __future__ import annotations

import argparse
import json
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from event_switch_manager.console.discovery import (
    BluetoothDirection,
    IdentityQuality,
    PortTransportKind,
    SerialDiscovery,
    SerialPlatformStatus,
    SerialPortInfo,
    discover_serial_ports,
)
from event_switch_manager.console.models import (
    ConsoleEvidence,
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
from event_switch_manager.console.parser import AuthPromptKind
from event_switch_manager.console.session import (
    ConsoleOperatorAbort,
    ConsoleSendOperation,
    ConsoleSession,
    LiveDeviceDisabled,
    SessionError,
    SessionState,
    SessionStateError,
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
from event_switch_manager.lab_runner.reporting import (
    ArtifactIdentityError,
    LabBuildMetadata,
    LabEvidenceError,
    LabReportWriter,
    sha256_file,
    sha256_text,
    validate_lab_provenance,
    verify_report_fingerprint,
)
from event_switch_manager.lab_runner.targets import get_target
from event_switch_manager.lab_runner.transport import (
    AuthorizedSerialTransport,
    LabSerialError,
)


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


def _bind_write_token(transport: AuthorizedSerialTransport) -> object:
    token = object()
    transport.bind_write_token(token, lambda: SessionState.AUTHENTICATING)
    return token


def test_lab_transport_rejects_raw_and_forged_sends() -> None:
    transport = _open_transport(serial=FakeSerial(initial=""), target_key="c1000")
    with pytest.raises(TransportError, match="raw lab write"):
        transport.write("show version\r")
    with pytest.raises(TransportError, match="bound session"):
        transport.write_authorized(
            "show version\r",
            operation=ConsoleSendOperation.QUERY,
            query=ConsoleQuery.VERSION,
        )
    token = _bind_write_token(transport)
    with pytest.raises(LabAuthorizationError, match="not match|outside"):
        transport.write_authorized(
            "show version\r",
            operation=ConsoleSendOperation.QUERY,
            query=ConsoleQuery.LICENSE,
            session_token=token,
        )
    with pytest.raises(LabAuthorizationError, match="not match"):
        transport.write_authorized(
            "show inventory\r",
            operation=ConsoleSendOperation.QUERY,
            query=ConsoleQuery.VERSION,
            session_token=token,
        )
    transport.close()


def test_direct_write_authorized_cannot_bypass_credential_state_or_text() -> None:
    transport = _open_transport(serial=FakeSerial(initial=""))
    with pytest.raises(TransportError, match="bound session"):
        transport.write_authorized(
            "lab-user\r",
            operation=ConsoleSendOperation.USERNAME,
        )
    token = object()
    transport.bind_write_token(token, lambda: SessionState.USER_EXEC)
    with pytest.raises(TransportError, match="authenticated state"):
        transport.write_authorized(
            "lab-user\r",
            operation=ConsoleSendOperation.USERNAME,
            session_token=token,
        )
    token = _bind_write_token(transport)
    with pytest.raises(LabAuthorizationError, match="fixed"):
        transport.write_authorized(
            "configure terminal\r",
            operation=ConsoleSendOperation.ENABLE,
            session_token=token,
        )
    with pytest.raises(LabAuthorizationError, match="control"):
        transport.write_authorized(
            "lab\ruser\r",
            operation=ConsoleSendOperation.USERNAME,
            session_token=token,
        )
    assert transport._serial is not None
    assert transport._serial.writes == []
    transport.close()


def test_partial_write_stops_when_authorization_is_cancelled() -> None:
    port = _port()
    auth = _auth(port=port)

    class CancelOnFirstWriteSerial(FakeSerial):
        def write(self, data: bytes) -> int:
            self.writes.append(data[:1])
            auth.cancel()
            return 1

    serial = CancelOnFirstWriteSerial(initial="")
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    auth.authorize_open(transport)
    transport.open()
    token = _bind_write_token(transport)
    with pytest.raises(LabAuthorizationError, match="cancelled"):
        transport.write_authorized(
            "show version\r",
            operation=ConsoleSendOperation.QUERY,
            query=ConsoleQuery.VERSION,
            session_token=token,
        )
    assert b"".join(serial.writes) == b"s"
    transport.close()


def test_partial_session_write_stops_after_session_cancel() -> None:
    port = _port()
    auth = _auth(port=port)
    holder: dict[str, ConsoleSession] = {}

    class CancelOnFirstChunkSerial(FakeSerial):
        def write(self, data: bytes) -> int:
            self.writes.append(data[:1])
            holder["session"].cancel()
            return 1

    serial = CancelOnFirstChunkSerial(initial="R1>\n")
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.01),
        timeout=1.0,
    )
    holder["session"] = session
    session.open(None)
    try:
        with pytest.raises(SessionError):
            session.query_result(ConsoleQuery.VERSION)
        assert b"".join(serial.writes) == b"s"
    finally:
        session.close()


def test_authorization_immutability_and_forged_target_rejection() -> None:
    auth = _auth()
    with pytest.raises(AttributeError):
        auth.target = get_target("c1000")
    with pytest.raises(AttributeError):
        auth.expires_at = datetime.now(UTC)
    forged = type(auth.target)(
        key="2960x",
        label="forged",
        expected_pid=auth.target.expected_pid,
        expected_release=auth.target.expected_release,
        allowed_queries=auth.target.allowed_queries,
    )
    with pytest.raises(LabAuthorizationError, match="forged"):
        issue_authorization(
            forged,
            com_endpoint="COM3",
            adapter_identity="usb:test",
            operator_confirmed=True,
        )
    transport = _open_transport(serial=FakeSerial(initial=""))
    token = _bind_write_token(transport)
    transport.write_authorized(
        "\r", operation=ConsoleSendOperation.WAKE, session_token=token,
    )
    with pytest.raises(LabAuthorizationError, match="one authorized wake"):
        transport.write_authorized(
            "\r", operation=ConsoleSendOperation.WAKE, session_token=token,
        )
    transport.close()


_BT_OUTGOING_HWID = (
    "BTHENUM\\{00001101-0000-1000-8000-00805F9B34FB}_VID&000205AC_PID&0239"
    "\\7&1A2B3C4D&0&001B101B9C8F_C00000000"
)


def _bluetooth_discovery(
    *,
    com: str = "COM3",
    hwid: str = _BT_OUTGOING_HWID,
) -> SerialDiscovery:
    entry = type("Entry", (), {
        "device": com,
        "description": f"蓝牙链接上的标准串行 ({com})",
        "hwid": hwid,
        "vid": None,
        "pid": None,
        "serial_number": None,
        "manufacturer": "Microsoft",
        "location": None,
        "interface": None,
    })()
    return discover_serial_ports(lambda: (entry,), platform_name="win32")


def _manual_bluetooth_auth(
    port: SerialPortInfo,
    *,
    direction: str | None = "outgoing",
) -> LabAuthorization:
    return issue_authorization(
        get_target("2960x"),
        com_endpoint=port.port,
        adapter_identity=port.adapter_identity,
        ttl_seconds=300,
        operator_confirmed=True,
        artifact_sha256="a" * 64,
        software_git_sha="b" * 40,
        binding_mode="manual-bluetooth",
        identity_confidence="manual-bound",
        bluetooth_direction=direction,
    )


def test_gui_bluetooth_manual_binding_validation() -> None:
    from event_switch_manager.lab_runner.gui import GuiValidationError, validate_selection

    port = _bluetooth_discovery().ports[0]
    with pytest.raises(GuiValidationError, match="非生产"):
        validate_selection(
            port,
            non_production_confirmed=False,
            manual_bluetooth_binding=True,
        )
    with pytest.raises(GuiValidationError, match="人工绑定"):
        validate_selection(
            port,
            non_production_confirmed=True,
            manual_bluetooth_binding=False,
        )
    with pytest.raises(GuiValidationError, match="方向"):
        validate_selection(
            port,
            non_production_confirmed=True,
            manual_bluetooth_binding=True,
            operator_bluetooth_direction="unknown",
        )
    validate_selection(
        port,
        non_production_confirmed=True,
        manual_bluetooth_binding=True,
        operator_bluetooth_direction="outgoing",
    )
    ambiguous_usb = _port(quality=IdentityQuality.AMBIGUOUS)
    with pytest.raises(GuiValidationError, match="稳定"):
        validate_selection(
            ambiguous_usb,
            non_production_confirmed=True,
            manual_bluetooth_binding=True,
        )


def test_bluetooth_without_pnp_or_direction_cannot_bind() -> None:
    from event_switch_manager.lab_runner.gui import GuiValidationError, validate_selection

    entry = type("Entry", (), {
        "device": "COM7",
        "description": "蓝牙链接上的标准串行 (COM7)",
        "hwid": None,
        "vid": None,
        "pid": None,
        "serial_number": None,
        "manufacturer": "Microsoft",
        "location": None,
        "interface": None,
    })()
    discovery = discover_serial_ports(lambda: (entry,), platform_name="win32")
    port = discovery.ports[0]
    assert port.transport_kind is PortTransportKind.BLUETOOTH_SPP
    assert port.pnp_instance_identity is None
    with pytest.raises(GuiValidationError, match="PnP"):
        validate_selection(
            port,
            non_production_confirmed=True,
            manual_bluetooth_binding=True,
        )
    from event_switch_manager.lab_runner import cli as lab_cli

    with pytest.raises(LabAuthorizationError, match="PnP"):
        lab_cli._select_port(discovery, "COM7", manual_bluetooth_binding=True)
    with pytest.raises(LabAuthorizationError, match="direction"):
        issue_authorization(
            get_target("2960x"),
            com_endpoint="COM7",
            adapter_identity=port.adapter_identity,
            operator_confirmed=True,
            binding_mode="manual-bluetooth",
            identity_confidence="manual-bound",
            bluetooth_direction=None,
        )


def test_gui_unknown_enumeration_requires_operator_direction() -> None:
    from event_switch_manager.lab_runner.gui import GuiValidationError, validate_selection

    entry = type("Entry", (), {
        "device": "COM5",
        "description": "蓝牙链接上的标准串行 (COM5)",
        "hwid": "BTHENUM\\{00001101-0000-1000-8000-00805F9B34FB}",
        "vid": None,
        "pid": None,
        "serial_number": None,
        "manufacturer": "Microsoft",
        "location": None,
        "interface": None,
    })()
    port = discover_serial_ports(lambda: (entry,), platform_name="win32").ports[0]
    with pytest.raises(GuiValidationError, match="明确选择"):
        validate_selection(
            port,
            non_production_confirmed=True,
            manual_bluetooth_binding=True,
            operator_bluetooth_direction="unknown",
        )
    validate_selection(
        port,
        non_production_confirmed=True,
        manual_bluetooth_binding=True,
        operator_bluetooth_direction="incoming",
    )
    incoming = _bluetooth_discovery(
        hwid=(
            "BTHENUM\\{00001101-0000-1000-8000-00805F9B34FB}_LOCALMFG&0000"
            "\\7&1A2B3C4D&0&000000000000_00000002"
        ),
    ).ports[0]
    with pytest.raises(GuiValidationError, match="不一致"):
        validate_selection(
            incoming,
            non_production_confirmed=True,
            manual_bluetooth_binding=True,
            operator_bluetooth_direction="outgoing",
        )


def test_gui_cleanup_blocks_connect_and_retry_contract() -> None:
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Tk display unavailable")
    from event_switch_manager.lab_runner import gui as gui_module

    root.withdraw()
    app = gui_module.ConsoleLabGui(root, smoke=True)
    app.artifact_ok = True
    app.self_ok = True
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        "event_switch_manager.lab_runner.gui.cleanup_required", lambda: True,
    )
    monkeypatch.setattr("tkinter.messagebox.showwarning", lambda *_a, **_k: None)
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *_a, **_k: None)
    try:
        app._refresh_status()
        assert str(app.connect_button.cget("state")) == "disabled"
        assert str(app.cleanup_button.cget("state")) == "normal"
        app._finish_cleanup(False)
        assert str(app.connect_button.cget("state")) == "disabled"
        assert str(app.cleanup_button.cget("state")) == "normal"
        app._finish_cleanup(True)
        assert str(app.cleanup_button.cget("state")) == "disabled"
    finally:
        monkeypatch.undo()
        app.on_close()


def test_cli_cleanup_retention_blocks_new_session_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    class CloseFailSerial(FakeSerial):
        def __init__(self) -> None:
            super().__init__(initial="R1>\n", close_failures=1)
            self.privileged = False

        def write(self, data: bytes) -> int:
            self.writes.append(data)
            if data == b"enable\r":
                self.privileged = True
                self.buffer += "R1#\n"
            elif data and data != b"\r":
                prompt = "R1#\n" if self.privileged else "R1>\n"
                self.buffer += data.decode("ascii", errors="replace") + f"\r\n{prompt}"
            return len(data)

    class FakeAdapter:
        def observe(
            self,
            session: ConsoleSession,
            *,
            expected_pid: str,
            expected_release: str,
            query_hook: Any,
            lab_provenance: LabProvenance,
            deadline_seconds: float,
            partial_evidence_callback: Any = None,
        ) -> ConsoleEvidence:
            _ = (
                expected_pid, expected_release, query_hook, deadline_seconds,
                partial_evidence_callback,
            )
            target = get_target("2960x")
            session.set_profile(target.profile)
            results = tuple(session.query_result(q) for q in target.allowed_queries)
            observation = ConsoleObservation(
                source=ConsoleSource.AUTHORIZED_LIVE_LAB,
                session_identity="cleanup-test",
                exact_pid=target.expected_pid,
                software_version=target.expected_release,
                completeness=ObservationCompleteness.COMPLETE,
            )
            return build_evidence(observation, results, lab_provenance=lab_provenance)

    serial = CloseFailSerial()
    port = _port()
    discovery = _discovery(port)
    metadata = LabBuildMetadata("a" * 40, "b" * 64, "test", True, True)
    monkeypatch.setattr(LabBuildMetadata, "load", classmethod(lambda _cls: metadata))
    monkeypatch.setattr(lab_cli, "discover_serial_ports", lambda: discovery)
    monkeypatch.setattr(lab_cli, "_confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(lab_cli, "CiscoObservationAdapter", FakeAdapter)
    monkeypatch.setattr(
        lab_cli,
        "AuthorizedSerialTransport",
        lambda auth, parameters=None: AuthorizedSerialTransport(
            auth,
            discovery=lambda: discovery,
            serial_factory=lambda _port, _params: serial,
        ),
    )
    exit_code = lab_cli.run_experiment(argparse.Namespace(
        target="2960x",
        com="COM3",
        ttl_minutes=5.0,
        output_dir=str(tmp_path),
    ))
    assert exit_code == lab_cli.EXIT_CLEANUP
    assert lab_cli.cleanup_required() is True
    called: list[bool] = []

    def blocked_discovery() -> SerialDiscovery:
        called.append(True)
        return discovery

    monkeypatch.setattr(lab_cli, "discover_serial_ports", blocked_discovery)
    blocked = lab_cli.run_experiment(argparse.Namespace(
        target="2960x",
        com="COM3",
        ttl_minutes=5.0,
        output_dir=str(tmp_path / "blocked"),
    ))
    assert blocked == lab_cli.EXIT_CLEANUP
    assert called == []
    assert lab_cli.retry_cleanup() is True
    assert lab_cli.cleanup_required() is False


def test_gui_log_redacts_identity_like_values() -> None:
    from event_switch_manager.lab_runner.gui import redact_gui_log

    raw = (
        "COM8 USB Serial VID:PID=0403:6001 identity=usb:0403:6001:SN123456 "
        "usb_serial=SN123456 location=1-2.1\n"
        "已配对设备名称: MySecretSPPName\n"
        "identity=BTHENUM\\{00001101-0000-1000-8000-00805F9B34FB}_VID&1\n"
    )
    redacted = redact_gui_log(raw)
    assert "SN123456" not in redacted
    assert "1-2.1" not in redacted
    assert "MySecretSPPName" not in redacted
    assert "BTHENUM" not in redacted
    assert "<id>" in redacted


def test_gui_refresh_is_off_main_thread_and_ui_dispatch_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time

    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Tk display unavailable")
    from event_switch_manager.lab_runner import gui as gui_module

    root.withdraw()
    app = gui_module.ConsoleLabGui(root, smoke=True)
    discovery = _discovery(_port())
    monkeypatch.setattr(gui_module, "discover_serial_ports", lambda: discovery)
    app.refresh_ports()
    assert app.refresh_worker is not None
    deadline = time.monotonic() + 2
    while app.discovery is None and time.monotonic() < deadline:
        root.update()
        time.sleep(0.02)
    assert app.discovery is not None
    assert len(app.port_tree.get_children()) == 1

    holder: dict[str, str] = {}
    worker = threading.Thread(
        target=lambda: holder.update(
            value=app._run_on_ui(lambda: "dispatched", 2.0),
        ),
    )
    worker.start()
    deadline = time.monotonic() + 2
    while worker.is_alive() and time.monotonic() < deadline:
        root.update()
        time.sleep(0.02)
    worker.join(timeout=1)
    assert holder.get("value") == "dispatched"
    app.on_close()


def test_split_auth_prompt_trailing_space_is_tolerated() -> None:
    class SplitPromptSerial(FakeSerial):
        def write(self, data: bytes) -> int:
            self.writes.append(data)
            if b"lab-pass" in data:
                self.buffer += "R1>\n"
            return len(data)

    port = _port()
    auth = _auth(port=port)
    serial = SplitPromptSerial(initial="Password:")

    def provider(_kind: Any) -> str:
        # Simulate the trailing prompt space arriving while the operator
        # types the password.
        serial.buffer += " "
        return "lab-pass"

    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.01),
        credential_provider=provider,
        timeout=1.0,
    )
    session.open(None, initial_timeout=0.5)
    try:
        assert session.state is SessionState.USER_EXEC
        assert b"lab-pass\r" in serial.writes
    finally:
        session.close()


def test_gui_uses_exact_completed_report_not_lexicographic_latest(
    tmp_path: Path,
) -> None:
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Tk display unavailable")
    from event_switch_manager.lab_runner import gui as gui_module

    root.withdraw()
    app = gui_module.ConsoleLabGui(root, smoke=True)
    older = tmp_path / "experiment-zzzz" / "console-lab-report.json"
    newer = tmp_path / "experiment-aaaa" / "console-lab-report.json"
    older.parent.mkdir()
    newer.parent.mkdir()
    older.write_text(json.dumps({
        "observation": {"exact_pid": "OLD-DEVICE", "completeness": "partial"},
        "outcome": {"experiment_verdict": "FAILED_OR_CANCELLED"},
    }), encoding="utf-8")
    newer.write_text(json.dumps({
        "observation": {"exact_pid": "NEW-DEVICE", "completeness": "complete"},
        "outcome": {"experiment_verdict": "READONLY_QUERIES_COMPLETED"},
    }), encoding="utf-8")
    app._load_completed_report(newer)
    info = app.info_text.get("1.0", "end")
    assert "NEW-DEVICE" in info
    assert "OLD-DEVICE" not in info
    app.on_close()


def test_gui_credential_masking_and_no_auth_rejection() -> None:
    from event_switch_manager.lab_runner.gui import credential_show_character

    assert credential_show_character(AuthPromptKind.USERNAME) == ""
    assert credential_show_character(AuthPromptKind.PASSWORD) == "*"
    assert credential_show_character(AuthPromptKind.ENABLE_PASSWORD) == "*"
    port = _port()
    from event_switch_manager.lab_runner.gui import GuiValidationError, validate_selection

    with pytest.raises(GuiValidationError, match="非生产"):
        validate_selection(
            port,
            non_production_confirmed=False,
            manual_bluetooth_binding=False,
        )


def test_gui_cancel_before_session_activation_stops_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    called: list[bool] = []

    def fake_discovery() -> SerialDiscovery:
        called.append(True)
        return _discovery(_port())

    monkeypatch.setattr(lab_cli, "discover_serial_ports", fake_discovery)
    lab_cli.reset_active_experiment_cancel()
    lab_cli.cancel_active_experiment()
    try:
        code = lab_cli.run_experiment(argparse.Namespace(
            target="2960x",
            com="COM3",
            ttl_minutes=5.0,
            output_dir="unused",
        ))
    finally:
        lab_cli.reset_active_experiment_cancel()
    assert code == lab_cli.EXIT_TRANSPORT
    assert called == []


def test_gui_close_waits_for_live_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Tk display unavailable")
    from event_switch_manager.lab_runner import gui as gui_module

    root.withdraw()
    app = gui_module.ConsoleLabGui(root, smoke=True)
    release = threading.Event()
    done = threading.Event()

    def worker() -> None:
        release.wait(2)
        done.set()

    app.worker = threading.Thread(target=worker, daemon=True)
    app.worker.start()
    monkeypatch.setattr("tkinter.messagebox.askyesno", lambda *_args, **_kwargs: True)
    app.on_close()
    assert app._closing is True
    assert root.winfo_exists()
    release.set()
    done.wait(2)
    app._finish_worker(0)
    deadline = time.monotonic() + 2
    exists = True
    while exists and time.monotonic() < deadline:
        try:
            root.update()
        except tk.TclError:
            exists = False
            break
        try:
            exists = bool(root.winfo_exists())
        except tk.TclError:
            exists = False
        time.sleep(0.02)
    assert exists is False


def test_gui_duplicate_connect_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Tk display unavailable")
    from event_switch_manager.lab_runner import gui as gui_module

    root.withdraw()
    app = gui_module.ConsoleLabGui(root, smoke=True)
    release = threading.Event()
    app.worker = threading.Thread(target=release.wait, args=(2,), daemon=True)
    app.worker.start()
    errors: list[bool] = []
    monkeypatch.setattr(
        "tkinter.messagebox.showerror",
        lambda *_args, **_kwargs: errors.append(True),
    )
    app.connect()
    assert errors == []
    release.set()
    app.worker.join(timeout=2)
    app.worker = None
    app.on_close()


def test_packaging_launcher_routes_default_to_gui(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import importlib.util
    import sys
    import types

    launcher_path = (
        Path(__file__).resolve().parents[1]
        / "packaging"
        / "console_lab"
        / "launcher.py"
    )
    spec = importlib.util.spec_from_file_location("console_lab_launcher", launcher_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    calls: list[str] = []

    def gui_main(_args: list[str]) -> int:
        calls.append("gui")
        return 0

    def cli_main(_args: list[str]) -> int:
        calls.append("cli")
        return 0

    gui_module = types.ModuleType("event_switch_manager.lab_runner.gui")
    gui_module.main = gui_main  # type: ignore[attr-defined]
    cli_module = types.ModuleType("event_switch_manager.lab_runner.cli")
    cli_module.main = cli_main  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "event_switch_manager.lab_runner.gui", gui_module)
    monkeypatch.setitem(sys.modules, "event_switch_manager.lab_runner.cli", cli_module)
    monkeypatch.setattr(sys, "argv", [str(launcher_path)])
    assert module.main() == 0
    assert calls == ["gui"]
    monkeypatch.setattr(sys, "argv", [str(launcher_path), "--self-test"])
    assert module.main() == 0
    assert calls == ["gui", "cli"]


def test_gui_window_close_without_worker_is_safe() -> None:
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Tk display unavailable")
    from event_switch_manager.lab_runner.gui import ConsoleLabGui

    root.withdraw()
    app = ConsoleLabGui(root, smoke=True)
    app.on_close()
    assert app.worker is None
    assert app.worker_result is None


def test_cli_refuses_bluetooth_without_manual_binding() -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    discovery = _bluetooth_discovery()
    with pytest.raises(LabAuthorizationError, match="人工绑定"):
        lab_cli._select_port(discovery, "COM3", manual_bluetooth_binding=False)
    selected = lab_cli._select_port(
        discovery, "COM3", manual_bluetooth_binding=True,
    )
    assert selected.transport_kind is PortTransportKind.BLUETOOTH_SPP


def test_bluetooth_unknown_enumeration_can_bind_operator_direction() -> None:
    entry = type("Entry", (), {
        "device": "COM5",
        "description": "蓝牙链接上的标准串行 (COM5)",
        "hwid": "BTHENUM\\{00001101-0000-1000-8000-00805F9B34FB}",
        "vid": None,
        "pid": None,
        "serial_number": None,
        "manufacturer": "Microsoft",
        "location": None,
        "interface": None,
    })()
    discovery = discover_serial_ports(lambda: (entry,), platform_name="win32")
    port = discovery.ports[0]
    assert port.bluetooth_direction is BluetoothDirection.UNKNOWN
    auth = issue_authorization(
        get_target("2960x"),
        com_endpoint=port.port,
        adapter_identity=port.adapter_identity,
        operator_confirmed=True,
        binding_mode="manual-bluetooth",
        identity_confidence="manual-bound",
        bluetooth_direction="outgoing",
        enumerated_bluetooth_direction="unknown",
    )
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: discovery,
        serial_factory=lambda _port, _params: FakeSerial(initial=""),
    )
    auth.authorize_open(transport)
    transport.open()
    assert auth.bluetooth_direction == "outgoing"
    assert auth.enumerated_bluetooth_direction == "unknown"
    transport.close()
    with pytest.raises(LabAuthorizationError, match="conflict"):
        issue_authorization(
            get_target("2960x"),
            com_endpoint=port.port,
            adapter_identity=port.adapter_identity,
            operator_confirmed=True,
            binding_mode="manual-bluetooth",
            identity_confidence="manual-bound",
            bluetooth_direction="outgoing",
            enumerated_bluetooth_direction="incoming",
        )


def test_bluetooth_manual_binding_opens_with_lower_confidence() -> None:
    discovery = _bluetooth_discovery()
    port = discovery.ports[0]
    assert port.transport_kind is PortTransportKind.BLUETOOTH_SPP
    assert port.bluetooth_direction is BluetoothDirection.OUTGOING
    auth = _manual_bluetooth_auth(port)
    serial = FakeSerial(initial="")
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: discovery,
        serial_factory=lambda _port, _params: serial,
    )
    auth.authorize_open(transport)
    transport.open()
    assert transport.identity_quality == "manual-bound"
    assert auth.consumed is True
    transport.close()


def test_bluetooth_manual_binding_rejects_strict_usb_auth_and_changes() -> None:
    discovery = _bluetooth_discovery()
    port = discovery.ports[0]
    strict = _auth(port=port)  # stable-usb authorization
    strict_transport = AuthorizedSerialTransport(
        strict,
        discovery=lambda: discovery,
        serial_factory=lambda _port, _params: FakeSerial(initial=""),
    )
    strict.authorize_open(strict_transport)
    with pytest.raises(LabAuthorizationError):
        strict_transport.open()

    auth = _manual_bluetooth_auth(port, direction="incoming")
    wrong_direction = AuthorizedSerialTransport(
        auth,
        discovery=lambda: discovery,
        serial_factory=lambda _port, _params: FakeSerial(initial=""),
    )
    auth.authorize_open(wrong_direction)
    with pytest.raises(LabAuthorizationError):
        wrong_direction.open()

    changed_auth = _manual_bluetooth_auth(port)
    changed_discovery = _bluetooth_discovery(com="COM7")
    changed = AuthorizedSerialTransport(
        changed_auth,
        discovery=lambda: changed_discovery,
        serial_factory=lambda _port, _params: FakeSerial(initial=""),
    )
    changed_auth.authorize_open(changed)
    with pytest.raises(LabAuthorizationError):
        changed.open()


def test_transport_partial_write_and_cleanup_retry() -> None:
    serial = FakeSerial(initial="", close_failures=1)
    serial.partial_write = True
    transport = _open_transport(serial=serial)
    token = _bind_write_token(transport)
    transport.write_authorized(
        "show version\r",
        operation=ConsoleSendOperation.QUERY,
        query=ConsoleQuery.VERSION,
        session_token=token,
    )
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
        elif data == b"\r":
            self.buffer += "R1>\n"
        return len(data)


class BlockingTerminalSerial(FakeTerminalSerial):
    """Realistic silent pySerial semantics: empty read consumes its timeout."""

    def read(self, count: int) -> bytes:
        data = super().read(count)
        if data:
            return data
        time.sleep(min(self.timeout, 0.2))
        return b""


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


def test_rejected_query_does_not_reuse_previous_write_count() -> None:
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
        first = session.query_result(ConsoleQuery.VERSION)
        assert first.command_sent is True
        assert first.sent_bytes == len("show version\r")
        auth.cancel()
        with pytest.raises(SessionError):
            session.query_result(ConsoleQuery.INVENTORY)
        failed = session.last_results[-1]
        assert failed.query is ConsoleQuery.INVENTORY
        assert failed.command_sent is False
        assert failed.sent_bytes == 0
        assert failed.response_bytes == 0
        assert failed.completion_status == "not-sent"
        assert failed.failure_stage == "authorize-query"
    finally:
        session.close()


def test_blocking_empty_read_does_not_consume_full_prompt_deadline() -> None:
    import time

    port = _port()
    auth = _auth(port=port)
    serial = BlockingTerminalSerial(initial="R1>\n")
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.05),
        timeout=1.0,
    )
    session.open(None)
    try:
        started = time.monotonic()
        result = session.query_result(ConsoleQuery.VERSION)
        elapsed = time.monotonic() - started
        assert result.status is QueryStatus.OK
        assert elapsed < 0.8, "blocking read consumed the full command deadline"
    finally:
        session.close()


def test_passive_attach_requires_one_operator_confirmed_wake() -> None:
    port = _port()
    auth = _auth(port=port)
    serial = FakeTerminalSerial(initial="")
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.01),
        timeout=0.1,
    )
    session.open(None, initial_timeout=0.02, allow_silent=True)
    try:
        assert session.state is SessionState.AWAITING_PROMPT
        session.wake_once()
        assert serial.writes[-1] == b"\r"
        session.finish_attach(None, timeout=0.5)
        assert session.is_attached is True
        with pytest.raises(SessionStateError):
            session.wake_once()
    finally:
        session.close()


def test_ambiguous_banner_is_not_treated_as_true_silence_or_woken() -> None:
    port = _port()
    auth = _auth(port=port)
    serial = FakeSerial(initial="UNRECOGNIZED BANNER\n")
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.01),
        timeout=0.2,
    )
    with pytest.raises(SessionError):
        session.open(None, initial_timeout=0.05, allow_silent=True)
    assert session.transport_ever_opened
    assert serial.writes == []


def test_unsafe_initial_state_never_wakes_and_has_no_send() -> None:
    port = _port()
    auth = _auth(port=port)
    serial = FakeSerial(initial="switch: \n")
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.01),
        timeout=0.2,
    )
    with pytest.raises(SessionError):
        session.open(None, initial_timeout=0.2, allow_silent=True)
    assert serial.writes == []


def test_expired_authorization_blocks_next_send() -> None:
    port = _port()
    target = get_target("2960x")
    auth = issue_authorization(
        target,
        com_endpoint=port.port,
        adapter_identity=port.adapter_identity,
        ttl_seconds=0.05,
        operator_confirmed=True,
        artifact_sha256="a" * 64,
        software_git_sha="b" * 40,
    )
    serial = FakeSerial(initial="R1>\n")
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.005),
        timeout=0.2,
    )
    session.open(None, initial_timeout=0.2)
    try:
        time.sleep(0.07)
        with pytest.raises(SessionError):
            session.query_result(ConsoleQuery.VERSION)
    finally:
        session.close()


def test_cancellation_interrupts_blocking_read_without_waiting_full_timeout() -> None:
    import threading

    class SilentQuerySerial(BlockingTerminalSerial):
        def write(self, data: bytes) -> int:
            self.writes.append(data)
            return len(data)

    port = _port()
    auth = _auth(port=port)
    serial = SilentQuerySerial(initial="R1>\n")
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.01),
        timeout=1.0,
    )
    session.open(None)
    try:
        timer = threading.Timer(0.05, session.cancel)
        timer.start()
        started = time.monotonic()
        with pytest.raises(SessionError):
            session.query_result(ConsoleQuery.VERSION)
        timer.cancel()
        assert time.monotonic() - started < 0.8
    finally:
        session.close()


def test_operator_gate_blocks_query_before_any_send(monkeypatch: pytest.MonkeyPatch) -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    port = _port()
    auth = _auth(port=port)
    target = get_target("2960x")
    count = [0]
    gate = lab_cli._OperatorGate(auth, target, count)
    serial = FakeSerial(initial="R1>\n")
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=gate,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.01),
        timeout=1.0,
    )
    session.open(None, initial_timeout=0.2)
    try:
        monkeypatch.setattr(lab_cli, "_confirm", lambda *_args, **_kwargs: False)
        with pytest.raises(ConsoleOperatorAbort):
            session.query_result(ConsoleQuery.VERSION)
        assert b"show version\r" not in serial.writes
        assert count[0] == 0
    finally:
        session.close()


def test_credential_is_not_sent_after_auth_budget_expiry() -> None:
    port = _port()
    auth = _auth(port=port)
    serial = FakeSerial(initial="Username: ")

    def provider(_kind: Any) -> str:
        time.sleep(0.06)
        return "late-user"

    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.01),
        credential_provider=provider,
        auth_timeout=0.01,
        timeout=1.0,
    )
    with pytest.raises(SessionError):
        session.open(None, initial_timeout=0.5)
    assert serial.writes == []


def test_operator_cancel_is_distinguished_from_internal_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    class CompleteAdapter:
        def observe(
            self,
            session: ConsoleSession,
            *,
            expected_pid: str,
            expected_release: str,
            query_hook: Any,
            lab_provenance: LabProvenance,
            deadline_seconds: float,
            partial_evidence_callback: Any = None,
        ) -> ConsoleEvidence:
            _ = (
                expected_pid, expected_release, query_hook, deadline_seconds,
                partial_evidence_callback,
            )
            observation = ConsoleObservation(
                source=ConsoleSource.AUTHORIZED_LIVE_LAB,
                session_identity="operator-cancel",
                exact_pid="WS-C2960X-24TS-L",
                software_version="15.2(7)E10",
                completeness=ObservationCompleteness.COMPLETE,
            )
            return build_evidence(
                observation, (), lab_provenance=lab_provenance,
            )

    port = _port()
    discovery = _discovery(port)
    serial = FakeSerial(initial="R1>\n")
    metadata = LabBuildMetadata("a" * 40, "b" * 64, "test", True, True)
    monkeypatch.setattr(LabBuildMetadata, "load", classmethod(lambda _cls: metadata))
    monkeypatch.setattr(lab_cli, "discover_serial_ports", lambda: discovery)
    monkeypatch.setattr(
        lab_cli,
        "_confirm",
        lambda prompt, **_kwargs: "核对" not in prompt and "enable" not in prompt.casefold(),
    )
    monkeypatch.setattr(lab_cli, "CiscoObservationAdapter", CompleteAdapter)
    monkeypatch.setattr(
        lab_cli,
        "AuthorizedSerialTransport",
        lambda auth, parameters=None: AuthorizedSerialTransport(
            auth,
            discovery=lambda: discovery,
            serial_factory=lambda _port, _params: serial,
        ),
    )
    exit_code = lab_cli.run_experiment(argparse.Namespace(
        target="2960x",
        com="COM3",
        ttl_minutes=5.0,
        output_dir=str(tmp_path),
    ))
    assert exit_code != 0
    report = next(tmp_path.glob("experiment-*/console-lab-report.json"))
    payload = json.loads(report.read_text(encoding="utf-8"))
    diagnostics = payload["diagnostics"]
    assert diagnostics["operator_cancelled"] is True
    assert diagnostics["primary_failure"] is None
    assert diagnostics["authorization_final_state"] == "cancelled-by-operator"
    assert payload["cleanup"]["status"] == "RELEASED"


def test_operator_confirmation_time_is_not_query_execution_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    port = _port()
    auth = _auth(port=port)
    target = get_target("2960x")
    gate = lab_cli._OperatorGate(auth, target, [0])
    serial = FakeTerminalSerial(initial="R1>\n")
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=gate,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.01),
        timeout=1.0,
    )
    session.open(None, initial_timeout=0.2)
    gate.session = session
    try:
        def slow_confirm(*_args: Any, **_kwargs: Any) -> bool:
            time.sleep(0.05)
            return True

        monkeypatch.setattr(lab_cli, "_confirm", slow_confirm)
        result = session.query_result(ConsoleQuery.VERSION)
        assert result.status is QueryStatus.OK
        assert result.duration_seconds < 0.04
    finally:
        session.close()


def test_enable_credentials_are_requested_only_at_enable_prompt() -> None:
    class EnableSerial(FakeSerial):
        def write(self, data: bytes) -> int:
            self.writes.append(data)
            if data == b"enable\r":
                self.buffer += "Password: "
            elif b"enable-pass" in data:
                self.buffer += "R1#\n"
            return len(data)

    port = _port()
    auth = _auth(port=port)
    serial = EnableSerial(initial="R1>\n")
    prompts: list[str] = []

    def provider(kind: Any) -> str:
        prompts.append(kind.name)
        return "enable-pass"

    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.01),
        credential_provider=provider,
        timeout=1.0,
    )
    session.open(None, initial_timeout=0.5)
    try:
        assert session.state is SessionState.USER_EXEC
        session.enable_with_operator()
        assert session.state.name == "PRIVILEGED_EXEC"
        assert prompts == ["ENABLE_PASSWORD"]
    finally:
        session.close()


def test_credentials_only_requested_at_real_auth_prompt() -> None:
    class AuthSerial(FakeSerial):
        def write(self, data: bytes) -> int:
            self.writes.append(data)
            if b"lab-user" in data:
                self.buffer += "Password: "
            elif b"lab-pass" in data:
                self.buffer += "R1>\n"
            return len(data)

    port = _port()
    auth = _auth(port=port)
    serial = AuthSerial(initial="Username: ")
    prompts: list[str] = []

    def provider(kind: Any) -> str:
        prompts.append(kind.name)
        return "lab-user" if kind.name == "USERNAME" else "lab-pass"

    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: serial,
    )
    session = ConsoleSession(
        transport,
        lab_gate=auth,
        completion_policy=LiveCompletionPolicy(quiet_seconds=0.01),
        credential_provider=provider,
        timeout=1.0,
    )
    session.open(None, initial_timeout=0.5)
    try:
        assert prompts == ["USERNAME", "PASSWORD"]
        assert session.state is SessionState.USER_EXEC
        assert b"lab-user" in b"".join(serial.writes)
        assert b"lab-pass" in b"".join(serial.writes)
    finally:
        session.close()


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


def test_completion_policy_preserves_candidate_across_trailing_whitespace() -> None:
    import time

    policy = LiveCompletionPolicy(quiet_seconds=0.02)
    policy.observe_chunk("R1#")
    policy.candidate_seen()
    policy.observe_chunk(" ")
    assert policy.candidate_ready() is False
    time.sleep(0.03)
    assert policy.candidate_ready() is True
    policy.observe_chunk("late-junk")
    assert policy.candidate_ready() is False


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
    auth = _auth()
    provenance = LabProvenance(
        experiment_id=auth.experiment_id,
        target="2960x",
        authorization_digest=auth.digest,
        expected_pid="WS-C2960X-24TS-L",
        expected_release="15.2(7)E10",
        observed_pid="WS-C2960X-24TS-L",
        observed_release="15.2(7)E10",
        com_endpoint="COM3",
        adapter_identity_sha256=sha256_text(_port().adapter_identity),
        artifact_sha256=auth.artifact_sha256,
        software_git_sha=auth.software_git_sha,
        operator_confirmed=True,
        cleanup_status="RELEASED",
    )
    evidence = build_evidence(observation, (), lab_provenance=provenance)
    writer = LabReportWriter(
        tmp_path,
        build=LabBuildMetadata("b" * 40, "a" * 64, "test"),
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
    assert "1-2.1" not in report
    assert first["report_fingerprint"] == second["report_fingerprint"]
    assert verify_report_fingerprint(first) is True
    tampered = dict(first)
    tampered["error"] = "changed"
    assert verify_report_fingerprint(tampered) is False
    assert (tmp_path / "console-lab-summary.txt").exists()
    assert (tmp_path / "SHA256SUMS").exists()
    assert "console-lab-report.json" in (tmp_path / "SHA256SUMS").read_text(encoding="utf-8")
    fingerprint_input = tmp_path / "console-lab-report-fingerprint-input.json"
    assert sha256_file(fingerprint_input) == first["report_fingerprint"]


def test_artifact_identity_recomputes_exe_sha_and_rejects_forgery(
    tmp_path: Path,
) -> None:
    exe = tmp_path / "EventSwitchManager-ConsoleLab.exe"
    exe.write_bytes(b"fake frozen lab executable")
    actual = sha256_text("fake frozen lab executable")
    record = tmp_path / "EventSwitchManager-ConsoleLab-build-record.json"
    record.write_text(
        json.dumps({
            "package": "EventSwitchManager-ConsoleLab",
            "git_sha": "a" * 40,
            "executable_sha256": actual,
        }),
        encoding="utf-8",
    )
    metadata = LabBuildMetadata.load(exe)
    assert metadata.is_frozen is True
    assert metadata.identity_verified is True
    assert metadata.artifact_sha256 == actual
    record.write_text(
        json.dumps({
            "package": "EventSwitchManager-ConsoleLab",
            "git_sha": "a" * 40,
            "executable_sha256": "0" * 64,
        }),
        encoding="utf-8",
    )
    with pytest.raises(ArtifactIdentityError):
        LabBuildMetadata.load(exe)
    record.unlink()
    with pytest.raises(ArtifactIdentityError):
        LabBuildMetadata.load(exe).require_frozen()


def test_report_retains_failed_evidence_without_claiming_success(tmp_path: Path) -> None:
    observation = ConsoleObservation(
        source=ConsoleSource.AUTHORIZED_LIVE_LAB,
        session_identity="lab-session",
        exact_pid="WS-C2960X-24TS-L",
        software_version="15.2(7)E10",
        serial_number="FAILED-EVIDENCE",
        completeness=ObservationCompleteness.PARTIAL,
    )
    auth = _auth()
    provenance = LabProvenance(
        experiment_id=auth.experiment_id,
        target="2960x",
        authorization_digest=auth.digest,
        expected_pid="WS-C2960X-24TS-L",
        expected_release="15.2(7)E10",
        observed_pid="WS-C2960X-24TS-L",
        observed_release="15.2(7)E10",
        com_endpoint="COM3",
        adapter_identity_sha256=sha256_text(_port().adapter_identity),
        artifact_sha256=auth.artifact_sha256,
        software_git_sha=auth.software_git_sha,
        operator_confirmed=False,
        cleanup_status="CLEANUP_REQUIRED",
    )
    evidence = build_evidence(observation, (), lab_provenance=provenance)
    with pytest.raises(LabEvidenceError, match="provenance"):
        validate_lab_provenance(
            provenance.model_copy(update={"adapter_identity_sha256": "0" * 64}),
            auth,
            get_target("2960x"),
            observation,
        )
    writer = LabReportWriter(
        tmp_path,
        build=LabBuildMetadata(auth.software_git_sha, auth.artifact_sha256, "test"),
        authorization=auth,
        target=get_target("2960x"),
        discovery=_discovery(_port()),
        port=_port(),
    )
    payload = writer.write(
        evidence=evidence,
        connection={
            "status": "CLEANUP_REQUIRED",
            "opened": True,
            "readonly_queries_completed": False,
            "experiment_verdict": "FAILED_OR_CANCELLED",
        },
        cleanup_status="CLEANUP_REQUIRED",
        operator_confirmations=0,
        error="cleanup required",
    )
    assert payload["evidence"]["source"] == "AUTHORIZED_LIVE_LAB"
    assert payload["evidence"]["lab_provenance_digest"] is not None
    assert payload["outcome"]["experiment_verdict"] == "FAILED_OR_CANCELLED"
    assert "FAILED-EVIDENCE" not in (tmp_path / "console-lab-report.json").read_text(
        encoding="utf-8",
    )


def test_report_does_not_claim_success_for_never_opened_failure(tmp_path: Path) -> None:
    auth = _auth()
    writer = LabReportWriter(
        tmp_path,
        build=LabBuildMetadata("b" * 40, "a" * 64, "test"),
        authorization=auth,
        target=get_target("2960x"),
        discovery=_discovery(_port()),
        port=_port(),
    )
    payload = writer.write(
        evidence=None,
        connection={
            "status": "OPEN_FAILED",
            "opened": False,
            "readonly_queries_completed": False,
            "experiment_verdict": "FAILED_OR_CANCELLED",
        },
        cleanup_status="RELEASED",
        operator_confirmations=0,
        error="session: open failed",
    )
    assert payload["connection"]["opened"] is False
    assert payload["outcome"]["experiment_verdict"] == "FAILED_OR_CANCELLED"
    assert payload["outcome"]["hardware_verdict"] == "NOT_VERIFIED"
    assert payload["evidence"]["hardware_verified"] is False


def test_run_experiment_happy_path_is_wired_without_hardware(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    class IntegrationSerial(FakeSerial):
        def __init__(self) -> None:
            super().__init__(initial="R1>\n")
            self.privileged = False

        def write(self, data: bytes) -> int:
            self.writes.append(data)
            if data == b"enable\r":
                self.privileged = True
                self.buffer += "R1#\n"
            elif data and data != b"\r":
                prompt = "R1#\n" if self.privileged else "R1>\n"
                self.buffer += data.decode("ascii", errors="replace") + f"\r\n{prompt}"
            return len(data)

    port = _port()
    discovery = _discovery(port)
    serial = IntegrationSerial()

    class FakeAdapter:
        def observe(
            self,
            session: ConsoleSession,
            *,
            expected_pid: str,
            expected_release: str,
            query_hook: Any,
            lab_provenance: LabProvenance,
            deadline_seconds: float,
            partial_evidence_callback: Any = None,
        ) -> ConsoleEvidence:
            _ = (
                expected_pid, expected_release, query_hook, deadline_seconds,
                partial_evidence_callback,
            )
            target = get_target("2960x")
            session.set_profile(target.profile)
            results = tuple(
                session.query_result(query) for query in target.allowed_queries
            )
            observation = ConsoleObservation(
                source=ConsoleSource.AUTHORIZED_LIVE_LAB,
                session_identity="lab-integration",
                exact_pid=target.expected_pid,
                software_version=target.expected_release,
                serial_number="INTEGRATION-SERIAL",
                completeness=ObservationCompleteness.COMPLETE,
            )
            return build_evidence(
                observation,
                results,
                lab_provenance=lab_provenance,
            )

    metadata = LabBuildMetadata("a" * 40, "b" * 64, "test", True, True)
    monkeypatch.setattr(
        LabBuildMetadata, "load", classmethod(lambda _cls: metadata),
    )
    monkeypatch.setattr(lab_cli, "discover_serial_ports", lambda: discovery)
    monkeypatch.setattr(lab_cli, "_confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(lab_cli, "CiscoObservationAdapter", FakeAdapter)
    monkeypatch.setattr(
        lab_cli,
        "AuthorizedSerialTransport",
        lambda auth, parameters=None: AuthorizedSerialTransport(
            auth,
            discovery=lambda: discovery,
            serial_factory=lambda _port, _params: serial,
        ),
    )
    exit_code = lab_cli.run_experiment(argparse.Namespace(
        target="2960x",
        com="COM3",
        ttl_minutes=5.0,
        output_dir=str(tmp_path),
    ))
    assert exit_code == 0
    report = next(tmp_path.glob("experiment-*/console-lab-report.json"))
    assert lab_cli.last_report_path() == report
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["outcome"]["experiment_verdict"] == "READONLY_QUERIES_COMPLETED"
    assert payload["outcome"]["hardware_verdict"] == "NOT_VERIFIED"
    assert payload["connection"]["opened"] is True
    assert payload["connection"]["status"] == "RELEASED"
    assert payload["evidence"]["source"] == "AUTHORIZED_LIVE_LAB"
    assert len(payload["queries"]) == len(get_target("2960x").allowed_queries)
    assert verify_report_fingerprint(payload) is True


def test_run_experiment_retains_identity_conflict_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.console.observation import IdentityConflict
    from event_switch_manager.lab_runner import cli as lab_cli

    class ConflictSerial(FakeSerial):
        def write(self, data: bytes) -> int:
            self.writes.append(data)
            if data == b"enable\r":
                self.buffer += "R1#\n"
            return len(data)

    port = _port()
    discovery = _discovery(port)
    serial = ConflictSerial(initial="R1>\n")

    class ConflictAdapter:
        def observe(
            self,
            session: ConsoleSession,
            *,
            expected_pid: str,
            expected_release: str,
            query_hook: Any,
            lab_provenance: LabProvenance,
            deadline_seconds: float,
            partial_evidence_callback: Any = None,
        ) -> ConsoleEvidence:
            _ = (expected_pid, expected_release, query_hook, deadline_seconds)
            observation = ConsoleObservation(
                source=ConsoleSource.AUTHORIZED_LIVE_LAB,
                session_identity="lab-conflict",
                exact_pid="WS-C2960X-24TS-L",
                software_version="15.2(7)E10",
                serial_number="CONFLICT-SERIAL",
                completeness=ObservationCompleteness.PARTIAL,
                unknown_fields=("identity-conflict-expected-pid",),
            )
            if partial_evidence_callback is not None:
                partial_evidence_callback(observation, ())
            raise IdentityConflict("expected identity conflict")

    metadata = LabBuildMetadata("a" * 40, "b" * 64, "test", True, True)
    monkeypatch.setattr(LabBuildMetadata, "load", classmethod(lambda _cls: metadata))
    monkeypatch.setattr(lab_cli, "discover_serial_ports", lambda: discovery)
    monkeypatch.setattr(lab_cli, "_confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(lab_cli, "CiscoObservationAdapter", ConflictAdapter)
    monkeypatch.setattr(
        lab_cli,
        "AuthorizedSerialTransport",
        lambda auth, parameters=None: AuthorizedSerialTransport(
            auth,
            discovery=lambda: discovery,
            serial_factory=lambda _port, _params: serial,
        ),
    )
    exit_code = lab_cli.run_experiment(argparse.Namespace(
        target="2960x",
        com="COM3",
        ttl_minutes=5.0,
        output_dir=str(tmp_path),
    ))
    assert exit_code != 0
    report = next(tmp_path.glob("experiment-*/console-lab-report.json"))
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["outcome"]["experiment_verdict"] == "FAILED_OR_CANCELLED"
    assert payload["evidence"]["source"] == "AUTHORIZED_LIVE_LAB"
    assert payload["evidence"]["lab_provenance_digest"] is not None
    assert "CONFLICT-SERIAL" not in report.read_text(encoding="utf-8")


def test_run_experiment_bluetooth_manual_binding_happy_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    class IntegrationSerial(FakeSerial):
        def __init__(self) -> None:
            super().__init__(initial="R1>\n")
            self.privileged = False

        def write(self, data: bytes) -> int:
            self.writes.append(data)
            if data == b"enable\r":
                self.privileged = True
                self.buffer += "R1#\n"
            elif data and data != b"\r":
                prompt = "R1#\n" if self.privileged else "R1>\n"
                self.buffer += data.decode("ascii", errors="replace") + f"\r\n{prompt}"
            return len(data)

    discovery = _bluetooth_discovery()
    port = discovery.ports[0]
    serial = IntegrationSerial()
    target = get_target("2960x")

    class FakeAdapter:
        def observe(
            self,
            session: ConsoleSession,
            *,
            expected_pid: str,
            expected_release: str,
            query_hook: Any,
            lab_provenance: LabProvenance,
            deadline_seconds: float,
            partial_evidence_callback: Any = None,
        ) -> ConsoleEvidence:
            _ = (
                expected_pid, expected_release, query_hook, deadline_seconds,
                partial_evidence_callback,
            )
            session.set_profile(target.profile)
            results = tuple(session.query_result(q) for q in target.allowed_queries)
            observation = ConsoleObservation(
                source=ConsoleSource.AUTHORIZED_LIVE_LAB,
                session_identity="lab-bt",
                exact_pid=target.expected_pid,
                software_version=target.expected_release,
                completeness=ObservationCompleteness.COMPLETE,
            )
            return build_evidence(
                observation, results, lab_provenance=lab_provenance,
            )

    metadata = LabBuildMetadata("a" * 40, "b" * 64, "test", True, True)
    monkeypatch.setattr(LabBuildMetadata, "load", classmethod(lambda _cls: metadata))
    monkeypatch.setattr(lab_cli, "discover_serial_ports", lambda: discovery)
    monkeypatch.setattr(lab_cli, "_confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(lab_cli, "CiscoObservationAdapter", FakeAdapter)
    monkeypatch.setattr(
        lab_cli,
        "AuthorizedSerialTransport",
        lambda auth, parameters=None: AuthorizedSerialTransport(
            auth,
            discovery=lambda: discovery,
            serial_factory=lambda _port, _params: serial,
        ),
    )
    exit_code = lab_cli.run_experiment(argparse.Namespace(
        target="2960x",
        com=port.port,
        ttl_minutes=5.0,
        output_dir=str(tmp_path),
        manual_bluetooth_binding=True,
        bluetooth_direction="outgoing",
    ))
    assert exit_code == 0
    report = next(tmp_path.glob("experiment-*/console-lab-report.json"))
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["discovery"]["transport_kind"] == "bluetooth-spp"
    assert payload["discovery"]["binding_mode"] == "manual-bluetooth"
    assert payload["discovery"]["identity_confidence"] == "manual-bound"
    assert payload["outcome"]["experiment_verdict"] == "READONLY_QUERIES_COMPLETED"
    assert payload["evidence"]["source"] == "AUTHORIZED_LIVE_LAB"


def test_run_experiment_records_open_failure_truthfully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    port = _port()
    discovery = _discovery(port)
    serial = FakeSerial(initial="switch: \n")
    metadata = LabBuildMetadata("a" * 40, "b" * 64, "test", True, True)
    monkeypatch.setattr(LabBuildMetadata, "load", classmethod(lambda _cls: metadata))
    monkeypatch.setattr(lab_cli, "discover_serial_ports", lambda: discovery)
    monkeypatch.setattr(lab_cli, "_confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        lab_cli,
        "AuthorizedSerialTransport",
        lambda auth, parameters=None: AuthorizedSerialTransport(
            auth,
            discovery=lambda: discovery,
            serial_factory=lambda _port, _params: serial,
        ),
    )
    exit_code = lab_cli.run_experiment(argparse.Namespace(
        target="2960x",
        com="COM3",
        ttl_minutes=5.0,
        output_dir=str(tmp_path),
    ))
    assert exit_code != 0
    report = next(tmp_path.glob("experiment-*/console-lab-report.json"))
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["connection"]["status"] == "ATTACH_FAILED"
    assert payload["connection"]["transport_status"] == "OPENED"
    assert payload["connection"]["passive_attach_status"] == "FAILED"
    assert payload["connection"]["opened"] is True
    assert payload["connection"]["transport_opened"] is True
    assert payload["outcome"]["experiment_verdict"] == "FAILED_OR_CANCELLED"
    assert serial.writes == []


def test_attach_prompt_collision_reports_stage_and_terminal_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    port = _port()
    discovery = _discovery(port)
    serial = FakeSerial(initial="banner\r\nR1#\r\nR2#\r\n")
    metadata = LabBuildMetadata("a" * 40, "b" * 64, "test", True, True)
    monkeypatch.setattr(LabBuildMetadata, "load", classmethod(lambda _cls: metadata))
    monkeypatch.setattr(lab_cli, "discover_serial_ports", lambda: discovery)
    monkeypatch.setattr(lab_cli, "_confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        lab_cli,
        "AuthorizedSerialTransport",
        lambda auth, parameters=None: AuthorizedSerialTransport(
            auth,
            discovery=lambda: discovery,
            serial_factory=lambda _port, _params: serial,
        ),
    )
    exit_code = lab_cli.run_experiment(argparse.Namespace(
        target="2960x",
        com="COM3",
        ttl_minutes=5.0,
        output_dir=str(tmp_path),
    ))
    assert exit_code != 0
    report = next(tmp_path.glob("experiment-*/console-lab-report.json"))
    payload = json.loads(report.read_text(encoding="utf-8"))
    connection = payload["connection"]
    assert connection["opened"] is True
    assert connection["transport_status"] == "OPENED"
    assert connection["passive_attach_status"] == "FAILED"
    assert connection["status"] == "ATTACH_FAILED"
    assert payload["diagnostics"]["phase"] == "passive-attach"
    assert payload["diagnostics"]["primary_failure"]["stage"] == "passive-attach"
    assert payload["diagnostics"]["terminal"]["prompt_collision_reason"] is not None
    assert payload["diagnostics"]["terminal"]["rx_chunk_count"] >= 1
    assert payload["diagnostics"]["wake_sent"] is False
    assert payload["connection"]["readonly_queries_completed"] is False


def test_late_data_during_final_review_cannot_be_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    class IntegrationSerial(FakeSerial):
        def __init__(self) -> None:
            super().__init__(initial="R1>\n")
            self.privileged = False

        def write(self, data: bytes) -> int:
            self.writes.append(data)
            if data == b"enable\r":
                self.privileged = True
                self.buffer += "R1#\n"
            elif data and data != b"\r":
                prompt = "R1#\n" if self.privileged else "R1>\n"
                self.buffer += data.decode("ascii", errors="replace") + f"\r\n{prompt}"
            return len(data)

    port = _port()
    discovery = _discovery(port)
    serial = IntegrationSerial()
    target = get_target("2960x")

    class FakeAdapter:
        def observe(
            self,
            session: ConsoleSession,
            *,
            expected_pid: str,
            expected_release: str,
            query_hook: Any,
            lab_provenance: LabProvenance,
            deadline_seconds: float,
            partial_evidence_callback: Any = None,
        ) -> ConsoleEvidence:
            _ = (
                expected_pid, expected_release, query_hook, deadline_seconds,
                partial_evidence_callback,
            )
            session.set_profile(target.profile)
            results = tuple(session.query_result(q) for q in target.allowed_queries)
            observation = ConsoleObservation(
                source=ConsoleSource.AUTHORIZED_LIVE_LAB,
                session_identity="lab-late",
                exact_pid=target.expected_pid,
                software_version=target.expected_release,
                completeness=ObservationCompleteness.COMPLETE,
            )
            evidence = build_evidence(
                observation, results, lab_provenance=lab_provenance,
            )
            serial.buffer += "late asynchronous syslog\r\n"
            return evidence

    metadata = LabBuildMetadata("a" * 40, "b" * 64, "test", True, True)
    monkeypatch.setattr(LabBuildMetadata, "load", classmethod(lambda _cls: metadata))
    monkeypatch.setattr(lab_cli, "discover_serial_ports", lambda: discovery)
    monkeypatch.setattr(lab_cli, "_confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(lab_cli, "CiscoObservationAdapter", FakeAdapter)
    monkeypatch.setattr(
        lab_cli,
        "AuthorizedSerialTransport",
        lambda auth, parameters=None: AuthorizedSerialTransport(
            auth,
            discovery=lambda: discovery,
            serial_factory=lambda _port, _params: serial,
        ),
    )
    exit_code = lab_cli.run_experiment(argparse.Namespace(
        target="2960x",
        com="COM3",
        ttl_minutes=5.0,
        output_dir=str(tmp_path),
    ))
    assert exit_code != 0
    report = next(tmp_path.glob("experiment-*/console-lab-report.json"))
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["outcome"]["experiment_verdict"] == "FAILED_OR_CANCELLED"
    assert payload["evidence"]["source"] == "AUTHORIZED_LIVE_LAB"
    assert payload["evidence"]["lab_provenance_digest"] is not None


def test_r89_field_failure_fixtures_are_sanitized() -> None:
    fixture = Path(__file__).parent / "fixtures" / "console_lab_r89_failures.json"
    data = json.loads(fixture.read_text(encoding="utf-8"))
    assert data["schema"] == "r89-field-failure-fixtures-v1"
    assert len(data["failures"]) == 2
    text = fixture.read_text(encoding="utf-8").casefold()
    for forbidden in ("password", "secret", "hostname", "serial_number", "mac"):
        assert forbidden not in text
    first = data["failures"][0]
    assert first["transport_opened"] is False
    assert first["connection_status"] == "OPEN_FAILED"
    second = data["failures"][1]
    assert second["transport_opened"] is True
    assert second["query"] == "version"
    assert second["sent_bytes"] == 13
    assert second["response_bytes"] == 0
    assert second["authorization_final_state"] == "cancelled-after-primary-failure"


def test_serial_open_failure_preserves_os_diagnostic() -> None:
    port = _port()
    auth = _auth(port=port)
    transport = AuthorizedSerialTransport(
        auth,
        discovery=lambda: _discovery(port),
        serial_factory=lambda _port, _params: (_ for _ in ()).throw(
            OSError(13, "synthetic denied"),
        ),
    )
    auth.authorize_open(transport)
    with pytest.raises(LabSerialError) as error:
        transport.open()
    assert error.value.code == "lab-serial-open-failed"
    assert error.value.stage == "open"
    assert error.value.os_error_type in {"OSError", "PermissionError"}
    assert transport.ever_opened is False
    assert transport.cleanup_required is False


def test_first_query_failure_not_masked_by_cancelled_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.lab_runner import cli as lab_cli

    class ReadFailSerial(FakeSerial):
        def __init__(self) -> None:
            super().__init__(initial="")
            self.fail_reads = False

        def write(self, data: bytes) -> int:
            self.writes.append(data)
            if data == b"\r":
                self.buffer += "R1>\n"
            else:
                self.fail_reads = True
            return len(data)

        def read(self, count: int) -> bytes:
            if self.fail_reads:
                raise OSError(10054, "synthetic bluetooth reset")
            return super().read(count)

    port = _port()
    discovery = _discovery(port)
    serial = ReadFailSerial()
    metadata = LabBuildMetadata("a" * 40, "b" * 64, "test", True, True)
    monkeypatch.setattr(LabBuildMetadata, "load", classmethod(lambda _cls: metadata))
    monkeypatch.setattr(lab_cli, "discover_serial_ports", lambda: discovery)
    monkeypatch.setattr(
        lab_cli,
        "_confirm",
        lambda prompt, **_kwargs: "enable" not in prompt.casefold(),
    )
    monkeypatch.setattr(
        lab_cli,
        "AuthorizedSerialTransport",
        lambda auth, parameters=None: AuthorizedSerialTransport(
            auth,
            discovery=lambda: discovery,
            serial_factory=lambda _port, _params: serial,
        ),
    )
    exit_code = lab_cli.run_experiment(argparse.Namespace(
        target="2960x",
        com="COM3",
        ttl_minutes=5.0,
        output_dir=str(tmp_path),
    ))
    assert exit_code != 0
    report_path = next(tmp_path.glob("experiment-*/console-lab-report.json"))
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    diagnostics = payload["diagnostics"]
    primary = diagnostics["primary_failure"]
    assert primary is not None
    assert primary["stage"] in {"read", "send", "parse"}
    assert primary["query"] == "version"
    assert primary["command_sent"] is True
    assert primary["sent_bytes"] == len("show version\r")
    assert primary["response_bytes"] == 0
    assert diagnostics["wake_sent"] is True
    assert diagnostics["wake_confirmed"] is True
    assert diagnostics["authorization_final_state"] == (
        "cancelled-after-primary-failure"
    )
    assert "authorization: lab authorization was cancelled" not in (
        payload.get("error") or ""
    )
    query = next(
        item for item in payload["queries"] if item["query"] == "version"
    )
    assert query["command_sent"] is True
    assert query["sent_bytes"] == len("show version\r")
    assert query["response_bytes"] == 0
    assert query["failure_stage"] is not None


def test_gui_passive_diagnostic_entry_is_separate_and_receive_only() -> None:
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Tk display unavailable")
    from event_switch_manager.lab_runner import gui as gui_module

    root.withdraw()
    app = gui_module.ConsoleLabGui(root, smoke=True)
    try:
        assert "被动终端诊断" in str(app.passive_button.cget("text"))
        assert "只收不发" in str(app.passive_button.cget("text"))
        assert str(app.export_button.cget("state")) == "disabled"
        assert "连接并开始实验" in str(app.connect_button.cget("text"))
    finally:
        app.on_close()


def test_gui_profile_switch_refreshes_auth_summary_and_progress() -> None:
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Tk display unavailable")
    from event_switch_manager.lab_runner import gui as gui_module

    root.withdraw()
    app = gui_module.ConsoleLabGui(root, smoke=True)
    app.discovery = _discovery(_port())
    app.port_tree.insert("", "end", iid="COM3", values=(
        "COM3", "usb", "unknown", "-", "stable", "no",
    ))
    app.port_tree.selection_set("COM3")
    app.target_var.set("c1000")
    app._update_auth_panel()
    assert "C1000-16T-2G-L" in app.auth_text.get()
    assert app.progress.cget("value") == 0
    app.progress.start(12)
    app._finish_worker(6)
    assert int(app.progress.cget("value")) == 0
    assert app.connection_status_var.get().startswith("状态:")
    app.on_close()


def test_build_record_supports_gui_and_cli_entrypoint_hashes(tmp_path: Path) -> None:
    gui = tmp_path / "EventSwitchManager-ConsoleLab.exe"
    cli = tmp_path / "EventSwitchManager-ConsoleLab-CLI.exe"
    gui.write_bytes(b"gui executable")
    cli.write_bytes(b"cli executable")
    gui_hash = sha256_text("gui executable")
    cli_hash = sha256_text("cli executable")
    (tmp_path / "EventSwitchManager-ConsoleLab-build-record.json").write_text(
        json.dumps({
            "package": "EventSwitchManager-ConsoleLab",
            "git_sha": "a" * 40,
            "executable_sha256": gui_hash,
            "cli_executable_sha256": cli_hash,
        }),
        encoding="utf-8",
    )
    gui_meta = LabBuildMetadata.load(gui)
    cli_meta = LabBuildMetadata.load(cli)
    assert gui_meta.entrypoint == "gui"
    assert gui_meta.artifact_sha256 == gui_hash
    assert cli_meta.entrypoint == "cli"
    assert cli_meta.artifact_sha256 == cli_hash


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

    captured: list[tuple[Any, Any]] = []
    fake = FakeLabSession()
    with pytest.raises(Exception, match="authorized target"):
        CiscoObservationAdapter().observe(
            fake,  # type: ignore[arg-type]
            expected_pid="C1000-16T-2G-L",
            expected_release="15.2(7)E2",
            partial_evidence_callback=lambda observation, results: captured.append(
                (observation, results),
            ),
        )
    assert ConsoleQuery.INTERFACES not in fake.queries
    assert len(captured) == 1
    partial_observation, partial_results = captured[0]
    assert partial_observation.exact_pid == "WS-C2960X-24TS-L"
    assert partial_observation.completeness is ObservationCompleteness.PARTIAL
    assert len(partial_results) == 2
