"""R91 receive-only passive terminal diagnostics tests; no real COM."""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

import pytest

from event_switch_manager.console.discovery import (
    IdentityQuality,
    SerialDiscovery,
    SerialPlatformStatus,
    SerialPortInfo,
)
from event_switch_manager.lab_runner.passive import run_passive_diagnostics
from event_switch_manager.lab_runner.reporting import LabBuildMetadata


class PassiveSerial:
    def __init__(self, chunks: list[str], *, close_failures: int = 0) -> None:
        self.chunks = list(chunks)
        self.writes: list[bytes] = []
        self.closed = False
        self.close_failures = close_failures
        self.timeout = 1.0

    @property
    def in_waiting(self) -> int:
        return len(self.chunks[0].encode()) if self.chunks else 0

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        return len(data)

    def read(self, count: int) -> bytes:
        _ = count
        if not self.chunks:
            return b""
        return self.chunks.pop(0).encode("ascii")

    def close(self) -> None:
        if self.close_failures:
            self.close_failures -= 1
            raise OSError("synthetic passive close failure")
        self.closed = True


def _port() -> SerialPortInfo:
    return SerialPortInfo(
        port="COM3",
        description="USB Serial",
        adapter_identity="usb:0403:6001:TEST",
        identity_quality=IdentityQuality.STABLE,
    )


def _discovery() -> SerialDiscovery:
    return SerialDiscovery(
        platform="win32",
        status=SerialPlatformStatus.SUPPORTED,
        supported=True,
        ports=(_port(),),
    )


def _args(tmp_path: Path, duration: float = 0.4) -> argparse.Namespace:
    return argparse.Namespace(
        target="2960x",
        com="COM3",
        manual_bluetooth_binding=False,
        bluetooth_direction="unknown",
        output_dir=str(tmp_path),
        duration_seconds=duration,
        ttl_minutes=5.0,
        operator_confirmed=True,
    )


def _metadata() -> LabBuildMetadata:
    return LabBuildMetadata("a" * 40, "b" * 64, "test", True, True)


def test_passive_mode_receives_and_never_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serial = PassiveSerial([
        "banner Password: <secret> IP 10.1.2.3 MAC 00:11:22:33:44:55\r\n",
        "\x1b[2Jterminal\x08 R1#\r\n",
    ])
    monkeypatch.setattr(
        LabBuildMetadata, "load", classmethod(lambda _cls: _metadata()),
    )
    result = run_passive_diagnostics(
        _args(tmp_path),
        discovery=_discovery(),
        serial_factory=lambda _port, _params: serial,
    )
    assert result.transport_opened is True
    assert result.bytes_written == 0
    assert serial.writes == []
    assert result.status == "COMPLETED", (result.error, result.primary_failure)
    assert result.cleanup_status == "RELEASED"
    payload = json.loads(result.report_path.read_text(encoding="utf-8"))
    assert payload["mode"] == "receive-only"
    assert payload["transport"]["bytes_written"] == 0
    assert payload["privacy"]["raw_transcript_saved"] is False
    assert payload["privacy"]["credentials_saved"] is False
    combined = (
        result.report_path.read_text(encoding="utf-8")
        + result.events_path.read_text(encoding="utf-8")
        + result.summary_path.read_text(encoding="utf-8")
    )
    for forbidden in ("<secret>", "10.1.2.3", "00:11:22:33:44:55"):
        assert forbidden not in combined
    assert "<CR>" in combined or "<LF>" in combined
    assert result.zip_path is not None and result.zip_path.exists()
    zip_path = result.zip_path
    with zipfile.ZipFile(zip_path) as archive:
        names = set(archive.namelist())
        assert names == {
            "passive-report.json",
            "passive-events.jsonl",
            "passive-summary.txt",
            "SHA256SUMS.passive",
        }
        for name in names:
            assert "<secret>" not in archive.read(name).decode("utf-8")


def test_passive_auth_prompt_stops_without_sending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serial = PassiveSerial(["Username: \r\n"])
    monkeypatch.setattr(
        LabBuildMetadata, "load", classmethod(lambda _cls: _metadata()),
    )
    result = run_passive_diagnostics(
        _args(tmp_path, duration=0.5),
        discovery=_discovery(),
        serial_factory=lambda _port, _params: serial,
    )
    assert result.status == "AUTH_PROMPT_OBSERVED"
    assert serial.writes == []
    assert result.bytes_written == 0
    payload = json.loads(result.report_path.read_text(encoding="utf-8"))
    assert payload["primary_failure"]["stage"] == "authentication"
    assert payload["terminal"]["parser_event_counts"].get("auth-prompt", 0) >= 1


def test_passive_reuses_application_lease_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.console.lease import ConsoleLeaseManager

    manager = ConsoleLeaseManager()
    held = manager.acquire(
        "usb:0403:6001:TEST", "other-owner", endpoint="COM3",
    )
    serial = PassiveSerial([])
    monkeypatch.setattr(
        LabBuildMetadata, "load", classmethod(lambda _cls: _metadata()),
    )
    try:
        result = run_passive_diagnostics(
            _args(tmp_path, duration=0.2),
            discovery=_discovery(),
            serial_factory=lambda _port, _params: serial,
            lease_manager=manager,
        )
    finally:
        held.release()
    assert result.transport_opened is False
    assert serial.writes == []
    assert result.status == "OPEN_FAILED"
    assert manager.active_owner("COM3") is None


def test_passive_export_is_bounded_and_checksummed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serial = PassiveSerial(["x" * 1000 + "\r\n"] * 200)
    monkeypatch.setattr(
        LabBuildMetadata, "load", classmethod(lambda _cls: _metadata()),
    )
    result = run_passive_diagnostics(
        _args(tmp_path, duration=0.3),
        discovery=_discovery(),
        serial_factory=lambda _port, _params: serial,
    )
    assert result.bytes_written == 0
    assert result.events_path.exists()
    payload = json.loads(result.report_path.read_text(encoding="utf-8"))
    assert payload["terminal"]["bounded_limits"]["max_events"] == 256
    assert payload["terminal"]["rx_chunk_count"] <= 512
    assert len(payload["events"]) <= 256
    assert len(payload["chunks"]) <= 512
    assert result.zip_path is not None
    with zipfile.ZipFile(result.zip_path) as archive:
        checksums = archive.read("SHA256SUMS.passive").decode("utf-8")
        assert "passive-report.json" in checksums
        assert "passive-events.jsonl" in checksums
