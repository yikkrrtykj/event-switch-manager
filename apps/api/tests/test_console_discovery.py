from types import SimpleNamespace

import pytest

from event_switch_manager.console.discovery import (
    IdentityQuality,
    SerialPlatformStatus,
    discover_serial_ports,
)
from event_switch_manager.console.lease import OS_EXCLUSIVITY_STATUS
from event_switch_manager.console.transport import (
    LiveSerialDisabled,
    SerialParameters,
    SerialTransport,
)


def _port(**values: object) -> SimpleNamespace:
    defaults = {
        "device": "COM3",
        "description": "USB Serial Port",
        "hwid": "USB VID:PID=0403:6001 SER=ABC123",
        "vid": 0x0403,
        "pid": 0x6001,
        "serial_number": "ABC123",
        "manufacturer": "FTDI",
        "location": "1-2.1",
        "interface": None,
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def test_windows_enumeration_is_read_only_and_preserves_adapter_identity() -> None:
    discovery = discover_serial_ports(
        lambda: (_port(),), platform_name="win32",
    )
    assert discovery.status is SerialPlatformStatus.SUPPORTED
    assert discovery.supported is True
    assert len(discovery.ports) == 1
    port = discovery.ports[0]
    assert port.port == "COM3"
    assert port.vid == 0x0403
    assert port.pid == 0x6001
    assert port.adapter_identity == "usb:0403:6001:ABC123"
    assert port.identity_quality is IdentityQuality.STABLE
    assert port.usb is True


def test_no_ports_is_a_supported_empty_result() -> None:
    discovery = discover_serial_ports(lambda: (), platform_name="win32")
    assert discovery.status is SerialPlatformStatus.SUPPORTED
    assert discovery.ports == ()


def test_multiple_distinct_adapters_and_port_list_changes() -> None:
    entries: list[SimpleNamespace] = [_port()]
    first = discover_serial_ports(lambda: tuple(entries), platform_name="win32")
    assert [port.port for port in first.ports] == ["COM3"]
    entries.append(_port(
        device="COM7", serial_number="XYZ789",
        hwid="USB VID:PID=0403:6015 SER=XYZ789",
        vid=0x0403, pid=0x6015,
    ))
    second = discover_serial_ports(lambda: tuple(entries), platform_name="win32")
    assert [port.port for port in second.ports] == ["COM3", "COM7"]
    assert len({port.adapter_identity for port in second.ports}) == 2


def test_missing_serial_never_uses_dynamic_com_number_as_permanent_identity() -> None:
    discovery = discover_serial_ports(
        lambda: (_port(serial_number=None),), platform_name="win32",
    )
    port = discovery.ports[0]
    assert "COM3" not in port.adapter_identity
    assert port.identity_quality is IdentityQuality.AMBIGUOUS
    assert port.adapter_identity.startswith("usb:0403:6001:loc:")


def test_duplicate_adapter_identity_is_flagged() -> None:
    first = _port()
    second = _port(device="COM4")
    discovery = discover_serial_ports(
        lambda: (first, second), platform_name="win32",
    )
    assert discovery.duplicate_identities == ("usb:0403:6001:ABC123",)
    assert all(port.duplicate_identity for port in discovery.ports)
    assert all(port.identity_quality is IdentityQuality.AMBIGUOUS for port in discovery.ports)


def test_enumeration_error_is_sanitized_and_does_not_claim_hardware() -> None:
    def broken() -> tuple[object, ...]:
        raise OSError("COM adapter failure")

    discovery = discover_serial_ports(broken, platform_name="win32")
    assert discovery.status is SerialPlatformStatus.ENUMERATION_ERROR
    assert discovery.supported is False
    assert discovery.ports == ()
    assert discovery.errors == ("serial-enumeration-failed",)


def test_non_windows_returns_explicit_unsupported_status_without_fake_records() -> None:
    discovery = discover_serial_ports(lambda: (_port(),), platform_name="linux")
    assert discovery.status is SerialPlatformStatus.UNSUPPORTED_PLATFORM
    assert discovery.supported is False
    assert discovery.ports == ()


def test_default_windows_enumeration_is_safe_without_opening_a_port() -> None:
    discovery = discover_serial_ports(platform_name="win32")
    assert discovery.status in {
        SerialPlatformStatus.SUPPORTED,
        SerialPlatformStatus.ENUMERATION_ERROR,
    }
    assert discovery.ports == () or all(
        port.port.startswith("COM") for port in discovery.ports
    )


def test_live_serial_adapter_is_disabled_and_os_exclusivity_is_not_claimed() -> None:
    port = discover_serial_ports(lambda: (_port(),), platform_name="win32").ports[0]
    transport = SerialTransport(port)
    with pytest.raises(LiveSerialDisabled, match="live serial is disabled"):
        transport.open()
    assert OS_EXCLUSIVITY_STATUS == "NOT_VERIFIED"
    assert SerialParameters().baudrate == 9600
    with pytest.raises(ValueError):
        SerialParameters(read_timeout_seconds=0)
