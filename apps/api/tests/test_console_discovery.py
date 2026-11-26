import sys
from types import SimpleNamespace

import pytest

from event_switch_manager.console.discovery import (
    BluetoothDirection,
    IdentityQuality,
    PortTransportKind,
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


def _bluetooth_port(
    *, device: str = "COM3",
    hwid: str = (
        "BTHENUM\\{00001101-0000-1000-8000-00805F9B34FB}_VID&000205AC_PID&0239"
        "\\7&1A2B3C4D&0&001B101B9C8F_C00000000"
    ),
    description: str = "蓝牙链接上的标准串行 (COM3)",
) -> SimpleNamespace:
    return SimpleNamespace(
        device=device,
        description=description,
        hwid=hwid,
        vid=None,
        pid=None,
        serial_number=None,
        manufacturer="Microsoft",
        location=None,
        interface=None,
        bluetooth_name=None,
    )


def test_bluetooth_spp_outgoing_is_manual_ambiguous_identity() -> None:
    discovery = discover_serial_ports(
        lambda: (_bluetooth_port(),), platform_name="win32",
    )
    port = discovery.ports[0]
    assert port.transport_kind is PortTransportKind.BLUETOOTH_SPP
    assert port.bluetooth_direction is BluetoothDirection.OUTGOING
    assert port.remote_bluetooth_identity == "001B101B9C8F"
    assert port.identity_quality is IdentityQuality.AMBIGUOUS
    assert port.manual_binding_required is True
    assert port.pnp_instance_identity is not None
    assert "COM3" not in port.adapter_identity
    assert port.adapter_identity.startswith("bluetooth-pnp:")
    assert port.usb is False


def test_bluetooth_spp_incoming_and_unknown_direction() -> None:
    incoming = _bluetooth_port(
        device="COM4",
        hwid=(
            "BTHENUM\\{00001101-0000-1000-8000-00805F9B34FB}_LOCALMFG&0000"
            "\\7&1A2B3C4D&0&000000000000_00000002"
        ),
        description="蓝牙链接上的标准串行 (COM4)",
    )
    unknown = _bluetooth_port(
        device="COM5",
        hwid="BTHENUM\\{00001101-0000-1000-8000-00805F9B34FB}",
        description="蓝牙链接上的标准串行 (COM5)",
    )
    discovery = discover_serial_ports(
        lambda: (incoming, unknown), platform_name="win32",
    )
    assert discovery.ports[0].bluetooth_direction is BluetoothDirection.INCOMING
    assert discovery.ports[0].remote_bluetooth_identity is None
    assert discovery.ports[1].bluetooth_direction is BluetoothDirection.UNKNOWN


def test_bluetooth_duplicate_pnp_identity_is_flagged() -> None:
    first = _bluetooth_port(device="COM3")
    second = _bluetooth_port(device="COM6")
    discovery = discover_serial_ports(
        lambda: (first, second), platform_name="win32",
    )
    assert len(discovery.duplicate_identities) == 1
    assert all(port.duplicate_identity for port in discovery.ports)


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


def test_default_enumeration_matches_the_host_platform() -> None:
    discovery = discover_serial_ports()
    if sys.platform == "win32":
        assert discovery.status in {
            SerialPlatformStatus.SUPPORTED,
            SerialPlatformStatus.ENUMERATION_ERROR,
        }
        assert all(port.port.startswith("COM") for port in discovery.ports)
    else:
        assert discovery.status is SerialPlatformStatus.UNSUPPORTED_PLATFORM
        assert discovery.ports == ()


def test_live_serial_adapter_is_disabled_and_os_exclusivity_is_not_claimed() -> None:
    port = discover_serial_ports(lambda: (_port(),), platform_name="win32").ports[0]
    transport = SerialTransport(port)
    with pytest.raises(LiveSerialDisabled, match="live serial is disabled"):
        transport.open()
    with pytest.raises(LiveSerialDisabled, match="live serial is disabled"):
        SerialTransport(port, allow_live=True).open()
    assert OS_EXCLUSIVITY_STATUS == "NOT_VERIFIED"
    assert SerialParameters().baudrate == 9600
    with pytest.raises(ValueError):
        SerialParameters(read_timeout_seconds=0)
