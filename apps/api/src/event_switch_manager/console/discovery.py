"""Read-only Windows COM port discovery.

Discovery calls the operating-system enumerator only.  It never opens a port,
never writes bytes and never treats a dynamic COM number as a permanent
hardware identity.
"""

from __future__ import annotations

import hashlib
import re
import sys
from collections import Counter
from collections.abc import Callable
from enum import StrEnum
from typing import Any

from ..planning.types import Record

_PORT_LABEL = re.compile(r"^(COM\d+|/dev/tty[A-Za-z0-9._-]+)$")


class SerialPlatformStatus(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED_PLATFORM = "unsupported-platform"
    ENUMERATION_ERROR = "enumeration-error"


class IdentityQuality(StrEnum):
    STABLE = "stable"
    AMBIGUOUS = "ambiguous"


class PortTransportKind(StrEnum):
    USB = "usb"
    BLUETOOTH_SPP = "bluetooth-spp"
    NATIVE_SERIAL = "native-serial"
    UNKNOWN = "unknown"


class BluetoothDirection(StrEnum):
    INCOMING = "incoming"
    OUTGOING = "outgoing"
    UNKNOWN = "unknown"


class SerialPortInfo(Record):
    port: str
    description: str | None = None
    hardware_id: str | None = None
    vid: int | None = None
    pid: int | None = None
    serial_number: str | None = None
    manufacturer: str | None = None
    location: str | None = None
    interface: str | None = None
    adapter_identity: str
    identity_quality: IdentityQuality
    duplicate_identity: bool = False
    transport_kind: PortTransportKind = PortTransportKind.UNKNOWN
    pnp_instance_identity: str | None = None
    bluetooth_name: str | None = None
    bluetooth_direction: BluetoothDirection = BluetoothDirection.UNKNOWN
    remote_bluetooth_identity: str | None = None

    @property
    def usb(self) -> bool:
        return self.vid is not None and self.pid is not None

    @property
    def manual_binding_required(self) -> bool:
        return self.transport_kind is PortTransportKind.BLUETOOTH_SPP


class SerialDiscovery(Record):
    platform: str
    status: SerialPlatformStatus
    supported: bool
    ports: tuple[SerialPortInfo, ...] = ()
    duplicate_identities: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


def _value(item: Any, name: str) -> Any:
    if isinstance(item, dict):
        return item.get(name)
    return getattr(item, name, None)


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _normalize_serial(value: Any) -> str | None:
    text = _optional_text(value)
    if text is None:
        return None
    if text.upper() in {"N/A", "NA", "NONE", "UNKNOWN", "0"}:
        return None
    return text


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.casefold().encode("utf-8")).hexdigest()[:24]


def _bluetooth_direction(hardware_id: str | None) -> BluetoothDirection:
    if not hardware_id:
        return BluetoothDirection.UNKNOWN
    upper = hardware_id.upper()
    remote = _bluetooth_remote_identity(hardware_id)
    if "_LOCALMFG&0000" in upper:
        return BluetoothDirection.INCOMING
    if remote is None:
        return BluetoothDirection.UNKNOWN
    if remote == "000000000000":
        return BluetoothDirection.INCOMING
    return BluetoothDirection.OUTGOING


def _bluetooth_remote_identity(hardware_id: str | None) -> str | None:
    if not hardware_id:
        return None
    match = re.search(r"&0&([0-9A-Fa-f]{12})(?:_|$)", hardware_id)
    return match.group(1).upper() if match else None


def _bluetooth_info(
    hardware_id: str | None,
    description: str | None,
    *,
    bluetooth_name: str | None = None,
) -> tuple[PortTransportKind, BluetoothDirection, str | None, str | None, str | None]:
    looks_bluetooth = bool(
        (hardware_id and "BTHENUM" in hardware_id.upper())
        or (description and ("蓝牙" in description or "bluetooth" in description.casefold()))
    )
    if not looks_bluetooth:
        return PortTransportKind.UNKNOWN, BluetoothDirection.UNKNOWN, None, None, None
    direction = _bluetooth_direction(hardware_id)
    remote = _bluetooth_remote_identity(hardware_id)
    if remote == "000000000000":
        remote = None
    pnp = hardware_id.casefold() if hardware_id else None
    return PortTransportKind.BLUETOOTH_SPP, direction, pnp, remote, bluetooth_name


def _adapter_identity(
    *, vid: int | None, pid: int | None, serial: str | None,
    location: str | None, hardware_id: str | None,
    transport_kind: PortTransportKind = PortTransportKind.UNKNOWN,
    pnp_instance_identity: str | None = None,
    description: str | None = None,
) -> tuple[str, IdentityQuality]:
    if transport_kind is PortTransportKind.BLUETOOTH_SPP:
        # A BTHENUM/PnP instance is useful for a manual, per-session binding,
        # but is not a verified stable hardware identity across re-pairing.
        basis = pnp_instance_identity or hardware_id or description or "bluetooth"
        return f"bluetooth-pnp:{_short_hash(basis)}", IdentityQuality.AMBIGUOUS
    usb = (
        f"{vid:04x}:{pid:04x}"
        if vid is not None and pid is not None
        else None
    )
    if usb is not None and serial is not None:
        return f"usb:{usb}:{serial}", IdentityQuality.STABLE
    if usb is not None and location is not None:
        return f"usb:{usb}:loc:{location}", IdentityQuality.AMBIGUOUS
    basis = location or hardware_id or "unknown-adapter"
    return f"ambiguous:{basis}", IdentityQuality.AMBIGUOUS


def _default_ports() -> tuple[Any, ...]:
    from serial.tools import list_ports  # type: ignore[import-untyped]

    return tuple(list_ports.comports())


def discover_serial_ports(
    enumerator: Callable[[], tuple[Any, ...]] | None = None,
    *,
    platform_name: str | None = None,
) -> SerialDiscovery:
    """Enumerate ports without opening or writing to any of them.

    ``enumerator`` is injectable solely for deterministic Windows tests and
    simulator/CI environments.  The production path uses pySerial's
    ``list_ports.comports()``.
    """
    platform = platform_name or sys.platform
    if platform != "win32":
        return SerialDiscovery(
            platform=platform,
            status=SerialPlatformStatus.UNSUPPORTED_PLATFORM,
            supported=False,
        )
    try:
        entries = (enumerator or _default_ports)()
    except Exception:
        return SerialDiscovery(
            platform=platform,
            status=SerialPlatformStatus.ENUMERATION_ERROR,
            supported=False,
            errors=("serial-enumeration-failed",),
        )

    ports: list[SerialPortInfo] = []
    errors: list[str] = []
    for entry in entries:
        port = _optional_text(_value(entry, "port")) or _optional_text(_value(entry, "device"))
        if port is None or _PORT_LABEL.fullmatch(port) is None:
            errors.append("invalid-port-entry")
            continue
        vid = _optional_int(_value(entry, "vid"))
        pid = _optional_int(_value(entry, "pid"))
        serial = _normalize_serial(_value(entry, "serial_number"))
        location = _optional_text(_value(entry, "location"))
        hardware_id = _optional_text(_value(entry, "hwid"))
        description = _optional_text(_value(entry, "description"))
        bt_kind, bt_direction, pnp, remote, bt_name = _bluetooth_info(
            hardware_id,
            description,
            bluetooth_name=_optional_text(_value(entry, "bluetooth_name")),
        )
        if bt_kind is PortTransportKind.BLUETOOTH_SPP:
            transport_kind = PortTransportKind.BLUETOOTH_SPP
        elif vid is not None and pid is not None:
            transport_kind = PortTransportKind.USB
        elif hardware_id and re.match(
            r"^(ACPI|PCI|PNP|ROOT)\\",
            hardware_id,
            re.IGNORECASE,
        ):
            transport_kind = PortTransportKind.NATIVE_SERIAL
        elif description and ("serial" in description.casefold() or "串行" in description):
            transport_kind = PortTransportKind.NATIVE_SERIAL
        else:
            transport_kind = PortTransportKind.UNKNOWN
        identity, quality = _adapter_identity(
            vid=vid, pid=pid, serial=serial, location=location,
            hardware_id=hardware_id,
            transport_kind=transport_kind,
            pnp_instance_identity=pnp,
            description=description,
        )
        ports.append(SerialPortInfo(
            port=port,
            description=description,
            hardware_id=hardware_id,
            vid=vid,
            pid=pid,
            serial_number=serial,
            manufacturer=_optional_text(_value(entry, "manufacturer")),
            location=location,
            interface=_optional_text(_value(entry, "interface")),
            adapter_identity=identity,
            identity_quality=quality,
            transport_kind=transport_kind,
            pnp_instance_identity=pnp,
            bluetooth_name=bt_name,
            bluetooth_direction=bt_direction,
            remote_bluetooth_identity=remote,
        ))

    counts = Counter(port.adapter_identity for port in ports)
    duplicate_ids = tuple(sorted(identity for identity, count in counts.items() if count > 1))
    duplicate_set = set(duplicate_ids)
    return SerialDiscovery(
        platform=platform,
        status=SerialPlatformStatus.SUPPORTED,
        supported=True,
        ports=tuple(
            port.model_copy(update={
                "duplicate_identity": port.adapter_identity in duplicate_set,
                "identity_quality": (
                    IdentityQuality.AMBIGUOUS
                    if port.adapter_identity in duplicate_set
                    else port.identity_quality
                ),
            })
            for port in ports
        ),
        duplicate_identities=duplicate_ids,
        errors=tuple(errors),
    )


__all__ = [
    "BluetoothDirection",
    "IdentityQuality",
    "PortTransportKind",
    "SerialDiscovery",
    "SerialPlatformStatus",
    "SerialPortInfo",
    "discover_serial_ports",
]
