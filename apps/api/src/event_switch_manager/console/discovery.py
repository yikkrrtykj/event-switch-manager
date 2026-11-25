"""Read-only Windows COM port discovery.

Discovery calls the operating-system enumerator only.  It never opens a port,
never writes bytes and never treats a dynamic COM number as a permanent
hardware identity.
"""

from __future__ import annotations

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

    @property
    def usb(self) -> bool:
        return self.vid is not None and self.pid is not None


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


def _adapter_identity(
    *, vid: int | None, pid: int | None, serial: str | None,
    location: str | None, hardware_id: str | None,
) -> tuple[str, IdentityQuality]:
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
        identity, quality = _adapter_identity(
            vid=vid, pid=pid, serial=serial, location=location,
            hardware_id=hardware_id,
        )
        ports.append(SerialPortInfo(
            port=port,
            description=_optional_text(_value(entry, "description")),
            hardware_id=hardware_id,
            vid=vid,
            pid=pid,
            serial_number=serial,
            manufacturer=_optional_text(_value(entry, "manufacturer")),
            location=location,
            interface=_optional_text(_value(entry, "interface")),
            adapter_identity=identity,
            identity_quality=quality,
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
    "IdentityQuality",
    "SerialDiscovery",
    "SerialPlatformStatus",
    "SerialPortInfo",
    "discover_serial_ports",
]
