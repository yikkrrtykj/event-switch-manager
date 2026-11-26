"""Authorized, bounded real-serial transport for the isolated ConsoleLab."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import Any

from event_switch_manager.console.discovery import (
    SerialDiscovery,
    SerialPortInfo,
    discover_serial_ports,
)
from event_switch_manager.console.lease import OS_EXCLUSIVITY_STATUS
from event_switch_manager.console.session import ConsoleSendOperation, SessionState
from event_switch_manager.console.transport import (
    SerialParameters,
    TransportDisconnected,
    TransportError,
)
from event_switch_manager.integrations import ConsoleQuery

from .authorization import LabAuthorization, LabAuthorizationError
from .targets import LAB_SOURCE

MAX_READ_BYTES = 4096
MAX_WRITE_BYTES = 4096
DTR_RTS_BEHAVIOR = "NOT_VERIFIED"
BREAK_SUPPORT = "DISABLED"

SerialFactory = Callable[[str, SerialParameters], Any]
DiscoveryFactory = Callable[[], SerialDiscovery]


def _pyserial_factory(port: str, parameters: SerialParameters) -> Any:
    from serial import Serial  # type: ignore[import-untyped]

    kwargs: dict[str, Any] = {
        "baudrate": parameters.baudrate,
        "bytesize": parameters.data_bits,
        "parity": parameters.parity,
        "stopbits": parameters.stop_bits,
        "timeout": parameters.read_timeout_seconds,
        "write_timeout": parameters.write_timeout_seconds,
        "xonxoff": parameters.flow_control == "xonxoff",
        "rtscts": parameters.flow_control == "rtscts",
        "dsrdtr": False,
    }
    # Windows serial handles are exclusive by default.  pySerial's explicit
    # exclusive flag is POSIX-only and is not used to claim Windows OS-level
    # exclusivity before the H1 experiment.
    if os.name != "nt":
        kwargs["exclusive"] = True
    return Serial(port, **kwargs)


class AuthorizedSerialTransport:
    """Serial transport requiring a one-shot lab authorization."""

    source = LAB_SOURCE
    os_exclusive_access = OS_EXCLUSIVITY_STATUS

    def __init__(
        self,
        authorization: LabAuthorization,
        *,
        parameters: SerialParameters | None = None,
        discovery: DiscoveryFactory | None = None,
        serial_factory: SerialFactory | None = None,
        max_read_bytes: int = MAX_READ_BYTES,
    ) -> None:
        if not 0 < max_read_bytes <= 65536:
            raise ValueError("max_read_bytes must be in (0, 65536]")
        self._authorization = authorization
        self._parameters = parameters or SerialParameters()
        self._discovery = discovery or discover_serial_ports
        self._serial_factory = serial_factory or _pyserial_factory
        self._max_read_bytes = max_read_bytes
        self._port: SerialPortInfo | None = None
        self._serial: Any = None
        self._is_open = False
        self._cleanup_required = False
        self._ever_opened = False
        self._write_token: object | None = None
        self._write_state_provider: object | None = None

    @property
    def authorization(self) -> LabAuthorization:
        return self._authorization

    @property
    def selected_port(self) -> SerialPortInfo | None:
        return self._port

    @property
    def port_identity(self) -> str:
        return self._authorization.adapter_identity

    @property
    def lease_endpoint(self) -> str:
        return self._authorization.com_endpoint

    @property
    def identity_quality(self) -> str:
        return "stable"

    @property
    def is_open(self) -> bool:
        return self._is_open

    @property
    def ever_opened(self) -> bool:
        return self._ever_opened

    def bind_write_token(self, token: object, state_provider: object | None = None) -> None:
        self._write_token = token
        self._write_state_provider = state_provider

    @property
    def cleanup_required(self) -> bool:
        return self._cleanup_required

    def pending_data(self) -> bool:
        if not self._is_open or self._serial is None or self._cleanup_required:
            return False
        try:
            return bool(self._serial.in_waiting)
        except Exception as exc:
            raise TransportError("lab-serial-status-failed") from exc

    def open(self) -> None:
        if self._is_open or self._serial is not None or self._cleanup_required:
            raise TransportError("lab serial transport is already open or dirty")
        try:
            discovery = self._discovery()
        except Exception as exc:
            raise TransportError("lab-serial-enumeration-failed") from exc
        if not discovery.supported:
            raise TransportError("lab-serial-platform-unsupported")
        endpoint = self._authorization.com_endpoint.casefold()
        matches = [
            port for port in discovery.ports
            if port.port.casefold() == endpoint
        ]
        if len(matches) != 1:
            raise LabAuthorizationError("authorized COM endpoint is not uniquely enumerated")
        port = matches[0]
        self._authorization.check_port(port)
        self._authorization.consume_for_open(port)
        self._port = port
        try:
            serial_port = self._serial_factory(port.port, self._parameters)
        except Exception as exc:
            raise TransportError("lab-serial-open-failed") from exc
        self._serial = serial_port
        self._is_open = True
        self._ever_opened = True
        self._authorization.bind_transport(self)

    def close(self) -> None:
        serial_port = self._serial
        if serial_port is None:
            self._is_open = False
            self._cleanup_required = False
            return
        try:
            serial_port.close()
        except Exception as exc:
            self._cleanup_required = True
            self._is_open = True
            raise TransportError("lab-serial-close-failed") from exc
        self._serial = None
        self._is_open = False
        self._cleanup_required = False
        self._authorization.cancel()

    def write(self, text: str) -> None:
        _ = text
        raise TransportError(
            "raw lab write is disabled; use an authorized send operation",
        )

    def write_authorized(
        self,
        text: str,
        *,
        operation: ConsoleSendOperation,
        query: ConsoleQuery | None = None,
        session_token: object | None = None,
    ) -> None:
        if not self._is_open or self._serial is None or self._cleanup_required:
            raise TransportDisconnected("lab serial transport is not open")
        if self._write_token is None or session_token is not self._write_token:
            raise TransportError("lab send requires a bound session capability")
        if operation in {
            ConsoleSendOperation.USERNAME,
            ConsoleSendOperation.PASSWORD,
            ConsoleSendOperation.ENABLE,
            ConsoleSendOperation.ENABLE_PASSWORD,
        }:
            provider = self._write_state_provider
            state = provider() if callable(provider) else None
            if state is not SessionState.AUTHENTICATING:
                raise TransportError("credential send outside authenticated state")
        self._authorization.authorize_send(operation, text, query)
        if not text:
            return
        try:
            payload = text.encode("ascii")
        except UnicodeEncodeError as exc:
            raise TransportError("lab-serial-write-encoding-failed") from exc
        if len(payload) > MAX_WRITE_BYTES:
            raise TransportError("lab-serial-write-bound-exceeded")
        deadline = time.monotonic() + self._parameters.write_timeout_seconds
        sent = 0
        while sent < len(payload):
            # Expiry/cancellation is re-checked before every partial chunk so
            # no remaining bytes are written after authorization is revoked.
            self._authorization.check_active()
            if time.monotonic() >= deadline:
                raise TransportError("lab-serial-write-timeout")
            try:
                count = self._serial.write(payload[sent:])
            except Exception as exc:
                raise TransportError("lab-serial-write-failed") from exc
            if not isinstance(count, int) or count <= 0:
                raise TransportError("lab-serial-partial-write")
            sent += count

    def read_chunk(self, timeout: float) -> str:
        if not self._is_open or self._serial is None or self._cleanup_required:
            raise TransportDisconnected("lab serial transport is not open")
        if not 0 < timeout <= 30:
            raise ValueError("read timeout must be in (0, 30] seconds")
        try:
            self._serial.timeout = timeout
            waiting = int(getattr(self._serial, "in_waiting", 0) or 0)
            count = min(self._max_read_bytes, max(1, waiting))
            data = self._serial.read(count)
        except Exception as exc:
            raise TransportError("lab-serial-read-failed") from exc
        if not data:
            return ""
        return str(data.decode("ascii", errors="replace"))


def lab_serial_safety_flags() -> dict[str, str]:
    return {
        "os_exclusive_access": OS_EXCLUSIVITY_STATUS,
        "dtr_rts_behavior": DTR_RTS_BEHAVIOR,
        "break_support": BREAK_SUPPORT,
    }


__all__ = [
    "AuthorizedSerialTransport",
    "BREAK_SUPPORT",
    "DTR_RTS_BEHAVIOR",
    "MAX_READ_BYTES",
    "SerialFactory",
    "lab_serial_safety_flags",
]
