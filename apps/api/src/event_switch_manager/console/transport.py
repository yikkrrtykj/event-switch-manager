"""Console transport abstraction and a deliberately disabled live serial adapter."""

from __future__ import annotations

from typing import Any, Literal, Protocol

from pydantic import field_validator

from ..planning.types import Record
from .discovery import SerialPortInfo
from .lease import OS_EXCLUSIVITY_STATUS
from .models import ConsoleSource


class TransportError(RuntimeError):
    """Base class for safe console transport errors."""


class TransportTimeout(TransportError):
    """The peer did not produce data within the bounded read window."""


class TransportDisconnected(TransportError):
    """The transport was closed or the peer disconnected."""


class LiveSerialDisabled(TransportError):
    """The live serial adapter is disabled in CON-01."""


class SerialParameters(Record):
    """Explicit Cisco console parameters; no device-wide assumption is implied."""

    baudrate: int = 9600
    data_bits: int = 8
    parity: Literal["N", "E", "O"] = "N"
    stop_bits: int = 1
    flow_control: Literal["none", "xonxoff", "rtscts"] = "none"
    read_timeout_seconds: float = 1.0
    write_timeout_seconds: float = 1.0

    @field_validator("baudrate", "data_bits", "stop_bits")
    @classmethod
    def _positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("serial parameters must be positive")
        return value

    @field_validator("read_timeout_seconds", "write_timeout_seconds")
    @classmethod
    def _bounded_timeout(cls, value: float) -> float:
        if not 0 < value <= 30:
            raise ValueError("serial timeout must be in (0, 30] seconds")
        return value


class ConsoleTransport(Protocol):
    """Minimal transport contract used by the read-only session."""

    @property
    def port_identity(self) -> str | None: ...

    @property
    def source(self) -> ConsoleSource: ...

    def open(self) -> None: ...

    def close(self) -> None: ...

    def write(self, text: str) -> None: ...

    def read_chunk(self, timeout: float) -> str: ...


class SerialTransport:
    """Real adapter that cannot open a port unless a live experiment opts in.

    CON-01 has no product API, launcher or UI path that can pass
    ``allow_live=True``.  The class is kept so the future transport can be
    reviewed without inventing a parallel abstraction.
    """

    source = ConsoleSource.LIVE_DEVICE
    os_exclusive_access = OS_EXCLUSIVITY_STATUS

    def __init__(
        self,
        port: SerialPortInfo,
        parameters: SerialParameters | None = None,
        *,
        allow_live: bool = False,
    ) -> None:
        self._port = port
        self._parameters = parameters or SerialParameters()
        self._allow_live = allow_live
        self._serial: Any = None
        self._is_open = False

    @property
    def port_identity(self) -> str:
        return self._port.adapter_identity

    @property
    def is_open(self) -> bool:
        return self._is_open

    def open(self) -> None:
        if not self._allow_live:
            raise LiveSerialDisabled(
                "live serial is disabled for CON-01; use simulator/recorded fixtures",
            )
        from serial import Serial  # type: ignore[import-untyped]

        flow = self._parameters.flow_control
        self._serial = Serial(
            self._port.port,
            baudrate=self._parameters.baudrate,
            bytesize=self._parameters.data_bits,
            parity=self._parameters.parity,
            stopbits=self._parameters.stop_bits,
            timeout=self._parameters.read_timeout_seconds,
            write_timeout=self._parameters.write_timeout_seconds,
            xonxoff=flow == "xonxoff",
            rtscts=flow == "rtscts",
            dsrdtr=False,
        )
        self._is_open = True

    def close(self) -> None:
        serial_port = self._serial
        self._serial = None
        self._is_open = False
        if serial_port is not None:
            serial_port.close()

    def write(self, text: str) -> None:
        if not self._is_open or self._serial is None:
            raise TransportDisconnected("serial transport is not open")
        if not text:
            return
        # No BREAK, DTR/RTS toggle, reload or arbitrary escape sequence is sent.
        self._serial.write(text.encode("ascii"))

    def read_chunk(self, timeout: float) -> str:
        if not self._is_open or self._serial is None:
            raise TransportDisconnected("serial transport is not open")
        if not 0 < timeout <= 30:
            raise ValueError("read timeout must be in (0, 30] seconds")
        self._serial.timeout = timeout
        data = self._serial.read(max(1, self._serial.in_waiting or 1))
        if not data:
            return ""
        return str(data.decode("ascii", errors="replace"))


__all__ = [
    "ConsoleTransport",
    "LiveSerialDisabled",
    "SerialParameters",
    "SerialTransport",
    "TransportDisconnected",
    "TransportError",
    "TransportTimeout",
]
