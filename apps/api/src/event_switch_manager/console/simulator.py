"""Transcript-driven five-family console simulator.

Fixtures are synthetic or explicitly marked recorded fixtures.  They are never
presented as real device captures and cannot promote hardware verification.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from event_switch_manager.domain import DeviceFamily
from event_switch_manager.integrations import ConsoleQuery

from .allowlist import supported_queries
from .models import ConsoleSource
from .transport import TransportDisconnected


@dataclass(frozen=True, slots=True)
class SimulatedStackMember:
    number: int
    pid: str
    serial_number: str
    role: str
    state: str
    software_version: str


@dataclass(frozen=True, slots=True)
class SimulatorProfile:
    family: DeviceFamily
    hostname: str
    model: str
    serial_number: str
    software_version: str
    license_declared: str | None
    license_observed: str | None
    license_status: str | None
    license_next_boot: str | None
    interfaces: tuple[str, ...]
    stack: tuple[SimulatedStackMember, ...]
    boot_state: str | None
    storage: tuple[str, ...]
    source: ConsoleSource = ConsoleSource.SIMULATOR
    fixture_id: str = "synthetic"
    username: str = field(default="console", repr=False)
    password: str = field(default="synthetic-password", repr=False)
    enable_password: str | None = field(default="synthetic-enable", repr=False)

    def version_output(self) -> str:
        if self.family in {
            DeviceFamily.CATALYST_3850,
            DeviceFamily.CATALYST_9200,
            DeviceFamily.CATALYST_9300,
        }:
            release_line = "Cisco IOS XE Software, Version " + self.software_version
        else:
            release_line = (
                "Cisco IOS Software, " + self.model
                + " Software (UNIVERSALK9-M), Version " + self.software_version
                + ", RELEASE SOFTWARE"
            )
        license_line = (
            "License Level: " + self.license_declared + "\n"
            if self.license_declared else ""
        )
        return (
            release_line + "\n"
            "Copyright (c) 1986-2026 by Cisco Systems, Inc.\n"
            "cisco " + self.model + " (X86) processor, 1 processor\n"
            "Processor board ID " + self.serial_number + "\n"
            "Configuration register is 0x2102\n"
            + license_line
        )

    def inventory_output(self) -> str:
        return (
            'NAME: "Chassis", DESCR: "Cisco ' + self.model + '"\n'
            "PID: " + self.model + ", VID: V02, SN: " + self.serial_number + "\n"
        )

    def interfaces_output(self) -> str:
        has_paging = len(self.interfaces) > 8
        lines = [
            "Port      Name               Status       Vlan       Duplex  Speed Type",
            "----------------------------------------------",
        ]
        for index, interface in enumerate(self.interfaces):
            lines.append(
                f"{interface:<9} {'Access':<18} {'connected':<12} "
                "20         a-full  a-1000 10/100/1000BaseTX",
            )
            if has_paging and index == 4:
                lines.append("--More--")
        return "\n".join(lines) + "\n"

    def stack_output(self) -> str:
        lines = [
            "Switch  Role       Model           Serial       Version    State",
            "------  ---------  --------------  -----------  ---------  -------",
        ]
        for member in self.stack:
            lines.append(
                f"{member.number:<7} {member.role:<9} {member.pid:<15} "
                f"{member.serial_number:<12} {member.software_version:<9} {member.state}"
            )
        return "\n".join(lines) + "\n"

    def license_output(self) -> str:
        feature = (self.license_observed or "network-advantage").replace(" ", "-")
        return (
            "Index 1 Feature: " + feature + "\n"
            "License Type: Permanent\n"
            "License State: " + (self.license_status or "Active, In Use") + "\n"
            "Next reboot license level: " + (self.license_next_boot or feature) + "\n"
        )

    def boot_output(self) -> str:
        return "BOOT variable = " + (self.boot_state or "flash:imagestring.bin") + "\n"

    def storage_output(self) -> str:
        lines = ["File Systems:", "    flash:  ", "    nvram:  "]
        lines.extend("    " + item for item in self.storage)
        return "\n".join(lines) + "\n"

    def query_output(self, query: ConsoleQuery) -> str:
        if query is ConsoleQuery.VERSION:
            return self.version_output()
        if query is ConsoleQuery.INVENTORY:
            return self.inventory_output()
        if query is ConsoleQuery.INTERFACES:
            return self.interfaces_output()
        if query is ConsoleQuery.STACK:
            return self.stack_output()
        if query is ConsoleQuery.LICENSE:
            return self.license_output()
        if query is ConsoleQuery.BOOT:
            return self.boot_output()
        if query is ConsoleQuery.STORAGE:
            return self.storage_output()
        raise ValueError(f"unsupported simulator query: {query}")


def _member(
    number: int, pid: str, serial: str, role: str, version: str,
) -> SimulatedStackMember:
    return SimulatedStackMember(number, pid, serial, role, "Ready", version)


def profiles() -> tuple[SimulatorProfile, ...]:
    """Five synthetic profiles; no real serial or device identity is claimed."""
    return (
        SimulatorProfile(
            family=DeviceFamily.CATALYST_2960X,
            hostname="lab-2960x",
            model="WS-C2960X-24PS-L",
            serial_number="FIXTURE2960X01",
            software_version="15.2(7)E7",
            license_declared="LAN Base",
            license_observed=None,
            license_status=None,
            license_next_boot=None,
            interfaces=("Gi1/0/1", "Gi1/0/2", "Gi1/0/3"),
            stack=(
                _member(1, "WS-C2960X-24PS-L", "FIXTURE2960X01", "Active", "15.2(7)E7"),
                _member(2, "WS-C2960X-24PS-L", "FIXTURE2960X02", "Standby", "15.2(7)E7"),
            ),
            boot_state="flash:c2960x-universalk9-mz.152-7.E7.bin",
            storage=("flash:", "nvram:"),
            fixture_id="synthetic-2960x",
        ),
        SimulatorProfile(
            family=DeviceFamily.CATALYST_3850,
            hostname="lab-3850",
            model="WS-C3850-24P",
            serial_number="FIXTURE385001",
            software_version="16.12.12",
            license_declared="IP Base",
            license_observed="Network Advantage",
            license_status="Active, In Use",
            license_next_boot="Network Advantage",
            interfaces=("Gi1/0/1", "Gi1/0/2", "Gi1/0/3"),
            stack=(
                _member(1, "WS-C3850-24P", "FIXTURE385001", "Active", "16.12.12"),
                _member(2, "WS-C3850-24P", "FIXTURE385002", "Standby", "16.12.12"),
            ),
            boot_state="flash:cat3k_caa-universalk9.SPA.16.12.12.bin",
            storage=("flash:",),
            fixture_id="synthetic-3850",
        ),
        SimulatorProfile(
            family=DeviceFamily.CATALYST_9200,
            hostname="lab-9200",
            model="C9200L-24P-4X",
            serial_number="FIXTURE920001",
            software_version="17.12.4",
            license_declared="Network Advantage",
            license_observed="Network Advantage",
            license_status="Active, In Use",
            license_next_boot="Network Advantage",
            interfaces=("Gi1/0/1", "Gi1/0/2", "Gi1/0/3"),
            stack=(_member(1, "C9200L-24P-4X", "FIXTURE920001", "Active", "17.12.4"),),
            boot_state="flash:cat9k_lite_iosxe.17.12.04.SPA.bin",
            storage=("flash:",),
            fixture_id="synthetic-9200",
        ),
        SimulatorProfile(
            family=DeviceFamily.CATALYST_9300,
            hostname="lab-9300",
            model="C9300L-24P-4X",
            serial_number="FIXTURE930001",
            software_version="17.12.4",
            license_declared="Network Advantage",
            license_observed="Network Advantage",
            license_status="Active, In Use",
            license_next_boot="Network Advantage",
            interfaces=("Gi1/0/1", "Gi1/0/2", "Gi1/0/3"),
            stack=(
                _member(1, "C9300L-24P-4X", "FIXTURE930001", "Active", "17.12.4"),
                _member(2, "C9300L-24P-4X", "FIXTURE930002", "Standby", "17.12.4"),
            ),
            boot_state="flash:cat9k_iosxe.17.12.04.SPA.bin",
            storage=("flash:",),
            fixture_id="synthetic-9300",
        ),
        SimulatorProfile(
            family=DeviceFamily.CATALYST_C1000,
            hostname="lab-c1000",
            model="C1000-24P-4G-L",
            serial_number="FIXTUREC100001",
            software_version="15.2(7)E1",
            license_declared=None,
            license_observed=None,
            license_status=None,
            license_next_boot=None,
            interfaces=("Gi1/0/1", "Gi1/0/2", "Gi1/0/3"),
            stack=(),
            boot_state="flash:c1000-universalk9-mz.152-7.E1.bin",
            storage=("flash:",),
            fixture_id="synthetic-c1000",
        ),
    )


@dataclass(slots=True)
class SimulatedConsoleTransport:
    profile: SimulatorProfile = field(default_factory=lambda: profiles()[3])
    chunk_size: int = 17
    pagination: bool = True
    wrong_password: bool = False
    enable_failure: bool = False
    timeout_commands: frozenset[ConsoleQuery] = frozenset()
    disconnect_commands: frozenset[ConsoleQuery] = frozenset()
    error_commands: frozenset[ConsoleQuery] = frozenset()
    echo: bool = True
    _closed: bool = field(init=False, default=False)
    _queue: deque[str] = field(init=False, default_factory=deque)
    _stage: str = field(init=False, default="username")
    _paging_remaining: str | None = field(init=False, default=None)
    _paging_prompt: str | None = field(init=False, default=None)
    _last_command: str | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self.chunk_size = max(1, self.chunk_size)

    @property
    def port_identity(self) -> str:
        return "sim:" + self.profile.fixture_id

    @property
    def source(self) -> ConsoleSource:
        return self.profile.source

    @property
    def fixture_id(self) -> str:
        return self.profile.fixture_id

    @property
    def stage(self) -> str:
        return self._stage

    @property
    def is_open(self) -> bool:
        return not self._closed

    def _enqueue(self, text: str) -> None:
        for index in range(0, len(text), self.chunk_size):
            self._queue.append(text[index:index + self.chunk_size])

    def open(self) -> None:
        self._closed = False
        self._queue.clear()
        self._stage = "username"
        self._enqueue("Cisco console simulator fixture\nUsername: ")

    def close(self) -> None:
        self._closed = True
        self._queue.clear()

    def read_chunk(self, timeout: float) -> str:
        _ = timeout
        if self._closed:
            raise TransportDisconnected("simulated console disconnected")
        if not self._queue:
            time.sleep(0.001)
            return ""
        return self._queue.popleft()

    def write(self, text: str) -> None:
        if self._closed:
            raise TransportDisconnected("simulated console disconnected")
        value = text.rstrip("\r\n")
        if self._stage == "username":
            if value != self.profile.username:
                self._enqueue("% Authentication failed\nUsername: ")
                return
            self._stage = "password"
            self._enqueue("Password: ")
            return
        if self._stage == "password":
            if self.wrong_password or value != self.profile.password:
                self._stage = "username"
                self._enqueue("% Authentication failed\nUsername: ")
                return
            self._stage = "user-exec"
            self._enqueue(self.profile.hostname + ">\n")
            return
        if self._stage == "enable-password":
            if not self.enable_failure and value == self.profile.enable_password:
                self._stage = "privileged-exec"
                self._enqueue(self.profile.hostname + "#\n")
            else:
                self._enqueue("% Access denied\n" + self.profile.hostname + ">\n")
            return
        if self._stage == "paging":
            if value.strip() == "":
                self._stage = "command"
                if self._paging_remaining is not None:
                    self._enqueue(self._paging_remaining)
                if self._paging_prompt is not None:
                    self._enqueue(self._paging_prompt)
                self._paging_remaining = None
                self._paging_prompt = None
            return
        if self._stage not in {"user-exec", "privileged-exec"}:
            return
        if value == "enable" and self._stage == "user-exec":
            if self.profile.enable_password is None:
                self._stage = "privileged-exec"
                self._enqueue(self.profile.hostname + "#\n")
            else:
                self._stage = "enable-password"
                self._enqueue("Password: ")
            return
        self._handle_command(value)

    def _handle_command(self, value: str) -> None:
        prompt = self.profile.hostname + (
            "#\n" if self._stage == "privileged-exec" else ">\n"
        )
        query = _query_for_command(value, self.profile.family)
        self._last_command = value
        if query is not None and query in self.disconnect_commands:
            self.close()
            return
        if self.echo:
            self._enqueue(value + "\n")
        if query is None:
            self._enqueue("% Invalid input detected at '^' marker.\n" + prompt)
            return
        if query in self.timeout_commands:
            return
        if query in self.error_commands:
            self._enqueue("% Invalid input detected at '^' marker.\n" + prompt)
            return
        output = self.profile.query_output(query)
        if self.pagination and "--More--" in output:
            marker = output.index("--More--")
            first = output[:marker + len("--More--")] + "\n"
            remaining = output[marker + len("--More--"):].lstrip("\n") + prompt
            self._stage = "paging"
            self._paging_remaining = remaining
            self._paging_prompt = ""
            self._enqueue(first)
            return
        self._enqueue(output + prompt)


def _query_for_command(command: str, family: DeviceFamily) -> ConsoleQuery | None:
    for query in supported_queries(family):
        from .allowlist import resolve_query

        if resolve_query(family, query).command == command:
            return query
    return None


__all__ = [
    "SimulatedConsoleTransport",
    "SimulatedStackMember",
    "SimulatorProfile",
    "profiles",
]
