"""Parse read-only console outputs into CON-01 observation evidence."""

from __future__ import annotations

import re

from event_switch_manager.domain import DeviceFamily
from event_switch_manager.integrations import ConsoleEngine, ConsoleQuery, SwitchObservation

from .allowlist import supported_queries
from .models import (
    ConsoleEvidence,
    ConsoleInterface,
    ConsoleObservation,
    ConsoleQueryResult,
    ConsoleStackMember,
    LicenseObservation,
    ObservationCompleteness,
    QueryStatus,
    build_evidence,
)
from .redaction import redact_console_output
from .session import ConsoleSession

_MODEL = re.compile(r"(?im)^cisco\s+([A-Za-z0-9][A-Za-z0-9-]*)\s+\([^)]*\)\s+processor")
_VERSION = re.compile(
    r"(?im)^(?:Cisco IOS XE Software, Version|Cisco IOS Software.*?Version)"
    r"\s+([^\s,]+)",
)
_PID = re.compile(r"(?im)^PID:\s*([^,\s]+)")
_SERIAL = re.compile(r"(?im)^Processor board ID\s*([^\s,]+)")
_SERIAL_INVENTORY = re.compile(r"(?im)\bSN:\s*([^\s,]+)")
_LICENSE_LEVEL = re.compile(r"(?im)^License Level:\s*([^\n]+)")
_LICENSE_FEATURE = re.compile(r"(?im)^Index\s+\d+\s+Feature:\s*(\S+)")
_LICENSE_TYPE = re.compile(r"(?im)^License Type:\s*([^\n]+)")
_LICENSE_STATE = re.compile(r"(?im)^License State:\s*([^\n]+)")
_LICENSE_NEXT = re.compile(r"(?im)^Next reboot license level:\s*([^\n]+)")
_BOOT = re.compile(r"(?im)^BOOT variable\s*=\s*([^;\n]+)")
_INTERFACE = re.compile(r"^(?P<name>(?:Gi|Te|Twe|Fa|Et)[A-Za-z0-9/.-]*)\s+(?P<rest>.*)$")
_STACK_ROW = re.compile(
    r"^(?P<number>\d+)\s+(?P<role>Active|Standby|Member|Unassigned)\s+"
    r"(?P<pid>\S+)\s+(?P<serial>\S+)\s+(?P<version>\S+)\s+(?P<state>\w+)$",
)


class ObservationError(RuntimeError):
    pass


class IdentityConflict(ObservationError):
    pass


def _first(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _family(pid: str | None) -> DeviceFamily | None:
    if pid is None:
        return None
    upper = pid.upper()
    for prefix, family in (
        ("WS-C2960X", DeviceFamily.CATALYST_2960X),
        ("WS-C3850", DeviceFamily.CATALYST_3850),
        ("C9200", DeviceFamily.CATALYST_9200),
        ("C9300", DeviceFamily.CATALYST_9300),
        ("C1000", DeviceFamily.CATALYST_C1000),
    ):
        if upper.startswith(prefix):
            return family
    return None


def _license_info(version_output: str, license_output: str | None) -> LicenseObservation:
    declared = _first(_LICENSE_LEVEL, version_output)
    observed = None
    next_boot = None
    status = None
    if license_output is not None:
        observed = _first(_LICENSE_FEATURE, license_output)
        if observed is not None:
            observed = observed.replace("-", " ").title()
        next_boot = _first(_LICENSE_NEXT, license_output)
        status = _first(_LICENSE_STATE, license_output)
        license_type = _first(_LICENSE_TYPE, license_output)
        if license_type is not None:
            status = f"{license_type}; {status}" if status else license_type
    ambiguous = bool(
        declared and observed and declared.casefold() != observed.casefold()
    )
    return LicenseObservation(
        declared=declared,
        observed=observed,
        next_boot=next_boot,
        status=status,
        ambiguous=ambiguous,
    )


def _interfaces(output: str | None) -> tuple[ConsoleInterface, ...]:
    if output is None:
        return ()
    values: dict[str, ConsoleInterface] = {}
    for line in output.splitlines():
        match = _INTERFACE.match(line.strip())
        if match is None:
            continue
        name = match.group("name")
        if name in {"Port", "Switch", "Interface"}:
            continue
        rest = match.group("rest")
        status = next(
            (part for part in rest.split() if part.lower() in {
                "connected", "notconnect", "disabled", "err-disabled",
                "monitoring", "suspended", "down",
            }),
            None,
        )
        values.setdefault(name, ConsoleInterface(name=name, status=status))
    return tuple(values.values())


def _stack(output: str | None) -> tuple[ConsoleStackMember, ...]:
    if output is None:
        return ()
    values: list[ConsoleStackMember] = []
    for line in output.splitlines():
        match = _STACK_ROW.match(line.strip())
        if match is None:
            continue
        values.append(ConsoleStackMember(
            number=int(match.group("number")),
            exact_pid=match.group("pid"),
            serial_number=match.group("serial"),
            role=match.group("role"),
            state=match.group("state"),
            software_version=match.group("version"),
        ))
    return tuple(values)


def _storage(output: str | None) -> tuple[str, ...]:
    if output is None:
        return ()
    values: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(("flash:", "bootflash:", "nvram:", "usbflash")):
            values.append(stripped)
    return tuple(dict.fromkeys(values))


def _result_text(results: tuple[ConsoleQueryResult, ...], query: ConsoleQuery) -> str | None:
    return next(
        (item.output for item in results if item.query is query and item.status is QueryStatus.OK),
        None,
    )


class CiscoObservationAdapter:
    """Read-only adapter from a typed ConsoleQuery session to observations."""

    def observe(self, session: ConsoleSession) -> ConsoleEvidence:
        results: list[ConsoleQueryResult] = []
        version_result = session.query_result(ConsoleQuery.VERSION)
        results.append(version_result)
        inventory_result = session.query_result(ConsoleQuery.INVENTORY)
        results.append(inventory_result)
        version_output = version_result.output
        inventory_output = inventory_result.output

        version_model = _first(_MODEL, version_output)
        inventory_pid = _first(_PID, inventory_output)
        exact_pid = inventory_pid or version_model
        if (
            version_model is not None
            and inventory_pid is not None
            and version_model.upper() != inventory_pid.upper()
        ):
            raise IdentityConflict("console identity fields conflict")
        family = _family(exact_pid)
        if family is not None:
            session.set_family(family)
        unknown: list[str] = []
        serial = (
            _first(_SERIAL, version_output)
            or _first(_SERIAL_INVENTORY, inventory_output)
        )
        software_version = _first(_VERSION, version_output)
        if exact_pid is None:
            unknown.append("exact-pid")
        if serial is None:
            unknown.append("serial")
        if software_version is None:
            unknown.append("software-version")
        if family is None:
            unknown.append("family")

        license_output: str | None = None
        interfaces_output: str | None = None
        stack_output: str | None = None
        boot_output: str | None = None
        storage_output: str | None = None
        if family is not None:
            for query in supported_queries(family):
                if query in {ConsoleQuery.VERSION, ConsoleQuery.INVENTORY}:
                    continue
                result = session.query_result(query)
                results.append(result)
                if query is ConsoleQuery.LICENSE:
                    license_output = result.output
                elif query is ConsoleQuery.INTERFACES:
                    interfaces_output = result.output
                elif query is ConsoleQuery.STACK:
                    stack_output = result.output
                elif query is ConsoleQuery.BOOT:
                    boot_output = result.output
                elif query is ConsoleQuery.STORAGE:
                    storage_output = result.output
        else:
            unknown.extend(("license", "interfaces", "stack", "boot", "storage"))

        license_info = _license_info(version_output, license_output)
        interfaces = _interfaces(interfaces_output)
        stack = _stack(stack_output)
        boot_state = _first(_BOOT, boot_output or "")
        storage = _storage(storage_output)
        if family is not None:
            if ConsoleQuery.INTERFACES in supported_queries(family) and not interfaces:
                unknown.append("interfaces")
            if family in {
                DeviceFamily.CATALYST_2960X,
                DeviceFamily.CATALYST_3850,
                DeviceFamily.CATALYST_9200,
                DeviceFamily.CATALYST_9300,
            } and not stack:
                unknown.append("stack")
            if family in {
                DeviceFamily.CATALYST_3850,
                DeviceFamily.CATALYST_9200,
                DeviceFamily.CATALYST_9300,
            }:
                if boot_state is None:
                    unknown.append("boot")
                if not storage:
                    unknown.append("storage")
            if family in {
                DeviceFamily.CATALYST_2960X,
                DeviceFamily.CATALYST_C1000,
            }:
                # These IOS queries are intentionally unsupported in R82.
                unknown.extend(("license-query-unsupported", "boot", "storage"))
        completeness = (
            ObservationCompleteness.COMPLETE
            if not unknown and family is not None
            else ObservationCompleteness.PARTIAL
            if family is not None
            else ObservationCompleteness.INCOMPLETE
        )
        observation = ConsoleObservation(
            source=session.source,
            session_identity=session.session_identity,
            port_identity=session.port_identity,
            family=family,
            hardware_model=exact_pid,
            ordering_sku=None,
            exact_pid=exact_pid,
            serial_number=serial,
            software_version=software_version,
            license=license_info,
            interfaces=interfaces,
            stack=stack,
            boot_state=boot_state,
            storage=storage,
            unknown_fields=tuple(sorted(set(unknown))),
            completeness=completeness,
        )
        return build_evidence(
            observation,
            tuple(results),
            fixture_id=session.fixture_id,
        )

    def discover(self, console: ConsoleEngine) -> SwitchObservation:
        if not isinstance(console, ConsoleSession):
            raise ObservationError("CON-01 discovery requires a ConsoleSession")
        return self.observe(console).observation.to_switch_observation()


__all__ = [
    "CiscoObservationAdapter",
    "IdentityConflict",
    "ObservationError",
    "redact_console_output",
]
