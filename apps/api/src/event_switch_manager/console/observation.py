"""Parse read-only console outputs into CON-01 observation evidence."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass

from event_switch_manager.domain import DeviceFamily
from event_switch_manager.integrations import ConsoleEngine, ConsoleQuery, SwitchObservation

from .allowlist import (
    QUERY_SPECS,
    ProfileNotVerified,
    resolve_profile,
    resolve_query,
    resolve_query_for_profile,
    supported_queries_for_profile,
)
from .models import (
    ConsoleEvidence,
    ConsoleInterface,
    ConsoleObservation,
    ConsoleQueryResult,
    ConsoleStackMember,
    LicenseFeature,
    LicenseObservation,
    ObservationCompleteness,
    QueryStatus,
    build_evidence,
)
from .redaction import redact_console_output
from .session import (
    ConsoleSession,
    ConsoleTimeout,
    DiscoveryCancelled,
    DiscoveryTimeout,
    UnexpectedAuthPrompt,
)

_MODEL = re.compile(r"(?im)^cisco\s+([A-Za-z0-9][A-Za-z0-9-]*)\s+\([^)]*\)\s+processor")
_VERSION = re.compile(
    r"(?im)^(?:Cisco IOS XE Software, Version|Cisco IOS Software.*?Version)"
    r"\s+([^\s,]+)",
)
_PID = re.compile(r"(?im)^PID:\s*([^,\s]+)")
_SERIAL = re.compile(r"(?im)^Processor board ID\s*([^\s,]+)")
_SERIAL_INVENTORY = re.compile(r"(?im)\bSN:\s*([^\s,]+)")
_INVENTORY_NAME = re.compile(r'(?im)^NAME:\s*"([^"]+)"')
_LICENSE_LEVEL = re.compile(r"(?im)^License Level:\s*([^\n]+)")
_LICENSE_BLOCK = re.compile(
    r"(?ims)^Index\s+\d+\s+Feature:\s*(\S+)(.*?)(?=^Index\s+\d+\s+Feature:|\Z)",
)
_LICENSE_TYPE = re.compile(r"(?im)^License Type:\s*([^\n]+)")
_LICENSE_STATE = re.compile(r"(?im)^License State:\s*([^\n]+)")
_LICENSE_NEXT = re.compile(r"(?im)^Next reboot license level:\s*([^\n]+)")
_BOOT = re.compile(r"(?im)^BOOT variable\s*=\s*([^;\n]+)")
_INTERFACE = re.compile(r"^(?P<name>(?:Gi|Te|Twe|Fa|Et)[A-Za-z0-9/.-]*)\s+(?P<rest>.*)$")
_STACK_ROW = re.compile(
    r"^(?P<number>\d+)\s+(?P<role>Active|Standby|Member|Unassigned)\s+"
    r"(?P<pid>\S+)\s+(?P<serial>\S+)\s+(?P<version>\S+)\s+(?P<state>\w+)$",
)


@dataclass(frozen=True, slots=True)
class _InventoryComponent:
    name: str
    pid: str | None
    serial: str | None


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


def _inventory_components(output: str) -> tuple[_InventoryComponent, ...]:
    components: list[_InventoryComponent] = []
    name: str | None = None
    pid: str | None = None
    serial: str | None = None

    def finish() -> None:
        nonlocal name, pid, serial
        if name is not None:
            components.append(_InventoryComponent(name, pid, serial))
        name, pid, serial = None, None, None

    for line in output.splitlines():
        stripped = line.strip()
        name_match = _INVENTORY_NAME.match(stripped)
        if name_match is not None:
            finish()
            name = name_match.group(1)
            continue
        if name is None:
            continue
        serial_match = _SERIAL_INVENTORY.search(stripped)
        if serial_match is not None and serial is None:
            serial = serial_match.group(1)
        pid_match = _PID.match(stripped)
        if pid_match is not None and pid is None:
            pid = pid_match.group(1)
    finish()
    return tuple(components)


def _chassis_inventory(output: str) -> tuple[str | None, str | None, tuple[str, ...]]:
    components = _inventory_components(output)
    chassis = [
        item for item in components
        if "chassis" in item.name.casefold()
        and "member" not in item.name.casefold()
    ]
    if len(chassis) == 1:
        return chassis[0].pid, chassis[0].serial, ()
    if len(chassis) > 1:
        raise IdentityConflict("multiple chassis components in inventory")
    if len(components) == 1:
        return components[0].pid, components[0].serial, ()
    return None, None, ("inventory-chassis-missing",)


def _license_info(version_output: str, license_output: str | None) -> LicenseObservation:
    declared = _first(_LICENSE_LEVEL, version_output)
    features: list[LicenseFeature] = []
    issues: list[str] = []
    if license_output is not None:
        for match in _LICENSE_BLOCK.finditer(license_output):
            raw_feature = match.group(1).strip()
            block = match.group(2)
            feature = raw_feature.replace("-", " ").title()
            license_type = _first(_LICENSE_TYPE, block)
            status = _first(_LICENSE_STATE, block)
            next_boot = _first(_LICENSE_NEXT, block)
            features.append(LicenseFeature(
                feature=feature,
                license_type=license_type,
                status=status,
                next_boot=next_boot,
            ))
        if not features:
            issues.append("license-feature-missing")
    observed = ", ".join(feature.feature for feature in features) or None
    statuses = [
        feature.status for feature in features if feature.status is not None
    ]
    types = [
        feature.license_type for feature in features if feature.license_type is not None
    ]
    next_boot = next(
        (feature.next_boot for feature in features if feature.next_boot is not None),
        None,
    )
    status = "; ".join(types + statuses) or None
    ambiguous = bool(
        declared and observed and declared.casefold() not in observed.casefold()
    )
    return LicenseObservation(
        declared=declared,
        observed=observed,
        next_boot=next_boot,
        status=status,
        features=tuple(features),
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
        stripped = line.strip()
        match = _STACK_ROW.match(stripped)
        if match is None:
            if re.match(r"^\d+\s+", stripped):
                raise IdentityConflict("malformed stack member row")
            continue
        values.append(ConsoleStackMember(
            number=int(match.group("number")),
            exact_pid=match.group("pid"),
            serial_number=match.group("serial"),
            role=match.group("role"),
            state=match.group("state"),
            software_version=match.group("version"),
        ))
    numbers = [item.number for item in values]
    serials = [
        item.serial_number.casefold()
        for item in values if item.serial_number is not None
    ]
    if len(numbers) != len(set(numbers)):
        raise IdentityConflict("duplicate stack member number")
    if len(serials) != len(set(serials)):
        raise IdentityConflict("duplicate stack member serial")
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


def _failure_status(exc: Exception) -> QueryStatus:
    if isinstance(exc, ConsoleTimeout):
        return QueryStatus.TIMEOUT
    if isinstance(exc, UnexpectedAuthPrompt):
        return QueryStatus.INCOMPLETE
    return QueryStatus.FAILED


def _failed_result(
    query: ConsoleQuery,
    command: str,
    status: QueryStatus,
) -> ConsoleQueryResult:
    return ConsoleQueryResult(
        query=query,
        command=command,
        status=status,
        output="",
        unknown_fields=("console-query-failed",),
    )


def _incomplete_evidence(
    session: ConsoleSession,
    results: tuple[ConsoleQueryResult, ...],
    reason: str,
) -> ConsoleEvidence:
    observation = ConsoleObservation(
        source=session.source,
        session_identity=session.session_identity,
        port_identity=session.port_identity,
        unknown_fields=(reason,),
        completeness=ObservationCompleteness.INCOMPLETE,
    )
    return build_evidence(
        observation,
        results,
        fixture_id=session.fixture_id,
    )


class CiscoObservationAdapter:
    """Read-only adapter from a typed ConsoleQuery session to observations."""

    def observe(
        self,
        session: ConsoleSession,
        *,
        deadline_seconds: float = 30.0,
        cancel_event: threading.Event | None = None,
    ) -> ConsoleEvidence:
        session.start_discovery(
            deadline_seconds=deadline_seconds,
            cancel_event=cancel_event,
        )
        try:
            return self._observe(session)
        finally:
            session.end_discovery()

    def _observe(self, session: ConsoleSession) -> ConsoleEvidence:
        results: list[ConsoleQueryResult] = []
        bootstrap_commands = {
            query: resolve_query(None, query).command
            for query in (ConsoleQuery.VERSION, ConsoleQuery.INVENTORY)
        }
        try:
            version_result = session.query_result(ConsoleQuery.VERSION)
            results.append(version_result)
            inventory_result = session.query_result(ConsoleQuery.INVENTORY)
            results.append(inventory_result)
        except (DiscoveryCancelled, DiscoveryTimeout):
            raise
        except Exception as exc:
            status = _failure_status(exc)
            failed = _failed_result(
                ConsoleQuery.VERSION
                if not results
                else ConsoleQuery.INVENTORY,
                bootstrap_commands[
                    ConsoleQuery.VERSION
                    if not results
                    else ConsoleQuery.INVENTORY
                ],
                status,
            )
            return _incomplete_evidence(
                session, (*results, failed), "bootstrap-query-failed",
            )

        version_output = version_result.output
        inventory_output = inventory_result.output
        version_model = _first(_MODEL, version_output)
        inventory_pid, inventory_serial, inventory_issues = _chassis_inventory(
            inventory_output,
        )
        exact_pid = inventory_pid or version_model
        if (
            version_model is not None
            and inventory_pid is not None
            and version_model.upper() != inventory_pid.upper()
        ):
            raise IdentityConflict("console identity fields conflict")
        version_serial = _first(_SERIAL, version_output)
        if (
            version_serial is not None
            and inventory_serial is not None
            and version_serial.casefold() != inventory_serial.casefold()
        ):
            raise IdentityConflict("version and inventory serials conflict")
        family = _family(exact_pid)
        software_version = _first(_VERSION, version_output)
        profile = None
        if exact_pid is not None and software_version is not None:
            try:
                profile = resolve_profile(exact_pid, software_version)
            except ProfileNotVerified:
                profile = None
        if profile is not None:
            session.set_profile(profile)
        unknown: list[str] = list(inventory_issues)
        serial = inventory_serial or version_serial
        if exact_pid is None:
            unknown.append("exact-pid")
        if serial is None:
            unknown.append("serial")
        if software_version is None:
            unknown.append("software-version")
        if family is None:
            unknown.append("family")
        if profile is None:
            unknown.append("exact-profile")

        license_output: str | None = None
        interfaces_output: str | None = None
        stack_output: str | None = None
        boot_output: str | None = None
        storage_output: str | None = None
        unsupported: list[ConsoleQuery] = []
        failed_query = False
        if profile is not None:
            for query in supported_queries_for_profile(profile):
                if query in {ConsoleQuery.VERSION, ConsoleQuery.INVENTORY}:
                    continue
                try:
                    result = session.query_result(query)
                except (DiscoveryCancelled, DiscoveryTimeout):
                    raise
                except Exception as exc:
                    spec = resolve_query_for_profile(profile, query)
                    results.append(_failed_result(query, spec.command, _failure_status(exc)))
                    unknown.append(query.value)
                    failed_query = True
                    break
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
            unsupported = [
                query for query in QUERY_SPECS[profile.family]
                if query not in supported_queries_for_profile(profile)
            ]
        else:
            unknown.extend(("license", "interfaces", "stack", "boot", "storage"))

        license_info = _license_info(version_output, license_output)
        if license_output is not None and not license_info.features:
            unknown.append("license-feature-missing")
        if license_info.ambiguous:
            unknown.append("license-declared-observed-mismatch")
        interfaces = _interfaces(interfaces_output)
        stack = _stack(stack_output)
        boot_state = _first(_BOOT, boot_output or "")
        storage = _storage(storage_output)
        if profile is not None:
            supported = set(supported_queries_for_profile(profile))
            if ConsoleQuery.INTERFACES in supported and not interfaces:
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
            ObservationCompleteness.INCOMPLETE
            if family is None
            else ObservationCompleteness.PARTIAL
            if failed_query or unknown or profile is None
            else ObservationCompleteness.COMPLETE
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
            unsupported_queries=tuple(unsupported),
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
