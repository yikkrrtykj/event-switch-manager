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
    ConsoleBootEntry,
    ConsoleEvidence,
    ConsoleInterface,
    ConsoleInventoryMember,
    ConsoleObservation,
    ConsoleQueryResult,
    ConsoleStackMember,
    ConsoleStorageEntry,
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
_LICENSE_LIFE = re.compile(r"(?im)^License (?:Life|Term)\s*:\s*([^\n]+)")
_LICENSE_NEXT = re.compile(r"(?im)^Next reboot license level:\s*([^\n]+)")
_BOOT = re.compile(r"(?im)^BOOT variable\s*=\s*([^;\n]+)")
_BOOT_MEMBER = re.compile(r"(?im)^Switch\s+(\d+)\s*$")
_BOOT_FIELD = re.compile(
    r"(?im)^(BOOT variable|CONFIG_FILE variable|PRIVATE_CONFIG_FILE variable|"
    r"Manual Boot|Enable Break)\s*=\s*([^\n]*)",
)
_INTERFACE = re.compile(
    r"^(?P<name>(?:Gi|Te|Twe|Fa|Et|Po|Vl|Lo|Nu)[A-Za-z0-9/.-]*)\s+(?P<rest>.*)$",
    re.IGNORECASE,
)
_STACK_ROW = re.compile(
    r"^(?P<number>\d+)\s+(?P<role>Active|Standby|Member|Master|Unassigned)\s+"
    r"(?P<pid>\S+)\s+(?P<serial>\S+)\s+(?P<version>\S+)\s+(?P<state>\w+)$",
    re.IGNORECASE,
)
_STACK_REAL = re.compile(
    r"^(?P<star>\*)?(?P<number>\d+)\s+"
    r"(?P<role>Master|Member|Active|Standby|Unassigned)\s+"
    r"(?P<mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}|\S+)\s+"
    r"(?P<priority>\d+)\s+(?P<hardware>V?\d+)\s+(?P<state>\w+)\s*$",
    re.IGNORECASE,
)
_STORAGE_PREFIX = re.compile(r"\b([A-Za-z][A-Za-z0-9_.-]*:)")
_STORAGE_TYPES = frozenset({
    "flash", "nvram", "disk", "tftp", "ftp", "http", "https", "usbflash", "bsl",
})
_LICENSE_NAMES = {
    "lanlite": "LAN Lite",
    "lanbase": "LAN Base",
    "ipbase": "IP Base",
    "ipservices": "IP Services",
    "networkessentials": "Network Essentials",
    "networkadvantage": "Network Advantage",
    "dnaessentials": "DNA Essentials",
    "dnaadvantage": "DNA Advantage",
}


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


def _license_name(value: str | None) -> str | None:
    if not value:
        return None
    compact = re.sub(r"[\s_-]+", "", value).casefold()
    mapped = _LICENSE_NAMES.get(compact)
    if mapped is not None:
        return mapped
    return value.strip()


def _license_info(version_output: str, license_output: str | None) -> LicenseObservation:
    declared = _license_name(_first(_LICENSE_LEVEL, version_output))
    features: list[LicenseFeature] = []
    if license_output is not None:
        for match in _LICENSE_BLOCK.finditer(license_output):
            block = match.group(2)
            feature = _license_name(match.group(1).strip())
            if feature is None:
                continue
            features.append(LicenseFeature(
                feature=feature,
                license_type=_first(_LICENSE_TYPE, block),
                status=_first(_LICENSE_STATE, block),
                life_time=_first(_LICENSE_LIFE, block),
                next_boot=_license_name(_first(_LICENSE_NEXT, block)),
            ))
    active = tuple(
        feature.feature for feature in features
        if feature.status is not None
        and "active" in feature.status.casefold()
        and "not in use" not in feature.status.casefold()
    )
    # Some IOS transcripts mark the active entitlement with "In Use" only.
    if not active:
        active = tuple(
            feature.feature for feature in features
            if feature.status is not None and "in use" in feature.status.casefold()
        )
    observed = ", ".join(active) or (
        ", ".join(feature.feature for feature in features) or None
    )
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
        active_features=active,
        ambiguous=ambiguous,
    )


_INTERFACE_STATUSES = frozenset({
    "connected", "notconnect", "disabled", "err-disabled", "monitoring",
    "suspended", "down", "up", "inactive",
})
_INTERFACE_NAME = re.compile(
    r"^(?P<prefix>Gi|Te|Twe|Fa|Et|Po|Vl|Lo|Nu)(?P<member>\d+)/"
    r"(?P<slot>\d+)/(?P<index>\d+)$",
    re.IGNORECASE,
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
        if name.casefold() in {"port", "switch", "interface"}:
            continue
        rest = match.group("rest")
        lower_rest = rest.casefold()
        status = next(
            (part.casefold() for part in rest.split()
             if part.casefold() in _INTERFACE_STATUSES),
            None,
        )
        present = "not present" not in lower_rest
        physical = not name.casefold().startswith(("po", "vl", "lo", "nu"))
        member: int | None = None
        port_index: int | None = None
        name_match = _INTERFACE_NAME.match(name)
        if name_match is not None:
            member = int(name_match.group("member"))
            port_index = int(name_match.group("index"))
        medium = None
        if "sfp" in lower_rest or "1000base" in lower_rest and "10/100/1000" not in lower_rest:
            medium = "sfp"
        elif "10/100/1000" in lower_rest:
            medium = "copper"
        values.setdefault(name, ConsoleInterface(
            name=name,
            status=status,
            physical=physical,
            present=present,
            member=member,
            port_index=port_index,
            medium=medium,
        ))
    return tuple(values.values())


def _inventory_members(output: str) -> tuple[ConsoleInventoryMember, ...]:
    components = _inventory_components(output)
    modules: dict[int, _InventoryComponent] = {}
    chassis: list[tuple[int, _InventoryComponent]] = []
    for component in components:
        lower = component.name.casefold()
        module_match = re.search(r"(?:switch|member)\s+(\d+).*module", lower)
        if module_match is None:
            module_match = re.search(r"module.*(?:switch|member)\s+(\d+)", lower)
        if module_match is not None:
            modules[int(module_match.group(1))] = component
            continue
        if component.name.isdigit():
            chassis.append((int(component.name), component))
        elif lower == "chassis":
            chassis.append((1, component))
    result: list[ConsoleInventoryMember] = []
    for member, component in chassis:
        module = modules.get(member)
        result.append(ConsoleInventoryMember(
            name=component.name,
            pid=component.pid,
            serial_number=component.serial,
            member=member,
            component="chassis",
            module_pid=module.pid if module else None,
            module_serial=module.serial if module else None,
        ))
    return tuple(result)


def _stack(
    output: str | None,
    inventory: tuple[ConsoleInventoryMember, ...] = (),
) -> tuple[ConsoleStackMember, ...]:
    if output is None:
        return ()
    inventory_by_member = {
        item.member: item for item in inventory if item.member is not None
    }
    values: list[ConsoleStackMember] = []
    for line in output.splitlines():
        stripped = line.strip()
        real = _STACK_REAL.match(stripped)
        if real is not None:
            number = int(real.group("number"))
            bound = inventory_by_member.get(number)
            values.append(ConsoleStackMember(
                number=number,
                exact_pid=bound.pid if bound else None,
                serial_number=bound.serial_number if bound else None,
                role=real.group("role"),
                state=real.group("state"),
                priority=int(real.group("priority")),
                hardware_version=real.group("hardware"),
                mac=real.group("mac"),
                module_pid=bound.module_pid if bound else None,
                module_serial=bound.module_serial if bound else None,
            ))
            continue
        old = _STACK_ROW.match(stripped)
        if old is not None:
            values.append(ConsoleStackMember(
                number=int(old.group("number")),
                exact_pid=old.group("pid"),
                serial_number=old.group("serial"),
                role=old.group("role"),
                state=old.group("state"),
                software_version=old.group("version"),
            ))
            continue
        if re.match(r"^\*?\d+\s+", stripped):
            raise IdentityConflict("malformed stack member row")
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


def _boot_info(output: str | None) -> tuple[ConsoleBootEntry, ...]:
    if output is None:
        return ()
    values: dict[int | None, dict[str, str]] = {}
    current_member: int | None = None
    for line in output.splitlines():
        stripped = line.strip()
        member_match = _BOOT_MEMBER.match(stripped)
        if member_match is not None:
            current_member = int(member_match.group(1))
            values.setdefault(current_member, {})
            continue
        field = _BOOT_FIELD.match(stripped)
        if field is None:
            continue
        key = field.group(1).strip()
        values.setdefault(current_member, {})[key] = field.group(2).strip().rstrip(";")
    result: list[ConsoleBootEntry] = []
    for member, fields in values.items():
        if not fields:
            continue
        result.append(ConsoleBootEntry(
            member=member,
            boot_variable=fields.get("BOOT variable"),
            config_file=fields.get("CONFIG_FILE variable"),
            private_config_file=fields.get("PRIVATE_CONFIG_FILE variable"),
            manual_boot=fields.get("Manual Boot"),
            enable_break=fields.get("Enable Break"),
        ))
    return tuple(result)


def _storage_entries(output: str | None) -> tuple[ConsoleStorageEntry, ...]:
    if output is None:
        return ()
    result: list[ConsoleStorageEntry] = []
    seen: set[tuple[str, ...]] = set()
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("file systems", "size")):
            continue
        if "--More--" in stripped or "Prefixes" in stripped:
            continue
        prefixes = tuple(dict.fromkeys(_STORAGE_PREFIX.findall(stripped)))
        if not prefixes:
            continue
        if prefixes in seen:
            continue
        seen.add(prefixes)
        numbers = re.findall(r"\b(\d+)\b", stripped)
        tokens = [token.casefold() for token in stripped.split()]
        file_type = next(
            (token for token in tokens if token in _STORAGE_TYPES), None,
        )
        flags = next(
            (token for token in tokens if token in {"rw", "ro"}), None,
        )
        result.append(ConsoleStorageEntry(
            total_bytes=int(numbers[0]) if numbers else None,
            free_bytes=int(numbers[1]) if len(numbers) > 1 else None,
            file_type=file_type,
            flags=flags,
            prefixes=prefixes,
        ))
    return tuple(result)


def _storage_from_entries(entries: tuple[ConsoleStorageEntry, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(
        entry.primary_prefix for entry in entries if entry.primary_prefix
    ))


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
        inventory_members = _inventory_members(inventory_output)
        inventory_pids = {
            item.pid.upper() for item in inventory_members if item.pid is not None
        }
        if len(inventory_pids) > 1:
            raise IdentityConflict("multiple chassis PIDs in inventory")
        inventory_pid = next(iter(inventory_pids), None)
        exact_pid = inventory_pid or version_model
        if (
            version_model is not None
            and inventory_pid is not None
            and version_model.upper() != inventory_pid.upper()
        ):
            raise IdentityConflict("console identity fields conflict")
        version_serial = _first(_SERIAL, version_output)
        primary_member = next(
            (item for item in inventory_members if item.member == 1),
            inventory_members[0] if inventory_members else None,
        )
        inventory_serial = primary_member.serial_number if primary_member else None
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
        unknown: list[str] = []
        serial = inventory_serial or version_serial
        if not inventory_members:
            unknown.append("inventory-chassis-missing")
        if version_model is None:
            # The complete PID came from Inventory. Do not invent the missing
            # Version identity line from a truncated/paginated transcript.
            unknown.append("version-model-missing")
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
            if family is DeviceFamily.CATALYST_C1000:
                # C1000 show license returns an Incomplete command in the
                # reviewed transcript; it is not queried or inferred.
                unsupported.append(ConsoleQuery.LICENSE)
        else:
            unknown.extend(("license", "interfaces", "stack", "boot", "storage"))

        license_info = _license_info(version_output, license_output)
        if license_output is not None and not license_info.features:
            unknown.append("license-feature-missing")
        if license_info.ambiguous:
            unknown.append("license-declared-observed-mismatch")
        interfaces = _interfaces(interfaces_output)
        stack = _stack(stack_output, inventory_members)
        boot_entries = _boot_info(boot_output)
        boot_state = next(
            (entry.boot_variable for entry in boot_entries if entry.boot_variable),
            _first(_BOOT, boot_output or ""),
        )
        storage_entries = _storage_entries(storage_output)
        storage = _storage_from_entries(storage_entries)
        if profile is not None:
            supported = set(supported_queries_for_profile(profile))
            if ConsoleQuery.INTERFACES in supported and not interfaces:
                unknown.append("interfaces")
            if ConsoleQuery.STACK in supported and not stack:
                unknown.append("stack")
            if ConsoleQuery.BOOT in supported and not boot_entries:
                unknown.append("boot")
            if ConsoleQuery.STORAGE in supported and not storage_entries:
                unknown.append("storage")
            if ConsoleQuery.LICENSE in supported and not license_info.features:
                unknown.append("license")
            if stack and any(
                (member.state or "").casefold() != "ready" for member in stack
            ):
                unknown.append("stack-member-not-ready")
            if (
                len(inventory_members) > 1
                and all(item.name.isdigit() for item in inventory_members)
                and len(inventory_members) != len(stack)
            ):
                unknown.append("stack-inventory-mismatch")
            if (
                unsupported
                and not (
                    family is DeviceFamily.CATALYST_C1000
                    and all(query is ConsoleQuery.LICENSE for query in unsupported)
                )
            ):
                unknown.append("queries-not-reviewed")
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
            inventory=inventory_members,
            boot_entries=boot_entries,
            boot_state=boot_state,
            storage_entries=storage_entries,
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
