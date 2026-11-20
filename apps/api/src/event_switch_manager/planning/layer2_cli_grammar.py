"""CIS-02B2-03 independently authored Cisco Layer 2 CLI grammar.

This module is the grammar half of the independent validation layer. It was
authored separately from the frozen B2-02 renderer and deliberately shares no
oracle with it:

* it never imports :mod:`layer2_cli_candidates`;
* it contains no renderer template, ``compose`` lambda, parameter validator or
  text-policy helper;
* it does not derive its productions from renderer output.

Shared vocabulary is limited to the pure ``CommandTopic`` and ``CommandMode``
enums that name the reviewed dictionary entries. Reviewed scope data and the
machine-checkable parameter limits are supplied by the caller from the frozen
L1 evidence registry; this module fixes only the documented command forms and
their syntactic envelopes.

The grammar is intentionally narrower than the Cisco CLI. Only forms that the
frozen evidence registry documents for a reviewed scope are present: no aliases,
abbreviations, range syntax, cleanup forms, ``add``/``remove``/``except``
variants or configuration sequences. A form being grammatical says nothing
about platform support; that decision belongs to the independent scope
validator.
"""

from __future__ import annotations

import string
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .command_evidence import CommandMode, CommandTopic

# --------------------------------------------------------------------------- #
# Independent text policy
# --------------------------------------------------------------------------- #

_ALNUM: Final[frozenset[str]] = frozenset(string.ascii_letters + string.digits)

#: Reviewed VLAN-name character subset (1-32 characters, first character
#: alphanumeric). Independently re-derived from the B2-01 text contract.
VLAN_NAME_ALLOWED: Final[frozenset[str]] = _ALNUM | frozenset("._-")

#: Reviewed description character subset (1-240 characters, first character
#: alphanumeric, single ASCII line). The space is handled through token
#: boundaries; it is part of the accepted alphabet for completeness.
DESCRIPTION_ALLOWED: Final[frozenset[str]] = _ALNUM | frozenset(" .,:/_+%@-")

VLAN_NAME_MAXIMUM: Final[int] = 32
DESCRIPTION_MAXIMUM: Final[int] = 240

#: Absolute syntactic envelope for a VLAN id. Reserved ids are the legacy
#: default VLANs; the platform layer never accepts them as a planned value.
VLAN_ID_MINIMUM: Final[int] = 1
VLAN_ID_MAXIMUM: Final[int] = 4094
RESERVED_VLAN_IDS: Final[tuple[int, ...]] = (1002, 1003, 1004, 1005)

#: Reviewed trunk allowed-list envelope: explicit ascending ids, at most 64
#: entries. Range and ``add``/``remove``/``except`` forms are not produced.
VLAN_LIST_MAXIMUM_ENTRIES: Final[int] = 64

#: Spanning-tree bridge priority envelope and granularity.
PRIORITY_MINIMUM: Final[int] = 0
PRIORITY_MAXIMUM: Final[int] = 61440
PRIORITY_STEP: Final[int] = 4096

#: Absolute syntactic envelope of an EtherChannel / Port-Channel number. The
#: reviewed per-platform maximum is applied later from the evidence row.
PORT_CHANNEL_NUMBER_MINIMUM: Final[int] = 1
PORT_CHANNEL_NUMBER_MAXIMUM: Final[int] = 9999


class TargetClass(StrEnum):
    """Independent target classification of one parsed command."""

    DEVICE = "device"
    VLAN = "vlan"
    INTERFACE = "interface"
    PORT_CHANNEL = "port-channel"


class TextKind(StrEnum):
    VLAN_NAME = "vlan-name"
    DESCRIPTION = "description"


# --------------------------------------------------------------------------- #
# Grammar productions
# --------------------------------------------------------------------------- #


class IntegerParameter:
    """Integer argument with an absolute syntactic range."""

    __slots__ = ("maximum", "minimum", "name", "reserved", "step")

    name: str
    minimum: int
    maximum: int
    step: int | None
    reserved: tuple[int, ...]

    def __init__(
        self,
        name: str,
        minimum: int,
        maximum: int,
        *,
        step: int | None = None,
        reserved: tuple[int, ...] = (),
    ) -> None:
        self.name = name
        self.minimum = minimum
        self.maximum = maximum
        self.step = step
        self.reserved = reserved

    def __repr__(self) -> str:
        return (
            f"IntegerParameter({self.name!r}, {self.minimum}, {self.maximum}, "
            f"step={self.step!r}, reserved={self.reserved!r})"
        )


class EnumParameter:
    """Enumerated argument; the value set is the reviewed form vocabulary."""

    __slots__ = ("name", "values")

    name: str
    values: tuple[str, ...]

    def __init__(self, name: str, values: tuple[str, ...]) -> None:
        self.name = name
        self.values = values

    def __repr__(self) -> str:
        return f"EnumParameter({self.name!r}, {self.values!r})"


class TextParameter:
    """Bounded text argument with an independently applied character policy."""

    __slots__ = ("allowlist", "first_characters", "kind", "maximum", "name", "single_token")

    name: str
    kind: TextKind
    maximum: int
    allowlist: frozenset[str]
    first_characters: frozenset[str]
    single_token: bool

    def __init__(
        self,
        name: str,
        kind: TextKind,
        maximum: int,
        allowlist: frozenset[str],
        first_characters: frozenset[str],
        *,
        single_token: bool,
    ) -> None:
        self.name = name
        self.kind = kind
        self.maximum = maximum
        self.allowlist = allowlist
        self.first_characters = first_characters
        self.single_token = single_token

    def __repr__(self) -> str:
        return (
            f"TextParameter({self.name!r}, {self.kind.value!r}, {self.maximum}, "
            f"single_token={self.single_token!r})"
        )


class VlanListParameter:
    """Explicit ascending VLAN id list; replacement semantics are implicit."""

    __slots__ = ("ascending", "maximum", "maximum_entries", "minimum", "name", "reserved")

    name: str
    minimum: int
    maximum: int
    reserved: tuple[int, ...]
    maximum_entries: int
    ascending: bool

    def __init__(
        self,
        name: str,
        minimum: int,
        maximum: int,
        *,
        reserved: tuple[int, ...] = (),
        maximum_entries: int,
        ascending: bool = True,
    ) -> None:
        self.name = name
        self.minimum = minimum
        self.maximum = maximum
        self.reserved = reserved
        self.maximum_entries = maximum_entries
        self.ascending = ascending

    def __repr__(self) -> str:
        return (
            f"VlanListParameter({self.name!r}, {self.minimum}, {self.maximum}, "
            f"maximum_entries={self.maximum_entries}, ascending={self.ascending!r})"
        )


class PortChannelNameParameter:
    """The single ``interface Port-Channel<N>`` token, split into its number."""

    __slots__ = ("name",)

    name: str

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"PortChannelNameParameter({self.name!r})"


class ChannelNumberParameter:
    """A bare channel-group number token."""

    __slots__ = ("maximum", "minimum", "name")

    name: str
    minimum: int
    maximum: int

    def __init__(self, name: str, minimum: int, maximum: int) -> None:
        self.name = name
        self.minimum = minimum
        self.maximum = maximum

    def __repr__(self) -> str:
        return f"ChannelNumberParameter({self.name!r}, {self.minimum}, {self.maximum})"


Parameter = (
    IntegerParameter
    | EnumParameter
    | TextParameter
    | VlanListParameter
    | PortChannelNameParameter
    | ChannelNumberParameter
)


@dataclass(frozen=True, slots=True)
class Literal:
    """A fixed keyword token that must match exactly."""

    text: str


@dataclass(frozen=True, slots=True)
class ParameterSlot:
    """One argument position in a production."""

    parameter: Parameter


PatternItem = Literal | ParameterSlot


@dataclass(frozen=True, slots=True)
class GrammarForm:
    """One documented command form and its syntactic envelope."""

    form_id: str
    topic: CommandTopic
    pattern: tuple[PatternItem, ...]
    modes: frozenset[CommandMode]
    target_classes: frozenset[TargetClass]
    fixed_parameters: tuple[tuple[str, object], ...] = ()


# --------------------------------------------------------------------------- #
# Reviewed argument envelopes
# --------------------------------------------------------------------------- #


VLAN_ID = IntegerParameter(
    "vlan-id", VLAN_ID_MINIMUM, VLAN_ID_MAXIMUM, reserved=RESERVED_VLAN_IDS,
)
PRIORITY = IntegerParameter(
    "priority", PRIORITY_MINIMUM, PRIORITY_MAXIMUM, step=PRIORITY_STEP,
)
PORT_CHANNEL_NUMBER = PortChannelNameParameter("port-channel-number")
CHANNEL_GROUP_NUMBER = ChannelNumberParameter(
    "port-channel-number", PORT_CHANNEL_NUMBER_MINIMUM, PORT_CHANNEL_NUMBER_MAXIMUM,
)
VLAN_NAME = TextParameter(
    "vlan-name", TextKind.VLAN_NAME, VLAN_NAME_MAXIMUM, VLAN_NAME_ALLOWED, _ALNUM,
    single_token=True,
)
DESCRIPTION = TextParameter(
    "description", TextKind.DESCRIPTION, DESCRIPTION_MAXIMUM, DESCRIPTION_ALLOWED,
    _ALNUM, single_token=False,
)
VLAN_LIST = VlanListParameter(
    "vlan-list", VLAN_ID_MINIMUM, VLAN_ID_MAXIMUM, reserved=RESERVED_VLAN_IDS,
    maximum_entries=VLAN_LIST_MAXIMUM_ENTRIES, ascending=True,
)
BPDU_GUARD_STATE = EnumParameter("bpdu-guard", ("enable", "disable"))
POE_MODE = EnumParameter("poe-mode", ("auto", "static", "never"))
SPEED = EnumParameter("speed", ("10", "100", "1000", "auto"))
DUPLEX = EnumParameter("duplex", ("full", "half", "auto"))
LACP_MODE = EnumParameter("mode", ("active", "passive"))
STATIC_MODE = EnumParameter("mode", ("on",))

_GLOBAL = frozenset({CommandMode.GLOBAL})
_VLAN_MODE = frozenset({CommandMode.VLAN})
_SWITCHPORT_MODES = frozenset({CommandMode.INTERFACE, CommandMode.PORT_CHANNEL})
_SWITCHPORT_TARGETS = frozenset({
    TargetClass.INTERFACE, TargetClass.PORT_CHANNEL,
})
_DEVICE_TARGETS = frozenset({TargetClass.DEVICE})
_VLAN_TARGETS = frozenset({TargetClass.VLAN})
_PORT_CHANNEL_TARGETS = frozenset({TargetClass.PORT_CHANNEL})


def _slot(parameter: Parameter) -> ParameterSlot:
    return ParameterSlot(parameter)


#: The complete independently authored production set. Every entry is a single
#: configuration command in exactly one documented form.
FORMS: tuple[GrammarForm, ...] = (
    GrammarForm(
        form_id="vlan",
        topic=CommandTopic.VLAN,
        pattern=(Literal("vlan"), _slot(VLAN_ID)),
        modes=_GLOBAL,
        target_classes=_VLAN_TARGETS,
    ),
    GrammarForm(
        form_id="vlan-name",
        topic=CommandTopic.VLAN_NAME,
        pattern=(Literal("name"), _slot(VLAN_NAME)),
        modes=_VLAN_MODE,
        target_classes=_VLAN_TARGETS,
    ),
    GrammarForm(
        form_id="access-mode",
        topic=CommandTopic.ACCESS_MODE,
        pattern=(Literal("switchport"), Literal("mode"), Literal("access")),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
    ),
    GrammarForm(
        form_id="trunk-mode",
        topic=CommandTopic.TRUNK_MODE,
        pattern=(Literal("switchport"), Literal("mode"), Literal("trunk")),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
    ),
    GrammarForm(
        form_id="access-vlan",
        topic=CommandTopic.ACCESS_VLAN,
        pattern=(
            Literal("switchport"), Literal("access"), Literal("vlan"), _slot(VLAN_ID),
        ),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
    ),
    GrammarForm(
        form_id="native-vlan",
        topic=CommandTopic.NATIVE_VLAN,
        pattern=(
            Literal("switchport"), Literal("trunk"), Literal("native"),
            Literal("vlan"), _slot(VLAN_ID),
        ),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
    ),
    GrammarForm(
        form_id="allowed-vlans",
        topic=CommandTopic.ALLOWED_VLANS,
        pattern=(
            Literal("switchport"), Literal("trunk"), Literal("allowed"),
            Literal("vlan"), _slot(VLAN_LIST),
        ),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
        fixed_parameters=(("operation", "replace"),),
    ),
    GrammarForm(
        form_id="port-channel-interface",
        topic=CommandTopic.PORT_CHANNEL_INTERFACE,
        pattern=(Literal("interface"), _slot(PORT_CHANNEL_NUMBER)),
        modes=_GLOBAL,
        target_classes=_PORT_CHANNEL_TARGETS,
    ),
    GrammarForm(
        form_id="channel-group-static",
        topic=CommandTopic.CHANNEL_GROUP_STATIC,
        pattern=(
            Literal("channel-group"), _slot(CHANNEL_GROUP_NUMBER),
            Literal("mode"), Literal("on"),
        ),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
        fixed_parameters=(("mode", "on"),),
    ),
    GrammarForm(
        form_id="channel-group-lacp",
        topic=CommandTopic.CHANNEL_GROUP_LACP,
        pattern=(
            Literal("channel-group"), _slot(CHANNEL_GROUP_NUMBER),
            Literal("mode"), _slot(LACP_MODE),
        ),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
    ),
    GrammarForm(
        form_id="rapid-pvst",
        topic=CommandTopic.RAPID_PVST,
        pattern=(Literal("spanning-tree"), Literal("mode"), Literal("rapid-pvst")),
        modes=_GLOBAL,
        target_classes=_DEVICE_TARGETS,
    ),
    GrammarForm(
        form_id="vtp-transparent",
        topic=CommandTopic.VTP_TRANSPARENT,
        pattern=(Literal("vtp"), Literal("mode"), Literal("transparent")),
        modes=_GLOBAL,
        target_classes=_DEVICE_TARGETS,
    ),
    GrammarForm(
        form_id="root-priority",
        topic=CommandTopic.ROOT_PRIORITY,
        pattern=(
            Literal("spanning-tree"), Literal("vlan"), _slot(VLAN_ID),
            Literal("priority"), _slot(PRIORITY),
        ),
        modes=_GLOBAL,
        target_classes=_DEVICE_TARGETS,
    ),
    GrammarForm(
        form_id="portfast",
        topic=CommandTopic.PORTFAST,
        pattern=(Literal("spanning-tree"), Literal("portfast")),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
        fixed_parameters=(("portfast", "edge"),),
    ),
    GrammarForm(
        form_id="portfast-trunk",
        topic=CommandTopic.PORTFAST,
        pattern=(Literal("spanning-tree"), Literal("portfast"), Literal("trunk")),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
        fixed_parameters=(("portfast", "edge-trunk"),),
    ),
    GrammarForm(
        form_id="bpdu-guard",
        topic=CommandTopic.BPDU_GUARD,
        pattern=(
            Literal("spanning-tree"), Literal("bpduguard"), _slot(BPDU_GUARD_STATE),
        ),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
    ),
    GrammarForm(
        form_id="poe-mode",
        topic=CommandTopic.POE_MODE,
        pattern=(Literal("power"), Literal("inline"), _slot(POE_MODE)),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
    ),
    GrammarForm(
        form_id="speed",
        topic=CommandTopic.SPEED,
        pattern=(Literal("speed"), _slot(SPEED)),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
    ),
    GrammarForm(
        form_id="duplex",
        topic=CommandTopic.DUPLEX,
        pattern=(Literal("duplex"), _slot(DUPLEX)),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
    ),
    GrammarForm(
        form_id="description",
        topic=CommandTopic.DESCRIPTION,
        pattern=(Literal("description"), _slot(DESCRIPTION)),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
    ),
    GrammarForm(
        form_id="shutdown",
        topic=CommandTopic.ADMIN_SHUTDOWN,
        pattern=(Literal("shutdown"),),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
        fixed_parameters=(("admin-state", "down"),),
    ),
    GrammarForm(
        form_id="no-shutdown",
        topic=CommandTopic.ADMIN_SHUTDOWN,
        pattern=(Literal("no"), Literal("shutdown")),
        modes=_SWITCHPORT_MODES,
        target_classes=_SWITCHPORT_TARGETS,
        fixed_parameters=(("admin-state", "up"),),
    ),
)

FORM_BY_ID: Final[Mapping[str, GrammarForm]] = {form.form_id: form for form in FORMS}

_forms_by_topic: dict[CommandTopic, list[GrammarForm]] = {}
for _form in FORMS:
    _forms_by_topic.setdefault(_form.topic, []).append(_form)
FORMS_BY_TOPIC: Final[Mapping[CommandTopic, tuple[GrammarForm, ...]]] = {
    topic: tuple(forms) for topic, forms in _forms_by_topic.items()
}

_covered_topics = frozenset(FORMS_BY_TOPIC)
_missing_topics = tuple(topic for topic in CommandTopic if topic not in _covered_topics)
if _missing_topics:  # pragma: no cover - import-time contract guard
    raise ValueError(f"grammar is missing reviewed topics: {_missing_topics}")
if len(FORM_BY_ID) != len(FORMS):  # pragma: no cover - import-time contract guard
    raise ValueError("grammar form IDs must be unique")

#: Canonical hand-authored command per topic, used only for evidence-registry
#: coverage records. Parameter values are chosen inside every reviewed scope.
COVERAGE_COMMAND_BY_TOPIC: Final[Mapping[CommandTopic, str]] = {
    CommandTopic.VLAN: "vlan 10",
    CommandTopic.VLAN_NAME: "name CoveragePort",
    CommandTopic.ACCESS_MODE: "switchport mode access",
    CommandTopic.ACCESS_VLAN: "switchport access vlan 10",
    CommandTopic.TRUNK_MODE: "switchport mode trunk",
    CommandTopic.NATIVE_VLAN: "switchport trunk native vlan 10",
    CommandTopic.ALLOWED_VLANS: "switchport trunk allowed vlan 10,20",
    CommandTopic.PORT_CHANNEL_INTERFACE: "interface Port-Channel1",
    CommandTopic.CHANNEL_GROUP_STATIC: "channel-group 1 mode on",
    CommandTopic.CHANNEL_GROUP_LACP: "channel-group 1 mode active",
    CommandTopic.RAPID_PVST: "spanning-tree mode rapid-pvst",
    CommandTopic.VTP_TRANSPARENT: "vtp mode transparent",
    CommandTopic.ROOT_PRIORITY: "spanning-tree vlan 10 priority 4096",
    CommandTopic.PORTFAST: "spanning-tree portfast",
    CommandTopic.BPDU_GUARD: "spanning-tree bpduguard enable",
    CommandTopic.POE_MODE: "power inline auto",
    CommandTopic.SPEED: "speed 1000",
    CommandTopic.DUPLEX: "duplex full",
    CommandTopic.DESCRIPTION: "description Coverage port",
    CommandTopic.ADMIN_SHUTDOWN: "no shutdown",
}

# --------------------------------------------------------------------------- #
# Prohibited command vocabulary
# --------------------------------------------------------------------------- #

#: Command-position heads whose only effect would be a device-state, cleanup,
#: identity or destructive operation outside B2. This is checked only against
#: the command position, never against text that is a data argument (a port
#: description containing the word "reload" is still a description).
DANGEROUS_COMMAND_HEADS: Final[frozenset[str]] = frozenset({
    "aaa",
    "access-list",
    "archive",
    "banner",
    "boot",
    "clear",
    "configure",
    "copy",
    "crypto",
    "default",
    "delete",
    "disable",
    "do",
    "enable",
    "end",
    "erase",
    "exit",
    "factory-reset",
    "format",
    "hostname",
    "install",
    "ip",
    "ipv6",
    "license",
    "line",
    "logging",
    "login",
    "mkfs",
    "ntp",
    "password",
    "privilege",
    "reload",
    "reset",
    "rommon",
    "route-map",
    "snmp-server",
    "squeeze",
    "ssh",
    "tacacs-server",
    "telnet",
    "upgrade",
    "username",
    "vrf",
    "write",
})
