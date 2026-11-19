"""CIS-02B2 L1 command evidence registry.

Every rendered candidate must cite one reviewed, version-scoped command-evidence
row. This module holds those rows for the five reviewed Catalyst families.

Design rules enforced by this module:

* a row names exact PIDs, an exact operating release and an exact license scope;
  it never covers a family in general, so a family-level library cannot leak
  into an unreviewed PID or release;
* a row records the command grammar, its configuration mode, its documented
  parameter limits and the exact vendor page and section;
* rendering is permitted only for a row whose independent review state is
  ``independently-reviewed``. Every other state stays dictionary-only (SYN-P)
  and produces a deterministic blocker instead of command text;
* excluded releases (identity-only or aggregation-only) are expressed as absent
  release scope, never as a runtime guess;
* 2960X, 3850 and C1000 have **no** VLAN/access/trunk/STP/VTP/PortFast/BPDU-Guard
  rows, because CIS-01A has no reviewed feature evidence for those categories on
  those families. The capability gate and the evidence gate both fail closed.

The registry is data only. It does not connect to a device, does not read a
running-config and does not execute anything.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Literal

from ..domain import DeviceFamily
from .command_evidence_reviews import REJECTED_RECORDS, REVIEWED_RECORDS

EVIDENCE_SCHEMA_VERSION: Literal[1] = 1
EVIDENCE_REGISTRY_ID: Literal["cis-02b2-l1-command-evidence-v1"] = (
    "cis-02b2-l1-command-evidence-v1"
)


class CommandTopic(StrEnum):
    """One dictionary entry: a single reviewed Cisco command form."""

    VLAN = "vlan"
    VLAN_NAME = "vlan-name"
    ACCESS_MODE = "access-mode"
    ACCESS_VLAN = "access-vlan"
    TRUNK_MODE = "trunk-mode"
    NATIVE_VLAN = "native-vlan"
    ALLOWED_VLANS = "allowed-vlans"
    PORT_CHANNEL_INTERFACE = "port-channel-interface"
    CHANNEL_GROUP_STATIC = "channel-group-static"
    CHANNEL_GROUP_LACP = "channel-group-lacp"
    RAPID_PVST = "rapid-pvst"
    VTP_TRANSPARENT = "vtp-transparent"
    ROOT_PRIORITY = "root-priority"
    PORTFAST = "portfast"
    BPDU_GUARD = "bpdu-guard"
    POE_MODE = "poe-mode"
    SPEED = "speed"
    DUPLEX = "duplex"
    DESCRIPTION = "description"
    ADMIN_SHUTDOWN = "admin-shutdown"


class CommandMode(StrEnum):
    GLOBAL = "global"
    VLAN = "vlan"
    INTERFACE = "interface"
    PORT_CHANNEL = "port-channel"


class EvidenceReviewState(StrEnum):
    PENDING = "pending-independent-review"
    REVIEWED = "independently-reviewed"
    REJECTED = "independently-rejected"


@dataclass(frozen=True, slots=True)
class EvidenceReview:
    """Independent review attestation for exactly one evidence row."""

    state: EvidenceReviewState
    reviewer: str = ""
    reviewed_at: str = ""
    findings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.state is EvidenceReviewState.REVIEWED and not (
            self.reviewer and self.reviewed_at and self.findings
        ):
            raise ValueError("A reviewed evidence row needs reviewer, date and findings")


PENDING_REVIEW = EvidenceReview(EvidenceReviewState.PENDING)
REJECTED_REVIEW = EvidenceReview(
    EvidenceReviewState.REJECTED, "", "", ("Not independently confirmed.",),
)


@dataclass(frozen=True, slots=True)
class ParameterRule:
    """Machine-checkable parameter restriction for one command argument."""

    name: str
    kind: Literal["integer", "enum", "text", "vlan-list"]
    minimum: int | None = None
    maximum: int | None = None
    step: int | None = None
    values: tuple[str, ...] = ()
    pattern: str | None = None
    reserved: tuple[int, ...] = ()
    note: str = ""


@dataclass(frozen=True, slots=True)
class SourceRef:
    url: str
    section: str


@dataclass(frozen=True, slots=True)
class CommandEvidence:
    evidence_id: str
    family: DeviceFamily
    pids: tuple[str, ...]
    releases: tuple[str, ...]
    licenses: tuple[str, ...]
    topic: CommandTopic
    command: str
    grammar: str
    command_mode: CommandMode
    parameters: tuple[ParameterRule, ...]
    limits: tuple[str, ...]
    source_url: str
    source_section: str
    exclusions: tuple[str, ...]
    review: EvidenceReview = PENDING_REVIEW
    evidence_version: int = 1

    @property
    def renderable(self) -> bool:
        return self.review.state is EvidenceReviewState.REVIEWED

    @property
    def release_label(self) -> str:
        return " / ".join(self.releases)


def _integer(
    name: str, minimum: int, maximum: int, *,
    step: int | None = None, reserved: tuple[int, ...] = (), note: str = "",
) -> ParameterRule:
    return ParameterRule(
        name, "integer", minimum=minimum, maximum=maximum, step=step,
        reserved=reserved, note=note,
    )


def _enum(name: str, values: tuple[str, ...], note: str = "") -> ParameterRule:
    return ParameterRule(name, "enum", values=values, note=note)


def channel_rule(maximum: int) -> ParameterRule:
    return _integer(
        "port-channel-number", 1, maximum,
        note=f"The reviewed release documents EtherChannel numbers 1-{maximum}.",
    )


VLAN_ID = _integer(
    "vlan-id", 1, 4094, reserved=(1002, 1003, 1004, 1005),
    note="VLAN 1 is the default VLAN; 1002-1005 are reserved for legacy defaults.",
)
VLAN_NAME = ParameterRule(
    "vlan-name", "text", maximum=32, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$",
    note=(
        "Documented ASCII string of 1-32 characters; the renderer additionally "
        "rejects characters whose token quoting is not independently established."
    ),
)
DESCRIPTION = ParameterRule(
    "description", "text", maximum=240,
    pattern=r"^[A-Za-z0-9][A-Za-z0-9 .,:/_+%@-]{0,239}$",
    note=(
        "Documented single line of up to 240 characters; the renderer additionally "
        "rejects characters whose token quoting is not independently established."
    ),
)
TRUNK_VLAN_LIST = ParameterRule(
    "vlan-list", "vlan-list", minimum=1, maximum=4094,
    reserved=(1002, 1003, 1004, 1005),
    note="Explicit ascending ids; the renderer emits at most 64 ids per candidate.",
)
PRIORITY = _integer(
    "priority", 0, 61440, step=4096,
    note="Documented range 0-61440 in increments of 4096; default 32768.",
)

# --------------------------------------------------------------------------- #
# Reviewed platform scopes
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PlatformScope:
    """One exact family/PID/release/license evidence scope.

    Every value here is supplied per scope. The row builders never derive one
    scope's vendor claim from another scope, so a family-level library cannot
    spread into an unreviewed PID, release or license.
    """

    family: DeviceFamily
    id_key: str
    pids: tuple[str, ...]
    aggregation_releases: tuple[str, ...]
    feature_releases: tuple[str, ...]
    licenses: tuple[str, ...]
    channel_max: int
    channel_basis: str
    ports_per_channel: str
    sources: Mapping[CommandTopic, SourceRef]
    notes: Mapping[CommandTopic, tuple[str, ...]]
    exclusion: str
    parameter_overrides: Mapping[CommandTopic, tuple[ParameterRule, ...]]
    aggregation_only: bool = False


CR_2960X = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/"
    "15-2_7_e/command_reference/b_1527_2960x_cr/"
)
CG_2960X = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/"
    "15-2_7_e/configuration_guide/b_1527e_consolidated_2960x_cg/"
)
CR_3850 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/software/"
    "release/16-12/command_reference/b_1612_3850_cr/"
)
CG_3850 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/software/"
    "release/16-12/configuration_guide/"
)
CR_9200 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/"
    "release/17-12/command_reference/b_1712_9200_cr/"
)
CG_9200 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/"
    "release/17-12/configuration_guide/"
)
CR_9300 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/"
    "release/17-12/command_reference/b_1712_9300_cr/"
)
CG_9300 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/"
    "release/17-12/configuration_guide/"
)
CR_C1000 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst1000/software/"
    "releases/15_2_7_e/command_reference/b_1527e_1000_cr/"
)
CG_C1000 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst1000/software/"
    "releases/15_2_7_e/configuration_guides/"
)

S2960X_LANBASE = PlatformScope(
    family=DeviceFamily.CATALYST_2960X,
    id_key="catalyst-2960x-lanbase",
    pids=("WS-C2960X-24TS-L", "WS-C2960X-24PS-L"),
    aggregation_releases=("15.2(7)E", "15.2(7)E7"),
    feature_releases=("15.2(7)E", "15.2(7)E7"),
    licenses=("LAN Base",),
    channel_max=24,
    channel_basis="port-channel-number range is 1 to 24 (command reference)",
    ports_per_channel=(
        "A LAN Base switch supports up to 24 EtherChannels; the channel-group "
        "number range remains 1 to 24."
    ),
    sources={
        CommandTopic.PORT_CHANNEL_INTERFACE: SourceRef(
            CR_2960X + "layer_2_commands.html", "interface port-channel",
        ),
        CommandTopic.CHANNEL_GROUP_STATIC: SourceRef(
            CR_2960X + "layer_2_commands.html", "channel-group",
        ),
        CommandTopic.CHANNEL_GROUP_LACP: SourceRef(
            CR_2960X + "layer_2_commands.html", "channel-group",
        ),
        CommandTopic.SPEED: SourceRef(
            CG_2960X + "m_int_inter_cg.html",
            "Setting the Interface Speed and Duplex Parameters",
        ),
        CommandTopic.DUPLEX: SourceRef(
            CR_2960X + "interface_and_hardware_commands.html", "duplex",
        ),
        CommandTopic.DESCRIPTION: SourceRef(
            CG_2960X + "m_int_inter_cg.html", "Adding a Description for an Interface",
        ),
        CommandTopic.ADMIN_SHUTDOWN: SourceRef(
            CG_2960X + "m_int_inter_cg.html",
            "Shutting Down and Restarting the Interface",
        ),
        CommandTopic.POE_MODE: SourceRef(
            CR_2960X + "interface_and_hardware_commands.html", "power inline",
        ),
    },
    notes={
        CommandTopic.SPEED: (
            "Copper 10/100/1000 ports; nonegotiate is documented for SFP ports only.",
            "Do not disable auto-negotiation on PoE switches (documented restriction).",
        ),
        CommandTopic.DUPLEX: (
            "Half duplex is only for 10/100 Mb/s operation.",
            "Duplex options are not supported on 1000BASE-x or 10GBASE-x SFP modules.",
        ),
        CommandTopic.POE_MODE: (
            "power inline static is documented; max max-wattage is 4000-30000 mW.",
            "PoE requires the LAN Base image and PoE-capable hardware.",
        ),
        CommandTopic.CHANNEL_GROUP_LACP: (
            "An LACP channel group supports up to 16 ports: eight active, eight standby.",
        ),
    },
    exclusion=(
        "LAN Base only: LAN Lite EtherChannel and PoE limits are a separate scope."
    ),
    parameter_overrides={},
)

S2960X_LANLITE = PlatformScope(
    family=DeviceFamily.CATALYST_2960X,
    id_key="catalyst-2960x-lanlite",
    pids=("WS-C2960X-24TS-LL",),
    aggregation_releases=("15.2(7)E", "15.2(7)E7"),
    feature_releases=("15.2(7)E", "15.2(7)E7"),
    licenses=("LAN Lite",),
    channel_max=6,
    channel_basis=(
        "LAN Lite supports up to six EtherChannels; the channel-group number "
        "range remains 1 to 24"
    ),
    ports_per_channel=(
        "LAN Lite supports a maximum of six EtherChannels; the channel-group "
        "number range remains 1 to 24."
    ),
    sources={
        CommandTopic.PORT_CHANNEL_INTERFACE: SourceRef(
            CR_2960X + "layer_2_commands.html", "interface port-channel",
        ),
        CommandTopic.CHANNEL_GROUP_STATIC: SourceRef(
            CR_2960X + "layer_2_commands.html", "channel-group",
        ),
        CommandTopic.CHANNEL_GROUP_LACP: SourceRef(
            CR_2960X + "layer_2_commands.html", "channel-group",
        ),
        CommandTopic.SPEED: SourceRef(
            CG_2960X + "m_int_inter_cg.html",
            "Setting the Interface Speed and Duplex Parameters",
        ),
        CommandTopic.DUPLEX: SourceRef(
            CR_2960X + "interface_and_hardware_commands.html", "duplex",
        ),
        CommandTopic.DESCRIPTION: SourceRef(
            CG_2960X + "m_int_inter_cg.html", "Adding a Description for an Interface",
        ),
        CommandTopic.ADMIN_SHUTDOWN: SourceRef(
            CG_2960X + "m_int_inter_cg.html",
            "Shutting Down and Restarting the Interface",
        ),
        CommandTopic.POE_MODE: SourceRef(
            CR_2960X + "interface_and_hardware_commands.html", "power inline",
        ),
    },
    notes={
        CommandTopic.PORT_CHANNEL_INTERFACE: (
            "LAN Lite limits the number of EtherChannels to six.",
        ),
        CommandTopic.SPEED: (
            "Copper 10/100/1000 ports; the LAN Lite image does not support PoE.",
        ),
        CommandTopic.DUPLEX: (
            "Half duplex is only for 10/100 Mb/s operation.",
        ),
        CommandTopic.POE_MODE: (
            "PoE is supported only on the LAN Base image, so LAN Lite PoE is "
            "expected to be blocked by hardware capability, not by this row.",
        ),
    },
    exclusion=(
        "LAN Lite lacks FlexStack-Plus and PoE; no Stack or PoE claim is made here."
    ),
    parameter_overrides={},
)

S3850 = PlatformScope(
    family=DeviceFamily.CATALYST_3850,
    id_key="catalyst-3850",
    pids=("WS-C3850-24T", "WS-C3850-24P", "WS-C3850-24T-L", "WS-C3850-24P-S"),
    aggregation_releases=("16.12.12", "16.12.10a"),
    feature_releases=("16.12.12",),
    licenses=("LAN Base", "IP Base", "IP Services"),
    channel_max=128,
    channel_basis="port-channel logical interface numbers: 1 to 128",
    ports_per_channel="",
    sources={
        CommandTopic.PORT_CHANNEL_INTERFACE: SourceRef(
            CG_3850 + "lyr2/b_1612_lyr2_3850_cg/configuring___etherchannels.html",
            "Channel Groups and Port-Channel Interfaces",
        ),
        CommandTopic.CHANNEL_GROUP_STATIC: SourceRef(
            CR_3850 + "layer_2_3_commands.html", "channel-group",
        ),
        CommandTopic.CHANNEL_GROUP_LACP: SourceRef(
            CR_3850 + "layer_2_3_commands.html", "channel-group",
        ),
        CommandTopic.SPEED: SourceRef(
            CR_3850 + "interface_and_hardware_commands.html", "speed",
        ),
        CommandTopic.DUPLEX: SourceRef(
            CR_3850 + "interface_and_hardware_commands.html", "duplex",
        ),
        CommandTopic.DESCRIPTION: SourceRef(
            CG_3850
            + "int_hw/b_1612_int_and_hw_3850_cg/"
            "configuring_interface_characteristics.html",
            "Adding a Description for an Interface",
        ),
        CommandTopic.ADMIN_SHUTDOWN: SourceRef(
            CG_3850
            + "int_hw/b_1612_int_and_hw_3850_cg/"
            "configuring_interface_characteristics.html",
            "Shutting Down and Restarting the Interface",
        ),
        CommandTopic.POE_MODE: SourceRef(
            CR_3850 + "interface_and_hardware_commands.html", "power inline",
        ),
    },
    notes={
        CommandTopic.SPEED: (
            "Gigabit Ethernet ports support all speed options; 10-Gigabit ports "
            "do not support the speed command.",
            "1000BASE-x SFP ports support the nonegotiate keyword.",
        ),
        CommandTopic.DUPLEX: (
            "Half duplex is only for 10/100 Mb/s operation.",
            "Duplex is not configurable on 10-Gigabit Ethernet ports.",
        ),
        CommandTopic.POE_MODE: (
            "power inline static is documented; max max-wattage 4000-30000 mW "
            "for the command reference, up to 60000 mW for UPOE ports.",
        ),
    },
    exclusion=(
        "16.12.10a permits aggregation rows only; interface rows need 16.12.12. "
        "Modular uplink and optic state remain field unknowns."
    ),
    parameter_overrides={},
)

S9200 = PlatformScope(
    family=DeviceFamily.CATALYST_9200,
    id_key="catalyst-9200",
    pids=(
        "C9200-24T", "C9200-24P", "C9200L-24T-4G", "C9200L-24T-4G-E",
        "C9200L-24P-4X", "C9200L-24P-4X-A",
    ),
    aggregation_releases=("17.12.4",),
    feature_releases=("17.12.4",),
    licenses=("Network Essentials", "Network Advantage"),
    channel_max=48,
    channel_basis="port-channel-number range is 1 to 48 (command reference)",
    ports_per_channel=(
        "Each EtherChannel can consist of up to eight compatibly configured "
        "Ethernet ports."
    ),
    sources={
        CommandTopic.VLAN: SourceRef(
            CR_9200 + "vlan_commands.html", "vlan",
        ),
        CommandTopic.VLAN_NAME: SourceRef(
            CR_9200 + "vlan_commands.html",
            "vlan (Usage Guidelines: name vlan-name)",
        ),
        CommandTopic.ACCESS_MODE: SourceRef(
            CG_9200 + "vlan/b_1712_vlan_9200_cg/configuring_vlans.html",
            "Assigning Static-Access Ports to a VLAN",
        ),
        CommandTopic.ACCESS_VLAN: SourceRef(
            CG_9200 + "vlan/b_1712_vlan_9200_cg/configuring_vlans.html",
            "Assigning Static-Access Ports to a VLAN",
        ),
        CommandTopic.TRUNK_MODE: SourceRef(
            CG_9200 + "vlan/b_1712_vlan_9200_cg/configuring_vlan_trunks.html",
            "Layer 2 Interface Modes",
        ),
        CommandTopic.NATIVE_VLAN: SourceRef(
            CR_9200 + "vlan_commands.html", "switchport trunk",
        ),
        CommandTopic.ALLOWED_VLANS: SourceRef(
            CR_9200 + "vlan_commands.html", "switchport trunk",
        ),
        CommandTopic.PORT_CHANNEL_INTERFACE: SourceRef(
            CR_9200 + "layer_2_3_commands.html", "interface port-channel",
        ),
        CommandTopic.CHANNEL_GROUP_STATIC: SourceRef(
            CR_9200 + "layer_2_3_commands.html", "channel-group",
        ),
        CommandTopic.CHANNEL_GROUP_LACP: SourceRef(
            CR_9200 + "layer_2_3_commands.html", "channel-group",
        ),
        CommandTopic.RAPID_PVST: SourceRef(
            CG_9200 + "lyr2/b_1712_lyr2_9200_cg/configuring_spanning_tree_protocol.html",
            "Changing the Spanning-Tree Mode",
        ),
        CommandTopic.VTP_TRANSPARENT: SourceRef(
            CR_9200 + "vlan_commands.html", "vtp (global configuration)",
        ),
        CommandTopic.ROOT_PRIORITY: SourceRef(
            CG_9200 + "lyr2/b_1712_lyr2_9200_cg/configuring_spanning_tree_protocol.html",
            "(Optional) Configuring the Device Priority of a VLAN",
        ),
        CommandTopic.PORTFAST: SourceRef(
            CG_9200
            + "lyr2/b_1712_lyr2_9200_cg/configuring_optional_spanning_tree_features.html",
            "(Optional) Enabling PortFast",
        ),
        CommandTopic.BPDU_GUARD: SourceRef(
            CG_9200
            + "lyr2/b_1712_lyr2_9200_cg/configuring_optional_spanning_tree_features.html",
            "(Optional) Enabling Bridge Protocol Data Unit Guard",
        ),
        CommandTopic.POE_MODE: SourceRef(
            CG_9200 + "int_hw/b_1712_int_and_hw_9200_cg/configuring_poe.html",
            "Configuring a Power Management Mode on a PoE Port",
        ),
        CommandTopic.SPEED: SourceRef(
            CG_9200
            + "int_hw/b_1712_int_and_hw_9200_cg/"
            "configuring_interface_characteristics.html",
            "Setting the Interface Speed and Duplex Parameters",
        ),
        CommandTopic.DUPLEX: SourceRef(
            CR_9200 + "interface_and_hardware_commands.html", "duplex",
        ),
        CommandTopic.DESCRIPTION: SourceRef(
            CG_9200
            + "int_hw/b_1712_int_and_hw_9200_cg/"
            "configuring_interface_characteristics.html",
            "Example: Adding a Description to an Interface",
        ),
        CommandTopic.ADMIN_SHUTDOWN: SourceRef(
            CG_9200
            + "int_hw/b_1712_int_and_hw_9200_cg/"
            "configuring_interface_characteristics.html",
            "Shutting Down and Restarting an Interface",
        ),
    },
    notes={
        CommandTopic.VLAN: (
            "VLAN ids 1-4094; normal range 1-1005 and extended range 1006-4094.",
            "VLAN numbers 1002-1005 are the FDDI and Token Ring default VLANs.",
        ),
        CommandTopic.VLAN_NAME: (
            "Documented ASCII string of 1-32 characters, unique in the domain.",
            "The VTP guide also states 20 characters for VTP v1/v2 and 128 for "
            "VTP v3; the command reference 32-character bound is the reviewed one.",
        ),
        CommandTopic.TRUNK_MODE: (
            "The default Layer 2 mode is dynamic auto, so trunk mode is explicit.",
        ),
        CommandTopic.NATIVE_VLAN: (
            "The 17.12 VLAN configuration guide states the "
            "switchport trunk native vlan command is not supported while the "
            "command reference documents it; the contradiction is unresolved and "
            "the row cannot render.",
        ),
        CommandTopic.ALLOWED_VLANS: (
            "Documented vlan-list form: add, remove, except, all, none, or an "
            "explicit comma-separated list.",
        ),
        CommandTopic.ROOT_PRIORITY: (
            "Priority range 0-61440 in increments of 4096; default 32768.",
        ),
        CommandTopic.PORTFAST: (
            "spanning-tree portfast trunk is required on trunk ports.",
        ),
        CommandTopic.BPDU_GUARD: (
            "Only the enable form is printed by the reviewed page; the disable "
            "form is not confirmed for this release.",
        ),
        CommandTopic.POE_MODE: (
            "Modes auto, static and never; auto is the default.",
            "No PoE budget, class or cable evidence is available offline.",
        ),
        CommandTopic.SPEED: (
            "Only configuration examples speed 10 and speed 100 are printed by the "
            "reviewed page; the full usage line was not visible.",
            "SFP/SFP+ ports support only nonegotiate forms.",
        ),
        CommandTopic.DUPLEX: (
            "Half duplex cannot be configured at 1000/10000/2500/5000 Mb/s.",
            "Duplex is not supported on 1000BASE-x or 10GBASE-x SFP modules.",
        ),
        CommandTopic.DESCRIPTION: (
            "The reviewed guide prints only the example "
            "'description Connects to Marketing'; the 240-character bound is the "
            "CIS-02B2 contract citation and must be re-confirmed by the reviewer.",
        ),
        CommandTopic.CHANNEL_GROUP_LACP: (
            "Active initiates LACP negotiation; passive only responds.",
        ),
    },
    exclusion=(
        "17.12.5 is identity-only. Modular C9200 uplink modules and optics "
        "require field evidence."
    ),
    parameter_overrides={
        CommandTopic.PORTFAST: (
            _enum(
                "portfast", ("edge", "edge-trunk"),
                "The disable form is not confirmed for this release.",
            ),
        ),
        CommandTopic.BPDU_GUARD: (
            _enum(
                "bpdu-guard", ("enable",),
                "The disable form is not confirmed for this release.",
            ),
        ),
    },
)

S9300 = PlatformScope(
    family=DeviceFamily.CATALYST_9300,
    id_key="catalyst-9300",
    pids=(
        "C9300-24T", "C9300-24P", "C9300L-24T-4G", "C9300L-24T-4G-E",
        "C9300L-24P-4X", "C9300L-24P-4X-E", "C9300X-24Y", "C9300X-24Y-A",
    ),
    aggregation_releases=("17.12.4",),
    feature_releases=("17.12.4",),
    licenses=("Network Essentials", "Network Advantage"),
    channel_max=128,
    channel_basis="port-channel-number range is 1 to 128 (command reference)",
    ports_per_channel=(
        "Each EtherChannel can consist of up to eight compatibly configured "
        "Ethernet ports."
    ),
    sources={
        CommandTopic.VLAN: SourceRef(CR_9300 + "vlan_commands.html", "vlan"),
        CommandTopic.VLAN_NAME: SourceRef(
            CR_9300 + "vlan_commands.html",
            "vlan (Usage Guidelines: name vlan-name)",
        ),
        CommandTopic.ACCESS_MODE: SourceRef(
            CG_9300 + "vlan/b_1712_vlan_9300_cg/configuring_vlans.html",
            "Assigning Static-Access Ports to a VLAN",
        ),
        CommandTopic.ACCESS_VLAN: SourceRef(
            CG_9300 + "vlan/b_1712_vlan_9300_cg/configuring_vlans.html",
            "Assigning Static-Access Ports to a VLAN",
        ),
        CommandTopic.TRUNK_MODE: SourceRef(
            CG_9300 + "vlan/b_1712_vlan_9300_cg/configuring_vlan_trunks.html",
            "Layer 2 Interface Modes",
        ),
        CommandTopic.NATIVE_VLAN: SourceRef(
            CR_9300 + "vlan_commands.html", "switchport trunk",
        ),
        CommandTopic.ALLOWED_VLANS: SourceRef(
            CR_9300 + "vlan_commands.html", "switchport trunk",
        ),
        CommandTopic.PORT_CHANNEL_INTERFACE: SourceRef(
            CR_9300 + "layer_2_3_commands.html", "interface port-channel",
        ),
        CommandTopic.CHANNEL_GROUP_STATIC: SourceRef(
            CR_9300 + "layer_2_3_commands.html", "channel-group",
        ),
        CommandTopic.CHANNEL_GROUP_LACP: SourceRef(
            CR_9300 + "layer_2_3_commands.html", "channel-group",
        ),
        CommandTopic.RAPID_PVST: SourceRef(
            CG_9300 + "lyr2/b_1712_lyr2_9300_cg/configuring_spanning_tree_protocol.html",
            "Changing the Spanning-Tree Mode",
        ),
        CommandTopic.VTP_TRANSPARENT: SourceRef(
            CR_9300 + "vlan_commands.html", "vtp (global configuration)",
        ),
        CommandTopic.ROOT_PRIORITY: SourceRef(
            CG_9300 + "lyr2/b_1712_lyr2_9300_cg/configuring_spanning_tree_protocol.html",
            "(Optional) Configuring the Device Priority of a VLAN",
        ),
        CommandTopic.PORTFAST: SourceRef(
            CG_9300
            + "lyr2/b_1712_lyr2_9300_cg/configuring_optional_spanning_tree_features.html",
            "(Optional) Enabling PortFast",
        ),
        CommandTopic.BPDU_GUARD: SourceRef(
            CG_9300
            + "lyr2/b_1712_lyr2_9300_cg/configuring_optional_spanning_tree_features.html",
            "(Optional) Enabling Bridge Protocol Data Unit Guard",
        ),
        CommandTopic.POE_MODE: SourceRef(
            CG_9300 + "int_hw/b_1712_int_and_hw_9300_cg/configuring_poe.html",
            "Configuring a Power Management Mode on a PoE Port",
        ),
        CommandTopic.SPEED: SourceRef(
            CG_9300
            + "int_hw/b_1712_int_and_hw_9300_cg/"
            "configuring_interface_characteristics.html",
            "Setting the Interface Speed and Duplex Parameters",
        ),
        CommandTopic.DUPLEX: SourceRef(
            CR_9300 + "interface_and_hardware_commands.html", "duplex",
        ),
        CommandTopic.DESCRIPTION: SourceRef(
            CG_9300
            + "int_hw/b_1712_int_and_hw_9300_cg/"
            "configuring_interface_characteristics.html",
            "Example: Adding a Description to an Interface",
        ),
        CommandTopic.ADMIN_SHUTDOWN: SourceRef(
            CG_9300
            + "int_hw/b_1712_int_and_hw_9300_cg/"
            "configuring_interface_characteristics.html",
            "Shutting Down and Restarting an Interface",
        ),
    },
    notes={
        CommandTopic.VLAN: (
            "VLAN ids 1-4094; normal range 1-1005 and extended range 1006-4094.",
            "VLAN numbers 1002-1005 are reserved for Token Ring and FDDI VLANs.",
        ),
        CommandTopic.VLAN_NAME: (
            "Documented ASCII string of 1-32 characters, unique in the domain.",
        ),
        CommandTopic.TRUNK_MODE: (
            "The default Layer 2 mode is dynamic auto, so trunk mode is explicit.",
        ),
        CommandTopic.NATIVE_VLAN: (
            "Native VLAN change is a topology-wide risk and is never rendered "
            "without field topology evidence.",
        ),
        CommandTopic.ALLOWED_VLANS: (
            "Documented vlan-list form: add, remove, except, all, none, or an "
            "explicit comma-separated list.",
        ),
        CommandTopic.ROOT_PRIORITY: (
            "Priority range 0-61440 in increments of 4096; default 32768.",
        ),
        CommandTopic.PORTFAST: (
            "spanning-tree portfast trunk is required on trunk ports.",
        ),
        CommandTopic.BPDU_GUARD: (
            "Only the enable form is printed by the reviewed page; the disable "
            "form is not confirmed for this release.",
        ),
        CommandTopic.POE_MODE: (
            "Modes auto, static and never; auto is the default.",
            "No PoE budget, class or cable evidence is available offline.",
        ),
        CommandTopic.SPEED: (
            "The reviewed page prints configuration examples only; the full usage "
            "line was not visible.",
        ),
        CommandTopic.DUPLEX: (
            "Half duplex cannot be configured at 1000/10000/2500/5000 Mb/s.",
        ),
        CommandTopic.DESCRIPTION: (
            "Only the example description line is printed by the reviewed guide; "
            "the 240-character bound is the CIS-02B2 contract citation and must be "
            "re-confirmed by the reviewer.",
        ),
        CommandTopic.CHANNEL_GROUP_LACP: (
            "Active initiates LACP negotiation; passive only responds.",
        ),
    },
    exclusion=(
        "17.12.5 is identity-only. Modular uplink modules, optics and StackWise "
        "hardware require field evidence."
    ),
    parameter_overrides={
        # The 17.12.4 Catalyst 9300 command reference prints both
        # ``spanning-tree bpduguard {enable | disable}``, so both forms stay
        # eligible. The PortFast ``disable`` form is not confirmed.
        CommandTopic.PORTFAST: (
            _enum(
                "portfast", ("edge", "edge-trunk"),
                "The disable form is not confirmed for this release.",
            ),
        ),
        # The cited command reference documents 1-128, but other 17.12 Catalyst
        # 9300 pages state 1-48. The renderer accepts only the intersection until
        # that contradiction is resolved by an independent re-review.
        CommandTopic.PORT_CHANNEL_INTERFACE: (
            channel_rule(48),
        ),
        CommandTopic.CHANNEL_GROUP_STATIC: (channel_rule(48),),
        CommandTopic.CHANNEL_GROUP_LACP: (channel_rule(48),),
    },
)

SC1000 = PlatformScope(
    family=DeviceFamily.CATALYST_C1000,
    id_key="catalyst-c1000",
    pids=("C1000-24T-4G-L", "C1000-24P-4G-L"),
    aggregation_releases=("15.2(7)E1",),
    feature_releases=("15.2(7)E1",),
    licenses=(),
    channel_max=6,
    channel_basis="channel-group-number range is 1 to 6; six EtherChannels maximum",
    ports_per_channel="",
    sources={
        CommandTopic.PORT_CHANNEL_INTERFACE: SourceRef(
            CR_C1000 + "layer_2_commands.html", "interface port-channel",
        ),
        CommandTopic.CHANNEL_GROUP_STATIC: SourceRef(
            CR_C1000 + "layer_2_commands.html", "channel-group",
        ),
        CommandTopic.CHANNEL_GROUP_LACP: SourceRef(
            CR_C1000 + "layer_2_commands.html", "channel-group",
        ),
        CommandTopic.SPEED: SourceRef(
            CR_C1000 + "interface_and_hardware_commands.html", "speed",
        ),
        CommandTopic.DUPLEX: SourceRef(
            CR_C1000 + "interface_and_hardware_commands.html", "duplex",
        ),
        CommandTopic.DESCRIPTION: SourceRef(
            CG_C1000
            + "int_hw/b_1527e_int_and_hw_c1000_cg/"
            "configuring_interface_characteristics.html",
            "Adding a Description for an Interface",
        ),
        CommandTopic.ADMIN_SHUTDOWN: SourceRef(
            CG_C1000
            + "int_hw/b_1527e_int_and_hw_c1000_cg/"
            "configuring_interface_characteristics.html",
            "Shutting Down and Restarting the Interface",
        ),
        CommandTopic.POE_MODE: SourceRef(
            CR_C1000 + "interface_and_hardware_commands.html", "power inline",
        ),
    },
    notes={
        CommandTopic.SPEED: (
            "Documented form: speed {10 | 100 | 1000 | auto [10 | 100 | 1000]}.",
            "speed is not supported on 10-Gigabit interfaces.",
        ),
        CommandTopic.DUPLEX: (
            "Half duplex is only for 10/100 Mb/s operation.",
            "Duplex options are not supported on 1000BASE-x or 10GBASE-x SFP modules.",
        ),
        CommandTopic.POE_MODE: (
            "power inline static is documented; max max-wattage 4000-30000 mW.",
            "The command is supported only on PoE-capable ports.",
        ),

    },
    exclusion=(
        "No reviewed Stack layout. Bare 15.2(7)E is not reviewed; an explicit "
        "license claim is unverified for the stock image."
    ),
    parameter_overrides={},
)

SCOPES: tuple[PlatformScope, ...] = (
    S2960X_LANBASE, S2960X_LANLITE, S3850, S9200, S9300, SC1000,
)


# --------------------------------------------------------------------------- #
# Row builders
# --------------------------------------------------------------------------- #

_CHANNEL_TOPICS: tuple[CommandTopic, ...] = (
    CommandTopic.PORT_CHANNEL_INTERFACE,
    CommandTopic.CHANNEL_GROUP_STATIC,
    CommandTopic.CHANNEL_GROUP_LACP,
)
_INTERFACE_TOPICS: tuple[CommandTopic, ...] = (
    CommandTopic.SPEED,
    CommandTopic.DUPLEX,
    CommandTopic.DESCRIPTION,
    CommandTopic.ADMIN_SHUTDOWN,
    CommandTopic.POE_MODE,
)
_L2_TOPICS: tuple[CommandTopic, ...] = (
    CommandTopic.VLAN,
    CommandTopic.VLAN_NAME,
    CommandTopic.ACCESS_MODE,
    CommandTopic.ACCESS_VLAN,
    CommandTopic.TRUNK_MODE,
    CommandTopic.NATIVE_VLAN,
    CommandTopic.ALLOWED_VLANS,
    CommandTopic.RAPID_PVST,
    CommandTopic.VTP_TRANSPARENT,
    CommandTopic.ROOT_PRIORITY,
    CommandTopic.PORTFAST,
    CommandTopic.BPDU_GUARD,
)

_GRAMMAR: Mapping[CommandTopic, tuple[str, str, CommandMode]] = {
    CommandTopic.VLAN: ("vlan", "vlan vlan-id", CommandMode.GLOBAL),
    CommandTopic.VLAN_NAME: ("name", "name vlan-name", CommandMode.VLAN),
    CommandTopic.ACCESS_MODE: (
        "switchport mode", "switchport mode access", CommandMode.INTERFACE,
    ),
    CommandTopic.ACCESS_VLAN: (
        "switchport access vlan", "switchport access vlan vlan-id",
        CommandMode.INTERFACE,
    ),
    CommandTopic.TRUNK_MODE: (
        "switchport mode", "switchport mode trunk", CommandMode.INTERFACE,
    ),
    CommandTopic.NATIVE_VLAN: (
        "switchport trunk native vlan", "switchport trunk native vlan vlan-id",
        CommandMode.INTERFACE,
    ),
    CommandTopic.ALLOWED_VLANS: (
        "switchport trunk allowed vlan", "switchport trunk allowed vlan vlan-list",
        CommandMode.INTERFACE,
    ),
    CommandTopic.PORT_CHANNEL_INTERFACE: (
        "interface Port-Channel", "interface Port-Channel port-channel-number",
        CommandMode.GLOBAL,
    ),
    CommandTopic.CHANNEL_GROUP_STATIC: (
        "channel-group ... mode on", "channel-group channel-group-number mode on",
        CommandMode.INTERFACE,
    ),
    CommandTopic.CHANNEL_GROUP_LACP: (
        "channel-group ... mode active|passive",
        "channel-group channel-group-number mode {active | passive}",
        CommandMode.INTERFACE,
    ),
    CommandTopic.RAPID_PVST: (
        "spanning-tree mode", "spanning-tree mode rapid-pvst", CommandMode.GLOBAL,
    ),
    CommandTopic.VTP_TRANSPARENT: (
        "vtp mode", "vtp mode transparent", CommandMode.GLOBAL,
    ),
    CommandTopic.ROOT_PRIORITY: (
        "spanning-tree vlan ... priority", "spanning-tree vlan vlan-id priority priority",
        CommandMode.GLOBAL,
    ),
    CommandTopic.PORTFAST: (
        "spanning-tree portfast", "spanning-tree portfast [trunk]",
        CommandMode.INTERFACE,
    ),
    CommandTopic.BPDU_GUARD: (
        "spanning-tree bpduguard", "spanning-tree bpduguard enable",
        CommandMode.INTERFACE,
    ),
    CommandTopic.POE_MODE: (
        "power inline", "power inline {auto | static | never}", CommandMode.INTERFACE,
    ),
    CommandTopic.SPEED: (
        "speed", "speed {10 | 100 | 1000 | auto}", CommandMode.INTERFACE,
    ),
    CommandTopic.DUPLEX: (
        "duplex", "duplex {full | half | auto}", CommandMode.INTERFACE,
    ),
    CommandTopic.DESCRIPTION: (
        "description", "description string", CommandMode.INTERFACE,
    ),
    CommandTopic.ADMIN_SHUTDOWN: (
        "shutdown", "shutdown / no shutdown", CommandMode.INTERFACE,
    ),
}

_DEFAULT_PARAMETERS: Mapping[CommandTopic, tuple[ParameterRule, ...]] = {
    CommandTopic.VLAN: (VLAN_ID,),
    CommandTopic.VLAN_NAME: (VLAN_NAME,),
    CommandTopic.ACCESS_MODE: (),
    CommandTopic.ACCESS_VLAN: (VLAN_ID,),
    CommandTopic.TRUNK_MODE: (),
    CommandTopic.NATIVE_VLAN: (VLAN_ID,),
    CommandTopic.ALLOWED_VLANS: (TRUNK_VLAN_LIST,),
    CommandTopic.PORT_CHANNEL_INTERFACE: (),
    CommandTopic.CHANNEL_GROUP_STATIC: (_enum("mode", ("on",)),),
    CommandTopic.CHANNEL_GROUP_LACP: (_enum("mode", ("active", "passive")),),
    CommandTopic.RAPID_PVST: (),
    CommandTopic.VTP_TRANSPARENT: (),
    CommandTopic.ROOT_PRIORITY: (VLAN_ID, PRIORITY),
    CommandTopic.PORTFAST: (_enum("portfast", ("edge", "edge-trunk", "disabled")),),
    CommandTopic.BPDU_GUARD: (_enum("bpdu-guard", ("enable", "disable")),),
    CommandTopic.POE_MODE: (_enum("poe-mode", ("auto", "static", "never")),),
    CommandTopic.SPEED: (_enum("speed", ("10", "100", "1000", "auto")),),
    CommandTopic.DUPLEX: (_enum("duplex", ("full", "half", "auto")),),
    CommandTopic.DESCRIPTION: (DESCRIPTION,),
    CommandTopic.ADMIN_SHUTDOWN: (_enum("admin-state", ("up", "down")),),
}

_TOPIC_EXCLUSIONS: Mapping[CommandTopic, tuple[str, ...]] = {
    CommandTopic.VLAN: ("VLAN deletion is never rendered.",),
    CommandTopic.VLAN_NAME: ("Exiting VLAN configuration is not a candidate.",),
    CommandTopic.ACCESS_MODE: (
        "A routed port is never converted to a switchport.",
    ),
    CommandTopic.ACCESS_VLAN: (
        "Access VLAN and access mode are separate commands.",
        "Access VLAN 1 is the platform default and needs no candidate.",
    ),
    CommandTopic.TRUNK_MODE: (
        "Trunk-to-access transitions need cleanup and topology evidence.",
    ),
    CommandTopic.NATIVE_VLAN: (
        "Native VLAN change is R5 and needs field topology evidence.",
    ),
    CommandTopic.ALLOWED_VLANS: (
        "add/remove/except forms are not rendered in B2-02.",
    ),
    CommandTopic.PORT_CHANNEL_INTERFACE: (
        "Routed Port-Channels are never converted to L2.",
    ),
    CommandTopic.CHANNEL_GROUP_STATIC: (
        "Static aggregation is never reported as LACP.",
    ),
    CommandTopic.CHANNEL_GROUP_LACP: (
        "auto/desirable PAgP modes are not reviewed.",
    ),
    CommandTopic.RAPID_PVST: (
        "Topology, current root and uplink role must be confirmed first.",
    ),
    CommandTopic.VTP_TRANSPARENT: (
        "Current VTP mode and domain are unknown offline.",
        "Transparent mode changes local VLAN-database behaviour; it is not a claim "
        "that all VTP traffic stops.",
    ),
    CommandTopic.ROOT_PRIORITY: (
        "A single device priority does not identify the affected VLANs.",
        "Root-bridge election impact requires field review.",
    ),
    CommandTopic.PORTFAST: (
        "PortFast on a non-edge port is a topology risk.",
    ),
    CommandTopic.BPDU_GUARD: (
        "Err-disable recovery policy is a field prerequisite.",
    ),
    CommandTopic.POE_MODE: (
        "Power budget, PoE class and cable state remain field unknowns.",
    ),
    CommandTopic.SPEED: (
        "Fiber/SFP port speed requires installed-optic evidence.",
    ),
    CommandTopic.DUPLEX: (
        "Duplex on an optic port requires installed-optic evidence.",
    ),
    CommandTopic.DESCRIPTION: (
        "Clearing a description is cleanup and is not rendered.",
    ),
    CommandTopic.ADMIN_SHUTDOWN: (
        "Shutdown of a management/uplink port needs topology evidence.",
    ),
}


def _parameters(scope: PlatformScope, topic: CommandTopic) -> tuple[ParameterRule, ...]:
    base: list[ParameterRule] = list(_DEFAULT_PARAMETERS[topic])
    if topic in {
        CommandTopic.PORT_CHANNEL_INTERFACE,
        CommandTopic.CHANNEL_GROUP_STATIC,
        CommandTopic.CHANNEL_GROUP_LACP,
    }:
        base.insert(0, channel_rule(scope.channel_max))
    override = scope.parameter_overrides.get(topic)
    if override is not None:
        replaced = {rule.name for rule in override}
        base = [*override, *(rule for rule in base if rule.name not in replaced)]
    return tuple(base)


def _limits(scope: PlatformScope, topic: CommandTopic) -> tuple[str, ...]:
    base: tuple[str, ...]
    if topic is CommandTopic.PORT_CHANNEL_INTERFACE:
        base = (
            f"{scope.channel_basis}.",
            f"{scope.ports_per_channel}",
            "Creates the logical Port-Channel interface.",
        )
    elif topic in {
        CommandTopic.CHANNEL_GROUP_STATIC, CommandTopic.CHANNEL_GROUP_LACP,
    }:
        base = (f"{scope.channel_basis}.", f"{scope.ports_per_channel}")
    elif topic is CommandTopic.SPEED:
        base = ("Documented speed command for the reviewed release.",)
    elif topic is CommandTopic.DUPLEX:
        base = ("Documented duplex command for the reviewed release.",)
    elif topic is CommandTopic.DESCRIPTION:
        base = ("Documented single-line interface description.",)
    elif topic is CommandTopic.ADMIN_SHUTDOWN:
        base = ("Administrative state only; link protocol state is not implied.",)
    elif topic is CommandTopic.POE_MODE:
        base = ("Command evidence is separate from the hardware PoE rating.",)
    elif topic is CommandTopic.VLAN:
        base = ("VLAN ids 1-4094.",)
    elif topic is CommandTopic.VLAN_NAME:
        base = ("VLAN name is a 1-32 character ASCII string.",)
    elif topic is CommandTopic.ROOT_PRIORITY:
        base = ("Priority must be a multiple of 4096.",)
    elif topic is CommandTopic.RAPID_PVST:
        base = ("Topology-wide STP mode; never R0.",)
    elif topic is CommandTopic.VTP_TRANSPARENT:
        base = ("Changes the local VLAN database and propagation behaviour.",)
    elif topic is CommandTopic.PORTFAST:
        base = ("Edge and edge-trunk forms are the reviewed PortFast forms.",)
    elif topic is CommandTopic.BPDU_GUARD:
        base = ("BPDU Guard err-disables a port that receives BPDUs.",)
    elif topic is CommandTopic.NATIVE_VLAN:
        base = ("Native VLAN 1 is the platform default.",)
    elif topic is CommandTopic.ALLOWED_VLANS:
        base = ("Explicit VLAN list; the native VLAN is unaffected.",)
    else:
        base = ("Layer 2 switchport command only.",)
    combined = (*base, *scope.notes.get(topic, ()))
    return tuple(value for value in combined if value)


def _rows_for(
    scope: PlatformScope, topics: tuple[CommandTopic, ...], releases: tuple[str, ...],
) -> tuple[CommandEvidence, ...]:
    rows: list[CommandEvidence] = []
    for topic in topics:
        source = scope.sources.get(topic)
        if source is None:
            # No reviewed vendor page for this exact scope: the category stays
            # blocked instead of inheriting another family's command evidence.
            continue
        command, grammar, mode = _GRAMMAR[topic]
        rows.append(CommandEvidence(
            evidence_id=f"l1-{scope.id_key}-{topic.value}-v1",
            family=scope.family,
            pids=scope.pids,
            releases=releases,
            licenses=scope.licenses,
            topic=topic,
            command=command,
            grammar=grammar,
            command_mode=mode,
            parameters=_parameters(scope, topic),
            limits=_limits(scope, topic),
            source_url=source.url,
            source_section=source.section,
            exclusions=(scope.exclusion, *_TOPIC_EXCLUSIONS[topic]),
        ))
    return tuple(rows)


_DRAFT_ROWS: tuple[CommandEvidence, ...] = tuple(
    row
    for scope in SCOPES
    for row in (
        *_rows_for(scope, _CHANNEL_TOPICS, scope.aggregation_releases),
        *_rows_for(scope, _INTERFACE_TOPICS, scope.feature_releases),
        *(()
          if scope.aggregation_only
          else _rows_for(scope, _L2_TOPICS, scope.feature_releases)),
    )
)

# Independent review attestations, keyed by evidence ID. A row absent from both
# tables keeps ``PENDING_REVIEW`` and therefore can never render text.
def _attestation(
    record: Mapping[str, object], state: EvidenceReviewState,
) -> EvidenceReview:
    findings = record.get("findings")
    if not isinstance(findings, tuple):
        raise TypeError("A review record needs a findings tuple")
    return EvidenceReview(
        state,
        str(record.get("reviewer", "")),
        str(record.get("reviewed_at", "")),
        tuple(str(finding) for finding in findings),
    )


REVIEWS: dict[str, EvidenceReview] = {
    evidence_id: _attestation(record, EvidenceReviewState.REVIEWED)
    for evidence_id, record in REVIEWED_RECORDS.items()
}
REJECTIONS: dict[str, EvidenceReview] = {
    evidence_id: _attestation(record, EvidenceReviewState.REJECTED)
    for evidence_id, record in REJECTED_RECORDS.items()
}


def _with_reviews() -> tuple[CommandEvidence, ...]:
    rows: list[CommandEvidence] = []
    for row in _DRAFT_ROWS:
        review = REVIEWS.get(row.evidence_id) or REJECTIONS.get(row.evidence_id)
        rows.append(replace(row, review=review) if review is not None else row)
    ids = [row.evidence_id for row in rows]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate command-evidence IDs")
    return tuple(rows)


ROWS: tuple[CommandEvidence, ...] = _with_reviews()


class CommandEvidenceRegistry:
    """Version-scoped lookup over reviewed L1 command evidence."""

    def __init__(self, rows: tuple[CommandEvidence, ...]) -> None:
        self._rows = rows
        self._by_id = {row.evidence_id: row for row in rows}

    @property
    def rows(self) -> tuple[CommandEvidence, ...]:
        return self._rows

    @property
    def fingerprint_rows(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (row.evidence_id, row.review.state.value)
            for row in sorted(self._rows, key=lambda item: item.evidence_id)
        )

    def get(self, evidence_id: str) -> CommandEvidence | None:
        return self._by_id.get(evidence_id)

    def applicable(
        self,
        family: DeviceFamily,
        pid: str,
        release: str,
        license_name: str | None,
        topic: CommandTopic,
    ) -> tuple[CommandEvidence, ...]:
        """Return rows that bind to this exact PID, release and license scope."""
        normalized_pid = pid.upper()
        normalized_license = (license_name or "").casefold()
        return tuple(
            row for row in self._rows
            if row.family is family
            and normalized_pid in {value.upper() for value in row.pids}
            and release.casefold() in {value.casefold() for value in row.releases}
            and normalized_license in {
                value.casefold() for value in (row.licenses or ("",))
            }
            and row.topic is topic
        )

    def renderable(
        self,
        family: DeviceFamily,
        pid: str,
        release: str,
        license_name: str | None,
        topic: CommandTopic,
    ) -> CommandEvidence | None:
        """Return the single reviewed row allowed to render, or ``None``."""
        candidates = tuple(
            row for row in self.applicable(family, pid, release, license_name, topic)
            if row.renderable
        )
        return candidates[0] if len(candidates) == 1 else None

    def blocker(
        self,
        family: DeviceFamily,
        pid: str,
        release: str,
        license_name: str | None,
        topic: CommandTopic,
    ) -> str:
        """Deterministic reason code explaining why a topic cannot render."""
        rows = self.applicable(family, pid, release, license_name, topic)
        if not rows:
            return f"syntax-evidence-missing:{topic.value}"
        if any(row.review.state is EvidenceReviewState.REJECTED for row in rows):
            return f"syntax-evidence-rejected:{topic.value}"
        return f"syntax-evidence-not-reviewed:{topic.value}"


DEFAULT_REGISTRY = CommandEvidenceRegistry(ROWS)


def evidence_reference(registry: CommandEvidenceRegistry) -> Mapping[str, object]:
    """Stable description of the registry version used by one render."""
    return {
        "registry_id": EVIDENCE_REGISTRY_ID,
        "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
        "rows": len(registry.rows),
        "reviewed_rows": sum(1 for row in registry.rows if row.renderable),
        "row_versions": [list(item) for item in registry.fingerprint_rows],
    }


__all__ = [
    "DEFAULT_REGISTRY",
    "EVIDENCE_REGISTRY_ID",
    "EVIDENCE_SCHEMA_VERSION",
    "PENDING_REVIEW",
    "REJECTIONS",
    "REJECTED_REVIEW",
    "REVIEWS",
    "ROWS",
    "SCOPES",
    "CommandEvidence",
    "CommandEvidenceRegistry",
    "CommandMode",
    "CommandTopic",
    "EvidenceReview",
    "EvidenceReviewState",
    "ParameterRule",
    "PlatformScope",
    "SourceRef",
    "evidence_reference",
]
