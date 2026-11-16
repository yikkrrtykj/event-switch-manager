"""Cisco document scopes for selected, exact chassis PIDs."""

from dataclasses import dataclass
from enum import StrEnum

from .domain import DeviceFamily
from .integrations import Capability

CISCO = "https://www.cisco.com/c/en/us/"
DATA = CISCO + "products/collateral/switches/"
GUIDE = CISCO + "td/docs/switches/lan/"
G2960 = GUIDE + "catalyst2960x/software/15-2_7_e/configuration_guide/b_1527e_consolidated_2960x_cg/"
G3850 = GUIDE + "catalyst3850/software/release/16-12/configuration_guide/"
G9200 = GUIDE + "catalyst9200/software/release/17-12/configuration_guide/"
G9300 = GUIDE + "catalyst9300/software/release/17-12/configuration_guide/"
G1000 = GUIDE + "catalyst1000/software/releases/15_2_7_e/configuration_guides/"

D2960 = DATA + "catalyst-2960-x-series-switches/datasheet_c78-728232.html"
D3850 = DATA + "catalyst-3850-series-switches/datasheet_c78-720918.html"
D9200 = DATA + "catalyst-9200-series-switches/nb-06-cat9200-ser-data-sheet-cte-en.html"
D9300 = DATA + "catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html"
D1000 = (
    GUIDE + "catalyst1000/hardware/installation/24_48_port_hig/"
    "b_c1000_24_48_hig/product_overview.html"
)
I2960 = G2960 + "m_int_inter_cg.html"
I3850 = G3850 + "int_hw/b_1612_int_and_hw_3850_cg/configuring_interface_characteristics.html"
I9200 = G9200 + "int_hw/b_1712_int_and_hw_9200_cg/configuring_interface_characteristics.html"
I9300 = G9300 + "int_hw/b_1712_int_and_hw_9300_cg/configuring_interface_characteristics.html"
I1000 = G1000 + "int_hw/b_1527e_int_and_hw_c1000_cg/configuring_interface_characteristics.html"


@dataclass(frozen=True, slots=True)
class Source:
    url: str
    section: str


class Medium(StrEnum):
    COPPER = "copper-rj45"
    SFP = "sfp"
    SFP_PLUS = "sfp-plus"
    SFP28 = "sfp28"


@dataclass(frozen=True, slots=True)
class PortGroup:
    medium: Medium
    slot: int
    first: int
    count: int
    prefix: str
    rates: tuple[int, ...]
    poe_plus: bool = False


@dataclass(frozen=True, slots=True)
class Profile:
    family: DeviceFamily
    hardware: Source
    interfaces: str
    train: str
    version_pattern: str
    licenses: tuple[str, ...]
    ports: tuple[PortGroup, ...]
    stack_limit: int | None
    stack_conditions: str
    modular: bool = False


ESSENTIALS = "Network Essentials"
ADVANTAGE = "Network Advantage"
IOS_E = r"15\.2\(7\)E\d*"
XE_1712 = r"17\.12\.\d+[a-z]?"


def copper(poe: bool) -> PortGroup:
    return PortGroup(Medium.COPPER, 0, 1, 24, "gi", (10, 100, 1000), poe)


def sfp(count: int, slot: int = 1, first: int = 1) -> PortGroup:
    return PortGroup(Medium.SFP, slot, first, count, "gi", (1000,))


SFP_PLUS = PortGroup(Medium.SFP_PLUS, 1, 1, 4, "te", (1000, 10000))
SFP28 = PortGroup(Medium.SFP28, 0, 1, 24, "twe", (1000, 10000, 25000))


def x2960(poe: bool, lite: bool = False) -> Profile:
    return Profile(
        DeviceFamily.CATALYST_2960X, Source(D2960, "Switch models and FlexStack-Plus"), I2960,
        "IOS 15.2(7)Ex", IOS_E, ("LAN Lite",) if lite else ("LAN Base",),
        (copper(poe), sfp(2 if lite else 4, 0, 25)), 0 if lite else 8,
        "LAN Base requires FlexStack-Plus module and cabling. LAN Lite lacks FlexStack-Plus.",
    )


def x3850(poe: bool) -> Profile:
    return Profile(
        DeviceFamily.CATALYST_3850, Source(D3850, "Configurations and StackWise-480"), I3850,
        "IOS XE 16.12.x", r"16\.12\.\d+[a-z]?", ("LAN Base", "IP Base", "IP Services"),
        (copper(poe),), 9, "StackWise-480 cables and matching feature sets required.",
        modular=True,
    )


def x9200(poe: bool, fixed: PortGroup | None = None) -> Profile:
    return Profile(
        DeviceFamily.CATALYST_9200, Source(D9200, "Switch configurations and stacking"), I9200,
        "IOS XE 17.12.x", XE_1712, (ESSENTIALS, ADVANTAGE),
        (copper(poe), fixed) if fixed else (copper(poe),), 8,
        "Match license and StackWise kit. C9200L and modular C9200 use different StackWise.",
        modular=fixed is None,
    )


def x9300(ports: tuple[PortGroup, ...], *, modular: bool = False) -> Profile:
    return Profile(
        DeviceFamily.CATALYST_9300, Source(D9300, "Switch configurations and stacking"), I9300,
        "IOS XE 17.12.x", XE_1712, (ESSENTIALS, ADVANTAGE), ports, 8,
        "Match active license and use the StackWise hardware applicable to the model.",
        modular=modular,
    )


def x1000(poe: bool) -> Profile:
    return Profile(
        DeviceFamily.CATALYST_C1000, Source(D1000, "24-port and 48-port switch models"), I1000,
        "IOS 15.2(7)Ex", IOS_E, (), (copper(poe), sfp(4, 0, 25)), None,
        "Single IP Management requires a separate Stack layout rule.",
    )


# Ordering suffixes do not substitute for the active license.
PROFILES = {
    "WS-C2960X-24TS-L": x2960(False),
    "WS-C2960X-24PS-L": x2960(True),
    "WS-C2960X-24TS-LL": x2960(False, lite=True),
    "WS-C3850-24T": x3850(False),
    "WS-C3850-24P": x3850(True),
    "WS-C3850-24T-L": x3850(False),
    "WS-C3850-24P-S": x3850(True),
    "C9200-24T": x9200(False),
    "C9200-24P": x9200(True),
    "C9200L-24T-4G": x9200(False, sfp(4)),
    "C9200L-24T-4G-E": x9200(False, sfp(4)),
    "C9200L-24P-4X": x9200(True, SFP_PLUS),
    "C9200L-24P-4X-A": x9200(True, SFP_PLUS),
    "C9300-24T": x9300((copper(False),), modular=True),
    "C9300-24P": x9300((copper(True),), modular=True),
    "C9300L-24T-4G": x9300((copper(False), sfp(4))),
    "C9300L-24T-4G-E": x9300((copper(False), sfp(4))),
    "C9300L-24P-4X": x9300((copper(True), SFP_PLUS)),
    "C9300L-24P-4X-E": x9300((copper(True), SFP_PLUS)),
    "C9300X-24Y": x9300((SFP28,), modular=True),
    "C9300X-24Y-A": x9300((SFP28,), modular=True),
    "C1000-24T-4G-L": x1000(False),
    "C1000-24P-4G-L": x1000(True),
}


class CiscoCapability(StrEnum):
    IDENTITY = "identity"
    STACK = "stack"
    PORT_LAYOUT = "port-layout"
    PORT_MEDIA = "port-media"
    SPEED = "speed"
    DUPLEX = "duplex"
    POE_PLUS = "poe-plus"
    ACCESS = "access"
    TRUNK = "trunk"
    PORT_CHANNEL = "port-channel"
    PORTFAST = "portfast"
    BPDU_GUARD = "bpdu-guard"
    VTP_TRANSPARENT = "vtp-transparent"
    STATIC_ROUTE = "static-route"
    DEFAULT_ROUTE = "default-route"
    SSH_V2 = "ssh-v2"
    AAA = "aaa"
    BOOT = "boot"
    STORAGE = "storage"


type CapabilityId = Capability | CiscoCapability

L2_9300 = G9300 + "lyr2/b_1712_lyr2_9300_cg.pdf"
L2_9200 = G9200 + "lyr2/b_1712_lyr2_9200_cg.pdf"
L2_3850 = G3850 + "lyr2/b_1612_lyr2_3850_cg.pdf"
L2_1000 = G1000 + "lyr2/b_1527e_layer2_c1000_cg/configuring_etherchannels.html"
L2_2960 = (
    GUIDE + "catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr/"
    "layer_2_commands.html"
)
IP_9300 = G9300 + "rtng/b_1712_rtng_9300_cg/configuring_ip_unicast_routing.html"
DHCP_9300 = G9300 + "ip/b_1712_ip_9300_cg.pdf"
SEC_9300 = G9300 + "sec/b_1712_sec_9300_cg.pdf"
SYS_9300 = G9300 + "sys_mgmt/b_1712_sys_mgmt_9300_cg.pdf"
UPGRADE_9300 = (
    GUIDE + "catalyst9300/software/release/17-12/release_notes/ol-17-12-9300/"
    "upgrading_the_switch_software.html"
)


def aggregation(source: str, locator: str) -> dict[CapabilityId, Source]:
    return {
        Capability.LACP: Source(source, locator),
        CiscoCapability.PORT_CHANNEL: Source(source, locator),
    }


def modern_l2(source: str) -> dict[CapabilityId, Source]:
    return {
        **aggregation(source, "Configuring EtherChannels: LACP and Port-Channel interfaces"),
        Capability.VLAN: Source(source, "Configuring VLANs"),
        CiscoCapability.TRUNK: Source(source, "Configuring VLAN Trunks"),
        Capability.RAPID_PVST: Source(source, "Configuring STP: spanning-tree modes"),
        CiscoCapability.PORTFAST: Source(source, "Configuring Optional Spanning-Tree Features"),
        CiscoCapability.BPDU_GUARD: Source(source, "Configuring Optional Spanning-Tree Features"),
        CiscoCapability.VTP_TRANSPARENT: Source(source, "Configuring VTP: VTP modes"),
    }


FEATURES: dict[DeviceFamily, dict[CapabilityId, Source]] = {
    DeviceFamily.CATALYST_2960X: aggregation(L2_2960, "channel-group and LAN Lite limits"),
    DeviceFamily.CATALYST_3850: aggregation(L2_3850, "Configuring EtherChannels"),
    DeviceFamily.CATALYST_C1000: aggregation(L2_1000, "Layer 2 EtherChannels and LACP modes"),
    DeviceFamily.CATALYST_9200: {
        **modern_l2(L2_9200),
        CiscoCapability.ACCESS: Source(I9200, "Switch Ports"),
        Capability.SVI: Source(I9200, "Layer 3 Interfaces"),
        Capability.ROUTED_PORT: Source(I9200, "Routed Ports"),
        Capability.IPV4_ROUTING: Source(D9200, "High-performance IP routing"),
        CiscoCapability.STATIC_ROUTE: Source(D9200, "High-performance IP routing"),
    },
    DeviceFamily.CATALYST_9300: {
        **modern_l2(L2_9300),
        CiscoCapability.ACCESS: Source(I9300, "Switch Ports"),
        Capability.ROUTED_PORT: Source(I9300, "Routed Ports"),
        Capability.SVI: Source(I9300, "Layer 3 Interfaces"),
        Capability.IPV4_ROUTING: Source(IP_9300, "Enabling IP Unicast Routing"),
        CiscoCapability.STATIC_ROUTE: Source(IP_9300, "Configuring Static Unicast Routes"),
        CiscoCapability.DEFAULT_ROUTE: Source(IP_9300, "Configuring the Default Route"),
        Capability.DHCP_RELAY: Source(DHCP_9300, "Configuring the DHCP Relay Agent"),
        Capability.DHCP_SERVER: Source(DHCP_9300, "Configuring the DHCP Server"),
        Capability.DHCP_CLIENT: Source(DHCP_9300, "Configuring the DHCP Client"),
        CiscoCapability.SSH_V2: Source(SEC_9300, "Secure Shell Version 2 Support"),
        CiscoCapability.AAA: Source(SEC_9300, "Controlling Switch Access; AAA and TACACS+"),
        CiscoCapability.BOOT: Source(SYS_9300, "Software Boot Modes"),
        CiscoCapability.STORAGE: Source(UPGRADE_9300, "Upgrading in Install Mode: flash space"),
    },
}
