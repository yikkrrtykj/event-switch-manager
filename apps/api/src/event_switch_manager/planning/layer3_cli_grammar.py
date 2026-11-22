"""CIS-03-03B independent Catalyst 9300 L3 CLI grammar.

This module deliberately knows nothing about the CIS-03-03A renderer, the
command-evidence registry or the L2 grammar.  It is a small, deterministic
description of the six reviewed command forms and their parameter boundaries.
The parser consumes this module; the validator consumes the parser result.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network
from typing import Final

GRAMMAR_ID: Final = "cis-03-03b-independent-l3-cli-grammar-v1"

VLAN_MIN: Final = 1
VLAN_MAX: Final = 4094
RESERVED_VLANS: Final = frozenset({1, 1002, 1003, 1004, 1005})

SVI_PREFIX_MIN: Final = 1
SVI_PREFIX_MAX: Final = 30
ROUTE_PREFIX_MIN: Final = 0
ROUTE_PREFIX_MAX: Final = 32
DISTANCE_MIN: Final = 1
DISTANCE_MAX: Final = 255
SAFE_DISTANCE_MAX: Final = 254


class L3Form(StrEnum):
    IP_ROUTING = "ip-routing"
    SVI_INTERFACE = "svi-interface"
    SVI_ADDRESS = "svi-address"
    STATIC_ROUTE = "static-route"
    DEFAULT_ROUTE = "default-route"
    DHCP_HELPER_ADDRESS = "dhcp-helper-address"


class L3Mode(StrEnum):
    GLOBAL = "global"
    INTERFACE = "interface"


class L3TargetClass(StrEnum):
    DEVICE = "device"
    SVI = "svi"
    ROUTE = "route"


class L3RiskFloor(StrEnum):
    R2 = "R2"
    R3 = "R3"


@dataclass(frozen=True, slots=True)
class GrammarRule:
    form: L3Form
    syntax: str
    mode: L3Mode
    target_class: L3TargetClass
    risk_floor: L3RiskFloor
    token_min: int
    token_max: int


#: Independent form table.  It is not generated from renderer templates or
#: evidence-row grammar strings.
GRAMMAR_RULES: Final[tuple[GrammarRule, ...]] = (
    GrammarRule(
        L3Form.IP_ROUTING,
        "ip routing",
        L3Mode.GLOBAL,
        L3TargetClass.DEVICE,
        L3RiskFloor.R2,
        2,
        2,
    ),
    GrammarRule(
        L3Form.SVI_INTERFACE,
        "interface Vlan<vlan-id>",
        L3Mode.GLOBAL,
        L3TargetClass.SVI,
        L3RiskFloor.R2,
        2,
        2,
    ),
    GrammarRule(
        L3Form.SVI_ADDRESS,
        "ip address <address> <mask>",
        L3Mode.INTERFACE,
        L3TargetClass.SVI,
        L3RiskFloor.R2,
        4,
        4,
    ),
    GrammarRule(
        L3Form.STATIC_ROUTE,
        "ip route <prefix> <mask> <next-hop> [<distance>]",
        L3Mode.GLOBAL,
        L3TargetClass.ROUTE,
        L3RiskFloor.R2,
        5,
        6,
    ),
    GrammarRule(
        L3Form.DEFAULT_ROUTE,
        "ip route 0.0.0.0 0.0.0.0 <next-hop> [<distance>]",
        L3Mode.GLOBAL,
        L3TargetClass.ROUTE,
        L3RiskFloor.R3,
        5,
        6,
    ),
    GrammarRule(
        L3Form.DHCP_HELPER_ADDRESS,
        "ip helper-address <address>",
        L3Mode.INTERFACE,
        L3TargetClass.SVI,
        L3RiskFloor.R2,
        3,
        3,
    ),
)

FORM_BY_VALUE: Final[dict[str, GrammarRule]] = {
    rule.form.value: rule for rule in GRAMMAR_RULES
}
FORM_BY_SYNTAX: Final[dict[str, GrammarRule]] = {
    rule.syntax: rule for rule in GRAMMAR_RULES
}


def is_reserved_vlan(vlan: int) -> bool:
    return vlan in RESERVED_VLANS


def canonical_svi_name(vlan: int) -> str:
    return f"Vlan{vlan}"


def parse_canonical_ipv4(token: str) -> IPv4Address | None:
    """Parse one canonical dotted-decimal IPv4 address, without repair."""
    try:
        address = IPv4Address(token)
    except ValueError:
        return None
    return address if str(address) == token else None


def parse_canonical_mask(token: str) -> tuple[IPv4Address, int] | None:
    """Return (netmask, prefixlen) only for a canonical contiguous mask."""
    try:
        network = IPv4Network(f"0.0.0.0/{token}", strict=False)
    except ValueError:
        return None
    if str(network.netmask) != token:
        return None
    return network.netmask, network.prefixlen


def parse_canonical_network(
    prefix_token: str, mask_token: str,
) -> tuple[IPv4Network, IPv4Address] | None:
    mask = parse_canonical_mask(mask_token)
    if mask is None:
        return None
    netmask, prefixlen = mask
    prefix = parse_canonical_ipv4(prefix_token)
    if prefix is None:
        return None
    try:
        network = IPv4Network(f"{prefix}/{prefixlen}", strict=False)
    except ValueError:
        return None
    if network.prefixlen != prefixlen:
        return None
    if network.network_address != prefix:
        return None
    return network, netmask


def parse_interface_vlan(token: str) -> int | None:
    """Accept only the canonical ``Vlan<decimal>`` spelling."""
    if not token.startswith("Vlan"):
        return None
    digits = token[4:]
    if not digits.isdigit() or digits.startswith("0"):
        return None
    vlan = int(digits)
    if not VLAN_MIN <= vlan <= VLAN_MAX:
        return None
    return vlan


def parse_uint(token: str, *, minimum: int, maximum: int) -> int | None:
    """Parse an unsigned decimal without leading zeros or implicit repair."""
    if not token.isdigit() or token.startswith("0"):
        return None
    value = int(token)
    return value if minimum <= value <= maximum else None


def is_unicast_ipv4(address: IPv4Address) -> bool:
    return not (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_reserved
        or address.is_link_local
    )


def is_usable_svi_address(address: IPv4Address, network: IPv4Network) -> bool:
    if not SVI_PREFIX_MIN <= network.prefixlen <= SVI_PREFIX_MAX:
        return False
    return address in network and (
        address != network.network_address
        and address != network.broadcast_address
    )
