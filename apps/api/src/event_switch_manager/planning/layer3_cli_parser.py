"""CIS-03-03B independent single-command L3 parser.

The parser consumes one printable-ASCII command line and returns a structured
result.  It does not import the CIS-03-03A renderer or evidence registry, does
not execute commands, and never normalizes, strips, truncates or repairs text.
Only the frozen generic text-safety lexer is reused.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Network
from typing import Final

from pydantic import JsonValue

from .layer2_cli_lexer import lex_command
from .layer3_cli_grammar import (
    DISTANCE_MAX,
    DISTANCE_MIN,
    FORM_BY_VALUE,
    ROUTE_PREFIX_MAX,
    SVI_PREFIX_MAX,
    SVI_PREFIX_MIN,
    L3Form,
    L3Mode,
    L3TargetClass,
    is_unicast_ipv4,
    is_usable_svi_address,
    parse_canonical_ipv4,
    parse_canonical_mask,
    parse_canonical_network,
    parse_interface_vlan,
    parse_uint,
)

PARSER_ID: Final = "cis-03-03b-independent-l3-command-parser-v1"


class ParseStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class ParseFailure:
    code: str
    token_index: int | None = None
    position: int | None = None

    @property
    def reason(self) -> str:
        suffix = "" if self.token_index is None else f"@{self.token_index}"
        return f"{self.code}{suffix}"


@dataclass(frozen=True, slots=True)
class ParseParameter:
    name: str
    value: str | int


@dataclass(frozen=True, slots=True)
class ParsedCommand:
    status: ParseStatus
    form: L3Form | None
    mode: L3Mode | None
    target_class: L3TargetClass | None
    parameters: tuple[ParseParameter, ...] = ()
    failures: tuple[ParseFailure, ...] = ()
    token_count: int = 0

    @property
    def ok(self) -> bool:
        return self.status is ParseStatus.PASS

    @property
    def failure_codes(self) -> tuple[str, ...]:
        return tuple(failure.reason for failure in self.failures)

    def parameter(self, name: str) -> str | int | None:
        return next(
            (item.value for item in self.parameters if item.name == name),
            None,
        )

    def parameter_dict(self) -> dict[str, JsonValue]:
        return {item.name: item.value for item in self.parameters}



def _failure(
    code: str, token_index: int | None = None, position: int | None = None,
) -> ParseFailure:
    return ParseFailure(code=code, token_index=token_index, position=position)


def _fail(
    code: str,
    *,
    token_index: int | None = None,
    position: int | None = None,
    token_count: int = 0,
) -> ParsedCommand:
    return ParsedCommand(
        status=ParseStatus.FAIL,
        form=None,
        mode=None,
        target_class=None,
        failures=(_failure(code, token_index, position),),
        token_count=token_count,
    )


def _ok(
    form: L3Form,
    parameters: tuple[ParseParameter, ...],
    token_count: int,
) -> ParsedCommand:
    rule = FORM_BY_VALUE[form.value]
    return ParsedCommand(
        status=ParseStatus.PASS,
        form=form,
        mode=rule.mode,
        target_class=rule.target_class,
        parameters=parameters,
        token_count=token_count,
    )


_DANGEROUS_HEADS: Final[frozenset[str]] = frozenset({
    "no", "reload", "erase", "format", "factory-reset", "boot", "copy",
    "write", "delete", "username", "aaa", "crypto", "line", "transport",
    "snmp-server", "logging", "ntp", "shutdown", "default",
})
_DANGEROUS_IP_HEADS: Final[frozenset[str]] = frozenset({
    "ssh", "http", "https", "domain", "name-server", "default-network",
})

def parse_l3_command(text: object) -> ParsedCommand:
    """Parse one exact command, failing closed on any unsafe/extra token."""
    lexed = lex_command(text)
    if not lexed.ok:
        first = lexed.issues[0]
        return _fail(
            first.code.value,
            position=first.position,
            token_count=len(lexed.tokens),
        )
    tokens = lexed.token_texts
    if not tokens:
        return _fail("text-empty")
    if len(tokens) > 12:
        return _fail("too-many-tokens", token_index=12, token_count=len(tokens))

    head = tokens[0]
    if head == "interface":
        return _parse_interface(tokens)
    if head in _DANGEROUS_HEADS:
        return _fail("dangerous-command", token_index=0, token_count=len(tokens))
    if head != "ip" or len(tokens) < 2:
        return _fail("unknown-command", token_index=0, token_count=len(tokens))

    sub = tokens[1]
    if sub in _DANGEROUS_IP_HEADS:
        return _fail("dangerous-command", token_index=1, token_count=len(tokens))

    if sub == "routing":
        if len(tokens) != 2:
            return _fail("trailing-token", token_index=2, token_count=len(tokens))
        return _ok(L3Form.IP_ROUTING, (), len(tokens))

    if sub == "address":
        return _parse_svi_address(tokens)

    if sub == "helper-address":
        return _parse_helper(tokens)

    if sub == "route":
        return _parse_route(tokens)

    return _fail("unknown-command", token_index=1, token_count=len(tokens))


def _parse_interface(tokens: tuple[str, ...]) -> ParsedCommand:
    if len(tokens) != 2:
        return _fail("trailing-token", token_index=2, token_count=len(tokens))
    vlan = parse_interface_vlan(tokens[1])
    if vlan is None:
        return _fail("invalid-interface", token_index=1, token_count=len(tokens))
    return _ok(
        L3Form.SVI_INTERFACE,
        (ParseParameter("vlan_id", vlan),),
        len(tokens),
    )


def _parse_svi_address(tokens: tuple[str, ...]) -> ParsedCommand:
    if len(tokens) != 4:
        return _fail("wrong-token-count", token_index=0, token_count=len(tokens))
    address = parse_canonical_ipv4(tokens[2])
    if address is None:
        return _fail("invalid-ipv4", token_index=2, token_count=len(tokens))
    mask = parse_canonical_mask(tokens[3])
    if mask is None:
        return _fail("invalid-mask", token_index=3, token_count=len(tokens))
    _, prefixlen = mask
    if not SVI_PREFIX_MIN <= prefixlen <= SVI_PREFIX_MAX:
        return _fail("svi-prefix-not-first-batch", token_index=3, token_count=len(tokens))
    network = IPv4Network(f"{address}/{prefixlen}", strict=False)
    if not is_usable_svi_address(address, network):
        return _fail("svi-address-not-usable", token_index=2, token_count=len(tokens))
    return _ok(
        L3Form.SVI_ADDRESS,
        (
            ParseParameter("address", str(address)),
            ParseParameter("mask", str(network.netmask)),
            ParseParameter("prefix_length", prefixlen),
        ),
        len(tokens),
    )


def _parse_helper(tokens: tuple[str, ...]) -> ParsedCommand:
    if len(tokens) != 3:
        return _fail("wrong-token-count", token_index=0, token_count=len(tokens))
    server = parse_canonical_ipv4(tokens[2])
    if server is None or not is_unicast_ipv4(server):
        return _fail("invalid-helper-server", token_index=2, token_count=len(tokens))
    return _ok(
        L3Form.DHCP_HELPER_ADDRESS,
        (ParseParameter("server", str(server)),),
        len(tokens),
    )


def _parse_route(tokens: tuple[str, ...]) -> ParsedCommand:
    if len(tokens) not in (5, 6):
        return _fail("wrong-token-count", token_index=0, token_count=len(tokens))
    destination = parse_canonical_network(tokens[2], tokens[3])
    if destination is None:
        return _fail("invalid-route-destination", token_index=2, token_count=len(tokens))
    network, _ = destination
    next_hop = parse_canonical_ipv4(tokens[4])
    if next_hop is None or not is_unicast_ipv4(next_hop):
        return _fail("invalid-next-hop", token_index=4, token_count=len(tokens))
    distance: int
    if len(tokens) == 6:
        parsed_distance = parse_uint(
            tokens[5], minimum=DISTANCE_MIN, maximum=DISTANCE_MAX,
        )
        if parsed_distance is None:
            return _fail("invalid-distance", token_index=5, token_count=len(tokens))
        distance = parsed_distance
    else:
        distance = 1
    if network.prefixlen == 0:
        if network.network_address.compressed != "0.0.0.0":
            return _fail(
                "invalid-route-destination", token_index=2, token_count=len(tokens),
            )
        form = L3Form.DEFAULT_ROUTE
    else:
        if network.prefixlen > ROUTE_PREFIX_MAX:
            return _fail(
                "invalid-route-destination", token_index=3, token_count=len(tokens),
            )
        form = L3Form.STATIC_ROUTE
    return _ok(
        form,
        (
            ParseParameter("destination", str(network)),
            ParseParameter("mask", str(network.netmask)),
            ParseParameter("next_hop", str(next_hop)),
            ParseParameter("distance", distance),
        ),
        len(tokens),
    )


__all__ = [
    "ParsedCommand",
    "ParseFailure",
    "ParseParameter",
    "ParseStatus",
    "PARSER_ID",
    "parse_l3_command",
]
