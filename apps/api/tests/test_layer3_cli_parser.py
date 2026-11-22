"""CIS-03-03B independent grammar/parser goldens and adversarial tests."""

from __future__ import annotations

import pytest

from event_switch_manager.planning.layer3_cli_grammar import (
    GRAMMAR_RULES,
    L3Form,
    L3Mode,
    L3TargetClass,
)
from event_switch_manager.planning.layer3_cli_parser import (
    ParsedCommand,
    parse_l3_command,
)


def parsed(text: str) -> ParsedCommand:
    return parse_l3_command(text)


@pytest.mark.parametrize(
    ("text", "form", "mode", "target", "parameters"),
    (
        (
            "ip routing",
            L3Form.IP_ROUTING,
            L3Mode.GLOBAL,
            L3TargetClass.DEVICE,
            {},
        ),
        (
            "interface Vlan10",
            L3Form.SVI_INTERFACE,
            L3Mode.GLOBAL,
            L3TargetClass.SVI,
            {"vlan_id": 10},
        ),
        (
            "ip address 192.168.10.1 255.255.255.0",
            L3Form.SVI_ADDRESS,
            L3Mode.INTERFACE,
            L3TargetClass.SVI,
            {
                "address": "192.168.10.1",
                "mask": "255.255.255.0",
                "prefix_length": 24,
            },
        ),
        (
            "ip route 10.200.0.0 255.255.255.0 10.0.0.2",
            L3Form.STATIC_ROUTE,
            L3Mode.GLOBAL,
            L3TargetClass.ROUTE,
            {
                "destination": "10.200.0.0/24",
                "mask": "255.255.255.0",
                "next_hop": "10.0.0.2",
                "distance": 1,
            },
        ),
        (
            "ip route 10.200.0.0 255.255.255.0 10.0.0.2 254",
            L3Form.STATIC_ROUTE,
            L3Mode.GLOBAL,
            L3TargetClass.ROUTE,
            {
                "destination": "10.200.0.0/24",
                "mask": "255.255.255.0",
                "next_hop": "10.0.0.2",
                "distance": 254,
            },
        ),
        (
            "ip route 0.0.0.0 0.0.0.0 10.0.0.2",
            L3Form.DEFAULT_ROUTE,
            L3Mode.GLOBAL,
            L3TargetClass.ROUTE,
            {
                "destination": "0.0.0.0/0",
                "mask": "0.0.0.0",
                "next_hop": "10.0.0.2",
                "distance": 1,
            },
        ),
        (
            "ip helper-address 192.168.10.5",
            L3Form.DHCP_HELPER_ADDRESS,
            L3Mode.INTERFACE,
            L3TargetClass.SVI,
            {"server": "192.168.10.5"},
        ),
    ),
)
def test_golden_forms(
    text: str,
    form: L3Form,
    mode: L3Mode,
    target: L3TargetClass,
    parameters: dict[str, object],
) -> None:
    result = parsed(text)
    assert result.ok is True
    assert result.form is form
    assert result.mode is mode
    assert result.target_class is target
    assert result.parameter_dict() == parameters
    assert result.failure_codes == ()


def test_grammar_forms_are_explicit_and_unique() -> None:
    assert len(GRAMMAR_RULES) == 6
    assert {rule.form for rule in GRAMMAR_RULES} == set(L3Form)
    assert len({rule.syntax for rule in GRAMMAR_RULES}) == 6


@pytest.mark.parametrize(
    ("text", "reason"),
    (
        ("", "text-empty"),
        ("ip", "unknown-command"),
        ("ip routingx", "unknown-command"),
        ("ip routing extra", "trailing-token"),
        ("ip routing ", "text-edge-whitespace"),
        (" ip routing", "text-edge-whitespace"),
        ("ip  routing", "text-double-space"),
        ("ip\trouting", "text-control-character"),
        ("ip routing\n", "text-control-character"),
        ("ip routing\r", "text-control-character"),
        ("ip routing\x00", "text-control-character"),
        ("ip routingé", "text-non-ascii"),
        ("no ip routing", "dangerous-command"),
        ("reload", "dangerous-command"),
        ("erase startup-config", "dangerous-command"),
        ("copy run start", "dangerous-command"),
        ("ip ssh server", "dangerous-command"),
        ("ip route 10.0.0.0 255.255.255.0 10.0.0.2 ; reload", "text-forbidden-character"),
        ("ip route 10.0.0.0 255.255.255.0 10.0.0.2 | reload", "text-forbidden-character"),
        ("ip route 10.0.0.0 255.255.255.0 10.0.0.2 && reload", "text-forbidden-character"),
        ("ip route 10.0.0.0 255.255.255.0 10.0.0.2 # x", "text-forbidden-character"),
        ("ip address 192.168.10.1 255.255.255.0 extra", "wrong-token-count"),
        ("interface Vlan10 extra", "trailing-token"),
        ("ip helper-address 192.168.10.5 extra", "wrong-token-count"),
        ("ip helper-address 0.0.0.0", "invalid-helper-server"),
        ("ip helper-address 224.0.0.1", "invalid-helper-server"),
        ("ip helper-address 127.0.0.1", "invalid-helper-server"),
        ("ip route 0.0.0.0 0.0.0.0 10.0.0.2 256", "invalid-distance"),
        ("ip route 10.0.0.0 255.0.255.0 10.0.0.2", "invalid-route-destination"),
        ("ip route 10.0.0.1 255.255.255.0 10.0.0.2", "invalid-route-destination"),
        ("ip address 192.168.10.1 255.255.255.253", "invalid-mask"),
        ("ip address 192.168.10.1 255.255.255.0 1", "wrong-token-count"),
    ),
)
def test_negative_and_unsafe_inputs(text: str, reason: str) -> None:
    result = parsed(text)
    assert result.ok is False
    assert any(item.split("@")[0] == reason for item in result.failure_codes)


@pytest.mark.parametrize(
    ("text", "reason"),
    (
        ("interface Vlan0", "invalid-interface"),
        ("interface Vlan4095", "invalid-interface"),
        ("interface Vlan01", "invalid-interface"),
        ("interface vlan10", "invalid-interface"),
        ("interface Vlan", "invalid-interface"),
        ("interface Vlan10/1", "invalid-interface"),
        ("ip address 10.0.0.0 255.255.255.0", "svi-address-not-usable"),
        ("ip address 10.0.0.255 255.255.255.0", "svi-address-not-usable"),
        ("ip address 10.0.0.0 255.255.255.254", "svi-prefix-not-first-batch"),
        ("ip address 10.0.0.0 255.255.255.255", "svi-prefix-not-first-batch"),
        ("ip address 10.0.0.127 255.255.255.128", "svi-address-not-usable"),
    ),
)
def test_svi_boundaries(text: str, reason: str) -> None:
    result = parsed(text)
    assert result.ok is False
    assert any(item.split("@")[0] == reason for item in result.failure_codes)


@pytest.mark.parametrize(
    ("text", "form"),
    (
        ("interface Vlan1", L3Form.SVI_INTERFACE),
        ("interface Vlan1001", L3Form.SVI_INTERFACE),
        ("interface Vlan4094", L3Form.SVI_INTERFACE),
        ("ip address 10.0.0.1 255.255.255.252", L3Form.SVI_ADDRESS),
        ("ip route 10.0.0.0 255.0.0.0 10.0.0.2", L3Form.STATIC_ROUTE),
        ("ip route 10.0.0.1 255.255.255.255 10.0.0.2", L3Form.STATIC_ROUTE),
        ("ip route 0.0.0.0 0.0.0.0 10.0.0.2 255", L3Form.DEFAULT_ROUTE),
    ),
)
def test_grammar_boundaries_accepted(text: str, form: L3Form) -> None:
    result = parsed(text)
    assert result.ok is True
    assert result.form is form


def test_static_and_default_are_disjoint_by_destination() -> None:
    static_result = parsed("ip route 10.0.0.0 255.255.255.0 10.0.0.2")
    default_result = parsed("ip route 0.0.0.0 0.0.0.0 10.0.0.2")
    assert static_result.form is L3Form.STATIC_ROUTE
    assert default_result.form is L3Form.DEFAULT_ROUTE


def test_reserved_vlan_is_syntax_only_not_final_safety() -> None:
    # The grammar accepts the full 1-4094 VLAN range; reserved VLAN policy is
    # enforced independently by the validator, not silently repaired here.
    for vlan in (1, 1002, 1003, 1004, 1005):
        result = parsed(f"interface Vlan{vlan}")
        assert result.ok is True
        assert result.parameter("vlan_id") == vlan
