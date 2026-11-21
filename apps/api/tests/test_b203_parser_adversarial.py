"""CIS-02B2-03 hand-authored adversarial parser corpus.

Every negative case is hand-written: malformed syntax, character injection,
token-boundary attacks, parameter boundaries, prohibited cleanup/destructive
operations, aliases/abbreviations/case variants and unsafe text. Each case
asserts a real parser rejection and a deterministic reason code.
"""

from __future__ import annotations

from typing import Any

import pytest

from event_switch_manager.planning.layer2_cli_grammar import COVERAGE_COMMAND_BY_TOPIC
from event_switch_manager.planning.layer2_cli_parser import (
    parse_command,
    scan_for_dangerous_command,
)

#: Characters the B2 safety contract rejects anywhere in command text.
INJECTION_CHARACTERS = (
    ";", "|", "&", "<", ">", "!", "?", "*", "$", "=", '"', "'", "\\", "`",
    "#", "^", "~", "(", ")", "[", "]", "{", "}",
)

INJECTION_BASES = (
    "vlan 10",
    "shutdown",
    "description Players desk",
    "switchport trunk allowed vlan 10,20",
)


@pytest.mark.parametrize("base", INJECTION_BASES)
@pytest.mark.parametrize("character", INJECTION_CHARACTERS)
def test_injected_character_never_becomes_part_of_a_command(
    base: str, character: str,
) -> None:
    variants = [f"{base}{character}", f"{character}{base}"]
    if " " in base:
        variants.append(base.replace(" ", f"{character} ", 1))
    for text in variants:
        result = parse_command(text)
        assert not result.ok, text
        assert "text-forbidden-character" in result.failure_codes, (text, result.failure_codes)


_CONTROL_CASES = {
    "vlan 10\x00": "text-control-character",
    "vlan 10\x01": "text-control-character",
    "vlan 10\x1b": "text-control-character",
    "vlan 10\t20": "text-control-character",
    "vlan 10\x7f": "text-control-character",
    "vlan 10\n": "text-not-single-line",
    "vlan 10\r": "text-not-single-line",
    "vlan 10\nvlan 20": "text-not-single-line",
    "vlan 10\r\nvlan 20": "text-not-single-line",
    "shutdown\nreload": "text-not-single-line",
    "description a\nb": "text-not-single-line",
}


@pytest.mark.parametrize(("text", "code"), _CONTROL_CASES.items())
def test_cr_lf_nul_tab_and_control_characters_are_rejected(
    text: str, code: str,
) -> None:
    result = parse_command(text)
    assert not result.ok
    assert code in result.failure_codes


_NON_ASCII_CASES = (
    "vlan 10\u00e9",
    "vlan 10\u200b",
    "vlan\u00a010",
    "vlan 10\u202e",
    "ｖｌａｎ 10",
    "vlan 10\u0301",
    "shutdown\u200d",
    "descripti\u043en Players",
    "\ufeffvlan 10",
    "🚀 vlan 10",
)


@pytest.mark.parametrize("text", _NON_ASCII_CASES)
def test_unicode_confusables_and_invisible_characters_are_rejected(
    text: str,
) -> None:
    result = parse_command(text)
    assert not result.ok
    assert "text-non-ascii" in result.failure_codes


_WHITESPACE_CASES = {
    " vlan 10": "text-edge-whitespace",
    "vlan 10 ": "text-edge-whitespace",
    "vlan  10": "text-double-space",
    "shutdown ": "text-edge-whitespace",
    " shutdown": "text-edge-whitespace",
    "description  Players": "text-double-space",
    "description Players  desk": "text-double-space",
    "no  shutdown": "text-double-space",
    "vlan\t10": "text-control-character",
}


@pytest.mark.parametrize(("text", "code"), _WHITESPACE_CASES.items())
def test_leading_trailing_and_repeated_spaces_are_never_trimmed(
    text: str, code: str,
) -> None:
    result = parse_command(text)
    assert not result.ok
    assert code in result.failure_codes


@pytest.mark.parametrize("text", ["", " ", "   "])
def test_empty_command_text_is_rejected(text: str) -> None:
    result = parse_command(text)
    assert not result.ok


@pytest.mark.parametrize("value", [None, 5, 1.5, [], {}, ("vlan", 10)])
def test_non_string_command_values_fail_closed(value: Any) -> None:
    result = parse_command(value)
    assert not result.ok
    assert result.command is None
    assert "text-not-a-string" in result.failure_codes


@pytest.mark.parametrize("text", ["description " + "a" * 600, "vlan " + "1" * 600])
def test_overlong_command_text_is_rejected_without_truncation(text: str) -> None:
    result = parse_command(text)
    assert not result.ok
    assert "text-too-long" in result.failure_codes


_DANGEROUS_COMMANDS = (
    "reload",
    "reload in 5",
    "erase startup-config",
    "erase nvram:",
    "delete flash:image.bin",
    "format flash:",
    "factory-reset",
    "reset system",
    "boot system flash:image.bin",
    "write memory",
    "copy running-config startup-config",
    "configure terminal",
    "configure replace flash:config",
    "clear counters",
    "default interface GigabitEthernet1/0/1",
    "username admin privilege 15 secret x",
    "enable secret x",
    "aaa new-model",
    "crypto key generate rsa",
    "ssh",
    "telnet 192.0.2.1",
    "line vty 0 4",
    "login local",
    "banner motd hello",
    "archive log config",
    "license install flash:license",
    "install add file flash:image.bin",
    "upgrade",
    "rommon",
    "squeeze",
    "mkfs",
    "hostname EVIL",
    "end",
    "exit",
    "do show running-config",
)


@pytest.mark.parametrize("text", _DANGEROUS_COMMANDS)
def test_prohibited_r6_and_device_state_commands_are_denied(text: str) -> None:
    result = parse_command(text)
    assert not result.ok
    assert "dangerous-operation-denied" in result.failure_codes
    assert scan_for_dangerous_command(text) == ("dangerous-operation-denied",)


_NO_FORMS = (
    "no",
    "no vlan 10",
    "no switchport",
    "no switchport mode access",
    "no channel-group 1 mode active",
    "no spanning-tree portfast",
    "no spanning-tree bpduguard enable",
    "no description",
    "no power inline",
    "no speed",
    "no duplex",
    "no shutdown extra",
)


@pytest.mark.parametrize("text", _NO_FORMS)
def test_only_a_complete_no_shutdown_form_is_legal(text: str) -> None:
    result = parse_command(text)
    assert not result.ok
    assert "cleanup-or-dangerous-operation-denied" in result.failure_codes


def test_no_shutdown_remains_the_reviewed_legal_form() -> None:
    result = parse_command("no shutdown")
    assert result.ok
    assert result.command is not None
    assert dict(result.command.parameters) == {"admin-state": "up"}


_UNREVIEWED_FORMS = {
    "shut": "command-not-reviewed",
    "shutd": "command-not-reviewed",
    "desc Players": "command-not-reviewed",
    "van 10": "command-not-reviewed",
    "vlan10": "command-not-reviewed",
    "vlan 10 20": "trailing-token",
    "switchport mode acc": "command-not-reviewed",
    "switchport mode": "command-not-reviewed",
    "switchport access vlan": "parameter-missing",
    "switchport access": "command-not-reviewed",
    "interface GigabitEthernet1/0/1": "invalid-port-channel-interface",
    "interface Vlan10": "invalid-port-channel-interface",
    "interface": "parameter-missing",
    "SPANNING-TREE mode rapid-pvst": "command-not-reviewed",
    "SHUTDOWN": "command-not-reviewed",
    "Vlan 10": "command-not-reviewed",
    "switchport MODE access": "command-not-reviewed",
    "speed AUTO": "parameter-not-allowed:speed",
    "vtp mode TRANSPARENT": "command-not-reviewed",
    "spanning-tree portfast TRUNK": "trailing-token",
    "channel-group 1 mode ON": "parameter-not-allowed:mode",
    "spanning-tree mode pvst": "command-not-reviewed",
    "vtp mode server": "command-not-reviewed",
    "spanning-tree portfast disable": "trailing-token",
    "spanning-tree portfast enable": "trailing-token",
    "spanning-tree bpduguard true": "parameter-not-allowed:bpdu-guard",
    "power inline on": "parameter-not-allowed:poe-mode",
    "speed 10000": "parameter-not-allowed:speed",
    "duplex 1000": "parameter-not-allowed:duplex",
    "spanning-tree": "command-not-reviewed",
    "switchport": "command-not-reviewed",
    "channel-group": "parameter-missing",
    "channel-group 1": "command-not-reviewed",
    "channel-group 1 mode": "parameter-missing",
    "name": "vlan-name-empty",
    "description": "description-empty",
    "spanning-tree vlan": "parameter-missing",
    "spanning-tree vlan 10": "command-not-reviewed",
    "spanning-tree vlan 10 priority": "parameter-missing",
}


@pytest.mark.parametrize(("text", "code"), _UNREVIEWED_FORMS.items())
def test_unreviewed_forms_aliases_abbreviations_and_extra_tokens_are_rejected(
    text: str, code: str,
) -> None:
    result = parse_command(text)
    assert not result.ok
    assert code in result.failure_codes


_BOUNDARY_CASES: tuple[tuple[str, str], ...] = (
    # VLAN ids.
    ("vlan 0", "parameter-out-of-range:vlan-id"),
    ("vlan 4095", "parameter-out-of-range:vlan-id"),
    ("vlan 1002", "parameter-reserved-value:vlan-id"),
    ("vlan 1003", "parameter-reserved-value:vlan-id"),
    ("vlan 1004", "parameter-reserved-value:vlan-id"),
    ("vlan 1005", "parameter-reserved-value:vlan-id"),
    ("vlan 010", "parameter-not-integer:vlan-id"),
    ("vlan 1e3", "parameter-not-integer:vlan-id"),
    ("vlan +10", "parameter-not-integer:vlan-id"),
    ("vlan -10", "parameter-not-integer:vlan-id"),
    ("vlan 10.0", "parameter-not-integer:vlan-id"),
    ("switchport access vlan 0", "parameter-out-of-range:vlan-id"),
    ("switchport access vlan 1002", "parameter-reserved-value:vlan-id"),
    ("switchport trunk native vlan 4095", "parameter-out-of-range:vlan-id"),
    ("switchport trunk native vlan 1004", "parameter-reserved-value:vlan-id"),
    # Trunk allowed VLAN lists.
    ("switchport trunk allowed vlan 0", "vlan-list-out-of-range"),
    ("switchport trunk allowed vlan 4095", "vlan-list-out-of-range"),
    ("switchport trunk allowed vlan 1002", "vlan-list-reserved-value"),
    ("switchport trunk allowed vlan 10-20", "vlan-list-invalid-entry"),
    ("switchport trunk allowed vlan 10,", "vlan-list-empty"),
    ("switchport trunk allowed vlan ,10", "vlan-list-empty"),
    ("switchport trunk allowed vlan 10,,20", "vlan-list-empty"),
    ("switchport trunk allowed vlan 10,10", "vlan-list-duplicate"),
    ("switchport trunk allowed vlan 20,10", "vlan-list-not-ascending"),
    ("switchport trunk allowed vlan all", "vlan-list-invalid-entry"),
    ("switchport trunk allowed vlan none", "vlan-list-invalid-entry"),
    ("switchport trunk allowed vlan except 10", "vlan-list-invalid-entry"),
    ("switchport trunk allowed vlan add 10", "vlan-list-invalid-entry"),
    ("switchport trunk allowed vlan remove 10", "vlan-list-invalid-entry"),
    (
        "switchport trunk allowed vlan "
        + ",".join(str(value) for value in range(1, 66)),
        "vlan-list-too-long",
    ),
    # Bridge priority.
    ("spanning-tree vlan 10 priority 4097", "parameter-step-violation:priority"),
    ("spanning-tree vlan 10 priority 61441", "parameter-out-of-range:priority"),
    ("spanning-tree vlan 10 priority 70000", "parameter-out-of-range:priority"),
    ("spanning-tree vlan 10 priority -4096", "parameter-not-integer:priority"),
    ("spanning-tree vlan 10 priority 04096", "parameter-not-integer:priority"),
    ("spanning-tree vlan 1002 priority 4096", "parameter-reserved-value:vlan-id"),
    # EtherChannel numbers.
    ("channel-group 0 mode on", "parameter-out-of-range:port-channel-number"),
    ("channel-group 10000 mode on", "parameter-out-of-range:port-channel-number"),
    ("channel-group 01 mode on", "parameter-not-integer:port-channel-number"),
    ("interface Port-Channel0", "invalid-port-channel-interface"),
    ("interface Port-Channel01", "invalid-port-channel-interface"),
    ("interface Port-Channel10000", "invalid-port-channel-interface"),
    ("interface Port-channel1", "invalid-port-channel-interface"),
    ("interface port-channel1", "invalid-port-channel-interface"),
    ("interface Port-Channel-1", "invalid-port-channel-interface"),
    ("interface Port-Channel 1", "invalid-port-channel-interface"),
    # Text limits and text policy.
    ("description " + "a" * 241, "description-too-long"),
    ("description _Players", "description-invalid-first-character"),
    ("description .Players", "description-invalid-first-character"),
    ("description Players;desk", "text-forbidden-character"),
    ("description Players=desk", "text-forbidden-character"),
    ("name " + "A" + "b" * 32, "vlan-name-too-long"),
    ("name _Players", "vlan-name-invalid-first-character"),
    ("name .Players", "vlan-name-invalid-first-character"),
    ("name Players name", "trailing-token"),
    ("name Players;desk", "text-forbidden-character"),
)


@pytest.mark.parametrize(("text", "code"), _BOUNDARY_CASES)
def test_parameter_and_text_boundaries_are_rejected(text: str, code: str) -> None:
    result = parse_command(text)
    assert not result.ok
    assert code in result.failure_codes


_SEQUENCE_CASES = (
    "vlan 10\ninterface GigabitEthernet1/0/1",
    "configure terminal\nvlan 10",
    "vlan 10; vlan 20",
    "vlan 10 && reload",
    "vlan 10 || erase startup-config",
    "vlan 10 > flash:x",
    "shutdown\nreload",
    "description x\nreload",
    "no shutdown\nno shutdown",
    "vlan 10 | reload",
    "vlan 10 && shutdown",
)


@pytest.mark.parametrize("text", _SEQUENCE_CASES)
def test_full_configuration_sequences_are_never_accepted(text: str) -> None:
    result = parse_command(text)
    assert not result.ok
    assert result.command is None


_MUTATION_BASES = tuple(sorted(COVERAGE_COMMAND_BY_TOPIC.values()))


@pytest.mark.parametrize("text", _MUTATION_BASES)
def test_single_token_and_single_character_mutations_are_rejected(text: str) -> None:
    first_space = text.find(" ")
    split_at = first_space + 1 if first_space >= 0 else len(text) // 2
    suffix = ";" if text.startswith("description ") else " extra"
    mutations = (
        text[0].upper() + text[1:],
        "x" + text,
        text + suffix,
        text[:split_at] + ";" + text[split_at:],
        text + "\t",
        text.replace(" ", "  ", 1),
    )
    for mutated in mutations:
        result = parse_command(mutated)
        assert not result.ok, mutated
        assert result.command is None


def test_all_rejections_are_deterministic() -> None:
    cases = (
        *(_DANGEROUS_COMMANDS),
        *(_NO_FORMS),
        *_UNREVIEWED_FORMS,
        *(text for text, _code in _BOUNDARY_CASES),
        *_SEQUENCE_CASES,
    )
    for text in cases:
        first = parse_command(text)
        for _ in range(3):
            again = parse_command(text)
            assert again.failure_codes == first.failure_codes
            assert again.failures == first.failures
            assert again.command is None


def test_description_and_vlan_name_safe_alphabet_accepts_only_reviewed_characters() -> None:
    assert parse_command("description !").failure_codes == ("text-forbidden-character",)
    for character in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~":
        result = parse_command(f"description A{character}B")
        if character in ".,:/_+%@-":
            assert result.ok, character
        else:
            assert not result.ok, character
