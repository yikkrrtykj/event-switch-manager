"""CIS-02B2-03 independent recursive-descent command parser.

The parser consumes exactly one command line and returns a typed, structured
value or a deterministic failure. It has no renderer dependency:

* it never imports :mod:`layer2_cli_candidates`;
* it never re-composes an expected command and compares strings;
* it does not execute anything, call ``eval``/``exec`` or spawn a process;
* it never strips, trims or normalizes input before matching.

Every production must consume the whole token sequence. A residual token is a
failure, not something to ignore. Data arguments (a description or a VLAN name)
are parsed as data and can never be promoted to a second command; conversely a
command keyword in the command position is checked against the independently
authored grammar and the prohibited-operation vocabulary.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from .command_evidence import CommandMode, CommandTopic
from .layer2_cli_grammar import (
    DANGEROUS_COMMAND_HEADS,
    FORMS,
    PORT_CHANNEL_NUMBER_MAXIMUM,
    PORT_CHANNEL_NUMBER_MINIMUM,
    ChannelNumberParameter,
    EnumParameter,
    GrammarForm,
    IntegerParameter,
    Literal,
    PortChannelNameParameter,
    TargetClass,
    TextKind,
    TextParameter,
    VlanListParameter,
)
from .layer2_cli_lexer import TextIssue, lex_command


class FailureKind(StrEnum):
    """Which independent judgement produced a failure."""

    GRAMMAR = "grammar"
    PARAMETER = "parameter"
    SAFETY = "safety"
    CONTEXT = "context"


@dataclass(frozen=True, slots=True)
class ParseFailure:
    """One deterministic parse failure with a stable machine code."""

    kind: FailureKind
    code: str
    detail: str = ""
    position: int = 0

    @property
    def reason(self) -> str:
        return f"{self.code}:{self.detail}" if self.detail else self.code


@dataclass(frozen=True, slots=True)
class ParsedCommand:
    """Structured result of parsing one reviewed Cisco configuration command."""

    text: str
    topic: CommandTopic
    form_id: str
    mode: CommandMode
    target_class: TargetClass
    parameters: Mapping[str, object]
    tokens: tuple[str, ...]

    def parameter(self, name: str) -> object:
        return self.parameters.get(name)

    def json_parameters(self) -> dict[str, object]:
        payload: dict[str, object] = {}
        for key in sorted(self.parameters):
            value = self.parameters[key]
            payload[key] = list(value) if isinstance(value, tuple) else value
        return payload


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Complete result of independent parsing."""

    text: str
    tokens: tuple[str, ...]
    command: ParsedCommand | None
    failures: tuple[ParseFailure, ...]
    lex_issues: tuple[TextIssue, ...]

    @property
    def ok(self) -> bool:
        return self.command is not None and not self.failures

    @property
    def failure_codes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(failure.code for failure in self.failures))

    @property
    def safety_failures(self) -> tuple[ParseFailure, ...]:
        return tuple(
            failure for failure in self.failures
            if failure.kind is FailureKind.SAFETY
        )

    @property
    def grammar_failures(self) -> tuple[ParseFailure, ...]:
        return tuple(
            failure for failure in self.failures
            if failure.kind is FailureKind.GRAMMAR
        )


@dataclass(frozen=True, slots=True)
class _Attempt:
    form: GrammarForm
    matched: bool
    matched_literals: int
    parameters: Mapping[str, object] | None
    failure: ParseFailure | None


_CANONICAL_MODES: Mapping[CommandMode, int] = {
    CommandMode.GLOBAL: 0,
    CommandMode.VLAN: 1,
    CommandMode.INTERFACE: 2,
    CommandMode.PORT_CHANNEL: 3,
}


def parse_command(
    text: object, *, expected_mode: CommandMode | None = None,
) -> ParseResult:
    """Parse one command line under the independently authored grammar."""
    lexed = lex_command(text)
    tokens = lexed.token_texts
    if lexed.issues:
        failures = tuple(
            ParseFailure(
                FailureKind.SAFETY,
                issue.code.value,
                f"unsafe command text at offset {issue.position}",
                issue.position,
            )
            for issue in lexed.issues
        )
        return ParseResult(lexed.text, tokens, None, failures, lexed.issues)
    if not tokens:
        return ParseResult(
            lexed.text, tokens, None,
            (ParseFailure(FailureKind.SAFETY, "text-empty", "empty command text"),),
            lexed.issues,
        )

    safety = _prohibited_operation(tokens)
    if safety is not None:
        return ParseResult(lexed.text, tokens, None, (safety,), lexed.issues)

    attempts = tuple(_attempt(form, tokens) for form in FORMS)
    exact = tuple(
        attempt for attempt in attempts
        if attempt.matched and attempt.failure is None
    )
    if len(exact) > 1:
        return ParseResult(
            lexed.text, tokens, None,
            (ParseFailure(
                FailureKind.GRAMMAR, "ambiguous-grammar",
                "more than one production accepts this token sequence",
            ),),
            lexed.issues,
        )
    if exact:
        form = exact[0].form
        if expected_mode is not None and expected_mode not in form.modes:
            return ParseResult(
                lexed.text, tokens, None,
                (ParseFailure(
                    FailureKind.CONTEXT, "mode-mismatch",
                    f"{form.form_id} is not legal in {expected_mode.value} context",
                ),),
                lexed.issues,
            )
        parameters = dict(exact[0].parameters or {})
        command = ParsedCommand(
            text=lexed.text,
            topic=form.topic,
            form_id=form.form_id,
            mode=_canonical_mode(form, expected_mode),
            target_class=_canonical_target(form),
            parameters=MappingProxyType(parameters),
            tokens=tokens,
        )
        return ParseResult(lexed.text, tokens, command, (), lexed.issues)

    matched = tuple(attempt for attempt in attempts if attempt.matched)
    if matched:
        best = max(matched, key=lambda attempt: attempt.matched_literals)
        failure = best.failure
        assert failure is not None  # invariant: a non-exact match carries a failure
        return ParseResult(lexed.text, tokens, None, (failure,), lexed.issues)

    return ParseResult(
        lexed.text, tokens, None,
        (ParseFailure(
            FailureKind.GRAMMAR, "command-not-reviewed",
            f"command head {tokens[0]!r} is not a reviewed B2 command form",
        ),),
        lexed.issues,
    )


def scan_for_dangerous_command(text: object) -> tuple[str, ...]:
    """Return prohibited-operation codes present in the command position.

    Only the command position is inspected. The word ``reload`` inside a
    description is data, not an executed command, and must not be misreported.
    """
    lexed = lex_command(text)
    if not lexed.ok or not lexed.tokens:
        return ()
    failure = _prohibited_operation(lexed.token_texts)
    return () if failure is None else (failure.code,)


def _prohibited_operation(tokens: tuple[str, ...]) -> ParseFailure | None:
    head = tokens[0]
    if head == "no":
        if len(tokens) == 2 and tokens[1] == "shutdown":
            return None
        return ParseFailure(
            FailureKind.SAFETY,
            "cleanup-or-dangerous-operation-denied",
            "the only reviewed no-form is a complete 'no shutdown' command",
        )
    if head in DANGEROUS_COMMAND_HEADS:
        return ParseFailure(
            FailureKind.SAFETY,
            "dangerous-operation-denied",
            f"command head {head!r} is outside the reviewed B2 command scope",
        )
    return None


def _attempt(form: GrammarForm, tokens: tuple[str, ...]) -> _Attempt:
    parameters: dict[str, object] = {}
    position = 0
    matched_literals = 0
    for item in form.pattern:
        if isinstance(item, Literal):
            if position >= len(tokens) or tokens[position] != item.text:
                return _Attempt(form, False, matched_literals, None, None)
            position += 1
            matched_literals += 1
            continue
        consumed = _consume(item.parameter, tokens, position)
        if isinstance(consumed, ParseFailure):
            return _Attempt(form, True, matched_literals, None, consumed)
        value, consumed_tokens = consumed
        parameters[item.parameter.name] = value
        position += consumed_tokens
    if position != len(tokens):
        return _Attempt(
            form, True, matched_literals, None,
            ParseFailure(
                FailureKind.GRAMMAR, "trailing-token",
                f"unexpected trailing token {tokens[position]!r} after {form.form_id}",
                position,
            ),
        )
    merged: dict[str, object] = dict(form.fixed_parameters)
    merged.update(parameters)
    return _Attempt(form, True, matched_literals, merged, None)


def _consume(
    parameter: object, tokens: tuple[str, ...], position: int,
) -> tuple[object, int] | ParseFailure:
    if isinstance(parameter, IntegerParameter):
        return _consume_integer(parameter, tokens, position)
    if isinstance(parameter, EnumParameter):
        return _consume_enum(parameter, tokens, position)
    if isinstance(parameter, TextParameter):
        return _consume_text(parameter, tokens, position)
    if isinstance(parameter, VlanListParameter):
        return _consume_vlan_list(parameter, tokens, position)
    if isinstance(parameter, PortChannelNameParameter):
        return _consume_port_channel_name(parameter, tokens, position)
    if isinstance(parameter, ChannelNumberParameter):
        return _consume_channel_number(parameter, tokens, position)
    raise TypeError(f"unknown grammar parameter: {parameter!r}")


def _canonical_integer(token: str) -> int | None:
    if not token or not token.isascii() or not token.isdigit():
        return None
    if len(token) > 1 and token.startswith("0"):
        return None
    return int(token)


def _consume_integer(
    parameter: IntegerParameter, tokens: tuple[str, ...], position: int,
) -> tuple[int, int] | ParseFailure:
    if position >= len(tokens):
        return ParseFailure(
            FailureKind.PARAMETER, "parameter-missing", parameter.name, position,
        )
    value = _canonical_integer(tokens[position])
    if value is None:
        return ParseFailure(
            FailureKind.PARAMETER, f"parameter-not-integer:{parameter.name}",
            tokens[position], position,
        )
    if value < parameter.minimum or value > parameter.maximum:
        return ParseFailure(
            FailureKind.PARAMETER, f"parameter-out-of-range:{parameter.name}",
            f"{value} outside {parameter.minimum}..{parameter.maximum}", position,
        )
    if parameter.step is not None and value % parameter.step != 0:
        return ParseFailure(
            FailureKind.PARAMETER, f"parameter-step-violation:{parameter.name}",
            f"{value} is not a multiple of {parameter.step}", position,
        )
    if value in parameter.reserved:
        return ParseFailure(
            FailureKind.PARAMETER, f"parameter-reserved-value:{parameter.name}",
            str(value), position,
        )
    return value, 1


def _consume_enum(
    parameter: EnumParameter, tokens: tuple[str, ...], position: int,
) -> tuple[str, int] | ParseFailure:
    if position >= len(tokens):
        return ParseFailure(
            FailureKind.PARAMETER, "parameter-missing", parameter.name, position,
        )
    token = tokens[position]
    if token not in parameter.values:
        return ParseFailure(
            FailureKind.PARAMETER, f"parameter-not-allowed:{parameter.name}",
            token, position,
        )
    return token, 1


def _consume_text(
    parameter: TextParameter, tokens: tuple[str, ...], position: int,
) -> tuple[str, int] | ParseFailure:
    if position >= len(tokens):
        return ParseFailure(
            FailureKind.PARAMETER, f"{parameter.kind.value}-empty", parameter.name, position,
        )
    if parameter.single_token:
        value = tokens[position]
        consumed = 1
    else:
        value = " ".join(tokens[position:])
        consumed = len(tokens) - position
    failure = _text_failure(parameter, value, position)
    if failure is not None:
        return failure
    return value, consumed


def _text_failure(
    parameter: TextParameter, value: str, position: int,
) -> ParseFailure | None:
    prefix = parameter.kind.value
    if not value:
        return ParseFailure(FailureKind.PARAMETER, f"{prefix}-empty", parameter.name, position)
    if len(value) > parameter.maximum:
        return ParseFailure(
            FailureKind.PARAMETER, f"{prefix}-too-long",
            f"length {len(value)} exceeds {parameter.maximum}", position,
        )
    if value[0] not in parameter.first_characters:
        return ParseFailure(
            FailureKind.PARAMETER, f"{prefix}-invalid-first-character",
            value[0], position,
        )
    for offset, character in enumerate(value):
        if character not in parameter.allowlist:
            return ParseFailure(
                FailureKind.PARAMETER, f"{prefix}-forbidden-character",
                repr(character), position + offset,
            )
    if parameter.kind is TextKind.DESCRIPTION:
        if value != value.strip() or "  " in value:
            return ParseFailure(
                FailureKind.PARAMETER, "description-unsafe-whitespace",
                parameter.name, position,
            )
    return None


def _consume_vlan_list(
    parameter: VlanListParameter, tokens: tuple[str, ...], position: int,
) -> tuple[tuple[int, ...], int] | ParseFailure:
    if position >= len(tokens):
        return ParseFailure(
            FailureKind.PARAMETER, "vlan-list-empty", parameter.name, position,
        )
    token = tokens[position]
    raw_entries = token.split(",")
    if not token or any(entry == "" for entry in raw_entries):
        return ParseFailure(
            FailureKind.PARAMETER, "vlan-list-empty", token, position,
        )
    if len(raw_entries) > parameter.maximum_entries:
        return ParseFailure(
            FailureKind.PARAMETER, "vlan-list-too-long",
            f"{len(raw_entries)} entries exceed {parameter.maximum_entries}", position,
        )
    values: list[int] = []
    for entry in raw_entries:
        value = _canonical_integer(entry)
        if value is None:
            return ParseFailure(
                FailureKind.PARAMETER, "vlan-list-invalid-entry", entry, position,
            )
        if value < parameter.minimum or value > parameter.maximum:
            return ParseFailure(
                FailureKind.PARAMETER, "vlan-list-out-of-range",
                f"{value} outside {parameter.minimum}..{parameter.maximum}", position,
            )
        if value in parameter.reserved:
            return ParseFailure(
                FailureKind.PARAMETER, "vlan-list-reserved-value", str(value), position,
            )
        values.append(value)
    if len(set(values)) != len(values):
        return ParseFailure(
            FailureKind.PARAMETER, "vlan-list-duplicate", token, position,
        )
    if parameter.ascending and values != sorted(values):
        return ParseFailure(
            FailureKind.PARAMETER, "vlan-list-not-ascending", token, position,
        )
    return tuple(values), 1


def _consume_port_channel_name(
    parameter: PortChannelNameParameter, tokens: tuple[str, ...], position: int,
) -> tuple[int, int] | ParseFailure:
    if position >= len(tokens):
        return ParseFailure(
            FailureKind.PARAMETER, "parameter-missing", parameter.name, position,
        )
    token = tokens[position]
    prefix = "Port-Channel"
    if not token.startswith(prefix):
        return ParseFailure(
            FailureKind.GRAMMAR, "invalid-port-channel-interface", token, position,
        )
    number = _canonical_integer(token[len(prefix):])
    if number is None or not (
        PORT_CHANNEL_NUMBER_MINIMUM <= number <= PORT_CHANNEL_NUMBER_MAXIMUM
    ):
        return ParseFailure(
            FailureKind.GRAMMAR, "invalid-port-channel-interface", token, position,
        )
    return number, 1


def _consume_channel_number(
    parameter: ChannelNumberParameter, tokens: tuple[str, ...], position: int,
) -> tuple[int, int] | ParseFailure:
    if position >= len(tokens):
        return ParseFailure(
            FailureKind.PARAMETER, "parameter-missing", parameter.name, position,
        )
    value = _canonical_integer(tokens[position])
    if value is None:
        return ParseFailure(
            FailureKind.PARAMETER, f"parameter-not-integer:{parameter.name}",
            tokens[position], position,
        )
    if value < parameter.minimum or value > parameter.maximum:
        return ParseFailure(
            FailureKind.PARAMETER, f"parameter-out-of-range:{parameter.name}",
            f"{value} outside {parameter.minimum}..{parameter.maximum}", position,
        )
    return value, 1


def _canonical_mode(
    form: GrammarForm, expected_mode: CommandMode | None,
) -> CommandMode:
    if expected_mode is not None and expected_mode in form.modes:
        return expected_mode
    return min(form.modes, key=lambda mode: _CANONICAL_MODES[mode])


def _canonical_target(form: GrammarForm) -> TargetClass:
    return min(form.target_classes, key=lambda target: target.value)
