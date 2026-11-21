"""CIS-02B2-03 strict single-line tokenizer.

The lexer is the text-safety half of the independent validation layer. It does
not import the frozen renderer and it never normalizes input:

* a rejected character is never stripped, truncated, replaced, escaped or
  case-folded into an accepted command;
* only one printable ASCII line is allowed, with exactly one space between
  tokens and no leading or trailing space;
* tokens keep their original text, so the parser compares what was received,
  not a cleaned-up variant.

Shell metacharacters and other characters outside the reviewed safe alphabet
are rejected at the text layer before any command form is matched. That keeps
the policy independent from the command grammar: an injected semicolon cannot
become part of a "description" or a trailing command.
"""

from __future__ import annotations

import string
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

#: No reviewed candidate can be longer than this; a longer line is refused
#: before parsing rather than truncated.
MAX_COMMAND_LENGTH: Final[int] = 512

#: Reviewed safe printable alphabet. It is the union of the command keyword
#: alphabet and the reviewed VLAN-name / description character subsets.
SAFE_TEXT_CHARACTERS: Final[frozenset[str]] = frozenset(
    string.ascii_letters + string.digits + " .,:/_+%@-",
)

_SPACE: Final[str] = " "


class TextIssueCode(StrEnum):
    """Deterministic text-safety reason codes."""

    NOT_A_STRING = "text-not-a-string"
    EMPTY = "text-empty"
    TOO_LONG = "text-too-long"
    NON_ASCII = "text-non-ascii"
    CONTROL_CHARACTER = "text-control-character"
    FORBIDDEN_CHARACTER = "text-forbidden-character"
    EDGE_WHITESPACE = "text-edge-whitespace"
    DOUBLE_SPACE = "text-double-space"
    NOT_SINGLE_LINE = "text-not-single-line"


@dataclass(frozen=True, slots=True)
class TextIssue:
    """One deterministic text-safety violation at a character offset."""

    code: TextIssueCode
    position: int

    @property
    def reason(self) -> str:
        return f"{self.code.value}@{self.position}"


@dataclass(frozen=True, slots=True)
class Token:
    """One space-delimited token with its original text and offset."""

    text: str
    index: int
    start: int


@dataclass(frozen=True, slots=True)
class LexResult:
    """Result of strict tokenization; ``issues`` is empty only when accepted."""

    text: str
    tokens: tuple[Token, ...]
    issues: tuple[TextIssue, ...]

    @property
    def ok(self) -> bool:
        return not self.issues

    @property
    def failure_codes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(issue.code.value for issue in self.issues))

    @property
    def token_texts(self) -> tuple[str, ...]:
        return tuple(token.text for token in self.tokens)


_EMPTY = LexResult("", (), (TextIssue(TextIssueCode.EMPTY, 0),))


def _append(issues: list[TextIssue], code: TextIssueCode, position: int) -> None:
    issue = TextIssue(code, position)
    if issue not in issues:
        issues.append(issue)


def lex_command(text: object) -> LexResult:
    """Tokenize one command line, rejecting anything outside the safe alphabet.

    The argument is typed as ``object`` so a non-string JSON value (number,
    list, object) fails closed instead of being coerced with ``str()``.
    """
    if not isinstance(text, str):
        return LexResult("", (), (TextIssue(TextIssueCode.NOT_A_STRING, 0),))
    if text == "":
        return _EMPTY

    issues: list[TextIssue] = []
    if len(text) > MAX_COMMAND_LENGTH:
        _append(issues, TextIssueCode.TOO_LONG, MAX_COMMAND_LENGTH)

    for position, character in enumerate(text):
        code_point = ord(character)
        if code_point < 0x20 or code_point == 0x7F:
            _append(issues, TextIssueCode.CONTROL_CHARACTER, position)
            continue
        if code_point > 0x7E:
            _append(issues, TextIssueCode.NON_ASCII, position)
            continue
        if character not in SAFE_TEXT_CHARACTERS:
            _append(issues, TextIssueCode.FORBIDDEN_CHARACTER, position)

    if text.startswith(_SPACE):
        _append(issues, TextIssueCode.EDGE_WHITESPACE, 0)
    if text.endswith(_SPACE):
        _append(issues, TextIssueCode.EDGE_WHITESPACE, len(text) - 1)
    for position in range(len(text) - 1):
        if text[position] == _SPACE and text[position + 1] == _SPACE:
            _append(issues, TextIssueCode.DOUBLE_SPACE, position)
    newline = text.find("\n")
    carriage_return = text.find("\r")
    if newline >= 0 or carriage_return >= 0:
        position = min(
            value for value in (newline, carriage_return) if value >= 0
        )
        _append(issues, TextIssueCode.NOT_SINGLE_LINE, position)

    tokens = _tokenize(text)
    return LexResult(text, tokens, tuple(issues))


def _tokenize(text: str) -> tuple[Token, ...]:
    tokens: list[Token] = []
    start = 0
    index = 0
    while start < len(text):
        end = text.find(_SPACE, start)
        if end < 0:
            end = len(text)
        if end > start:
            tokens.append(Token(text[start:end], index, start))
            index += 1
        start = end + 1
    return tuple(tokens)

