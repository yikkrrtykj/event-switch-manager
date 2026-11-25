"""Bounded, incremental Cisco IOS / IOS XE prompt parser.

All device output is untrusted data.  The parser only recognizes terminal
control, prompts, authentication prompts and pagination; it never executes or
derives a next CLI command from output text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from .models import CONSOLE_PARSER_VERSION

_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_PAGINATION = re.compile(r"(?:--\s*More\s*--|<---\s*More\s*--->)")
_PROMPT = re.compile(
    r"(?m)^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,63})(?P<suffix>[>#])\s*$",
)
_CONFIG_PROMPT = re.compile(
    r"(?m)^[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?:\([^)]*\))#\s*$",
)
_ROMMON_PROMPT = re.compile(r"(?mi)^rommon(?:\s+\d+)?\s*>\s*$")
_INITIAL_DIALOG = re.compile(r"(?i)initial configuration dialog.*\[yes/no\]")
_AUTH_PROMPT = re.compile(
    r"(?im)^(?P<label>username|password|enable password|enter password)\s*:\s*$",
)
_COMMAND_ERROR = re.compile(
    r"(?im)^% ?(?:invalid input|incomplete command|ambiguous command|unknown command|error)",
)

MAX_RESPONSE_BYTES = 256 * 1024
MAX_PAGINATION_PAGES = 20


class ParserEventKind(StrEnum):
    OUTPUT = "output"
    PROMPT = "prompt"
    AUTH_PROMPT = "auth-prompt"
    PAGINATION = "pagination"
    UNSAFE_STATE = "unsafe-state"


class PromptMode(StrEnum):
    USER_EXEC = "user-exec"
    PRIVILEGED_EXEC = "privileged-exec"


class AuthPromptKind(StrEnum):
    USERNAME = "username"
    PASSWORD = "password"
    ENABLE_PASSWORD = "enable-password"


@dataclass(frozen=True, slots=True)
class ParserEvent:
    kind: ParserEventKind
    output: str = ""
    mode: PromptMode | None = None
    auth_prompt: AuthPromptKind | None = None
    reason: str | None = None


class ConsoleOutputLimit(RuntimeError):
    """Bounded parser limits were exceeded."""


class ConsolePaginationLimit(RuntimeError):
    """The device requested more pages than the configured bound."""


def sanitize_console_text(text: str) -> str:
    """Remove ANSI/control noise and apply backspace without trusting content."""
    text = _ANSI.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    output: list[str] = []
    for character in text:
        if character == "\b":
            if output:
                output.pop()
            continue
        if character in {"\x00", "\x07"}:
            continue
        if character in {"\t", "\n"} or 0x20 <= ord(character) <= 0x7E:
            output.append(character)
    return "".join(output)


def _auth_kind(label: str) -> AuthPromptKind:
    normalized = label.casefold()
    if normalized == "username":
        return AuthPromptKind.USERNAME
    if normalized == "enable password":
        return AuthPromptKind.ENABLE_PASSWORD
    return AuthPromptKind.PASSWORD


class ConsolePromptParser:
    def __init__(
        self,
        *,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        max_pagination_pages: int = MAX_PAGINATION_PAGES,
    ) -> None:
        if max_response_bytes <= 0 or max_pagination_pages <= 0:
            raise ValueError("parser limits must be positive")
        self._buffer = ""
        self._max_response_bytes = max_response_bytes
        self._max_pagination_pages = max_pagination_pages
        self._pages = 0
        self.parser_version = CONSOLE_PARSER_VERSION

    @property
    def pages(self) -> int:
        return self._pages

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer.encode("utf-8", errors="replace"))

    def reset(self) -> None:
        self._buffer = ""
        self._pages = 0

    def feed(self, data: str) -> tuple[ParserEvent, ...]:
        if not isinstance(data, str):
            raise TypeError("console parser input must be text")
        cleaned = sanitize_console_text(data)
        self._buffer += cleaned
        if self.buffered_bytes > self._max_response_bytes:
            self.reset()
            raise ConsoleOutputLimit("console response exceeded the byte limit")

        events: list[ParserEvent] = []
        while self._buffer:
            pagination = _PAGINATION.search(self._buffer)
            if pagination is not None:
                if self._pages >= self._max_pagination_pages:
                    self.reset()
                    raise ConsolePaginationLimit("console pagination limit exceeded")
                self._pages += 1
                if pagination.start():
                    events.append(ParserEvent(
                        ParserEventKind.OUTPUT,
                        output=self._buffer[:pagination.start()],
                    ))
                self._buffer = self._buffer[pagination.end():]
                events.append(ParserEvent(ParserEventKind.PAGINATION))
                continue

            stripped = self._buffer.rstrip()
            last_line = stripped.rsplit("\n", 1)[-1]

            auth = _AUTH_PROMPT.fullmatch(last_line.strip())
            if auth is not None:
                output = self._buffer[:self._buffer.rfind(last_line)]
                self._buffer = ""
                if output:
                    events.append(ParserEvent(ParserEventKind.OUTPUT, output=output))
                events.append(ParserEvent(
                    ParserEventKind.AUTH_PROMPT,
                    auth_prompt=_auth_kind(auth.group("label")),
                ))
                continue

            if _INITIAL_DIALOG.search(self._buffer):
                output = _INITIAL_DIALOG.split(self._buffer, 1)[0]
                self._buffer = ""
                if output:
                    events.append(ParserEvent(ParserEventKind.OUTPUT, output=output))
                events.append(ParserEvent(
                    ParserEventKind.UNSAFE_STATE,
                    reason="initial-configuration-dialog",
                ))
                continue

            if _CONFIG_PROMPT.fullmatch(last_line.strip()):
                self._buffer = ""
                events.append(ParserEvent(
                    ParserEventKind.UNSAFE_STATE,
                    reason="configuration-mode",
                ))
                continue

            if _ROMMON_PROMPT.fullmatch(last_line.strip()):
                self._buffer = ""
                events.append(ParserEvent(
                    ParserEventKind.UNSAFE_STATE,
                    reason="bootloader-rommon",
                ))
                continue

            prompt = _PROMPT.fullmatch(last_line.strip())
            if prompt is not None:
                start = self._buffer.rfind(last_line)
                output = self._buffer[:start]
                self._buffer = ""
                if output:
                    events.append(ParserEvent(ParserEventKind.OUTPUT, output=output))
                events.append(ParserEvent(
                    ParserEventKind.PROMPT,
                    mode=(
                        PromptMode.PRIVILEGED_EXEC
                        if prompt.group("suffix") == "#"
                        else PromptMode.USER_EXEC
                    ),
                ))
                continue

            break
        return tuple(events)


def command_error_present(output: str) -> bool:
    return _COMMAND_ERROR.search(output) is not None


__all__ = [
    "AuthPromptKind",
    "ConsoleOutputLimit",
    "ConsolePaginationLimit",
    "ConsolePromptParser",
    "MAX_PAGINATION_PAGES",
    "MAX_RESPONSE_BYTES",
    "ParserEvent",
    "ParserEventKind",
    "PromptMode",
    "command_error_present",
    "sanitize_console_text",
]
