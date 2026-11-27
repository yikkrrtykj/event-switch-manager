"""Bounded, incremental Cisco IOS / IOS XE prompt parser.

All device output is untrusted data.  The parser only recognizes terminal
control, prompts, authentication prompts and pagination; it never executes or
derives a next CLI command from output text.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum

from .models import CONSOLE_PARSER_VERSION

_PAGINATION_END = re.compile(r"(?:--\s*More\s*--|<---\s*More\s*--->)\s*$")
_PROMPT = re.compile(
    r"(?m)^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,63})(?P<suffix>[>#])\s*$",
)
_CONFIG_PROMPT = re.compile(
    r"(?m)^[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?:\([^)]*\))#\s*$",
)
_ROMMON_PROMPT = re.compile(r"(?mi)^rommon(?:\s+\d+)?\s*>\s*$")
_SWITCH_PROMPT = re.compile(r"(?mi)^switch:\s*$")
_INITIAL_DIALOG = re.compile(r"(?i)initial configuration dialog.*\[yes/no\]")
_AUTH_PROMPT = re.compile(
    r"(?im)^(?P<label>username|password|enable password|enter password)\s*:\s*$",
)
_COMMAND_ERROR = re.compile(
    r"(?im)^% ?(?:invalid input|incomplete command|ambiguous command|unknown command|error)",
)

MAX_RESPONSE_BYTES = 256 * 1024
MAX_PAGINATION_PAGES = 20
MAX_PROMPT_REPEATS = 2
MAX_PROMPT_CANDIDATES = 3


def prompt_identity_token(prompt: str, mode: PromptMode | None = None) -> str:
    """Anonymous stable token for diagnostics; never exposes the hostname."""
    material = f"{prompt}|{mode.value if mode is not None else 'unknown'}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


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
    prompt: str | None = None
    mode: PromptMode | None = None
    auth_prompt: AuthPromptKind | None = None
    reason: str | None = None


class ConsoleOutputLimit(RuntimeError):
    """Bounded parser limits were exceeded."""


class ConsolePaginationLimit(RuntimeError):
    """The device requested more pages than the configured bound."""


class _TerminalSanitizer:
    """Bounded, stateful terminal noise removal across chunk boundaries.

    CSI/OSC payloads are deliberately discarded rather than accumulated.  The
    state machine only retains the few bits needed to recognize a terminator,
    so an unterminated escape sequence cannot bypass response limits.
    """

    def __init__(self) -> None:
        self._escape_mode: str | None = None
        self._osc_escape = False
        self._skip_lf = False

    def reset(self) -> None:
        self._escape_mode = None
        self._osc_escape = False
        self._skip_lf = False

    def feed(self, data: str) -> str:
        output: list[str] = []
        for character in data:
            if self._skip_lf:
                self._skip_lf = False
                if character == "\n":
                    continue
            if self._escape_mode is not None:
                if self._escape_mode == "start":
                    if character == "[":
                        self._escape_mode = "csi"
                    elif character == "]":
                        self._escape_mode = "osc"
                    else:
                        self._escape_mode = None
                    continue
                if self._escape_mode == "csi":
                    if 0x40 <= ord(character) <= 0x7E:
                        self._escape_mode = None
                    continue
                if self._escape_mode == "osc":
                    if self._osc_escape:
                        self._osc_escape = False
                        if character == "\\":
                            self._escape_mode = None
                        continue
                    if character == "\x07":
                        self._escape_mode = None
                    elif character == "\x1b":
                        self._osc_escape = True
                    continue
                continue
            if character == "\x1b":
                self._escape_mode = "start"
                continue
            if character == "\r":
                # A lone CR is a complete line terminator even when CR/LF
                # arrive in different reads.  The following LF, if any, is
                # suppressed without buffering across chunk boundaries.
                output.append("\n")
                self._skip_lf = True
                continue
            if character == "\b":
                output.append("\b")
                continue
            if character in {"\t", "\n"} or 0x20 <= ord(character) <= 0x7E:
                output.append(character)
        return "".join(output)


def sanitize_console_text(text: str) -> str:
    """Best-effort one-shot sanitizer retained for callers and tests."""
    sanitizer = _TerminalSanitizer()
    raw = sanitizer.feed(text)
    output: list[str] = []
    for character in raw:
        if character == "\b":
            if output:
                output.pop()
        else:
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
        self._terminal = _TerminalSanitizer()
        self._prompt_collision = False
        self._prompt_collision_reason: str | None = None
        self._prompt_candidates = 0
        self._prompt_repeats = 0
        self._last_prompt_identity: str | None = None
        self._last_prompt_text: str | None = None
        self._last_prompt_mode: PromptMode | None = None
        self.parser_version = CONSOLE_PARSER_VERSION

    @property
    def pages(self) -> int:
        return self._pages

    @property
    def prompt_collision(self) -> bool:
        return self._prompt_collision

    @property
    def prompt_collision_reason(self) -> str | None:
        return self._prompt_collision_reason

    @property
    def prompt_candidates(self) -> int:
        return self._prompt_candidates

    @property
    def prompt_repeats(self) -> int:
        return self._prompt_repeats

    @property
    def last_prompt_identity(self) -> str | None:
        return self._last_prompt_identity

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer.encode("utf-8", errors="replace"))

    @property
    def has_unconsumed_non_whitespace(self) -> bool:
        return bool(self._buffer.strip())

    def mark_prompt_collision(self, reason: str = "caller-detected") -> None:
        self._prompt_collision = True
        self._prompt_collision_reason = reason

    def reset(self) -> None:
        self._buffer = ""
        self._pages = 0
        self._terminal.reset()
        self._prompt_collision = False
        self._prompt_collision_reason = None
        self._prompt_candidates = 0
        self._prompt_repeats = 0
        self._last_prompt_identity = None
        self._last_prompt_text = None
        self._last_prompt_mode = None

    def _prompt_collision_for_prefix(
        self,
        prefix: str,
        prompt_text: str,
        mode: PromptMode,
    ) -> str | None:
        """Distinguish a safe repeated same-identity prompt from corruption.

        Only exact repeats of the same prompt identity and mode are accepted,
        and only within a small bound.  Different identities, mixed modes,
        config/ROMMON prompts, or excessive repeats remain collisions.
        """
        repeated = 0
        prompt_seen = False
        for line in prefix.splitlines():
            normalized = line.strip()
            if not normalized:
                continue
            if _CONFIG_PROMPT.fullmatch(normalized):
                return "config-prompt-in-output"
            if _ROMMON_PROMPT.fullmatch(normalized):
                return "rommon-prompt-in-output"
            if _SWITCH_PROMPT.fullmatch(normalized):
                return "switch-prompt-in-output"
            match = _PROMPT.fullmatch(normalized)
            if match is None:
                if prompt_seen:
                    return "output-after-prompt-in-prefix"
                continue
            if normalized != prompt_text:
                return "different-prompt-in-output"
            repeated += 1
            prompt_seen = True
        if repeated > MAX_PROMPT_REPEATS:
            return "excessive-prompt-repeats"
        if repeated:
            self._prompt_repeats += repeated
        return None

    def feed(self, data: str) -> tuple[ParserEvent, ...]:
        if not isinstance(data, str):
            raise TypeError("console parser input must be text")
        for character in self._terminal.feed(data):
            if character == "\b":
                self._buffer = self._buffer[:-1]
            else:
                self._buffer += character
        if self.buffered_bytes > self._max_response_bytes:
            self.reset()
            raise ConsoleOutputLimit("console response exceeded the byte limit")

        events: list[ParserEvent] = []
        while self._buffer:
            stripped = self._buffer.rstrip()
            pagination = _PAGINATION_END.search(stripped)
            if pagination is not None:
                if self._pages >= self._max_pagination_pages:
                    self.reset()
                    raise ConsolePaginationLimit("console pagination limit exceeded")
                self._pages += 1
                output = stripped[:pagination.start()]
                self._buffer = ""
                if output:
                    events.append(ParserEvent(ParserEventKind.OUTPUT, output=output))
                events.append(ParserEvent(ParserEventKind.PAGINATION))
                continue

            last_line = stripped.rsplit("\n", 1)[-1]

            auth = _AUTH_PROMPT.fullmatch(last_line.strip())
            if auth is not None:
                start = self._buffer.rfind(last_line)
                output = self._buffer[:start]
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

            if _SWITCH_PROMPT.fullmatch(last_line.strip()):
                self._buffer = ""
                events.append(ParserEvent(
                    ParserEventKind.UNSAFE_STATE,
                    reason="switch-boot-prompt",
                ))
                continue

            prompt = _PROMPT.fullmatch(last_line.strip())
            if prompt is not None:
                start = self._buffer.rfind(last_line)
                output = self._buffer[:start]
                self._buffer = ""
                mode = (
                    PromptMode.PRIVILEGED_EXEC
                    if prompt.group("suffix") == "#"
                    else PromptMode.USER_EXEC
                )
                prompt_text = last_line.strip()
                if (
                    self._last_prompt_text is not None
                    and (
                        prompt_text != self._last_prompt_text
                        or mode is not self._last_prompt_mode
                    )
                ):
                    self._prompt_collision = True
                    self._prompt_collision_reason = (
                        "prompt-identity-changed-between-chunks"
                    )
                if output:
                    collision = self._prompt_collision_for_prefix(
                        output, prompt_text, mode,
                    )
                    if collision is not None:
                        self._prompt_collision = True
                        self._prompt_collision_reason = collision
                    events.append(ParserEvent(ParserEventKind.OUTPUT, output=output))
                self._prompt_candidates += 1
                if (
                    self._prompt_candidates + self._prompt_repeats
                    > MAX_PROMPT_CANDIDATES
                ):
                    self._prompt_collision = True
                    self._prompt_collision_reason = "excessive-prompt-candidates"
                self._last_prompt_text = prompt_text
                self._last_prompt_mode = mode
                self._last_prompt_identity = prompt_identity_token(
                    prompt_text, mode,
                )
                events.append(ParserEvent(
                    ParserEventKind.PROMPT,
                    prompt=prompt_text,
                    mode=mode,
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
    "MAX_PROMPT_CANDIDATES",
    "MAX_PROMPT_REPEATS",
    "MAX_RESPONSE_BYTES",
    "ParserEvent",
    "ParserEventKind",
    "PromptMode",
    "command_error_present",
    "prompt_identity_token",
    "sanitize_console_text",
]
