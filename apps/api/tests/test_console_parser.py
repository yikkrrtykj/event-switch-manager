from __future__ import annotations

import pytest

from event_switch_manager.console.parser import (
    AuthPromptKind,
    ConsoleOutputLimit,
    ConsolePaginationLimit,
    ConsolePromptParser,
    ParserEventKind,
    PromptMode,
    command_error_present,
    sanitize_console_text,
)


def _kinds(events: tuple[object, ...]) -> list[ParserEventKind]:
    return [event.kind for event in events]  # type: ignore[attr-defined]


def test_ansi_backspace_and_crlf_are_cleaned() -> None:
    assert sanitize_console_text("\x1b[31mR1\x1b[0m\b1\r\nok") == "R1\nok"


def test_incremental_terminal_state_ansi_backspace_and_crlf() -> None:
    parser = ConsolePromptParser()
    assert parser.feed("\x1b[") == ()
    assert parser.feed("31mR1\x1b[0") == ()
    assert parser.feed("m\b1\r") == ()
    events = parser.feed("\nR1>")
    assert _kinds(events) == [ParserEventKind.OUTPUT, ParserEventKind.PROMPT]
    assert events[0].output.endswith("R1\n")
    assert events[1].prompt == "R1>"


def test_pagination_marker_may_be_split_but_body_marker_is_not_paging() -> None:
    parser = ConsolePromptParser()
    assert parser.feed("line\n--Mo") == ()
    events = parser.feed("re--")
    assert _kinds(events) == [ParserEventKind.OUTPUT, ParserEventKind.PAGINATION]
    body = ConsolePromptParser()
    events = body.feed("This body mentions --More-- inline\nR1>")
    assert _kinds(events) == [ParserEventKind.OUTPUT, ParserEventKind.PROMPT]


def test_same_hostname_prompt_in_body_is_marked_as_collision() -> None:
    parser = ConsolePromptParser()
    events = parser.feed("R1#\nR1>")
    assert _kinds(events) == [ParserEventKind.OUTPUT, ParserEventKind.PROMPT]
    assert parser.prompt_collision is True


def test_fragmented_prompt_is_bounded_and_recognized() -> None:
    parser = ConsolePromptParser()
    assert parser.feed("R1") == ()
    events = parser.feed("> ")
    assert _kinds(events) == [ParserEventKind.PROMPT]
    assert events[0].mode is PromptMode.USER_EXEC


def test_ios_xe_privileged_prompt_and_body_prompt_collision() -> None:
    parser = ConsolePromptParser()
    events = parser.feed("CORE# is literal output text\nCORE#\n")
    assert _kinds(events) == [ParserEventKind.OUTPUT, ParserEventKind.PROMPT]
    assert events[0].output == "CORE# is literal output text\n"
    assert events[1].mode is PromptMode.PRIVILEGED_EXEC


def test_pagination_and_fragmented_next_page() -> None:
    parser = ConsolePromptParser()
    first = parser.feed("line one\n--More--\n")
    assert _kinds(first) == [ParserEventKind.OUTPUT, ParserEventKind.PAGINATION]
    second = parser.feed("line two\nR1>\n")
    assert _kinds(second) == [ParserEventKind.OUTPUT, ParserEventKind.PROMPT]
    assert second[0].output.lstrip("\n") == "line two\n"


def test_auth_prompts_and_unsafe_modes() -> None:
    parser = ConsolePromptParser()
    events = parser.feed("Username: ")
    assert _kinds(events) == [ParserEventKind.AUTH_PROMPT]
    assert events[0].auth_prompt is AuthPromptKind.USERNAME
    events = parser.feed("Password: ")
    assert events[0].auth_prompt is AuthPromptKind.PASSWORD
    events = parser.feed("R1(config)#")
    assert _kinds(events) == [ParserEventKind.UNSAFE_STATE]
    assert events[0].reason == "configuration-mode"
    events = parser.feed("rommon 2 >")
    assert events[0].reason == "bootloader-rommon"
    events = parser.feed("switch:")
    assert events[0].reason == "switch-boot-prompt"
    events = parser.feed("Would you like to enter the initial configuration dialog? [yes/no]:")
    assert events[-1].reason == "initial-configuration-dialog"


def test_command_error_detection() -> None:
    assert command_error_present("% Invalid input detected at '^' marker.")
    assert command_error_present("% Incomplete command.")
    assert not command_error_present("Version 17.12.4")


def test_parser_limits_fail_closed() -> None:
    parser = ConsolePromptParser(max_response_bytes=10)
    with pytest.raises(ConsoleOutputLimit):
        parser.feed("x" * 20)
    limited = ConsolePromptParser(max_pagination_pages=1)
    limited.feed("--More--\n")
    with pytest.raises(ConsolePaginationLimit):
        limited.feed("--More--\n")


def test_non_text_input_is_rejected() -> None:
    parser = ConsolePromptParser()
    with pytest.raises(TypeError):
        parser.feed(b"bytes")  # type: ignore[arg-type]
