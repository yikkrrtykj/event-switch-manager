"""R90 terminal protocol matrix: chunking invariance and prompt safety."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

import pytest

from event_switch_manager.console.lease import ConsoleLeaseManager
from event_switch_manager.console.models import ConsoleSource
from event_switch_manager.console.parser import (
    ConsolePromptParser,
    ParserEvent,
    ParserEventKind,
    PromptMode,
    prompt_identity_token,
)
from event_switch_manager.console.session import ConsoleSession, SessionError
from event_switch_manager.console.simulator import profiles
from event_switch_manager.integrations import ConsoleQuery


def _feed(chunks: Iterable[str]) -> tuple[ConsolePromptParser, list[ParserEvent]]:
    parser = ConsolePromptParser()
    events: list[ParserEvent] = []
    for chunk in chunks:
        events.extend(parser.feed(chunk))
    return parser, events


def _prompts(events: list[ParserEvent]) -> list[tuple[str | None, object]]:
    return [
        (event.prompt, event.mode)
        for event in events
        if event.kind is ParserEventKind.PROMPT
    ]


def _all_split_variants(text: str) -> list[list[str]]:
    variants: list[list[str]] = [[text]]
    for index in range(1, len(text)):
        variants.append([text[:index], text[index:]])
    variants.append(list(text))
    step = max(1, len(text) // 7)
    variants.append([text[index:index + step] for index in range(0, len(text), step)])
    return variants


STARTUP_STREAMS = (
    "lab-c1000 con0 is now available\r\nPress RETURN to get started.\r\n",
    "lab-c9300  con0 is now available \r\nPress RETURN to get started. \r\n",
    "Press RETURN to get started.\r\n",
    "banner\r\nPress RETURN to get started.\r\n",
)


@pytest.mark.parametrize("stream", STARTUP_STREAMS)
def test_startup_readiness_parser_is_chunk_invariant(stream: str) -> None:
    outcomes = []
    for variants in _all_split_variants(stream):
        parser, events = _feed(variants)
        startup = [
            event for event in events
            if event.kind is ParserEventKind.STARTUP_READY
        ]
        outcomes.append((
            len(startup),
            startup[0].startup_host_token if startup else None,
            parser.startup_readiness,
        ))
    assert len(set(outcomes)) == 1
    assert outcomes[0][0] == 1
    assert outcomes[0][2] is True


@pytest.mark.parametrize(
    "stream",
    [
        "Press RETURN to get started!\r\n",
        "press return to get started.\r\n",
        "Press RETURN to get start.\r\n",
        "Press RETURN to get started. extra\r\n",
        "banner only\r\n",
    ],
)
def test_startup_readiness_requires_strict_known_text(stream: str) -> None:
    parser, events = _feed([stream])
    assert parser.startup_readiness is False
    assert not any(
        event.kind is ParserEventKind.STARTUP_READY for event in events
    )


def test_startup_readiness_optional_hostname_is_anonymous() -> None:
    parser = ConsolePromptParser()
    events = parser.feed(
        "lab-c1000 con0 is now available\r\n"
        "Press RETURN to get started.\r\n",
    )
    startup = next(
        event for event in events
        if event.kind is ParserEventKind.STARTUP_READY
    )
    assert startup.startup_host_token is not None
    assert "lab-c1000" not in str(startup)


def test_startup_readiness_all_five_profiles() -> None:
    for profile in profiles():
        stream = (
            f"{profile.hostname} con0 is now available\r\n"
            "Press RETURN to get started.\r\n"
        )
        for variants in _all_split_variants(stream):
            parser, events = _feed(variants)
            startup = [
                event for event in events
                if event.kind is ParserEventKind.STARTUP_READY
            ]
            assert len(startup) == 1
            assert startup[0].startup_host_token is not None
            assert parser.startup_readiness is True


def test_startup_readiness_random_splits_all_profiles() -> None:
    import random

    rng = random.Random(9200)
    for profile in profiles():
        stream = (
            f"{profile.hostname} con0 is now available\r\n"
            "Press RETURN to get started.\r\n"
        )
        for _ in range(40):
            chunks: list[str] = []
            index = 0
            while index < len(stream):
                width = rng.randint(1, 11)
                chunks.append(stream[index:index + width])
                index += width
            parser, events = _feed(chunks)
            startup = [
                event for event in events
                if event.kind is ParserEventKind.STARTUP_READY
            ]
            assert len(startup) == 1
            assert startup[0].startup_host_token is not None
            assert parser.startup_readiness is True


@pytest.mark.parametrize(
    "stream",
    [
        "banner line\r\nR1>\r\n",
        "R1#\r\n",
        "R1#\r\nR1#\r\n",
        "banner\r\nR1#\r\nlab-2960x#\r\n",
        "\x1b[2Jbanner\r\nR1#\r\n",
        "banner\rR1#\r\n",
        "banner\r\nR1#",
    ],
)
def test_parser_chunking_invariance_for_exec_prompts(stream: str) -> None:
    outcomes = []
    for variants in _all_split_variants(stream):
        parser, events = _feed(variants)
        final = _prompts(events)[-1] if _prompts(events) else None
        outcomes.append((final, parser.prompt_collision))
    assert len(set(outcomes)) == 1, outcomes


@pytest.mark.parametrize(
    "stream",
    [
        "R1#\r\nR1#\r\n",
        "R1#\r\nR1#\r\nR1#\r\n",
        "R1>\r\nR1>\r\n",
        "banner\r\nR1#\r\n",
        "\x1b]0;title\x07R1#\n",
        "R1X\b#\r\n",
    ],
)
def test_parser_accepts_safe_same_identity_prompts(stream: str) -> None:
    for variants in _all_split_variants(stream):
        parser, events = _feed(variants)
        assert parser.prompt_collision is False, (
            variants, parser.prompt_collision_reason,
        )
        assert _prompts(events)


@pytest.mark.parametrize(
    "stream",
    [
        "R1#\r\nR2#\r\n",
        "R1>\r\nR1#\r\n",
        "R1#\r\nR1#\r\nR1#\r\nR1#\r\n",
    ],
)
def test_parser_rejects_changed_or_excessive_prompts(stream: str) -> None:
    for variants in _all_split_variants(stream):
        parser, _events = _feed(variants)
        assert parser.prompt_collision is True, variants


@pytest.mark.parametrize(
    "stream",
    [
        "R1#\r\nR1(config)#\r\n",
        "R1#\r\nrommon 1 >\r\n",
        "R1#\r\ninitial configuration dialog? [yes/no]:\r\n",
    ],
)
def test_parser_rejects_unsafe_device_states(stream: str) -> None:
    for variants in _all_split_variants(stream):
        _parser, events = _feed(variants)
        assert any(event.kind is ParserEventKind.UNSAFE_STATE for event in events), variants


def test_all_five_profiles_repeat_same_prompt_safely() -> None:
    assert len(profiles()) == 5
    for profile in profiles():
        prompt = f"{profile.hostname}#"
        parser = ConsolePromptParser()
        events = parser.feed(f"banner\r\n{prompt}\r\n{prompt}\r\n")
        assert parser.prompt_collision is False
        assert [event.prompt for event in events if event.kind is ParserEventKind.PROMPT] == [
            prompt,
        ]
        assert parser.prompt_repeats == 1
        assert parser.last_prompt_identity == prompt_identity_token(
            prompt, PromptMode.PRIVILEGED_EXEC,
        )


class _ChunkTransport:
    source = ConsoleSource.SIMULATOR
    port_identity = "sim:chunk-matrix"
    lease_endpoint = "sim:chunk-matrix"
    identity_quality = "stable"

    def __init__(
        self,
        chunks: list[str],
        *,
        response_chunks: list[str] | None = None,
    ) -> None:
        self._chunks = list(chunks)
        self._response_chunks = list(response_chunks or [])
        self._open = False
        self.writes: list[str] = []

    def pending_data(self) -> bool:
        return bool(self._chunks)

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def write(self, text: str) -> None:
        self.writes.append(text)
        if text == "show version\r":
            self._chunks.extend(self._response_chunks)

    def read_chunk(self, timeout: float) -> str:
        _ = timeout
        if not self._open:
            raise RuntimeError("closed")
        return self._chunks.pop(0) if self._chunks else ""


def _open_chunks(chunks: list[str]) -> ConsoleSession:
    session = ConsoleSession(
        _ChunkTransport(chunks),
        lease_manager=ConsoleLeaseManager(),
        timeout=0.5,
    )
    session.open(None)
    return session


@pytest.mark.parametrize(
    "stream",
    [
        "banner\r\nR1#\r\nR1#\r\n",
        "banner\r\nR1#\r\n",
    ],
)
def test_session_chunking_invariance_for_safe_attach(stream: str) -> None:
    outcomes = []
    for variants in _all_split_variants(stream):
        session = _open_chunks(variants)
        try:
            outcomes.append((
                session.is_attached,
                session.terminal_diagnostics["prompt_collision_reason"],
            ))
        finally:
            session.close()
    assert len(set(outcomes)) == 1
    assert outcomes[0][0] is True
    assert outcomes[0][1] is None


@pytest.mark.parametrize(
    "stream",
    [
        "R1#\r\nR2#\r\n",
        "R1#\r\nR1#\r\nR1#\r\nR1#\r\n",
        "R1#\r\ncopy running-config startup-config\r\nR1#\r\n",
        "R1#\r\n%SYS-5-CONFIG_I: asynchronous event\r\nR1#\r\n",
        "R1#\r\nR1(config)#\r\n",
        "R1#\r\nrommon 1 >\r\n",
        "R1#\r\ninitial configuration dialog? [yes/no]:\r\n",
    ],
)
def test_session_rejects_unsafe_chunked_terminal_states(stream: str) -> None:
    for variants in _all_split_variants(stream):
        with pytest.raises(SessionError):
            session = _open_chunks(variants)
            session.close()


def test_query_response_chunking_is_invariant() -> None:
    response = (
        "show version\r\n"
        "Cisco IOS Software, C2960X Software\r\n"
        "R1#\r\n"
    )
    outcomes = []
    for variants in _all_split_variants(response):
        transport = _ChunkTransport(
            ["R1#\r\n"], response_chunks=variants,
        )
        session = ConsoleSession(
            transport,
            lease_manager=ConsoleLeaseManager(),
            timeout=1.0,
        )
        session.open(None)
        try:
            result = session.query_result(ConsoleQuery.VERSION)
            outcomes.append((
                result.status.value,
                "Cisco IOS Software" in result.output,
                result.command_sent,
                result.response_bytes > 0,
            ))
        finally:
            session.close()
    assert len(set(outcomes)) == 1, outcomes
    assert outcomes[0] == ("ok", True, True, True)


def test_terminal_diagnostics_are_bounded_and_content_free() -> None:
    session = ConsoleSession(
        _ChunkTransport(["x" * 10] * 40 + ["\r\nR1#\r\n"]),
        lease_manager=ConsoleLeaseManager(),
        timeout=5.0,
    )
    try:
        session.open(None)
        diagnostics = session.terminal_diagnostics
    finally:
        session.close()
    chunk_count = diagnostics["rx_chunk_count"]
    total_bytes = diagnostics["rx_total_bytes"]
    assert isinstance(chunk_count, int) and chunk_count >= 1
    assert isinstance(total_bytes, int) and total_bytes > 0
    lengths = diagnostics["rx_chunk_lengths"]
    assert isinstance(lengths, list)
    assert len(lengths) <= 64
    assert diagnostics["prompt_identity_token"] is not None
    assert "R1#" not in str(diagnostics)
    assert "banner" not in str(diagnostics)
    assert "authentication" not in str(diagnostics).casefold() or (
        diagnostics["authentication_prompt_seen"] is False
    )


def test_all_five_profiles_run_a_query_through_chunked_transport() -> None:
    for profile in profiles():
        response = (
            f"show version\r\nCisco IOS Software, {profile.model}\r\n"
            f"{profile.hostname}#\r\n"
        )
        transport = _ChunkTransport(
            [f"{profile.hostname}#\r\n"],
            response_chunks=[response[:max(1, len(response) // 3)],
                             response[max(1, len(response) // 3):]],
        )
        session = ConsoleSession(
            transport,
            lease_manager=ConsoleLeaseManager(),
            timeout=1.0,
        )
        session.open(None)
        try:
            result = session.query_result(ConsoleQuery.VERSION)
        finally:
            session.close()
        assert result.status.value == "ok"
        assert "Cisco IOS Software" in result.output


def test_pagination_chunking_is_invariant() -> None:
    stream = "page one\r\n--More--"
    for variants in _all_split_variants(stream):
        parser, events = _feed(variants)
        assert parser.pages == 1
        assert any(event.kind is ParserEventKind.PAGINATION for event in events)


def test_r91_attach_failure_fixture_is_evidence_only() -> None:
    fixture = Path(__file__).parent / "fixtures" / "console_lab_r91_attach_failure.json"
    data = json.loads(fixture.read_text(encoding="utf-8"))
    failure = data["failure"]
    assert data["schema"] == "r91-passive-attach-failure-fixture-v1"
    assert failure["transport_status"] == "OPENED"
    assert failure["passive_attach_status"] == "FAILED"
    assert failure["primary_failure"] == "AmbiguousConsoleOutput"
    assert failure["prompt_collision_reason"] == "output-between-prompt-candidates"
    assert failure["prompt_candidates"] == 3
    assert failure["prompt_modes"] == {"user-exec": 3}
    assert failure["prompt_repeats"] == 0
    assert failure["rx_chunk_count"] == 188
    assert failure["rx_total_bytes"] == 293
    assert failure["parser_buffer_bytes"] == 0
    assert failure["wake_sent"] is False
    assert failure["queries"] == 0
    assert failure["root_cause"] == "not-inferred"


def test_r90_terminal_failure_fixture_is_sanitized() -> None:
    fixture = Path(__file__).parent / "fixtures" / "console_lab_r90_terminal_failure.json"
    data = json.loads(fixture.read_text(encoding="utf-8"))
    assert data["schema"] == "r90-terminal-failure-fixture-v1"
    failure = data["failure"]
    assert failure["transport_opened"] is True
    assert failure["connection_status"] == "ATTACH_FAILED"
    assert failure["passive_attach_status"] == "FAILED"
    assert failure["wake_sent"] is False
    assert failure["queries"] == 0
    assert failure["terminal_diagnostics"]["raw_transcript_saved"] is False
    assert failure["terminal_diagnostics"]["credential_saved"] is False
    assert "password" not in fixture.read_text(encoding="utf-8").casefold()


def test_prompt_candidate_exposes_incomplete_line_metadata() -> None:
    parser = ConsolePromptParser()
    events = parser.feed("banner\r\nR1#")
    prompt_event = next(event for event in events if event.kind is ParserEventKind.PROMPT)
    assert prompt_event.line_terminated is False

    parser = ConsolePromptParser()
    events = parser.feed("banner\r\nR1#\r\n")
    prompt_event = next(event for event in events if event.kind is ParserEventKind.PROMPT)
    assert prompt_event.line_terminated is True


def test_prompt_identity_token_never_contains_hostname() -> None:
    prompt = "very-secret-hostname#"
    token = prompt_identity_token(prompt, PromptMode.PRIVILEGED_EXEC)
    assert prompt not in token
    assert len(token) == 16
