"""Bounded live-serial prompt completion policy.

The policy does not prove that a real serial response is complete.  It imposes
a bounded quiet window after the first candidate prompt, then the
operator-assisted runner requires a separate human confirmation before another
command is sent.  Real-serial completion remains NOT_VERIFIED.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(slots=True)
class LiveCompletionPolicy:
    quiet_seconds: float = 0.25

    _last_chunk_at: float | None = None
    _candidate_at: float | None = None
    _chunks: int = 0

    def __post_init__(self) -> None:
        if not 0 < self.quiet_seconds <= 2:
            raise ValueError("live completion quiet window must be in (0, 2]")

    def observe_chunk(self, chunk: str) -> None:
        if not chunk:
            return
        self._chunks += 1
        self._last_chunk_at = time.monotonic()
        if self._candidate_at is not None and not chunk.strip():
            # Terminal prompts and their trailing CR/LF/space may arrive in
            # separate chunks.  Preserve the candidate and restart the quiet
            # window for bounded trailing whitespace.
            return
        # Any non-whitespace bytes after a candidate prompt are a new
        # observation and cannot be silently treated as completion.
        self._candidate_at = None

    def candidate_seen(self) -> None:
        self._candidate_at = time.monotonic()

    def candidate_ready(self) -> bool:
        if self._candidate_at is None:
            return False
        reference = self._last_chunk_at or self._candidate_at
        return time.monotonic() - reference >= self.quiet_seconds

    def next_check_seconds(self) -> float:
        if self._candidate_at is None:
            return self.quiet_seconds
        reference = self._last_chunk_at or self._candidate_at
        return max(0.001, self.quiet_seconds - (time.monotonic() - reference))

    @property
    def chunk_count(self) -> int:
        return self._chunks


__all__ = ["LiveCompletionPolicy"]
