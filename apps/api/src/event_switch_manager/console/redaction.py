"""Small, deterministic redaction helper for console observations and logs."""

from __future__ import annotations

import re

_SECRET_LINE = re.compile(r"(?i)\b(?:username|password|enable password|secret)\s*:")
_SECRET_VALUE = re.compile(r"(?i)\b(?:password|secret)\s+\S+")


def redact_console_output(text: str, secrets: tuple[str, ...] = ()) -> str:
    """Remove credential-shaped lines and exact synthetic secrets.

    The exact-value pass is deliberately independent of keyword heuristics so a
    test transcript containing a bare credential is still redacted.
    """
    values = tuple(secret for secret in secrets if secret)
    lines: list[str] = []
    for line in text.splitlines():
        if _SECRET_LINE.search(line) or _SECRET_VALUE.search(line):
            lines.append("[REDACTED]")
            continue
        redacted = line
        for secret in values:
            redacted = redacted.replace(secret, "[REDACTED]")
        lines.append(redacted)
    return "\n".join(lines).strip()


__all__ = ["redact_console_output"]
