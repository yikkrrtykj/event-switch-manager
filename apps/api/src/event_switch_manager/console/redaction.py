"""Small, deterministic redaction helper for console observations and logs."""

from __future__ import annotations

import re

_SECRET_LINE = re.compile(r"(?i)\b(?:username|password|enable password|secret)\s*:")
_SECRET_VALUE = re.compile(r"(?i)\b(?:password|secret)\s+\S+")


def redact_console_output(text: str) -> str:
    """Remove credential-shaped lines before evidence/export/error handling."""
    lines: list[str] = []
    for line in text.splitlines():
        if _SECRET_LINE.search(line) or _SECRET_VALUE.search(line):
            lines.append("[REDACTED]")
        else:
            lines.append(line)
    return "\n".join(lines).strip()


__all__ = ["redact_console_output"]
