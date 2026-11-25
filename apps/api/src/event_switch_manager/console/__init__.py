"""CON-01 console read-only discovery foundation.

This package is deliberately not wired into the application API or launcher.
It contains observation-only models and a disabled live-serial adapter.  Real
device sessions are not reachable from the product runtime in CON-01.
"""

from .models import (
    CONSOLE_EVIDENCE_SCHEMA_VERSION,
    CONSOLE_PARSER_VERSION,
    ConsoleEvidence,
    ConsoleInterface,
    ConsoleObservation,
    ConsoleSource,
    ConsoleStackMember,
    LicenseObservation,
    ObservationCompleteness,
    QueryStatus,
)
from .session import ConsoleCredentials, ConsoleSession

__all__ = [
    "CONSOLE_EVIDENCE_SCHEMA_VERSION",
    "CONSOLE_PARSER_VERSION",
    "ConsoleCredentials",
    "ConsoleEvidence",
    "ConsoleInterface",
    "ConsoleObservation",
    "ConsoleSession",
    "ConsoleSource",
    "ConsoleStackMember",
    "LicenseObservation",
    "ObservationCompleteness",
    "QueryStatus",
]
