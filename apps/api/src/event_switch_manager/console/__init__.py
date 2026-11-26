"""CON-01 console read-only discovery foundation.

This package is deliberately not wired into the application API or launcher.
It contains observation-only models and a disabled live-serial adapter.  Real
device sessions are not reachable from the product runtime in CON-01.
"""

from .models import (
    CONSOLE_EVIDENCE_SCHEMA_VERSION,
    CONSOLE_PARSER_VERSION,
    ConsoleBootEntry,
    ConsoleEvidence,
    ConsoleInterface,
    ConsoleInventoryMember,
    ConsoleObservation,
    ConsoleSource,
    ConsoleStackMember,
    ConsoleStorageEntry,
    LicenseFeature,
    LicenseObservation,
    ObservationCompleteness,
    QueryStatus,
)
from .session import ConsoleCredentials, ConsoleSession

__all__ = [
    "CONSOLE_EVIDENCE_SCHEMA_VERSION",
    "CONSOLE_PARSER_VERSION",
    "ConsoleBootEntry",
    "ConsoleCredentials",
    "ConsoleEvidence",
    "ConsoleInterface",
    "ConsoleInventoryMember",
    "ConsoleObservation",
    "ConsoleSession",
    "ConsoleSource",
    "ConsoleStackMember",
    "ConsoleStorageEntry",
    "LicenseFeature",
    "LicenseObservation",
    "ObservationCompleteness",
    "QueryStatus",
]
