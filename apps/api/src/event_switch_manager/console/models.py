"""Versioned console observation and evidence contracts.

The existing ``SwitchObservation`` contract remains the stable integration
shape.  This module adds the richer CON-01 evidence envelope and a conversion
method; it does not change the event plan, capability registry or deployment
state.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from event_switch_manager.domain import DeviceFamily
from event_switch_manager.integrations import (
    Capability,
    ConsoleQuery,
    StackMember,
    Support,
    SwitchObservation,
)

from ..planning.types import Record

CONSOLE_EVIDENCE_SCHEMA_VERSION: Literal[1] = 1
CONSOLE_PARSER_VERSION: Literal["con-01-prompt-v1"] = "con-01-prompt-v1"


class ConsoleSource(StrEnum):
    SIMULATOR = "SIMULATOR"
    RECORDED_FIXTURE = "RECORDED_FIXTURE"
    LIVE_DEVICE = "LIVE_DEVICE"


class QueryStatus(StrEnum):
    OK = "ok"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"
    TIMEOUT = "timeout"
    DISCONNECTED = "disconnected"
    INCOMPLETE = "incomplete"


class ObservationCompleteness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    INCOMPLETE = "incomplete"


class LicenseFeature(Record):
    feature: str
    license_type: str | None = None
    status: str | None = None
    next_boot: str | None = None


class LicenseObservation(Record):
    """Separate declared, observed, next-boot and active-license claims."""

    declared: str | None = None
    observed: str | None = None
    next_boot: str | None = None
    status: str | None = None
    features: tuple[LicenseFeature, ...] = ()
    active_verified: Literal[False] = False
    ambiguous: bool = False


class ConsoleInterface(Record):
    name: str
    status: str | None = None


class ConsoleStackMember(Record):
    number: int
    exact_pid: str | None = None
    serial_number: str | None = None
    role: str | None = None
    state: str | None = None
    software_version: str | None = None


class ConsoleQueryResult(Record):
    query: ConsoleQuery
    command: str
    status: QueryStatus
    output: str = ""
    unknown_fields: tuple[str, ...] = ()


class ConsoleObservation(Record):
    schema_version: Literal[1] = CONSOLE_EVIDENCE_SCHEMA_VERSION
    observation_id: UUID = Field(default_factory=uuid4)
    source: ConsoleSource
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    session_identity: str
    port_identity: str | None = None
    family: DeviceFamily | None = None
    hardware_model: str | None = None
    ordering_sku: str | None = None
    exact_pid: str | None = None
    serial_number: str | None = None
    software_version: str | None = None
    license: LicenseObservation = LicenseObservation()
    interfaces: tuple[ConsoleInterface, ...] = ()
    stack: tuple[ConsoleStackMember, ...] = ()
    boot_state: str | None = None
    storage: tuple[str, ...] = ()
    capabilities: tuple[tuple[Capability, Support], ...] = ()
    unknown_fields: tuple[str, ...] = ()
    completeness: ObservationCompleteness = ObservationCompleteness.INCOMPLETE
    parser_version: Literal["con-01-prompt-v1"] = CONSOLE_PARSER_VERSION
    hardware_verified: Literal[False] = False
    deployment_approved: Literal[False] = False

    @field_validator("captured_at")
    @classmethod
    def _captured_at_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("captured_at must be timezone-aware")
        return value.astimezone(UTC)

    def to_switch_observation(self) -> SwitchObservation:
        """Return the legacy integration shape, not a hardware attestation.

        This conversion intentionally loses source/completeness metadata.  It
        must not be used as a substitute for ``ConsoleEvidence``.
        """
        return SwitchObservation(
            family=self.family,
            model=self.exact_pid or self.hardware_model or "unknown",
            serial_number=self.serial_number or "unknown",
            software_version=self.software_version or "unknown",
            license=self.license.observed or self.license.declared,
            interfaces=tuple(item.name for item in self.interfaces),
            stack=tuple(
                StackMember(
                    number=member.number,
                    model=member.exact_pid or "unknown",
                    serial_number=member.serial_number or "unknown",
                    state=member.state or "unknown",
                )
                for member in self.stack
            ),
            boot_state=self.boot_state,
            config_storage=self.storage,
            capabilities=self.capabilities,
        )


class ConsoleEvidence(Record):
    schema_version: Literal[1] = CONSOLE_EVIDENCE_SCHEMA_VERSION
    observation: ConsoleObservation
    source: ConsoleSource
    fixture_id: str | None = None
    query_results: tuple[ConsoleQueryResult, ...] = ()
    unsupported_queries: tuple[ConsoleQuery, ...] = ()
    completeness: ObservationCompleteness = ObservationCompleteness.INCOMPLETE
    unknown_fields: tuple[str, ...] = ()
    content_fingerprint: str = ""
    hardware_verified: Literal[False] = False
    deployment_approved: Literal[False] = False

    @field_validator("content_fingerprint")
    @classmethod
    def _fingerprint_shape(cls, value: str) -> str:
        if value and (len(value) != 64 or any(c not in "0123456789abcdef" for c in value)):
            raise ValueError("content_fingerprint must be a lowercase SHA-256 hex digest")
        return value


class ConsoleEvidenceRejected(ValueError):
    """A source or identity cannot be used as R82 production evidence."""


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def compute_evidence_fingerprint(evidence: ConsoleEvidence) -> str:
    payload = evidence.model_dump(mode="json")
    payload.pop("content_fingerprint", None)
    # IDs and capture time identify an evidence instance; they are not content.
    observation = payload.get("observation")
    if isinstance(observation, dict):
        observation.pop("observation_id", None)
        observation.pop("captured_at", None)
        observation.pop("session_identity", None)
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def build_evidence(
    observation: ConsoleObservation,
    query_results: tuple[ConsoleQueryResult, ...],
    *,
    fixture_id: str | None = None,
    unsupported_queries: tuple[ConsoleQuery, ...] = (),
) -> ConsoleEvidence:
    """Build immutable read-only evidence.

    LIVE_DEVICE is modeled but rejected in CON-01.  A simulator or recorded
    fixture never promotes hardware verification or deployment approval.
    """
    if observation.source is ConsoleSource.LIVE_DEVICE:
        raise ConsoleEvidenceRejected("live-device-evidence-disabled")
    if any(not result.command.startswith("show ") for result in query_results):
        raise ConsoleEvidenceRejected("non-read-only-query-in-evidence")
    if len(set(unsupported_queries)) != len(unsupported_queries):
        raise ConsoleEvidenceRejected("duplicate-unsupported-query")
    evidence = ConsoleEvidence(
        observation=observation,
        source=observation.source,
        fixture_id=fixture_id,
        query_results=query_results,
        unsupported_queries=unsupported_queries,
        completeness=observation.completeness,
        unknown_fields=observation.unknown_fields,
        content_fingerprint="",
    )
    return evidence.model_copy(
        update={"content_fingerprint": compute_evidence_fingerprint(evidence)},
    )


def verify_evidence(evidence: ConsoleEvidence) -> bool:
    """Recompute a fingerprint and re-check source/completeness consistency."""
    return bool(
        evidence.source is evidence.observation.source
        and evidence.completeness is evidence.observation.completeness
        and evidence.unknown_fields == evidence.observation.unknown_fields
        and evidence.content_fingerprint
        == compute_evidence_fingerprint(evidence)
    )
