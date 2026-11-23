"""CIS-03-04A-1 trusted Layer 3 Registry selection.

The production trust boundary has two separate concerns:

* a Registry object is only trusted when it is one of the explicitly registered
  production objects below (object identity, not an ID or fingerprint string);
* the selected object must be the one that the trusted saved-revision device
  identity resolves to.

Catalyst 9300 and the reviewed Catalyst 9200 scope are explicitly registered.
Any other platform, or an identity outside the reviewed PID/release/license
scope, resolves to a row-less sentinel.  The sentinel can render only blocked
candidates; it carries no command evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from ..domain import DeviceFamily
from .layer3_c9200_command_evidence_reviews import C9200_REVIEWED_REGISTRY
from .layer3_command_evidence import (
    DEFAULT_REGISTRY,
    CommandEvidenceRegistry,
)
from .layer3_intent import L3Identity

UNREVIEWED_PLATFORM_REGISTRY_ID = "cis-03-l1-command-evidence-unreviewed-v1"

#: Blocking-only registry for a platform without independently reviewed
#: production command evidence.  It deliberately has no rows and is not an
#: approval of any C9200 command evidence.
UNREVIEWED_PLATFORM_REGISTRY = CommandEvidenceRegistry(
    (), registry_id=UNREVIEWED_PLATFORM_REGISTRY_ID, production=True,
)


class RegistrySelectionError(ValueError):
    """A production Registry request is not the trusted selected object."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class RegistrySelection:
    registry: CommandEvidenceRegistry
    assignment_id: UUID
    family: DeviceFamily | None
    evidence_approved: bool
    reason_code: str


@dataclass(frozen=True, slots=True)
class _RegisteredRegistry:
    registry: CommandEvidenceRegistry
    family: DeviceFamily | None
    evidence_approved: bool


# Object identity is intentional.  A copied Registry with the same ID and
# fingerprint is not trusted merely because its values look familiar.
_REGISTERED: tuple[_RegisteredRegistry, ...] = (
    _RegisteredRegistry(
        registry=DEFAULT_REGISTRY,
        family=DeviceFamily.CATALYST_9300,
        evidence_approved=True,
    ),
    _RegisteredRegistry(
        registry=C9200_REVIEWED_REGISTRY,
        family=DeviceFamily.CATALYST_9200,
        evidence_approved=True,
    ),
    _RegisteredRegistry(
        registry=UNREVIEWED_PLATFORM_REGISTRY,
        family=None,
        evidence_approved=False,
    ),
)


def _row_pids(row: object) -> tuple[str, ...]:
    classification = getattr(row, "classification", None)
    if classification is not None:
        return tuple(classification.verified_pids)
    return tuple(getattr(row, "pids", ()))


def _matches_registry_scope(
    registry: CommandEvidenceRegistry,
    family: DeviceFamily,
    identity: L3Identity,
) -> bool:
    if (
        identity.family is not family
        or identity.pid_evidence != "exact-verified-pid"
        or identity.exact_pid is None
        or identity.software_image is None
    ):
        return False
    pid = identity.exact_pid.upper()
    release = identity.software_image.casefold()
    license_name = (
        identity.software_license.casefold()
        if identity.software_license is not None
        else None
    )
    for row in registry.rows:
        if row.family is not family:
            continue
        if pid not in {item.upper() for item in _row_pids(row)}:
            continue
        if release not in {item.casefold() for item in row.releases}:
            continue
        if row.licenses:
            if license_name not in {item.casefold() for item in row.licenses}:
                continue
        elif license_name is not None:
            continue
        return True
    return False


def select_l3_registry(identity: L3Identity) -> RegistrySelection:
    """Resolve exactly one Registry from trusted saved-revision identity.

    The URL, request body and headers never contribute to this decision.
    """
    for entry in _REGISTERED:
        if not entry.evidence_approved or entry.family is None:
            continue
        if _matches_registry_scope(entry.registry, entry.family, identity):
            return RegistrySelection(
                registry=entry.registry,
                assignment_id=identity.assignment_id,
                family=entry.family,
                evidence_approved=True,
                reason_code="registry-selected-reviewed-platform",
            )
    return RegistrySelection(
        registry=UNREVIEWED_PLATFORM_REGISTRY,
        assignment_id=identity.assignment_id,
        family=identity.family,
        evidence_approved=False,
        reason_code="platform-evidence-unreviewed",
    )


def is_registered_production_registry(registry: CommandEvidenceRegistry) -> bool:
    return any(entry.registry is registry for entry in _REGISTERED)


def assert_production_registry(
    registry: CommandEvidenceRegistry,
    identity: L3Identity,
) -> RegistrySelection:
    """Fail closed unless ``registry`` is exactly the trusted selection."""
    if not is_registered_production_registry(registry):
        raise RegistrySelectionError("untrusted-production-registry")
    selection = select_l3_registry(identity)
    if registry is not selection.registry:
        raise RegistrySelectionError("registry-selection-mismatch")
    return selection


__all__ = [
    "C9200_REVIEWED_REGISTRY",
    "RegistrySelection",
    "RegistrySelectionError",
    "UNREVIEWED_PLATFORM_REGISTRY",
    "UNREVIEWED_PLATFORM_REGISTRY_ID",
    "assert_production_registry",
    "is_registered_production_registry",
    "select_l3_registry",
]
