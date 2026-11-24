"""R68 Domain-only management scope, PID identity and license evidence.

This module adds an explicit, testable boundary between:

* a hardware/product model,
* a Cisco ordering SKU (whose ``-A``/``-E`` suffix records a default
  Network Stack license),
* the exact PID reported by a device,
* a declared Saved Revision license, and
* a device-verified active license.

It never treats an ordering-suffix default license as a verified active
license.  The supplemental DNS evidence is read-only evidence; it does not
activate any production authorization.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from ..domain import DeviceFamily
from .management_command_evidence import (
    C9200_MANAGEMENT_HARDWARE_PIDS,
    C9200_MANAGEMENT_ORDERING_SKUS,
    C9300_MANAGEMENT_HARDWARE_PIDS,
    C9300_MANAGEMENT_ORDERING_SKUS,
    MANAGEMENT_LICENSES,
)

URL_9300_RELEASE_NOTES = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/release_notes/ol-17-12-9300/introduction.html"
)
URL_9200_RELEASE_NOTES = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/release_notes/ol-17-12-9200/introduction.html"
)
URL_9300_HARDWARE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "hardware/install/b_c9300_hig/Product-overview.html"
)
URL_9200_DATA_SHEET = (
    "https://www.cisco.com/c/en/us/products/collateral/switches/"
    "catalyst-9200-series-switches/nb-06-cat9200-ser-data-sheet-cte-en.html"
)
URL_9300_DNS = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/configuration_guide/sys_mgmt/"
    "b_1712_sys_mgmt_9300_cg/administering_the_device.html"
)
URL_9200_DNS = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/configuration_guide/sys_mgmt/"
    "b_1712_sys_mgmt_9200_cg/administering_the_device.html"
)


class ManagementPidKind(StrEnum):
    HARDWARE_MODEL = "hardware-model"
    ORDERING_SKU = "ordering-sku"


class ManagementLicenseEvidenceLevel(StrEnum):
    # DOCUMENTED_COMPATIBILITY is family-level command documentation only.
    # It is not proof of per-PID/per-License command authorization.
    DOCUMENTED_COMPATIBILITY = "DOCUMENTED_COMPATIBILITY"
    DECLARED_NOT_DEVICE_VERIFIED = "DECLARED_NOT_DEVICE_VERIFIED"
    # Future state only.  No R68 software path can emit this value without a
    # separately designed, source-bound device verification contract.
    DEVICE_VERIFIED = "DEVICE_VERIFIED"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


LICENSE_COMPATIBILITY_SCOPE = "family-command-documentation-only"


@dataclass(frozen=True, slots=True)
class ManagementPidScope:
    family: DeviceFamily
    input_pid: str
    kind: ManagementPidKind
    hardware_model: str
    ordering_sku: str | None
    default_license: str | None
    source_url: str
    source_section: str

    @property
    def is_exact_device_pid(self) -> bool:
        return self.kind is ManagementPidKind.HARDWARE_MODEL


@dataclass(frozen=True, slots=True)
class ManagementLicenseEvidence:
    family: DeviceFamily
    input_pid: str
    declared_license: str | None
    hardware_model: str | None
    ordering_sku: str | None
    ordering_default_license: str | None
    feature_compatibility: ManagementLicenseEvidenceLevel
    active_license_evidence: ManagementLicenseEvidenceLevel
    active_license_verified: bool
    source_url: str
    note: str


@dataclass(frozen=True, slots=True)
class DomainDnsSupplementalEvidence:
    family: DeviceFamily
    source_url: str
    source_section: str
    command: str
    configuration_mode: str
    default_domain_setting: str
    leading_dot_rule: str
    limitations: tuple[str, ...]

    def content_digest(self) -> str:
        payload = {
            "family": self.family.value,
            "source_url": self.source_url,
            "source_section": self.source_section,
            "command": self.command,
            "configuration_mode": self.configuration_mode,
            "default_domain_setting": self.default_domain_setting,
            "leading_dot_rule": self.leading_dot_rule,
            "limitations": self.limitations,
        }
        canonical = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# The mapping is deliberately explicit.  A bare hardware model is not assigned
# a default license; the -A/-E ordering suffix does not become an active
# license, and no suffix is stripped by the renderer to make a PID authorized.
_PID_ROWS: tuple[tuple[DeviceFamily, str, ManagementPidKind, str, str | None,
                        str | None, str, str], ...] = (
    (DeviceFamily.CATALYST_9300, "C9300-24T",
     ManagementPidKind.HARDWARE_MODEL, "C9300-24T", None, None,
     URL_9300_HARDWARE, "Switch Models"),
    (DeviceFamily.CATALYST_9300, "C9300-24T-A",
     ManagementPidKind.ORDERING_SKU, "C9300-24T", "C9300-24T-A",
     "Network Advantage", URL_9300_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9300 Series Switches—Model Numbers"),
    (DeviceFamily.CATALYST_9300, "C9300-24T-E",
     ManagementPidKind.ORDERING_SKU, "C9300-24T", "C9300-24T-E",
     "Network Essentials", URL_9300_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9300 Series Switches—Model Numbers"),
    (DeviceFamily.CATALYST_9300, "C9300-24P",
     ManagementPidKind.HARDWARE_MODEL, "C9300-24P", None, None,
     URL_9300_HARDWARE, "Switch Models"),
    (DeviceFamily.CATALYST_9300, "C9300-24P-A",
     ManagementPidKind.ORDERING_SKU, "C9300-24P", "C9300-24P-A",
     "Network Advantage", URL_9300_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9300 Series Switches—Model Numbers"),
    (DeviceFamily.CATALYST_9300, "C9300-24P-E",
     ManagementPidKind.ORDERING_SKU, "C9300-24P", "C9300-24P-E",
     "Network Essentials", URL_9300_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9300 Series Switches—Model Numbers"),
    (DeviceFamily.CATALYST_9300, "C9300L-24T-4G",
     ManagementPidKind.HARDWARE_MODEL, "C9300L-24T-4G", None, None,
     URL_9300_HARDWARE, "Switch Models"),
    (DeviceFamily.CATALYST_9300, "C9300L-24T-4G-A",
     ManagementPidKind.ORDERING_SKU, "C9300L-24T-4G", "C9300L-24T-4G-A",
     "Network Advantage", URL_9300_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9300L Series Switches"),
    (DeviceFamily.CATALYST_9300, "C9300L-24T-4G-E",
     ManagementPidKind.ORDERING_SKU, "C9300L-24T-4G", "C9300L-24T-4G-E",
     "Network Essentials", URL_9300_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9300L Series Switches"),
    (DeviceFamily.CATALYST_9300, "C9300L-24P-4X",
     ManagementPidKind.HARDWARE_MODEL, "C9300L-24P-4X", None, None,
     URL_9300_HARDWARE, "Switch Models"),
    (DeviceFamily.CATALYST_9300, "C9300L-24P-4X-A",
     ManagementPidKind.ORDERING_SKU, "C9300L-24P-4X", "C9300L-24P-4X-A",
     "Network Advantage", URL_9300_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9300L Series Switches"),
    (DeviceFamily.CATALYST_9300, "C9300L-24P-4X-E",
     ManagementPidKind.ORDERING_SKU, "C9300L-24P-4X", "C9300L-24P-4X-E",
     "Network Essentials", URL_9300_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9300L Series Switches"),
    (DeviceFamily.CATALYST_9300, "C9300X-24Y",
     ManagementPidKind.HARDWARE_MODEL, "C9300X-24Y", None, None,
     URL_9300_HARDWARE, "Switch Models"),
    (DeviceFamily.CATALYST_9300, "C9300X-24Y-A",
     ManagementPidKind.ORDERING_SKU, "C9300X-24Y", "C9300X-24Y-A",
     "Network Advantage", URL_9300_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9300X Series Switches"),
    (DeviceFamily.CATALYST_9300, "C9300X-24Y-E",
     ManagementPidKind.ORDERING_SKU, "C9300X-24Y", "C9300X-24Y-E",
     "Network Essentials", URL_9300_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9300X Series Switches"),
    (DeviceFamily.CATALYST_9200, "C9200-24T",
     ManagementPidKind.HARDWARE_MODEL, "C9200-24T", None, None,
     URL_9200_DATA_SHEET, "Switch models and configurations"),
    (DeviceFamily.CATALYST_9200, "C9200-24T-A",
     ManagementPidKind.ORDERING_SKU, "C9200-24T", "C9200-24T-A",
     "Network Advantage", URL_9200_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9200 Series Switches—Model Numbers"),
    (DeviceFamily.CATALYST_9200, "C9200-24T-E",
     ManagementPidKind.ORDERING_SKU, "C9200-24T", "C9200-24T-E",
     "Network Essentials", URL_9200_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9200 Series Switches—Model Numbers"),
    (DeviceFamily.CATALYST_9200, "C9200-24P",
     ManagementPidKind.HARDWARE_MODEL, "C9200-24P", None, None,
     URL_9200_DATA_SHEET, "Switch models and configurations"),
    (DeviceFamily.CATALYST_9200, "C9200-24P-A",
     ManagementPidKind.ORDERING_SKU, "C9200-24P", "C9200-24P-A",
     "Network Advantage", URL_9200_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9200 Series Switches—Model Numbers"),
    (DeviceFamily.CATALYST_9200, "C9200-24P-E",
     ManagementPidKind.ORDERING_SKU, "C9200-24P", "C9200-24P-E",
     "Network Essentials", URL_9200_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9200 Series Switches—Model Numbers"),
    (DeviceFamily.CATALYST_9200, "C9200L-24T-4G",
     ManagementPidKind.HARDWARE_MODEL, "C9200L-24T-4G", None, None,
     URL_9200_DATA_SHEET, "Switch models and configurations"),
    (DeviceFamily.CATALYST_9200, "C9200L-24T-4G-A",
     ManagementPidKind.ORDERING_SKU, "C9200L-24T-4G", "C9200L-24T-4G-A",
     "Network Advantage", URL_9200_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9200L Series Switches"),
    (DeviceFamily.CATALYST_9200, "C9200L-24T-4G-E",
     ManagementPidKind.ORDERING_SKU, "C9200L-24T-4G", "C9200L-24T-4G-E",
     "Network Essentials", URL_9200_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9200L Series Switches"),
    (DeviceFamily.CATALYST_9200, "C9200L-24P-4X",
     ManagementPidKind.HARDWARE_MODEL, "C9200L-24P-4X", None, None,
     URL_9200_DATA_SHEET, "Switch models and configurations"),
    (DeviceFamily.CATALYST_9200, "C9200L-24P-4X-A",
     ManagementPidKind.ORDERING_SKU, "C9200L-24P-4X", "C9200L-24P-4X-A",
     "Network Advantage", URL_9200_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9200L Series Switches"),
    (DeviceFamily.CATALYST_9200, "C9200L-24P-4X-E",
     ManagementPidKind.ORDERING_SKU, "C9200L-24P-4X", "C9200L-24P-4X-E",
     "Network Essentials", URL_9200_RELEASE_NOTES,
     "Supported Hardware > Cisco Catalyst 9200L Series Switches"),
)

PID_SCOPES: dict[str, ManagementPidScope] = {
    row[1].upper(): ManagementPidScope(
        family=row[0],
        input_pid=row[1],
        kind=row[2],
        hardware_model=row[3],
        ordering_sku=row[4],
        default_license=row[5],
        source_url=row[6],
        source_section=row[7],
    )
    for row in _PID_ROWS
}

DECLARED_HARDWARE_PIDS: dict[DeviceFamily, tuple[str, ...]] = {
    DeviceFamily.CATALYST_9300: C9300_MANAGEMENT_HARDWARE_PIDS,
    DeviceFamily.CATALYST_9200: C9200_MANAGEMENT_HARDWARE_PIDS,
}
DECLARED_ORDERING_SKUS: dict[DeviceFamily, tuple[str, ...]] = {
    DeviceFamily.CATALYST_9300: C9300_MANAGEMENT_ORDERING_SKUS,
    DeviceFamily.CATALYST_9200: C9200_MANAGEMENT_ORDERING_SKUS,
}

if not (
    set(DECLARED_HARDWARE_PIDS[DeviceFamily.CATALYST_9300])
    | set(DECLARED_ORDERING_SKUS[DeviceFamily.CATALYST_9300])
) <= set(PID_SCOPES):
    raise ValueError("C9300 declared management PID has no explicit scope")
if not (
    set(DECLARED_HARDWARE_PIDS[DeviceFamily.CATALYST_9200])
    | set(DECLARED_ORDERING_SKUS[DeviceFamily.CATALYST_9200])
) <= set(PID_SCOPES):
    raise ValueError("C9200 declared management PID has no explicit scope")


def resolve_management_pid(pid: str | None) -> ManagementPidScope | None:
    if pid is None:
        return None
    return PID_SCOPES.get(pid.strip().upper())


def is_ordering_sku(pid: str | None) -> bool:
    scope = resolve_management_pid(pid)
    return bool(scope and scope.kind is ManagementPidKind.ORDERING_SKU)


def management_license_evidence(
    pid: str | None,
    declared_license: str | None,
) -> ManagementLicenseEvidence:
    """Classify license evidence without promoting ordering defaults.

    There is deliberately no caller-supplied ``device_verified_license``
    argument in R68.  A plain string equality can never promote a Declared
    License to Device-Verified.  DEVICE_VERIFIED remains a future state that
    requires a separate source-bound device verification design.
    """
    scope = resolve_management_pid(pid)
    source_url = scope.source_url if scope else URL_9300_RELEASE_NOTES
    if scope is None:
        return ManagementLicenseEvidence(
            family=DeviceFamily.CATALYST_9300 if pid is None else (
                DeviceFamily.CATALYST_9200
                if (pid or "").upper().startswith("C9200")
                else DeviceFamily.CATALYST_9300
            ),
            input_pid=pid or "",
            declared_license=declared_license,
            hardware_model=None,
            ordering_sku=None,
            ordering_default_license=None,
            feature_compatibility=ManagementLicenseEvidenceLevel.UNKNOWN,
            active_license_evidence=ManagementLicenseEvidenceLevel.UNKNOWN,
            active_license_verified=False,
            source_url=source_url,
            note="PID has no explicit R68 scope mapping.",
        )
    if not declared_license:
        return ManagementLicenseEvidence(
            family=scope.family,
            input_pid=scope.input_pid,
            declared_license=None,
            hardware_model=scope.hardware_model,
            ordering_sku=scope.ordering_sku,
            ordering_default_license=scope.default_license,
            feature_compatibility=ManagementLicenseEvidenceLevel.UNKNOWN,
            active_license_evidence=ManagementLicenseEvidenceLevel.UNKNOWN,
            active_license_verified=False,
            source_url=source_url,
            note="No declared license is available; Active License is unknown.",
        )
    normalized = declared_license.casefold()
    if normalized not in {name.casefold() for name in MANAGEMENT_LICENSES}:
        return ManagementLicenseEvidence(
            family=scope.family,
            input_pid=scope.input_pid,
            declared_license=declared_license,
            hardware_model=scope.hardware_model,
            ordering_sku=scope.ordering_sku,
            ordering_default_license=scope.default_license,
            feature_compatibility=ManagementLicenseEvidenceLevel.UNSUPPORTED,
            active_license_evidence=ManagementLicenseEvidenceLevel.UNSUPPORTED,
            active_license_verified=False,
            source_url=source_url,
            note="Declared license is outside the reviewed base license scope.",
        )
    return ManagementLicenseEvidence(
        family=scope.family,
        input_pid=scope.input_pid,
        declared_license=declared_license,
        hardware_model=scope.hardware_model,
        ordering_sku=scope.ordering_sku,
        ordering_default_license=scope.default_license,
        feature_compatibility=ManagementLicenseEvidenceLevel.DOCUMENTED_COMPATIBILITY,
        active_license_evidence=(
            ManagementLicenseEvidenceLevel.DECLARED_NOT_DEVICE_VERIFIED
        ),
        active_license_verified=False,
        source_url=source_url,
        note=(
            "DOCUMENTED_COMPATIBILITY is family-level command documentation "
            f"({LICENSE_COMPATIBILITY_SCOPE}), not per-PID/per-License "
            "authorization. The ordering/default license is not an Active "
            "License; the Saved Revision license is declared, not "
            "device-verified."
        ),
    )


C9300_DOMAIN_DNS_SUPPLEMENT = DomainDnsSupplementalEvidence(
    family=DeviceFamily.CATALYST_9300,
    source_url=URL_9300_DNS,
    source_section="Setting Up DNS",
    command="ip domain name name",
    configuration_mode="global configuration",
    default_domain_setting="DNS default domain name: none configured",
    leading_dot_rule=(
        "Do not include the initial period that separates an unqualified name "
        "from the domain name."
    ),
    limitations=(
        "The cited configuration guide does not document a complete maximum "
        "DNS name length or all character-set boundaries.",
        "The application's DNS regex is a conservative application restriction, "
        "not a complete vendor CLI grammar.",
        "The supplemental evidence does not verify hardware or active license.",
        "The supplemental evidence does not authorize SSH version or deployment.",
    ),
)
C9200_DOMAIN_DNS_SUPPLEMENT = DomainDnsSupplementalEvidence(
    family=DeviceFamily.CATALYST_9200,
    source_url=URL_9200_DNS,
    source_section="Setting Up DNS",
    command="ip domain name name",
    configuration_mode="global configuration",
    default_domain_setting="DNS default domain name: none configured",
    leading_dot_rule=(
        "Do not include the initial period that separates an unqualified name "
        "from the domain name."
    ),
    limitations=C9300_DOMAIN_DNS_SUPPLEMENT.limitations,
)
DOMAIN_DNS_SUPPLEMENTS: dict[DeviceFamily, DomainDnsSupplementalEvidence] = {
    DeviceFamily.CATALYST_9300: C9300_DOMAIN_DNS_SUPPLEMENT,
    DeviceFamily.CATALYST_9200: C9200_DOMAIN_DNS_SUPPLEMENT,
}


__all__ = [
    "C9200_DOMAIN_DNS_SUPPLEMENT",
    "C9300_DOMAIN_DNS_SUPPLEMENT",
    "DECLARED_HARDWARE_PIDS",
    "DECLARED_ORDERING_SKUS",
    "DOMAIN_DNS_SUPPLEMENTS",
    "LICENSE_COMPATIBILITY_SCOPE",
    "DomainDnsSupplementalEvidence",
    "ManagementLicenseEvidence",
    "ManagementLicenseEvidenceLevel",
    "ManagementPidKind",
    "ManagementPidScope",
    "PID_SCOPES",
    "URL_9200_DATA_SHEET",
    "URL_9200_DNS",
    "URL_9200_RELEASE_NOTES",
    "URL_9300_DNS",
    "URL_9300_HARDWARE",
    "URL_9300_RELEASE_NOTES",
    "is_ordering_sku",
    "management_license_evidence",
    "resolve_management_pid",
]
