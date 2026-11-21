"""CIS-03-03A exact L3 command evidence (Catalyst 9300 17.12.4).

This registry is intentionally independent of the frozen L2 command-evidence
registry.  A row names exact PIDs, an exact release and an exact license scope;
it never covers a family in general.

Production rows start ``PENDING``.  A row may render command text only after a
real independent review attestation binds the row's content SHA-256 digest.
The repository currently contains no such production attestation, so the
default registry renders no candidate text.  Test-only registries may inject
reviewed rows to exercise renderer mechanics, but they are not production
evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Literal

from ..domain import DeviceFamily
from .layer3_command_evidence_reviews import REJECTED_RECORDS, REVIEWED_RECORDS

REGISTRY_ID: Literal["cis-03-l1-command-evidence-v1"] = "cis-03-l1-command-evidence-v1"
EVIDENCE_SCHEMA_VERSION: Literal[1] = 1

_9300_PIDS = (
    "C9300-24T", "C9300-24P",
    "C9300L-24T-4G", "C9300L-24T-4G-E",
    "C9300L-24P-4X", "C9300L-24P-4X-E",
    "C9300X-24Y", "C9300X-24Y-A",
)
_RELEASE = "17.12.4"
_FORWARD_LICENSES = ("Network Essentials", "Network Advantage")
_DHCP_LICENSES = ("Network Advantage",)

_ROUTING_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/configuration_guide/rtng/"
    "b_1712_rtng_9300_cg/configuring_ip_unicast_routing.html"
)
_STATIC_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/configuration_guide/rtng/"
    "b_1712_rtng_9300_cg/protocol_independent_features.html"
)
_DHCP_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/configuration_guide/ip/"
    "b_1712_ip_9300_cg/configuring_dhcp.html"
)
_CR_IP_ROUTE = (
    "https://www.cisco.com/c/en/us/td/docs/ios/iproute_pi/command/reference/"
    "iri_book/iri_pi1.html#wp1037816"
)
_CR_IP_ROUTING = (
    "https://www.cisco.com/c/en/us/td/docs/ios/iproute_pi/command/reference/"
    "iri_book/iri_pi1.html#wp1029588"
)
_CR_IP_ADDRESS = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/command_reference/b_1712_9300_cr/"
    "ip_addressing_services_commands.html#wp1447909228"
)
_ADMIN_DISTANCE = (
    "https://www.cisco.com/c/en/us/support/docs/ip/"
    "border-gateway-protocol-bgp/15986-admin-distance.html"
)


class L3CommandTopic(StrEnum):
    IP_ROUTING = "ip-routing"
    SVI_INTERFACE = "svi-interface"
    SVI_ADDRESS = "svi-address"
    STATIC_ROUTE = "static-route"
    DEFAULT_ROUTE = "default-route"
    DHCP_HELPER_ADDRESS = "dhcp-helper-address"


class L3CommandMode(StrEnum):
    GLOBAL = "global"
    INTERFACE = "interface"


class EvidenceReviewState(StrEnum):
    PENDING = "pending-independent-review"
    REVIEWED = "independently-reviewed"
    REJECTED = "independently-rejected"


@dataclass(frozen=True, slots=True)
class SourceRef:
    url: str
    section: str


@dataclass(frozen=True, slots=True)
class ParameterRule:
    name: str
    kind: Literal[
        "vlan-id", "ipv4-address", "ipv4-mask",
        "ipv4-prefix", "distance", "interface-name",
    ]
    minimum: int | None = None
    maximum: int | None = None
    reserved_values: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceReview:
    state: EvidenceReviewState
    reviewer: str
    reviewed_at: str
    findings: tuple[str, ...]
    content_digest: str


PENDING_REVIEW = EvidenceReview(
    EvidenceReviewState.PENDING, "", "", (), "",
)


@dataclass(frozen=True, slots=True)
class CommandEvidenceRow:
    evidence_id: str
    family: DeviceFamily
    pids: tuple[str, ...]
    releases: tuple[str, ...]
    licenses: tuple[str, ...]
    topic: L3CommandTopic
    command: str
    grammar: str
    mode: L3CommandMode
    parameters: tuple[ParameterRule, ...]
    limits: tuple[str, ...]
    source_url: str
    source_section: str
    command_reference_url: str | None = None
    command_reference_section: str | None = None
    command_reference_scope: str | None = None
    semantic_source_url: str | None = None
    semantic_source_section: str | None = None
    exclusions: tuple[str, ...] = ()
    requirements: tuple[str, ...] = ()
    review: EvidenceReview = PENDING_REVIEW
    evidence_version: int = EVIDENCE_SCHEMA_VERSION

    def content_payload(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "family": self.family.value,
            "pids": list(self.pids),
            "releases": list(self.releases),
            "licenses": list(self.licenses),
            "topic": self.topic.value,
            "command": self.command,
            "grammar": self.grammar,
            "mode": self.mode.value,
            "parameters": [
                {
                    "name": item.name,
                    "kind": item.kind,
                    "minimum": item.minimum,
                    "maximum": item.maximum,
                    "reserved_values": list(item.reserved_values),
                }
                for item in self.parameters
            ],
            "limits": list(self.limits),
            "source_url": self.source_url,
            "source_section": self.source_section,
            "command_reference_url": self.command_reference_url,
            "command_reference_section": self.command_reference_section,
            "command_reference_scope": self.command_reference_scope,
            "semantic_source_url": self.semantic_source_url,
            "semantic_source_section": self.semantic_source_section,
            "exclusions": list(self.exclusions),
            "requirements": list(self.requirements),
            "evidence_version": self.evidence_version,
        }

    def content_digest(self) -> str:
        canonical = json.dumps(
            self.content_payload(), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def renderable(self) -> bool:
        return (
            self.review.state is EvidenceReviewState.REVIEWED
            and self.review.content_digest == self.content_digest()
        )


@dataclass(frozen=True, slots=True)
class CommandEvidenceRegistry:
    rows: tuple[CommandEvidenceRow, ...]
    registry_id: str = REGISTRY_ID

    def __post_init__(self) -> None:
        ids = [row.evidence_id for row in self.rows]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate command evidence ID")

    @property
    def renderable_count(self) -> int:
        return sum(1 for row in self.rows if row.renderable)

    def get(self, evidence_id: str) -> CommandEvidenceRow | None:
        return next(
            (row for row in self.rows if row.evidence_id == evidence_id), None,
        )

    def matching(
        self,
        topic: L3CommandTopic,
        exact_pid: str | None,
        release: str | None,
        license_name: str | None,
    ) -> tuple[CommandEvidenceRow, ...]:
        if exact_pid is None or release is None:
            return ()
        pid = exact_pid.upper()
        license_fold = (license_name or "").casefold()
        return tuple(
            row for row in self.rows
            if row.topic is topic
            and pid in {item.upper() for item in row.pids}
            and release.casefold() in {item.casefold() for item in row.releases}
            and (
                (row.licenses and license_fold in {
                    item.casefold() for item in row.licenses
                })
                or (not row.licenses and license_name is None)
            )
        )

    @property
    def fingerprint(self) -> str:
        payload = [
            {
                "evidence_id": row.evidence_id,
                "content_digest": row.content_digest(),
                "review_state": row.review.state.value,
                "review_digest": row.review.content_digest,
            }
            for row in self.rows
        ]
        canonical = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        return sha256(canonical.encode("utf-8")).hexdigest()


def _review_record(
    record: dict[str, object], state: EvidenceReviewState,
) -> EvidenceReview:
    findings = record.get("findings")
    if not isinstance(findings, (list, tuple)):
        raise TypeError("Evidence review findings must be a sequence")
    return EvidenceReview(
        state=state,
        reviewer=str(record.get("reviewer", "")),
        reviewed_at=str(record.get("reviewed_at", "")),
        findings=tuple(str(item) for item in findings),
        content_digest=str(record.get("content_digest", "")),
    )


_REVIEWS = {
    evidence_id: _review_record(record, EvidenceReviewState.REVIEWED)
    for evidence_id, record in REVIEWED_RECORDS.items()
}
_REJECTIONS = {
    evidence_id: _review_record(record, EvidenceReviewState.REJECTED)
    for evidence_id, record in REJECTED_RECORDS.items()
}


def _row(
    evidence_id: str,
    topic: L3CommandTopic,
    command: str,
    grammar: str,
    mode: L3CommandMode,
    parameters: tuple[ParameterRule, ...],
    limits: tuple[str, ...],
    source_url: str,
    source_section: str,
    *,
    command_reference_url: str | None = None,
    command_reference_section: str | None = None,
    command_reference_scope: str | None = None,
    semantic_source_url: str | None = None,
    semantic_source_section: str | None = None,
    exclusions: tuple[str, ...] = (),
    requirements: tuple[str, ...] = (),
    licenses: tuple[str, ...] = _FORWARD_LICENSES,
) -> CommandEvidenceRow:
    review = _REVIEWS.get(evidence_id) or _REJECTIONS.get(evidence_id) or PENDING_REVIEW
    return CommandEvidenceRow(
        evidence_id=evidence_id,
        family=DeviceFamily.CATALYST_9300,
        pids=_9300_PIDS,
        releases=(_RELEASE,),
        licenses=licenses,
        topic=topic,
        command=command,
        grammar=grammar,
        mode=mode,
        parameters=parameters,
        limits=limits,
        source_url=source_url,
        source_section=source_section,
        command_reference_url=command_reference_url,
        command_reference_section=command_reference_section,
        command_reference_scope=command_reference_scope,
        semantic_source_url=semantic_source_url,
        semantic_source_section=semantic_source_section,
        exclusions=exclusions,
        requirements=requirements,
        review=review,
    )


_SVI_NAME_EXCLUSION = (
    "SVI name must be exactly Vlan<vlan>; case variants and fuzzy names are excluded.",
    "VLAN 1 and 1002-1005 are rejected by the first-batch renderer.",
)
_ROUTE_EXCLUSION = (
    "No no-form, cleanup, deletion, VRF, DHCP, name, permanent, track or tag form.",
    "Only an IPv4 next-hop is supported; interface-only next hop is excluded.",
)
_DHCP_EXCLUSION = (
    "No DHCP Server, DHCP Client, DHCP snooping or DHCP option configuration.",
)


ROWS: tuple[CommandEvidenceRow, ...] = (
    _row(
        "l3-9300-ip-routing-v1",
        L3CommandTopic.IP_ROUTING,
        "ip routing",
        "ip routing",
        L3CommandMode.GLOBAL,
        (),
        ("Enable only on the planned Cisco Core; at least one SVI must exist.",),
        _ROUTING_GUIDE,
        "Enabling IP Unicast Routing",
        command_reference_url=_CR_IP_ROUTING,
        command_reference_section="ip routing",
        exclusions=("No no ip routing form in the first batch.",),
        requirements=(
            "Device is a supported Cisco Core.",
            "At least one SVI exists in the trusted L3 Intent.",
        ),
    ),
    _row(
        "l3-9300-svi-interface-v1",
        L3CommandTopic.SVI_INTERFACE,
        "interface vlan <vlan-id>",
        "interface vlan <vlan-id>",
        L3CommandMode.GLOBAL,
        (
            ParameterRule(
                "vlan-id", "vlan-id", 1, 4094, (1, 1002, 1003, 1004, 1005),
            ),
        ),
        ("One SVI per VLAN per assignment.",),
        _ROUTING_GUIDE,
        "Assigning IP Addresses to Network Interfaces",
        exclusions=_SVI_NAME_EXCLUSION,
        requirements=(
            "SVI name is exactly Vlan<vlan>.",
            "SVI VLAN is declared and carried by a planned up port.",
        ),
    ),
    _row(
        "l3-9300-svi-address-v1",
        L3CommandTopic.SVI_ADDRESS,
        "ip address <ip-address> <subnet-mask>",
        "ip address <ip-address> <subnet-mask>",
        L3CommandMode.INTERFACE,
        (
            ParameterRule("ip-address", "ipv4-address"),
            ParameterRule("subnet-mask", "ipv4-mask", 1, 30),
        ),
        (
            "One primary address per SVI.",
            "First batch restricts prefix length to 1-30.",
            "Address must be usable and match the gateway/subnet.",
        ),
        _ROUTING_GUIDE,
        "Assigning IP Addresses to Network Interfaces",
        command_reference_url=_CR_IP_ADDRESS,
        command_reference_section="ip address",
        exclusions=("No secondary address, DHCP address or unnumbered form.",),
        requirements=(
            "SVI exists with exact Vlan<vlan> name.",
            "Address matches gateway/subnet and is usable.",
        ),
    ),
    _row(
        "l3-9300-static-route-v1",
        L3CommandTopic.STATIC_ROUTE,
        "ip route <prefix> <mask> <next-hop> [<distance>]",
        "ip route <prefix> <mask> <next-hop> [<distance>]",
        L3CommandMode.GLOBAL,
        (
            ParameterRule("prefix", "ipv4-prefix", 1, 32),
            ParameterRule("mask", "ipv4-mask", 1, 32),
            ParameterRule("next-hop", "ipv4-address"),
            ParameterRule("distance", "distance", 1, 255),
        ),
        (
            "Distance range is 1-255; 255 is not installed in the routing table.",
            "Next hop must be on-link.",
        ),
        _STATIC_GUIDE,
        "Configuring Static Unicast Routes",
        command_reference_url=_CR_IP_ROUTE,
        command_reference_section="ip route",
        command_reference_scope=(
            "Cisco IOS IP Routing: Protocol-Independent Command Reference; "
            "Catalyst 9300 17.12 platform applicability from the platform guide."
        ),
        semantic_source_url=_ADMIN_DISTANCE,
        semantic_source_section="Understand Administrative Distance",
        exclusions=_ROUTE_EXCLUSION,
        requirements=(
            "Route owner is the supported Cisco Core.",
            "Destination is not 0.0.0.0/0.",
            "Next hop is on-link.",
        ),
    ),
    _row(
        "l3-9300-default-route-v1",
        L3CommandTopic.DEFAULT_ROUTE,
        "ip route 0.0.0.0 0.0.0.0 <next-hop> [<distance>]",
        "ip route 0.0.0.0 0.0.0.0 <next-hop> [<distance>]",
        L3CommandMode.GLOBAL,
        (
            ParameterRule("next-hop", "ipv4-address"),
            ParameterRule("distance", "distance", 1, 255),
        ),
        (
            "Distance range is 1-255; distance 255 is not installed.",
            "Next hop must equal the transit hillstone_ip.",
        ),
        _STATIC_GUIDE,
        "How to Configure Default Routes and Networks",
        command_reference_url=_CR_IP_ROUTE,
        command_reference_section="ip route",
        command_reference_scope=(
            "Cisco IOS IP Routing: Protocol-Independent Command Reference; "
            "Catalyst 9300 17.12 platform applicability from the platform guide."
        ),
        semantic_source_url=_ADMIN_DISTANCE,
        semantic_source_section="Understand Administrative Distance",
        exclusions=_ROUTE_EXCLUSION,
        requirements=(
            "Device has a trusted transit relation.",
            "Route ID is the transit preferred default route.",
            "Next hop equals transit.hillstone_ip.",
        ),
    ),
    _row(
        "l3-9300-dhcp-helper-address-v1",
        L3CommandTopic.DHCP_HELPER_ADDRESS,
        "ip helper-address <ip-address>",
        "ip helper-address <ip-address>",
        L3CommandMode.INTERFACE,
        (ParameterRule("ip-address", "ipv4-address"),),
        ("One candidate per relay server; no reviewed maximum is asserted.",),
        _DHCP_GUIDE,
        "Configuring the DHCP Relay Agent",
        exclusions=_DHCP_EXCLUSION,
        requirements=(
            "SVI exists with an address.",
            "DHCP Relay capability and relay decision are allowed.",
            "Server is a valid unicast IPv4 address.",
        ),
        licenses=_DHCP_LICENSES,
    ),
)

DEFAULT_REGISTRY = CommandEvidenceRegistry(ROWS)


def evidence_row_count() -> int:
    return len(ROWS)


__all__ = [
    "DEFAULT_REGISTRY",
    "EVIDENCE_SCHEMA_VERSION",
    "REGISTRY_ID",
    "CommandEvidenceRegistry",
    "CommandEvidenceRow",
    "EvidenceReview",
    "EvidenceReviewState",
    "L3CommandMode",
    "L3CommandTopic",
    "ParameterRule",
    "PENDING_REVIEW",
    "ROWS",
    "SourceRef",
    "evidence_row_count",
]
