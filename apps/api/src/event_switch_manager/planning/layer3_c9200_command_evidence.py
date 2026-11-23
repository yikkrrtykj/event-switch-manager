"""CIS-03-04A-2 Catalyst 9200 layer-3 evidence drafts.

This module is deliberately NOT imported by the production Layer 3 registry
selection or command rendering pipeline.  The rows below are evidence-review
candidates only: every row starts PENDING, uses independent Catalyst 9200
evidence IDs, and cannot authorize CLI text.

The four topics in this batch are:

* ``ip routing``
* ``interface Vlan<number>``
* ``ip address <address> <mask>``
* ``ip route <network> <mask> <next-hop>``

Default Route, DHCP Helper, routed-port transition, VRF, dynamic routing and
complete configuration generation remain outside this evidence batch.
"""

from __future__ import annotations

from ..domain import DeviceFamily
from .layer3_command_evidence import (
    PENDING_REVIEW,
    CommandEvidenceRegistry,
    CommandEvidenceRow,
    EvidenceClassification,
    EvidenceStatus,
    L3CommandMode,
    L3CommandTopic,
    ParameterRule,
    SourceRef,
)

C9200_RELEASE = "17.12.4"

# Explicit Evidence-owned PID scope.  This module deliberately does not import
# the Capability whitelist; future Capability changes must not silently widen
# reviewed Evidence or alter its content digest.
C9200_HARDWARE_PIDS = (
    "C9200-24T",
    "C9200-24P",
    "C9200L-24T-4G",
    "C9200L-24P-4X",
)
C9200_ORDERING_SKUS = (
    "C9200L-24T-4G-E",
    "C9200L-24P-4X-A",
)
C9200_PIDS = C9200_HARDWARE_PIDS + C9200_ORDERING_SKUS
C9200_ORDERING_SKU_DEFAULT_LICENSES = {
    "C9200L-24T-4G-E": "Network Essentials",
    "C9200L-24P-4X-A": "Network Advantage",
}
C9200_LICENSES = ("Network Essentials", "Network Advantage")

C9200_DRAFT_REGISTRY_ID = "cis-03-c9200-l3-command-evidence-draft-v1"

C9200_ROUTING_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/configuration_guide/rtng/"
    "b_1712_rtng_9200_cg/configuring_ip_unicast_routing.html"
)
C9200_STATIC_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/configuration_guide/rtng/"
    "b_1712_rtng_9200_cg/protocol_independent_features.html"
)
C9200_INTERFACE_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/configuration_guide/int_hw/"
    "b_1712_int_and_hw_9200_cg/configuring_interface_characteristics.html"
)
C9200_COMMAND_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/command_reference/"
    "b_1712_9200_cr/ip_commands.html"
)
C9200_INTERFACE_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/command_reference/"
    "b_1712_9200_cr/interface_and_hardware_commands.html"
)
C9200_GENERIC_IP_ROUTE_REFERENCE = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_pi/"
    "command/iri-cr-book/iri-cr-a1.html"
)
C9200_RELEASE_NOTES = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/release_notes/ol-17-12-9200.html"
)
C9200_RELEASE_WHATS_NEW = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/release_notes/ol-17-12-9200/"
    "whats_new_in_cisco_ios_dublin_1712x.html"
)
C9200_INTRODUCTION = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/release_notes/ol-17-12-9200/introduction.html"
)
C9200_LICENSING_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/release_notes/ol-17-12-9200/"
    "licensing_and_scaling_guidelines.html"
)
C9200_LICENSE_FEATURE_MAPPING = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst_9000/"
    "cat9000-config-available-licenses.html"
)
C9200_LIMITATIONS = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/release_notes/ol-17-12-9200/"
    "limitations_and_restrictions.html"
)

_C9200_COMMON_SUPPLEMENTAL = (
    SourceRef(C9200_RELEASE_WHATS_NEW, "What's New in Cisco IOS XE Dublin 17.12.x"),
    SourceRef(C9200_INTRODUCTION, "Cisco Catalyst 9200 Series Switches—Model Numbers"),
    SourceRef(C9200_LICENSING_GUIDE, "Licensing and Scaling Guidelines"),
    SourceRef(C9200_INTERFACE_GUIDE, "Interface Connections"),
    SourceRef(C9200_LIMITATIONS, "Limitations and Restrictions"),
)

_INDEPENDENT_REVIEW_BLOCKER = "independent-evidence-review-required"


def _classification(
    *,
    generic_command_reference: bool,
    renderer_safety_restriction: tuple[str, ...],
    excluded_scope_notes: tuple[str, ...],
) -> EvidenceClassification:
    return EvidenceClassification(
        platform_documented=True,
        generic_command_reference=generic_command_reference,
        license_evidence=EvidenceStatus.VERIFIED,
        license_source_url=C9200_INTERFACE_GUIDE,
        license_source_section="Interface Connections",
        hardware_pids=C9200_HARDWARE_PIDS,
        ordering_skus=C9200_ORDERING_SKUS,
        verified_pids=C9200_PIDS,
        renderer_safety_restriction=renderer_safety_restriction,
        blocking_evidence_gaps=(_INDEPENDENT_REVIEW_BLOCKER,),
        excluded_scope_notes=(
            "ordering-sku-default-license-is-not-active-license",
            "actual-active-license-not-hardware-verified",
            *excluded_scope_notes,
        ),
    )


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
    command_reference_url: str | None,
    command_reference_section: str | None,
    command_reference_scope: str,
    exclusions: tuple[str, ...],
    requirements: tuple[str, ...],
    renderer_safety_restriction: tuple[str, ...],
    excluded_scope_notes: tuple[str, ...],
    generic_command_reference: bool = False,
) -> CommandEvidenceRow:
    return CommandEvidenceRow(
        evidence_id=evidence_id,
        family=DeviceFamily.CATALYST_9200,
        pids=C9200_PIDS,
        releases=(C9200_RELEASE,),
        licenses=C9200_LICENSES,
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
        supplemental_sources=_C9200_COMMON_SUPPLEMENTAL,
        classification=_classification(
            generic_command_reference=generic_command_reference,
            renderer_safety_restriction=renderer_safety_restriction,
            excluded_scope_notes=excluded_scope_notes,
        ),
        exclusions=exclusions,
        requirements=requirements,
        review=PENDING_REVIEW,
    )


ROWS: tuple[CommandEvidenceRow, ...] = (
    _row(
        "l3-9200-ip-routing-v1",
        L3CommandTopic.IP_ROUTING,
        "ip routing",
        "ip routing",
        L3CommandMode.GLOBAL,
        (),
        (
            "Global IPv4 routing is disabled by default on Catalyst 9200.",
            "At least one Layer 3 interface must be configured for routing.",
            "The planned device must be a supported Cisco Core.",
        ),
        C9200_ROUTING_GUIDE,
        "Configuration Guidelines for IP Routing",
        command_reference_url=None,
        command_reference_section=None,
        command_reference_scope=(
            "Catalyst 9200 17.12 IP Routing Configuration Guide, Configuration "
            "Guidelines for IP Routing and Enabling IP Unicast Routing. The "
            "platform guide directly documents the command and mode."
        ),
        exclusions=(
            "No no-form, cleanup, VRF, dynamic-routing or complete-script form.",
        ),
        requirements=(
            "Supported Cisco Core identity is trusted.",
            "At least one SVI or routed interface is planned.",
        ),
        renderer_safety_restriction=(
            "planned-cisco-core-only",
            "at-least-one-layer3-interface-required",
        ),
        excluded_scope_notes=(
            "default-route-not-in-this-evidence-batch",
            "dynamic-routing-not-in-this-evidence-batch",
        ),
    ),
    _row(
        "l3-9200-svi-interface-v1",
        L3CommandTopic.SVI_INTERFACE,
        "interface Vlan<vlan-id>",
        "interface Vlan<vlan-id>",
        L3CommandMode.GLOBAL,
        (
            ParameterRule(
                "vlan-id", "vlan-id", 1, 4094,
                (1, 1002, 1003, 1004, 1005),
            ),
        ),
        (
            "The official syntax is interface vlan vlan-id; the renderer uses "
            "the canonical Vlan<vlan-id> spelling.",
            "VLAN 1 and reserved VLANs 1002-1005 are excluded by renderer policy.",
            "One SVI per VLAN per assignment in this evidence batch.",
        ),
        C9200_ROUTING_GUIDE,
        "Configuration Guidelines for IP Routing",
        command_reference_url=C9200_INTERFACE_REFERENCE,
        command_reference_section="interface",
        command_reference_scope=(
            "Catalyst 9200 17.12 Command Reference, Interface and Hardware Commands; "
            "SVI creation is also described in the Routing Configuration Guide and "
            "the Interface Characteristics Guide."
        ),
        exclusions=(
            "No interface range, port-channel, routed-port, VRF or fuzzy interface names.",
            "VLAN 1 and 1002-1005 are not supported by this evidence batch's renderer.",
        ),
        requirements=(
            "The VLAN is declared in the trusted plan.",
            "The SVI belongs to the selected Core assignment.",
        ),
        renderer_safety_restriction=(
            "vlan-1-1002-1005-blocked",
            "exact-Vlan-name",
            "one-svi-per-vlan",
        ),
        excluded_scope_notes=(
            "svi-name-case-and-range-renderer-policy",
            "official-syntax-interface-vlan-vlan-id",
        ),
    ),
    _row(
        "l3-9200-svi-address-v1",
        L3CommandTopic.SVI_ADDRESS,
        "ip address <ip-address> <subnet-mask>",
        "ip address <ip-address> <subnet-mask>",
        L3CommandMode.INTERFACE,
        (
            ParameterRule("ip-address", "ipv4-address"),
            ParameterRule("subnet-mask", "ipv4-mask", 1, 30),
        ),
        (
            "Only one usable primary IPv4 address per SVI is modeled.",
            "The renderer's /31 and /32 exclusions are safety policy, not a claim "
            "that the platform does not support them.",
            "The address must match the gateway/subnet in the trusted plan.",
        ),
        C9200_ROUTING_GUIDE,
        "Assigning IP Addresses to Network Interfaces",
        command_reference_url=C9200_COMMAND_REFERENCE + "#wp1447909228",
        command_reference_section="ip address",
        command_reference_scope=(
            "Catalyst 9200 17.12 Command Reference, IP Addressing Services Commands, "
            "ip address."
        ),
        exclusions=(
            "No secondary address, DHCP address, unnumbered interface or IPv6 form.",
        ),
        requirements=(
            "An SVI exists with the exact Vlan<vlan> name.",
            "The address is usable and matches the planned gateway/subnet.",
        ),
        renderer_safety_restriction=(
            "prefix-1-30-only",
            "primary-address-only",
            "gateway-subnet-match",
        ),
        excluded_scope_notes=(
            "slash31-slash32-renderer-excluded",
            "secondary-address-renderer-excluded",
        ),
    ),
    _row(
        "l3-9200-static-route-v1",
        L3CommandTopic.STATIC_ROUTE,
        "ip route <network> <mask> <next-hop>",
        "ip route <network> <mask> <next-hop>",
        L3CommandMode.GLOBAL,
        (
            ParameterRule("network", "ipv4-prefix", 1, 32),
            ParameterRule("mask", "ipv4-mask", 1, 32),
            ParameterRule("next-hop", "ipv4-address"),
        ),
        (
            "Official syntax also permits interface next-hop and distance.",
            "This evidence batch only allows the IPv4 next-hop form.",
            "The destination must not be 0.0.0.0/0; Default Route is a separate "
            "excluded topic.",
            "The next hop must be on-link in the trusted plan.",
        ),
        C9200_STATIC_GUIDE,
        "Configuring Static Unicast Routes",
        command_reference_url=C9200_GENERIC_IP_ROUTE_REFERENCE,
        command_reference_section="ip route",
        command_reference_scope=(
            "Catalyst 9200 17.12 Protocol-Independent Features, Configuring Static "
            "Unicast Routes, combined with the Cisco IOS XE protocol-independent "
            "ip route reference. The platform guide directly documents the syntax."
        ),
        exclusions=(
            "No interface-only next hop, VRF, name, tag, track, permanent or no-form.",
            "No default-route candidate even though the official ip route syntax "
            "can express 0.0.0.0/0.",
        ),
        requirements=(
            "Route owner is the supported Cisco Core.",
            "Destination is not 0.0.0.0/0.",
            "Next hop is on-link and reachable in the trusted plan.",
        ),
        renderer_safety_restriction=(
            "ipv4-next-hop-only",
            "default-route-excluded",
            "on-link-next-hop-only",
        ),
        excluded_scope_notes=(
            "default-route-topic-remains-blocked",
            "official-syntax-includes-interface-next-hop-and-distance",
            "route-capacity-and-hardware-limit-not-verified",
        ),
        generic_command_reference=True,
    ),
)

DRAFT_REGISTRY = CommandEvidenceRegistry(
    ROWS,
    registry_id=C9200_DRAFT_REGISTRY_ID,
    production=False,
)


def pending_digests() -> dict[str, str]:
    """Return deterministic SHA-256 content digests for independent review."""
    return {row.evidence_id: row.content_digest() for row in ROWS}


__all__ = [
    "C9200_DRAFT_REGISTRY_ID",
    "C9200_HARDWARE_PIDS",
    "C9200_LICENSES",
    "C9200_ORDERING_SKUS",
    "C9200_ORDERING_SKU_DEFAULT_LICENSES",
    "C9200_PIDS",
    "C9200_RELEASE",
    "DRAFT_REGISTRY",
    "ROWS",
    "pending_digests",
]
