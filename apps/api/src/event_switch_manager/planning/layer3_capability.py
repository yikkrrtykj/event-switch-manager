"""CIS-03-02A exact L3 capability evidence.

This module is deliberately independent of the frozen CIS-02B2 L2 evidence
registry and of the family-indexed ``cisco_catalog.FEATURES`` table.  A row is
scoped to an exact PID, release and license scope, and a row never applies to a
family in general.

The resolver distinguishes three conclusions that must not be collapsed:

* vendor documentation status (supported / unsupported / unknown);
* runtime prerequisite status (satisfied-by-plan / unobserved / missing);
* hardware verification, which is always ``False`` in this phase.

Only a documented capability with no unobserved platform prerequisite is
``DOCUMENTED``.  ``CONDITIONAL`` still produces diagnostic intent but blocks
generation.  ``UNKNOWN`` and ``UNSUPPORTED`` fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import UUID

from ..domain import DeviceFamily
from ..integrations import Support
from ..planning.inventory import EventDeviceAssignment, PhysicalDevice
from ..planning.plan import EventPlan
from ..planning.types import Record


class L3Capability(StrEnum):
    IPV4_ROUTING = "ipv4-routing"
    SVI = "svi"
    ROUTED_PORT = "routed-port"
    STATIC_ROUTE = "static-route"
    DEFAULT_ROUTE = "default-route"
    DHCP_RELAY = "dhcp-relay"


class DocumentationStatus(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class PrerequisiteStatus(StrEnum):
    NOT_REQUIRED = "not-required"
    UNOBSERVED = "unobserved"
    MISSING = "missing"


class L3Verdict(StrEnum):
    DOCUMENTED = "documented"
    CONDITIONAL = "conditional"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


FORWARDING_CAPABILITIES = frozenset({
    L3Capability.IPV4_ROUTING,
    L3Capability.SVI,
    L3Capability.ROUTED_PORT,
    L3Capability.STATIC_ROUTE,
    L3Capability.DEFAULT_ROUTE,
})


@dataclass(frozen=True, slots=True)
class L3EvidenceRow:
    evidence_id: str
    family: DeviceFamily
    pids: tuple[str, ...]
    releases: tuple[str, ...]
    licenses: tuple[str, ...]
    capability: L3Capability
    documentation: DocumentationStatus
    prerequisite: PrerequisiteStatus
    source_url: str
    source_section: str
    conditions: tuple[str, ...] = ()
    limits: tuple[str, ...] = ()
    evidence_version: int = 1


class L3EvidenceRef(Record):
    evidence_id: str
    url: str
    section: str
    conditions: tuple[str, ...] = ()
    limits: tuple[str, ...] = ()


class L3CapabilityDecision(Record):
    capability: L3Capability
    verdict: L3Verdict
    documentation: DocumentationStatus
    prerequisite: PrerequisiteStatus
    reason_code: str
    reason: str
    evidence: tuple[L3EvidenceRef, ...] = ()
    affects_forwarding: bool
    hardware_verified: Literal[False] = False
    deployment_allowed: Literal[False] = False

    @property
    def intent_allowed(self) -> bool:
        return self.verdict is L3Verdict.DOCUMENTED


@dataclass(frozen=True, slots=True)
class L3Target:
    assignment_id: UUID
    hostname: str
    family: DeviceFamily | None
    physical_device_id: UUID | None
    exact_pid: str | None
    software_image: str | None
    license: str | None
    stack_identity: Literal["standalone", "resolved", "unresolved"]


class _UnknownIdentity(LookupError):
    def __init__(self, reason_code: str, reason: str) -> None:
        super().__init__(reason)
        self.reason_code = reason_code
        self.reason = reason


G2960 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/"
    "software/15-2_7_e/configuration_guide/b_1527e_consolidated_2960x_cg/"
)
G3850 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/"
    "software/release/16-12/configuration_guide/rtng/b_1612_rtng_3850_cg/"
)
G9200 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/configuration_guide/rtng/b_1712_rtng_9200_cg/"
)
G9300 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/configuration_guide/rtng/b_1712_rtng_9300_cg/"
)
DHCP9300 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/configuration_guide/ip/b_1712_ip_9300_cg/"
)
C1000 = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst1000/"
    "software/releases/15_2_7_e/configuration_guides/"
)

P2960 = G2960 + "m_rt_152ex_ipunirt.html"
S2960 = G2960 + "m_sm_1527_sdm_template.html"
P3850 = G3850 + "configuring_ip_unicast_routing.html"
P9200 = G9200 + "configuring_ip_unicast_routing.html"
P9300 = G9300 + "configuring_ip_unicast_routing.html"
P9300_DHCP = DHCP9300 + "configuring_dhcp.html"
P1000 = C1000 + "rtng/b_1527e_routing_c1000_cg/configuring_ip_unicast_routing.html"
P1000_INT = (
    C1000 + "int_hw/b_1527e_int_and_hw_c1000_cg/configuring_interface_characteristics.html"
)

_2960_LANBASE_PIDS = ("WS-C2960X-24TS-L", "WS-C2960X-24PS-L")
_2960_LANLITE_PIDS = ("WS-C2960X-24TS-LL",)
_2960_RELEASES = ("15.2(7)E", "15.2(7)E7")
_3850_PIDS = ("WS-C3850-24T", "WS-C3850-24P", "WS-C3850-24T-L", "WS-C3850-24P-S")
_9200_PIDS = (
    "C9200-24T", "C9200-24P", "C9200L-24T-4G",
    "C9200L-24T-4G-E", "C9200L-24P-4X", "C9200L-24P-4X-A",
)
_9300_PIDS = (
    "C9300-24T", "C9300-24P", "C9300L-24T-4G", "C9300L-24T-4G-E",
    "C9300L-24P-4X", "C9300L-24P-4X-E", "C9300X-24Y", "C9300X-24Y-A",
)
_C1000_PIDS = ("C1000-24T-4G-L", "C1000-24P-4G-L")

_2960_SDM_CONDITION = (
    "LAN Base routing requires 'sdm prefer lanbase-routing' and a reload; "
    "the running SDM template was not observed."
)
_2960_LITE_CONDITION = (
    "LAN Lite supports only the default SDM template and has 0 IPv4 unicast routes."
)
_2960_LIMIT = "Up to 16 static routes including the default route."
_3850_LANBASE_CONDITION = "LAN Base static routing is documented on SVIs only."
_3850_LANBASE_LIMIT = "Up to 16 user-configured static routes."
_C1000_LIMIT = "Up to 16 static routes including the default route."


def _row(
    evidence_id: str,
    family: DeviceFamily,
    pids: tuple[str, ...],
    releases: tuple[str, ...],
    licenses: tuple[str, ...],
    capability: L3Capability,
    source_url: str,
    source_section: str,
    *,
    documentation: DocumentationStatus = DocumentationStatus.SUPPORTED,
    prerequisite: PrerequisiteStatus = PrerequisiteStatus.NOT_REQUIRED,
    conditions: tuple[str, ...] = (),
    limits: tuple[str, ...] = (),
) -> L3EvidenceRow:
    return L3EvidenceRow(
        evidence_id=evidence_id,
        family=family,
        pids=pids,
        releases=releases,
        licenses=licenses,
        capability=capability,
        documentation=documentation,
        prerequisite=prerequisite,
        source_url=source_url,
        source_section=source_section,
        conditions=conditions,
        limits=limits,
    )


ROWS: tuple[L3EvidenceRow, ...] = (
    # 2960X LAN Base: static routing on SVIs only, behind the routing SDM template.
    *(
        _row(
            f"l3-2960x-lanbase-{capability.value}-v1",
            DeviceFamily.CATALYST_2960X,
            _2960_LANBASE_PIDS,
            _2960_RELEASES,
            ("LAN Base",),
            capability,
            P2960,
            {
                L3Capability.IPV4_ROUTING: "Configuring IP Unicast Routing",
                L3Capability.SVI: "Assigning IP Addresses to SVIs",
                L3Capability.STATIC_ROUTE: "Configuring Static Unicast Routes",
                L3Capability.DEFAULT_ROUTE: "Configuring Static Unicast Routes",
            }[capability],
            prerequisite=PrerequisiteStatus.UNOBSERVED,
            conditions=(_2960_SDM_CONDITION,),
            limits=(_2960_LIMIT,),
        )
        for capability in (
            L3Capability.IPV4_ROUTING,
            L3Capability.SVI,
            L3Capability.STATIC_ROUTE,
            L3Capability.DEFAULT_ROUTE,
        )
    ),
    # 2960X LAN Lite: explicit negative evidence, not a family-wide inference.
    *(
        _row(
            f"l3-2960x-lanlite-{capability.value}-v1",
            DeviceFamily.CATALYST_2960X,
            _2960_LANLITE_PIDS,
            _2960_RELEASES,
            ("LAN Lite",),
            capability,
            S2960,
            "Restrictions for SDM Templates",
            documentation=DocumentationStatus.UNSUPPORTED,
            conditions=(_2960_LITE_CONDITION,),
            limits=("IPv4 unicast routes: 0.",),
        )
        for capability in (
            L3Capability.IPV4_ROUTING,
            L3Capability.STATIC_ROUTE,
            L3Capability.DEFAULT_ROUTE,
        )
    ),
    # 3850 LAN Base: static routing on SVIs only, 16 routes.
    *(
        _row(
            f"l3-3850-lanbase-{capability.value}-v1",
            DeviceFamily.CATALYST_3850,
            _3850_PIDS,
            ("16.12.12",),
            ("LAN Base",),
            capability,
            P3850,
            {
                L3Capability.IPV4_ROUTING: "Information About IP Routing",
                L3Capability.SVI: "How to Configure IP Routing",
                L3Capability.STATIC_ROUTE: "Information About IP Routing",
            }[capability],
            conditions=(_3850_LANBASE_CONDITION,),
            limits=(_3850_LANBASE_LIMIT,),
        )
        for capability in (
            L3Capability.IPV4_ROUTING,
            L3Capability.SVI,
            L3Capability.STATIC_ROUTE,
        )
    ),
    # 3850 IP Base / IP Services: static, default and routed port documented.
    *(
        _row(
            f"l3-3850-ipbase-services-{capability.value}-v1",
            DeviceFamily.CATALYST_3850,
            _3850_PIDS,
            ("16.12.12",),
            ("IP Base", "IP Services"),
            capability,
            P3850,
            {
                L3Capability.IPV4_ROUTING: "Information About IP Routing",
                L3Capability.SVI: "How to Configure IP Routing",
                L3Capability.ROUTED_PORT: "How to Configure IP Routing",
                L3Capability.STATIC_ROUTE: "Information About IP Routing",
                L3Capability.DEFAULT_ROUTE: "Information About IP Routing",
            }[capability],
        )
        for capability in (
            L3Capability.IPV4_ROUTING,
            L3Capability.SVI,
            L3Capability.ROUTED_PORT,
            L3Capability.STATIC_ROUTE,
            L3Capability.DEFAULT_ROUTE,
        )
    ),
    # 9200: current reviewed L3 evidence; default route and DHCP stay UNKNOWN.
    *(
        _row(
            f"l3-9200-{capability.value}-v1",
            DeviceFamily.CATALYST_9200,
            _9200_PIDS,
            ("17.12.4",),
            ("Network Essentials", "Network Advantage"),
            capability,
            P9200,
            {
                L3Capability.IPV4_ROUTING: "Configuration Guidelines for IP Routing",
                L3Capability.SVI: "Configuration Guidelines for IP Routing",
                L3Capability.ROUTED_PORT: "Configuration Guidelines for IP Routing",
                L3Capability.STATIC_ROUTE: "Configuring Static Unicast Routes",
            }[capability],
        )
        for capability in (
            L3Capability.IPV4_ROUTING,
            L3Capability.SVI,
            L3Capability.ROUTED_PORT,
            L3Capability.STATIC_ROUTE,
        )
    ),
    # 9300: full reviewed L3 forwarding evidence at 17.12.4.
    *(
        _row(
            f"l3-9300-{capability.value}-v1",
            DeviceFamily.CATALYST_9300,
            _9300_PIDS,
            ("17.12.4",),
            ("Network Essentials", "Network Advantage"),
            capability,
            P9300,
            {
                L3Capability.IPV4_ROUTING: "Configuration Guidelines for IP Routing",
                L3Capability.SVI: "Configuration Guidelines for IP Routing",
                L3Capability.ROUTED_PORT: "Configuration Guidelines for IP Routing",
                L3Capability.STATIC_ROUTE: "Configuring Static Unicast Routes",
                L3Capability.DEFAULT_ROUTE: "Configuring the Default Route",
            }[capability],
        )
        for capability in (
            L3Capability.IPV4_ROUTING,
            L3Capability.SVI,
            L3Capability.ROUTED_PORT,
            L3Capability.STATIC_ROUTE,
            L3Capability.DEFAULT_ROUTE,
        )
    ),
    _row(
        "l3-9300-dhcp-relay-v1",
        DeviceFamily.CATALYST_9300,
        _9300_PIDS,
        ("17.12.4",),
        ("Network Advantage",),
        L3Capability.DHCP_RELAY,
        P9300_DHCP,
        "Configuring the DHCP Relay Agent",
    ),
    # C1000: static/default routing with the documented 16-route limit.
    *(
        _row(
            f"l3-c1000-{capability.value}-v1",
            DeviceFamily.CATALYST_C1000,
            _C1000_PIDS,
            ("15.2(7)E1",),
            (),
            capability,
            P1000,
            {
                L3Capability.IPV4_ROUTING: "How to Enable IP Unicast Routing",
                L3Capability.SVI: "Assigning IP Addresses to SVIs",
                L3Capability.ROUTED_PORT: "How to Enable IP Unicast Routing",
                L3Capability.STATIC_ROUTE: "Configuring Default Routes and Networks",
                L3Capability.DEFAULT_ROUTE: "Configuring Default Routes and Networks",
            }[capability],
            limits=(_C1000_LIMIT,),
        )
        for capability in (
            L3Capability.IPV4_ROUTING,
            L3Capability.SVI,
            L3Capability.ROUTED_PORT,
            L3Capability.STATIC_ROUTE,
            L3Capability.DEFAULT_ROUTE,
        )
    ),
)


def _exact_pid(plan: EventPlan, assignment: EventDeviceAssignment) -> str | None:
    device: PhysicalDevice | None = next(
        (item for item in plan.physical_devices if item.id == assignment.physical_device_id),
        None,
    )
    if device is None or device.vendor != "cisco" or not device.model or not device.verified_serial:
        return None
    return device.model.upper()


def _stack_identity(plan: EventPlan, assignment: EventDeviceAssignment) -> Literal[
    "standalone", "resolved", "unresolved"
]:
    stack = next((item for item in plan.stacks if item.assignment_id == assignment.id), None)
    if stack is None:
        return "standalone"
    devices = {item.id: item for item in plan.physical_devices}
    pids = {
        (devices[member.physical_device_id].model or "").upper()
        for member in stack.members
        if member.physical_device_id in devices
        and devices[member.physical_device_id].model
        and devices[member.physical_device_id].verified_serial
    }
    if len(pids) != 1 or any(member.state != "ready" for member in stack.members):
        return "unresolved"
    return "resolved"


def target_for(plan: EventPlan, assignment: EventDeviceAssignment) -> L3Target:
    software = assignment.software
    return L3Target(
        assignment_id=assignment.id,
        hostname=assignment.hostname,
        family=assignment.family,
        physical_device_id=assignment.physical_device_id,
        exact_pid=_exact_pid(plan, assignment),
        software_image=software.image if software else None,
        license=software.license if software else None,
        stack_identity=_stack_identity(plan, assignment),
    )


def _unknown(
    target: L3Target, capability: L3Capability, code: str, reason: str,
) -> L3CapabilityDecision:
    return L3CapabilityDecision(
        capability=capability,
        verdict=L3Verdict.UNKNOWN,
        documentation=DocumentationStatus.UNKNOWN,
        prerequisite=PrerequisiteStatus.MISSING,
        reason_code=code,
        reason=reason,
        affects_forwarding=capability in FORWARDING_CAPABILITIES,
    )


def _evidence(row: L3EvidenceRow) -> L3EvidenceRef:
    return L3EvidenceRef(
        evidence_id=row.evidence_id,
        url=row.source_url,
        section=row.source_section,
        conditions=row.conditions,
        limits=row.limits,
    )


def resolve_l3_capability(
    plan: EventPlan,
    assignment_id: UUID,
    capability: L3Capability,
) -> L3CapabilityDecision:
    """Resolve one exact capability without ever promoting an unreviewed SKU."""
    assignment = next((item for item in plan.assignments if item.id == assignment_id), None)
    if assignment is None:
        raise LookupError("Assignment not found in plan")
    target = target_for(plan, assignment)
    if target.exact_pid is None:
        return _unknown(
            target, capability, "l3-identity-incomplete",
            "Supply an exact Cisco PID and verified serial.",
        )
    if target.stack_identity == "unresolved":
        return _unknown(
            target, capability, "l3-stack-unresolved",
            "A Stack must have homogeneous exact PIDs and ready members.",
        )
    if target.software_image is None:
        return _unknown(
            target, capability, "l3-software-missing", "Supply the running IOS/IOS XE release.",
        )
    family_rows = tuple(
        row for row in ROWS
        if target.exact_pid in {pid.upper() for pid in row.pids}
    )
    if not family_rows:
        return _unknown(
            target, capability, "l3-pid-unlisted", "No L3 evidence row for this exact PID.",
        )
    if assignment.family is not None and any(
        row.family is not assignment.family for row in family_rows
    ):
        return _unknown(
            target, capability, "l3-family-mismatch",
            "Assignment family conflicts with the exact PID evidence.",
        )
    compatible = tuple(
        row for row in family_rows
        if target.software_image.casefold() in {release.casefold() for release in row.releases}
    )
    if not compatible:
        return _unknown(
            target, capability, "l3-release-unmatched",
            "No reviewed L3 evidence for this exact release.",
        )
    license_name = (target.license or "").casefold()
    capability_rows = tuple(
        row for row in compatible if row.capability is capability
    )
    if not capability_rows:
        return _unknown(
            target, capability, "l3-evidence-missing",
            "No reviewed L3 evidence for this exact PID, release and capability.",
        )
    licensed = tuple(
        row for row in capability_rows
        if (row.licenses and license_name in {item.casefold() for item in row.licenses})
        or (not row.licenses and target.license is None)
    )
    if not licensed:
        return _unknown(
            target, capability, "l3-license-unmatched",
            "No reviewed L3 evidence for this exact active license.",
        )
    rows = licensed
    if len(rows) != 1:
        return _unknown(
            target, capability, "l3-evidence-ambiguous",
            "More than one L3 evidence row matches this exact scope.",
        )
    row = rows[0]
    if row.documentation is DocumentationStatus.UNSUPPORTED:
        return L3CapabilityDecision(
            capability=capability,
            verdict=L3Verdict.UNSUPPORTED,
            documentation=row.documentation,
            prerequisite=row.prerequisite,
            reason_code="l3-documented-unsupported",
            reason="Vendor documentation excludes this capability for the exact profile.",
            evidence=(_evidence(row),),
            affects_forwarding=capability in FORWARDING_CAPABILITIES,
        )
    if row.documentation is DocumentationStatus.UNKNOWN:
        return _unknown(
            target, capability, "l3-documentation-unknown",
            "Vendor documentation does not establish this capability.",
        )
    if row.prerequisite is PrerequisiteStatus.UNOBSERVED:
        return L3CapabilityDecision(
            capability=capability,
            verdict=L3Verdict.CONDITIONAL,
            documentation=row.documentation,
            prerequisite=row.prerequisite,
            reason_code="l3-runtime-prerequisite-unobserved",
            reason="Vendor documentation applies, but a runtime prerequisite was not observed.",
            evidence=(_evidence(row),),
            affects_forwarding=capability in FORWARDING_CAPABILITIES,
        )
    if row.prerequisite is PrerequisiteStatus.MISSING:
        return _unknown(
            target, capability, "l3-runtime-prerequisite-missing",
            "A required runtime prerequisite is missing.",
        )
    return L3CapabilityDecision(
        capability=capability,
        verdict=L3Verdict.DOCUMENTED,
        documentation=row.documentation,
        prerequisite=row.prerequisite,
        reason_code="l3-documented",
        reason="Vendor documentation applies to this exact profile.",
        evidence=(_evidence(row),),
        affects_forwarding=capability in FORWARDING_CAPABILITIES,
    )


def evidence_row_count() -> int:
    return len(ROWS)


def capability_documentation_verdict(
    decisions: tuple[L3CapabilityDecision, ...],
) -> Support:
    """Aggregate documentation only; runtime and hardware stay separate."""
    verdicts = {decision.verdict for decision in decisions}
    if L3Verdict.UNSUPPORTED in verdicts:
        return Support.UNSUPPORTED
    if L3Verdict.UNKNOWN in verdicts:
        return Support.UNKNOWN
    return Support.SUPPORTED
