"""CIS-03-03A offline Cisco L3 candidate renderer.

Given one immutable saved revision, its read-only Layer3Intent and an exact L3
command-evidence registry, this module renders *candidate* command objects for
human review.  Each candidate is one command in one explicit configuration
context, backed by one scope-matched evidence row.

It is deliberately not a deployment feature:

* no full configuration, paste-ready block, execution order or script;
* ``candidate_only`` is true and every deployment flag is false;
* no device is contacted, no running-config is read and no state is written;
* ``syntax_validation.parser_verified`` is false because the independent parser
  belongs to CIS-03-03B;
* command text is emitted only when the device readiness, capability, semantic
  gates and an independently reviewed evidence digest all hold.

Production evidence rows are currently PENDING.  Tests inject an explicitly
test-only reviewed registry to exercise the positive path; that registry is not
production evidence and is never referenced by the default build.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from ..domain import DeviceRole
from .layer3_capability import L3Capability, L3Verdict
from .layer3_command_evidence import (
    DEFAULT_REGISTRY,
    CommandEvidenceRegistry,
    CommandEvidenceRow,
    EvidenceReviewState,
    L3CommandTopic,
)
from .layer3_intent import (
    L3DeviceIntent,
    L3InterfaceIntent,
    L3InterfaceRole,
    L3RouteIntent,
    Layer3Intent,
    build_layer3_intent,
)
from .layer3_registry_selection import (
    RegistrySelectionError,
    assert_production_registry,
)
from .plan import PlanRevision, canonical_plan, plan_hash
from .types import Record

RENDER_SCHEMA_VERSION: Literal[1] = 1
CONTRACT_ID: Literal["cis-03-cisco-l3-cli-candidate-v1"] = (
    "cis-03-cisco-l3-cli-candidate-v1"
)
DICTIONARY_ID: Literal["cis-03-l1-command-dictionary-v1"] = (
    "cis-03-l1-command-dictionary-v1"
)
BASE_BLOCKERS: tuple[str, ...] = (
    "candidate-only-no-execution",
    "deployment-generation-disabled",
    "hardware-not-verified",
    "device-state-unknown",
    "syntax-dictionary-only",
    "independent-parser-not-implemented",
)
_RESERVED_VLANS = frozenset({1, 1002, 1003, 1004, 1005})
_MAX_SVI_PREFIX = 30


class CandidateCategory(StrEnum):
    IP_ROUTING = "ip-routing"
    SVI_INTERFACE = "svi-interface"
    SVI_ADDRESS = "svi-address"
    STATIC_ROUTE = "static-route"
    DEFAULT_ROUTE = "default-route"
    DHCP_HELPER_ADDRESS = "dhcp-helper-address"


class CandidateStatus(StrEnum):
    CANDIDATE = "candidate"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"


class RenderState(StrEnum):
    REVIEW_CANDIDATES = "review-candidates"
    BLOCKED = "blocked"
    NOT_APPLICABLE = "not-applicable"


class RiskClass(StrEnum):
    R2 = "R2"
    R3 = "R3"


class RenderBindingError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class RenderTargetNotFound(LookupError):
    pass


class CandidateTarget(Record):
    kind: Literal["device", "svi", "route"]
    stable_id: UUID
    name: str


class CommandContext(Record):
    mode: Literal["global", "interface"]
    mode_header: str
    target_name: str


class CandidateProvenance(Record):
    intent_interface_id: UUID | None = None
    intent_route_id: UUID | None = None
    intent_subnet_id: UUID | None = None
    intent_fingerprint: str


class CapabilityEvidence(Record):
    capability: str
    verdict: str
    reason_code: str


class SyntaxEvidence(Record):
    evidence_id: str
    topic: str
    release: str
    review_state: str
    content_digest: str
    source_url: str
    source_section: str


class SyntaxValidation(Record):
    level: Literal["dictionary-only"] = "dictionary-only"
    dictionary_id: Literal["cis-03-l1-command-dictionary-v1"] = DICTIONARY_ID
    parser_verified: Literal[False] = False


class Candidate(Record):
    candidate_id: str
    assignment_id: UUID
    target: CandidateTarget
    category: CandidateCategory
    command_context: CommandContext
    status: CandidateStatus
    candidate_text: str | None
    parameters: dict[str, JsonValue] = {}
    provenance: CandidateProvenance
    capability_evidence: tuple[CapabilityEvidence, ...] = ()
    syntax_evidence: tuple[SyntaxEvidence, ...] = ()
    syntax_validation: SyntaxValidation = SyntaxValidation()
    risk_class: RiskClass
    potential_connectivity_impact: bool
    requires_field_verification: bool
    prerequisites: tuple[str, ...] = ()
    blocking_reasons: tuple[str, ...] = ()
    candidate_fingerprint: str


class SourceBinding(Record):
    revision_uuid: UUID
    revision_number: int
    revision_hash: str
    l3_intent_schema_version: int
    l3_intent_fingerprint: str
    command_evidence_registry_id: str
    command_evidence_registry_fingerprint: str


class DeviceRef(Record):
    assignment_id: UUID
    hostname: str
    role: str
    family: str | None
    exact_pid: str | None
    software_image: str | None
    software_license: str | None
    stack_identity: str


class RenderSafety(Record):
    candidate_only: Literal[True] = True
    executable: Literal[False] = False
    deployable: Literal[False] = False
    deployment_allowed: Literal[False] = False
    device_connection: Literal["none"] = "none"
    running_config_read: Literal[False] = False
    device_writes_enabled: Literal[False] = False
    cli: None = None
    deployment_artifact: None = None
    hardware_verified: Literal[False] = False
    parser_verified: Literal[False] = False


class RenderSummary(Record):
    total: int
    candidates: int
    blocked: int
    unsupported: int
    categories: tuple[str, ...]


class L3CandidateDocument(Record):
    l3_render_schema_version: Literal[1] = RENDER_SCHEMA_VERSION
    contract_id: Literal["cis-03-cisco-l3-cli-candidate-v1"] = CONTRACT_ID
    source: SourceBinding
    assignment_id: UUID
    device: DeviceRef
    render_state: RenderState
    candidates: tuple[Candidate, ...] = ()
    blocked_operations: tuple[str, ...] = ()
    unresolved_prerequisites: tuple[str, ...] = ()
    deployment_blockers: tuple[str, ...]
    safety: RenderSafety = RenderSafety()
    summary: RenderSummary
    l3_render_fingerprint: str
    verification: Literal["not-verified"] = "not-verified"
    deployment_status: Literal["blocked"] = "blocked"
    executable: Literal[False] = False
    cli: None = None
    device_writes_enabled: Literal[False] = False


def _json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: JsonValue) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def candidate_fingerprint(candidate: Candidate) -> str:
    payload = candidate.model_dump(mode="json")
    payload.pop("candidate_fingerprint")
    return _sha256_json(payload)


def render_fingerprint(document: L3CandidateDocument) -> str:
    payload = document.model_dump(mode="json")
    payload.pop("l3_render_fingerprint")
    return _sha256_json(payload)


def intent_fingerprint(intent: Layer3Intent) -> str:
    payload = intent.model_dump(mode="json")
    payload.pop("intent_fingerprint")
    return _sha256_json(payload)


def _candidate_id(
    assignment_id: UUID, category: CandidateCategory, target: str, field: str,
) -> str:
    digest = hashlib.sha256(
        f"{assignment_id}|{category.value}|{target}|{field}".encode(),
    ).hexdigest()[:16]
    return f"l3cand-{digest}"


def _device(intent: Layer3Intent, assignment_id: UUID) -> L3DeviceIntent:
    device = next(
        (item for item in intent.devices if item.identity.assignment_id == assignment_id),
        None,
    )
    if device is None:
        raise RenderTargetNotFound(str(assignment_id))
    return device


def _device_ref(device: L3DeviceIntent) -> DeviceRef:
    identity = device.identity
    return DeviceRef(
        assignment_id=identity.assignment_id,
        hostname=identity.hostname,
        role=identity.role.value,
        family=identity.family.value if identity.family else None,
        exact_pid=identity.exact_pid,
        software_image=identity.software_image,
        software_license=identity.software_license,
        stack_identity=identity.stack_identity,
    )


def _capability(device: L3DeviceIntent, capability: L3Capability) -> CapabilityEvidence | None:
    check = next(
        (item for item in device.capability_checks if item.capability is capability),
        None,
    )
    if check is None:
        return None
    return CapabilityEvidence(
        capability=check.capability.value,
        verdict=check.verdict.value,
        reason_code=check.reason_code,
    )


def _capability_blockers(
    device: L3DeviceIntent, capability: L3Capability,
) -> tuple[str, ...]:
    check = next(
        (item for item in device.capability_checks if item.capability is capability),
        None,
    )
    if check is None:
        return (f"capability-missing:{capability.value}",)
    if check.verdict is L3Verdict.DOCUMENTED:
        return ()
    return (check.reason_code,)


def _device_blockers(device: L3DeviceIntent) -> tuple[str, ...]:
    identity = device.identity
    blockers: list[str] = []
    if identity.role is not DeviceRole.CORE:
        blockers.append("assignment-not-cisco-core")
    if identity.vendor != "cisco":
        blockers.append("assignment-not-cisco")
    if identity.stack_identity == "unresolved":
        blockers.append("stack-unresolved")
    if not device.readiness.allowed:
        blockers.append("device-readiness-blocked")
    if device.readiness.ip_routing.value != "enable":
        blockers.append("ip-routing-not-enabled")
    blockers.extend(device.readiness.blockers)
    if any(conflict.severity == "ERROR" for conflict in device.conflicts):
        blockers.append("intent-has-error-conflict")
    for operation in device.blocked_operations:
        if operation.operation in {"policy-acl", "ip-routing", "routed-port-transition"}:
            blockers.append(operation.reason_code)
    return _dedupe(tuple(blockers))


def _evidence(
    registry: CommandEvidenceRegistry,
    device: L3DeviceIntent,
    topic: L3CommandTopic,
) -> tuple[CommandEvidenceRow | None, tuple[str, ...], tuple[SyntaxEvidence, ...]]:
    identity = device.identity
    rows = registry.matching(
        topic, identity.exact_pid, identity.software_image, identity.software_license,
    )
    if not rows:
        return None, ("syntax-evidence-missing",), ()
    if len(rows) != 1:
        return None, ("syntax-evidence-ambiguous",), ()
    row = rows[0]
    ref = SyntaxEvidence(
        evidence_id=row.evidence_id,
        topic=row.topic.value,
        release=row.releases[0],
        review_state=row.review.state.value,
        content_digest=row.content_digest(),
        source_url=row.source_url,
        source_section=row.source_section,
    )
    blockers: list[str] = []
    if row.review.state is EvidenceReviewState.PENDING:
        blockers.append("syntax-evidence-pending")
    elif row.review.state is EvidenceReviewState.REJECTED:
        blockers.append("syntax-evidence-rejected")
    elif row.review.content_digest != row.content_digest():
        blockers.append("syntax-evidence-digest-mismatch")
    blockers.extend(row.scope_blockers())
    if not row.renderable:
        blockers.append("syntax-evidence-not-renderable")
    return row, _dedupe(tuple(blockers)), (ref,)


def _candidate(
    *,
    assignment_id: UUID,
    intent_fp: str,
    category: CandidateCategory,
    target: CandidateTarget,
    context: CommandContext,
    text: str,
    parameters: Mapping[str, JsonValue],
    device: L3DeviceIntent,
    capability: L3Capability,
    row: CommandEvidenceRow | None,
    syntax: tuple[SyntaxEvidence, ...],
    evidence_blockers: tuple[str, ...],
    semantic_blockers: tuple[str, ...],
    provenance_interface_id: UUID | None = None,
    provenance_route_id: UUID | None = None,
    provenance_subnet_id: UUID | None = None,
    risk_class: RiskClass,
) -> Candidate:
    gate_blockers = (
        *_device_blockers(device),
        *_capability_blockers(device, capability),
        *evidence_blockers,
        *semantic_blockers,
    )
    capability_ref = _capability(device, capability)
    text_available = (
        row is not None
        and row.renderable
        and not gate_blockers
    )
    status = (
        CandidateStatus.CANDIDATE if text_available
        else CandidateStatus.BLOCKED
    )
    if any(
        check.capability is capability
        and check.verdict is L3Verdict.UNSUPPORTED
        for check in device.capability_checks
    ):
        status = CandidateStatus.UNSUPPORTED
    identifiers = _candidate_id(
        assignment_id, category, f"{target.kind}:{target.stable_id}", target.name,
    )
    candidate = Candidate(
        candidate_id=identifiers,
        assignment_id=assignment_id,
        target=target,
        category=category,
        command_context=context,
        status=status,
        candidate_text=text if text_available else None,
        parameters=dict(parameters),
        provenance=CandidateProvenance(
            intent_interface_id=provenance_interface_id,
            intent_route_id=provenance_route_id,
            intent_subnet_id=provenance_subnet_id,
            intent_fingerprint=intent_fp,
        ),
        capability_evidence=(capability_ref,) if capability_ref else (),
        syntax_evidence=syntax,
        risk_class=risk_class,
        potential_connectivity_impact=True,
        requires_field_verification=True,
        prerequisites=(
            *(row.requirements if row else ()),
            "device readiness and capability are plan-level only",
            "hardware remains not verified",
        ),
        blocking_reasons=_dedupe(gate_blockers),
        candidate_fingerprint="",
    )
    return candidate.model_copy(update={
        "candidate_fingerprint": candidate_fingerprint(candidate),
    })


def _svi_blockers(
    interface: L3InterfaceIntent, device: L3DeviceIntent,
) -> tuple[str, ...]:
    blockers: list[str] = []
    if interface.kind != "svi":
        blockers.append("svi-kind-unsupported")
    if interface.role is L3InterfaceRole.OTHER:
        blockers.append("svi-role-other")
    elif interface.role is L3InterfaceRole.GATEWAY:
        if interface.gateway_address is None or interface.subnet_id is None:
            blockers.append("svi-gateway-binding-missing")
    elif interface.role is L3InterfaceRole.TRANSIT:
        if (
            device.transit is None
            or interface.interface_id != device.transit.core_svi_id
        ):
            blockers.append("svi-transit-binding-missing")
    if interface.vlan is None:
        blockers.append("svi-vlan-missing")
    else:
        if interface.name != f"Vlan{interface.vlan}":
            blockers.append("svi-name-mismatch")
        if interface.vlan in _RESERVED_VLANS:
            blockers.append("svi-vlan-reserved")
    if interface.address is None:
        blockers.append("svi-address-missing")
    else:
        prefix = interface.address.network.prefixlen
        if not 1 <= prefix <= _MAX_SVI_PREFIX:
            blockers.append("svi-prefix-not-first-batch")
        if (
            interface.address.ip == interface.address.network.network_address
            or interface.address.ip == interface.address.network.broadcast_address
        ):
            blockers.append("svi-address-not-usable")
    if interface.carrier.value != "planned-up":
        blockers.append("svi-carrier-not-planned")
    if (
        interface.gateway_address is not None
        and interface.address is not None
        and interface.address.ip != interface.gateway_address
    ):
        blockers.append("svi-gateway-mismatch")
    return _dedupe(tuple(blockers))


def _route_dependency_blockers(
    device: L3DeviceIntent,
    route: L3RouteIntent,
    registry: CommandEvidenceRegistry,
) -> tuple[str, ...]:
    matches = tuple(
        item for item in device.interfaces
        if item.kind == "svi"
        and item.address is not None
        and route.next_hop in item.address.network
    )
    if not matches:
        return ("route-next-hop-not-on-link",)
    if len(matches) != 1:
        return ("route-next-hop-ambiguous",)
    interface = matches[0]
    blockers: list[str] = [
        f"route-dependency-{reason}"
        for reason in _svi_blockers(interface, device)
    ]
    blockers.extend(
        f"route-dependency-svi-capability-{reason}"
        for reason in _capability_blockers(device, L3Capability.SVI)
    )
    _, interface_evidence, _ = _evidence(
        registry, device, L3CommandTopic.SVI_INTERFACE,
    )
    _, address_evidence, _ = _evidence(
        registry, device, L3CommandTopic.SVI_ADDRESS,
    )
    blockers.extend(
        f"route-dependency-svi-interface-{reason}"
        for reason in interface_evidence
    )
    blockers.extend(
        f"route-dependency-svi-address-{reason}"
        for reason in address_evidence
    )
    return _dedupe(tuple(blockers))


def _route_blockers(
    device: L3DeviceIntent,
    route: L3RouteIntent,
    category: CandidateCategory,
    registry: CommandEvidenceRegistry,
) -> tuple[str, ...]:
    blockers: list[str] = []
    if not 1 <= route.distance <= 255:
        blockers.append("route-distance-out-of-range")
    if route.distance == 255:
        blockers.append("route-distance-255-not-installed")
    if route.owner_assignment_id != device.identity.assignment_id:
        blockers.append("route-owner-mismatch")
    blockers.extend(_route_dependency_blockers(device, route, registry))
    if category is CandidateCategory.STATIC_ROUTE:
        if route.destination.prefixlen == 0:
            blockers.append("static-route-default-destination")
    else:
        if device.transit is None:
            blockers.append("default-route-transit-missing")
        else:
            if route.route_id != device.transit.default_route_id:
                blockers.append("additional-default-route-not-first-batch")
            if route.next_hop != device.transit.hillstone_ip:
                blockers.append("default-route-next-hop-mismatch")
            if route.next_hop not in device.transit.network:
                blockers.append("default-route-next-hop-not-in-transit")
    return _dedupe(tuple(blockers))


def _ip_routing_candidate(
    device: L3DeviceIntent,
    registry: CommandEvidenceRegistry,
    assignment_id: UUID,
    intent_fp: str,
) -> Candidate:
    row, evidence_blockers, syntax = _evidence(
        registry, device, L3CommandTopic.IP_ROUTING,
    )
    semantic: list[str] = []
    if not any(item.kind == "svi" for item in device.interfaces):
        semantic.append("no-svi-for-ip-routing")
    return _candidate(
        assignment_id=assignment_id,
        intent_fp=intent_fp,
        category=CandidateCategory.IP_ROUTING,
        target=CandidateTarget(
            kind="device", stable_id=device.identity.assignment_id,
            name=device.identity.hostname,
        ),
        context=CommandContext(
            mode="global", mode_header="configure terminal",
            target_name=device.identity.hostname,
        ),
        text="ip routing",
        parameters={},
        device=device,
        capability=L3Capability.IPV4_ROUTING,
        row=row,
        syntax=syntax,
        evidence_blockers=evidence_blockers,
        semantic_blockers=tuple(semantic),
        risk_class=RiskClass.R2,
    )


def _svi_candidates(
    device: L3DeviceIntent,
    registry: CommandEvidenceRegistry,
    assignment_id: UUID,
    intent_fp: str,
) -> tuple[Candidate, ...]:
    values: list[Candidate] = []
    for interface in device.interfaces:
        if interface.kind != "svi":
            continue
        blockers = _svi_blockers(interface, device)
        row, evidence_blockers, syntax = _evidence(
            registry, device, L3CommandTopic.SVI_INTERFACE,
        )
        values.append(_candidate(
            assignment_id=assignment_id,
            intent_fp=intent_fp,
            category=CandidateCategory.SVI_INTERFACE,
            target=CandidateTarget(
                kind="svi", stable_id=interface.interface_id,
                name=interface.name,
            ),
            context=CommandContext(
                mode="global", mode_header="configure terminal",
                target_name=interface.name,
            ),
            text=f"interface {interface.name}",
            parameters={"vlan_id": interface.vlan},
            device=device,
            capability=L3Capability.SVI,
            row=row,
            syntax=syntax,
            evidence_blockers=evidence_blockers,
            semantic_blockers=blockers,
            provenance_interface_id=interface.interface_id,
            provenance_subnet_id=interface.subnet_id,
            risk_class=RiskClass.R2,
        ))
        address_row, address_evidence, address_syntax = _evidence(
            registry, device, L3CommandTopic.SVI_ADDRESS,
        )
        address_blockers = blockers
        address_text = ""
        if interface.address is not None:
            address_text = (
                f"ip address {interface.address.ip} {interface.address.netmask}"
            )
        else:
            address_blockers = (*address_blockers, "svi-address-missing")
        values.append(_candidate(
            assignment_id=assignment_id,
            intent_fp=intent_fp,
            category=CandidateCategory.SVI_ADDRESS,
            target=CandidateTarget(
                kind="svi", stable_id=interface.interface_id,
                name=interface.name,
            ),
            context=CommandContext(
                mode="interface", mode_header=f"interface {interface.name}",
                target_name=interface.name,
            ),
            text=address_text,
            parameters={
                "address": str(interface.address.ip) if interface.address else None,
                "mask": str(interface.address.netmask) if interface.address else None,
            },
            device=device,
            capability=L3Capability.SVI,
            row=address_row,
            syntax=address_syntax,
            evidence_blockers=address_evidence,
            semantic_blockers=address_blockers,
            provenance_interface_id=interface.interface_id,
            provenance_subnet_id=interface.subnet_id,
            risk_class=RiskClass.R2,
        ))
    return tuple(values)


def _route_candidates(
    device: L3DeviceIntent,
    registry: CommandEvidenceRegistry,
    assignment_id: UUID,
    intent_fp: str,
) -> tuple[Candidate, ...]:
    values: list[Candidate] = []
    for route in device.routes:
        is_default = route.kind == "default"
        category = (
            CandidateCategory.DEFAULT_ROUTE if is_default
            else CandidateCategory.STATIC_ROUTE
        )
        topic = (
            L3CommandTopic.DEFAULT_ROUTE if is_default
            else L3CommandTopic.STATIC_ROUTE
        )
        capability = (
            L3Capability.DEFAULT_ROUTE if is_default
            else L3Capability.STATIC_ROUTE
        )
        row, evidence_blockers, syntax = _evidence(registry, device, topic)
        blockers = _route_blockers(device, route, category, registry)
        if is_default:
            text = f"ip route 0.0.0.0 0.0.0.0 {route.next_hop}"
        else:
            text = (
                f"ip route {route.destination.network_address} "
                f"{route.destination.netmask} {route.next_hop}"
            )
        if route.distance != 1:
            text = f"{text} {route.distance}"
        values.append(_candidate(
            assignment_id=assignment_id,
            intent_fp=intent_fp,
            category=category,
            target=CandidateTarget(
                kind="route", stable_id=route.route_id,
                name=str(route.destination),
            ),
            context=CommandContext(
                mode="global", mode_header="configure terminal",
                target_name=str(route.destination),
            ),
            text=text,
            parameters={
                "destination": str(route.destination),
                "next_hop": str(route.next_hop),
                "distance": route.distance,
            },
            device=device,
            capability=capability,
            row=row,
            syntax=syntax,
            evidence_blockers=evidence_blockers,
            semantic_blockers=blockers,
            provenance_route_id=route.route_id,
            risk_class=RiskClass.R3 if is_default else RiskClass.R2,
        ))
    return tuple(values)


def _dhcp_candidates(
    device: L3DeviceIntent,
    registry: CommandEvidenceRegistry,
    assignment_id: UUID,
    intent_fp: str,
) -> tuple[Candidate, ...]:
    values: list[Candidate] = []
    svis = {
        item.interface_id: item for item in device.interfaces if item.kind == "svi"
    }
    _, svi_interface_evidence, _ = _evidence(
        registry, device, L3CommandTopic.SVI_INTERFACE,
    )
    _, svi_address_evidence, _ = _evidence(
        registry, device, L3CommandTopic.SVI_ADDRESS,
    )
    svi_capability_blockers = _capability_blockers(device, L3Capability.SVI)
    for relay in device.dhcp_relays:
        svi = svis.get(relay.svi_id)
        semantic: list[str] = [
            *svi_interface_evidence,
            *svi_address_evidence,
            *svi_capability_blockers,
        ]
        if not relay.allowed:
            semantic.append("dhcp-relay-not-allowed")
        semantic.extend(relay.blockers)
        if svi is None:
            semantic.append("dhcp-relay-svi-missing")
        else:
            semantic.extend(_svi_blockers(svi, device))
            if svi.subnet_id != relay.subnet_id:
                semantic.append("dhcp-relay-svi-subnet-mismatch")
            if svi.vlan != relay.vlan:
                semantic.append("dhcp-relay-svi-vlan-mismatch")
        for server in relay.servers:
            row, evidence_blockers, syntax = _evidence(
                registry, device, L3CommandTopic.DHCP_HELPER_ADDRESS,
            )
            address = server
            if (
                address.is_unspecified
                or address.is_multicast
                or address.is_loopback
                or address.is_reserved
            ):
                semantic.append("dhcp-helper-server-invalid")
            values.append(_candidate(
                assignment_id=assignment_id,
                intent_fp=intent_fp,
                category=CandidateCategory.DHCP_HELPER_ADDRESS,
                target=CandidateTarget(
                    kind="svi",
                    stable_id=relay.svi_id,
                    name=f"{svi.name if svi else str(relay.svi_id)} -> {server}",
                ),
                context=CommandContext(
                    mode="interface",
                    mode_header=(
                        f"interface {svi.name}" if svi
                        else f"interface Vlan{relay.vlan}"
                    ),
                    target_name=svi.name if svi else f"Vlan{relay.vlan}",
                ),
                text=f"ip helper-address {server}",
                parameters={
                    "server": str(server),
                    "subnet_id": str(relay.subnet_id),
                },
                device=device,
                capability=L3Capability.DHCP_RELAY,
                row=row,
                syntax=syntax,
                evidence_blockers=evidence_blockers,
                semantic_blockers=_dedupe(tuple(semantic)),
                provenance_subnet_id=relay.subnet_id,
                risk_class=RiskClass.R2,
            ))
    return tuple(values)


def _verify_binding(
    revision: PlanRevision,
    intent: Layer3Intent,
    baseline: PlanRevision | None,
) -> Layer3Intent:
    if plan_hash(canonical_plan(revision.plan)) != revision.content_hash:
        raise RenderBindingError("revision-canonical-hash-mismatch")
    if baseline is not None:
        if plan_hash(canonical_plan(baseline.plan)) != baseline.content_hash:
            raise RenderBindingError("baseline-canonical-hash-mismatch")
        if baseline.plan.event_id != revision.plan.event_id:
            raise RenderBindingError("baseline-event-mismatch")
    if (
        intent.revision_id != revision.id
        or intent.revision_hash != revision.content_hash
        or intent.event_id != revision.plan.event_id
    ):
        raise RenderBindingError("intent-revision-mismatch")
    trusted = build_layer3_intent(revision, baseline)
    if trusted.intent_fingerprint != intent.intent_fingerprint:
        raise RenderBindingError("intent-not-derived-from-trusted-revision")
    if (
        intent.baseline.revision_id
        != (baseline.id if baseline is not None else None)
        or intent.baseline.revision_hash
        != (baseline.content_hash if baseline is not None else None)
    ):
        raise RenderBindingError("intent-baseline-mismatch")
    return trusted


def build_l3_cli_candidates(
    revision: PlanRevision,
    intent: Layer3Intent,
    assignment_id: UUID,
    registry: CommandEvidenceRegistry = DEFAULT_REGISTRY,
    *,
    baseline: PlanRevision | None = None,
    test_only_registry: bool = False,
) -> L3CandidateDocument:
    """Build one deterministic, read-only candidate document."""
    if not registry.production and not test_only_registry:
        raise RenderBindingError("non-production-registry-not-allowed")
    if test_only_registry and registry.production:
        raise RenderBindingError("test-only-path-rejects-production-registry")
    intent = _verify_binding(revision, intent, baseline)
    device = _device(intent, assignment_id)
    if not test_only_registry:
        try:
            assert_production_registry(registry, device.identity)
        except RegistrySelectionError as exc:
            raise RenderBindingError(exc.reason_code) from None
    device_ref = _device_ref(device)
    source = SourceBinding(
        revision_uuid=revision.id,
        revision_number=revision.number,
        revision_hash=revision.content_hash,
        l3_intent_schema_version=intent.l3_intent_schema_version,
        l3_intent_fingerprint=intent.intent_fingerprint,
        command_evidence_registry_id=registry.registry_id,
        command_evidence_registry_fingerprint=registry.fingerprint,
    )
    if device.identity.role is not DeviceRole.CORE or device.identity.vendor != "cisco":
        candidates: tuple[Candidate, ...] = ()
    else:
        candidates = (
            _ip_routing_candidate(
                device, registry, assignment_id, intent.intent_fingerprint,
            ),
            *_svi_candidates(
                device, registry, assignment_id, intent.intent_fingerprint,
            ),
            *_route_candidates(
                device, registry, assignment_id, intent.intent_fingerprint,
            ),
            *_dhcp_candidates(
                device, registry, assignment_id, intent.intent_fingerprint,
            ),
        )
    blockers = _dedupe((
        *BASE_BLOCKERS,
        *device.readiness.blockers,
        *device.service_blockers,
        *(reason for candidate in candidates for reason in candidate.blocking_reasons),
    ))
    unresolved = _dedupe(tuple(
        reason for candidate in candidates for reason in candidate.blocking_reasons
    ))
    render_state = (
        RenderState.REVIEW_CANDIDATES
        if any(item.status is CandidateStatus.CANDIDATE for item in candidates)
        else RenderState.NOT_APPLICABLE
        if not candidates
        else RenderState.BLOCKED
    )
    categories = tuple(sorted({item.category.value for item in candidates}))
    summary = RenderSummary(
        total=len(candidates),
        candidates=sum(1 for item in candidates
                       if item.status is CandidateStatus.CANDIDATE),
        blocked=sum(1 for item in candidates
                    if item.status is CandidateStatus.BLOCKED),
        unsupported=sum(1 for item in candidates
                        if item.status is CandidateStatus.UNSUPPORTED),
        categories=categories,
    )
    draft = L3CandidateDocument(
        source=source,
        assignment_id=assignment_id,
        device=device_ref,
        render_state=render_state,
        candidates=candidates,
        blocked_operations=tuple(
            operation.operation for operation in device.blocked_operations
        ),
        unresolved_prerequisites=unresolved,
        deployment_blockers=blockers,
        summary=summary,
        l3_render_fingerprint="",
    )
    return draft.model_copy(update={"l3_render_fingerprint": render_fingerprint(draft)})


__all__ = [
    "BASE_BLOCKERS",
    "CONTRACT_ID",
    "Candidate",
    "CandidateCategory",
    "CandidateStatus",
    "CandidateTarget",
    "CommandContext",
    "DICTIONARY_ID",
    "L3CandidateDocument",
    "RENDER_SCHEMA_VERSION",
    "RenderBindingError",
    "RenderSafety",
    "RenderState",
    "RenderTargetNotFound",
    "RiskClass",
    "build_l3_cli_candidates",
    "candidate_fingerprint",
    "intent_fingerprint",
    "render_fingerprint",
]
