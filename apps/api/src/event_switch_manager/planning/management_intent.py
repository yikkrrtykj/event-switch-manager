"""CIS-04B device-level management/authentication intent.

The intent is derived from the immutable Saved Revision, the existing exact
device identity, management VLAN/IP, domain and opaque credential reference.
It contains no password, private key or other secret value.

A valid software plan is never a claim that SSH/AAA is configured or that
hardware is reachable. Production remains BLOCKED until independent command
evidence, credential-provider verification and console recovery are available.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal
from uuid import UUID

from .layer2_intent import Layer2Intent
from .management_command_evidence import (
    MANAGEMENT_EVIDENCE_DRAFT_REGISTRY,
    MANAGEMENT_EVIDENCE_REGISTRY_ID,
)
from .plan import PlanRevision
from .types import Record

MANAGEMENT_INTENT_SCHEMA_VERSION: Literal[1] = 1
MANAGEMENT_INTENT_CONTRACT_ID: Literal["cis-04b-management-intent-v1"] = (
    "cis-04b-management-intent-v1"
)
MANAGEMENT_STATUSES = {
    "PLANNED", "VALIDATED", "BLOCKED", "NOT_IMPLEMENTED",
    "HARDWARE_NOT_VERIFIED",
}
_SECRET_REFERENCE_PREFIX = "credref:"


class ManagementIdentity(Record):
    assignment_id: UUID
    hostname: str
    role: str
    family: str | None
    exact_pid: str | None
    pid_evidence: str
    serial_verified: bool
    software_image: str | None
    software_license: str | None
    stack_identity: str


class CredentialReferenceView(Record):
    reference: str | None
    present: bool
    valid: bool
    event_scoped: bool
    secret_material_present: Literal[False] = False
    secret_availability: Literal["not-verified"] = "not-verified"
    provider: Literal["protected-credential-provider-not-implemented"] = (
        "protected-credential-provider-not-implemented"
    )
    reason_codes: tuple[str, ...] = ()
    value_not_returned: Literal[True] = True


class ManagementReachability(Record):
    status: Literal["PLANNED", "BLOCKED"]
    management_vlan: int
    vlan_declared: bool
    management_ip: str | None
    management_subnet: str | None
    duplicate_ip: bool
    reason_codes: tuple[str, ...] = ()


class SSHPolicy(Record):
    status: Literal["PLANNED", "BLOCKED", "NOT_IMPLEMENTED"]
    target_protocol: Literal["sshv2"] = "sshv2"
    telnet_enabled: Literal[False] = False
    plaintext_management_auth: Literal[False] = False
    sshv1_fallback_allowed: Literal[False] = False
    rsa_key_state: Literal["unknown-not-read"] = "unknown-not-read"
    rsa_key_assumed: Literal[False] = False
    reason_codes: tuple[str, ...] = ()


class AuthenticationPolicy(Record):
    status: Literal["PLANNED", "BLOCKED", "NOT_IMPLEMENTED"]
    method: Literal["local-only", "local-with-external-aaa-fallback"] = "local-only"
    local_authentication_required: Literal[True] = True
    local_fallback_required: Literal[True] = True
    external_aaa_requested: Literal[False] = False
    external_aaa_status: Literal["NOT_IMPLEMENTED"] = "NOT_IMPLEMENTED"
    credential_reference: CredentialReferenceView
    reason_codes: tuple[str, ...] = ()


class ConsoleRecoveryPolicy(Record):
    status: Literal["PLANNED", "BLOCKED"]
    required: Literal[True] = True
    local_recovery_account_required: Literal[True] = True
    console_operation: Literal["not-executed"] = "not-executed"
    console_access_verified: Literal[False] = False
    lockout_risk: Literal["present-not-mitigated"] = "present-not-mitigated"
    reason_codes: tuple[str, ...] = ()


class AAAPolicy(Record):
    status: Literal["NOT_IMPLEMENTED", "BLOCKED"]
    mode: Literal["local-only", "external-aaa", "local-with-fallback"] = "local-only"
    external_servers: tuple[str, ...] = ()
    deletion_or_auth_switch_generation: Literal[False] = False
    reason_codes: tuple[str, ...] = ()


class ManagementIntent(Record):
    management_intent_schema_version: Literal[1] = (
        MANAGEMENT_INTENT_SCHEMA_VERSION
    )
    contract_id: Literal["cis-04b-management-intent-v1"] = (
        MANAGEMENT_INTENT_CONTRACT_ID
    )
    event_id: UUID
    revision_id: UUID
    revision_number: int
    revision_hash: str
    assignment_id: UUID
    identity: ManagementIdentity
    management_vlan: int
    management_domain: str | None
    intended_status: Literal[
        "PLANNED", "VALIDATED", "BLOCKED", "NOT_IMPLEMENTED",
        "HARDWARE_NOT_VERIFIED",
    ]
    status: Literal[
        "PLANNED", "VALIDATED", "BLOCKED", "NOT_IMPLEMENTED",
        "HARDWARE_NOT_VERIFIED",
    ]
    validation_scope: Literal["software-planning-only"] = (
        "software-planning-only"
    )
    software_validation_status: Literal["BLOCKED"] = "BLOCKED"
    hardware_status: Literal["HARDWARE_NOT_VERIFIED"] = (
        "HARDWARE_NOT_VERIFIED"
    )
    not_implemented_capabilities: tuple[str, ...] = (
        "protected-credential-provider",
        "external-aaa",
        "console-operation",
        "management-command-evidence-review",
    )
    reachability: ManagementReachability
    ssh_policy: SSHPolicy
    authentication: AuthenticationPolicy
    console_recovery: ConsoleRecoveryPolicy
    aaa: AAAPolicy
    evidence_registry_id: str = MANAGEMENT_EVIDENCE_REGISTRY_ID
    evidence_registry_fingerprint: str
    evidence_status: Literal["PENDING", "PARTIAL", "REVIEWED"] = "PENDING"
    risk_codes: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    hardware_verified: Literal[False] = False
    deployment_allowed: Literal[False] = False
    device_connection: Literal["none"] = "none"
    intent_fingerprint: str


class ManagementInputError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _sha256(value: object) -> str:
    canonical = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def management_intent_fingerprint(intent: ManagementIntent) -> str:
    payload = intent.model_dump(mode="json")
    payload.pop("intent_fingerprint", None)
    return _sha256(payload)


def _credential_reference(
    reference: str | None, event_id: UUID,
) -> tuple[CredentialReferenceView, tuple[str, ...]]:
    if reference is None:
        return (
            CredentialReferenceView(
                reference=None,
                present=False,
                valid=False,
                event_scoped=False,
                reason_codes=("credential-reference-missing",),
            ),
            ("credential-reference-missing", "credential-secret-not-verified"),
        )
    prefix, _, rest = reference.partition(":")
    scope, _, opaque = rest.partition(":")
    try:
        scoped_event = UUID(scope)
    except ValueError:
        scoped_event = None
    valid = bool(prefix == "credref" and scoped_event and opaque)
    event_scoped = scoped_event == event_id if scoped_event else False
    reasons: list[str] = []
    if not valid:
        reasons.append("credential-reference-invalid")
    elif not event_scoped:
        reasons.append("credential-reference-cross-event")
    reasons.append("credential-secret-not-verified")
    return (
        CredentialReferenceView(
            reference=reference if valid and event_scoped else None,
            present=True,
            valid=valid,
            event_scoped=event_scoped,
            reason_codes=tuple(reasons),
        ),
        tuple(reasons),
    )


def build_management_intent(
    revision: PlanRevision,
    l2_intent: Layer2Intent,
    assignment_id: UUID,
) -> ManagementIntent:
    plan = revision.plan
    assignment = next(
        (item for item in plan.assignments if item.id == assignment_id),
        None,
    )
    if assignment is None:
        raise ManagementInputError("assignment-not-in-saved-revision")
    l2_device = next(
        (item for item in l2_intent.devices
         if item.identity.assignment_id == assignment_id),
        None,
    )
    if l2_device is None:
        raise ManagementInputError("device-identity-not-in-saved-revision")
    identity = l2_device.identity
    declared_vlans = {item.vlan_id for item in l2_intent.vlans}
    management_vlan = plan.management_vlan
    vlan_declared = management_vlan in declared_vlans
    management_ip = assignment.management_ip
    subnets = [
        subnet for subnet in plan.subnets if subnet.vlan == management_vlan
    ]
    management_subnet = str(subnets[0].network) if subnets else None
    duplicate_ip = bool(
        management_ip is not None
        and any(
            other.id != assignment_id
            and other.management_ip == management_ip
            for other in plan.assignments
        )
    )
    reachability_reasons: list[str] = []
    if not vlan_declared:
        reachability_reasons.append("management-vlan-not-declared")
    if management_ip is None:
        reachability_reasons.append("management-ip-not-planned")
    elif not subnets:
        reachability_reasons.append("management-vlan-has-no-subnet")
    elif not any(management_ip in subnet.network for subnet in subnets):
        reachability_reasons.append("management-ip-outside-management-subnet")
    if duplicate_ip:
        reachability_reasons.append("management-ip-duplicate")
    routing_reasons: list[str] = []
    if assignment.management_domain is None:
        routing_reasons.append("management-domain-not-planned")
    credential, credential_reasons = _credential_reference(
        assignment.credential_reference, plan.event_id,
    )
    routing_reasons.extend(credential_reasons)
    reachability_status: Literal["PLANNED", "BLOCKED"] = (
        "BLOCKED" if reachability_reasons else "PLANNED"
    )
    if not reachability_reasons:
        reachability_reasons.append("management-reachability-not-verified")
    reasons = [*reachability_reasons, *routing_reasons]

    ssh_reasons: list[str] = ["management-evidence-pending"]
    if management_ip is None or not subnets or duplicate_ip:
        ssh_reasons.append("management-reachability-not-validated")
    if assignment.management_domain is None:
        ssh_reasons.append("ssh-domain-name-not-planned")
    if not credential.valid or not credential.event_scoped:
        ssh_reasons.append("credential-reference-not-validated")
    ssh_reasons.extend((
        "ssh-rsa-key-state-unknown",
        "console-recovery-not-verified",
        "authentication-lockout-risk",
    ))
    auth_reasons = list(credential_reasons)
    auth_reasons.extend(("local-account-not-verified", "authentication-lockout-risk"))
    console_reasons = (
        "console-recovery-not-verified",
        "local-recovery-account-not-verified",
        "console-operation-not-executed",
    )
    aaa_reasons = (
        "external-aaa-not-implemented",
        "aaa-auth-switch-blocked",
    )
    hardware_reasons = ("hardware-not-verified",)
    all_reasons = tuple(dict.fromkeys((
        *reasons, *ssh_reasons, *auth_reasons, *console_reasons,
        *aaa_reasons, *hardware_reasons,
    )))
    intent = ManagementIntent(
        event_id=plan.event_id,
        revision_id=revision.id,
        revision_number=revision.number,
        revision_hash=revision.content_hash,
        assignment_id=assignment_id,
        identity=ManagementIdentity(
            assignment_id=assignment_id,
            hostname=identity.hostname,
            role=identity.role.value,
            family=identity.family.value if identity.family else None,
            exact_pid=identity.pid,
            pid_evidence=identity.pid_evidence,
            serial_verified=identity.serial_verified,
            software_image=identity.software_image,
            software_license=identity.software_license,
            stack_identity=identity.stack_identity,
        ),
        management_vlan=management_vlan,
        management_domain=assignment.management_domain,
        intended_status="PLANNED",
        status="BLOCKED",
        software_validation_status="BLOCKED",
        hardware_status="HARDWARE_NOT_VERIFIED",
        reachability=ManagementReachability(
            status=reachability_status,
            management_vlan=management_vlan,
            vlan_declared=vlan_declared,
            management_ip=str(management_ip) if management_ip else None,
            management_subnet=management_subnet,
            duplicate_ip=duplicate_ip,
            reason_codes=tuple(reachability_reasons),
        ),
        ssh_policy=SSHPolicy(
            status="BLOCKED",
            reason_codes=tuple(ssh_reasons),
        ),
        authentication=AuthenticationPolicy(
            status="BLOCKED",
            method="local-only",
            credential_reference=credential,
            reason_codes=tuple(auth_reasons),
        ),
        console_recovery=ConsoleRecoveryPolicy(
            status="BLOCKED",
            reason_codes=console_reasons,
        ),
        aaa=AAAPolicy(
            status="NOT_IMPLEMENTED",
            mode="local-only",
            reason_codes=aaa_reasons,
        ),
        evidence_registry_id=MANAGEMENT_EVIDENCE_REGISTRY_ID,
        evidence_registry_fingerprint=(
            MANAGEMENT_EVIDENCE_DRAFT_REGISTRY.fingerprint
        ),
        evidence_status="PENDING",
        risk_codes=(
            "management-lockout-risk",
            "hardware-not-verified",
            "secret-not-available",
        ),
        reason_codes=all_reasons,
        intent_fingerprint="",
    )
    return intent.model_copy(update={
        "intent_fingerprint": management_intent_fingerprint(intent),
    })


__all__ = [
    "AAAPolicy",
    "AuthenticationPolicy",
    "ConsoleRecoveryPolicy",
    "CredentialReferenceView",
    "ManagementIdentity",
    "ManagementInputError",
    "ManagementIntent",
    "ManagementReachability",
    "SSHPolicy",
    "build_management_intent",
    "management_intent_fingerprint",
]
