"""CIS-04B management/SSHv2 command evidence drafts.

These are deliberately PENDING evidence rows for Cisco IOS XE Dublin 17.12.4
on Catalyst 9300 and 9200.  No independent reviewer has approved them.  The
registry is non-production and can only emit BLOCKED candidates until a fixed,
digest-bound independent review exists.

The command templates never contain a real password, private key or other
secret.  The local username topic is marked secret-bearing and can never render
CLI text from this module.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Literal

from ..domain import DeviceFamily
from .layer3_c9200_command_evidence import C9200_PIDS
from .layer3_command_evidence import (
    EvidenceReviewState,
)

MANAGEMENT_EVIDENCE_REGISTRY_ID = (
    "cis-04b-management-command-evidence-draft-v1"
)
MANAGEMENT_RELEASE = "17.12.4"
MANAGEMENT_LICENSES: tuple[str, ...] = (
    "Network Essentials",
    "Network Advantage",
)
C9300_MANAGEMENT_PIDS: tuple[str, ...] = (
    "C9300-24T", "C9300-24P", "C9300L-24T-4G", "C9300L-24T-4G-E",
    "C9300L-24P-4X", "C9300L-24P-4X-E", "C9300X-24Y", "C9300X-24Y-A",
)
C9200_MANAGEMENT_PIDS: tuple[str, ...] = C9200_PIDS

URL_9300_SECURITY = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/configuration_guide/sec/b_1712_sec_9300_cg/"
)
URL_9200_SECURITY = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/configuration_guide/sec/b_1712_sec_9200_cg/"
)
URL_9300_COMMANDS = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/command_reference/b_1712_9300_cr/security_commands.html"
)
URL_9200_COMMANDS = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/"
    "software/release/17-12/command_reference/b_1712_9200_cr/security_commands.html"
)


class ManagementCommandTopic(StrEnum):
    DOMAIN_NAME = "management-domain-name"
    SSH_VERSION = "management-ssh-version"
    RSA_KEY = "management-rsa-key"
    LOCAL_USERNAME = "management-local-username"
    VTY_TRANSPORT = "management-vty-transport"
    LOGIN_LOCAL = "management-login-local"
    AAA_NEW_MODEL = "management-aaa-new-model"
    AAA_LOGIN_LOCAL = "management-aaa-login-default"
    CONSOLE_AUTH = "management-console-auth"


@dataclass(frozen=True, slots=True)
class ManagementEvidenceRow:
    evidence_id: str
    family: DeviceFamily
    pids: tuple[str, ...]
    releases: tuple[str, ...]
    licenses: tuple[str, ...]
    topic: ManagementCommandTopic
    command: str
    configuration_mode: Literal["global", "line"]
    source_url: str
    source_section: str
    preconditions: tuple[str, ...]
    exclusions: tuple[str, ...]
    risks: tuple[str, ...]
    secret_bearing: bool
    review_state: EvidenceReviewState = EvidenceReviewState.PENDING
    reviewer: str = ""
    reviewed_at: str = ""
    findings: tuple[str, ...] = ()
    review_digest: str = ""

    def content_digest(self) -> str:
        payload = {
            "evidence_id": self.evidence_id,
            "family": self.family.value,
            "pids": self.pids,
            "releases": self.releases,
            "licenses": self.licenses,
            "topic": self.topic.value,
            "command": self.command,
            "configuration_mode": self.configuration_mode,
            "source_url": self.source_url,
            "source_section": self.source_section,
            "preconditions": self.preconditions,
            "exclusions": self.exclusions,
            "risks": self.risks,
            "secret_bearing": self.secret_bearing,
        }
        canonical = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def well_formed(self) -> bool:
        return (
            bool(self.evidence_id)
            and bool(self.source_url)
            and bool(self.source_section)
            and bool(self.command)
            and self.configuration_mode in {"global", "line"}
        )

    @property
    def renderable(self) -> bool:
        return (
            self.well_formed
            and self.review_state is EvidenceReviewState.REVIEWED
            and bool(self.reviewer)
            and bool(self.reviewed_at)
            and bool(self.findings)
            and self.review_digest == self.content_digest()
        )

    def with_review(self, *, reviewer: str, reviewed_at: str,
                    findings: tuple[str, ...]) -> ManagementEvidenceRow:
        return replace(
            self,
            review_state=EvidenceReviewState.REVIEWED,
            reviewer=reviewer,
            reviewed_at=reviewed_at,
            findings=findings,
            review_digest=self.content_digest(),
        )


@dataclass(frozen=True, slots=True)
class ManagementEvidenceRegistry:
    rows: tuple[ManagementEvidenceRow, ...]
    registry_id: str = MANAGEMENT_EVIDENCE_REGISTRY_ID
    production: bool = False

    def __post_init__(self) -> None:
        ids = [row.evidence_id for row in self.rows]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate management evidence ID")
        if self.production:
            raise ValueError(
                "Management command evidence is PENDING and has no production Registry",
            )

    @property
    def fingerprint(self) -> str:
        payload = [
            {
                "evidence_id": row.evidence_id,
                "content_digest": row.content_digest(),
                "review_state": row.review_state.value,
                "review_digest": row.review_digest,
            }
            for row in sorted(self.rows, key=lambda item: item.evidence_id)
        ]
        canonical = json.dumps(
            {
                "registry_id": self.registry_id,
                "rows": payload,
                "production": self.production,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def renderable_count(self) -> int:
        return sum(1 for row in self.rows if row.renderable)

    def find(
        self, family: DeviceFamily, pid: str, release: str, license_name: str,
        topic: ManagementCommandTopic,
    ) -> ManagementEvidenceRow | None:
        release_key = release.casefold()
        license_key = license_name.casefold()
        for row in self.rows:
            if (row.family is family
                and pid.upper() in {item.upper() for item in row.pids}
                and release_key in {item.casefold() for item in row.releases}
                and license_key in {item.casefold() for item in row.licenses}
                and row.topic is topic):
                return row
        return None


_TOPIC_BASE: dict[ManagementCommandTopic, dict[str, object]] = {
    ManagementCommandTopic.DOMAIN_NAME: {
        "command": "ip domain name <domain>",
        "mode": "global",
        "section": "Configuring a Device for SSH Version 2 Using a Hostname and Domain Name",
        "preconditions": ("management-domain-planned",),
        "exclusions": ("do not invent or derive a domain from a device name",),
        "risks": ("domain change can affect certificate and SSH identity",),
        "secret": False,
    },
    ManagementCommandTopic.SSH_VERSION: {
        "command": "ip ssh version 2",
        "mode": "global",
        "section": "Secure Shell Version 2 Support",
        "preconditions": ("management-ip-planned", "authentication-and-recovery-planned"),
        "exclusions": ("no SSHv1 compatibility mode", "no Telnet transport"),
        "risks": ("enabling remote management before recovery is verified can lock out operators",),
        "secret": False,
    },
    ManagementCommandTopic.RSA_KEY: {
        "command": "crypto key generate rsa modulus 4096",
        "mode": "global",
        "section": "Configuring a Device for SSH Version 2 Using RSA Key Pairs",
        "preconditions": ("domain-planned", "key-state-unknown-not-read"),
        "exclusions": ("never assume an RSA key already exists",),
        "risks": ("key generation and replacement can change the SSH host identity",),
        "secret": False,
    },
    ManagementCommandTopic.LOCAL_USERNAME: {
        "command": "username <name> privilege 15 secret <redacted>",
        "mode": "global",
        "section": "Controlling Switch Access with Passwords and Privilege Levels",
        "preconditions": (
            "credential-reference-validated",
            "secret-available-through-protected-provider",
        ),
        "exclusions": ("never render a password, secret or secret placeholder",),
        "risks": ("credential creation and privilege level can grant broad access",),
        "secret": True,
    },
    ManagementCommandTopic.VTY_TRANSPORT: {
        "command": "transport input ssh",
        "mode": "line",
        "section": "Secure Shell Version 2 Support",
        "preconditions": ("vty-authentication-planned", "console-recovery-verified"),
        "exclusions": ("no Telnet", "no unauthenticated VTY"),
        "risks": ("remote access can lock out operators without verified recovery",),
        "secret": False,
    },
    ManagementCommandTopic.LOGIN_LOCAL: {
        "command": "login local",
        "mode": "line",
        "section": "Configuring Local Authentication and Authorization",
        "preconditions": ("local-credential-reference-validated", "console-recovery-verified"),
        "exclusions": ("do not assume a local account exists",),
        "risks": ("local-only login can lock out operators when credentials are absent",),
        "secret": False,
    },
    ManagementCommandTopic.AAA_NEW_MODEL: {
        "command": "aaa new-model",
        "mode": "global",
        "section": "Configuring Authentication",
        "preconditions": ("aaa-recovery-path-verified", "local-fallback-verified"),
        "exclusions": ("no AAA activation without verified local fallback",),
        "risks": ("AAA activation can lock out management",),
        "secret": False,
    },
    ManagementCommandTopic.AAA_LOGIN_LOCAL: {
        "command": "aaa authentication login default local",
        "mode": "global",
        "section": "Configuring Authentication",
        "preconditions": ("local-account-verified", "console-recovery-verified"),
        "exclusions": ("no external-only authentication without fallback",),
        "risks": ("authentication method changes can lock out management",),
        "secret": False,
    },
    ManagementCommandTopic.CONSOLE_AUTH: {
        "command": "login authentication CONSOLE",
        "mode": "line",
        "section": "Configuring Authentication",
        "preconditions": ("named-console-method-planned", "console-recovery-verified"),
        "exclusions": ("no console lockout",),
        "risks": ("console authentication changes can remove recovery access",),
        "secret": False,
    },
}


def _rows_for_family_rows(
    family: DeviceFamily, pids: tuple[str, ...],
    base_url: str, command_url: str,
) -> tuple[ManagementEvidenceRow, ...]:
    rows: list[ManagementEvidenceRow] = []
    for topic in ManagementCommandTopic:
        base = _TOPIC_BASE[topic]
        family_name = family.value.replace("catalyst-", "")
        topic_name = topic.value.removeprefix("management-")
        rows.append(ManagementEvidenceRow(
            evidence_id=f"mgmt-{family_name}-{topic_name}-v1",
            family=family,
            pids=pids,
            releases=(MANAGEMENT_RELEASE,),
            licenses=MANAGEMENT_LICENSES,
            topic=topic,
            command=str(base["command"]),
            configuration_mode=base["mode"],  # type: ignore[arg-type]
            source_url=command_url if base["secret"] else base_url,
            source_section=str(base["section"]),
            preconditions=tuple(base["preconditions"]),  # type: ignore[arg-type]
            exclusions=tuple(base["exclusions"]),  # type: ignore[arg-type]
            risks=tuple(base["risks"]),  # type: ignore[arg-type]
            secret_bearing=bool(base["secret"]),
        ))
    return tuple(rows)


MANAGEMENT_EVIDENCE_ROWS: tuple[ManagementEvidenceRow, ...] = (
    *_rows_for_family_rows(
        DeviceFamily.CATALYST_9300,
        C9300_MANAGEMENT_PIDS,
        URL_9300_SECURITY,
        URL_9300_COMMANDS,
    ),
    *_rows_for_family_rows(
        DeviceFamily.CATALYST_9200,
        C9200_MANAGEMENT_PIDS,
        URL_9200_SECURITY,
        URL_9200_COMMANDS,
    ),
)

MANAGEMENT_EVIDENCE_DRAFT_REGISTRY = ManagementEvidenceRegistry(
    MANAGEMENT_EVIDENCE_ROWS,
)


__all__ = [
    "C9200_MANAGEMENT_PIDS",
    "C9300_MANAGEMENT_PIDS",
    "MANAGEMENT_EVIDENCE_DRAFT_REGISTRY",
    "MANAGEMENT_EVIDENCE_REGISTRY_ID",
    "MANAGEMENT_EVIDENCE_ROWS",
    "MANAGEMENT_LICENSES",
    "MANAGEMENT_RELEASE",
    "ManagementCommandTopic",
    "ManagementEvidenceRegistry",
    "ManagementEvidenceRow",
    "URL_9200_COMMANDS",
    "URL_9200_SECURITY",
    "URL_9300_COMMANDS",
    "URL_9300_SECURITY",
]
