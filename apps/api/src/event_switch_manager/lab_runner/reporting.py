"""Redacted, deterministic local reports for the controlled ConsoleLab."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from event_switch_manager.console.discovery import SerialDiscovery, SerialPortInfo
from event_switch_manager.console.models import ConsoleEvidence

from .authorization import LabAuthorization
from .targets import LabTarget
from .transport import lab_serial_safety_flags


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_token(value: str | None) -> str | None:
    """Stable, non-reversible token for a serial/MAC-like identity value."""
    if not value:
        return None
    return f"<id:{hashlib.sha256(value.casefold().encode('utf-8')).hexdigest()[:12]}>"


@dataclass(frozen=True, slots=True)
class LabBuildMetadata:
    software_git_sha: str
    artifact_sha256: str
    artifact_name: str

    @classmethod
    def load(cls, executable: Path | None = None) -> LabBuildMetadata:
        exe = executable or Path(sys.executable)
        record = exe.parent / "EventSwitchManager-ConsoleLab-build-record.json"
        if record.exists():
            try:
                data = json.loads(record.read_text(encoding="utf-8"))
                return cls(
                    software_git_sha=str(data.get("git_sha", "unknown")),
                    artifact_sha256=str(data.get("executable_sha256", "unknown")),
                    artifact_name=str(data.get("package", "EventSwitchManager-ConsoleLab")),
                )
            except (OSError, ValueError):
                pass
        try:
            digest = sha256_file(exe)
        except OSError:
            digest = "unknown"
        return cls("unknown", digest, "source-run")


class LabReportWriter:
    def __init__(
        self,
        output_dir: Path,
        *,
        build: LabBuildMetadata,
        authorization: LabAuthorization,
        target: LabTarget,
        discovery: SerialDiscovery,
        port: SerialPortInfo | None,
    ) -> None:
        self.output_dir = output_dir
        self.build = build
        self.authorization = authorization
        self.target = target
        self.discovery = discovery
        self.port = port

    def _discovery_summary(self) -> dict[str, Any]:
        port = self.port
        return {
            "platform": self.discovery.platform,
            "status": self.discovery.status.value,
            "supported": self.discovery.supported,
            "duplicate_identities": len(self.discovery.duplicate_identities),
            "com_endpoint": port.port if port else None,
            "description": port.description if port else None,
            "manufacturer": port.manufacturer if port else None,
            "vid": f"{port.vid:04x}" if port and port.vid is not None else None,
            "pid": f"{port.pid:04x}" if port and port.pid is not None else None,
            "usb_serial_token": stable_token(port.serial_number) if port else None,
            "location": port.location if port else None,
            "adapter_identity_sha256": sha256_text(port.adapter_identity) if port else None,
            "identity_quality": port.identity_quality.value if port else None,
            "duplicate_identity": port.duplicate_identity if port else None,
        }

    def _observation_summary(self, evidence: ConsoleEvidence | None) -> dict[str, Any] | None:
        if evidence is None:
            return None
        observation = evidence.observation
        return {
            "source": observation.source.value,
            "family": observation.family.value if observation.family else None,
            "exact_pid": observation.exact_pid,
            "software_version": observation.software_version,
            "serial_token": stable_token(observation.serial_number),
            "license": {
                "declared": observation.license.declared,
                "observed": observation.license.observed,
                "next_boot": observation.license.next_boot,
                "active_features": list(observation.license.active_features),
                "active_verified": observation.license.active_verified,
                "features": [
                    {
                        "feature": item.feature,
                        "license_type": item.license_type,
                        "status": item.status,
                        "period_left": item.period_left,
                    }
                    for item in observation.license.features
                ],
            },
            "interfaces": [
                {
                    "name": item.name,
                    "status": item.status,
                    "physical": item.physical,
                    "present": item.present,
                }
                for item in observation.interfaces
            ],
            "stack": [
                {
                    "number": item.number,
                    "role": item.role,
                    "state": item.state,
                    "priority": item.priority,
                    "hardware_version": item.hardware_version,
                    "pid": item.exact_pid,
                    "serial_token": stable_token(item.serial_number),
                    "mac_token": stable_token(item.mac),
                    "module_pid": item.module_pid,
                    "module_serial_token": stable_token(item.module_serial),
                }
                for item in observation.stack
            ],
            "inventory": [
                {
                    "member": item.member,
                    "component": item.component,
                    "pid": item.pid,
                    "serial_token": stable_token(item.serial_number),
                    "module_pid": item.module_pid,
                    "module_serial_token": stable_token(item.module_serial),
                }
                for item in observation.inventory
            ],
            "boot": [
                {
                    "member": item.member,
                    "boot_path_list": item.boot_path_list,
                    "config_file": item.config_file,
                    "private_config_file": item.private_config_file,
                }
                for item in observation.boot_entries
            ],
            "storage": [
                {
                    "file_type": item.file_type,
                    "flags": item.flags,
                    "prefixes": list(item.prefixes),
                    "total_bytes": item.total_bytes,
                    "free_bytes": item.free_bytes,
                    "alias_conflict": item.alias_conflict,
                }
                for item in observation.storage_entries
            ],
            "unknown_fields": list(observation.unknown_fields),
            "completeness": observation.completeness.value,
            "parser_version": observation.parser_version,
            "hardware_verified": observation.hardware_verified,
            "deployment_approved": observation.deployment_approved,
        }

    def build_payload(
        self,
        *,
        evidence: ConsoleEvidence | None,
        connection: dict[str, Any],
        cleanup_status: str,
        operator_confirmations: int,
        error: str | None,
        cancelled: bool = False,
    ) -> dict[str, Any]:
        queries = (
            [
                {
                    "query": item.query.value,
                    "command": item.command,
                    "status": item.status.value,
                    "duration_seconds": item.duration_seconds,
                    "unknown_fields": list(item.unknown_fields),
                }
                for item in evidence.query_results
            ]
            if evidence
            else []
        )
        payload: dict[str, Any] = {
            "schema_version": 1,
            "report_type": "controlled-live-console-lab",
            "generated_at": datetime.now(UTC).isoformat(),
            "software": {
                "package": self.build.artifact_name,
                "git_sha": self.build.software_git_sha,
                "artifact_sha256": self.build.artifact_sha256,
            },
            "experiment": {
                "experiment_id": self.authorization.experiment_id,
                "target": self.target.key,
                "expected_pid": self.target.expected_pid,
                "expected_release": self.target.expected_release,
                "allowed_queries": [item.value for item in self.authorization.allowed_queries],
                "authorization_digest": self.authorization.digest,
                "issued_at": self.authorization.issued_at.isoformat(),
                "expires_at": self.authorization.expires_at.isoformat(),
                "operator_confirmed": self.authorization.operator_confirmed,
                "consumed": self.authorization.consumed,
                "cancelled": self.authorization.cancelled,
            },
            "discovery": self._discovery_summary(),
            "connection": connection,
            "queries": queries,
            "observation": self._observation_summary(evidence),
            "evidence": {
                "source": evidence.source.value if evidence else None,
                "content_fingerprint": evidence.content_fingerprint if evidence else None,
                "completeness": evidence.completeness.value if evidence else None,
                "unknown_fields": list(evidence.unknown_fields) if evidence else [],
                "lab_provenance_digest": (
                    sha256_text(canonical_json(evidence.lab_provenance.model_dump(mode="json")))
                    if evidence and evidence.lab_provenance else None
                ),
                "hardware_verified": False,
                "deployment_approved": False,
            },
            "operator": {
                "confirmation_count": operator_confirmations,
                "completion_policy": "bounded-quiet-window-plus-operator",
            },
            "serial_safety": {
                **lab_serial_safety_flags(),
                "device_writes": "DISABLED",
                "real_serial_completion": "NOT_VERIFIED",
            },
            "cleanup": {"status": cleanup_status},
            "cancelled": cancelled,
            "error": error,
        }
        fingerprint_payload = {
            key: value for key, value in payload.items()
            if key not in {"generated_at", "report_fingerprint"}
        }
        payload["report_fingerprint"] = sha256_text(canonical_json(fingerprint_payload))
        return payload

    def write(
        self,
        *,
        evidence: ConsoleEvidence | None,
        connection: dict[str, Any],
        cleanup_status: str,
        operator_confirmations: int,
        error: str | None,
        cancelled: bool = False,
    ) -> dict[str, Any]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        payload = self.build_payload(
            evidence=evidence,
            connection=connection,
            cleanup_status=cleanup_status,
            operator_confirmations=operator_confirmations,
            error=error,
            cancelled=cancelled,
        )
        report_path = self.output_dir / "console-lab-report.json"
        summary_path = self.output_dir / "console-lab-summary.txt"
        sums_path = self.output_dir / "SHA256SUMS"
        report_text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        report_path.write_text(report_text + "\n", encoding="utf-8")
        summary = self._summary_text(payload)
        summary_path.write_text(summary, encoding="utf-8")
        sums = (
            f"{sha256_file(report_path)}  console-lab-report.json\n"
            f"{sha256_file(summary_path)}  console-lab-summary.txt\n"
        )
        sums_path.write_text(sums, encoding="utf-8")
        return payload

    def _summary_text(self, payload: dict[str, Any]) -> str:
        observation = payload["observation"] or {}
        lines = [
            "Event Switch Manager — Controlled Console Lab",
            f"实验目标: {payload['experiment']['target']}",
            f"授权实验 ID: {payload['experiment']['experiment_id']}",
            f"授权摘要: {payload['experiment']['authorization_digest']}",
            f"连接状态: {payload['connection'].get('status')}",
            f"COM: {payload['discovery'].get('com_endpoint')}",
            f"设备 PID: {observation.get('exact_pid')}",
            f"软件版本: {observation.get('software_version')}",
            f"完整性: {observation.get('completeness')}",
            f"未知字段: {', '.join(observation.get('unknown_fields', [])) or '无'}",
            f"查询数: {len(payload['queries'])}",
            f"清理状态: {payload['cleanup']['status']}",
            f"硬件认证: {payload['evidence']['hardware_verified']}",
            f"部署许可: {payload['evidence']['deployment_approved']}",
            f"报告指纹: {payload['report_fingerprint']}",
            "",
            "报告仅包含脱敏摘要，不包含完整未脱敏 transcript。",
            "真实串口完成性和硬件验收仍为 NOT_VERIFIED。",
        ]
        if payload.get("error"):
            lines.append(f"错误: {payload['error']}")
        return "\n".join(lines) + "\n"


__all__ = [
    "LabBuildMetadata",
    "LabReportWriter",
    "canonical_json",
    "sha256_file",
    "sha256_text",
    "stable_token",
]
