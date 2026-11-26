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
from event_switch_manager.console.models import ConsoleEvidence, ConsoleSource

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


class ArtifactIdentityError(RuntimeError):
    """The running executable does not match its frozen build record."""


@dataclass(frozen=True, slots=True)
class LabBuildMetadata:
    software_git_sha: str
    artifact_sha256: str
    artifact_name: str
    is_frozen: bool = False
    identity_verified: bool = False

    @classmethod
    def load(cls, executable: Path | None = None) -> LabBuildMetadata:
        exe = executable or Path(sys.executable)
        try:
            actual_exe_sha = sha256_file(exe)
        except OSError:
            actual_exe_sha = "unknown"
        record = exe.parent / "EventSwitchManager-ConsoleLab-build-record.json"
        if record.exists():
            try:
                data = json.loads(record.read_text(encoding="utf-8"))
                recorded = str(data.get("executable_sha256", ""))
                if recorded != actual_exe_sha:
                    raise ArtifactIdentityError(
                        "running executable SHA-256 does not match the build record",
                    )
                git_sha = str(data.get("git_sha", ""))
                if not git_sha or git_sha == "unknown":
                    raise ArtifactIdentityError("build record has no Git identity")
                return cls(
                    software_git_sha=git_sha,
                    artifact_sha256=actual_exe_sha,
                    artifact_name=str(
                        data.get("package", "EventSwitchManager-ConsoleLab"),
                    ),
                    is_frozen=True,
                    identity_verified=True,
                )
            except (OSError, ValueError) as exc:
                raise ArtifactIdentityError("build record is unreadable") from exc
        return cls(
            "unknown", actual_exe_sha, "source-run",
            is_frozen=False, identity_verified=False,
        )

    def require_frozen(self) -> None:
        if not self.is_frozen or not self.identity_verified:
            raise ArtifactIdentityError(
                "real ConsoleLab experiments require a verified frozen artifact",
            )


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
            "transport_kind": port.transport_kind.value if port else None,
            "description_token": stable_token(port.description) if port else None,
            "manufacturer_token": stable_token(port.manufacturer) if port else None,
            "bluetooth_name_token": (
                stable_token(port.bluetooth_name) if port else None
            ),
            "bluetooth_direction": (
                port.bluetooth_direction.value if port else None
            ),
            "operator_bluetooth_direction": self.authorization.bluetooth_direction,
            "enumerated_bluetooth_direction": (
                self.authorization.enumerated_bluetooth_direction
            ),
            "remote_bluetooth_token": (
                stable_token(port.remote_bluetooth_identity) if port else None
            ),
            "pnp_instance_token": stable_token(port.pnp_instance_identity) if port else None,
            "identity_confidence": (
                self.authorization.identity_confidence
            ),
            "binding_mode": self.authorization.binding_mode,
            "vid": f"{port.vid:04x}" if port and port.vid is not None else None,
            "pid": f"{port.pid:04x}" if port and port.pid is not None else None,
            "usb_serial_token": stable_token(port.serial_number) if port else None,
            "location_token": stable_token(port.location) if port else None,
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
            "interfaces_observed": len(observation.interfaces),
            "expected_layout_verified": False,
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
                    "boot_path_token": stable_token(item.boot_path_list),
                    "config_file_token": stable_token(item.config_file),
                    "private_config_file_token": stable_token(item.private_config_file),
                }
                for item in observation.boot_entries
            ],
            "storage": [
                {
                    "file_type": item.file_type,
                    "flags": item.flags,
                    "prefix_tokens": [
                        stable_token(prefix) for prefix in item.prefixes
                    ],
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
        query_results: tuple[Any, ...] = (),
    ) -> dict[str, Any]:
        if evidence is not None and evidence.source is ConsoleSource.AUTHORIZED_LIVE_LAB:
            validate_lab_provenance(
                evidence.lab_provenance,
                self.authorization,
                self.target,
                evidence.observation,
            )
        source_results = evidence.query_results if evidence else query_results
        queries = [
            {
                "query": item.query.value,
                "command": item.command,
                "status": item.status.value,
                "duration_seconds": item.duration_seconds,
                "output_bytes": item.output_bytes,
                "output_lines": item.output_lines,
                "pagination_events": item.pagination_events,
                "completion_status": item.completion_status,
                "unknown_fields": list(item.unknown_fields),
            }
            for item in source_results
        ]
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
            "outcome": {
                "connection_status": connection.get("status"),
                "opened": connection.get("opened"),
                "readonly_queries_completed": connection.get(
                    "readonly_queries_completed", False,
                ),
                "observation_completeness": connection.get(
                    "observation_completeness",
                ),
                "experiment_verdict": connection.get("experiment_verdict"),
                "hardware_verdict": "NOT_VERIFIED",
                "cleanup_status": cleanup_status,
                "cancelled": cancelled,
            },
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
        fingerprint_input = canonical_json(fingerprint_payload)
        payload["report_fingerprint"] = sha256_text(fingerprint_input)
        payload["_fingerprint_input"] = fingerprint_input
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
        query_results: tuple[Any, ...] = (),
    ) -> dict[str, Any]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        payload = self.build_payload(
            evidence=evidence,
            connection=connection,
            cleanup_status=cleanup_status,
            operator_confirmations=operator_confirmations,
            error=error,
            cancelled=cancelled,
            query_results=query_results,
        )
        report_path = self.output_dir / "console-lab-report.json"
        fingerprint_input_path = self.output_dir / "console-lab-report-fingerprint-input.json"
        summary_path = self.output_dir / "console-lab-summary.txt"
        sums_path = self.output_dir / "SHA256SUMS"
        fingerprint_input = str(payload.pop("_fingerprint_input"))
        fingerprint_input_path.write_text(fingerprint_input, encoding="utf-8")
        report_text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        report_path.write_text(report_text + "\n", encoding="utf-8")
        summary = self._summary_text(payload)
        summary_path.write_text(summary, encoding="utf-8")
        sums = (
            f"{sha256_file(report_path)}  console-lab-report.json\n"
            f"{sha256_file(fingerprint_input_path)}  console-lab-report-fingerprint-input.json\n"
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
            f"实验 verdict: {payload['outcome']['experiment_verdict']}",
            f"连接状态: {payload['outcome']['connection_status']}",
            "",
            "报告仅包含脱敏摘要，不包含完整未脱敏 transcript。",
            "report fingerprint 只作内容完整性检查，不是真实性签名。",
            "真实串口完成性和硬件验收仍为 NOT_VERIFIED。",
        ]
        if payload.get("error"):
            lines.append(f"错误: {payload['error']}")
        return "\n".join(lines) + "\n"


class LabEvidenceError(RuntimeError):
    """A caller-supplied lab provenance does not match the real experiment."""


def validate_lab_provenance(
    provenance: Any,
    authorization: LabAuthorization,
    target: LabTarget,
    observation: Any,
    *,
    require_success: bool = False,
) -> None:
    if provenance is None:
        raise LabEvidenceError("lab evidence requires provenance")
    checks = (
        provenance.experiment_id == authorization.experiment_id,
        provenance.authorization_digest == authorization.digest,
        provenance.target == target.key,
        provenance.expected_pid == target.expected_pid,
        provenance.expected_release == target.expected_release,
        provenance.com_endpoint.casefold() == authorization.com_endpoint.casefold(),
        provenance.adapter_identity_sha256 == sha256_text(authorization.adapter_identity),
        provenance.artifact_sha256 == authorization.artifact_sha256,
        provenance.software_git_sha == authorization.software_git_sha,
        provenance.binding_mode == authorization.binding_mode,
        provenance.identity_confidence == authorization.identity_confidence,
        provenance.bluetooth_direction == authorization.bluetooth_direction,
        provenance.enumerated_bluetooth_direction
        == authorization.enumerated_bluetooth_direction,
        provenance.hardware_evidence == "lab-readonly-unverified",
    )
    if require_success and not (
        provenance.operator_confirmed is True
        and provenance.cleanup_status == "RELEASED"
    ):
        raise LabEvidenceError("lab provenance is not a successful operator run")
    if not all(checks):
        raise LabEvidenceError("lab provenance does not match the authorization/run")
    if observation is not None:
        if provenance.observed_pid != observation.exact_pid:
            raise LabEvidenceError("lab provenance observed PID mismatch")
        if provenance.observed_release != observation.software_version:
            raise LabEvidenceError("lab provenance observed release mismatch")


def verify_report_fingerprint(payload: dict[str, Any]) -> bool:
    """Independently recompute the content-integrity fingerprint of a report."""
    supplied = payload.get("report_fingerprint")
    if not isinstance(supplied, str):
        return False
    fingerprint_payload = {
        key: value for key, value in payload.items()
        if key not in {"generated_at", "report_fingerprint"}
    }
    return supplied == sha256_text(canonical_json(fingerprint_payload))


__all__ = [
    "ArtifactIdentityError",
    "LabBuildMetadata",
    "LabEvidenceError",
    "LabReportWriter",
    "canonical_json",
    "sha256_file",
    "sha256_text",
    "stable_token",
    "validate_lab_provenance",
    "verify_report_fingerprint",
]
