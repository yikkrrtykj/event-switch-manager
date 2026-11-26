"""Standalone operator-assisted Windows ConsoleLab entry point."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from event_switch_manager.console.discovery import (
    SerialDiscovery,
    SerialPortInfo,
    discover_serial_ports,
)
from event_switch_manager.console.models import (
    ConsoleEvidence,
    LabProvenance,
    compute_evidence_fingerprint,
)
from event_switch_manager.console.observation import CiscoObservationAdapter, IdentityConflict
from event_switch_manager.console.session import (
    ConsoleCredentials,
    ConsoleOperatorAbort,
    ConsoleSession,
    ConsoleTimeout,
    SessionCleanupError,
    SessionError,
)
from event_switch_manager.console.transport import SerialParameters
from event_switch_manager.integrations import ConsoleQuery

from .authorization import (
    LabAuthorizationError,
    issue_authorization,
)
from .completion import LiveCompletionPolicy
from .reporting import LabBuildMetadata, LabReportWriter, sha256_text
from .targets import LAB_TARGETS, LabTarget, get_target
from .transport import AuthorizedSerialTransport, lab_serial_safety_flags

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_DISCOVERY = 3
EXIT_AUTHORIZATION = 4
EXIT_IDENTITY = 5
EXIT_TRANSPORT = 6
EXIT_CLEANUP = 7


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="EventSwitchManager-ConsoleLab",
        description="受控 Cisco Console 只读实验工具（本地、离线、operator-assisted）",
    )
    parser.add_argument("--version", action="version", version="EventSwitchManager-ConsoleLab R86")
    parser.add_argument("--self-test", action="store_true", help="离线自检；不枚举也不打开串口")
    parser.add_argument("--list-ports", action="store_true", help="只枚举串口，不打开串口")
    parser.add_argument("--json", action="store_true", help="与 --list-ports 一起输出 JSON")
    parser.add_argument("--target", choices=sorted(LAB_TARGETS), help="实验目标 Profile")
    parser.add_argument("--com", help="明确选择的 COM endpoint，例如 COM3")
    parser.add_argument("--output-dir", default="console-lab-output", help="本地报告目录")
    parser.add_argument("--ttl-minutes", type=float, default=20.0, help="授权有效期（1–30 分钟）")
    return parser


def _print_discovery(discovery: SerialDiscovery, *, as_json: bool) -> None:
    rows = [
        {
            "endpoint": item.port,
            "description": item.description,
            "manufacturer": item.manufacturer,
            "vid": f"{item.vid:04x}" if item.vid is not None else None,
            "pid": f"{item.pid:04x}" if item.pid is not None else None,
            "usb_serial": item.serial_number,
            "location": item.location,
            "identity": item.adapter_identity,
            "identity_quality": item.identity_quality.value,
            "duplicate_identity": item.duplicate_identity,
        }
        for item in discovery.ports
    ]
    payload = {
        "platform": discovery.platform,
        "status": discovery.status.value,
        "supported": discovery.supported,
        "errors": list(discovery.errors),
        "ports": rows,
    }
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return
    print(f"平台: {payload['platform']} 状态: {payload['status']}")
    if not rows:
        print("未发现串口设备。")
    for row in rows:
        print(
            f"{row['endpoint']}  {row['description'] or '-'}  "
            f"VID:PID={row['vid']}:{row['pid']}  "
            f"identity={row['identity']}  quality={row['identity_quality']}  "
            f"duplicate={row['duplicate_identity']}"
        )
    if discovery.errors:
        print("枚举错误: " + ", ".join(discovery.errors))


def _select_port(discovery: SerialDiscovery, requested: str | None) -> SerialPortInfo:
    if not discovery.supported:
        raise LabAuthorizationError("当前平台不支持 Windows COM 枚举")
    matches = [
        item for item in discovery.ports
        if requested is not None and item.port.casefold() == requested.casefold()
    ]
    if requested is None:
        stable = [
            item for item in discovery.ports
            if not item.duplicate_identity
            and item.identity_quality.value == "stable"
        ]
        if len(stable) != 1:
            raise LabAuthorizationError(
                "必须明确选择唯一且 identity 稳定的 COM；请检查适配器后重试",
            )
        return stable[0]
    if len(matches) != 1:
        raise LabAuthorizationError("指定 COM 未被唯一枚举，拒绝打开")
    return matches[0]


def _confirm(prompt: str) -> bool:
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip() == "YES" or answer.strip().casefold() == "y"


def _credentials() -> ConsoleCredentials:
    username = input("Console username: ").strip()
    password = getpass.getpass("Console password (不回显): ")
    enable = getpass.getpass("Enable password (可留空, 不回显): ")
    return ConsoleCredentials(username, password, enable or None)


def _redacted_output(output: str) -> str:
    # Never include a complete raw transcript in the report.  The interactive
    # display is deliberately line-limited and redacts identity-like values.
    from event_switch_manager.console.redaction import redact_console_output

    text = redact_console_output(output)
    patterns = (
        (r"(?im)(Processor board ID\s+)(\S+)", r"\1<id>"),
        (r"(?im)(\bSN:\s*)(\S+)", r"\1<id>"),
        (r"(?i)\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b", "<mac>"),
        (r"(?m)^([A-Za-z0-9_-]+)([>#])$", r"<host>\2"),
    )
    import re

    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    lines = [line for line in text.splitlines() if line.strip()]
    excerpt = "\n".join(lines[:20])
    if len(lines) > 20:
        excerpt += "\n... (报告不保存完整 transcript)"
    return excerpt


def _operator_query_hook(
    session: ConsoleSession,
    *,
    confirmations: list[int],
) -> Any:
    def hook(query: ConsoleQuery, result: Any) -> None:
        if session.pending_data():
            raise ConsoleOperatorAbort("operator aborted: late terminal data")
        print(
            f"\n查询: {query.value}  状态: {result.status.value}  "
            f"耗时: {result.duration_seconds:.3f}s",
        )
        print("脱敏结果摘要:")
        print(_redacted_output(result.output) or "(无可见输出)")
        if not _confirm("输入 y 确认该查询结果完整并允许继续；其他输入中止: "):
            raise ConsoleOperatorAbort("operator did not confirm query completion")
        confirmations[0] += 1

    return hook


def _lab_provenance(
    authorization: Any,
    target: LabTarget,
    port: SerialPortInfo,
    evidence: ConsoleEvidence | None,
    *,
    operator_confirmed: bool,
    cleanup_status: str,
) -> LabProvenance:
    observation = evidence.observation if evidence else None
    return LabProvenance(
        experiment_id=authorization.experiment_id,
        target=target.key,
        authorization_digest=authorization.digest,
        expected_pid=target.expected_pid,
        expected_release=target.expected_release,
        observed_pid=observation.exact_pid if observation else None,
        observed_release=observation.software_version if observation else None,
        com_endpoint=port.port,
        adapter_identity_sha256=sha256_text(port.adapter_identity),
        artifact_sha256=authorization.artifact_sha256,
        software_git_sha=authorization.software_git_sha,
        operator_confirmed=operator_confirmed,
        cleanup_status=cleanup_status,
    )


def _attach_provenance(
    evidence: ConsoleEvidence,
    provenance: LabProvenance,
) -> ConsoleEvidence:
    updated = evidence.model_copy(update={"lab_provenance": provenance})
    return updated.model_copy(
        update={"content_fingerprint": compute_evidence_fingerprint(updated)},
    )


def run_self_test() -> int:
    """Offline checks that never call COM enumeration or open a serial port."""
    for target in LAB_TARGETS.values():
        profile = target.profile
        if profile.exact_pid != target.expected_pid:
            raise RuntimeError("target PID resolution failed")
        if not target.allowed_queries:
            raise RuntimeError("target query scope is empty")
    flags = lab_serial_safety_flags()
    if flags["break_support"] != "DISABLED":
        raise RuntimeError("BREAK support is not disabled")
    digest = hashlib.sha256(b"console-lab-self-test").hexdigest()
    if len(digest) != 64:
        raise RuntimeError("digest self-test failed")
    print("CONSOLE-LAB SELF-TEST PASS")
    print(f"targets={','.join(sorted(LAB_TARGETS))}")
    print(f"serial_safety={json.dumps(flags, ensure_ascii=False, sort_keys=True)}")
    print("real_serial_opened=NO")
    return EXIT_OK


def run_list_ports(*, as_json: bool) -> int:
    discovery = discover_serial_ports()
    _print_discovery(discovery, as_json=as_json)
    if not discovery.supported:
        return EXIT_DISCOVERY
    return EXIT_OK


def run_experiment(args: argparse.Namespace) -> int:
    if not args.target or not args.com:
        print("实验需要 --target 和明确选择的 --com；不会自动扫描并连接其他端口。", file=sys.stderr)
        return EXIT_USAGE
    try:
        target = get_target(args.target)
    except ValueError:
        print("未知实验 target。", file=sys.stderr)
        return EXIT_USAGE
    ttl_seconds = args.ttl_minutes * 60
    discovery = discover_serial_ports()
    _print_discovery(discovery, as_json=False)
    try:
        port = _select_port(discovery, args.com)
    except LabAuthorizationError as exc:
        print(f"授权拒绝: {exc}", file=sys.stderr)
        return EXIT_DISCOVERY
    if port.duplicate_identity or port.identity_quality.value != "stable":
        print(
            "拒绝连接：adapter identity 重复或不可靠；"
            "未经现场人工身份确认不得降级连接。",
            file=sys.stderr,
        )
        return EXIT_DISCOVERY
    print(f"\n授权目标: {target.label} ({target.expected_pid} / {target.expected_release})")
    print(f"COM: {port.port}  adapter identity: {port.adapter_identity}")
    print(f"允许查询: {', '.join(item.value for item in target.allowed_queries)}")
    if not _confirm(
        "确认该设备无生产业务、无关键链路，并允许本次受控只读实验。输入 YES 继续: ",
    ):
        print("操作者未确认，未打开串口。", file=sys.stderr)
        return EXIT_AUTHORIZATION
    build = LabBuildMetadata.load()
    try:
        authorization = issue_authorization(
            target,
            com_endpoint=port.port,
            adapter_identity=port.adapter_identity,
            ttl_seconds=ttl_seconds,
            operator_confirmed=True,
            artifact_sha256=build.artifact_sha256,
            software_git_sha=build.software_git_sha,
        )
    except LabAuthorizationError as exc:
        print(f"授权创建失败: {exc}", file=sys.stderr)
        return EXIT_AUTHORIZATION
    transport = AuthorizedSerialTransport(
        authorization,
        parameters=SerialParameters(),
    )
    policy = LiveCompletionPolicy()
    session = ConsoleSession(
        transport,
        lab_gate=authorization,
        completion_policy=policy,
        timeout=2.0,
        max_total_response_bytes=512 * 1024,
    )
    writer = LabReportWriter(
        Path(args.output_dir),
        build=build,
        authorization=authorization,
        target=target,
        discovery=discovery,
        port=port,
    )
    confirmations = [0]
    evidence: ConsoleEvidence | None = None
    cleanup_status = "NOT_OPENED"
    error: str | None = None
    cancelled = False
    exit_code = EXIT_OK
    try:
        print("\n请输入本地凭据；密码不会写入参数、环境变量、日志或报告。")
        credentials = _credentials()
        session.open(credentials)
        cleanup_status = "OPEN"
        print("登录成功；开始 operator-assisted 只读查询。每条查询均需人工确认。")
        adapter = CiscoObservationAdapter()
        base_provenance = _lab_provenance(
            authorization,
            target,
            port,
            None,
            operator_confirmed=False,
            cleanup_status="OPEN",
        )
        evidence = adapter.observe(
            session,
            expected_pid=target.expected_pid,
            expected_release=target.expected_release,
            query_hook=_operator_query_hook(session, confirmations=confirmations),
            lab_provenance=base_provenance,
        )
        if evidence.completeness.value == "COMPLETE":
            print("程序完成解析；该结果仍不是硬件认证。")
        else:
            print("观察结果为 PARTIAL/INCOMPLETE；报告记录未知字段，禁止标记 COMPLETE。")
    except LabAuthorizationError as exc:
        error = f"authorization: {exc}"
        exit_code = EXIT_AUTHORIZATION
    except IdentityConflict as exc:
        error = f"identity: {exc}"
        exit_code = EXIT_IDENTITY
    except ConsoleOperatorAbort as exc:
        error = f"operator: {exc}"
        cancelled = True
        exit_code = EXIT_TRANSPORT
    except KeyboardInterrupt:
        error = "operator-interrupt"
        cancelled = True
        exit_code = EXIT_TRANSPORT
    except ConsoleTimeout as exc:
        error = f"timeout: {exc}"
        exit_code = EXIT_TRANSPORT
    except SessionCleanupError as exc:
        error = f"cleanup: {exc}"
        cleanup_status = "CLEANUP_REQUIRED"
        exit_code = EXIT_CLEANUP
    except SessionError as exc:
        error = f"session: {exc}"
        exit_code = EXIT_TRANSPORT
    except Exception as exc:
        error = f"unexpected: {type(exc).__name__}"
        exit_code = EXIT_TRANSPORT
    finally:
        try:
            session.close()
            if cleanup_status != "CLEANUP_REQUIRED":
                cleanup_status = "RELEASED"
        except SessionCleanupError:
            cleanup_status = "CLEANUP_REQUIRED"
            exit_code = EXIT_CLEANUP
        authorization.cancel()

    if evidence is not None:
        provenance = _lab_provenance(
            authorization,
            target,
            port,
            evidence,
            operator_confirmed=(
                confirmations[0] > 0 and cleanup_status == "RELEASED" and not cancelled
            ),
            cleanup_status=cleanup_status,
        )
        evidence = _attach_provenance(evidence, provenance)
    connection = {
        "status": "RELEASED" if cleanup_status == "RELEASED" else cleanup_status,
        "com_endpoint": port.port,
        "opened": cleanup_status != "NOT_OPENED",
        "operator_confirmed": confirmations[0],
        "real_serial_completion": "NOT_VERIFIED",
    }
    try:
        payload = writer.write(
            evidence=evidence,
            connection=connection,
            cleanup_status=cleanup_status,
            operator_confirmations=confirmations[0],
            error=error,
            cancelled=cancelled,
        )
    except Exception as exc:
        print(f"报告写入失败: {type(exc).__name__}", file=sys.stderr)
        return EXIT_TRANSPORT
    print(f"\n报告: {Path(args.output_dir) / 'console-lab-report.json'}")
    print(f"摘要: {Path(args.output_dir) / 'console-lab-summary.txt'}")
    print(f"报告指纹: {payload['report_fingerprint']}")
    print(f"FINAL: {cleanup_status} REAL-SERIAL-COMPLETION=NOT_VERIFIED DEVICE-WRITES=DISABLED")
    if exit_code == EXIT_OK and cleanup_status != "RELEASED":
        exit_code = EXIT_CLEANUP
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        try:
            return run_self_test()
        except Exception as exc:
            print(f"CONSOLE-LAB SELF-TEST FAIL: {type(exc).__name__}", file=sys.stderr)
            return EXIT_TRANSPORT
    if args.list_ports:
        return run_list_ports(as_json=args.json)
    if not args.target:
        _parser().print_help()
        return EXIT_USAGE
    return run_experiment(args)


__all__ = [
    "EXIT_AUTHORIZATION",
    "EXIT_CLEANUP",
    "EXIT_DISCOVERY",
    "EXIT_IDENTITY",
    "EXIT_OK",
    "EXIT_TRANSPORT",
    "EXIT_USAGE",
    "main",
    "run_experiment",
    "run_list_ports",
    "run_self_test",
]
