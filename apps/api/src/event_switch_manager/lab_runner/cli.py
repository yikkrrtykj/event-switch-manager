"""Standalone operator-assisted Windows ConsoleLab entry point."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import queue
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol

from event_switch_manager.console.discovery import (
    PortTransportKind,
    SerialDiscovery,
    SerialPortInfo,
    discover_serial_ports,
)
from event_switch_manager.console.models import (
    ConsoleEvidence,
    LabProvenance,
    ObservationCompleteness,
    build_evidence,
    compute_evidence_fingerprint,
)
from event_switch_manager.console.observation import CiscoObservationAdapter, IdentityConflict
from event_switch_manager.console.parser import AuthPromptKind
from event_switch_manager.console.session import (
    ConsoleOperatorAbort,
    ConsoleSession,
    ConsoleTimeout,
    SessionCleanupError,
    SessionError,
    SessionState,
)
from event_switch_manager.console.transport import SerialParameters
from event_switch_manager.integrations import ConsoleQuery

from .authorization import (
    LabAuthorizationError,
    issue_authorization,
)
from .completion import LiveCompletionPolicy
from .reporting import (
    ArtifactIdentityError,
    LabBuildMetadata,
    LabEvidenceError,
    LabReportWriter,
    sha256_text,
    validate_lab_provenance,
)
from .targets import LAB_TARGETS, LabTarget, get_target
from .transport import AuthorizedSerialTransport, lab_serial_safety_flags


class LabUiCallbacks(Protocol):
    def confirm(self, prompt: str, timeout_seconds: float = 120.0) -> bool: ...

    def credential(self, kind: AuthPromptKind) -> str: ...


_UI_CONTEXT = threading.local()
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_SESSION: ConsoleSession | None = None


def _ui_callbacks() -> LabUiCallbacks | None:
    callbacks = getattr(_UI_CONTEXT, "callbacks", None)
    return callbacks if callbacks is not None else None


def cancel_active_experiment() -> None:
    """GUI cancellation hook; never opens or reconnects a port."""
    with _ACTIVE_LOCK:
        session = _ACTIVE_SESSION
    if session is not None:
        session.cancel()


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
    parser.add_argument("--version", action="version", version="EventSwitchManager-ConsoleLab R88")
    parser.add_argument("--self-test", action="store_true", help="离线自检；不枚举也不打开串口")
    parser.add_argument(
        "--artifact-check", action="store_true",
        help="核对运行 EXE SHA-256 与 Build Record；不枚举也不打开串口",
    )
    parser.add_argument("--list-ports", action="store_true", help="只枚举串口，不打开串口")
    parser.add_argument("--json", action="store_true", help="与 --list-ports 一起输出 JSON")
    parser.add_argument("--target", choices=sorted(LAB_TARGETS), help="实验目标 Profile")
    parser.add_argument("--com", help="明确选择的 COM endpoint，例如 COM3")
    parser.add_argument(
        "--manual-bluetooth-binding", action="store_true",
        help="仅对明确选择的 Bluetooth SPP 端口使用人工绑定（单次会话）",
    )
    parser.add_argument(
        "--bluetooth-direction",
        choices=("incoming", "outgoing", "unknown"),
        default="unknown",
        help="Bluetooth SPP 方向；unknown 表示现场无法可靠判断",
    )
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
            "transport_kind": item.transport_kind.value,
            "bluetooth_name": item.bluetooth_name,
            "bluetooth_direction": item.bluetooth_direction.value,
            "pnp_instance_identity": item.pnp_instance_identity,
            "remote_bluetooth_identity": item.remote_bluetooth_identity,
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
            f"kind={row['transport_kind']}  "
            f"bt={row['bluetooth_direction']}  "
            f"identity={row['identity']}  quality={row['identity_quality']}  "
            f"duplicate={row['duplicate_identity']}"
        )
    if discovery.errors:
        print("枚举错误: " + ", ".join(discovery.errors))


def _select_port(
    discovery: SerialDiscovery,
    requested: str | None,
    *,
    manual_bluetooth_binding: bool = False,
) -> SerialPortInfo:
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
    selected = matches[0]
    if selected.transport_kind is PortTransportKind.BLUETOOTH_SPP:
        if not manual_bluetooth_binding:
            raise LabAuthorizationError(
                "Bluetooth SPP 需要显式的人工绑定授权，不能自动连接",
            )
        if not selected.pnp_instance_identity:
            raise LabAuthorizationError(
                "Bluetooth 端口缺少 PnP instance identity，拒绝绑定",
            )
        if selected.duplicate_identity:
            raise LabAuthorizationError("Bluetooth PnP identity 重复，拒绝绑定")
    elif selected.identity_quality.value != "stable" or selected.duplicate_identity:
        raise LabAuthorizationError("非 Bluetooth 端口仍需唯一且稳定的 identity")
    return selected


def _read_prompt(prompt: str, *, timeout_seconds: float, secret: bool) -> str | None:
    """Read a console interaction with a wall-clock bound.

    A daemon reader is used because Python's input()/getpass() cannot be
    interrupted portably.  On timeout the caller stops the experiment; the
    daemon reader is never allowed to drive a later send.
    """
    results: queue.Queue[str | None] = queue.Queue(maxsize=1)

    def reader() -> None:
        try:
            value = (
                getpass.getpass(prompt)
                if secret
                else input(prompt)
            )
        except (EOFError, KeyboardInterrupt):
            results.put(None)
        except Exception:
            results.put(None)
        else:
            results.put(value)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    thread.join(timeout_seconds)
    if thread.is_alive():
        return None
    try:
        return results.get_nowait()
    except queue.Empty:
        return None


def _confirm(prompt: str, *, timeout_seconds: float = 120.0) -> bool:
    callbacks = _ui_callbacks()
    if callbacks is not None:
        try:
            return bool(callbacks.confirm(prompt, timeout_seconds))
        except Exception:
            return False
    answer = _read_prompt(prompt, timeout_seconds=timeout_seconds, secret=False)
    if answer is None:
        return False
    return answer.strip() == "YES" or answer.strip().casefold() == "y"


def _lab_credential(kind: AuthPromptKind) -> str:
    callbacks = _ui_callbacks()
    if callbacks is not None:
        provided = callbacks.credential(kind)
        if not provided:
            raise SessionError("credential prompt was cancelled or empty")
        return provided
    if not sys.stdin.isatty():
        raise SessionError("a safe interactive terminal is required for credentials")
    value: str | None
    if kind is AuthPromptKind.USERNAME:
        value = _read_prompt(
            "Console username (不回显控制字符): ",
            timeout_seconds=120.0,
            secret=False,
        )
    elif kind is AuthPromptKind.PASSWORD:
        value = _read_prompt(
            "Console password (不回显): ",
            timeout_seconds=120.0,
            secret=True,
        )
    else:
        value = _read_prompt(
            "Enable password (不回显): ",
            timeout_seconds=120.0,
            secret=True,
        )
    if not value:
        raise SessionError("credential prompt was cancelled or empty")
    return value


class _OperatorGate:
    def __init__(self, authorization: Any, target: LabTarget, counter: list[int]) -> None:
        self.authorization = authorization
        self.target = target
        self.counter = counter
        self.session: ConsoleSession | None = None

    def authorize_open(self, transport: object) -> None:
        self.authorization.authorize_open(transport)

    def authorize_query(self, query: ConsoleQuery) -> None:
        self.authorization.authorize_query(query)
        self.authorization.check_active()
        started = time.monotonic()
        if not _confirm(
            f"确认执行授权只读查询 {query.value}？输入 y 继续: ",
        ):
            raise ConsoleOperatorAbort("operator did not confirm query start")
        operator_elapsed = time.monotonic() - started
        if self.session is not None:
            self.session.extend_discovery_budget(operator_elapsed)
        self.authorization.check_active()
        self.counter[0] += 1

    def authorize_send(
        self, operation: object, text: str, query: ConsoleQuery | None = None,
    ) -> None:
        self.authorization.authorize_send(operation, text, query)

    def check_active(self) -> None:
        self.authorization.check_active()

    def remaining_seconds(self) -> float | None:
        remaining = self.authorization.remaining_seconds()
        return None if remaining is None else float(remaining)


def _redacted_output(output: str) -> str:
    # Never include a complete raw transcript in the report.  The interactive
    # display is deliberately line-limited and redacts identity-like values.
    from event_switch_manager.console.redaction import redact_console_output

    text = redact_console_output(output)
    patterns = (
        (r"(?im)(Processor board ID\s+)(\S+)", r"\1<id>"),
        (r"(?im)(\bSN:\s*)(\S+)", r"\1<id>"),
        (r"(?i)\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b", "<mac>"),
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>"),
        (r"(?im)^(\s*(?:VLAN|vlan)\s+)(\d+)\b", r"\1<vlan>"),
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


def _operator_query_hook(session: ConsoleSession) -> Any:
    def hook(query: ConsoleQuery, result: Any) -> None:
        if session.pending_data():
            raise ConsoleOperatorAbort("operator aborted: late terminal data")
        output = result.output
        print(
            f"\n查询: {query.value}  命令: {result.command}  "
            f"状态: {result.status.value}  耗时: {result.duration_seconds:.3f}s",
        )
        print(
            f"响应: bytes={len(output.encode('ascii', errors='replace'))} "
            f"lines={len(output.splitlines())} "
            f"pagination={result.pagination_events} "
            f"completion={result.completion_status}",
        )
        if result.unknown_fields:
            print("unknown_fields=" + ", ".join(result.unknown_fields))
        print("脱敏结果摘要:")
        print(_redacted_output(output) or "(无可见输出)")

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
        binding_mode=authorization.binding_mode,
        identity_confidence=authorization.identity_confidence,
        bluetooth_direction=authorization.bluetooth_direction,
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


def run_artifact_check() -> int:
    try:
        build = LabBuildMetadata.load()
        build.require_frozen()
    except ArtifactIdentityError as exc:
        print(f"CONSOLE-LAB ARTIFACT CHECK FAIL: {exc}", file=sys.stderr)
        return EXIT_AUTHORIZATION
    print("CONSOLE-LAB ARTIFACT CHECK PASS")
    print(f"exe_sha256={build.artifact_sha256}")
    print(f"git_sha={build.software_git_sha}")
    print("real_serial_opened=NO")
    return EXIT_OK


def run_list_ports(*, as_json: bool) -> int:
    discovery = discover_serial_ports()
    _print_discovery(discovery, as_json=as_json)
    if not discovery.supported:
        return EXIT_DISCOVERY
    return EXIT_OK


def run_experiment(
    args: argparse.Namespace,
    *,
    callbacks: LabUiCallbacks | None = None,
) -> int:
    global _ACTIVE_SESSION
    previous = getattr(_UI_CONTEXT, "callbacks", None)
    _UI_CONTEXT.callbacks = callbacks
    try:
        return _run_experiment(args)
    finally:
        _UI_CONTEXT.callbacks = previous
        with _ACTIVE_LOCK:
            _ACTIVE_SESSION = None


def _run_experiment(args: argparse.Namespace) -> int:
    global _ACTIVE_SESSION
    if not args.target or not args.com:
        print("实验需要 --target 和明确选择的 --com；不会自动扫描并连接其他端口。", file=sys.stderr)
        return EXIT_USAGE
    try:
        target = get_target(args.target)
    except ValueError:
        print("未知实验 target。", file=sys.stderr)
        return EXIT_USAGE
    ttl_seconds = args.ttl_minutes * 60
    manual_bluetooth_binding = bool(
        getattr(args, "manual_bluetooth_binding", False),
    )
    requested_direction = str(
        getattr(args, "bluetooth_direction", "unknown"),
    )
    discovery = discover_serial_ports()
    _print_discovery(discovery, as_json=False)
    try:
        port = _select_port(
            discovery,
            args.com,
            manual_bluetooth_binding=manual_bluetooth_binding,
        )
    except LabAuthorizationError as exc:
        print(f"授权拒绝: {exc}", file=sys.stderr)
        return EXIT_DISCOVERY
    is_bluetooth = port.transport_kind is PortTransportKind.BLUETOOTH_SPP
    binding_direction: str | None = None
    if is_bluetooth:
        if not manual_bluetooth_binding:
            print("拒绝连接：Bluetooth SPP 必须人工绑定。", file=sys.stderr)
            return EXIT_DISCOVERY
        if port.duplicate_identity:
            print("拒绝连接：Bluetooth PnP identity 重复。", file=sys.stderr)
            return EXIT_DISCOVERY
        actual_direction = port.bluetooth_direction.value
        if requested_direction != "unknown" and actual_direction not in {
            "unknown", requested_direction,
        }:
            print("拒绝连接：现场方向与枚举方向不一致。", file=sys.stderr)
            return EXIT_DISCOVERY
        binding_direction = (
            actual_direction
            if actual_direction != "unknown"
            else requested_direction
        )
        print(
            "\nBluetooth SPP 人工绑定："
            f"COM={port.port} direction={actual_direction} "
            f"pnp={sha256_text(port.pnp_instance_identity or '')[:16]}",
        )
        if port.bluetooth_name:
            print(f"已配对设备名称: {port.bluetooth_name}")
        if not _confirm(
            "确认这是正确的蓝牙设备与端口（不是别的 Bluetooth 串口）；"
            "输入 YES 继续: ",
        ):
            print("操作者未确认 Bluetooth 绑定，未打开串口。", file=sys.stderr)
            return EXIT_AUTHORIZATION
    elif port.duplicate_identity or port.identity_quality.value != "stable":
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
    try:
        build = LabBuildMetadata.load()
        build.require_frozen()
    except ArtifactIdentityError as exc:
        print(f"拒绝真实实验：{exc}", file=sys.stderr)
        return EXIT_AUTHORIZATION
    try:
        authorization = issue_authorization(
            target,
            com_endpoint=port.port,
            adapter_identity=port.adapter_identity,
            ttl_seconds=ttl_seconds,
            operator_confirmed=True,
            artifact_sha256=build.artifact_sha256,
            software_git_sha=build.software_git_sha,
            binding_mode=(
                "manual-bluetooth" if is_bluetooth else "stable-usb"
            ),
            identity_confidence=(
                "manual-bound" if is_bluetooth else "stable"
            ),
            bluetooth_direction=(
                binding_direction if is_bluetooth else None
            ),
        )
    except LabAuthorizationError as exc:
        print(f"授权创建失败: {exc}", file=sys.stderr)
        return EXIT_AUTHORIZATION
    transport = AuthorizedSerialTransport(
        authorization,
        parameters=SerialParameters(),
    )
    policy = LiveCompletionPolicy()
    output_dir = Path(args.output_dir) / f"experiment-{authorization.experiment_id[:12]}"
    writer = LabReportWriter(
        output_dir,
        build=build,
        authorization=authorization,
        target=target,
        discovery=discovery,
        port=port,
    )
    confirmations = [0]
    gate = _OperatorGate(authorization, target, confirmations)
    session = ConsoleSession(
        transport,
        lab_gate=gate,
        completion_policy=policy,
        credential_provider=_lab_credential,
        timeout=60.0,
        max_total_response_bytes=512 * 1024,
    )
    gate.session = session
    with _ACTIVE_LOCK:
        _ACTIVE_SESSION = session
    evidence: ConsoleEvidence | None = None
    connection_state = "NOT_ATTEMPTED"
    cleanup_status = "NOT_ATTEMPTED"
    error: str | None = None
    cancelled = False
    wake_sent = False
    wake_confirmed = False
    final_review_confirmed = False
    exit_code = EXIT_OK
    try:
        connection_state = "OPEN_FAILED"
        print(
            "\n被动 attach：不预先索取凭据；仅在设备实际出现认证提示时安全读取。",
        )
        session.open(None, initial_timeout=10.0, allow_silent=True)
        connection_state = "OPENED"
        if session.state is SessionState.AWAITING_PROMPT:
            print("设备当前静默，未返回任何已确认的 EXEC prompt。")
            if not _confirm(
                "确认该设备处于安全、非生产实验状态且无未提交命令；"
                "输入 YES 后最多发送一次 CR 唤醒: ",
            ):
                raise ConsoleOperatorAbort("operator declined the silent-device wake")
            if not _confirm("再次确认发送唯一一次 CR 唤醒？输入 y 继续: "):
                raise ConsoleOperatorAbort("operator did not confirm wake")
            session.wake_once()
            wake_sent = True
            wake_confirmed = True
            session.finish_attach(None, timeout=30.0)
        if not session.is_attached:
            raise SessionError("no reliable EXEC prompt after passive attach/wake")
        if session.state is SessionState.USER_EXEC and _confirm(
            "当前为 USER EXEC；是否需要发送 enable 进入 privileged EXEC？"
            "密码仅在出现提示时安全读取。输入 y 继续: ",
        ):
            session.enable_with_operator()
        print("已获得可靠 EXEC/auth prompt；开始 operator-assisted 只读查询。")
        base_provenance = _lab_provenance(
            authorization,
            target,
            port,
            None,
            operator_confirmed=False,
            cleanup_status="OPENED",
        )
        adapter = CiscoObservationAdapter()
        remaining = authorization.remaining_seconds() or 0.0
        partial_evidence: list[ConsoleEvidence] = []

        def retain_partial(
            observation: Any,
            results: tuple[Any, ...],
        ) -> None:
            partial_evidence.append(
                build_evidence(
                    observation,
                    tuple(results),
                    lab_provenance=base_provenance,
                ),
            )

        evidence = adapter.observe(
            session,
            expected_pid=target.expected_pid,
            expected_release=target.expected_release,
            query_hook=_operator_query_hook(session),
            lab_provenance=base_provenance,
            deadline_seconds=min(290.0, max(10.0, remaining - 1.0)),
            partial_evidence_callback=retain_partial,
        )
        if evidence.completeness is ObservationCompleteness.COMPLETE:
            print("程序完成解析；该结果仍不是硬件认证。")
        else:
            print("观察结果为 PARTIAL/INCOMPLETE；报告记录未知字段，禁止标记 COMPLETE。")
        final_review_confirmed = _confirm(
            "请核对以上全部脱敏查询结果；确认本次只读流程结束时输入 YES: ",
        )
        if not final_review_confirmed:
            cancelled = True
            error = "operator: final result review not confirmed"
            exit_code = EXIT_TRANSPORT
        else:
            if session.pending_data():
                raise ConsoleOperatorAbort("late terminal data during final review")
            authorization.check_active()
    except LabAuthorizationError as exc:
        error = f"authorization: {exc}"
        exit_code = EXIT_AUTHORIZATION
    except IdentityConflict as exc:
        error = f"identity: {exc}"
        exit_code = EXIT_IDENTITY
        if partial_evidence:
            evidence = partial_evidence[0]
    except ConsoleOperatorAbort as exc:
        error = f"operator: {exc}"
        cancelled = True
        exit_code = EXIT_TRANSPORT
    except KeyboardInterrupt:
        session.cancel()
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
        if connection_state == "OPENED":
            try:
                session.close()
                cleanup_status = "RELEASED"
                connection_state = "RELEASED"
            except SessionCleanupError:
                cleanup_status = "CLEANUP_REQUIRED"
                connection_state = "CLEANUP_REQUIRED"
                exit_code = EXIT_CLEANUP
        elif connection_state == "OPEN_FAILED":
            try:
                session.close()
                cleanup_status = "RELEASED"
            except SessionCleanupError:
                cleanup_status = "CLEANUP_REQUIRED"
                exit_code = EXIT_CLEANUP
        authorization.cancel()

    if evidence is not None:
        completed_queries = {
            result.query for result in evidence.query_results
            if result.status.value == "ok"
        }
        queries_complete = completed_queries == set(target.allowed_queries)
        operator_confirmed = (
            confirmations[0] == len(target.allowed_queries)
            and final_review_confirmed
            and cleanup_status == "RELEASED"
            and not cancelled
        )
        provenance = _lab_provenance(
            authorization,
            target,
            port,
            evidence,
            operator_confirmed=operator_confirmed,
            cleanup_status=cleanup_status,
        )
        try:
            validate_lab_provenance(provenance, authorization, target, evidence.observation)
            evidence = _attach_provenance(evidence, provenance)
        except LabEvidenceError as exc:
            error = f"evidence: {exc}"
            exit_code = EXIT_AUTHORIZATION
            evidence = None
            queries_complete = False
    else:
        queries_complete = False
        operator_confirmed = False
    experiment_verdict = (
        "READONLY_QUERIES_COMPLETED"
        if (
            queries_complete
            and cleanup_status == "RELEASED"
            and not error
            and operator_confirmed
        )
        else "FAILED_OR_CANCELLED"
    )
    connection = {
        "status": connection_state,
        "com_endpoint": port.port,
        "opened": session.transport_ever_opened,
        "transport_opened": session.transport_ever_opened,
        "wake_sent": wake_sent,
        "wake_confirmed": wake_confirmed,
        "operator_confirmations": confirmations[0],
        "operator_final_review": final_review_confirmed,
        "readonly_queries_completed": queries_complete,
        "observation_completeness": (
            evidence.completeness.value if evidence is not None else None
        ),
        "experiment_verdict": experiment_verdict,
        "hardware_verdict": "NOT_VERIFIED",
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
            query_results=session.last_results,
        )
    except Exception as exc:
        print(f"报告写入失败: {type(exc).__name__}", file=sys.stderr)
        return EXIT_TRANSPORT
    print(f"\n报告: {output_dir / 'console-lab-report.json'}")
    print(f"摘要: {output_dir / 'console-lab-summary.txt'}")
    print(f"报告指纹: {payload['report_fingerprint']}")
    print(
        f"FINAL: connection={connection_state} cleanup={cleanup_status} "
        f"verdict={experiment_verdict} REAL-SERIAL-COMPLETION=NOT_VERIFIED "
        "DEVICE-WRITES=DISABLED",
    )
    if exit_code == EXIT_OK and cleanup_status != "RELEASED":
        exit_code = EXIT_CLEANUP
    if exit_code == EXIT_OK and not queries_complete:
        exit_code = EXIT_TRANSPORT
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        try:
            return run_self_test()
        except Exception as exc:
            print(f"CONSOLE-LAB SELF-TEST FAIL: {type(exc).__name__}", file=sys.stderr)
            return EXIT_TRANSPORT
    if args.artifact_check:
        return run_artifact_check()
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
    "run_artifact_check",
    "run_experiment",
    "run_list_ports",
    "run_self_test",
]
