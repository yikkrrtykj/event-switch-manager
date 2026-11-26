"""Standalone Tkinter ConsoleLab GUI.

The GUI is a thin operator surface over the same Console Engine, authorization,
send and reporting gates used by the CLI.  It never opens a COM port during
startup, refresh, self-test or artifact check.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import queue
import re
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any

from event_switch_manager.console.discovery import (
    BluetoothDirection,
    PortTransportKind,
    SerialDiscovery,
    SerialPortInfo,
    discover_serial_ports,
)
from event_switch_manager.console.parser import AuthPromptKind

from .cli import (
    EXIT_CLEANUP,
    EXIT_OK,
    cancel_active_experiment,
    cleanup_required,
    last_report_path,
    reset_active_experiment_cancel,
    run_experiment,
)
from .cli import (
    retry_cleanup as retry_console_cleanup,
)
from .reporting import ArtifactIdentityError, LabBuildMetadata
from .targets import LAB_TARGETS, get_target
from .transport import lab_serial_safety_flags


class GuiValidationError(RuntimeError):
    pass


_LOG_REDACTIONS = (
    (re.compile(r"(?i)(usb:[0-9a-f]{4}:[0-9a-f]{4}:)[^\s]+"), r"\1<id>"),
    (re.compile(r"(?i)(usb_serial\s*[=:]\s*)[^\s,;]+"), r"\1<id>"),
    (re.compile(r"(?i)(location\s*[=:]\s*)[^\s,;]+"), r"\1<id>"),
    (re.compile(r"(?i)(serial\s*[=:]\s*)[^\s,;]+"), r"\1<id>"),
    (re.compile(r"(?i)(identity\s*=\s*)BTHENUM[^\s]+"), r"\1<bt-pnp>"),
    (re.compile(r"(?i)(已配对设备名称\s*[:：]\s*).+"), r"\1<redacted>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"(?i)\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b"), "<mac>"),
)


def redact_gui_log(text: str) -> str:
    """Redact identity-like values before they reach the GUI log widget."""
    redacted = text
    for pattern, replacement in _LOG_REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def validate_selection(
    port: SerialPortInfo,
    *,
    non_production_confirmed: bool,
    manual_bluetooth_binding: bool,
    operator_bluetooth_direction: str = "unknown",
) -> None:
    """Pure preflight used by the GUI and its tests; never opens a port."""
    if not non_production_confirmed:
        raise GuiValidationError("必须确认设备为非生产实验设备")
    if port.duplicate_identity:
        raise GuiValidationError("该端口 identity 重复，拒绝连接")
    if port.transport_kind is PortTransportKind.BLUETOOTH_SPP:
        if not manual_bluetooth_binding:
            raise GuiValidationError("Bluetooth SPP 需要勾选人工绑定")
        if not port.pnp_instance_identity:
            raise GuiValidationError("Bluetooth 端口缺少 PnP instance identity，拒绝绑定")
        if operator_bluetooth_direction not in {"incoming", "outgoing"}:
            raise GuiValidationError(
                "Bluetooth 操作者必须明确选择 incoming 或 outgoing 方向",
            )
        if port.bluetooth_direction is BluetoothDirection.UNKNOWN:
            pass
        elif port.bluetooth_direction.value != operator_bluetooth_direction:
            raise GuiValidationError("人工确认方向与枚举方向不一致")
        if port.identity_quality.value not in {"ambiguous", "stable"}:
            raise GuiValidationError("Bluetooth identity quality 不受支持")
        return
    if operator_bluetooth_direction not in {"unknown", "incoming", "outgoing"}:
        raise GuiValidationError("Bluetooth 方向参数无效")
    if port.identity_quality.value != "stable":
        raise GuiValidationError("该端口不是唯一稳定 identity，拒绝连接")


def credential_show_character(kind: AuthPromptKind) -> str:
    """Return the Tk Entry mask; usernames are visible, secrets are masked."""
    return "" if kind is AuthPromptKind.USERNAME else "*"


def _self_test() -> tuple[bool, str]:
    try:
        for target in LAB_TARGETS.values():
            if target.profile.exact_pid != target.expected_pid:
                raise RuntimeError("target profile mismatch")
            if not target.allowed_queries:
                raise RuntimeError("empty query scope")
        flags = lab_serial_safety_flags()
        if flags.get("break_support") != "DISABLED":
            raise RuntimeError("BREAK safety flag mismatch")
        return True, "Self-test PASS；未打开串口"
    except Exception as exc:
        return False, f"Self-test FAIL：{type(exc).__name__}"


def _artifact_check() -> tuple[bool, str]:
    try:
        build = LabBuildMetadata.load()
        build.require_frozen()
        return True, f"Artifact PASS：{build.artifact_sha256[:16]}…"
    except ArtifactIdentityError as exc:
        return False, f"Artifact FAIL：{exc}"
    except Exception as exc:
        return False, f"Artifact FAIL：{type(exc).__name__}"


class _QueueWriter(io.TextIOBase):
    def __init__(self, output: queue.Queue[tuple[str, Any]]) -> None:
        self._output = output

    def write(self, text: str) -> int:
        if text:
            self._output.put(("log", redact_gui_log(text)))
        return len(text)

    def flush(self) -> None:
        return None


class _GuiCallbacks:
    def __init__(self, app: ConsoleLabGui) -> None:
        self.app = app

    def confirm(self, prompt: str, timeout_seconds: float = 120.0) -> bool:
        return self.app.ask_confirmation(prompt, timeout_seconds)

    def credential(self, kind: AuthPromptKind) -> str:
        return self.app.ask_credential(kind)


class ConsoleLabGui:
    def __init__(self, root: tk.Tk, *, smoke: bool = False) -> None:
        self.root = root
        self.smoke = smoke
        self.root.title("Event Switch Manager — Console Lab")
        self.root.geometry("1180x820")
        self.root.minsize(980, 680)
        self.output_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.ui_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.worker: threading.Thread | None = None
        self.refresh_worker: threading.Thread | None = None
        self.worker_result: int | None = None
        self.discovery: SerialDiscovery | None = None
        self.last_output_dir: Path | None = None
        self._closing = False
        self.active_dialog: tk.Toplevel | None = None
        self.artifact_ok, artifact_text = _artifact_check()
        self.self_ok, self_text = _self_test()
        self.artifact_text = artifact_text
        self.self_text = self_text
        self._build()
        self._refresh_status()
        self._poll_output()
        if not smoke:
            self.refresh_ports()

    # ---------- layout ----------
    def _build(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

        status = ttk.LabelFrame(outer, text="Artifact / 安全状态", padding=8)
        status.pack(fill="x")
        self.artifact_label = ttk.Label(status, text="")
        self.artifact_label.pack(anchor="w")
        self.self_label = ttk.Label(status, text="")
        self.self_label.pack(anchor="w")
        ttk.Label(
            status,
            text="产品 LIVE_DEVICE 保持禁用；本工具仅进行受控只读实验。",
        ).pack(anchor="w", pady=(4, 0))

        ports = ttk.LabelFrame(outer, text="串口 / Bluetooth SPP", padding=8)
        ports.pack(fill="x", pady=(8, 0))
        controls = ttk.Frame(ports)
        controls.pack(fill="x")
        ttk.Button(controls, text="刷新串口", command=self.refresh_ports).pack(side="left")
        self.manual_bt_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            controls,
            text="人工绑定选中的 Bluetooth SPP 端口",
            variable=self.manual_bt_var,
            command=self._update_auth_panel,
        ).pack(side="left", padx=12)
        self.port_count_label = ttk.Label(controls, text="未刷新")
        self.port_count_label.pack(side="right")

        columns = ("com", "kind", "direction", "name", "quality", "duplicate")
        self.port_tree = ttk.Treeview(
            ports, columns=columns, show="headings", height=6, selectmode="browse",
        )
        headings = {
            "com": "COM",
            "kind": "类型",
            "direction": "Bluetooth 方向",
            "name": "设备名称（可靠时）",
            "quality": "Identity quality",
            "duplicate": "重复",
        }
        widths = {
            "com": 80, "kind": 130, "direction": 130,
            "name": 220, "quality": 130, "duplicate": 80,
        }
        for column in columns:
            self.port_tree.heading(column, text=headings[column])
            self.port_tree.column(column, width=widths[column], anchor="w")
        self.port_tree.pack(fill="x", pady=6)
        self.port_tree.bind("<<TreeviewSelect>>", lambda _event: self._update_auth_panel())

        target_row = ttk.Frame(outer)
        target_row.pack(fill="x", pady=(8, 0))
        ttk.Label(target_row, text="目标 Profile:").pack(side="left")
        self.target_var = tk.StringVar(value="2960x")
        ttk.Combobox(
            target_row,
            textvariable=self.target_var,
            values=sorted(LAB_TARGETS),
            width=12,
            state="readonly",
        ).pack(side="left", padx=(6, 18))
        ttk.Label(target_row, text="串口: 9600 / 8-N-1 / no flow control").pack(side="left")
        ttk.Label(target_row, text="  Bluetooth 人工方向:").pack(side="left", padx=(18, 0))
        self.bt_direction_var = tk.StringVar(value="unknown")
        self.bt_direction_var.trace_add("write", lambda *_args: self._update_auth_panel())
        ttk.Combobox(
            target_row,
            textvariable=self.bt_direction_var,
            values=("incoming", "outgoing", "unknown"),
            width=10,
            state="readonly",
        ).pack(side="left")
        ttk.Label(target_row, text="  授权时长(分钟):").pack(side="left", padx=(18, 0))
        self.ttl_var = tk.StringVar(value="20")
        ttk.Spinbox(
            target_row, from_=1, to=30, textvariable=self.ttl_var, width=5,
        ).pack(side="left")

        safety = ttk.LabelFrame(outer, text="安全授权", padding=8)
        safety.pack(fill="x", pady=(8, 0))
        self.auth_text = tk.StringVar(value="请选择端口")
        ttk.Label(safety, textvariable=self.auth_text, justify="left").pack(anchor="w")
        self.non_production_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            safety,
            text="我确认该设备无生产业务、无关键链路，并允许本次受控只读实验",
            variable=self.non_production_var,
            command=self._update_auth_panel,
        ).pack(anchor="w", pady=(6, 0))
        self.warning_label = ttk.Label(safety, text="", foreground="#a33")
        self.warning_label.pack(anchor="w")

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=(8, 0))
        self.connect_button = ttk.Button(actions, text="连接并开始实验", command=self.connect)
        self.connect_button.pack(side="left")
        self.cancel_button = ttk.Button(
            actions, text="取消 / 安全断开", command=self.cancel_experiment,
            state="disabled",
        )
        self.cancel_button.pack(side="left", padx=8)
        self.cleanup_button = ttk.Button(
            actions, text="重试 Cleanup", command=self.retry_cleanup,
            state="disabled",
        )
        self.cleanup_button.pack(side="left", padx=8)
        ttk.Button(actions, text="打开报告目录", command=self.open_report_dir).pack(side="left")
        self.progress = ttk.Progressbar(actions, mode="indeterminate", length=180)
        self.progress.pack(side="right")

        info = ttk.LabelFrame(outer, text="设备信息 / 查询摘要", padding=8)
        info.pack(fill="both", expand=False, pady=(8, 0))
        self.info_text = tk.Text(info, height=14, wrap="word", state="disabled")
        self.info_text.pack(fill="both", expand=True)

        logs = ttk.LabelFrame(outer, text="实时脱敏日志", padding=8)
        logs.pack(fill="both", expand=True, pady=(8, 0))
        self.log_text = tk.Text(logs, height=12, wrap="word", state="disabled")
        log_scroll = ttk.Scrollbar(logs, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _refresh_status(self) -> None:
        self.artifact_label.configure(text=self.artifact_text)
        self.self_label.configure(text=self.self_text)
        blocked = cleanup_required()
        if blocked:
            self.connect_button.configure(state="disabled")
            self.cleanup_button.configure(state="normal")
        elif not self.artifact_ok or not self.self_ok:
            self.connect_button.configure(state="disabled")

    # ---------- ports ----------
    def refresh_ports(self) -> None:
        if self.worker is not None and self.worker.is_alive():
            return
        if self.refresh_worker is not None and self.refresh_worker.is_alive():
            return
        self.port_count_label.configure(text="枚举中…（不打开串口）")

        def enumerate_ports() -> None:
            try:
                discovery = discover_serial_ports()
            except Exception:
                discovery = None
            self.output_queue.put(("ports", discovery))

        self.refresh_worker = threading.Thread(
            target=enumerate_ports, name="console-lab-enumeration", daemon=True,
        )
        self.refresh_worker.start()

    def _apply_discovery(self, discovery: SerialDiscovery | None) -> None:
        self.refresh_worker = None
        if discovery is None:
            self.port_count_label.configure(text="枚举失败（未打开串口）")
            return
        self.discovery = discovery
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)
        for port in discovery.ports:
            self.port_tree.insert("", "end", iid=port.port, values=(
                port.port,
                port.transport_kind.value,
                port.bluetooth_direction.value,
                port.bluetooth_name or "-",
                port.identity_quality.value,
                "YES" if port.duplicate_identity else "no",
            ))
        self.port_count_label.configure(
            text=f"{len(discovery.ports)} 个端口，status={discovery.status.value}",
        )
        self._update_auth_panel()

    def selected_port(self) -> SerialPortInfo | None:
        selected = self.port_tree.selection()
        if not selected or self.discovery is None:
            return None
        endpoint = selected[0]
        return next(
            (port for port in self.discovery.ports if port.port == endpoint),
            None,
        )

    def _update_auth_panel(self) -> None:
        port = self.selected_port()
        if port is None:
            self.auth_text.set("请选择端口")
            self.warning_label.configure(text="")
            return
        target = get_target(self.target_var.get())
        direction = port.bluetooth_direction.value
        if port.transport_kind is PortTransportKind.BLUETOOTH_SPP and direction != "unknown":
            self.bt_direction_var.set(direction)
        warning = ""
        if port.transport_kind is PortTransportKind.BLUETOOTH_SPP:
            warning = (
                "Bluetooth SPP identity 为人工绑定、低置信度；"
                "必须确认真实设备、COM 与方向，不把 BTHENUM 当作稳定身份。"
            )
            if not self.manual_bt_var.get():
                warning += " 请勾选“人工绑定”。"
            if direction == "unknown" and self.bt_direction_var.get() == "unknown":
                warning += " 枚举方向 Unknown，必须人工选择 incoming/outgoing。"
        lines = [
            f"选择端口: {port.port}  类型: {port.transport_kind.value}",
            f"枚举 Bluetooth 方向: {direction}",
            f"人工确认 Bluetooth 方向: {self.bt_direction_var.get()}",
            f"已配对名称: {port.bluetooth_name or '不可靠/不可用'}",
            f"Adapter identity: {port.adapter_identity}",
            f"Identity quality: {port.identity_quality.value}  重复: {port.duplicate_identity}",
            f"预期 PID/release: {target.expected_pid} / {target.expected_release}",
            f"允许命令: {', '.join(item.value for item in target.allowed_queries)}",
            f"授权有效期: {self.ttl_var.get()} 分钟",
        ]
        if self.non_production_var.get():
            lines.append("非生产确认: 已勾选")
        self.auth_text.set("\n".join(lines))
        self.warning_label.configure(text=warning)

    # ---------- operator dialogs ----------
    def _run_on_ui(self, callback: Any, timeout_seconds: float) -> Any:
        if self._closing:
            return None
        done = threading.Event()
        result: dict[str, Any] = {}

        def wrapper() -> None:
            try:
                result["value"] = callback()
            except Exception:
                result["value"] = None
            finally:
                done.set()

        self.ui_queue.put(("ui", wrapper))
        if not done.wait(timeout_seconds):
            return None
        return result.get("value")

    def ask_confirmation(self, prompt: str, timeout_seconds: float = 120.0) -> bool:
        def show() -> bool:
            result: dict[str, bool] = {"value": False}
            dialog = tk.Toplevel(self.root)
            self.active_dialog = dialog
            dialog.title("ConsoleLab 安全确认")
            dialog.transient(self.root)
            dialog.grab_set()
            ttk.Label(dialog, text=prompt, wraplength=560, justify="left").pack(
                padx=18, pady=(16, 8),
            )
            buttons = ttk.Frame(dialog)
            buttons.pack(pady=(0, 14))

            def accept() -> None:
                result["value"] = True
                dialog.destroy()

            def reject() -> None:
                result["value"] = False
                dialog.destroy()

            ttk.Button(buttons, text="确认 / YES", command=accept).pack(side="left", padx=5)
            ttk.Button(buttons, text="取消", command=reject).pack(side="left", padx=5)
            dialog.protocol("WM_DELETE_WINDOW", reject)
            dialog.bind("<Return>", lambda _event: accept())
            dialog.bind("<Escape>", lambda _event: reject())
            dialog.after(int(max(1.0, timeout_seconds) * 1000), reject)
            dialog.wait_window()
            self.active_dialog = None
            return bool(result["value"])

        return bool(self._run_on_ui(show, timeout_seconds + 2))

    def ask_credential(self, kind: AuthPromptKind) -> str:
        def show() -> str:
            result: dict[str, str] = {}
            dialog = tk.Toplevel(self.root)
            self.active_dialog = dialog
            dialog.title("设备认证（凭据不保存）")
            dialog.transient(self.root)
            dialog.grab_set()
            label = {
                AuthPromptKind.USERNAME: "Console username",
                AuthPromptKind.PASSWORD: "Console password（不回显）",
                AuthPromptKind.ENABLE_PASSWORD: "Enable password（不回显）",
            }.get(kind, "Console credential（不回显）")
            ttk.Label(dialog, text=label).pack(padx=16, pady=(14, 4))
            value = tk.StringVar()
            entry = ttk.Entry(
                dialog,
                textvariable=value,
                show=credential_show_character(kind),
                width=34,
            )
            entry.pack(padx=16, pady=4)
            entry.focus_set()

            def accept() -> None:
                result["value"] = value.get()
                dialog.destroy()

            def cancel() -> None:
                result["value"] = ""
                dialog.destroy()

            buttons = ttk.Frame(dialog)
            buttons.pack(pady=10)
            ttk.Button(buttons, text="确定", command=accept).pack(side="left", padx=4)
            ttk.Button(buttons, text="取消", command=cancel).pack(side="left", padx=4)
            dialog.protocol("WM_DELETE_WINDOW", cancel)
            dialog.bind("<Return>", lambda _event: accept())
            dialog.bind("<Escape>", lambda _event: cancel())
            dialog.after(120_000, cancel)
            dialog.wait_window()
            self.active_dialog = None
            return result.get("value", "")

        return str(self._run_on_ui(show, 120) or "")

    # ---------- experiment ----------
    def connect(self) -> None:
        if self.worker is not None and self.worker.is_alive():
            return
        if cleanup_required():
            messagebox.showerror(
                "ConsoleLab",
                "上一会话 cleanup 未确认释放；请先“重试 Cleanup”，禁止新会话接管。",
                parent=self.root,
            )
            return
        if not self.artifact_ok or not self.self_ok:
            messagebox.showerror("ConsoleLab", "Artifact 或 self-test 未通过。", parent=self.root)
            return
        port = self.selected_port()
        if port is None:
            messagebox.showerror("ConsoleLab", "请先选择端口。", parent=self.root)
            return
        target = get_target(self.target_var.get())
        manual_bt = bool(self.manual_bt_var.get())
        operator_direction = self.bt_direction_var.get()
        try:
            validate_selection(
                port,
                non_production_confirmed=self.non_production_var.get(),
                manual_bluetooth_binding=manual_bt,
                operator_bluetooth_direction=operator_direction,
            )
        except GuiValidationError as exc:
            messagebox.showerror("ConsoleLab 安全门禁", str(exc), parent=self.root)
            return
        try:
            ttl = float(self.ttl_var.get())
        except ValueError:
            messagebox.showerror("ConsoleLab", "授权时长必须是数字。", parent=self.root)
            return
        if not 0 < ttl <= 30:
            messagebox.showerror("ConsoleLab", "授权时长必须在 1–30 分钟。", parent=self.root)
            return
        if port.transport_kind is PortTransportKind.BLUETOOTH_SPP:
            if not messagebox.askyesno(
                "Bluetooth 人工绑定",
                (
                    "你确认这是正确的 Bluetooth 设备与端口？\n\n"
                    f"COM: {port.port}\n"
                    f"枚举方向: {port.bluetooth_direction.value}\n"
                    f"人工确认方向: {operator_direction}\n"
                    f"identity: {port.adapter_identity}\n\n"
                    "人工绑定只对本次会话有效，不作为稳定 USB 身份。"
                ),
                parent=self.root,
            ):
                return
        self.last_output_dir = Path("console-lab-output")
        args = argparse.Namespace(
            target=target.key,
            com=port.port,
            ttl_minutes=ttl,
            output_dir=str(self.last_output_dir),
            manual_bluetooth_binding=manual_bt,
            bluetooth_direction=(
                operator_direction
                if port.transport_kind is PortTransportKind.BLUETOOTH_SPP
                else "unknown"
            ),
        )
        reset_active_experiment_cancel()
        self.progress.start(12)
        self.connect_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self._append_log(f"\n=== 开始 {target.expected_pid} / {port.port} ===\n")
        callbacks = _GuiCallbacks(self)

        def worker() -> None:
            writer = _QueueWriter(self.output_queue)
            try:
                with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
                    code = run_experiment(args, callbacks=callbacks)
            except Exception as exc:
                self.output_queue.put(("log", f"\nGUI worker error: {type(exc).__name__}\n"))
                code = 6
            self.output_queue.put(("done", code))

        self.worker = threading.Thread(target=worker, name="console-lab-worker", daemon=True)
        self.worker.start()

    def cancel_experiment(self) -> None:
        self._append_log("\n=== 操作者请求取消；最多一次 clean-up 重试 ===\n")
        cancel_active_experiment()
        self.cancel_button.configure(state="disabled")

    def open_report_dir(self) -> None:
        directory = self.last_output_dir
        if directory is None or not directory.exists():
            directory = Path("console-lab-output")
        if not directory.exists():
            messagebox.showinfo("ConsoleLab", "尚未生成报告目录。", parent=self.root)
            return
        try:
            opener = getattr(os, "startfile", None)
            if not callable(opener):
                raise OSError("directory opener is unavailable")
            opener(str(directory))
        except Exception as exc:
            messagebox.showerror(
                "ConsoleLab",
                f"无法打开目录：{type(exc).__name__}",
                parent=self.root,
            )

    def _append_log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _append_info(self, text: str) -> None:
        self.info_text.configure(state="normal")
        self.info_text.delete("1.0", "end")
        self.info_text.insert("1.0", text)
        self.info_text.configure(state="disabled")

    def _poll_output(self) -> None:
        try:
            while True:
                kind, payload = self.output_queue.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "ports":
                    self._apply_discovery(payload)
                elif kind == "done":
                    self._finish_worker(int(payload))
                elif kind == "cleanup_result":
                    self._finish_cleanup(bool(payload))
        except queue.Empty:
            pass
        try:
            while True:
                kind, callback = self.ui_queue.get_nowait()
                if kind == "ui" and callable(callback):
                    callback()
        except queue.Empty:
            pass
        try:
            if self.root.winfo_exists():
                self.root.after(100, self._poll_output)
        except tk.TclError:
            return

    def _finish_worker(self, code: int) -> None:
        self.worker_result = code
        self.worker = None
        self.progress.stop()
        self.cancel_button.configure(state="disabled")
        self._append_log(f"\n=== 实验结束 exit={code} ===\n")
        blocked = code == EXIT_CLEANUP or cleanup_required()
        if blocked:
            self._append_log("=== cleanup 未确认：CLEANUP_REQUIRED，未声明端口已释放 ===\n")
            self._closing = False
            self.connect_button.configure(state="disabled")
            self.cleanup_button.configure(state="normal")
            try:
                messagebox.showwarning(
                    "ConsoleLab cleanup",
                    "Cleanup 未确认；禁止新会话。请使用“重试 Cleanup”。",
                    parent=self.root,
                )
            except tk.TclError:
                pass
        self._load_completed_report(last_report_path())
        reset_active_experiment_cancel()
        if self._closing:
            self.root.after(50, self._destroy)
            return
        if not blocked:
            self.connect_button.configure(
                state="normal" if (self.artifact_ok and self.self_ok) else "disabled",
            )

    def retry_cleanup(self) -> None:
        if self.worker is not None and self.worker.is_alive():
            return
        self.cleanup_button.configure(state="disabled")
        self._append_log("\n=== 重试 Cleanup（不打开新串口） ===\n")

        def worker() -> None:
            ok = retry_console_cleanup()
            self.output_queue.put(("cleanup_result", ok))

        threading.Thread(
            target=worker, name="console-lab-cleanup-retry", daemon=True,
        ).start()

    def _finish_cleanup(self, ok: bool) -> None:
        if ok:
            self._append_log("=== Cleanup 已确认释放；此前会话不可恢复 ===\n")
            self.connect_button.configure(
                state="normal" if (self.artifact_ok and self.self_ok) else "disabled",
            )
            self.cleanup_button.configure(state="disabled")
            try:
                messagebox.showinfo(
                    "ConsoleLab cleanup",
                    "Cleanup 已确认释放；现在可以重新选择端口。",
                    parent=self.root,
                )
            except tk.TclError:
                pass
            return
        self._append_log("=== Cleanup 仍失败；保持 CLEANUP_REQUIRED ===\n")
        self.connect_button.configure(state="disabled")
        self.cleanup_button.configure(state="normal")
        try:
            messagebox.showwarning(
                "ConsoleLab cleanup",
                "Cleanup 仍失败；端口未确认释放，禁止新会话。",
                parent=self.root,
            )
        except tk.TclError:
            pass

    def _load_completed_report(self, report_path: Path | None) -> None:
        if report_path is None:
            self._append_info("本次实验未生成报告（可能在打开串口前取消或失败）。")
            return
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._append_info("本次实验报告读取失败。")
            return
        observation = payload.get("observation") or {}
        outcome = payload.get("outcome") or {}
        lines = [
            f"PID: {observation.get('exact_pid')}",
            f"IOS: {observation.get('software_version')}",
            f"License: {json.dumps(observation.get('license'), ensure_ascii=False)}",
            f"Stack: {json.dumps(observation.get('stack'), ensure_ascii=False)}",
            f"Interfaces: {json.dumps(observation.get('interfaces'), ensure_ascii=False)}",
            f"Boot: {json.dumps(observation.get('boot'), ensure_ascii=False)}",
            f"Storage: {json.dumps(observation.get('storage'), ensure_ascii=False)}",
            f"Unknown: {', '.join(observation.get('unknown_fields', [])) or '无'}",
            f"Completeness: {observation.get('completeness')}",
            f"Experiment verdict: {outcome.get('experiment_verdict')}",
            f"Cleanup: {outcome.get('cleanup_status')}",
            f"Hardware verdict: {outcome.get('hardware_verdict')}",
        ]
        self._append_info("\n".join(lines))

    def smoke_close(self, report_path: Path | None = None) -> None:
        payload = {
            "status": "passed" if (self.artifact_ok and self.self_ok) else "failed",
            "artifact_check": self.artifact_ok,
            "self_test": self.self_ok,
            "real_serial_opened": "NO",
            "com_enumeration": "SKIPPED_IN_SMOKE",
        }
        if report_path is not None:
            try:
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(
                    json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
            except OSError:
                payload["status"] = "failed"
        self.root.destroy()

    def _destroy(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def _close_active_dialog(self) -> None:
        dialog = self.active_dialog
        if dialog is not None:
            try:
                dialog.destroy()
            except tk.TclError:
                pass
            self.active_dialog = None

    def on_close(self) -> None:
        if self.worker is not None and self.worker.is_alive():
            if not messagebox.askyesno(
                "ConsoleLab",
                "实验仍在进行。取消并安全关闭窗口？\n"
                "窗口会等待 worker 报告 cleanup 后再关闭。",
                parent=self.root,
            ):
                return
            self._closing = True
            self.connect_button.configure(state="disabled")
            self.cancel_button.configure(state="disabled")
            self._append_log("\n=== 关闭窗口：发送取消请求并等待 cleanup ===\n")
            self._close_active_dialog()
            cancel_active_experiment()
            self.progress.start(12)
            return
        if cleanup_required():
            if messagebox.askyesno(
                "ConsoleLab cleanup",
                "上一会话 cleanup 未确认释放。现在重试 Cleanup？",
                parent=self.root,
            ):
                if retry_console_cleanup():
                    self._destroy()
                else:
                    messagebox.showwarning(
                        "ConsoleLab cleanup",
                        "Cleanup 仍失败；端口未确认释放，窗口保持打开。",
                        parent=self.root,
                    )
            else:
                messagebox.showwarning(
                    "ConsoleLab cleanup",
                    "Cleanup 未确认；不会声明安全关闭。请先重试 Cleanup。",
                    parent=self.root,
                )
            return
        self._destroy()


def _ensure_windowed_streams() -> None:
    """Windowed PyInstaller has no stdin/stdout/stderr; never let those break."""
    for name in ("stdin", "stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "r+" if name == "stdin" else "w"))


def main(argv: list[str] | None = None) -> int:
    _ensure_windowed_streams()
    args = list(sys.argv[1:] if argv is None else argv)
    smoke = "--gui-smoke" in args
    report_path: Path | None = None
    if "--gui-smoke-report" in args:
        index = args.index("--gui-smoke-report")
        if index + 1 < len(args):
            report_path = Path(args[index + 1])
    try:
        root = tk.Tk()
    except tk.TclError:
        if report_path is not None:
            try:
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(
                    json.dumps({"status": "failed", "reason": "tk-startup"}) + "\n",
                    encoding="utf-8",
                )
            except OSError:
                pass
        return 6
    app = ConsoleLabGui(root, smoke=smoke)
    if smoke:
        if app.artifact_ok and app.self_ok:
            root.after(500, lambda: app.smoke_close(report_path))
        else:
            root.after(100, lambda: app.smoke_close(report_path))
    root.mainloop()
    if smoke and not (app.artifact_ok and app.self_ok):
        return 6
    return EXIT_OK


__all__ = [
    "ConsoleLabGui",
    "GuiValidationError",
    "credential_show_character",
    "main",
    "redact_gui_log",
    "validate_selection",
]
