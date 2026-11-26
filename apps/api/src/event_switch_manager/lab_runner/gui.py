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
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any

from event_switch_manager.console.discovery import (
    PortTransportKind,
    SerialDiscovery,
    SerialPortInfo,
    discover_serial_ports,
)
from event_switch_manager.console.parser import AuthPromptKind

from .cli import (
    EXIT_OK,
    cancel_active_experiment,
    run_experiment,
)
from .reporting import ArtifactIdentityError, LabBuildMetadata
from .targets import LAB_TARGETS, get_target
from .transport import lab_serial_safety_flags


class GuiValidationError(RuntimeError):
    pass


def validate_selection(
    port: SerialPortInfo,
    *,
    non_production_confirmed: bool,
    manual_bluetooth_binding: bool,
) -> None:
    """Pure preflight used by the GUI and its tests; never opens a port."""
    if not non_production_confirmed:
        raise GuiValidationError("必须确认设备为非生产实验设备")
    if port.duplicate_identity:
        raise GuiValidationError("该端口 identity 重复，拒绝连接")
    if port.transport_kind is PortTransportKind.BLUETOOTH_SPP:
        if not manual_bluetooth_binding:
            raise GuiValidationError("Bluetooth SPP 需要勾选人工绑定")
        if port.identity_quality.value not in {"ambiguous", "stable"}:
            raise GuiValidationError("Bluetooth identity quality 不受支持")
        return
    if port.identity_quality.value != "stable":
        raise GuiValidationError("该端口不是唯一稳定 identity，拒绝连接")


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
            self._output.put(("log", text))
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
        self.worker: threading.Thread | None = None
        self.worker_result: int | None = None
        self.discovery: SerialDiscovery | None = None
        self.last_output_dir: Path | None = None
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
        if not self.artifact_ok or not self.self_ok:
            self.connect_button.configure(state="disabled")

    # ---------- ports ----------
    def refresh_ports(self) -> None:
        if self.worker is not None and self.worker.is_alive():
            return
        self.discovery = discover_serial_ports()
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)
        for port in self.discovery.ports:
            self.port_tree.insert("", "end", iid=port.port, values=(
                port.port,
                port.transport_kind.value,
                port.bluetooth_direction.value,
                port.bluetooth_name or "-",
                port.identity_quality.value,
                "YES" if port.duplicate_identity else "no",
            ))
        self.port_count_label.configure(
            text=f"{len(self.discovery.ports)} 个端口，status={self.discovery.status.value}",
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
        warning = ""
        if port.transport_kind is PortTransportKind.BLUETOOTH_SPP:
            warning = (
                "Bluetooth SPP identity 为人工绑定、低置信度；"
                "必须确认真实设备、COM 与方向，不把 BTHENUM 当作稳定身份。"
            )
            if not self.manual_bt_var.get():
                warning += " 请勾选“人工绑定”。"
        lines = [
            f"选择端口: {port.port}  类型: {port.transport_kind.value}",
            f"Bluetooth 方向: {direction}  已配对名称: {port.bluetooth_name or '不可靠/不可用'}",
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
    def ask_confirmation(self, prompt: str, timeout_seconds: float = 120.0) -> bool:
        result: dict[str, bool] = {}
        done = threading.Event()

        def show() -> None:
            try:
                result["value"] = bool(
                    messagebox.askyesno("ConsoleLab 安全确认", prompt, parent=self.root),
                )
            except tk.TclError:
                result["value"] = False
            finally:
                done.set()

        try:
            self.root.after(0, show)
        except tk.TclError:
            return False
        if not done.wait(timeout_seconds):
            return False
        return result.get("value", False)

    def ask_credential(self, kind: AuthPromptKind) -> str:
        result: dict[str, str] = {}
        done = threading.Event()

        def show() -> None:
            dialog = tk.Toplevel(self.root)
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
                dialog, textvariable=value, show="*" if kind is not AuthPromptKind.USERNAME else "",
                width=34,
            )
            entry.pack(padx=16, pady=4)
            entry.focus_set()

            def accept() -> None:
                result["value"] = value.get()
                dialog.destroy()
                done.set()

            def cancel() -> None:
                result["value"] = ""
                dialog.destroy()
                done.set()

            buttons = ttk.Frame(dialog)
            buttons.pack(pady=10)
            ttk.Button(buttons, text="确定", command=accept).pack(side="left", padx=4)
            ttk.Button(buttons, text="取消", command=cancel).pack(side="left", padx=4)
            dialog.protocol("WM_DELETE_WINDOW", cancel)
            dialog.bind("<Return>", lambda _event: accept())
            dialog.bind("<Escape>", lambda _event: cancel())

        try:
            self.root.after(0, show)
        except tk.TclError:
            return ""
        if not done.wait(120):
            return ""
        return result.get("value", "")

    # ---------- experiment ----------
    def connect(self) -> None:
        if self.worker is not None and self.worker.is_alive():
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
        try:
            validate_selection(
                port,
                non_production_confirmed=self.non_production_var.get(),
                manual_bluetooth_binding=manual_bt,
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
                    f"COM: {port.port}\n方向: {port.bluetooth_direction.value}\n"
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
                port.bluetooth_direction.value
                if port.transport_kind is PortTransportKind.BLUETOOTH_SPP
                else "unknown"
            ),
        )
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
            os.startfile(str(directory))
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
                elif kind == "done":
                    self._finish_worker(int(payload))
        except queue.Empty:
            pass
        if self.root.winfo_exists():
            self.root.after(100, self._poll_output)

    def _finish_worker(self, code: int) -> None:
        self.worker_result = code
        self.worker = None
        self.progress.stop()
        self.cancel_button.configure(state="disabled")
        self.connect_button.configure(
            state="normal" if (self.artifact_ok and self.self_ok) else "disabled",
        )
        self._append_log(f"\n=== 实验结束 exit={code} ===\n")
        self._load_latest_report()

    def _load_latest_report(self) -> None:
        base = self.last_output_dir or Path("console-lab-output")
        reports = sorted(base.glob("experiment-*/console-lab-report.json"))
        if not reports:
            return
        try:
            payload = json.loads(reports[-1].read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._append_info("报告读取失败。")
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

    def smoke_close(self) -> None:
        if self.artifact_ok and self.self_ok:
            print("CONSOLE-LAB GUI SMOKE PASS")
            print("real_serial_opened=NO")
            print("com_enumeration=SKIPPED_IN_SMOKE")
        self.root.destroy()

    def on_close(self) -> None:
        if self.worker is not None and self.worker.is_alive():
            if not messagebox.askyesno(
                "ConsoleLab",
                "实验仍在进行。取消并安全关闭窗口？",
                parent=self.root,
            ):
                return
            cancel_active_experiment()
            self.worker.join(timeout=5)
            if self.worker is not None and self.worker.is_alive():
                messagebox.showwarning(
                    "ConsoleLab",
                    "取消请求已发送，但 worker 尚未结束；关闭窗口不会声明 cleanup 已成功。",
                    parent=self.root,
                )
        self.root.destroy()


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    smoke = "--gui-smoke" in args
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"CONSOLE-LAB GUI FAIL: {type(exc).__name__}", file=sys.stderr)
        return 6
    app = ConsoleLabGui(root, smoke=smoke)
    if smoke:
        if app.artifact_ok and app.self_ok:
            root.after(500, app.smoke_close)
        else:
            root.after(100, root.destroy)
    root.mainloop()
    if smoke and not (app.artifact_ok and app.self_ok):
        return 6
    return EXIT_OK


__all__ = [
    "ConsoleLabGui",
    "GuiValidationError",
    "main",
    "validate_selection",
]
