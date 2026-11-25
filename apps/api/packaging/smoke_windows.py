from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ORIGIN = ""


def _request(
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float = 5,
) -> tuple[Any, dict[str, str]]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        ORIGIN + path,
        data=data,
        method=method,
        headers={
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if data is not None else {}),
            **({"Origin": ORIGIN} if data is not None else {}),
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read()
        content_type = response.headers.get("content-type", "")
        parsed = json.loads(body) if "json" in content_type else body.decode("utf-8")
        return parsed, {key.lower(): value for key, value in response.headers.items()}


def _wait_health(process: subprocess.Popen[bytes], timeout: float = 45) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"EXE exited before health check: {process.returncode}")
        try:
            data, _ = _request("/api/v1/health", timeout=1)
            if data.get("status") == "ok":
                return
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"health check timed out: {last_error}")


def _port_free(port: int) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _wait_port_free(port: int, timeout: float = 15) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_free(port):
            return True
        time.sleep(0.25)
    return False


def _listener_addresses(port: int) -> list[str]:
    command = (
        f"Get-NetTCPConnection -LocalPort {port} -State Listen | "
        "Select-Object -ExpandProperty LocalAddress"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=15, check=False,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _shutdown_gracefully(
    process: subprocess.Popen[bytes],
    log: Path,
    initial_children: list[int],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "shutdown_method": "windows-console-ctrl-c",
        "pid": process.pid,
        "forced_termination_used": False,
        "graceful_shutdown_observed": False,
        "process_tree_exited": False,
    }
    if process.poll() is not None:
        result["exit_code"] = int(process.returncode or 0)
        result["error"] = "process exited before Ctrl+C"
        return result
    helper = _signal_ctrl_c(process.pid)
    result["ctrl_c_helper"] = helper
    if not helper.get("sent") or helper.get("helper_exit_code") != 0:
        result["error"] = "isolated console Ctrl+C delivery failed"
        process.kill()
        process.wait(timeout=10)
        result["forced_termination_used"] = True
        result["exit_code"] = int(process.returncode or 0)
        result["process_tree_exited"] = _process_tree_exited(
            process.pid, initial_children,
        )
        return result
    try:
        exit_code = int(process.wait(timeout=20))
    except subprocess.TimeoutExpired:
        result["error"] = "Ctrl+C shutdown timed out"
        process.kill()
        exit_code = int(process.wait(timeout=10))
        result["forced_termination_used"] = True
    result["exit_code"] = exit_code
    result["process_tree_exited"] = _process_tree_exited(
        process.pid, initial_children,
    )
    text = log.read_text(errors="replace") if log.is_file() else ""
    result["graceful_shutdown_observed"] = (
        "Shutting down" in text and "Application shutdown complete" in text
    )
    result["log_tail"] = text[-1000:]
    return result


def _start(
    exe: Path, workspace: Path, cwd_name: str, port: int,
    log: Path, use_default_database: bool = False,
) -> subprocess.Popen[bytes]:
    cwd = workspace / cwd_name
    cwd.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    env["PATH"] = str(system_root / "System32") + os.pathsep + str(system_root)
    for name in ("PYTHONHOME", "PYTHONPATH", "NODE_PATH"):
        env.pop(name, None)
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["HTTP_PROXY"] = "http://127.0.0.1:9"
    env["HTTPS_PROXY"] = "http://127.0.0.1:9"
    log.parent.mkdir(parents=True, exist_ok=True)
    output = log.open("wb")
    args = [str(exe), "--no-browser"]
    if port != 8765:
        args.extend(["--port", str(port)])
    if not use_default_database:
        database = workspace / "UserData" / "esm.sqlite3"
        database.parent.mkdir(parents=True, exist_ok=True)
        args.extend(["--database", str(database)])
    # A dedicated console makes CTRL_C_EVENT group 0 target only this server
    # (plus the short-lived helper that ignores the event).
    flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    return subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        stdout=output,
        stderr=subprocess.STDOUT,
        creationflags=flags,
    )


def _powershell(command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=15, check=False,
    )


def _classify_runtime_modules(
    module_paths: list[str], package: Path,
) -> dict[str, Any]:
    package = package.resolve()
    modules: list[Path] = []
    for raw in module_paths:
        value = raw.strip()
        if not value:
            continue
        try:
            modules.append(Path(value).resolve())
        except OSError:
            continue
    python_modules = [
        path for path in modules
        if path.name.casefold().startswith("python")
        and path.suffix.casefold() in {".dll", ".exe"}
    ]
    node_modules = [
        path for path in modules
        if path.name.casefold() in {"node.exe", "node.dll"}
    ]
    package_python = [
        path for path in python_modules
        if path.is_relative_to(package)
    ]
    host_modules = [
        path for path in (*python_modules, *node_modules)
        if not path.is_relative_to(package)
    ]
    return {
        "module_count": len(modules),
        "python_modules": [str(path) for path in python_modules],
        "package_python_modules": [str(path) for path in package_python],
        "node_modules": [str(path) for path in node_modules],
        "host_runtime_modules": [str(path) for path in host_modules],
        "ok": bool(modules) and bool(package_python) and not host_modules,
    }


def _inspect_runtime_modules(
    process: subprocess.Popen[bytes],
    package: Path,
    runner: Any = None,
) -> dict[str, Any]:
    if process.poll() is not None:
        raise RuntimeError("runtime module inspection target is not running")
    command = (
        f"Get-Process -Id {process.pid} | "
        "Select-Object -ExpandProperty Modules | "
        "Select-Object -ExpandProperty FileName"
    )
    completed = (runner or _powershell)(command)
    if completed.returncode != 0:
        raise RuntimeError(
            "runtime module enumeration failed with exit "
            f"{completed.returncode}: {completed.stderr.strip()}"
        )
    paths = [line for line in completed.stdout.splitlines() if line.strip()]
    if not paths:
        raise RuntimeError("runtime module enumeration returned no modules")
    evidence = _classify_runtime_modules(paths, package)
    if not evidence["ok"]:
        raise RuntimeError(f"host runtime module check failed: {evidence}")
    return evidence


def _process_snapshot(pid: int) -> dict[str, Any]:
    command = (
        f"$target=@(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}' | "
        "Select-Object ProcessId,ParentProcessId,Name,CreationDate,"
        "ExecutablePath,CommandLine); "
        f"$children=@(Get-CimInstance Win32_Process -Filter 'ParentProcessId={pid}' | "
        "Select-Object ProcessId,ParentProcessId,Name,CreationDate,"
        "ExecutablePath,CommandLine); "
        "[pscustomobject]@{target=$target;children=$children} | "
        "ConvertTo-Json -Depth 4 -Compress"
    )
    completed = _powershell(command)
    if completed.returncode != 0:
        raise RuntimeError(
            f"process enumeration failed for {pid}: {completed.stderr.strip()}"
        )
    text = completed.stdout.strip()
    if not text:
        raise RuntimeError(f"process enumeration returned no data for {pid}")
    data = json.loads(text)
    target = data.get("target") or []
    children = data.get("children") or []
    if isinstance(target, dict):
        target = [target]
    if isinstance(children, dict):
        children = [children]
    return {"target": target, "children": children}


def _process_tree_exited(pid: int, initial_children: list[int]) -> bool:
    try:
        snapshot = _process_snapshot(pid)
        if snapshot["target"]:
            return False
        for child in initial_children:
            if _process_snapshot(child)["target"]:
                return False
        return True
    except Exception:
        return False


def _port_owner(port: int) -> list[int]:
    command = (
        f"Get-NetTCPConnection -LocalPort {port} -State Listen "
        "-ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty OwningProcess; exit 0"
    )
    completed = _powershell(command)
    if completed.returncode != 0:
        raise RuntimeError(f"port owner enumeration failed: {completed.stderr.strip()}")
    return [
        int(line.strip())
        for line in completed.stdout.splitlines()
        if line.strip().isdigit()
    ]


def _send_ctrl_c(pid: int) -> int:
    """Helper mode: send CTRL_C to the isolated console of the target PID."""
    import signal

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleCtrlHandler.argtypes = [ctypes.c_void_p, ctypes.c_bool]
    kernel32.SetConsoleCtrlHandler.restype = ctypes.c_bool
    kernel32.AttachConsole.argtypes = [ctypes.c_uint32]
    kernel32.AttachConsole.restype = ctypes.c_bool
    kernel32.FreeConsole.restype = ctypes.c_bool
    kernel32.GenerateConsoleCtrlEvent.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    kernel32.GenerateConsoleCtrlEvent.restype = ctypes.c_bool
    ignored = bool(kernel32.SetConsoleCtrlHandler(None, True))
    freed = bool(kernel32.FreeConsole())
    attached = bool(kernel32.AttachConsole(pid))
    sent = False
    if attached:
        # CTRL_C_EVENT must use process group 0: all processes attached to this
        # dedicated console. The helper itself ignores the event.
        sent = bool(kernel32.GenerateConsoleCtrlEvent(0, 0))
    # Do not restore the old handler: the event is delivered asynchronously,
    # and restoring it would make this helper terminate after successfully
    # delivering Ctrl+C to the target console.
    print(json.dumps({
        "pid": pid,
        "helper_pid": os.getpid(),
        "ignored": ignored,
        "freed": freed,
        "attached": attached,
        "sent": sent,
    }), flush=True)
    os._exit(0 if attached and sent else 2)


def _signal_ctrl_c(pid: int) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--send-ctrl-c", str(pid)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    try:
        evidence = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        evidence = {
            "pid": pid,
            "attached": False,
            "sent": False,
            "error": completed.stderr[-500:],
        }
    evidence["helper_exit_code"] = completed.returncode
    return evidence


def _integrity(path: Path) -> str:
    with sqlite3.connect(path) as connection:
        row = connection.execute("PRAGMA integrity_check").fetchone()
    return "ok" if row is not None and row[0] == "ok" else str(row)


def _make_plan(event_id: str) -> tuple[dict[str, Any], str]:
    tests = Path(__file__).resolve().parents[1] / "tests"
    source = Path(__file__).resolve().parents[1] / "src"
    for path in (str(tests), str(source)):
        if path not in sys.path:
            sys.path.insert(0, path)
    from layer3_helpers import make_l3_plan

    plan = make_l3_plan(event_id, static_route_count=1)
    core = next(item for item in plan["assignments"] if item["hostname"] == "L3-Core")
    core["management_ip"] = "192.168.10.3"
    core["management_domain"] = "example.com"
    core["credential_reference"] = "credref:" + event_id + ":netops"
    return plan, str(core["id"])


def _database_path(workspace: Path, args: argparse.Namespace) -> Path:
    if args.use_default_database:
        return Path(os.environ.get("LOCALAPPDATA", "")) / "EventSwitchManager" / "esm.sqlite3"
    return workspace / "UserData" / "esm.sqlite3"


def _capture_process(
    report: dict[str, Any], process: subprocess.Popen[bytes], port: int,
    key: str,
) -> list[int]:
    snapshot = _process_snapshot(process.pid)
    target = snapshot["target"]
    if len(target) != 1:
        raise RuntimeError(f"target process enumeration mismatch: {snapshot}")
    children = [
        int(item["ProcessId"])
        for item in snapshot["children"]
        if isinstance(item, dict) and item.get("ProcessId") is not None
    ]
    owners = _port_owner(port)
    if owners != [process.pid]:
        raise RuntimeError(
            f"port owner mismatch for {key}: expected {process.pid}, got {owners}"
        )
    report[key] = {
        "target": target[0],
        "children": snapshot["children"],
        "port_owner": owners,
    }
    return children


def _record_normal_shutdown(
    report: dict[str, Any], key: str, process: subprocess.Popen[bytes],
    log: Path, port: int, initial_children: list[int],
) -> None:
    shutdown = _shutdown_gracefully(process, log, initial_children)
    released = _wait_port_free(port)
    shutdown["port_released"] = released
    shutdown["port_owner_after"] = _port_owner(port)
    report[key] = shutdown
    if (
        shutdown["forced_termination_used"]
        or not shutdown["graceful_shutdown_observed"]
        or shutdown.get("exit_code") != 0
        or not shutdown["process_tree_exited"]
        or not released
        or shutdown["port_owner_after"]
    ):
        raise RuntimeError(f"{key} was not a verified graceful shutdown: {shutdown}")
    report["checks"].append(key.replace("_shutdown", "").replace("_", "-") + "-shutdown")


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test the Windows portable EXE")
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--build-record", type=Path)
    parser.add_argument("--zip", type=Path)
    parser.add_argument("--expected-git-sha")
    parser.add_argument(
        "--use-default-database", action="store_true",
        help="Use the normal LOCALAPPDATA database path (CI fresh-user acceptance)",
    )
    args = parser.parse_args()
    global ORIGIN
    args.workspace.mkdir(parents=True, exist_ok=True)
    exe = args.exe.resolve()
    package = exe.parent
    ORIGIN = f"http://127.0.0.1:{args.port}"
    database_path = _database_path(args.workspace, args)
    report: dict[str, Any] = {
        "schema_version": 2,
        "exe": str(exe),
        "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest() if exe.is_file() else None,
        "port": args.port,
        "default_port_used": args.port == 8765,
        "database_path": str(database_path),
        "checks": [],
        "status": "failed",
    }
    process: subprocess.Popen[bytes] | None = None
    try:
        if not exe.is_file():
            raise RuntimeError(f"EXE not found: {exe}")
        if args.build_record:
            record = json.loads(
                args.build_record.read_text(encoding="utf-8-sig")
            )
            artifact = {
                "build_record": str(args.build_record),
                "record_exe_sha256": record.get("executable_sha256"),
                "record_zip_sha256": record.get("zip_sha256"),
                "record_git_sha": record.get("git_sha"),
                "exe_sha256": report["exe_sha256"],
            }
            if record.get("executable_sha256") != report["exe_sha256"]:
                raise RuntimeError(f"EXE does not match Build Record: {artifact}")
            if args.zip:
                zip_sha = hashlib.sha256(args.zip.read_bytes()).hexdigest()
                artifact["zip_sha256"] = zip_sha
                if zip_sha != record.get("zip_sha256"):
                    raise RuntimeError(f"ZIP does not match Build Record: {artifact}")
            if args.expected_git_sha and record.get("git_sha") != args.expected_git_sha:
                raise RuntimeError(f"Build Record Git SHA mismatch: {artifact}")
            report["artifact_identity"] = artifact
        elif args.zip or args.expected_git_sha:
            raise RuntimeError("artifact verification requires --build-record")
        if not _port_free(args.port):
            raise RuntimeError(f"port {args.port} is already in use before smoke test")

        first_log = args.workspace / "first.log"
        process = _start(
            exe, args.workspace, "cwd-a", args.port, first_log,
            args.use_default_database,
        )
        _wait_health(process)
        report["checks"].append("health")
        first_children = _capture_process(
            report, process, args.port, "first_process",
        )
        report["checks"].append("process-tree-captured")
        addresses = _listener_addresses(args.port)
        report["listener_addresses"] = addresses
        if not addresses or any(address != "127.0.0.1" for address in addresses):
            raise RuntimeError(f"unexpected listener addresses: {addresses}")
        report["checks"].append("loopback-only")
        dashboard, _ = _request("/")
        if "<div id=\"root\"" not in dashboard and "Event Switch Manager" not in dashboard:
            raise RuntimeError("dashboard HTML was not served")
        report["checks"].append("dashboard")
        event, _ = _request("/api/v1/events", method="POST", payload={
            "name": "R77 Portable Smoke",
            "management_vlan": 10,
        })
        event_id = event["id"]
        report["checks"].append("create-event")
        plan, core_id = _make_plan(event_id)
        revision, _ = _request(
            f"/api/v1/events/{event_id}/plan-revisions",
            method="POST", payload=plan,
        )
        revision_id = revision["id"]
        report["checks"].append("save-revision")
        chosen, _ = _request(
            f"/api/v1/events/{event_id}/plan-revisions/{revision_id}",
        )
        if chosen.get("id") != revision_id:
            raise RuntimeError("saved revision could not be read")
        report["checks"].append("read-revision")
        base = (
            f"/api/v1/events/{event_id}/plan-revisions/{revision_id}"
            f"/assignments/{core_id}"
        )
        bundle, headers = _request(base + "/cisco-review-bundle")
        content = bundle["content"]
        if content["banner"][0] != "CISCO CONFIGURATION REVIEW REPORT":
            raise RuntimeError("review bundle banner mismatch")
        if content["identity"]["revision_id"] != revision_id:
            raise RuntimeError("review bundle revision identity mismatch")
        if content["safety"]["hardware_verified"] is not False:
            raise RuntimeError("review bundle safety mismatch")
        digest = bundle["content_digest"]
        canonical = json.dumps(
            content, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        recomputed_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise RuntimeError("review bundle digest is not SHA-256")
        if recomputed_digest != digest:
            raise RuntimeError(
                f"review bundle digest mismatch: {recomputed_digest} != {digest}"
            )
        filename = headers.get("content-disposition", "")
        if not filename.endswith('.json"') and not filename.endswith(".json"):
            raise RuntimeError("review bundle filename is not JSON")
        l3 = content["l3"]["summary"]
        management = content["management"]["summary"]
        assembly = content["assembly"]
        if l3.get("passed") != 9 or l3.get("blocked") != 1:
            raise RuntimeError(f"frozen C9300 L3 counts mismatch: {l3}")
        if management != {"total": 9, "passed": 0, "blocked": 9, "failed": 0}:
            raise RuntimeError(f"frozen management counts mismatch: {management}")
        if len(assembly["sections"]) != 12 or len(assembly["cross_layer_checks"]) != 11:
            raise RuntimeError("frozen assembly section/check counts mismatch")
        safety = assembly["safety"]
        if (
            safety.get("full_config_generated") is not False
            or safety.get("cli") is not None
            or safety.get("deployment_artifact") is not None
        ):
            raise RuntimeError(f"frozen assembly safety mismatch: {safety}")
        report["checks"].append("review-bundle")
        report["review_bundle"] = {
            "content_digest": digest,
            "digest_recomputed": recomputed_digest,
            "digest_matches": recomputed_digest == digest,
            "suggested_filename": bundle["suggested_filename"],
            "production_management": management,
            "l3_summary": l3,
            "assembly_complete": assembly["completeness"]["complete"],
        }
        runtime_evidence = _inspect_runtime_modules(process, package)
        report["host_runtime_evidence"] = runtime_evidence
        report["checks"].append("no-host-python-node-modules")
        if not database_path.is_file():
            raise RuntimeError("database was not created outside the package")
        report["checks"].append("data-outside-package")
        _record_normal_shutdown(
            report, "first_shutdown", process, first_log, args.port,
            first_children,
        )
        process = None
        integrity = _integrity(database_path)
        report["database_integrity_after_normal_shutdown"] = integrity
        if integrity != "ok":
            raise RuntimeError(f"database integrity after shutdown: {integrity}")
        report["checks"].append("database-integrity-normal")

        second_log = args.workspace / "second.log"
        process = _start(
            exe, args.workspace, "cwd-b", args.port, second_log,
            args.use_default_database,
        )
        _wait_health(process)
        second_children = _capture_process(
            report, process, args.port, "second_process",
        )
        events, _ = _request("/api/v1/events")
        if not any(item["id"] == event_id for item in events):
            raise RuntimeError("event did not persist across restart")
        revisions, _ = _request(f"/api/v1/events/{event_id}/plan-revisions")
        if not any(item["id"] == revision_id for item in revisions):
            raise RuntimeError("revision did not persist across restart")
        report["restart_persistence"] = True
        report["checks"].append("restart-persistence")
        _record_normal_shutdown(
            report, "second_shutdown", process, second_log, args.port,
            second_children,
        )
        process = None
        integrity = _integrity(database_path)
        report["database_integrity_after_restart"] = integrity
        if integrity != "ok":
            raise RuntimeError(f"database integrity after restart: {integrity}")
        second = report["second_shutdown"]
        report["shutdown_method"] = second["shutdown_method"]
        report["exit_code"] = second["exit_code"]
        report["graceful_shutdown_observed"] = second["graceful_shutdown_observed"]
        report["forced_termination_used"] = False
        report["process_tree_exited"] = second["process_tree_exited"]
        report["port_released"] = second["port_released"]
        report["database_integrity"] = integrity
        report["restart_persistence"] = True

        # Forced termination recovery is deliberately separate from normal shutdown.
        force_log = args.workspace / "forced.log"
        process = _start(
            exe, args.workspace, "cwd-c", args.port, force_log,
            args.use_default_database,
        )
        _wait_health(process)
        force_children = _capture_process(
            report, process, args.port, "forced_process",
        )
        forced_pid = process.pid
        process.kill()
        process.wait(timeout=10)
        forced_code = int(process.returncode or 0)
        process = None
        forced_released = _wait_port_free(args.port)
        forced_integrity = _integrity(database_path)
        forced_tree_exited = _process_tree_exited(forced_pid, force_children)
        report["forced_termination"] = {
            "forced_termination_used": True,
            "exit_code": forced_code,
            "process_tree_exited": forced_tree_exited,
            "port_released": forced_released,
            "port_owner_after": _port_owner(args.port),
            "database_integrity": forced_integrity,
        }
        if (
            not forced_released
            or forced_integrity != "ok"
            or not forced_tree_exited
            or report["forced_termination"]["port_owner_after"]
        ):
            raise RuntimeError(
                f"forced termination recovery failed: {report['forced_termination']}"
            )
        report["checks"].append("forced-termination-recovery-start")
        restart_log = args.workspace / "restart-after-force.log"
        process = _start(
            exe, args.workspace, "cwd-d", args.port, restart_log,
            args.use_default_database,
        )
        _wait_health(process)
        restart_children = _capture_process(
            report, process, args.port, "restart_after_force_process",
        )
        events, _ = _request("/api/v1/events")
        revisions, _ = _request(f"/api/v1/events/{event_id}/plan-revisions")
        if not any(item["id"] == event_id for item in events) or not any(
            item["id"] == revision_id for item in revisions
        ):
            raise RuntimeError("data was not readable after forced termination")
        report["forced_termination"]["restart_persistence"] = True
        report["checks"].append("forced-termination-restart-persistence")
        _record_normal_shutdown(
            report, "restart_after_force_shutdown", process, restart_log,
            args.port, restart_children,
        )
        process = None

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as owner:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                owner.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            owner.bind(("127.0.0.1", args.port))
            owner.listen()
            conflict_log = args.workspace / "conflict.log"
            conflict = _start(
                exe, args.workspace, "cwd-e", args.port, conflict_log,
                args.use_default_database,
            )
            try:
                conflict_code = conflict.wait(timeout=20)
            except subprocess.TimeoutExpired:
                conflict.kill()
                conflict_code = conflict.wait(timeout=10)
                raise RuntimeError("port-conflict instance did not fail promptly") from None
            if conflict_code == 0:
                raise RuntimeError("port-conflict EXE unexpectedly exited successfully")
            owners = _port_owner(args.port)
            if owner.getsockname()[1] != args.port or owners != [os.getpid()]:
                raise RuntimeError(
                    f"port owner was disturbed: owner={owners}, expected={os.getpid()}"
                )
            report["port_conflict"] = {
                "exit_code": conflict_code,
                "owner_unchanged": True,
                "port_owner": owners,
                "process_tree_exited": _process_tree_exited(conflict.pid, []),
            }
            if not report["port_conflict"]["process_tree_exited"]:
                raise RuntimeError("port-conflict process did not exit")
            report["checks"].append("port-conflict-safe")
        report["console_close"] = "NOT_VERIFIED"
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["error"] = str(exc)
        report["log_tail"] = _log_tail(args.workspace)
        return 1
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def _log_tail(workspace: Path) -> str:
    text = ""
    for name in (
        "first.log", "second.log", "forced.log",
        "restart-after-force.log", "conflict.log",
    ):
        path = workspace / name
        if path.is_file():
            text += f"\n--- {name} ---\n" + path.read_text(errors="replace")[-4000:]
    return text


if __name__ == "__main__":
    if "--send-ctrl-c" in sys.argv:
        index = sys.argv.index("--send-ctrl-c")
        raise SystemExit(_send_ctrl_c(int(sys.argv[index + 1])))
    raise SystemExit(main())
