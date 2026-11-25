from __future__ import annotations

import argparse
import json
import os
import signal
import socket
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


def _stop(process: subprocess.Popen[bytes]) -> int:
    if process.poll() is not None:
        return int(process.returncode or 0)
    try:
        if hasattr(signal, "CTRL_C_EVENT"):
            process.send_signal(signal.CTRL_C_EVENT)
        else:
            process.terminate()
    except (OSError, ValueError):
        process.terminate()
    try:
        return int(process.wait(timeout=15))
    except subprocess.TimeoutExpired:
        process.kill()
        return int(process.wait(timeout=10))


def _start(
    exe: Path, workspace: Path, cwd_name: str, port: int,
    log: Path, use_default_database: bool = False,
) -> subprocess.Popen[bytes]:
    cwd = workspace / cwd_name
    cwd.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    # The portable executable must not need a Python or Node installation.
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    env["PATH"] = str(system_root / "System32") + os.pathsep + str(system_root)
    for name in ("PYTHONHOME", "PYTHONPATH", "NODE_PATH"):
        env.pop(name, None)
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["HTTP_PROXY"] = "http://127.0.0.1:9"
    env["HTTPS_PROXY"] = "http://127.0.0.1:9"
    log.parent.mkdir(parents=True, exist_ok=True)
    output = log.open("wb")
    database_args: list[str] = []
    if not use_default_database:
        database = workspace / "UserData" / "esm.sqlite3"
        database.parent.mkdir(parents=True, exist_ok=True)
        database_args = ["--database", str(database)]
    return subprocess.Popen(
        [str(exe), "--no-browser", "--port", str(port), *database_args],
        cwd=cwd,
        env=env,
        stdout=output,
        stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )


def _module_check(process: subprocess.Popen[bytes], package: Path) -> list[str]:
    """Check loaded Python/Node modules stay inside the portable directory."""
    command = (
        f"Get-Process -Id {process.pid} | "
        "Select-Object -ExpandProperty Modules | "
        "Select-Object -ExpandProperty FileName"
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ["module inspection unavailable"]
    findings: list[str] = []
    package_text = str(package.resolve()).casefold()
    for line in completed.stdout.splitlines():
        module = line.strip()
        if not module:
            continue
        lowered = module.casefold()
        if ("python" in lowered and lowered.endswith(".dll")) or lowered.endswith("node.exe"):
            if not lowered.startswith(package_text):
                findings.append(module)
    return findings


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test the Windows portable EXE")
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
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
    report: dict[str, Any] = {
        "schema_version": 1,
        "exe": str(exe),
        "port": args.port,
        "checks": [],
        "status": "failed",
    }
    process: subprocess.Popen[bytes] | None = None
    try:
        if not exe.is_file():
            raise RuntimeError(f"EXE not found: {exe}")
        if not _port_free(args.port):
            raise RuntimeError(f"port {args.port} is already in use before smoke test")

        first_log = args.workspace / "first.log"
        process = _start(
            exe, args.workspace, "cwd-a", args.port, first_log,
            args.use_default_database,
        )
        _wait_health(process)
        report["checks"].append("health")
        dashboard, _ = _request("/")
        if "<div id=\"root\"" not in dashboard and "Event Switch Manager" not in dashboard:
            raise RuntimeError("dashboard HTML was not served")
        report["checks"].append("dashboard")
        event, _ = _request("/api/v1/events", method="POST", payload={
            "name": "R75 Portable Smoke",
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
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise RuntimeError("review bundle digest is not SHA-256")
        filename = headers.get("content-disposition", "")
        if not filename.endswith('.json"') and not filename.endswith(".json"):
            raise RuntimeError("review bundle filename is not JSON")
        report["checks"].append("review-bundle")
        report["review_bundle"] = {
            "content_digest": digest,
            "suggested_filename": bundle["suggested_filename"],
            "production_management": content["management"]["summary"],
            "l3_summary": content["l3"]["summary"],
            "assembly_complete": content["assembly"]["completeness"]["complete"],
        }
        findings = _module_check(process, package)
        report["host_runtime_modules"] = findings
        if findings:
            raise RuntimeError(f"host runtime modules loaded: {findings}")
        report["checks"].append("no-host-python-node-modules")
        if args.use_default_database:
            local = Path(os.environ.get("LOCALAPPDATA", ""))
            database_path = local / "EventSwitchManager" / "esm.sqlite3"
        else:
            database_path = args.workspace / "UserData" / "esm.sqlite3"
        report["database_path"] = str(database_path)
        if not database_path.is_file():
            raise RuntimeError("database was not created outside the package")
        report["checks"].append("data-outside-package")
        first_code = _stop(process)
        process = None
        if not _wait_port_free(args.port):
            raise RuntimeError("port was not released after graceful shutdown")
        report["checks"].append("port-release")
        report["first_exit_code"] = first_code

        second_log = args.workspace / "second.log"
        process = _start(
            exe, args.workspace, "cwd-b", args.port, second_log,
            args.use_default_database,
        )
        _wait_health(process)
        events, _ = _request("/api/v1/events")
        if not any(item["id"] == event_id for item in events):
            raise RuntimeError("event did not persist across restart")
        revisions, _ = _request(f"/api/v1/events/{event_id}/plan-revisions")
        if not any(item["id"] == revision_id for item in revisions):
            raise RuntimeError("revision did not persist across restart")
        report["checks"].append("restart-persistence")
        second_code = _stop(process)
        process = None
        if not _wait_port_free(args.port):
            raise RuntimeError("port was not released after second shutdown")
        report["checks"].append("second-port-release")
        report["second_exit_code"] = second_code

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as owner:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                owner.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            owner.bind(("127.0.0.1", args.port))
            owner.listen()
            conflict_log = args.workspace / "conflict.log"
            conflict = _start(
                exe, args.workspace, "cwd-c", args.port, conflict_log,
                args.use_default_database,
            )
            try:
                conflict_code = conflict.wait(timeout=20)
            except subprocess.TimeoutExpired:
                conflict.kill()
                conflict_code = conflict.wait(timeout=10)
            if conflict_code == 0:
                raise RuntimeError("port-conflict EXE unexpectedly exited successfully")
            if owner.getsockname()[1] != args.port:
                raise RuntimeError("port owner was disturbed")
            report["checks"].append("port-conflict-safe")
            report["port_conflict_exit_code"] = conflict_code
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["error"] = str(exc)
        report["log_tail"] = _log_tail(args.workspace)
        return 1
    finally:
        if process is not None and process.poll() is None:
            _stop(process)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def _log_tail(workspace: Path) -> str:
    text = ""
    for name in ("first.log", "second.log", "conflict.log"):
        path = workspace / name
        if path.is_file():
            text += f"\n--- {name} ---\n" + path.read_text(errors="replace")[-4000:]
    return text


if __name__ == "__main__":
    raise SystemExit(main())
