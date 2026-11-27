"""Offline ConsoleLab artifact smoke checks; never opens a COM port."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _pe_subsystem(path: Path) -> int:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    optional = pe_offset + 24
    return struct.unpack_from("<H", data, optional + 68)[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    package = Path(args.package).resolve()
    gui_exe = package / "EventSwitchManager-ConsoleLab.exe"
    cli_exe = package / "EventSwitchManager-ConsoleLab-CLI.exe"
    checks: list[str] = []
    errors: list[str] = []

    for name, path in (("gui-executable", gui_exe), ("cli-executable", cli_exe)):
        if path.exists():
            checks.append(name)
        else:
            errors.append(f"missing-{name}")
    for name, relative in (
        ("instructions", "instructions/README.zh-CN.txt"),
        ("acceptance-template", "instructions/H0-H4-ACCEPTANCE-TEMPLATE.txt"),
        ("dependency-manifest", "DEPENDENCIES-SHA256SUMS.txt"),
        ("build-record", "EventSwitchManager-ConsoleLab-build-record.json"),
    ):
        if (package / relative).exists():
            checks.append(f"{name}-present")
        else:
            errors.append(f"missing-{name}")
    nested_zips = [
        item for item in package.rglob("*.zip")
        if "_internal" not in item.parts and item.name != "base_library.zip"
    ]
    if nested_zips:
        errors.append("nested-zip-present")
    else:
        checks.append("single-extraction-no-nested-zip")
    if list(package.rglob("*.sqlite3")):
        errors.append("product-database-present")
    else:
        checks.append("no-product-database")
    if (package / "web").exists() or (package / "EventSwitchManager.exe").exists():
        errors.append("product-runtime-mixed")
    else:
        checks.append("product-runtime-separate")
    if list(package.rglob("python.exe")) or list(package.rglob("node_modules")):
        errors.append("host-runtime-dependency-present")
    else:
        checks.append("no-host-python-node")

    manifest = package / "DEPENDENCIES-SHA256SUMS.txt"
    if manifest.exists():
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            digest, _, relative = line.partition("  ")
            target = package / relative
            if not target.is_file() or _sha256(target) != digest:
                errors.append(f"dependency-manifest-mismatch:{relative}")
                break
        else:
            checks.append("dependency-manifest-integrity")

    if gui_exe.exists() and cli_exe.exists():
        try:
            gui_subsystem = _pe_subsystem(gui_exe)
            cli_subsystem = _pe_subsystem(cli_exe)
            if gui_subsystem == 2:
                checks.append("gui-windows-subsystem")
            else:
                errors.append(f"gui-console-subsystem-{gui_subsystem}")
            if cli_subsystem == 3:
                checks.append("cli-console-subsystem")
            else:
                errors.append(f"cli-subsystem-{cli_subsystem}")
        except (OSError, ValueError, struct.error):
            errors.append("pe-subsystem-check-failed")

    record_path = package / "EventSwitchManager-ConsoleLab-build-record.json"
    if record_path.exists():
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
            if gui_exe.exists() and record.get("executable_sha256") == _sha256(gui_exe):
                checks.append("gui-record-sha")
            else:
                errors.append("gui-record-sha-mismatch")
            if cli_exe.exists() and record.get("cli_executable_sha256") == _sha256(cli_exe):
                checks.append("cli-record-sha")
            else:
                errors.append("cli-record-sha-mismatch")
            if record.get("delivery_layout") == "onedir-single-extraction":
                checks.append("single-extraction-layout")
            else:
                errors.append("single-extraction-layout-missing")
            if record.get("artifact_contains_build_zip") is False:
                checks.append("no-build-zip-in-user-artifact")
            else:
                errors.append("build-zip-must-be-separate")
        except ValueError:
            errors.append("build-record-invalid")

    gui_report = package.parent / "EventSwitchManager-ConsoleLab-gui-smoke.json"
    if gui_exe.exists():
        try:
            result = subprocess.run(
                [
                    str(gui_exe), "--gui-smoke",
                    "--gui-smoke-report", str(gui_report),
                ],
                capture_output=True, timeout=60, check=False,
            )
            if result.returncode != 0:
                errors.append(f"gui-smoke-exit-{result.returncode}")
            elif not gui_report.exists():
                errors.append("gui-smoke-report-missing")
            else:
                payload = json.loads(gui_report.read_text(encoding="utf-8"))
                if payload.get("status") == "passed" and payload.get("real_serial_opened") == "NO":
                    checks.append("gui-smoke")
                else:
                    errors.append("gui-smoke-not-passed")
        except (OSError, subprocess.SubprocessError, ValueError):
            errors.append("gui-smoke-failed")
        finally:
            try:
                gui_report.unlink()
            except OSError:
                pass

    if cli_exe.exists():
        for name, command in (
            ("cli-artifact-check", [str(cli_exe), "--artifact-check"]),
            ("cli-self-test", [str(cli_exe), "--self-test"]),
            ("cli-list-ports-json", [str(cli_exe), "--list-ports", "--json"]),
        ):
            try:
                result = subprocess.run(
                    command, capture_output=True, text=True, timeout=45, check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(f"{name}-failed:{type(exc).__name__}")
                continue
            if result.returncode != 0:
                errors.append(f"{name}-exit-{result.returncode}")
                continue
            if (
                name == "cli-artifact-check"
                and "CONSOLE-LAB ARTIFACT CHECK PASS" not in result.stdout
            ):
                errors.append("cli-artifact-check-output")
            elif (
                name == "cli-self-test"
                and "CONSOLE-LAB SELF-TEST PASS" not in result.stdout
            ):
                errors.append("cli-self-test-output")
            elif name == "cli-list-ports-json":
                try:
                    payload = json.loads(result.stdout)
                    if payload.get("supported") is not True:
                        errors.append("cli-enumeration-unsupported")
                except ValueError:
                    errors.append("cli-list-ports-json-invalid")
            checks.append(name)

    report = {
        "status": "passed" if not errors else "failed",
        "gui_executable_sha256": _sha256(gui_exe) if gui_exe.exists() else None,
        "cli_executable_sha256": _sha256(cli_exe) if cli_exe.exists() else None,
        "checks": checks,
        "errors": errors,
        "real_serial_opened": "NO",
        "hardware_verified": False,
    }
    Path(args.report).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
