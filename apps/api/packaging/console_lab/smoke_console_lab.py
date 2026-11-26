"""Offline ConsoleLab artifact smoke checks; never opens a COM port."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    package = Path(args.package).resolve()
    exe = package / "EventSwitchManager-ConsoleLab.exe"
    checks: list[str] = []
    errors: list[str] = []
    if not exe.exists():
        errors.append("missing-executable")
    else:
        checks.append("executable-present")
    if not (package / "instructions" / "操作说明.txt").exists():
        errors.append("missing-instructions")
    else:
        checks.append("instructions-present")
    if not (package / "instructions" / "H0-H4-验收模板.txt").exists():
        errors.append("missing-acceptance-template")
    else:
        checks.append("acceptance-template-present")
    if list(package.rglob("*.sqlite3")):
        errors.append("product-database-present")
    else:
        checks.append("no-product-database")
    if (package / "web").exists() or (package / "EventSwitchManager.exe").exists():
        errors.append("product-runtime-mixed")
    else:
        checks.append("product-runtime-separate")
    for name, command in (
        ("self-test", [str(exe), "--self-test"]),
        ("list-ports-json", [str(exe), "--list-ports", "--json"]),
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
        else:
            checks.append(name)
        if name == "self-test":
            if "CONSOLE-LAB SELF-TEST PASS" not in result.stdout:
                errors.append("self-test-output")
            if "real_serial_opened=NO" in result.stdout:
                checks.append("no-real-serial")
        if name == "list-ports-json":
            try:
                payload = json.loads(result.stdout)
                if payload.get("supported") is not True:
                    errors.append("enumeration-unsupported")
            except ValueError:
                errors.append("list-ports-json-invalid")
    report = {
        "status": "passed" if not errors else "failed",
        "executable_sha256": _sha256(exe) if exe.exists() else None,
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
