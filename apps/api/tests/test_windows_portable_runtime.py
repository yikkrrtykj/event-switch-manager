from __future__ import annotations

import importlib.util
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from event_switch_manager.__main__ import (
    _ensure_loopback_port_available,
    _open_when_ready,
)
from event_switch_manager.app import create_app
from event_switch_manager.settings import (
    Settings,
    default_database_path,
    default_migrations_location,
    default_web_dist,
    frozen_bundle_root,
)


def test_default_database_is_outside_the_package() -> None:
    database = default_database_path()
    assert database.name == "esm.sqlite3"
    assert database.parent.name == "EventSwitchManager"
    source_root = Path(__file__).resolve().parents[2]
    assert source_root not in database.parents


def test_source_checkout_uses_absolute_web_dist() -> None:
    expected = Path(__file__).resolve().parents[2] / "web" / "dist"
    assert frozen_bundle_root() is None
    assert default_web_dist() == expected
    assert default_web_dist().is_absolute()
    assert default_migrations_location() == "event_switch_manager:migrations"


def test_frozen_paths_are_independent_of_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert frozen_bundle_root() == tmp_path
    assert default_web_dist() == tmp_path / "web"
    migrations = tmp_path / "event_switch_manager" / "migrations"
    with pytest.raises(RuntimeError, match="Packaged Alembic migration resources"):
        default_migrations_location()
    migrations.mkdir(parents=True)
    with pytest.raises(RuntimeError, match="env.py"):
        default_migrations_location()
    (migrations / "env.py").write_text("")
    (migrations / "script.py.mako").write_text("")
    (migrations / "versions").mkdir()
    with pytest.raises(RuntimeError, match="versions"):
        default_migrations_location()
    source_versions = (
        Path(__file__).resolve().parents[1]
        / "src" / "event_switch_manager" / "migrations" / "versions"
    )
    for name in ("0001_event_inventory.py", "0002_event_plans.py"):
        shutil.copy2(source_versions / name, migrations / "versions" / name)
    assert default_migrations_location() == str(migrations)


def test_packaged_migration_graph_requires_both_revisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    migrations = tmp_path / "event_switch_manager" / "migrations"
    versions = migrations / "versions"
    versions.mkdir(parents=True)
    (migrations / "env.py").write_text("")
    (migrations / "script.py.mako").write_text("")
    source_versions = (
        Path(__file__).resolve().parents[1]
        / "src" / "event_switch_manager" / "migrations" / "versions"
    )
    for name in ("0001_event_inventory.py", "0002_event_plans.py"):
        shutil.copy2(source_versions / name, versions / name)

    with pytest.raises(RuntimeError, match="migration graph"):
        (versions / "0001_event_inventory.py").unlink()
        default_migrations_location()

    shutil.copy2(source_versions / "0001_event_inventory.py", versions)
    (versions / "0002_event_plans.py").unlink()
    with pytest.raises(RuntimeError, match="migration graph|expected head"):
        default_migrations_location()

    shutil.copy2(source_versions / "0002_event_plans.py", versions)
    (versions / "0002_event_plans.py").write_text("not valid python")
    with pytest.raises(RuntimeError, match="migration graph"):
        default_migrations_location()


def test_frozen_app_rejects_missing_web_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    web = tmp_path / "web"
    web.mkdir()
    with pytest.raises(RuntimeError, match="Packaged web assets"):
        create_app(Settings(database_path=tmp_path / "esm.sqlite3", web_dist=web))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows console signal test")
def test_source_mode_ctrl_c_uses_real_console(tmp_path: Path) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    log_path = tmp_path / "source.log"
    database = tmp_path / "source.sqlite3"
    smoke = Path(__file__).resolve().parents[1] / "packaging" / "smoke_windows.py"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [
                sys.executable, "-m", "event_switch_manager",
                "--no-browser", "--port", str(port),
                "--database", str(database),
                "--web-dist", str(tmp_path / "web"),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
        )
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/api/v1/health", timeout=1,
                    ) as response:
                        if response.status == 200:
                            break
                except Exception:
                    pass
                time.sleep(0.2)
            else:
                raise AssertionError("source server did not become ready")
            helper = subprocess.run(
                [sys.executable, str(smoke), "--send-ctrl-c", str(process.pid)],
                capture_output=True, text=True, timeout=30, check=False,
            )
            assert helper.returncode == 0, helper.stdout + helper.stderr
            assert process.wait(timeout=20) == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
    text = log_path.read_text(errors="replace")
    assert "Shutting down" in text
    assert "Application shutdown complete" in text


def test_loopback_port_conflict_fails_without_stopping_owner() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as owner:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            owner.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        owner.bind(("127.0.0.1", 0))
        owner.listen()
        port = owner.getsockname()[1]
        with pytest.raises(RuntimeError, match="No other process was stopped"):
            _ensure_loopback_port_available(port)
        assert owner.getsockname()[1] == port


def test_loopback_port_can_be_reused_after_listener_closes() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    _ensure_loopback_port_available(port)


def _load_smoke_module() -> Any:
    path = Path(__file__).resolve().parents[1] / "packaging" / "smoke_windows.py"
    spec = importlib.util.spec_from_file_location("esm_smoke_windows", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runtime_module_classifier_accepts_package_python(tmp_path: Path) -> None:
    smoke = _load_smoke_module()
    package = tmp_path / "package"
    package.mkdir()
    bundled_python = package / "python312.dll"
    bundled_python.write_bytes(b"fixture")
    evidence = smoke._classify_runtime_modules(
        [str(package / "EventSwitchManager.exe"), str(bundled_python)],
        package,
    )
    assert evidence["ok"] is True
    assert evidence["host_runtime_modules"] == []
    assert evidence["package_python_modules"] == [str(bundled_python.resolve())]


def test_runtime_module_classifier_rejects_host_runtime(tmp_path: Path) -> None:
    smoke = _load_smoke_module()
    package = tmp_path / "package"
    package.mkdir()
    host_python = tmp_path / "python312.dll"
    host_python.write_bytes(b"fixture")
    lookalike = tmp_path / "package-other"
    lookalike.mkdir()
    lookalike_dll = lookalike / "python312.dll"
    lookalike_dll.write_bytes(b"fixture")
    evidence = smoke._classify_runtime_modules(
        [str(package / "EventSwitchManager.exe"), str(host_python), str(lookalike_dll)],
        package,
    )
    assert evidence["ok"] is False
    assert str(host_python.resolve()) in evidence["host_runtime_modules"]
    assert str(lookalike_dll.resolve()) in evidence["host_runtime_modules"]


def test_runtime_module_inspection_fails_closed(tmp_path: Path) -> None:
    smoke = _load_smoke_module()
    process = cast(Any, SimpleNamespace(pid=1234, poll=lambda: None))

    def empty(_: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 0, stdout="", stderr="")

    def failed(_: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 1, stdout="", stderr="denied")

    with pytest.raises(RuntimeError, match="no modules"):
        smoke._inspect_runtime_modules(process, tmp_path, runner=empty)
    with pytest.raises(RuntimeError, match="enumeration failed"):
        smoke._inspect_runtime_modules(process, tmp_path, runner=failed)
    not_running = cast(Any, SimpleNamespace(pid=1234, poll=lambda: 1))
    with pytest.raises(RuntimeError, match="not running"):
        smoke._inspect_runtime_modules(not_running, tmp_path, runner=empty)


def test_browser_contract_opens_only_after_server_ready() -> None:
    calls: list[str] = []

    def fake_open(url: str) -> bool:
        calls.append(url)
        return True

    from typing import Any, cast

    class FakeServer:
        started = False

    _open_when_ready(
        cast(Any, FakeServer()), "http://127.0.0.1:8765", timeout_seconds=0.01,
        open_browser=fake_open,
    )
    assert calls == []

    class ReadyServer:
        started = True

    _open_when_ready(
        cast(Any, ReadyServer()), "http://127.0.0.1:8765", timeout_seconds=0.01,
        open_browser=fake_open,
    )
    assert calls == ["http://127.0.0.1:8765"]
