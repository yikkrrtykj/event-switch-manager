from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

from event_switch_manager.__main__ import _ensure_loopback_port_available
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
    with pytest.raises(RuntimeError, match="Packaged Alembic migrations"):
        default_migrations_location()
    migrations.mkdir(parents=True)
    assert default_migrations_location() == str(migrations)


def test_frozen_app_rejects_missing_web_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    web = tmp_path / "web"
    web.mkdir()
    with pytest.raises(RuntimeError, match="Packaged web assets"):
        create_app(Settings(database_path=tmp_path / "esm.sqlite3", web_dist=web))


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
