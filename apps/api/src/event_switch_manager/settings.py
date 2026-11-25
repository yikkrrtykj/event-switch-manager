import sys
from dataclasses import dataclass, field
from pathlib import Path

from platformdirs import user_data_path

LOOPBACK = "127.0.0.1"
WEB_DEV_PORT = 5173


def default_database_path() -> Path:
    return user_data_path("EventSwitchManager", appauthor=False, roaming=False) / "esm.sqlite3"


def frozen_bundle_root() -> Path | None:
    """Return the PyInstaller payload root, independent of the launch directory."""
    if not getattr(sys, "frozen", False):
        return None
    root = getattr(sys, "_MEIPASS", None)
    return Path(root) if root is not None else Path(sys.executable).resolve().parent


def default_web_dist() -> Path:
    """Resolve the built UI from the package or from the source checkout."""
    root = frozen_bundle_root()
    if root is not None:
        return root / "web"
    return Path(__file__).resolve().parents[3] / "web" / "dist"


def default_migrations_location() -> str:
    """Resolve Alembic migrations as package data inside a frozen application."""
    root = frozen_bundle_root()
    if root is None:
        return "event_switch_manager:migrations"
    migrations = root / "event_switch_manager" / "migrations"
    if not migrations.is_dir():
        raise RuntimeError(f"Packaged Alembic migrations are missing: {migrations}")
    return str(migrations)


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: Path = field(default_factory=default_database_path)
    port: int = 8765
    web_dist: Path = field(default_factory=default_web_dist)
    development: bool = False

    @property
    def authority(self) -> str:
        return f"{LOOPBACK}:{self.port}"

    @property
    def allowed_authorities(self) -> frozenset[str]:
        authorities = {self.authority}
        if self.development:
            authorities.add(f"{LOOPBACK}:{WEB_DEV_PORT}")
        return frozenset(authorities)

    @property
    def url(self) -> str:
        return f"http://{self.authority}"
