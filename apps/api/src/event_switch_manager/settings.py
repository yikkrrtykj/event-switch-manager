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
    # Search upward so an installed package still finds the checkout's web
    # build, regardless of the launch working directory.
    package_file = Path(__file__).resolve()
    fallback: Path | None = None
    for parent in package_file.parents:
        candidate = parent / "apps" / "web" / "dist"
        if (candidate / "index.html").is_file():
            return candidate
        if fallback is None and (parent / "apps" / "web").is_dir():
            fallback = candidate
    if fallback is not None:
        return fallback
    return Path.cwd() / "apps" / "web" / "dist"


PACKAGED_REVISION_IDS = ("0001_event_inventory", "0002_event_plans")
PACKAGED_HEAD_ID = "0002_event_plans"


def _validate_packaged_migrations(migrations: Path) -> None:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config()
    config.set_main_option("script_location", str(migrations))
    try:
        script = ScriptDirectory.from_config(config)
        for revision_id in PACKAGED_REVISION_IDS:
            script.get_revision(revision_id)
        heads = set(script.get_heads())
    except Exception as exc:
        raise RuntimeError(
            f"Packaged Alembic migration graph is invalid: {exc}"
        ) from exc
    if heads != {PACKAGED_HEAD_ID}:
        raise RuntimeError(
            "Packaged Alembic migration graph has unexpected head(s): "
            f"{sorted(heads)}"
        )


def default_migrations_location() -> str:
    """Resolve Alembic migrations as package data inside a frozen application."""
    root = frozen_bundle_root()
    if root is None:
        return "event_switch_manager:migrations"
    migrations = root / "event_switch_manager" / "migrations"
    versions = migrations / "versions"
    required = (
        migrations / "env.py",
        migrations / "script.py.mako",
        versions,
    )
    missing = [str(path) for path in required if not path.exists()]
    if versions.exists() and not versions.is_dir():
        missing.append(f"{versions} (not a directory)")
    if versions.is_dir() and not any(
        item.suffix == ".py" and item.name != "__init__.py"
        for item in versions.iterdir()
    ):
        missing.append(str(versions / "*.py"))
    if not migrations.is_dir() or missing:
        detail = ", ".join(missing) if missing else str(migrations)
        raise RuntimeError(
            f"Packaged Alembic migration resources are missing: {detail}"
        )
    _validate_packaged_migrations(migrations)
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
