from dataclasses import dataclass, field
from pathlib import Path

from platformdirs import user_data_path

LOOPBACK = "127.0.0.1"
WEB_DEV_PORT = 5173


def default_database_path() -> Path:
    return user_data_path("EventSwitchManager", appauthor=False, roaming=False) / "esm.sqlite3"


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: Path = field(default_factory=default_database_path)
    port: int = 8765
    web_dist: Path = Path("apps/web/dist")
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
