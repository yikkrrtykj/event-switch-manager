from pathlib import Path

from fastapi.testclient import TestClient
from test_event_plans import ORIGIN

from event_switch_manager.app import create_app
from event_switch_manager.console.transport import SerialTransport
from event_switch_manager.settings import Settings


def test_console_engine_has_no_http_or_product_execution_entrypoint(tmp_path: Path) -> None:
    with TestClient(
        create_app(Settings(database_path=tmp_path / "boundary.sqlite3")),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN},
    ) as client:
        paths = set(client.get("/api/v1/openapi.json").json()["paths"])
    assert not any("console" in path or "serial" in path for path in paths)
    assert not hasattr(SerialTransport, "send_break")
