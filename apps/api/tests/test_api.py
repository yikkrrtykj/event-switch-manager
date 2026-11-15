from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from event_switch_manager.app import create_app
from event_switch_manager.database import create_database_engine, upgrade_database
from event_switch_manager.settings import Settings

ORIGIN = "http://127.0.0.1:8765"
API = "/api/v1"
SWITCH = {
    "hostname": "Core-01",
    "family": "catalyst-9300",
    "role": "core",
    "management_ip": "192.0.2.10",
    "serial_number": "SYNTHETIC-01",
}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "plan.sqlite3", web_dist=tmp_path / "web")
    with TestClient(
        create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}
    ) as session:
        yield session


def new_event(client: TestClient, name: str = "Lab event") -> str:
    response = client.post(f"{API}/events", json={"name": name})
    assert response.status_code == 201
    event_id: str = response.json()["id"]
    return event_id


def test_health_checks_migrated_database(client: TestClient) -> None:
    response = client.get(f"{API}/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ready", "device_writes_enabled": False}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_events_can_be_created_and_updated(client: TestClient) -> None:
    event_id = new_event(client, "  Lab event  ")
    event_url = f"{API}/events/{event_id}"
    assert client.get(event_url).json() == {
        "id": event_id, "name": "Lab event", "management_vlan": 10
    }
    response = client.put(event_url, json={"name": "Finals", "management_vlan": 120})
    assert response.status_code == 200
    assert client.get(f"{API}/events").json() == [response.json()]
    assert response.json()["management_vlan"] == 120


@pytest.mark.parametrize("vlan", [0, 4095, "10", True])
def test_event_rejects_invalid_vlan(client: TestClient, vlan: object) -> None:
    response = client.post(f"{API}/events", json={"name": "Lab", "management_vlan": vlan})
    assert response.status_code == 422


def test_devices_are_event_scoped_and_roles_are_independent(client: TestClient) -> None:
    first = new_event(client)
    second = new_event(client, "Second event")
    first_inventory = f"{API}/events/{first}/devices"
    second_inventory = f"{API}/events/{second}/devices"
    response = client.post(first_inventory, json=SWITCH)
    assert response.status_code == 201
    device_id = response.json()["id"]
    assert response.json()["event_id"] == first
    assert response.json()["management_ip"] == "192.0.2.10"
    assert client.get(second_inventory).json() == []
    assert client.get(f"{second_inventory}/{device_id}").status_code == 404
    assert client.put(f"{second_inventory}/{device_id}", json=SWITCH).status_code == 404
    assert client.post(second_inventory, json=SWITCH).status_code == 201
    assert client.put(
        f"{first_inventory}/{device_id}", json={**SWITCH, "role": "access"}
    ).status_code == 200
    assert client.get(f"{first_inventory}/{device_id}").json()["role"] == "access"
    assert client.get(f"{API}/events/{uuid4()}/devices").status_code == 404


@pytest.mark.parametrize(
    ("field", "duplicate"),
    [("hostname", "core-01"), ("serial_number", "synthetic-01"), ("management_ip", "192.0.2.10")],
)
def test_duplicate_inventory_is_rejected(
    client: TestClient, field: str, duplicate: str
) -> None:
    url = f"{API}/events/{new_event(client)}/devices"
    assert client.post(url, json=SWITCH).status_code == 201
    other = {
        **SWITCH,
        "hostname": "Access-01",
        "serial_number": "SYNTHETIC-02",
        "management_ip": "192.0.2.20",
    }
    assert client.post(url, json={**other, field: duplicate}).status_code == 409
    assert client.post(url, json=other).status_code == 201


@pytest.mark.parametrize(
    "extra",
    [
        {"hostname": "switch\nreload"},
        {"management_ip": "2001:db8::1"},
        {"family": "unknown"},
        {"serial_number": "a b"},
        {"commands": ["show version"]},
    ],
)
def test_device_input_validation(client: TestClient, extra: dict[str, object]) -> None:
    url = f"{API}/events/{new_event(client)}/devices"
    assert client.post(url, json={**SWITCH, **extra}).status_code == 422


def test_local_web_guard(client: TestClient) -> None:
    assert client.get(f"{API}/health", headers={"Host": "external.example"}).status_code == 400
    assert client.get(f"{API}/health", headers={"Host": "127.0.0.1:5173"}).status_code == 400
    for origin in ("null", "http://localhost:8765", "http://127.0.0.1:5173", "https://example.com"):
        response = client.post(f"{API}/events", headers={"Origin": origin}, json={"name": "Lab"})
        assert response.status_code == 403
    request = client.build_request("POST", f"{API}/events", json={"name": "Lab"})
    del request.headers["origin"]
    assert client.send(request).status_code == 403
    preflight = client.options(
        f"{API}/events",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "access-control-allow-origin" not in preflight.headers
    assert client.get(f"{API}/events").json() == []
    assert client.post(f"{API}/devices/deploy", json={}).status_code == 404


def test_vite_proxy_must_preserve_same_origin(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "dev.sqlite3", development=True)
    vite_url = "http://127.0.0.1:5173"
    with TestClient(create_app(settings), base_url=vite_url) as client:
        data = {"name": "Lab"}
        foreign = client.post(f"{API}/events", json=data, headers={"Origin": ORIGIN})
        local = client.post(f"{API}/events", json=data, headers={"Origin": vite_url})
        assert foreign.status_code == 403
        assert local.status_code == 201


def test_plan_survives_server_restart(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "planning data %.sqlite3")
    with TestClient(
        create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}
    ) as first:
        event_id = new_event(first)
        assert first.post(f"{API}/events/{event_id}/devices", json=SWITCH).status_code == 201
    with TestClient(create_app(settings), base_url=ORIGIN) as restarted:
        assert restarted.get(f"{API}/events/{event_id}/devices").json()[0]["hostname"] == "Core-01"


def test_migration_is_repeatable_and_enforces_foreign_keys(tmp_path: Path) -> None:
    engine = create_database_engine(tmp_path / "lab.sqlite3")
    try:
        upgrade_database(engine)
        upgrade_database(engine)
        assert set(inspect(engine).get_table_names()) == {
            "events", "devices", "alembic_version", "physical_assets",
            "assignment_identities", "event_plan_revisions",
        }
        with engine.connect() as connection:
            version = connection.scalar(text("SELECT version_num FROM alembic_version"))
            assert version == "0002_event_plans"
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "INSERT INTO devices (id, event_id, hostname, family, role) "
                        "VALUES ('1', 'missing', 'lab', 'catalyst-9300', 'core')"
                    )
                )
    finally:
        engine.dispose()


def test_built_assets_and_unknown_api_path(tmp_path: Path) -> None:
    web = tmp_path / "web"
    (web / "assets").mkdir(parents=True)
    (web / "assets" / "index.js").write_text("/* local script */", encoding="utf-8")
    (web / "index.html").write_text("<title>Event Switch Manager</title>", encoding="utf-8")
    with TestClient(
        create_app(Settings(database_path=tmp_path / "lab.sqlite3", web_dist=web)), base_url=ORIGIN
    ) as client:
        assert "<title>Event Switch Manager</title>" in client.get("/").text
        assert "local script" in client.get("/assets/index.js").text
        assert client.get(f"{API}/unimplemented").status_code == 404
