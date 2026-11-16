from pathlib import Path
from typing import Any, Literal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from test_event_plans import API, ORIGIN, synthetic_plan, uid

from event_switch_manager.app import create_app
from event_switch_manager.database import create_database_engine
from event_switch_manager.planning.persistence import save_revision
from event_switch_manager.planning.plan import EventPlan, canonical_plan, plan_hash
from event_switch_manager.settings import Settings

Mode = Literal["active", "passive", "static"]
PEER_CODE = "port_channel_peer_lacp"


def paired_plan(event_id: str, left: Mode, right: Mode, *, linked: bool) -> dict[str, Any]:
    plan = synthetic_plan(event_id)
    plan["physical_devices"].append({"id": uid(40), "vendor": "cisco"})
    plan["assignments"].append({
        "id": uid(41), "hostname": "Lab-Access", "role": "access", "physical_device_id": uid(40),
    })
    plan["logical_interfaces"].append({
        "id": uid(42), "assignment_id": uid(41), "name": "Port-channel11", "kind": "port-channel",
    })
    trunk = {"mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20]}
    for port, name in ((43, "Gi1/0/47"), (44, "Gi1/0/48")):
        plan["physical_interfaces"].append({
            "id": uid(port), "assignment_id": uid(41), "physical_device_id": uid(40),
            "name": name, "settings": trunk,
        })
    plan["port_channels"][0]["lacp"] = left
    plan["port_channels"].append({
        "interface_id": uid(42), "number": 11, "member_ids": [uid(43), uid(44)],
        "lacp": right, "settings": trunk,
    })
    if linked:
        plan["links"].extend([
            {"id": uid(45), "endpoints": [uid(8), uid(43)]},
            {"id": uid(46), "endpoints": [uid(44), uid(9)]},
        ])
    return plan


@pytest.mark.parametrize(("left", "right", "linked", "blocked"), [
    ("active", "active", True, False),
    ("active", "passive", True, False),
    ("passive", "active", True, False),
    ("static", "static", True, False),
    ("passive", "passive", True, True),
    ("static", "active", True, True),
    ("active", "static", True, True),
    ("static", "passive", True, True),
    ("passive", "static", True, True),
    ("passive", "passive", False, False),
    ("static", "active", False, False),
])
def test_linked_lacp_mode_pairs(
    tmp_path: Path, left: Mode, right: Mode, linked: bool, blocked: bool,
) -> None:
    settings = Settings(database_path=tmp_path / "pair.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        event = client.post(f"{API}/events", json={"name": "Synthetic channel peers"})
        assert event.status_code == 201
        event_id = event.json()["id"]
        endpoint = f"{API}/events/{event_id}"
        raw = paired_plan(event_id, left, right, linked=linked)
        checked = client.post(endpoint + "/plan/validate", json=raw)
        assert checked.status_code == 200
        issues = [item for item in checked.json() if item["severity"] == "ERROR"]
        saved = client.post(endpoint + "/plan-revisions", json=raw)
        if blocked:
            assert saved.status_code == 422, saved.text
            assert [(issue["path"], issue["code"]) for issue in issues] == [
                ("port_channels.0.lacp", PEER_CODE), ("port_channels.1.lacp", PEER_CODE),
            ]
            assert client.get(endpoint + "/plan-revisions").json() == []
        else:
            assert issues == []
            assert saved.status_code == 200, saved.text
            assert saved.json()["validation_status"] == "VALID_WITH_WARNINGS"


def test_existing_incompatible_pair_keeps_immutable_revision_data(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "legacy-pair.sqlite3")
    with TestClient(create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        event = client.post(f"{API}/events", json={"name": "Synthetic historical pair"})
        event_id = event.json()["id"]
        raw = paired_plan(event_id, "passive", "passive", linked=True)
        plan = EventPlan.model_validate(raw)
        canonical = canonical_plan(plan)
        engine = create_database_engine(settings.database_path)
        try:
            with Session(engine) as session:
                saved = save_revision(session, plan)
                revision_id = str(saved.id)
                session.commit()
        finally:
            engine.dispose()

        collection = f"{API}/events/{event_id}/plan-revisions"
        url = f"{collection}/{revision_id}"
        detail = client.get(url).json()
        assert detail["validation_status"] == "INVALID"
        assert {issue["code"] for issue in detail["validation_errors"]} == {PEER_CODE}
        export = client.get(url + "/export")
        assert export.content == canonical.encode()
        assert export.headers["etag"] == f'"{plan_hash(canonical)}"'
        again = client.post(collection, json=raw)
        assert again.status_code == 200
        assert again.json()["id"] == revision_id
        assert len(client.get(collection).json()) == 1
