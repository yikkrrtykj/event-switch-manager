"""CIS-03-02A read-only Layer 3 intent API tests."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from layer3_helpers import make_l3_plan

from event_switch_manager.app import create_app
from event_switch_manager.settings import Settings

API = "/api/v1"
ORIGIN = "http://127.0.0.1:8765"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_path=tmp_path / "l3-intent.sqlite3")
    with TestClient(
        create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN},
    ) as session:
        yield session


def _event(client: TestClient, name: str = "L3 event") -> str:
    response = client.post(f"{API}/events", json={"name": name})
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _save(client: TestClient, event_id: str, plan: dict[str, Any]) -> dict[str, Any]:
    plan["event_id"] = event_id
    response = client.post(f"{API}/events/{event_id}/plan-revisions", json=plan)
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def _intent(
    client: TestClient, event_id: str, revision_id: str, suffix: str = "",
) -> dict[str, Any]:
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision_id}/layer3-intent{suffix}",
    )
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def test_first_revision_intent_is_read_only_and_bound(client: TestClient) -> None:
    event_id = _event(client)
    revision = _save(client, event_id, make_l3_plan(event_id))
    document = _intent(client, event_id, str(revision["id"]))
    assert document["contract_id"] == "cis-03-cisco-l3-intent-v1"
    assert document["l3_intent_schema_version"] == 1
    assert document["source"] == "saved-revision"
    assert document["event_id"] == event_id
    assert document["revision_id"] == revision["id"]
    assert document["revision_hash"] == revision["content_hash"]
    assert document["baseline"] == {
        "source": "planning-baseline-unavailable",
        "revision_id": None,
        "revision_hash": None,
        "device_state": "unknown",
    }
    assert document["before_state_evidence"] == "planning-baseline-unavailable"
    assert document["verification"] == "not-verified"
    assert document["deployment_status"] == "blocked"
    assert document["executable"] is False
    assert document["cli"] is None
    assert document["device_writes_enabled"] is False
    readiness = document["readiness"]
    assert readiness["forwarding_ready"] is True
    assert readiness["hardware_verified"] is False
    assert readiness["deployment_allowed"] is False


def test_second_revision_binds_previous_saved_revision(client: TestClient) -> None:
    event_id = _event(client)
    first_plan = make_l3_plan(event_id)
    first = _save(client, event_id, first_plan)
    second_plan = copy.deepcopy(first_plan)
    second_plan["default_routes"][0]["preference"] = 5
    second = _save(client, event_id, second_plan)
    document = _intent(client, event_id, str(second["id"]))
    assert document["baseline"] == {
        "source": "previous-saved-revision",
        "revision_id": first["id"],
        "revision_hash": first["content_hash"],
        "device_state": "unknown",
    }
    assert document["before_state_evidence"] == "planning-baseline"


def test_api_rejects_every_undeclared_input(client: TestClient) -> None:
    event_id = _event(client)
    revision = _save(client, event_id, make_l3_plan(event_id))
    base = f"{API}/events/{event_id}/plan-revisions/{revision['id']}/layer3-intent"
    for suffix in (
        "?category=access-vlan", "?anything=1", "?revision_hash=abc",
        "?fingerprint=abc",
    ):
        response = client.get(base + suffix)
        assert response.status_code == 400, response.text
        assert response.json()["detail"]["reason_code"] == "undeclared-input"
        assert response.json()["detail"]["fields"] == [suffix.split("=")[0][1:]]
    response = client.request("GET", base, content=b"{}")
    assert response.status_code == 400
    assert response.json()["detail"]["fields"] == ["request-body"]
    response = client.get(base, headers={"If-Match": '"etag"'})
    assert response.status_code == 400
    assert response.json()["detail"]["fields"] == ["if-match"]
    response = client.get(base, headers={"If-None-Match": '"etag"'})
    assert response.status_code == 400
    assert response.json()["detail"]["fields"] == ["if-none-match"]


def test_route_is_get_only(client: TestClient) -> None:
    event_id = _event(client)
    revision = _save(client, event_id, make_l3_plan(event_id))
    path = f"{API}/events/{event_id}/plan-revisions/{revision['id']}/layer3-intent"
    assert client.post(path).status_code == 405
    assert client.put(path).status_code == 405
    assert client.delete(path).status_code == 405


def test_structured_not_found_errors(client: TestClient) -> None:
    event_id = _event(client)
    revision = _save(client, event_id, make_l3_plan(event_id))
    missing_event = client.get(
        f"{API}/events/00000000-0000-0000-0000-000000000000/plan-revisions/"
        f"{revision['id']}/layer3-intent",
    )
    assert missing_event.status_code == 404
    assert missing_event.json()["detail"] == {
        "reason_code": "event-not-found", "stage": "event",
    }
    missing_revision = client.get(
        f"{API}/events/{event_id}/plan-revisions/"
        "00000000-0000-0000-0000-000000000000/layer3-intent",
    )
    assert missing_revision.status_code == 404
    assert missing_revision.json()["detail"] == {
        "reason_code": "saved-revision-not-found", "stage": "revision",
    }


def test_cross_event_revision_is_isolated(client: TestClient) -> None:
    first_event = _event(client, "First")
    second_event = _event(client, "Second")
    revision = _save(client, first_event, make_l3_plan(first_event))
    response = client.get(
        f"{API}/events/{second_event}/plan-revisions/{revision['id']}/layer3-intent",
    )
    assert response.status_code == 404
    assert response.json()["detail"]["reason_code"] == "saved-revision-not-found"


def test_intent_read_does_not_change_revision_or_export(client: TestClient) -> None:
    event_id = _event(client)
    revision = _save(client, event_id, make_l3_plan(event_id))
    export_path = (
        f"{API}/events/{event_id}/plan-revisions/{revision['id']}/export"
    )
    before = client.get(export_path)
    before_read = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision['id']}",
    )
    _intent(client, event_id, str(revision["id"]))
    after = client.get(export_path)
    after_read = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision['id']}",
    )
    assert before.status_code == after.status_code == 200
    assert before.content == after.content
    assert before.headers["etag"] == after.headers["etag"] == f'"{revision["content_hash"]}"'
    assert before_read.json() == after_read.json()


def test_openapi_exposes_only_the_declared_layer3_route(client: TestClient) -> None:
    schema = client.get("/api/v1/openapi.json").json()
    path = "/api/v1/events/{event_id}/plan-revisions/{revision_id}/layer3-intent"
    assert path in schema["paths"]
    assert set(schema["paths"][path]) == {"get"}


def test_deny_policy_is_visible_over_api(client: TestClient) -> None:
    event_id = _event(client)
    revision = _save(client, event_id, make_l3_plan(event_id, deny_policy=True))
    document = _intent(client, event_id, str(revision["id"]))
    core = next(
        device for device in document["devices"]
        if device["identity"]["hostname"] == "L3-Core"
    )
    assert core["readiness"]["allowed"] is False
    assert core["readiness"]["ip_routing"] == "blocked"
    assert "l3-policy-acl-not-implemented" in core["blockers"]


def test_canonical_hash_failure_returns_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = _event(client)
    revision = _save(client, event_id, make_l3_plan(event_id))
    monkeypatch.setattr(
        "event_switch_manager.layer3_api.plan_hash", lambda _content: "0" * 64,
    )
    response = client.get(
        f"{API}/events/{event_id}/plan-revisions/{revision['id']}/layer3-intent",
    )
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "reason_code": "revision-canonical-hash-mismatch", "stage": "revision",
    }
