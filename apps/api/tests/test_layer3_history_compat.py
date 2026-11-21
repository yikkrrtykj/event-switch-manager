"""CIS-03-02A historical canonical-hash compatibility tests."""

from __future__ import annotations

from pathlib import Path

from event_switch_manager.planning.plan import EventPlan, canonical_plan, plan_hash

FIXTURE = Path(__file__).parent / "fixtures" / "layer3_historical_event_plan_v1.json"
EXPECTED_SHA256 = "538fb244be6033777b95536fba9294ef46d6ea78d1fbcf37d0be7956418917bd"


def test_historical_fixture_reparses_byte_identically() -> None:
    raw = FIXTURE.read_text(encoding="utf-8")
    plan = EventPlan.model_validate_json(raw)
    assert canonical_plan(plan) == raw
    assert plan_hash(canonical_plan(plan)) == EXPECTED_SHA256


def test_new_default_field_is_omitted_from_new_intent_hash() -> None:
    raw = FIXTURE.read_text(encoding="utf-8")
    plan = EventPlan.model_validate_json(raw)
    assert all(item.routing_enabled is None for item in plan.assignments)
    assert "routing_enabled" not in raw


def test_explicit_routing_enabled_is_canonical_and_changes_the_hash() -> None:
    raw = FIXTURE.read_text(encoding="utf-8")
    plan = EventPlan.model_validate_json(raw)
    first = plan.assignments[0]
    changed_plan = plan.model_copy(update={
        "assignments": (
            first.model_copy(update={"routing_enabled": True}),
            *plan.assignments[1:],
        ),
    })
    changed = canonical_plan(changed_plan)
    assert '"routing_enabled":true' in changed
    assert changed != raw
    assert plan_hash(changed) != EXPECTED_SHA256
    assert canonical_plan(changed_plan) == changed
