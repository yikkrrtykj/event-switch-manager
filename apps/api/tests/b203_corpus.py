"""Shared CIS-02B2-03 test fixtures (not collected as tests).

The module keeps hand-authored device scopes, the expected topic/scope matrix
and the helpers that build frozen B2-02 renderer documents. It imports the
existing frozen test fixture builders; it never derives expectations from the
renderer's own validation helpers.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

from event_switch_manager.domain import DeviceFamily
from event_switch_manager.planning.command_evidence import (
    CommandTopic,
)
from event_switch_manager.planning.layer2_cli_candidates import (
    CandidateCategory,
    L2CliCandidateDocument,
    build_l2_cli_candidates,
)
from event_switch_manager.planning.layer2_cli_validation import DeviceScope
from event_switch_manager.planning.layer2_config_preview import (
    build_device_layer2_config_preview,
)
from event_switch_manager.planning.layer2_intent import build_layer2_intent
from event_switch_manager.planning.plan import (
    EventPlan,
    PlanRevision,
    canonical_plan,
    plan_hash,
)

INTERFACE_TOPICS: frozenset[CommandTopic] = frozenset({
    CommandTopic.ADMIN_SHUTDOWN,
    CommandTopic.CHANNEL_GROUP_LACP,
    CommandTopic.CHANNEL_GROUP_STATIC,
    CommandTopic.DESCRIPTION,
    CommandTopic.DUPLEX,
    CommandTopic.POE_MODE,
    CommandTopic.PORT_CHANNEL_INTERFACE,
    CommandTopic.SPEED,
})

L2_TOPICS: frozenset[CommandTopic] = frozenset(CommandTopic) - INTERFACE_TOPICS

FROZEN_FAMILY_COUNTS: dict[str, tuple[int, int, int]] = {
    "2960x": (8, 24, 0),
    "3850": (8, 24, 0),
    "9200": (25, 7, 0),
    "9300": (25, 7, 0),
    "c1000": (8, 24, 0),
}

#: Renderer fingerprints of the deterministic frozen five-family fixture.
#: They pin the frozen B2-02 output: any renderer semantic change breaks them.
FROZEN_RENDER_FINGERPRINTS: dict[str, str] = {
    "2960x": "a17a54e4280991c1a814aec51caf9da0a05cc81f9c5eb0e7540d08420c83c354",
    "3850": "b94ec2e9a7adecd7927dc38bc548c0a65274cc04fe601a53d61a15fee63640ca",
    "9200": "d8d16efc616a0a1bcc5ea77758087674ebb92d67c644c1efbcd6ade475e0bf74",
    "9300": "4ff6169286f6f93bb81bb570ff9613488c27a338d91dab42582a494d12b9999d",
    "c1000": "1c2cd6d3ce7b13f28390e6993b21ce8bde3ca934714754e145298bd31d9dfe2c",
}

#: Exact device scopes used by the independent scope validator tests.
DEVICE_SCOPES: dict[str, dict[str, object]] = {
    "2960x-lanbase": {
        "family": "catalyst-2960x",
        "pid": "WS-C2960X-24PS-L",
        "release": "15.2(7)E",
        "license": "LAN Base",
    },
    "2960x-lanlite": {
        "family": "catalyst-2960x",
        "pid": "WS-C2960X-24TS-LL",
        "release": "15.2(7)E7",
        "license": "LAN Lite",
    },
    "3850": {
        "family": "catalyst-3850",
        "pid": "WS-C3850-24P",
        "release": "16.12.12",
        "license": "IP Base",
    },
    "9200": {
        "family": "catalyst-9200",
        "pid": "C9200L-24P-4X",
        "release": "17.12.4",
        "license": "Network Advantage",
    },
    "9300": {
        "family": "catalyst-9300",
        "pid": "C9300L-24P-4X",
        "release": "17.12.4",
        "license": "Network Advantage",
    },
    "c1000": {
        "family": "catalyst-c1000",
        "pid": "C1000-24P-4G-L",
        "release": "15.2(7)E1",
        "license": None,
    },
}

#: Independent oracle for the six unreviewed-identity scopes.
IDENTITY_ONLY_SCOPES: dict[str, dict[str, object]] = {
    "2960x-e1a": {
        "family": "catalyst-2960x",
        "pid": "WS-C2960X-24PS-L",
        "release": "15.2(7)E1a",
        "license": "LAN Base",
    },
    "3850-16.12.10a": {
        "family": "catalyst-3850",
        "pid": "WS-C3850-24P",
        "release": "16.12.10a",
        "license": "IP Base",
    },
    "9200-17.12.5": {
        "family": "catalyst-9200",
        "pid": "C9200L-24P-4X",
        "release": "17.12.5",
        "license": "Network Advantage",
    },
    "9300-17.12.5": {
        "family": "catalyst-9300",
        "pid": "C9300L-24P-4X",
        "release": "17.12.5",
        "license": "Network Advantage",
    },
    "c1000-bare-e": {
        "family": "catalyst-c1000",
        "pid": "C1000-24P-4G-L",
        "release": "15.2(7)E",
        "license": None,
    },
}

#: Hand-authored expected topic/scope matrix (independent of the registry).
SCOPE_TOPIC_ALLOWED: dict[str, frozenset[CommandTopic]] = {
    "2960x-lanbase": INTERFACE_TOPICS,
    "2960x-lanlite": INTERFACE_TOPICS,
    "3850": INTERFACE_TOPICS,
    "9200": (INTERFACE_TOPICS - {CommandTopic.DESCRIPTION})
    | (L2_TOPICS - {CommandTopic.NATIVE_VLAN}),
    "9300": (INTERFACE_TOPICS - {CommandTopic.DESCRIPTION}) | L2_TOPICS,
    "c1000": INTERFACE_TOPICS,
}

#: Aggregation-only release: only the three EtherChannel rows are in scope.
CHANNEL_TOPICS: frozenset[CommandTopic] = frozenset({
    CommandTopic.PORT_CHANNEL_INTERFACE,
    CommandTopic.CHANNEL_GROUP_STATIC,
    CommandTopic.CHANNEL_GROUP_LACP,
})

RELEASE_SCOPE_TOPIC_ALLOWED: dict[str, frozenset[CommandTopic]] = {
    "2960x-e1a": frozenset(),
    "3850-16.12.10a": CHANNEL_TOPICS,
    "9200-17.12.5": frozenset(),
    "9300-17.12.5": frozenset(),
    "c1000-bare-e": frozenset(),
}

UUID_PATTERN = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
SERIAL_PATTERN = re.compile(r"\ASYN-L2-[0-9A-F]{8}\Z")
_FROZEN_NAMESPACE = UUID("00000000-0000-4000-8000-000000000203")


def device_scope(
    key: str,
    *,
    release: str | None = None,
    license_name: str | None = None,
    pid: str | None = None,
    family: str | None = None,
    stack_identity: str = "standalone",
    stack_members: tuple[tuple[int, str | None, str], ...] = (),
) -> DeviceScope:
    """Build an independent device scope from the hand-authored tables."""
    spec = DEVICE_SCOPES[key] if key in DEVICE_SCOPES else IDENTITY_ONLY_SCOPES[key]
    family_value = family if family is not None else cast(str, spec["family"])
    return DeviceScope(
        family=_device_family(family_value),
        pid=pid if pid is not None else cast(str | None, spec["pid"]),
        release=release if release is not None else cast(str, spec["release"]),
        license=(
            license_name if license_name is not None
            else cast(str | None, spec["license"])
        ),
        stack_identity=stack_identity,
        stack_members=stack_members,
    )


def _device_family(value: str) -> DeviceFamily:
    return DeviceFamily(value)


def build_revision(plan: dict[str, Any], number: int = 1) -> PlanRevision:
    event_plan = EventPlan.model_validate(plan)
    return PlanRevision(
        id=_revision_uuid(str(plan["assignments"][0]["id"]), number),
        number=number,
        created_at=datetime(2026, 11, 20, 12, 0, 0, tzinfo=UTC),
        content_hash=plan_hash(canonical_plan(event_plan)),
        schema_version=1,
        plan=event_plan,
        warnings=(),
        validation_errors=(),
        validation_status=cast(Any, "VALID_WITH_WARNINGS"),
    )


def _revision_uuid(assignment_id: str, number: int) -> UUID:
    digest = hashlib.sha256(f"b203|{assignment_id}|{number}".encode()).hexdigest()
    return UUID(
        f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-"
        f"{digest[20:32]}"
    )


def render_plan(
    plan: dict[str, Any], *, categories: tuple[CandidateCategory, ...] | None = None,
) -> L2CliCandidateDocument:
    revision = build_revision(plan)
    intent = build_layer2_intent(revision, None)
    preview = build_device_layer2_config_preview(
        revision, intent, revision.plan.assignments[0].id,
    )
    return build_l2_cli_candidates(revision, intent, preview, categories=categories)


def render_sequence(
    plans: list[dict[str, Any]],
    *,
    categories: tuple[CandidateCategory, ...] | None = None,
) -> L2CliCandidateDocument:
    revisions = [build_revision(plan, index + 1) for index, plan in enumerate(plans)]
    current = revisions[-1]
    baseline = revisions[-2] if len(revisions) > 1 else None
    intent = build_layer2_intent(current, baseline)
    preview = build_device_layer2_config_preview(
        current, intent, current.plan.assignments[0].id,
    )
    return build_l2_cli_candidates(current, intent, preview, categories=categories)


def deterministic_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Freeze every generated UUID/serial so a fixture fingerprint is stable.

    The mapping follows first appearance in the plan structure, never the
    random UUID values, so the frozen fixture is comparable across runs.
    """
    ordered: list[str] = []
    for value in _walk_strings(plan):
        if UUID_PATTERN.match(value) and value not in ordered:
            ordered.append(value)
    mapping = {
        value: _deterministic_uuid(index) for index, value in enumerate(ordered)
    }
    return cast(dict[str, Any], _replace_strings(plan, mapping))


def _deterministic_uuid(index: int) -> str:
    digest = hashlib.sha256(f"b203-uuid-{index}".encode()).hexdigest()
    return str(UUID(
        f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-"
        f"{digest[20:32]}"
    ))


def _walk_strings(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            found.extend(_walk_strings(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_walk_strings(item))
    return found


def _replace_strings(value: object, mapping: dict[str, str]) -> object:
    if isinstance(value, str):
        if UUID_PATTERN.match(value):
            return mapping[value]
        if SERIAL_PATTERN.match(value):
            return "SYN-L2-B2030001"
        return value
    if isinstance(value, dict):
        return {key: _replace_strings(item, mapping) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_strings(item, mapping) for item in value]
    return value
