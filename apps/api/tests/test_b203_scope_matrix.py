"""CIS-02B2-03 independent scope matrix and per-evidence-row coverage.

The expectations in this module are hand-authored against the B2-01 platform
matrix. They are not derived from the renderer and not derived from the
independent scope validator itself: the test compares two independent oracles
(hand-written matrix and frozen registry data) against the validator.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from b203_corpus import (
    CHANNEL_TOPICS,
    DEVICE_SCOPES,
    IDENTITY_ONLY_SCOPES,
    INTERFACE_TOPICS,
    L2_TOPICS,
    RELEASE_SCOPE_TOPIC_ALLOWED,
    SCOPE_TOPIC_ALLOWED,
    device_scope,
)

from event_switch_manager.planning.command_evidence import (
    DEFAULT_REGISTRY,
    ROWS,
    CommandEvidence,
    CommandTopic,
    EvidenceReviewState,
    ParameterRule,
)
from event_switch_manager.planning.layer2_cli_grammar import (
    COVERAGE_COMMAND_BY_TOPIC,
    FORMS_BY_TOPIC,
    PORT_CHANNEL_NUMBER_MAXIMUM,
    PORT_CHANNEL_NUMBER_MINIMUM,
    ChannelNumberParameter,
    EnumParameter,
    IntegerParameter,
    ParameterSlot,
    PortChannelNameParameter,
    TargetClass,
    TextParameter,
    VlanListParameter,
)
from event_switch_manager.planning.layer2_cli_parser import parse_command
from event_switch_manager.planning.layer2_cli_validation import (
    DeviceScope,
    ScopeDecision,
    ScopeOutcome,
    _registry_coverage,
    classify_scope,
    device_identity_findings,
)

REGISTRY_FINGERPRINT = (
    "3547df751ec024972841bcdd65e8050a2f65c069e357d07a60891851a2d9b42c"
)


def _parse(text: str) -> str:
    result = parse_command(text)
    assert result.ok, (text, result.failure_codes)
    assert result.command is not None
    return text


def _decision(text: str, scope: DeviceScope) -> ScopeDecision:
    result = parse_command(text)
    assert result.ok, (text, result.failure_codes)
    command = result.command
    assert command is not None
    return classify_scope(command, scope)


def _row_scope(row: CommandEvidence) -> DeviceScope:
    return DeviceScope(
        family=row.family,
        pid=row.pids[0] if row.pids else None,
        release=row.releases[0] if row.releases else None,
        license=row.licenses[0] if row.licenses else None,
        stack_identity="standalone",
        stack_members=(),
    )


def test_registry_fingerprint_and_review_split_are_frozen() -> None:
    assert DEFAULT_REGISTRY.fingerprint == REGISTRY_FINGERPRINT
    assert len(ROWS) == 72
    assert sum(1 for row in ROWS if row.renderable) == 69
    assert sum(
        1 for row in ROWS if row.review.state is EvidenceReviewState.REJECTED
    ) == 1
    assert sum(
        1 for row in ROWS if row.review.state is EvidenceReviewState.PENDING
    ) == 2
    assert {row.topic for row in ROWS} == set(CommandTopic)


@pytest.mark.parametrize("scope_key", sorted(DEVICE_SCOPES))
@pytest.mark.parametrize("topic", list(CommandTopic), ids=lambda topic: topic.value)
def test_hand_authored_topic_scope_matrix(scope_key: str, topic: CommandTopic) -> None:
    decision = _decision(COVERAGE_COMMAND_BY_TOPIC[topic], device_scope(scope_key))
    expected_allowed = topic in SCOPE_TOPIC_ALLOWED[scope_key]
    if expected_allowed:
        assert decision.outcome is ScopeOutcome.ALLOWED, (scope_key, topic)
        assert decision.evidence_id is not None
        row = DEFAULT_REGISTRY.get(decision.evidence_id)
        assert row is not None
        assert row.renderable
        assert row.topic is topic
    else:
        assert decision.outcome is ScopeOutcome.BLOCKED, (scope_key, topic)
        assert decision.reason_code.startswith("syntax-evidence-")


@pytest.mark.parametrize("scope_key", sorted(IDENTITY_ONLY_SCOPES))
@pytest.mark.parametrize("topic", list(CommandTopic), ids=lambda topic: topic.value)
def test_identity_only_release_scopes_never_promote_command_syntax(
    scope_key: str, topic: CommandTopic,
) -> None:
    decision = _decision(COVERAGE_COMMAND_BY_TOPIC[topic], device_scope(scope_key))
    if topic in RELEASE_SCOPE_TOPIC_ALLOWED[scope_key]:
        assert decision.outcome is ScopeOutcome.ALLOWED
    else:
        assert decision.outcome is ScopeOutcome.BLOCKED
        assert decision.reason_code.startswith("syntax-evidence-")


def test_aggregation_only_3850_release_keeps_channel_rows_only() -> None:
    scope = device_scope("3850-16.12.10a")
    for topic in CHANNEL_TOPICS:
        decision = _decision(COVERAGE_COMMAND_BY_TOPIC[topic], scope)
        assert decision.outcome is ScopeOutcome.ALLOWED, topic
    for topic in set(CommandTopic) - CHANNEL_TOPICS:
        decision = _decision(COVERAGE_COMMAND_BY_TOPIC[topic], scope)
        assert decision.outcome is ScopeOutcome.BLOCKED, topic


@pytest.mark.parametrize(
    ("text", "expected_reason"),
    [
        (
            "spanning-tree bpduguard disable",
            "parameter-not-allowed:bpdu-guard",
        ),
        (
            "spanning-tree bpduguard enable",
            None,
        ),
    ],
)
def test_bpdu_guard_disable_is_reviewed_only_for_9300(
    text: str, expected_reason: str | None,
) -> None:
    assert _decision(text, device_scope("9300")).outcome is ScopeOutcome.ALLOWED
    c9200 = _decision(text, device_scope("9200"))
    if expected_reason is None:
        assert c9200.outcome is ScopeOutcome.ALLOWED
    else:
        assert c9200.outcome is ScopeOutcome.BLOCKED
        assert c9200.reason_code == expected_reason


@pytest.mark.parametrize("key", sorted(DEVICE_SCOPES))
def test_port_channel_numbers_respect_the_reviewed_scope_maximum(key: str) -> None:
    scope = device_scope(key)
    maximum = 48 if key in {"9200", "9300"} else {
        "2960x-lanbase": 24,
        "2960x-lanlite": 6,
        "3850": 128,
        "c1000": 6,
    }[key]
    accepted = _decision(f"interface Port-Channel{maximum}", scope)
    assert accepted.outcome is ScopeOutcome.ALLOWED
    rejected = _decision(f"interface Port-Channel{maximum + 1}", scope)
    assert rejected.outcome is ScopeOutcome.BLOCKED
    assert rejected.reason_code == (
        "parameter-out-of-range:port-channel-number"
    )


@pytest.mark.parametrize(
    ("key", "release", "license_name", "pid"),
    [
        ("2960x-lanbase", None, "LAN Lite", None),
        ("2960x-lanlite", None, "LAN Base", None),
        ("3850", None, "Network Advantage", None),
        ("9200", None, "LAN Base", None),
        ("9300", None, "LAN Base", None),
        ("c1000", None, "Stock image", None),
        ("9200", None, None, "C9300L-24P-4X"),
        ("9300", None, None, "C9200L-24P-4X"),
    ],
)
def test_pid_release_license_scope_is_never_extrapolated(
    key: str,
    release: str | None,
    license_name: str | None,
    pid: str | None,
) -> None:
    scope = device_scope(
        key, release=release, license_name=license_name, pid=pid,
    )
    for topic in CommandTopic:
        decision = _decision(COVERAGE_COMMAND_BY_TOPIC[topic], scope)
        assert decision.outcome is ScopeOutcome.BLOCKED, (key, topic)


@pytest.mark.parametrize(
    ("scope", "expected_reason"),
    [
        (
            device_scope("9300", stack_identity="unresolved"),
            "stack-identity-unresolved",
        ),
        (
            device_scope(
                "9300", stack_identity="standalone",
                stack_members=((1, "C9300L-24P-4X", "ready"),),
            ),
            "stack-identity-inconsistent",
        ),
        (
            device_scope(
                "9300", stack_identity="resolved",
                stack_members=((1, "C9300L-24P-4X", "missing"),),
            ),
            "stack-member-not-ready",
        ),
        (
            device_scope(
                "2960x-lanlite", stack_identity="resolved",
                stack_members=((1, "WS-C2960X-24TS-LL", "ready"),),
            ),
            "stack-limit-exceeded:1:0",
        ),
        (
            device_scope(
                "c1000", stack_identity="resolved",
                stack_members=((1, "C1000-24P-4G-L", "ready"),),
            ),
            "stack-limit-exceeded:1:0",
        ),
    ],
)
def test_stack_identity_and_limits_fail_closed(
    scope: DeviceScope, expected_reason: str,
) -> None:
    findings = device_identity_findings(scope)
    assert expected_reason in findings
    decision = _decision("interface Port-Channel1", scope)
    assert decision.outcome is ScopeOutcome.BLOCKED
    assert decision.reason_code == findings[0]


@pytest.mark.parametrize("license_name", ["lan base", "LAN BASE", "Lan Base"])
def test_stack_limit_lookup_is_license_case_insensitive(
    license_name: str,
) -> None:
    members = tuple(
        (number, "WS-C2960X-24PS-L", "ready") for number in range(1, 21)
    )
    scope = device_scope(
        "2960x-lanbase", license_name=license_name,
        stack_identity="resolved", stack_members=members,
    )
    findings = device_identity_findings(scope)
    assert "stack-limit-exceeded:20:8" in findings


def test_stack_member_pid_must_be_a_reviewed_family_pid() -> None:
    scope = device_scope(
        "9300", stack_identity="resolved",
        stack_members=((1, "WS-C2960X-24PS-L", "ready"),),
    )
    findings = device_identity_findings(scope)
    assert "stack-member-pid-not-verified" in findings
    decision = _decision("interface Port-Channel1", scope)
    assert decision.outcome is ScopeOutcome.BLOCKED


@pytest.mark.parametrize(
    "members",
    [
        ((1, "C9300L-24P-4X", "ready"), (1, "C9300L-24P-4X", "ready")),
        ((0, "C9300L-24P-4X", "ready"),),
    ],
)
def test_stack_member_numbers_must_be_unique_and_positive(
    members: tuple[tuple[int, str | None, str], ...],
) -> None:
    scope = device_scope(
        "9300", stack_identity="resolved", stack_members=members,
    )
    assert "stack-member-numbers-invalid" in device_identity_findings(scope)


@pytest.mark.parametrize(
    ("family", "pid"),
    [
        ("catalyst-2960x", "WS-C2960X-99XX"),
        ("catalyst-9200", "C9300L-24P-4X"),
        ("catalyst-9300", "C9200L-24P-4X"),
    ],
)
def test_unreviewed_pid_and_wrong_family_are_blocked(
    family: str, pid: str,
) -> None:
    scope = device_scope(
        "9300" if family == "catalyst-9200" else "2960x-lanbase",
        family=family,
        pid=pid,
    )
    decisions = {
        _decision(COVERAGE_COMMAND_BY_TOPIC[topic], scope).outcome
        for topic in CommandTopic
    }
    assert decisions == {ScopeOutcome.BLOCKED}


@pytest.mark.parametrize(
    ("scope_key", "expected_family_rows"),
    [
        ("2960x-lanbase", 16),
        ("2960x-lanlite", 16),
        ("3850", 8),
        ("9200", 20),
        ("9300", 20),
        ("c1000", 8),
    ],
)
def test_registry_rows_per_family_sum_to_the_frozen_72(
    scope_key: str, expected_family_rows: int,
) -> None:
    family = device_scope(scope_key).family
    assert family is not None
    rows = [row for row in ROWS if row.family is family]
    assert len(rows) == expected_family_rows
    assert {row.topic for row in rows} <= INTERFACE_TOPICS | L2_TOPICS


def test_registry_coverage_records_every_frozen_row() -> None:
    coverage = _registry_coverage()
    assert len(coverage) == 72
    allowed = [record for record in coverage
               if record.independent_scope_verdict is ScopeOutcome.ALLOWED]
    blocked = [record for record in coverage
               if record.independent_scope_verdict is ScopeOutcome.BLOCKED]
    assert len(allowed) == 69
    assert len(blocked) == 3
    assert {record.evidence_id for record in blocked} == {
        "l1-catalyst-9200-native-vlan-v1",
        "l1-catalyst-9200-description-v1",
        "l1-catalyst-9300-description-v1",
    }
    assert all(record.canonical_parse_status.value == "pass" for record in coverage)
    for record in allowed:
        assert record.renderable is True
        assert record.evidence_id_resolved == record.evidence_id
    for record in blocked:
        assert record.renderable is False


@pytest.mark.parametrize("row", ROWS, ids=lambda row: row.evidence_id)
def test_every_evidence_row_has_an_independent_coverage_record(
    row: CommandEvidence,
) -> None:
    decision = _decision(COVERAGE_COMMAND_BY_TOPIC[row.topic], _row_scope(row))
    if row.renderable:
        assert decision.outcome is ScopeOutcome.ALLOWED
        assert decision.evidence_id == row.evidence_id
        assert row.review.content_digest == row.content_digest
        return
    assert decision.outcome is ScopeOutcome.BLOCKED
    if row.review.state is EvidenceReviewState.REJECTED:
        assert decision.reason_code == (
            f"syntax-evidence-rejected:{row.topic.value}"
        )
    else:
        assert row.review.state is EvidenceReviewState.PENDING
        assert decision.reason_code == (
            f"syntax-evidence-not-reviewed:{row.topic.value}"
        )


# --------------------------------------------------------------------------- #
# Per-row parameter boundary coverage
# --------------------------------------------------------------------------- #


def _command(row: CommandEvidence, values: dict[str, object] | None = None) -> str:
    topic = row.topic
    merged = _default_values(row)
    merged.update(values or {})
    if topic is CommandTopic.VLAN:
        return f"vlan {merged['vlan-id']}"
    if topic is CommandTopic.VLAN_NAME:
        return f"name {merged['vlan-name']}"
    if topic is CommandTopic.ACCESS_MODE:
        return "switchport mode access"
    if topic is CommandTopic.TRUNK_MODE:
        return "switchport mode trunk"
    if topic is CommandTopic.ACCESS_VLAN:
        return f"switchport access vlan {merged['vlan-id']}"
    if topic is CommandTopic.NATIVE_VLAN:
        return f"switchport trunk native vlan {merged['vlan-id']}"
    if topic is CommandTopic.ALLOWED_VLANS:
        raw = merged["vlan-list"]
        assert isinstance(raw, (list, tuple))
        return "switchport trunk allowed vlan " + ",".join(
            str(value) for value in raw
        )
    if topic is CommandTopic.PORT_CHANNEL_INTERFACE:
        return f"interface Port-Channel{merged['port-channel-number']}"
    if topic is CommandTopic.CHANNEL_GROUP_STATIC:
        return f"channel-group {merged['port-channel-number']} mode on"
    if topic is CommandTopic.CHANNEL_GROUP_LACP:
        return (
            f"channel-group {merged['port-channel-number']} "
            f"mode {merged['mode']}"
        )
    if topic is CommandTopic.RAPID_PVST:
        return "spanning-tree mode rapid-pvst"
    if topic is CommandTopic.VTP_TRANSPARENT:
        return "vtp mode transparent"
    if topic is CommandTopic.ROOT_PRIORITY:
        return (
            f"spanning-tree vlan {merged['vlan-id']} "
            f"priority {merged['priority']}"
        )
    if topic is CommandTopic.PORTFAST:
        return {
            "edge": "spanning-tree portfast",
            "edge-trunk": "spanning-tree portfast trunk",
        }[str(merged["portfast"])]
    if topic is CommandTopic.BPDU_GUARD:
        return f"spanning-tree bpduguard {merged['bpdu-guard']}"
    if topic is CommandTopic.POE_MODE:
        return f"power inline {merged['poe-mode']}"
    if topic is CommandTopic.SPEED:
        return f"speed {merged['speed']}"
    if topic is CommandTopic.DUPLEX:
        return f"duplex {merged['duplex']}"
    if topic is CommandTopic.DESCRIPTION:
        return f"description {merged['description']}"
    if topic is CommandTopic.ADMIN_SHUTDOWN:
        return "no shutdown" if merged["admin-state"] == "up" else "shutdown"
    raise AssertionError(f"no test command builder for {topic.value}")


def _default_values(row: CommandEvidence) -> dict[str, object]:
    values: dict[str, object] = {}
    for rule in row.parameters:
        values[rule.name] = _representative_value(rule)
    return values


def _representative_value(rule: ParameterRule) -> object:
    if rule.kind == "integer":
        return rule.minimum if rule.minimum is not None else 0
    if rule.kind == "enum":
        return rule.values[0]
    if rule.kind == "text":
        return "A"
    if rule.kind == "vlan-list":
        return [rule.minimum if rule.minimum is not None else 1]
    raise AssertionError(rule.kind)


def _valid_cases(row: CommandEvidence) -> list[str]:
    cases = [COVERAGE_COMMAND_BY_TOPIC[row.topic]]
    for rule in row.parameters:
        if rule.kind == "integer":
            if rule.minimum is not None:
                cases.append(_command(row, {rule.name: rule.minimum}))
            if rule.maximum is not None:
                cases.append(_command(row, {rule.name: rule.maximum}))
            if rule.minimum is not None and rule.maximum is not None:
                if rule.step:
                    cases.append(_command(row, {
                        rule.name: min(
                            rule.minimum + rule.step, rule.maximum,
                        ),
                    }))
        elif rule.kind == "enum":
            for value in rule.values:
                cases.append(_command(row, {rule.name: value}))
        elif rule.kind == "text":
            maximum = rule.maximum or 1
            first = "A"
            if rule.name == "description":
                cases.append(_command(row, {"description": "A"}))
                cases.append(_command(row, {
                    "description": "A" + "b" * (maximum - 1),
                }))
            else:
                cases.append(_command(row, {"vlan-name": first}))
                cases.append(_command(row, {
                    "vlan-name": "A" + "b" * (maximum - 1),
                }))
        elif rule.kind == "vlan-list":
            minimum = rule.minimum if rule.minimum is not None else 1
            maximum = rule.maximum if rule.maximum is not None else 4094
            cases.append(_command(row, {"vlan-list": [minimum]}))
            cases.append(_command(row, {"vlan-list": [maximum]}))
            cases.append(_command(row, {
                "vlan-list": [minimum, minimum + 1],
            }))
    return list(dict.fromkeys(cases))


def _invalid_cases(row: CommandEvidence) -> list[str]:
    cases: list[str] = []
    for rule in row.parameters:
        if rule.kind == "integer":
            if rule.minimum is not None:
                cases.append(_command(row, {rule.name: rule.minimum - 1}))
            if rule.maximum is not None:
                cases.append(_command(row, {rule.name: rule.maximum + 1}))
            for reserved in rule.reserved:
                cases.append(_command(row, {rule.name: reserved}))
            if rule.step:
                cases.append(_command(row, {rule.name: rule.step + 1}))
        elif rule.kind == "text":
            maximum = rule.maximum or 1
            field = "description" if rule.name == "description" else "vlan-name"
            cases.append(_command(row, {field: "A" + "b" * maximum}))
            cases.append(_command(row, {field: "_bad"}))
        elif rule.kind == "enum":
            if rule.name not in {"admin-state", "portfast"} and (
                row.topic is not CommandTopic.CHANNEL_GROUP_STATIC
            ):
                cases.append(_command(row, {rule.name: "not-a-reviewed-value"}))
        elif rule.kind == "vlan-list":
            maximum = rule.maximum if rule.maximum is not None else 4094
            cases.append(_command(row, {"vlan-list": [maximum + 1]}))
            cases.append(_command(row, {"vlan-list": [10, 10]}))
            cases.append(_command(row, {"vlan-list": [20, 10]}))
            if rule.reserved:
                cases.append(_command(row, {"vlan-list": [rule.reserved[0]]}))
    return list(dict.fromkeys(cases))


@pytest.mark.parametrize("row", ROWS, ids=lambda row: row.evidence_id)
def test_every_evidence_row_parameter_boundaries(row: CommandEvidence) -> None:
    scope = _row_scope(row)
    for text in _valid_cases(row):
        result = parse_command(text)
        assert result.ok, (row.evidence_id, text, result.failure_codes)
        command = result.command
        assert command is not None
        decision = classify_scope(command, scope)
        if row.renderable:
            assert decision.outcome is ScopeOutcome.ALLOWED, (
                row.evidence_id, text, decision.reason_code,
            )
            assert decision.evidence_id == row.evidence_id
        else:
            assert decision.outcome is ScopeOutcome.BLOCKED
            assert decision.reason_code.startswith("syntax-evidence-")
    for text in _invalid_cases(row):
        result = parse_command(text)
        if not result.ok:
            continue
        command = result.command
        assert command is not None
        decision = classify_scope(command, scope)
        assert decision.outcome is ScopeOutcome.BLOCKED, (row.evidence_id, text)


def test_per_platform_lower_text_limit_is_applied_independently() -> None:
    row = next(
        row for row in ROWS
        if row.renderable and row.topic is CommandTopic.DESCRIPTION
    )
    rule = next(rule for rule in row.parameters if rule.name == "description")
    short_rule = replace(rule, maximum=10)
    short_row = replace(row, parameters=(short_rule,))
    reviewed_row = replace(
        short_row,
        review=replace(short_row.review, content_digest=short_row.content_digest),
    )
    assert reviewed_row.renderable
    scope = DeviceScope(
        family=reviewed_row.family,
        pid=reviewed_row.pids[0],
        release=reviewed_row.releases[0],
        license=reviewed_row.licenses[0],
        stack_identity="standalone",
        stack_members=(),
    )
    result = parse_command("description Players desk")
    assert result.ok and result.command is not None
    decision = classify_scope(result.command, scope, rows=(reviewed_row,))
    assert decision.outcome is ScopeOutcome.BLOCKED
    assert decision.reason_code == "unsafe-text-class:description-too-long"


def test_evidence_digest_mismatch_blocks_scope() -> None:
    row = next(row for row in ROWS if row.renderable)
    tampered = replace(
        row, review=replace(row.review, content_digest="0" * 64),
    )
    assert not tampered.renderable
    result = parse_command(COVERAGE_COMMAND_BY_TOPIC[row.topic])
    assert result.ok and result.command is not None
    decision = classify_scope(result.command, _row_scope(row), rows=(tampered,))
    assert decision.outcome is ScopeOutcome.BLOCKED
    assert decision.reason_code == (
        f"syntax-evidence-content-mismatch:{row.topic.value}"
    )


def test_ambiguous_reviewed_scope_rows_are_not_promoted() -> None:
    row = next(row for row in ROWS if row.renderable)
    duplicate = replace(row, evidence_id=row.evidence_id + "-duplicate")
    duplicate = replace(
        duplicate,
        review=replace(duplicate.review, content_digest=duplicate.content_digest),
    )
    result = parse_command(COVERAGE_COMMAND_BY_TOPIC[row.topic])
    assert result.ok and result.command is not None
    decision = classify_scope(
        result.command, _row_scope(row), rows=(row, duplicate),
    )
    assert decision.outcome is ScopeOutcome.BLOCKED
    assert decision.reason_code == (
        f"syntax-evidence-ambiguous:{row.topic.value}"
    )


def test_unreviewed_evidence_rows_cannot_be_promoted_by_valid_syntax() -> None:
    for evidence_id in (
        "l1-catalyst-9200-native-vlan-v1",
        "l1-catalyst-9200-description-v1",
        "l1-catalyst-9300-description-v1",
    ):
        row = DEFAULT_REGISTRY.get(evidence_id)
        assert row is not None
        result = parse_command(COVERAGE_COMMAND_BY_TOPIC[row.topic])
        assert result.ok and result.command is not None
        decision = classify_scope(result.command, _row_scope(row))
        assert decision.outcome is ScopeOutcome.BLOCKED
        assert decision.evidence_id == evidence_id


def _grammar_parameters(topic: CommandTopic) -> dict[str, object]:
    parameters: dict[str, object] = {}
    for form in FORMS_BY_TOPIC[topic]:
        for item in form.pattern:
            if isinstance(item, ParameterSlot):
                parameters[item.parameter.name] = item.parameter
    return parameters


def test_grammar_topics_match_the_frozen_registry_topics() -> None:
    assert set(FORMS_BY_TOPIC) == {row.topic for row in ROWS}
    assert len(FORMS_BY_TOPIC) == 20


def test_grammar_does_not_expand_reviewed_enumerations() -> None:
    for topic, forms in FORMS_BY_TOPIC.items():
        reviewed_values: dict[str, set[str]] = {}
        for row in ROWS:
            if row.topic is not topic:
                continue
            for rule in row.parameters:
                if rule.kind == "enum":
                    reviewed_values.setdefault(rule.name, set()).update(rule.values)
        for form in forms:
            for item in form.pattern:
                if not isinstance(item, ParameterSlot):
                    continue
                parameter = item.parameter
                if isinstance(parameter, EnumParameter):
                    assert set(parameter.values) <= reviewed_values.get(
                        parameter.name, set(),
                    ), (topic.value, form.form_id, parameter.name)


def test_grammar_envelope_contains_every_reviewed_parameter_envelope() -> None:
    for row in ROWS:
        grammar_parameters = _grammar_parameters(row.topic)
        for rule in row.parameters:
            parameter = grammar_parameters.get(rule.name)
            if parameter is None:
                # Fixed-form parameter: the grammar fixes one reviewed value.
                fixed = {
                    value for form in FORMS_BY_TOPIC[row.topic]
                    for name, value in form.fixed_parameters
                    if name == rule.name
                }
                if rule.kind == "enum" and fixed:
                    assert set(rule.values) <= {str(value) for value in fixed}
                continue
            if rule.kind == "integer":
                if isinstance(parameter, IntegerParameter):
                    minimum = parameter.minimum
                    maximum = parameter.maximum
                    step = parameter.step
                    reserved = parameter.reserved
                elif isinstance(parameter, ChannelNumberParameter):
                    minimum, maximum = parameter.minimum, parameter.maximum
                    step, reserved = None, ()
                elif isinstance(parameter, PortChannelNameParameter):
                    minimum = PORT_CHANNEL_NUMBER_MINIMUM
                    maximum = PORT_CHANNEL_NUMBER_MAXIMUM
                    step, reserved = None, ()
                else:  # pragma: no cover - closed union
                    raise AssertionError(type(parameter))
                if rule.minimum is not None:
                    assert minimum <= rule.minimum
                if rule.maximum is not None:
                    assert maximum >= rule.maximum
                if rule.step is not None:
                    assert step == rule.step
                assert set(rule.reserved) <= set(reserved)
            elif rule.kind == "enum":
                assert isinstance(parameter, EnumParameter)
                assert set(rule.values) <= set(parameter.values)
            elif rule.kind == "text":
                assert isinstance(parameter, TextParameter)
                assert parameter.maximum >= (rule.maximum or 0)
            elif rule.kind == "vlan-list":
                assert isinstance(parameter, VlanListParameter)
                if rule.minimum is not None:
                    assert parameter.minimum <= rule.minimum
                if rule.maximum is not None:
                    assert parameter.maximum >= rule.maximum
                assert set(rule.reserved) <= set(parameter.reserved)


def test_target_class_constant_matches_grammar_vocabulary() -> None:
    assert {target.value for target in TargetClass} == {
        "device", "vlan", "interface", "port-channel",
    }
