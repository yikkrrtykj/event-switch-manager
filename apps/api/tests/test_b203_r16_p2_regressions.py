"""CIS-02B2-03 R16 permanent regressions for P2-01 and P2-02.

P2-01: physical-member / port-attribute command forms (channel-group, PoE,
speed, duplex) must not be accepted in a logical Port-Channel context; legal
Port-Channel switchport/description/admin/PortFast/BPDU-Guard sub-commands must
keep passing only when the frozen Renderer actually emits them and the reviewed
evidence applies.

P2-02: independent validation must resolve the exact-PID reviewed PortGroup and
apply PoE capability, PoE-static budget, copper medium and speed-rate gates.
"""

from __future__ import annotations

import dataclasses
from typing import Any
from uuid import uuid4

import pytest
from b203_corpus import deterministic_plan, render_plan
from test_l2_cli_candidates import full_plan
from test_layer2_intent import make_plan, make_stack_plan

from event_switch_manager.planning.command_evidence import CommandMode, CommandTopic
from event_switch_manager.planning.layer2_cli_candidates import (
    Candidate,
    CandidateCategory,
    CandidateStatus,
    L2CliCandidateDocument,
    SyntaxValidationLevel,
    TargetKind,
    _candidate_id,
)
from event_switch_manager.planning.layer2_cli_grammar import FORM_BY_ID, TargetClass
from event_switch_manager.planning.layer2_cli_parser import parse_command
from event_switch_manager.planning.layer2_cli_validation import (
    ExpectedSource,
    Verdict,
    _target_capability_report,
    recompute_candidate_fingerprint,
    recompute_render_fingerprint,
    validate_candidate_document,
)

FIELD_BY_TOPIC: dict[str, str] = {
    "vlan": "definition",
    "vlan-name": "name",
    "access-mode": "mode",
    "access-vlan": "access_vlan",
    "trunk-mode": "mode",
    "native-vlan": "native_vlan",
    "allowed-vlans": "allowed_vlans",
    "port-channel-interface": "interface",
    "channel-group-static": "member",
    "channel-group-lacp": "member",
    "rapid-pvst": "spanning-tree-mode",
    "vtp-transparent": "vtp-mode",
    "root-priority": "root-priority",
    "portfast": "portfast",
    "bpdu-guard": "bpdu_guard",
    "poe-mode": "poe_mode",
    "speed": "speed",
    "duplex": "duplex",
    "description": "description",
    "admin-shutdown": "admin_state",
}


def _find(
    document: L2CliCandidateDocument,
    *,
    category: str | None = None,
    status: CandidateStatus | None = None,
    text: str | None = None,
    target_kind: TargetKind | None = None,
    target_name: str | None = None,
) -> tuple[int, Candidate]:
    for index, candidate in enumerate(document.candidates):
        if category is not None and candidate.category.value != category:
            continue
        if status is not None and candidate.status is not status:
            continue
        if text is not None and candidate.candidate_text != text:
            continue
        if target_kind is not None and candidate.target.kind is not target_kind:
            continue
        if target_name is not None and candidate.target.name != target_name:
            continue
        return index, candidate
    raise AssertionError(
        f"candidate not found: category={category} status={status} text={text!r} "
        f"kind={target_kind} name={target_name}"
    )


def _settle(
    document: L2CliCandidateDocument,
    *,
    index: int | None = None,
    changes: dict[str, Any] | None = None,
    field: str | None = None,
    recompute_id: bool = False,
    device_changes: dict[str, Any] | None = None,
) -> L2CliCandidateDocument:
    candidates = list(document.candidates)
    if index is not None:
        changed = candidates[index].model_copy(update=changes or {})
        if recompute_id:
            assert field is not None
            changed = changed.model_copy(update={
                "candidate_id": _candidate_id(
                    document.assignment_id,
                    changed.category,
                    changed.target.kind,
                    changed.target.stable_id,
                    field,
                ),
            })
        changed = changed.model_copy(update={
            "candidate_fingerprint": recompute_candidate_fingerprint(changed),
        })
        candidates[index] = changed
    settled = document.model_copy(update={"candidates": tuple(candidates)})
    if device_changes is not None:
        settled = settled.model_copy(update={
            "device": settled.device.model_copy(update=device_changes),
        })
    return settled.model_copy(update={
        "render_fingerprint": recompute_render_fingerprint(settled),
    })


def _report(document: L2CliCandidateDocument) -> Any:
    return validate_candidate_document(document)


def _po1_target_context(
    document: L2CliCandidateDocument,
) -> tuple[Any, Any]:
    for candidate in document.candidates:
        if (
            candidate.status is CandidateStatus.CANDIDATE
            and candidate.target.kind is TargetKind.PORT_CHANNEL
            and candidate.target.name == "Port-channel1"
            and candidate.command_context.mode is CommandMode.PORT_CHANNEL
        ):
            return candidate.target, candidate.command_context
    raise AssertionError("real Renderer has no Port-channel1 sub-command context")


def _forge_to_port_channel(
    document: L2CliCandidateDocument,
    index: int,
    *,
    field: str,
    context_mode: CommandMode = CommandMode.PORT_CHANNEL,
) -> L2CliCandidateDocument:
    target, context = _po1_target_context(document)
    context = context.model_copy(update={
        "mode": context_mode,
        "mode_header": "interface Port-channel1",
        "target_name": "Port-channel1",
    })
    return _settle(
        document,
        index=index,
        field=field,
        recompute_id=True,
        changes={"target": target, "command_context": context},
    )


def _expected_from(document: L2CliCandidateDocument) -> ExpectedSource:
    return ExpectedSource(
        saved_revision_uuid=document.source.saved_revision_uuid,
        revision_number=document.source.revision_number,
        revision_canonical_hash=document.source.revision_canonical_hash,
        intent_fingerprint=document.source.intent_fingerprint,
        preview_fingerprint=document.source.preview_fingerprint,
        render_fingerprint=document.render_fingerprint,
        assignment_id=document.assignment_id,
    )


def _real(
    plan: dict[str, Any],
    *,
    categories: tuple[CandidateCategory, ...] | None = None,
) -> L2CliCandidateDocument:
    return render_plan(deterministic_plan(plan), categories=categories)


def _plan(
    pid: str = "C9300L-24P-4X",
    family: str = "catalyst-9300",
    image: str = "17.12.4",
    license_name: str | None = "Network Advantage",
    ports: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return make_plan(
        str(uuid4()), pid=pid, family=family, image=image,
        license_name=license_name,
        ports=ports or [{
            "name": "Gi1/0/1",
            "settings": {"mode": "access", "access_vlan": 20},
        }],
    )


def _poe_plan(
    pid: str = "C9300L-24P-4X", port: str = "Gi1/0/1", **settings: object,
) -> dict[str, Any]:
    return _plan(pid=pid, ports=[{
        "name": port,
        "settings": {"mode": "access", "access_vlan": 20, **settings},
    }])


# --------------------------------------------------------------------------- #
# P2-01: Grammar/context narrowing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("text", [
    "channel-group 1 mode on",
    "channel-group 1 mode active",
    "channel-group 1 mode passive",
    "power inline auto",
    "speed 1000",
    "duplex full",
])
def test_physical_only_forms_reject_port_channel_mode(text: str) -> None:
    assert parse_command(text, expected_mode=CommandMode.INTERFACE).ok
    rejected = parse_command(text, expected_mode=CommandMode.PORT_CHANNEL)
    assert not rejected.ok
    assert rejected.failure_codes == ("mode-mismatch",)


def test_grammar_forms_narrow_physical_only_topics() -> None:
    for form_id in (
        "channel-group-static", "channel-group-lacp", "poe-mode",
        "speed", "duplex",
    ):
        form = FORM_BY_ID[form_id]
        assert form.modes == frozenset({CommandMode.INTERFACE})
        assert form.target_classes == frozenset({TargetClass.INTERFACE})
    for form_id in ("access-mode", "access-vlan", "trunk-mode", "description"):
        form = FORM_BY_ID[form_id]
        assert CommandMode.PORT_CHANNEL in form.modes
        assert any(target.value == "port-channel" for target in form.target_classes)


_P2_01_CHANNEL_CASES: tuple[tuple[str, str, str], ...] = (
    ("active", "active", "channel-group 1 mode active"),
    ("passive", "passive", "channel-group 1 mode passive"),
    ("static", "static", "channel-group 1 mode on"),
)


@pytest.mark.parametrize(("label", "lacp", "text"), _P2_01_CHANNEL_CASES)
def test_forged_port_channel_channel_group_cannot_get_overall_pass(
    label: str, lacp: str, text: str,
) -> None:
    plan = full_plan(str(uuid4()), "9300")
    if lacp != "active":
        plan["port_channels"][0]["lacp"] = lacp
    document = _real(plan)
    category = "port-channel" if label == "static" else "lacp-mode"
    index, candidate = _find(
        document, category=category, status=CandidateStatus.CANDIDATE, text=text,
    )
    real_report = _report(document)
    assert real_report.summary.overall_status is Verdict.PASS
    assert real_report.candidates[index].independent_verdict is Verdict.PASS

    forged = _forge_to_port_channel(document, index, field="member")
    assert forged.candidates[index].candidate_fingerprint == (
        recompute_candidate_fingerprint(forged.candidates[index])
    )
    assert forged.render_fingerprint == recompute_render_fingerprint(forged)
    report = _report(forged)
    item = report.candidates[index]
    assert item.parse.status is Verdict.FAIL
    assert "mode-mismatch" in {failure.code for failure in item.parse.failures}
    assert item.scope.status.value == "not-run"
    assert item.independent_verdict is Verdict.FAIL
    assert report.summary.overall_status is Verdict.FAIL
    assert item.fail_closed_action == (
        "block-visible-candidate-until-independent-validation-passes"
    )
    trusted = validate_candidate_document(forged, expected=_expected_from(document))
    assert trusted.summary.overall_status is Verdict.FAIL
    assert trusted.integrity.status is Verdict.FAIL
    assert "expected-source-mismatch:render_fingerprint" in (
        trusted.integrity.failures
    )


@pytest.mark.parametrize(("text", "category", "field"), [
    ("power inline auto", "poe-mode", "poe_mode"),
    ("speed 1000", "speed", "speed"),
    ("duplex full", "duplex", "duplex"),
])
def test_forged_port_channel_port_attribute_commands_cannot_get_overall_pass(
    text: str, category: str, field: str,
) -> None:
    document = _real(full_plan(str(uuid4()), "9300"))
    index, _candidate = _find(
        document, category=category, status=CandidateStatus.CANDIDATE, text=text,
    )
    forged = _forge_to_port_channel(document, index, field=field)
    report = _report(forged)
    item = report.candidates[index]
    assert item.parse.status is Verdict.FAIL
    assert "mode-mismatch" in {failure.code for failure in item.parse.failures}
    assert item.independent_verdict is Verdict.FAIL
    assert report.summary.overall_status is Verdict.FAIL
    assert item.fail_closed_action is not None


def test_forged_interface_context_with_port_channel_target_is_caught() -> None:
    document = _real(full_plan(str(uuid4()), "9300"))
    index, _candidate = _find(
        document, category="lacp-mode", status=CandidateStatus.CANDIDATE,
        text="channel-group 1 mode active",
    )
    forged = _forge_to_port_channel(
        document, index, field="member", context_mode=CommandMode.INTERFACE,
    )
    report = _report(forged)
    item = report.candidates[index]
    assert item.parse.status is Verdict.PASS
    assert item.context_binding.status is Verdict.FAIL
    assert any(
        reason.startswith("context-target-not-reviewed:")
        or reason.startswith("evidence-command-mode-context-mismatch:")
        for reason in item.context_binding.reasons
    )
    assert item.target_capability.status is Verdict.NOT_RUN
    assert item.semantics.status is Verdict.FAIL
    assert item.independent_verdict is Verdict.FAIL
    assert report.summary.overall_status is Verdict.FAIL


def test_legal_port_channel_subcommands_keep_passing() -> None:
    access_doc = _real(full_plan(str(uuid4()), "9300"))
    access_report = _report(access_doc)
    asserting = 0
    for index, candidate in enumerate(access_doc.candidates):
        if (
            candidate.status is CandidateStatus.CANDIDATE
            and candidate.target.kind is TargetKind.PORT_CHANNEL
            and candidate.target.name == "Port-channel1"
            and candidate.category.value in {
                "access-mode", "access-vlan", "port-channel",
            }
        ):
            asserting += 1
            item = access_report.candidates[index]
            assert item.context_binding.status is Verdict.PASS
            assert item.context_binding.reviewed_command_mode in {
                "interface", "global",
            }
            if candidate.category.value != "port-channel":
                assert item.context_binding.port_channel_exception_applied is True
            assert item.target_capability.status is Verdict.NOT_RUN
            assert item.independent_verdict is Verdict.PASS
    assert asserting >= 3
    # Renderer policy blocks these Po1 sub-commands; validation must not promote.
    for index, candidate in enumerate(access_doc.candidates):
        if (
            candidate.target.kind is TargetKind.PORT_CHANNEL
            and candidate.category.value in {
                "admin-shutdown", "portfast", "bpdu-guard",
            }
        ):
            assert candidate.status is not CandidateStatus.CANDIDATE
            assert candidate.candidate_text is None
            assert access_report.candidates[index].independent_verdict is not (
                Verdict.PASS
            )

    trunk_plan = full_plan(str(uuid4()), "9300")
    trunk_plan["port_channels"][0]["settings"] = {
        "mode": "trunk", "native_vlan": 10, "allowed_vlans": [10, 20, 30],
    }
    trunk_doc = _real(trunk_plan)
    trunk_report = _report(trunk_doc)
    trunk_asserting = 0
    for index, candidate in enumerate(trunk_doc.candidates):
        if (
            candidate.status is CandidateStatus.CANDIDATE
            and candidate.target.kind is TargetKind.PORT_CHANNEL
            and candidate.category.value in {"trunk-mode", "allowed-vlans"}
        ):
            trunk_asserting += 1
            assert trunk_report.candidates[index].independent_verdict is (
                Verdict.PASS
            )
            assert trunk_report.candidates[index].context_binding.status is (
                Verdict.PASS
            )
    assert trunk_asserting == 2

    # 2960X Po1 description is a real Renderer candidate and must stay PASS.
    plan_2960 = full_plan(str(uuid4()), "2960x")
    plan_2960["port_channels"][0]["settings"] = {
        "mode": "access", "access_vlan": 20,
        "description": "Aggregate uplink", "admin_state": "up",
    }
    doc_2960 = _real(plan_2960)
    report_2960 = _report(doc_2960)
    description_candidates = [
        (index, candidate) for index, candidate in enumerate(doc_2960.candidates)
        if candidate.status is CandidateStatus.CANDIDATE
        and candidate.target.kind is TargetKind.PORT_CHANNEL
        and candidate.category.value == "description"
    ]
    assert description_candidates
    for index, candidate in description_candidates:
        assert candidate.candidate_text is not None
        assert report_2960.candidates[index].context_binding.status is (
            Verdict.PASS
        )
        assert report_2960.candidates[index].independent_verdict is Verdict.PASS


def test_category_filter_cannot_hide_port_channel_context_error() -> None:
    plan = full_plan(str(uuid4()), "9300")
    filtered = _real(plan, categories=(CandidateCategory.LACP_MODE,))
    filtered_report = _report(filtered)
    assert filtered_report.summary.overall_status is Verdict.PASS
    index = next(
        i for i, candidate in enumerate(filtered.candidates)
        if candidate.status is CandidateStatus.CANDIDATE
    )
    source = filtered.candidates[index]
    target = source.target.model_copy(update={
        "kind": TargetKind.PORT_CHANNEL,
        "name": "Port-channel1",
        "stable_id": str(uuid4()),
    })
    context = source.command_context.model_copy(update={
        "mode": CommandMode.PORT_CHANNEL,
        "mode_header": "interface Port-channel1",
        "target_name": "Port-channel1",
    })
    forged = _settle(
        filtered, index=index, field="member", recompute_id=True,
        changes={"target": target, "command_context": context},
    )
    report = _report(forged)
    assert report.candidates[index].independent_verdict is Verdict.FAIL
    assert report.summary.overall_status is Verdict.FAIL


# --------------------------------------------------------------------------- #
# P2-02: exact-PID PortGroup capability / medium / rates
# --------------------------------------------------------------------------- #


def test_poe_capable_copper_positive_control_passes() -> None:
    document = _real(_poe_plan("C9300L-24P-4X", poe_mode="auto"))
    index, _candidate = _find(
        document, category="poe-mode", status=CandidateStatus.CANDIDATE,
        text="power inline auto",
    )
    report = _report(document)
    item = report.candidates[index]
    assert item.independent_verdict is Verdict.PASS
    assert item.target_capability.status is Verdict.PASS
    assert item.target_capability.applicable is True
    assert item.target_capability.port_group is not None
    assert item.target_capability.port_group.poe_plus is True
    assert item.target_capability.port_group.medium == "copper-rj45"
    assert report.summary.overall_status is Verdict.PASS


def test_non_poe_same_family_pid_cannot_inherit_poe() -> None:
    document = _real(_poe_plan("C9300L-24P-4X", poe_mode="auto"))
    index, _candidate = _find(
        document, category="poe-mode", status=CandidateStatus.CANDIDATE,
        text="power inline auto",
    )
    forged = _settle(
        document, device_changes={"exact_pid": "C9300L-24T-4G"},
    )
    report = _report(forged)
    item = report.candidates[index]
    assert item.independent_verdict is Verdict.FAIL
    assert item.target_capability.status is Verdict.FAIL
    assert any(
        reason.startswith("target-port-not-poe-capable:")
        for reason in item.target_capability.reasons
    )
    assert report.summary.overall_status is Verdict.FAIL
    assert report.summary.capability_fail == 1


def test_sfp_uplink_cannot_get_poe_capability_pass() -> None:
    document = _real(_poe_plan("C9300L-24P-4X", poe_mode="auto"))
    index, _candidate = _find(
        document, category="poe-mode", status=CandidateStatus.CANDIDATE,
        text="power inline auto",
    )
    target = document.candidates[index].target.model_copy(update={
        "name": "Te1/1/1", "stable_id": str(uuid4()),
    })
    context = document.candidates[index].command_context.model_copy(update={
        "target_name": "Te1/1/1", "mode_header": "interface Te1/1/1",
    })
    forged = _settle(
        document, index=index, field="poe_mode", recompute_id=True,
        changes={"target": target, "command_context": context},
    )
    report = _report(forged)
    item = report.candidates[index]
    assert item.target_capability.status is Verdict.FAIL
    assert any(
        reason.startswith("target-port-not-poe-capable:")
        for reason in item.target_capability.reasons
    )
    assert item.independent_verdict is Verdict.FAIL
    assert report.summary.overall_status is Verdict.FAIL


def test_poe_static_fails_closed_without_budget_evidence() -> None:
    # Real Renderer never emits a static PoE candidate; it is blocked.
    real_static = _real(_poe_plan("C9300L-24P-4X", poe_mode="static"))
    real_report = _report(real_static)
    static_records = [
        candidate for candidate in real_static.candidates
        if candidate.category.value == "poe-mode"
    ]
    assert static_records
    assert all(
        candidate.status is not CandidateStatus.CANDIDATE
        for candidate in static_records
    )
    assert real_report.summary.overall_status is Verdict.PASS

    auto_doc = _real(_poe_plan("C9300L-24P-4X", poe_mode="auto"))
    index, _candidate = _find(
        auto_doc, category="poe-mode", status=CandidateStatus.CANDIDATE,
        text="power inline auto",
    )
    forged = _settle(
        auto_doc, index=index, field="poe_mode", recompute_id=True,
        changes={
            "candidate_text": "power inline static",
            "parameters": {"poe-mode": "static"},
        },
    )
    report = _report(forged)
    item = report.candidates[index]
    assert item.parse.status is Verdict.PASS
    assert item.target_capability.status is Verdict.FAIL
    assert "poe-static-budget-evidence-required" in (
        item.target_capability.reasons
    )
    assert item.independent_verdict is Verdict.FAIL
    assert report.summary.overall_status is Verdict.FAIL


@pytest.mark.parametrize(("mode", "expected"), [("never", Verdict.PASS), ("auto", Verdict.PASS)])
def test_poe_never_and_auto_on_capable_port_pass(
    mode: str, expected: Verdict,
) -> None:
    document = _real(_poe_plan("C9300L-24P-4X", poe_mode=mode))
    index, _candidate = _find(
        document, category="poe-mode", status=CandidateStatus.CANDIDATE,
        text=f"power inline {mode}",
    )
    item = _report(document).candidates[index]
    assert item.target_capability.status is expected
    assert item.independent_verdict is expected


def test_poe_never_on_non_poe_and_sfp_fails() -> None:
    document = _real(_poe_plan("C9300L-24P-4X", poe_mode="never"))
    index, _candidate = _find(
        document, category="poe-mode", status=CandidateStatus.CANDIDATE,
        text="power inline never",
    )
    forged_pid = _settle(document, device_changes={"exact_pid": "C9300L-24T-4G"})
    assert _report(forged_pid).candidates[index].target_capability.status is (
        Verdict.FAIL
    )
    target = document.candidates[index].target.model_copy(update={
        "name": "Te1/1/1", "stable_id": str(uuid4()),
    })
    context = document.candidates[index].command_context.model_copy(update={
        "target_name": "Te1/1/1", "mode_header": "interface Te1/1/1",
    })
    forged_sfp = _settle(
        document, index=index, field="poe_mode", recompute_id=True,
        changes={"target": target, "command_context": context},
    )
    assert _report(forged_sfp).candidates[index].target_capability.status is (
        Verdict.FAIL
    )


def test_speed_duplex_copper_positive_and_sfp_negative() -> None:
    document = _real(_poe_plan(
        "C9300L-24P-4X", speed=1000, duplex="full",
    ))
    report = _report(document)
    for category, text in (("speed", "speed 1000"), ("duplex", "duplex full")):
        index, _candidate = _find(
            document, category=category, status=CandidateStatus.CANDIDATE,
            text=text,
        )
        item = report.candidates[index]
        assert item.target_capability.status is Verdict.PASS
        assert item.target_capability.port_group is not None
        assert item.target_capability.port_group.medium == "copper-rj45"
        assert item.independent_verdict is Verdict.PASS

        target = document.candidates[index].target.model_copy(update={
            "name": "Te1/1/1", "stable_id": str(uuid4()),
        })
        context = document.candidates[index].command_context.model_copy(update={
            "target_name": "Te1/1/1", "mode_header": "interface Te1/1/1",
        })
        forged = _settle(
            document, index=index, field=category, recompute_id=True,
            changes={"target": target, "command_context": context},
        )
        forged_item = _report(forged).candidates[index]
        assert forged_item.target_capability.status is Verdict.FAIL
        assert any(
            reason.startswith("target-port-not-copper:")
            for reason in forged_item.target_capability.reasons
        )
        assert forged_item.independent_verdict is Verdict.FAIL


def test_speed_rate_gate_is_applied_independently() -> None:
    document = _real(_poe_plan("C9300L-24P-4X", speed=1000))
    index, candidate = _find(
        document, category="speed", status=CandidateStatus.CANDIDATE,
        text="speed 1000",
    )
    parsed = parse_command("speed 1000").command
    assert parsed is not None
    # Defensive rate gate: the current reviewed grammar enum never exposes a
    # value outside copper rates, so exercise the gate directly with a parsed
    # parameter value to prove it is not a no-op.
    synthetic = dataclasses.replace(
        parsed, parameters={"speed": "10000"},
    )
    capability = _target_capability_report(
        candidate, synthetic, CommandTopic.SPEED, document.device,
    )
    assert capability.status is Verdict.FAIL
    assert any(
        reason.startswith("speed-not-in-port-rates:10000:")
        for reason in capability.reasons
    )


@pytest.mark.parametrize(("family", "pid", "image", "license_name", "sibling"), [
    ("catalyst-2960x", "WS-C2960X-24PS-L", "15.2(7)E", "LAN Base",
     "WS-C2960X-24TS-L"),
    ("catalyst-3850", "WS-C3850-24P", "16.12.12", "IP Base",
     "WS-C3850-24T"),
    ("catalyst-9200", "C9200L-24P-4X", "17.12.4", "Network Advantage",
     "C9200L-24T-4G"),
    ("catalyst-9300", "C9300L-24P-4X", "17.12.4", "Network Advantage",
     "C9300L-24T-4G"),
    ("catalyst-c1000", "C1000-24P-4G-L", "15.2(7)E1", None,
     "C1000-24T-4G-L"),
])
def test_exact_pid_poe_capability_never_inherits_across_models(
    family: str, pid: str, image: str, license_name: str | None, sibling: str,
) -> None:
    plan = _plan(
        pid=pid, family=family, image=image, license_name=license_name,
        ports=[{
            "name": "Gi1/0/1",
            "settings": {"mode": "access", "access_vlan": 20, "poe_mode": "auto"},
        }],
    )
    document = _real(plan)
    index, _candidate = _find(
        document, category="poe-mode", status=CandidateStatus.CANDIDATE,
        text="power inline auto",
    )
    positive = _report(document)
    assert positive.candidates[index].target_capability.status is Verdict.PASS
    assert positive.candidates[index].target_capability.port_group is not None
    assert positive.candidates[index].target_capability.port_group.poe_plus

    forged = _settle(document, device_changes={"exact_pid": sibling})
    report = _report(forged)
    item = report.candidates[index]
    assert item.target_capability.status is Verdict.FAIL
    assert any(
        reason.startswith("target-port-not-poe-capable:")
        for reason in item.target_capability.reasons
    )
    assert item.independent_verdict is Verdict.FAIL
    assert report.summary.overall_status is Verdict.FAIL


def test_unknown_pid_and_unknown_port_group_fail_closed() -> None:
    document = _real(_poe_plan("C9300L-24P-4X", poe_mode="auto"))
    index, _candidate = _find(
        document, category="poe-mode", status=CandidateStatus.CANDIDATE,
        text="power inline auto",
    )
    unknown_pid = _settle(
        document, device_changes={"exact_pid": "C9300L-24P-4Z"},
    )
    report_unknown_pid = _report(unknown_pid)
    assert report_unknown_pid.candidates[index].target_capability.status is (
        Verdict.FAIL
    )
    assert any(
        reason.startswith("target-capability-pid-unknown:")
        for reason in report_unknown_pid.candidates[index].target_capability.reasons
    )
    assert report_unknown_pid.summary.overall_status is Verdict.FAIL

    target = document.candidates[index].target.model_copy(update={"name": "Gi9/9/9"})
    context = document.candidates[index].command_context.model_copy(update={
        "target_name": "Gi9/9/9", "mode_header": "interface Gi9/9/9",
    })
    unknown_layout = _settle(
        document, index=index, field="poe_mode", recompute_id=True,
        changes={"target": target, "command_context": context},
    )
    report_layout = _report(unknown_layout)
    assert report_layout.candidates[index].target_capability.status is (
        Verdict.FAIL
    )
    assert any(
        reason.startswith("target-capability-")
        for reason in report_layout.candidates[index].target_capability.reasons
    )
    assert report_layout.summary.overall_status is Verdict.FAIL


def test_resolved_stack_member_capability_and_invalid_member() -> None:
    plan = make_stack_plan(str(uuid4()))
    plan["physical_interfaces"][0]["settings"] = {
        "mode": "access", "access_vlan": 20, "poe_mode": "auto",
    }
    document = _real(plan)
    index, candidate = _find(
        document, category="poe-mode", status=CandidateStatus.CANDIDATE,
        text="power inline auto",
    )
    report = _report(document)
    assert report.candidates[index].target_capability.status is Verdict.PASS

    target = candidate.target.model_copy(update={
        "name": "Gi9/0/1", "stable_id": str(uuid4()),
    })
    context = candidate.command_context.model_copy(update={
        "target_name": "Gi9/0/1", "mode_header": "interface Gi9/0/1",
    })
    forged = _settle(
        document, index=index, field="poe_mode", recompute_id=True,
        changes={"target": target, "command_context": context},
    )
    report_forged = _report(forged)
    assert report_forged.candidates[index].target_capability.status is (
        Verdict.FAIL
    )
    assert report_forged.summary.overall_status is Verdict.FAIL


_REAL_BLOCKED_CASES: tuple[tuple[str, str, str], ...] = (
    ("non-poe 24T", "C9300L-24T-4G", "Gi1/0/1"),
    ("sfp+ poe", "C9300L-24P-4X", "Te1/1/1"),
    ("poe static", "C9300L-24P-4X", "Gi1/0/1"),
)


@pytest.mark.parametrize(("label", "pid", "port"), _REAL_BLOCKED_CASES)
def test_real_renderer_blocked_poe_records_are_unchanged(
    label: str, pid: str, port: str,
) -> None:
    settings: dict[str, object] = {"poe_mode": "auto"}
    if label == "poe static":
        settings = {"poe_mode": "static"}
    plan = _plan(
        pid=pid,
        ports=[{"name": port, "settings": {"mode": "access", **settings}}],
    )
    document = _real(plan)
    report = _report(document)
    assert report.summary.overall_status is Verdict.PASS
    records = [
        candidate for candidate in document.candidates
        if candidate.category.value == "poe-mode"
    ]
    assert records
    for candidate in records:
        if candidate.status is not CandidateStatus.CANDIDATE:
            assert candidate.candidate_text is None
            assert candidate.syntax_validation.level is (
                SyntaxValidationLevel.NOT_RUN
            )
    # No new text may be generated for the Renderer-blocked combinations.
    assert all(
        candidate.candidate_text is None for candidate in records
    )


def test_real_renderer_blocked_sfp_speed_duplex_are_unchanged() -> None:
    plan = _plan(
        pid="C9300L-24P-4X",
        ports=[{
            "name": "Te1/1/1",
            "settings": {
                "mode": "access", "access_vlan": 20,
                "speed": 1000, "duplex": "full",
            },
        }],
    )
    document = _real(plan)
    report = _report(document)
    assert report.summary.overall_status is Verdict.PASS
    for category in ("speed", "duplex"):
        records = [
            candidate for candidate in document.candidates
            if candidate.category.value == category
        ]
        assert records
        for candidate in records:
            assert candidate.status is not CandidateStatus.CANDIDATE
            assert candidate.candidate_text is None
