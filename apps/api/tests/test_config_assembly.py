"""CIS-04 Device Configuration Assembly contract and API tests."""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from layer3_helpers import make_l3_plan, revision_for
from test_event_plans import API, ORIGIN

from event_switch_manager.app import create_app
from event_switch_manager.config_assembly_api import ASSEMBLY_SCOPE_HEADER
from event_switch_manager.planning.config_assembly import (
    ASSEMBLY_CONTRACT_ID,
    SECTION_CAPABILITY_MATRIX,
    SECTION_IDS,
    AssemblySection,
    AssemblySectionStatus,
    ConfigurationAssembly,
    assembly_fingerprint,
    evaluate_cross_layer_checks,
)
from event_switch_manager.planning.layer2_cli_candidates import (
    build_l2_cli_candidates,
)
from event_switch_manager.planning.layer2_cli_validation import (
    ExpectedSource as L2ExpectedSource,
)
from event_switch_manager.planning.layer2_cli_validation import (
    validate_candidate_document,
)
from event_switch_manager.planning.layer2_config_preview import (
    build_device_layer2_config_preview,
)
from event_switch_manager.planning.layer2_intent import (
    DeviceLayer2Intent,
    PortChannelIntent,
    PortChannelSettingsIntent,
    build_layer2_intent,
)
from event_switch_manager.planning.layer3_cli_candidates import (
    build_l3_cli_candidates,
)
from event_switch_manager.planning.layer3_cli_validation import (
    ExpectedSource as L3ExpectedSource,
)
from event_switch_manager.planning.layer3_cli_validation import (
    validate_l3_candidates,
)
from event_switch_manager.planning.layer3_intent import build_layer3_intent
from event_switch_manager.planning.layer3_registry_selection import select_l3_registry
from event_switch_manager.settings import Settings

ASSEMBLY_PATH = (
    API + "/events/{event}/plan-revisions/{revision}/assignments/"
    "{assignment}/config-assembly-preview"
)
C9200_REVIEWED_REGISTRY_ID = "cis-03-c9200-l3-command-evidence-v1"
C9200_REVIEWED_REGISTRY_FINGERPRINT = (
    "2c73c8b39100622360c6bfab935d995d8fb884dd999b6df0ae744a7be7cec876"
)
C9300_REGISTRY_FINGERPRINT = (
    "27d9c46f610b974de5570fb13e115260e2d109475a8d967704de9bb9ca6ef00b"
)
UNREVIEWED_REGISTRY_ID = "cis-03-l1-command-evidence-unreviewed-v1"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(
        create_app(Settings(database_path=tmp_path / "assembly.sqlite3")),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN},
    ) as session:
        yield session


def _event(client: TestClient, name: str) -> str:
    response = client.post(API + "/events", json={"name": name, "management_vlan": 10})
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _save(
    client: TestClient, event_id: str, plan: dict[str, Any],
) -> dict[str, Any]:
    response = client.post(
        API + f"/events/{event_id}/plan-revisions", json=plan,
    )
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def _assignment(plan: dict[str, Any], hostname: str = "L3-Core") -> str:
    return str(next(
        item["id"] for item in plan["assignments"]
        if item["hostname"] == hostname
    ))


def _unique_serials(plan: dict[str, Any], tag: str) -> None:
    for index, device in enumerate(plan["physical_devices"]):
        device["verified_serial"] = f"{tag}-{index}"


def c9200_candidate_plan(event_id: str) -> dict[str, Any]:
    plan = make_l3_plan(
        event_id,
        core_pid="C9200L-24P-4X",
        core_family="catalyst-9200",
        core_image="17.12.4",
        core_license="Network Advantage",
        with_relay=False,
        with_default=False,
        static_route_count=1,
    )
    core = next(
        item for item in plan["assignments"] if item["hostname"] == "L3-Core"
    )
    plan["transit"] = None
    plan["default_routes"] = []
    plan["static_routes"] = [
        route for route in plan["static_routes"]
        if route["assignment_id"] == core["id"]
    ]
    for route in plan["static_routes"]:
        route["next_hop"] = {"kind": "ip", "address": "192.168.10.2"}
    return plan


def _assembly(
    client: TestClient,
    event_id: str,
    revision: dict[str, Any],
    assignment_id: str,
) -> ConfigurationAssembly:
    response = client.get(ASSEMBLY_PATH.format(
        event=event_id, revision=revision["id"], assignment=assignment_id,
    ))
    assert response.status_code == 200, response.text
    assert response.headers[ASSEMBLY_SCOPE_HEADER] == "full"
    return ConfigurationAssembly.model_validate(response.json())


def _l3_report(
    client: TestClient,
    event_id: str,
    revision: dict[str, Any],
    assignment_id: str,
) -> dict[str, Any]:
    response = client.get(
        API + f"/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{assignment_id}/l3-cli-validation",
    )
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def _l2_report(
    client: TestClient,
    event_id: str,
    revision: dict[str, Any],
    assignment_id: str,
) -> dict[str, Any]:
    response = client.get(
        API + f"/events/{event_id}/plan-revisions/{revision['id']}"
        f"/assignments/{assignment_id}/l2-cli-validation",
    )
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def _section(
    assembly: ConfigurationAssembly, section_id: str,
) -> AssemblySection:
    return next(item for item in assembly.sections if item.section_id == section_id)


def _l3_section_totals(assembly: ConfigurationAssembly) -> tuple[int, int, int]:
    section_ids = {"ip-routing", "svi", "routes", "dhcp"}
    selected = [item for item in assembly.sections if item.section_id in section_ids]
    return (
        sum(item.candidate_count for item in selected),
        sum(item.passed_count for item in selected),
        sum(item.blocked_count for item in selected),
    )


def test_capability_gap_matrix_drives_not_implemented_chapters() -> None:
    assert set(SECTION_CAPABILITY_MATRIX) == set(SECTION_IDS)
    assert SECTION_CAPABILITY_MATRIX["management-auth-ssh"] == (
        "CIS-03/CIS-04B", True,
    )
    assert SECTION_CAPABILITY_MATRIX["snmp-syslog-ntp"] == ("CIS-03", False)
    assert all(
        implemented
        for section_id, (_, implemented) in SECTION_CAPABILITY_MATRIX.items()
        if section_id != "snmp-syslog-ntp"
    )


def test_c9300_assembly_sections_cross_checks_and_no_full_config(client: TestClient) -> None:
    event_id = _event(client, "C9300 assembly")
    plan = make_l3_plan(event_id, static_route_count=1)
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    assembly = _assembly(client, event_id, revision, assignment_id)

    assert assembly.contract_id == ASSEMBLY_CONTRACT_ID
    assert assembly.source.event_id == UUID(event_id)
    assert assembly.source.revision_id == UUID(revision["id"])
    assert assembly.source.revision_canonical_hash == revision["content_hash"]
    assert assembly.source.assignment_id == UUID(assignment_id)
    assert len(assembly.sections) == len(SECTION_IDS)
    assert assembly.completeness.complete is False
    assert assembly.safety.full_config_generated is False
    assert assembly.safety.executable is False
    assert assembly.full_config_generated is False

    l3 = _l3_report(client, event_id, revision, assignment_id)
    assert l3["source"]["command_evidence_registry_fingerprint"] == (
        C9300_REGISTRY_FINGERPRINT
    )
    assert l3["summary"]["passed"] == 9
    assert l3["summary"]["blocked"] == 1
    assert assembly.source.l3_render_fingerprint == l3["source"]["l3_render_fingerprint"]
    assert assembly.source.l3_validation_fingerprint == l3["report_fingerprint"]
    l2 = _l2_report(client, event_id, revision, assignment_id)
    assert assembly.source.l2_render_fingerprint == l2["source"]["render_fingerprint"]
    assert assembly.source.l2_validation_fingerprint == l2["report_fingerprint"]
    source_candidate_fingerprints = {
        *assembly.source.l2_candidate_fingerprints,
        *assembly.source.l3_candidate_fingerprints,
    }
    section_candidate_fingerprints = {
        candidate.candidate_fingerprint
        for section in assembly.sections for candidate in section.candidates
    }
    assert source_candidate_fingerprints
    assert source_candidate_fingerprints == section_candidate_fingerprints

    total, passed, blocked = _l3_section_totals(assembly)
    assert (total, passed, blocked) == (10, 9, 1)
    assert _section(assembly, "ip-routing").status is (
        AssemblySectionStatus.VALIDATED_SECTION
    )
    assert _section(assembly, "svi").status is AssemblySectionStatus.VALIDATED_SECTION
    assert _section(assembly, "routes").status is AssemblySectionStatus.VALIDATED_SECTION
    assert _section(assembly, "dhcp").status is AssemblySectionStatus.BLOCKED
    management = _section(assembly, "management-auth-ssh")
    assert management.status is AssemblySectionStatus.BLOCKED
    assert management.required is True
    assert management.missing_count == 1
    assert "management-evidence-pending" in management.reason_codes
    assert management.evidence_references
    assert "management-auth-ssh" in assembly.completeness.missing_features
    assert len(assembly.cross_layer_checks) == 11
    assert all(item.check_id for item in assembly.cross_layer_checks)
    assert any(item.check_id == "dhcp-relay-issue-30" for item in assembly.cross_layer_checks)

    raw = assembly.model_dump(mode="json")
    assert "cli" in raw and raw["cli"] is None
    assert "execution_order" not in raw
    assert "sequence" not in raw
    assert "commands" not in raw
    assert assembly.assembly_fingerprint == assembly_fingerprint(assembly)
    for section in assembly.sections:
        for candidate in section.candidates:
            if candidate.candidate_text is not None:
                assert candidate.status == "candidate"
                assert candidate.verdict == "pass"
                assert "\n" not in candidate.candidate_text
                assert "\r" not in candidate.candidate_text


def test_c9200_candidate_assembly_retains_registry_and_six_two_counts(
    client: TestClient,
) -> None:
    event_id = _event(client, "C9200 assembly")
    plan = c9200_candidate_plan(event_id)
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    assembly = _assembly(client, event_id, revision, assignment_id)
    l3 = _l3_report(client, event_id, revision, assignment_id)

    assert l3["summary"]["passed"] == 6
    assert l3["summary"]["failed"] == 0
    assert l3["summary"]["blocked"] == 2
    assert assembly.source.l3_command_evidence_registry_id == (
        C9200_REVIEWED_REGISTRY_ID
    )
    assert assembly.source.l3_command_evidence_registry_fingerprint == (
        C9200_REVIEWED_REGISTRY_FINGERPRINT
    )
    total, passed, blocked = _l3_section_totals(assembly)
    assert (total, passed, blocked) == (8, 6, 2)
    assert _section(assembly, "ip-routing").status is (
        AssemblySectionStatus.VALIDATED_SECTION
    )
    assert _section(assembly, "svi").status is AssemblySectionStatus.PARTIAL
    assert _section(assembly, "svi").passed_count == 4
    assert _section(assembly, "svi").blocked_count == 2
    assert _section(assembly, "routes").status is AssemblySectionStatus.VALIDATED_SECTION
    assert _section(assembly, "dhcp").status is AssemblySectionStatus.NOT_APPLICABLE
    assert assembly.completeness.complete is False
    assert assembly.full_config_generated is False

    rendered = [
        (candidate.category, candidate.candidate_text)
        for section in assembly.sections
        for candidate in section.candidates
        if candidate.candidate_text is not None
    ]
    assert {category for category, _ in rendered} >= {
        "ip-routing", "svi-interface", "svi-address", "static-route",
    }
    assert any(text == "ip routing" for _, text in rendered)
    assert any(text.startswith("interface Vlan") for _, text in rendered)
    assert any(text.startswith("ip address ") for _, text in rendered)
    assert any(text.startswith("ip route ") for _, text in rendered)
    for section in assembly.sections:
        for candidate in section.candidates:
            if candidate.category == "default-route":
                assert candidate.candidate_text is None
            if candidate.candidate_text is not None:
                assert candidate.verdict == "pass"


def test_c9200_default_route_plan_is_blocked_and_not_full_config(
    client: TestClient,
) -> None:
    event_id = _event(client, "C9200 default route assembly")
    plan = make_l3_plan(
        event_id,
        core_pid="C9200L-24P-4X",
        core_family="catalyst-9200",
        core_image="17.12.4",
        core_license="Network Advantage",
        with_relay=True,
        static_route_count=1,
    )
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    assembly = _assembly(client, event_id, revision, assignment_id)

    routes = _section(assembly, "routes")
    assert routes.status is AssemblySectionStatus.BLOCKED
    assert any(candidate.category == "default-route" for candidate in routes.candidates)
    assert all(
        candidate.candidate_text is None
        for candidate in routes.candidates
        if candidate.category == "default-route"
    )
    default_check = next(
        item for item in assembly.cross_layer_checks
        if item.check_id == "default-route-evidence-gate"
    )
    assert default_check.status.value == "FAIL"
    assert "default-route-not-evidence-approved" in default_check.reason_codes
    assert assembly.completeness.complete is False


def test_non_core_assignment_has_no_l3_pass_and_does_not_boost_completeness(
    client: TestClient,
) -> None:
    event_id = _event(client, "non-core assembly")
    plan = make_l3_plan(event_id, static_route_count=1)
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan, "L3-Access")
    assembly = _assembly(client, event_id, revision, assignment_id)

    assert _section(assembly, "ip-routing").status is (
        AssemblySectionStatus.NOT_APPLICABLE
    )
    assert _section(assembly, "svi").status is AssemblySectionStatus.NOT_APPLICABLE
    assert _section(assembly, "routes").status is AssemblySectionStatus.NOT_APPLICABLE
    assert _section(assembly, "management-auth-ssh").status is (
        AssemblySectionStatus.BLOCKED
    )
    assert _l3_section_totals(assembly) == (0, 0, 0)
    assert assembly.completeness.complete is False
    assert all(
        candidate.candidate_text is None
        for section in assembly.sections
        if section.section_id in {"ip-routing", "svi", "routes", "dhcp"}
        for candidate in section.candidates
    )


@pytest.mark.parametrize(
    ("pid", "family", "image", "license"),
    (
        ("WS-C2960X-24TS-L", "catalyst-2960x", "15.2(7)E", "LAN Base"),
        ("WS-C3850-24T", "catalyst-3850", "16.12.12", "IP Base"),
        ("C1000-24T-4G-L", "catalyst-c1000", "15.2(7)E1", "LAN Base"),
        ("C1000-16T-2G-L", "catalyst-c1000", "15.2(7)E2", None),
        ("C9200L-24P-4X", "catalyst-9200", "17.12.5", "Network Advantage"),
    ),
)
def test_unsupported_or_unknown_platform_does_not_inherit_validated_cli(
    client: TestClient, pid: str, family: str, image: str, license: str,
) -> None:
    event_id = _event(client, f"unsupported {family} {image}")
    plan = make_l3_plan(
        event_id, core_pid=pid, core_family=family, core_image=image,
        core_license=license, with_relay=False, static_route_count=1,
    )
    _unique_serials(plan, f"unsupported-{pid}")
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    assembly = _assembly(client, event_id, revision, assignment_id)

    assert assembly.source.l3_command_evidence_registry_id == UNREVIEWED_REGISTRY_ID
    assert assembly.completeness.complete is False
    assert all(
        candidate.candidate_text is None
        for section in assembly.sections
        for candidate in section.candidates
    )
    assert any(
        section.section_id in {"ip-routing", "svi", "routes"}
        and section.status is AssemblySectionStatus.BLOCKED
        for section in assembly.sections
    )


def test_assembly_rejects_undeclared_input_and_cross_scope_ids(
    client: TestClient,
) -> None:
    event_a = _event(client, "assembly scope A")
    plan_a = make_l3_plan(event_a, static_route_count=1)
    revision_a = _save(client, event_a, plan_a)
    assignment_a = _assignment(plan_a)
    url = ASSEMBLY_PATH.format(
        event=event_a, revision=revision_a["id"], assignment=assignment_a,
    )
    assert client.get(url + "?registry_id=reviewed").status_code == 400
    assert client.post(url, json={}).status_code == 405
    assert client.request("GET", url, json={"candidate": "ip routing"}).status_code == 400

    event_b = _event(client, "assembly scope B")
    plan_b = make_l3_plan(event_b, static_route_count=1)
    _unique_serials(plan_b, "scope-b")
    revision_b = _save(client, event_b, plan_b)
    assert client.get(ASSEMBLY_PATH.format(
        event=event_b, revision=revision_a["id"], assignment=assignment_a,
    )).status_code == 404
    assert client.get(ASSEMBLY_PATH.format(
        event=event_a, revision=revision_b["id"], assignment=assignment_a,
    )).status_code == 404
    assert client.get(ASSEMBLY_PATH.format(
        event=event_a, revision=revision_a["id"], assignment=str(uuid4()),
    )).status_code == 404
    hillstone_assignment = _assignment(plan_a, "L3-FW")
    response = client.get(ASSEMBLY_PATH.format(
        event=event_a, revision=revision_a["id"], assignment=hillstone_assignment,
    ))
    assert response.status_code == 409
    assert response.json()["detail"]["reason_code"] == "assignment-is-not-cisco"


def test_cross_layer_checks_fail_for_mutated_svi_and_route(
    client: TestClient,
) -> None:
    event_id = _event(client, "cross-layer mutation")
    plan = make_l3_plan(event_id, static_route_count=1)
    assignment_id = _assignment(plan)
    bundle = _trusted_bundle(plan, assignment_id)
    l2_device = bundle["l2_device"]
    l3_device = bundle["l3_device"]

    first_interface = l3_device.interfaces[0]
    bad_interface = first_interface.model_copy(update={
        "vlan": 99, "name": "Vlan99",
    })
    mutated_l3 = l3_device.model_copy(update={
        "interfaces": (bad_interface, *l3_device.interfaces[1:]),
    })
    checks = evaluate_cross_layer_checks(
        bundle["revision"], bundle["l2_intent"], l2_device, mutated_l3,
        bundle["l3_document"], bundle["l3_report"], UUID(assignment_id),
    )
    vlan_check = next(item for item in checks if item.check_id == "vlan-definition-exists")
    assert vlan_check.status.value == "FAIL"
    assert any("vlan-not-declared:99" in reason for reason in vlan_check.reason_codes)

    route = l3_device.routes[0]
    bad_route = route.model_copy(update={"next_hop": IPv4Address("203.0.113.1")})
    mutated_routes = l3_device.model_copy(update={
        "routes": (bad_route, *l3_device.routes[1:]),
    })
    checks = evaluate_cross_layer_checks(
        bundle["revision"], bundle["l2_intent"], l2_device, mutated_routes,
        bundle["l3_document"], bundle["l3_report"], UUID(assignment_id),
    )
    route_check = next(
        item for item in checks
        if item.check_id == "static-route-next-hop-dependency"
    )
    assert route_check.status.value == "FAIL"
    assert any("route-next-hop-not-on-link" in reason for reason in route_check.reason_codes)


def test_cross_layer_checks_detect_routed_channel_shutdown_and_management_conflicts(
    client: TestClient,
) -> None:
    event_id = _event(client, "cross-layer conflicts")
    plan = make_l3_plan(event_id, static_route_count=1)
    assignment_id = _assignment(plan)
    bundle = _trusted_bundle(plan, assignment_id)
    revision = bundle["revision"]
    l2_intent = bundle["l2_intent"]
    l2_device = bundle["l2_device"]
    l3_device = bundle["l3_device"]
    l3_document = bundle["l3_document"]
    l3_report = bundle["l3_report"]

    def run(device: DeviceLayer2Intent) -> dict[str, Any]:
        checks = evaluate_cross_layer_checks(
            revision, l2_intent, device, l3_device,
            l3_document, l3_report, UUID(assignment_id),
        )
        return {item.check_id: item for item in checks}

    ports = l2_device.desired.physical_ports
    routed = ports[0].model_copy(update={"mode": "routed", "switchport": True})
    routed_device = l2_device.model_copy(update={
        "desired": l2_device.desired.model_copy(update={
            "physical_ports": (routed, *ports[1:]),
        }),
    })
    assert run(routed_device)["routed-switchport-conflict"].status.value == "FAIL"

    channel = PortChannelIntent(
        interface_id=uuid4(),
        number=1,
        name="Port-channel1",
        member_ids=(ports[0].interface_id,),
        member_names=(ports[0].name,),
        lacp="active",
        settings=PortChannelSettingsIntent(
            mode="trunk",
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=(20,),
            routed_address=None,
            description=None,
            admin_state=None,
            portfast=None,
            bpdu_guard=None,
        ),
    )
    channel_device = l2_device.model_copy(update={
        "desired": l2_device.desired.model_copy(update={
            "port_channels": (channel,),
        }),
    })
    assert run(channel_device)["port-channel-membership"].status.value == "FAIL"

    native = ports[0].model_copy(update={"native_vlan": 999})
    native_device = l2_device.model_copy(update={
        "desired": l2_device.desired.model_copy(update={
            "physical_ports": (native, *ports[1:]),
        }),
    })
    assert run(native_device)["native-allowed-vlan-reference"].status.value == "FAIL"

    transit = revision.plan.transit
    assert transit is not None
    shutdown_ports = tuple(
        port.model_copy(update={
            "admin_state": "down", "shutdown_intent": "shutdown",
        }) if port.interface_id == transit.core_port_id else port
        for port in ports
    )
    assert any(port.interface_id == transit.core_port_id for port in ports)
    shutdown_device = l2_device.model_copy(update={
        "desired": l2_device.desired.model_copy(update={
            "physical_ports": shutdown_ports,
        }),
    })
    assert run(shutdown_device)["shutdown-uplink-consistency"].status.value == "FAIL"

    physical = ports[0].model_copy(update={"physical_device_id": uuid4()})
    physical_device = l2_device.model_copy(update={
        "desired": l2_device.desired.model_copy(update={
            "physical_ports": (physical, *ports[1:]),
        }),
    })
    assert run(physical_device)["physical-interface-assignment"].status.value == "FAIL"

    bad_plan = revision.plan.model_copy(update={"management_vlan": 99})
    bad_revision = revision.model_copy(update={"plan": bad_plan})
    checks = evaluate_cross_layer_checks(
        bad_revision, l2_intent, l2_device, l3_device,
        l3_document, l3_report, UUID(assignment_id),
    )
    management = next(
        item for item in checks if item.check_id == "management-vlan-management-ip"
    )
    assert management.status.value == "FAIL"


def _trusted_bundle(plan: dict[str, Any], assignment_id: str) -> dict[str, Any]:
    revision = revision_for(plan)
    l2_intent = build_layer2_intent(revision, None)
    l2_preview = build_device_layer2_config_preview(
        revision, l2_intent, UUID(assignment_id),
    )
    l2_document = build_l2_cli_candidates(revision, l2_intent, l2_preview)
    l2_expected = L2ExpectedSource(
        saved_revision_uuid=revision.id,
        revision_number=revision.number,
        revision_canonical_hash=revision.content_hash,
        intent_fingerprint=l2_intent.intent_fingerprint,
        preview_fingerprint=l2_preview.preview_fingerprint,
        render_fingerprint=l2_document.render_fingerprint,
        assignment_id=UUID(assignment_id),
    )
    l2_report = validate_candidate_document(l2_document, expected=l2_expected)
    l3_intent = build_layer3_intent(revision, None)
    l3_device = next(
        item for item in l3_intent.devices
        if item.identity.assignment_id == UUID(assignment_id)
    )
    selection = select_l3_registry(l3_device.identity)
    l3_document = build_l3_cli_candidates(
        revision, l3_intent, UUID(assignment_id), selection.registry,
    )
    l3_expected = L3ExpectedSource(
        event_id=revision.plan.event_id,
        saved_revision_uuid=revision.id,
        revision_number=revision.number,
        revision_canonical_hash=revision.content_hash,
        l3_intent_schema_version=l3_intent.l3_intent_schema_version,
        l3_intent_fingerprint=l3_intent.intent_fingerprint,
        l3_render_contract_id=l3_document.contract_id,
        l3_render_contract_version=l3_document.l3_render_schema_version,
        l3_render_fingerprint=l3_document.l3_render_fingerprint,
        command_evidence_registry_id=selection.registry.registry_id,
        command_evidence_registry_fingerprint=selection.registry.fingerprint,
        assignment_id=UUID(assignment_id),
        baseline_revision_uuid=l3_intent.baseline.revision_id,
        baseline_revision_hash=l3_intent.baseline.revision_hash,
    )
    l3_report = validate_l3_candidates(
        revision, l3_intent, l3_document, l3_expected,
        UUID(assignment_id), selection.registry,
    )
    l2_device = next(
        item for item in l2_intent.devices
        if item.identity.assignment_id == UUID(assignment_id)
    )
    return {
        "revision": revision,
        "l2_intent": l2_intent,
        "l2_device": l2_device,
        "l2_preview": l2_preview,
        "l2_document": l2_document,
        "l2_report": l2_report,
        "l3_intent": l3_intent,
        "l3_device": l3_device,
        "l3_document": l3_document,
        "l3_report": l3_report,
    }


def test_assembly_is_deterministic(client: TestClient) -> None:
    event_id = _event(client, "assembly deterministic")
    plan = c9200_candidate_plan(event_id)
    revision = _save(client, event_id, plan)
    assignment_id = _assignment(plan)
    path = ASSEMBLY_PATH.format(
        event=event_id, revision=revision["id"], assignment=assignment_id,
    )
    first = client.get(path)
    second = client.get(path)
    assert first.status_code == second.status_code == 200
    assert first.content == second.content
    body = ConfigurationAssembly.model_validate(first.json())
    assert body.assembly_fingerprint == assembly_fingerprint(body)
    assert body.completeness.complete is False
